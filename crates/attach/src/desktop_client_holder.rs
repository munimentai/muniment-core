use crate::client::{
    ChatPermissionAnswer, ClientError, RunCancelAccepted, RunMessageAccepted,
    RunPermissionAnswerAccepted, RunResumeAccepted, RunSubmitAccepted,
};
use crate::desktop_client::DesktopClient;
use crate::{Id, Operation, Response};
use serde_json::Value;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

const DESKTOP_CLIENT_LOCK_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, Default)]
pub struct DesktopClientHolder {
    pub(crate) inner: Arc<(Mutex<Option<DesktopClient>>, Condvar)>,
    /// Mirrors the held client's welcome version. Readers such as the
    /// disconnect observer run while the client lock is held, so they read
    /// the version here instead of locking the client again.
    pub(crate) runtime_version: Arc<Mutex<Option<String>>>,
}

impl DesktopClientHolder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn runtime_version(&self) -> Option<String> {
        self.runtime_version
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    pub fn request(
        &self,
        operation: Operation,
        idempotency_key: Option<Id>,
        body: Value,
    ) -> Result<Response, ClientError> {
        self.with_client(|client| client.request(operation, idempotency_key, body))
    }

    pub fn rename_thread(&self, thread_id: &str, title: &str) -> Result<(), ClientError> {
        self.with_client(|client| client.rename_thread(thread_id, title))
    }

    pub fn delete_thread(&self, thread_id: &str) -> Result<(), ClientError> {
        self.with_client(|client| client.delete_thread(thread_id))
    }

    pub fn thread_select(&self, thread_id: &str) -> Result<(), ClientError> {
        self.with_client(|client| client.thread_select(thread_id))
    }

    pub fn recheck_retention(&self) -> Result<(), ClientError> {
        self.with_client(DesktopClient::recheck_retention)
    }

    pub fn session_status(&self) -> Result<Value, ClientError> {
        self.with_client(DesktopClient::session_status)
    }

    pub fn entitlement_snapshot(&self) -> Result<Value, ClientError> {
        self.with_client(DesktopClient::entitlement_snapshot)
    }

    pub fn list_devices(&self) -> Result<Value, ClientError> {
        self.with_client(DesktopClient::list_devices)
    }

    pub fn sign_out(&self) -> Result<Value, ClientError> {
        self.with_client(DesktopClient::sign_out)
    }

    pub fn sign_in(&self) -> Result<Value, ClientError> {
        self.sign_in_with_diagnostics().map_err(|(error, _)| error)
    }

    pub fn sign_in_with_diagnostics(
        &self,
    ) -> Result<Value, (ClientError, Option<crate::ProtocolError>)> {
        let mut failure = None;
        let result = self.with_client(|client| {
            let result = client.sign_in();
            if result == Err(ClientError::AuthorizationFailed) {
                // Copy the matching response before another request can replace it.
                failure = client.last_request_error().cloned();
            }
            result
        });
        result.map_err(|error| (error, failure))
    }

    pub fn thread_summaries(&self, limit: u8, cursor: Option<&str>) -> Result<Value, ClientError> {
        self.with_client(|client| client.thread_summaries(limit, cursor))
    }

    pub fn thread_history(
        &self,
        thread_id: &str,
        limit: u8,
        cursor: Option<&str>,
    ) -> Result<Value, ClientError> {
        self.with_client(|client| client.thread_history(thread_id, limit, cursor))
    }

    pub fn list_companions(&self) -> Result<Value, ClientError> {
        self.with_client(DesktopClient::list_companions)
    }

    pub fn revoke_companion(&self, client_identity: &str) -> Result<Value, ClientError> {
        self.with_client(|client| client.revoke_companion(client_identity))
    }

    pub fn run_submit(
        &self,
        text: &str,
        files: &[String],
        thread_id: Option<&str>,
    ) -> Result<RunSubmitAccepted, ClientError> {
        self.with_client(|client| client.run_submit(text, files, thread_id))
    }

    pub fn run_submit_if_compatible(
        &self,
        text: &str,
        files: &[String],
        thread_id: Option<&str>,
        compatible: impl FnOnce(&str) -> bool,
    ) -> Result<RunSubmitAccepted, ClientError> {
        self.with_compatible_client(compatible, |client| {
            client.run_submit(text, files, thread_id)
        })
    }

    /// Captures the refusal under the client lock, before another request can replace it.
    pub fn run_submit_with_reason(
        &self,
        text: &str,
        files: &[String],
        thread_id: Option<&str>,
        compatible: impl FnOnce(&str) -> bool,
    ) -> Result<RunSubmitAccepted, (ClientError, Option<crate::ProtocolError>)> {
        let mut reason = None;
        let result = self.with_compatible_client(compatible, |client| {
            client.take_request_error();
            let result = client.run_submit(text, files, thread_id);
            if result.is_err() {
                reason = client.take_request_error();
            }
            result
        });
        result.map_err(|error| (error, reason))
    }

    pub fn run_cancel(&self, run_id: &str) -> Result<RunCancelAccepted, ClientError> {
        self.with_client(|client| client.run_cancel(run_id))
    }

    pub fn run_resume(&self, run_id: &str) -> Result<RunResumeAccepted, ClientError> {
        self.with_client(|client| client.run_resume(run_id))
    }

    pub fn run_resume_if_compatible(
        &self,
        run_id: &str,
        compatible: impl FnOnce(&str) -> bool,
    ) -> Result<RunResumeAccepted, ClientError> {
        self.with_compatible_client(compatible, |client| client.run_resume(run_id))
    }

    pub fn run_permission_answer(
        &self,
        run_id: &str,
        gate_id: &str,
        answer: ChatPermissionAnswer,
    ) -> Result<RunPermissionAnswerAccepted, ClientError> {
        self.with_client(|client| client.run_permission_answer(run_id, gate_id, answer))
    }

    pub fn run_steer(&self, run_id: &str, text: &str) -> Result<RunMessageAccepted, ClientError> {
        self.with_client(|client| client.run_steer(run_id, text))
    }

    pub fn run_steer_if_compatible(
        &self,
        run_id: &str,
        text: &str,
        compatible: impl FnOnce(&str) -> bool,
    ) -> Result<RunMessageAccepted, ClientError> {
        self.with_compatible_client(compatible, |client| client.run_steer(run_id, text))
    }

    pub fn run_follow_up(
        &self,
        run_id: &str,
        text: &str,
    ) -> Result<RunMessageAccepted, ClientError> {
        self.with_client(|client| client.run_follow_up(run_id, text))
    }

    pub fn run_follow_up_if_compatible(
        &self,
        run_id: &str,
        text: &str,
        compatible: impl FnOnce(&str) -> bool,
    ) -> Result<RunMessageAccepted, ClientError> {
        self.with_compatible_client(compatible, |client| client.run_follow_up(run_id, text))
    }

    fn with_compatible_client<T>(
        &self,
        compatible: impl FnOnce(&str) -> bool,
        call: impl FnOnce(&mut DesktopClient) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        self.with_client(|client| {
            if !compatible(client.runtime_version()) {
                return Err(ClientError::RuntimeUpgradePending);
            }
            call(client)
        })
    }

    fn with_client<T>(
        &self,
        call: impl FnOnce(&mut DesktopClient) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        let (client, wake) = &*self.inner;
        let mut client = Self::lock_client(client)?;
        let result = call(client.as_mut().ok_or(ClientError::DesktopUnavailable)?);
        // An authorization refusal does not break the transport. Keep the client so the shell can
        // report the refusal without a reconnect that repeats the same request.
        if !matches!(
            &result,
            Err(ClientError::RuntimeUpgradePending
                | ClientError::AuthorizationExpired
                | ClientError::AuthorizationFailed)
        ) && result.is_err()
        {
            *client = None;
            *self
                .runtime_version
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = None;
            wake.notify_all();
        }
        result
    }

    fn lock_client(
        client: &Mutex<Option<DesktopClient>>,
    ) -> Result<MutexGuard<'_, Option<DesktopClient>>, ClientError> {
        let deadline = Instant::now() + DESKTOP_CLIENT_LOCK_TIMEOUT;
        loop {
            match client.try_lock() {
                Ok(client) => return Ok(client),
                Err(TryLockError::Poisoned(error)) => return Ok(error.into_inner()),
                Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                    return Err(ClientError::DesktopBusy);
                }
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::desktop_client::desktop_client_for_test;
    use std::os::unix::net::UnixStream;
    use std::sync::Barrier;

    const IO_TIMEOUT: Duration = Duration::from_secs(5);

    fn test_client(runtime_version: &str) -> DesktopClient {
        let (stream, _peer) = UnixStream::pair().unwrap();
        desktop_client_for_test(Box::new(stream), runtime_version.to_string(), IO_TIMEOUT)
    }

    #[test]
    fn unauthorized_request_keeps_the_connection_for_an_explicit_retry() {
        use std::io::{Read, Write};

        let holder = DesktopClientHolder::new();
        let (stream, mut server) = UnixStream::pair().unwrap();
        server.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        *holder.inner.0.lock().unwrap() = Some(desktop_client_for_test(
            Box::new(stream),
            "1.0.0".into(),
            IO_TIMEOUT,
        ));
        *holder.runtime_version.lock().unwrap() = Some("1.0.0".into());
        let worker = std::thread::spawn(move || {
            for refused in [true, false] {
                let mut prefix = [0; 4];
                server.read_exact(&mut prefix).unwrap();
                let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
                server.read_exact(&mut body).unwrap();
                let request: crate::Request = serde_json::from_slice(&body).unwrap();
                assert_eq!(request.operation, Operation::ThreadSummaries);
                let response = if refused {
                    serde_json::json!({
                        "protocol": "muniment.attach/1", "request_id": request.request_id,
                        "ok": false, "error": crate::ProtocolError::unauthorized(),
                    })
                } else {
                    serde_json::json!({
                        "protocol": "muniment.attach/1", "request_id": request.request_id,
                        "ok": true, "body": {"summaries": [], "next_cursor": null},
                    })
                };
                server
                    .write_all(&crate::encode_frame(&response).unwrap())
                    .unwrap();
            }
        });

        assert_eq!(
            holder.thread_summaries(20, None),
            Err(ClientError::AuthorizationExpired)
        );
        assert!(holder.inner.0.lock().unwrap().is_some());
        assert_eq!(holder.runtime_version().as_deref(), Some("1.0.0"));
        assert!(holder.thread_summaries(20, None).is_ok());
        worker.join().unwrap();
        assert_eq!(
            holder.thread_summaries(20, None),
            Err(ClientError::ConnectionClosed)
        );
        assert!(holder.inner.0.lock().unwrap().is_none());
        assert_eq!(holder.runtime_version(), None);
    }

    #[test]
    fn submit_captures_each_refusal_without_stale_reasons_or_disconnects() {
        use std::io::{Read, Write};

        let holder = DesktopClientHolder::new();
        let (stream, mut server) = UnixStream::pair().unwrap();
        server.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        *holder.inner.0.lock().unwrap() = Some(desktop_client_for_test(
            Box::new(stream),
            "1.0.0".into(),
            IO_TIMEOUT,
        ));
        let reasons = [
            "chat_not_entitled: No chat model is currently available for this account.",
            "chat_not_entitled: The account has no allowed model.",
        ];
        let worker = std::thread::spawn(move || {
            for reason in reasons {
                let mut prefix = [0; 4];
                server.read_exact(&mut prefix).unwrap();
                let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
                server.read_exact(&mut body).unwrap();
                let request: crate::Request = serde_json::from_slice(&body).unwrap();
                assert_eq!(request.operation, Operation::RunSubmit);
                let response = serde_json::json!({
                    "protocol": "muniment.attach/1", "request_id": request.request_id,
                    "ok": false, "error": crate::ProtocolError::unauthorized_with_reason(reason),
                });
                server
                    .write_all(&crate::encode_frame(&response).unwrap())
                    .unwrap();
            }
        });
        for reason in reasons {
            let started = Instant::now();
            assert_eq!(
                holder.run_submit_with_reason("prompt", &[], None, |_| true),
                Err((
                    ClientError::AuthorizationExpired,
                    Some(crate::ProtocolError::unauthorized_with_reason(reason))
                ))
            );
            assert!(started.elapsed() < Duration::from_secs(30));
            assert!(holder.inner.0.lock().unwrap().is_some());
            assert_eq!(
                holder.run_submit_with_reason("prompt", &[], None, |_| false),
                Err((ClientError::RuntimeUpgradePending, None))
            );
        }
        worker.join().unwrap();
        assert_eq!(
            holder.run_submit_with_reason(" ", &[], None, |_| true),
            Err((ClientError::UnexpectedMessage, None))
        );
    }

    #[test]
    fn delayed_submit_refusal_keeps_reason_connection_and_other_request_deadlines() {
        use std::io::{Read, Write};
        use std::sync::mpsc;

        let holder = DesktopClientHolder::new();
        let (stream, mut server) = UnixStream::pair().unwrap();
        server.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        *holder.inner.0.lock().unwrap() = Some(desktop_client_for_test(
            Box::new(stream),
            "1.0.0".into(),
            IO_TIMEOUT,
        ));
        *holder.runtime_version.lock().unwrap() = Some("1.0.0".into());
        let reason = crate::ProtocolError::unauthorized_with_reason(
            "chat_not_entitled: No chat model is currently available for this account.",
        );
        let expected = reason.clone();
        let (release, released) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            for operation in [Operation::RunSubmit, Operation::SessionStatus] {
                let mut prefix = [0; 4];
                server.read_exact(&mut prefix).unwrap();
                let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
                server.read_exact(&mut body).unwrap();
                let request: crate::Request = serde_json::from_slice(&body).unwrap();
                assert_eq!(request.operation, operation);
                if operation == Operation::RunSubmit {
                    std::thread::sleep(Duration::from_secs(6));
                    let response = serde_json::json!({
                        "protocol": "muniment.attach/1", "request_id": request.request_id,
                        "ok": false, "error": reason,
                    });
                    server
                        .write_all(&crate::encode_frame(&response).unwrap())
                        .unwrap();
                } else {
                    // Keep the socket open without a response to test the next request's deadline.
                    let _ = released.recv_timeout(Duration::from_secs(35));
                }
            }
        });

        let started = Instant::now();
        assert_eq!(
            holder.run_submit_with_reason("prompt", &[], None, |_| true),
            Err((ClientError::AuthorizationExpired, Some(expected)))
        );
        assert!(started.elapsed() >= Duration::from_secs(6));
        assert!(started.elapsed() < Duration::from_secs(30));
        assert!(holder.inner.0.lock().unwrap().is_some());
        assert_eq!(holder.runtime_version().as_deref(), Some("1.0.0"));

        let started = Instant::now();
        assert_eq!(holder.session_status(), Err(ClientError::Timeout));
        let elapsed = started.elapsed();
        release.send(()).unwrap();
        worker.join().unwrap();
        assert!(elapsed >= IO_TIMEOUT);
        assert!(elapsed < IO_TIMEOUT + Duration::from_secs(2));
        assert!(holder.inner.0.lock().unwrap().is_none());
        assert_eq!(holder.runtime_version(), None);
    }

    #[test]
    fn sign_in_diagnostics_stay_with_the_failed_request() {
        use std::io::{Read, Write};
        let holder = DesktopClientHolder::new();
        let (stream, mut server) = UnixStream::pair().unwrap();
        server.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        *holder.inner.0.lock().unwrap() = Some(desktop_client_for_test(
            Box::new(stream),
            "1.0.0".into(),
            IO_TIMEOUT,
        ));
        let failure = crate::ProtocolError::authorization_failed("native authorization failed: HttpStatus status=400 error_code=invalid_client cf_ray=unavailable");
        let expected = failure.clone();
        let worker = std::thread::spawn(move || {
            for refused in [true, false] {
                let mut prefix = [0; 4];
                server.read_exact(&mut prefix).unwrap();
                let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
                server.read_exact(&mut body).unwrap();
                let request: crate::Request = serde_json::from_slice(&body).unwrap();
                let response = if refused {
                    serde_json::json!({ "protocol": "muniment.attach/1", "request_id": request.request_id, "ok": false, "error": failure })
                } else {
                    serde_json::json!({ "protocol": "muniment.attach/1", "request_id": request.request_id, "ok": true, "body": {"status": {"signed_in": true}} })
                };
                server
                    .write_all(&crate::encode_frame(&response).unwrap())
                    .unwrap();
            }
        });
        let failed = holder.sign_in_with_diagnostics();
        assert_eq!(
            failed,
            Err((ClientError::AuthorizationFailed, Some(expected.clone())))
        );
        assert!(holder.sign_in_with_diagnostics().is_ok());
        assert_eq!(
            failed,
            Err((ClientError::AuthorizationFailed, Some(expected)))
        );
        worker.join().unwrap();
        assert_eq!(
            holder.sign_in_with_diagnostics(),
            Err((ClientError::ConnectionClosed, None))
        );
        assert_eq!(
            holder.sign_in_with_diagnostics(),
            Err((ClientError::DesktopUnavailable, None))
        );
    }

    #[test]
    fn slow_call_makes_second_caller_busy_without_clearing_client() {
        let holder = DesktopClientHolder::new();
        let (client, _) = &*holder.inner;
        *client.lock().unwrap() = Some(test_client("0.0.1"));

        let entered = Arc::new(Barrier::new(2));
        let slow_holder = holder.clone();
        let slow_entered = entered.clone();
        let slow_call = std::thread::spawn(move || {
            slow_holder.with_client(|_| {
                slow_entered.wait();
                std::thread::sleep(DESKTOP_CLIENT_LOCK_TIMEOUT * 3);
                Ok(())
            })
        });
        entered.wait();

        let started = Instant::now();
        assert_eq!(holder.session_status(), Err(ClientError::DesktopBusy));
        assert!(started.elapsed() < DESKTOP_CLIENT_LOCK_TIMEOUT * 2);
        assert_eq!(slow_call.join().unwrap(), Ok(()));
        assert!(client.lock().unwrap().is_some());
    }

    #[test]
    fn compatible_check_and_request_keep_the_same_client_generation() {
        let holder = DesktopClientHolder::new();
        let (client, _) = &*holder.inner;
        *client.lock().unwrap() = Some(test_client("2.0.0"));

        let checked = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let request_holder = holder.clone();
        let request_checked = checked.clone();
        let request_release = release.clone();
        let request = std::thread::spawn(move || {
            request_holder.with_compatible_client(
                |version| {
                    assert_eq!(version, "2.0.0");
                    true
                },
                |client| {
                    request_checked.wait();
                    request_release.wait();
                    assert_eq!(client.runtime_version(), "2.0.0");
                    Ok(())
                },
            )
        });
        checked.wait();

        assert!(client.try_lock().is_err());
        let replacement_holder = holder.clone();
        let replacement = std::thread::spawn(move || {
            let (client, _) = &*replacement_holder.inner;
            *client.lock().unwrap() = Some(test_client("1.0.0"));
        });
        release.wait();
        assert_eq!(request.join().unwrap(), Ok(()));
        replacement.join().unwrap();

        let compatible = |version: &str| version >= "2.0.0";
        assert_eq!(
            holder.run_submit_if_compatible("prompt", &[], None, compatible),
            Err(ClientError::RuntimeUpgradePending)
        );
        assert_eq!(
            holder.run_resume_if_compatible("run", compatible),
            Err(ClientError::RuntimeUpgradePending)
        );
        assert_eq!(
            holder.run_steer_if_compatible("run", "message", compatible),
            Err(ClientError::RuntimeUpgradePending)
        );
        assert_eq!(
            holder.run_follow_up_if_compatible("run", "message", compatible),
            Err(ClientError::RuntimeUpgradePending)
        );
        assert!(client.lock().unwrap().is_some());
    }
}
