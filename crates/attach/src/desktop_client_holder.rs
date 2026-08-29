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
        self.with_client(DesktopClient::sign_in)
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
        if !matches!(&result, Err(ClientError::RuntimeUpgradePending)) && result.is_err() {
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
