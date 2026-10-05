use crate::client::{interruptible_connect_result, ClientError, InterruptibleConnectState};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    Connect(std::io::ErrorKind, Option<i32>),
    Handshake(ClientError),
}

type AdmissionHistory = std::collections::VecDeque<(Instant, serde_json::Value)>;

fn admission_history() -> &'static Mutex<AdmissionHistory> {
    static HISTORY: OnceLock<Mutex<AdmissionHistory>> = OnceLock::new();
    HISTORY.get_or_init(Mutex::default)
}

/// Returns recent admissions for this endpoint and startup attempt.
pub fn macos_admissions_since(endpoint: &Path, since: Instant) -> Vec<serde_json::Value> {
    admission_history()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .filter(|(observed, entry)| {
            *observed >= since && entry["endpoint"] == endpoint.to_string_lossy().as_ref()
        })
        .map(|(_, entry)| entry.clone())
        .collect()
}

fn record_admission(envelope: &serde_json::Value) {
    let mut history = admission_history()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // Bound memory when an endpoint stays unavailable.
    if history.len() == 128 {
        history.pop_front();
    }
    history.push_back((Instant::now(), envelope.clone()));
}

#[derive(Default)]
pub struct MacosConnectDiagnostic {
    last: Option<Failure>,
    pub(crate) failure: Option<serde_json::Value>,
}

impl MacosConnectDiagnostic {
    pub(crate) fn connect_desktop(
        &mut self,
        endpoint: &Path,
        version: &str,
        stop: &crate::DesktopClientStopHandle,
        holder: &crate::DesktopClientHolder,
        bound: Duration,
    ) -> Option<crate::DesktopClient> {
        let client = self.connect(endpoint, "desktop-client", &stop.inner, bound, |stream| {
            crate::handshake_desktop_client_stream(stream, version, bound)
        });
        holder.record_admission_failure(self.failure.clone());
        client
    }

    pub fn connect<S: InterruptibleConnectState, T>(
        &mut self,
        endpoint: &Path,
        route: &str,
        stop: &Arc<(Mutex<S>, Condvar)>,
        bound: Duration,
        handshake: impl FnOnce(UnixStream) -> Result<T, ClientError>,
    ) -> Option<T> {
        let started = Instant::now();
        let stream = interruptible_connect_result(endpoint, stop);
        let connect_elapsed = started.elapsed();
        let handshake_started = Instant::now();
        let result = match stream {
            Ok(Some(stream)) => handshake(stream).map_err(Failure::Handshake),
            Ok(None) => {
                self.last = None;
                self.failure = None;
                return None;
            }
            Err(error) => Err(Failure::Connect(error.kind(), error.raw_os_error())),
        };
        let mut envelope = serde_json::json!({
            "event": "macos_attach_admission",
            "observer": "desktop",
            "peer_pid": std::process::id(),
            "endpoint": endpoint,
            "requested_route": route,
            "elapsed_ms": started.elapsed().as_millis(),
            "connect_elapsed_ms": connect_elapsed.as_millis(),
            // The supervisor stop bounds connect. The I/O bound starts at the handshake.
            "connect_bound": "supervisor_stop",
        });
        match result {
            Ok(client) => {
                envelope["phase"] = "admitted".into();
                envelope["handshake_elapsed_ms"] =
                    serde_json::json!(handshake_started.elapsed().as_millis());
                envelope["io_bound_ms"] = serde_json::json!(bound.as_millis());
                record_admission(&envelope);
                eprintln!("muniment-desktop: {envelope}");
                self.last = None;
                self.failure = None;
                Some(client)
            }
            Err(failure) => {
                match failure {
                    Failure::Connect(kind, os_error) => {
                        envelope["phase"] = "connect".into();
                        envelope["closed_by"] = "not_connected".into();
                        envelope["code_check"] = "not_run".into();
                        envelope["error"] = serde_json::json!({
                            "kind": format!("{kind:?}"), "os_error": os_error,
                        });
                    }
                    Failure::Handshake(error) => {
                        envelope["phase"] = "handshake".into();
                        envelope["closed_by"] = if error == ClientError::ConnectionClosed {
                            "runtime_or_transport"
                        } else {
                            "desktop"
                        }
                        .into();
                        envelope["code_check"] = "runtime_reports_result".into();
                        envelope["error"] = format!("{error:?}").into();
                        envelope["handshake_elapsed_ms"] =
                            serde_json::json!(handshake_started.elapsed().as_millis());
                        envelope["io_bound_ms"] = serde_json::json!(bound.as_millis());
                    }
                }
                record_admission(&envelope);
                if self.last != Some(failure) {
                    eprintln!("muniment-desktop: {envelope}");
                }
                self.last = Some(failure);
                self.failure = Some(envelope);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DesktopClientHolder, DesktopClientStopHandle};

    #[test]
    fn unavailable_endpoint_reaches_the_supervisor_and_startup_diagnostic() {
        let endpoint =
            std::env::temp_dir().join(format!("m1876-missing-{}.sock", std::process::id()));
        let started = Instant::now();
        let holder = DesktopClientHolder::new();
        let stop = DesktopClientStopHandle::new();
        let mut diagnostic = MacosConnectDiagnostic::default();
        let mut attempts = 0;
        crate::desktop_supervisor::serve_desktop_client_with(
            || {
                let client = diagnostic.connect_desktop(
                    &endpoint,
                    "1.0.0",
                    &stop,
                    &holder,
                    Duration::from_millis(50),
                );
                attempts += 1;
                if attempts == 2 {
                    stop.stop();
                }
                client
            },
            stop.clone(),
            holder.clone(),
            Duration::from_millis(1),
            |_| panic!("an unavailable endpoint cannot connect"),
        );
        assert_eq!(attempts, 2);
        let failure = holder.admission_failure_since(started).unwrap();
        assert_eq!(failure["phase"], "connect");
        assert_eq!(failure["requested_route"], "desktop-client");
        assert_eq!(failure["endpoint"], endpoint.to_str().unwrap());
        assert_eq!(failure["error"]["kind"], "NotFound");
        assert!(failure["error"]["os_error"].is_number());
        assert_eq!(failure["code_check"], "not_run");
        assert_eq!(failure["closed_by"], "not_connected");
        assert!(failure["connect_elapsed_ms"].is_number());
        assert_eq!(failure["connect_bound"], "supervisor_stop");
        assert!(failure["handshake_elapsed_ms"].is_null());
        assert!(holder.admission_failure_since(Instant::now()).is_none());
        assert!(diagnostic
            .connect_desktop(
                &endpoint,
                "1.0.0",
                &stop,
                &holder,
                Duration::from_millis(50)
            )
            .is_none());
        assert!(holder.admission_failure_since(started).is_none());
    }

    #[test]
    fn presenter_supervisor_reports_connect_errors_before_the_handshake() {
        use crate::presenter_client::{serve_approval_presenter_with, ApprovalPresenterStopHandle};
        let stop = ApprovalPresenterStopHandle::new();
        let mut diagnostic = MacosConnectDiagnostic::default();
        let mut attempts = 0;
        serve_approval_presenter_with(
            || {
                let client = diagnostic.connect(
                    Path::new(""),
                    "approval-presenter",
                    &stop.inner,
                    Duration::from_millis(50),
                    |_| panic!("the invalid endpoint cannot reach the handshake"),
                );
                attempts += 1;
                stop.stop();
                client
            },
            stop.clone(),
            Duration::from_millis(1),
            |_| {},
            |_| panic!("an unavailable presenter cannot request approval"),
        );
        assert_eq!(attempts, 1);
        let failure = diagnostic.failure.unwrap();
        assert_eq!(failure["requested_route"], "approval-presenter");
        assert_eq!(failure["phase"], "connect");
        assert_eq!(failure["error"]["kind"], "InvalidInput");
        assert_eq!(failure["code_check"], "not_run");
    }

    #[test]
    fn handshake_failure_and_recovery_replace_the_connect_failure() {
        use std::os::unix::net::UnixListener;
        let endpoint =
            std::env::temp_dir().join(format!("m1876-recovery-{}.sock", std::process::id()));
        let stop = DesktopClientStopHandle::new();
        let mut diagnostic = MacosConnectDiagnostic::default();
        let bound = Duration::from_millis(50);
        let started = Instant::now();
        assert!(diagnostic
            .connect::<_, ()>(
                &endpoint,
                "desktop-client",
                &stop.inner,
                bound,
                |_| unreachable!()
            )
            .is_none());
        let listener = UnixListener::bind(&endpoint).unwrap();
        for error in [ClientError::Timeout, ClientError::ConnectionClosed] {
            assert!(diagnostic
                .connect::<_, ()>(&endpoint, "desktop-client", &stop.inner, bound, |_| Err(
                    error
                ))
                .is_none());
            drop(listener.accept().unwrap());
            let failure = diagnostic.failure.as_ref().unwrap();
            assert_eq!(failure["phase"], "handshake");
            assert_eq!(failure["error"], format!("{error:?}"));
            assert_eq!(failure["io_bound_ms"], 50);
            assert!(failure["handshake_elapsed_ms"].is_number());
            assert_eq!(
                failure["closed_by"],
                if error == ClientError::Timeout {
                    "desktop"
                } else {
                    "runtime_or_transport"
                }
            );
        }
        assert_eq!(
            diagnostic.connect(&endpoint, "desktop-client", &stop.inner, bound, |_| Ok(())),
            Some(())
        );
        drop(listener.accept().unwrap());
        assert!(diagnostic.failure.is_none());
        assert!(diagnostic.last.is_none());
        let admissions = macos_admissions_since(&endpoint, started);
        assert_eq!(admissions.len(), 4);
        assert_eq!(admissions[0]["phase"], "connect");
        assert_eq!(admissions[1]["error"], "Timeout");
        assert_eq!(admissions[2]["error"], "ConnectionClosed");
        assert_eq!(admissions[3]["phase"], "admitted");
        for admission in admissions {
            assert!(admission["elapsed_ms"].is_number());
            assert_eq!(admission["requested_route"], "desktop-client");
        }
        assert!(macos_admissions_since(&endpoint, Instant::now()).is_empty());
        assert!(macos_admissions_since(Path::new("another-endpoint"), started).is_empty());
        drop(listener);
        assert!(diagnostic
            .connect::<_, ()>(
                &endpoint,
                "desktop-client",
                &stop.inner,
                bound,
                |_| unreachable!()
            )
            .is_none());
        assert_eq!(
            diagnostic.failure.as_ref().unwrap()["error"]["kind"],
            "ConnectionRefused"
        );
        std::fs::remove_file(endpoint).unwrap();
    }
}
