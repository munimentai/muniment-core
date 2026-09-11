use crate::client::{interruptible_connect_result, ClientError, InterruptibleConnectState};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Connected,
    Io(std::io::ErrorKind),
    Refused(ClientError),
}

/// Logs Linux connection outcomes without repeating an unchanged retry failure.
#[derive(Default)]
pub struct LinuxConnectDiagnostic {
    last: Option<Outcome>,
}

impl LinuxConnectDiagnostic {
    pub fn connect<S: InterruptibleConnectState, T>(
        &mut self,
        endpoint: &Path,
        route: &str,
        stop: &Arc<(Mutex<S>, Condvar)>,
        handshake: impl FnOnce(UnixStream) -> Result<T, ClientError>,
    ) -> Option<T> {
        // A new attempt after success follows a closed session.
        if self.last == Some(Outcome::Connected) {
            self.last = None;
        }
        let result = match interruptible_connect_result(endpoint, stop) {
            Ok(Some(stream)) => handshake(stream).map_err(Outcome::Refused),
            Ok(None) => return None,
            Err(error) => Err(Outcome::Io(error.kind())),
        };
        let outcome = result
            .as_ref()
            .map_or_else(|error| *error, |_| Outcome::Connected);
        if self.changed(outcome) {
            // Debug formatting escapes control characters in the endpoint.
            eprintln!(
                "muniment-desktop: connect endpoint={endpoint:?} route={route} outcome={outcome:?}"
            );
        }
        result.ok()
    }

    fn changed(&mut self, outcome: Outcome) -> bool {
        if self.last == Some(outcome) {
            return false;
        }
        self.last = Some(outcome);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct StopState {
        stopped: bool,
        stream: Option<UnixStream>,
    }

    impl InterruptibleConnectState for StopState {
        fn stopped(&self) -> bool {
            self.stopped
        }
        fn set_stream(&mut self, stream: Option<UnixStream>) {
            self.stream = stream;
        }
    }

    #[test]
    fn connect_preserves_io_kinds_and_cancellation() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::net::UnixListener;
        let stop = Arc::new((Mutex::new(StopState::default()), Condvar::new()));
        for path in [
            Path::new(""),
            Path::new(std::ffi::OsStr::from_bytes(b"a\0b")),
            Path::new(&"x".repeat(108)),
        ] {
            assert_eq!(
                interruptible_connect_result(path, &stop)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        let endpoint =
            std::env::temp_dir().join(format!("m1775-connect-{}.sock", std::process::id()));
        assert_eq!(
            interruptible_connect_result(&endpoint, &stop)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        let listener = UnixListener::bind(&endpoint).unwrap();
        let stream = interruptible_connect_result(&endpoint, &stop)
            .unwrap()
            .unwrap();
        let accepted = listener.accept().unwrap().0;
        drop(stream);
        drop(accepted);
        drop(listener);
        assert_eq!(
            interruptible_connect_result(&endpoint, &stop)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::ConnectionRefused
        );
        assert!(stop.0.lock().unwrap().stream.is_none());
        stop.0.lock().unwrap().stopped = true;
        assert!(interruptible_connect_result(&endpoint, &stop)
            .unwrap()
            .is_none());
        std::fs::remove_file(endpoint).unwrap();
    }

    #[test]
    fn retries_log_only_changes_and_recovery_resets_the_failure() {
        let mut diagnostic = LinuxConnectDiagnostic::default();
        for outcome in [
            Outcome::Io(std::io::ErrorKind::NotFound),
            Outcome::Io(std::io::ErrorKind::ConnectionRefused),
            Outcome::Refused(ClientError::ProtocolIncompatible),
            Outcome::Connected,
            Outcome::Io(std::io::ErrorKind::NotFound),
        ] {
            assert!(diagnostic.changed(outcome));
            assert!(!diagnostic.changed(outcome));
        }
    }
}
