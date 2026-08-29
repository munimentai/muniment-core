#[cfg(unix)]
mod unix_tests {
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use muniment_core::attach::{
        connect_windows_desktop_client_with, ClientError, WindowsAttachConnectError,
        WindowsPipeSecurityError,
    };

    fn failure(error: WindowsAttachConnectError) -> ClientError {
        let result = connect_windows_desktop_client_with::<UnixStream, (), _, _>(
            "1.2.3",
            Duration::from_secs(4),
            Instant::now() + Duration::from_secs(5),
            |_| Err(error),
            |_, _, _| panic!("the handshake must not run after a connect failure"),
        );
        result.unwrap_err()
    }

    #[test]
    fn maps_an_expired_deadline_to_timeout() {
        assert_eq!(
            failure(WindowsAttachConnectError::DeadlineExpired),
            ClientError::Timeout
        );
    }

    #[test]
    fn maps_an_absent_endpoint_to_desktop_unavailable() {
        assert_eq!(
            failure(WindowsAttachConnectError::EndpointAbsent),
            ClientError::DesktopUnavailable
        );
    }

    #[test]
    fn maps_other_connect_failures_to_desktop_unavailable() {
        let failures = [
            WindowsAttachConnectError::IdentityUnavailable,
            WindowsAttachConnectError::InvalidPipePath,
            WindowsAttachConnectError::Open(5),
            WindowsAttachConnectError::Wait(121),
            WindowsAttachConnectError::EndpointSecurity(
                WindowsPipeSecurityError::IdentityUnavailable,
            ),
        ];

        for error in failures {
            assert_eq!(failure(error), ClientError::DesktopUnavailable);
        }
    }

    #[test]
    fn forwards_the_connected_stream_and_caller_settings_to_the_handshake() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let io_timeout = Duration::from_secs(4);
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut connected_at = None;

        let result = connect_windows_desktop_client_with(
            "1.2.3",
            io_timeout,
            deadline,
            |received_deadline| {
                connected_at = Some(received_deadline);
                Ok(stream)
            },
            |_, client_version, received_timeout| {
                assert_eq!(client_version, "1.2.3");
                assert_eq!(received_timeout, io_timeout);
                Ok("connected")
            },
        );

        assert_eq!(result, Ok("connected"));
        assert_eq!(connected_at, Some(deadline));
    }

    #[test]
    fn returns_a_handshake_failure_without_remapping_it() {
        let (stream, _peer) = UnixStream::pair().unwrap();

        let result = connect_windows_desktop_client_with(
            "1.2.3",
            Duration::from_secs(4),
            Instant::now() + Duration::from_secs(5),
            |_| Ok(stream),
            |_, _, _| Err::<(), _>(ClientError::ProtocolIncompatible),
        );

        assert_eq!(result, Err(ClientError::ProtocolIncompatible));
    }
}
