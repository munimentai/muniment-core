#[cfg(unix)]
mod unix_tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use muniment_core::attach::{
        connect_windows_desktop_client_with, encode_frame, handshake_desktop_client,
        reconnect_welcome, serve_windows_desktop_client_with, ClientError, DesktopClientHolder,
        DesktopClientStopHandle, WindowsAttachConnectError, WindowsPipeSecurityError,
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

    #[test]
    fn retries_a_failed_attempt_with_a_deadline() {
        let stop = DesktopClientStopHandle::new();
        let connect_stop = stop.clone();
        let mut attempts = 0;
        let started = Instant::now();

        serve_windows_desktop_client_with(
            "1.2.3",
            Duration::from_secs(1),
            Duration::from_millis(1),
            stop,
            DesktopClientHolder::new(),
            |_| {},
            (
                |deadline| {
                    attempts += 1;
                    assert!(deadline > started);
                    if attempts == 2 {
                        connect_stop.stop();
                    }
                    Err::<UnixStream, _>(WindowsAttachConnectError::EndpointAbsent)
                },
                |_, _, _| panic!("the handshake must not run after a connect failure"),
            ),
        );

        assert_eq!(attempts, 2);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn observes_a_served_connection_and_its_end() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            read_frame(&mut peer);
            peer.write_all(
                &encode_frame(&reconnect_welcome(1, "runtime-1", "11".repeat(16), "")).unwrap(),
            )
            .unwrap();
            peer.write_all(
                &encode_frame(&serde_json::json!({
                    "profile_id": "profile-1",
                    "capability": "33".repeat(32),
                    "expires_at": 60,
                    "idle_timeout_seconds": 30,
                    "workspace_scopes": {}
                }))
                .unwrap(),
            )
            .unwrap();
        });
        let stop = DesktopClientStopHandle::new();
        let observe_stop = stop.clone();
        let holder = DesktopClientHolder::new();
        let observed_holder = holder.clone();
        let mut observed = Vec::new();
        let mut stream = Some(stream);

        serve_windows_desktop_client_with(
            "1.2.3",
            Duration::from_secs(1),
            Duration::from_millis(10),
            stop,
            holder,
            |connected| {
                if connected {
                    assert_eq!(
                        observed_holder.runtime_version().as_deref(),
                        Some("runtime-1")
                    );
                    observe_stop.stop();
                }
                observed.push(connected);
            },
            (|_| Ok(stream.take().unwrap()), handshake_desktop_client),
        );

        assert_eq!(observed, [true, false]);
        assert_eq!(observed_holder.runtime_version(), None);
        worker.join().unwrap();
    }

    #[test]
    fn stop_waits_for_at_most_the_bounded_attempt() {
        let stop = DesktopClientStopHandle::new();
        let serving_stop = stop.clone();
        let (deadline_sender, deadline_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            serve_windows_desktop_client_with(
                "1.2.3",
                Duration::from_secs(1),
                Duration::from_millis(100),
                serving_stop,
                DesktopClientHolder::new(),
                |_| {},
                (
                    |deadline| {
                        deadline_sender.send(deadline).unwrap();
                        while Instant::now() < deadline {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err::<UnixStream, _>(WindowsAttachConnectError::DeadlineExpired)
                    },
                    |_, _, _| panic!("the handshake must not run after a connect failure"),
                ),
            );
        });

        let deadline = deadline_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert!(deadline <= Instant::now() + Duration::from_millis(100));
        let stopped_at = Instant::now();
        stop.stop();
        server.join().unwrap();
        assert!(stopped_at.elapsed() < Duration::from_millis(500));
    }

    fn read_frame(stream: &mut UnixStream) {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        let mut body = vec![0; u32::from_be_bytes(header) as usize];
        stream.read_exact(&mut body).unwrap();
    }
}
