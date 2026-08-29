#[cfg(unix)]
mod unix_tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use muniment_core::attach::{
        decode_frame, serve_windows_attach_session_with_reader, Welcome,
        WindowsAttachConnectionRoute, WindowsAttachPeerReader, WindowsAttachRouteReader,
        WindowsAttachSessionError, WindowsPeerError, WindowsPeerReadError, MAX_FRAME_LENGTH,
    };

    struct FakePeerReader {
        peer_sid: Vec<u8>,
        local_sid: Vec<u8>,
    }

    impl WindowsAttachPeerReader for FakePeerReader {
        fn connected_peer_sid(&self) -> Result<Vec<u8>, WindowsPeerReadError> {
            Ok(self.peer_sid.clone())
        }

        fn local_process_user_sid(&self) -> Result<Vec<u8>, WindowsPeerReadError> {
            Ok(self.local_sid.clone())
        }
    }

    struct FakeRouteReader(PathBuf);

    impl WindowsAttachRouteReader for FakeRouteReader {
        fn peer_image_path(&self) -> Result<PathBuf, WindowsPeerReadError> {
            Ok(self.0.clone())
        }
    }

    fn reader(peer_sid: &[u8], local_sid: &[u8]) -> FakePeerReader {
        FakePeerReader {
            peer_sid: peer_sid.to_vec(),
            local_sid: local_sid.to_vec(),
        }
    }

    fn route_reader(path: &str) -> FakeRouteReader {
        FakeRouteReader(PathBuf::from(path))
    }

    fn expected_desktop_executable() -> &'static Path {
        Path::new("/Program Files/Muniment/muniment.exe")
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }

    fn hello_frame() -> Vec<u8> {
        frame(
            br#"{"protocol":"muniment.attach/1","client":{"kind":"editor-extension","version":"0.0.1"},"supported":{"min":1,"max":1},"client_nonce":"nonce","authorized_client_id":"018f0000-0000-7000-8000-000000000099"}"#,
        )
    }

    fn read_all(mut stream: UnixStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn matching_desktop_peer_returns_desktop_client_route_and_one_welcome_frame() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame()).unwrap();

        assert_eq!(
            serve_windows_attach_session_with_reader(
                &mut server,
                &reader(&[1, 2, 3], &[1, 2, 3]),
                &route_reader("/Program Files/Muniment/muniment.exe"),
                Some(expected_desktop_executable()),
                "1.2.3",
                deadline(),
            ),
            Ok(WindowsAttachConnectionRoute::DesktopClient)
        );

        drop(server);
        let response = read_all(client);
        let (welcome, consumed) = decode_frame::<Welcome>(&response).unwrap().unwrap();
        assert_eq!(consumed, response.len());
        assert_eq!(welcome.selected, 1);
        assert_eq!(welcome.desktop_version, "1.2.3");
        assert_eq!(welcome.server_nonce.len(), 32);
        assert_eq!(welcome.approval_challenge.len(), 32);
    }

    #[test]
    fn other_peer_returns_companion_route() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame()).unwrap();

        assert_eq!(
            serve_windows_attach_session_with_reader(
                &mut server,
                &reader(&[1, 2, 3], &[1, 2, 3]),
                &route_reader("/Program Files/Other/other.exe"),
                Some(expected_desktop_executable()),
                "1.2.3",
                deadline(),
            ),
            Ok(WindowsAttachConnectionRoute::Companion)
        );
    }

    #[test]
    fn absent_expected_desktop_executable_returns_companion_route() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame()).unwrap();

        assert_eq!(
            serve_windows_attach_session_with_reader(
                &mut server,
                &reader(&[1, 2, 3], &[1, 2, 3]),
                &route_reader("/Program Files/Muniment/muniment.exe"),
                None,
                "1.2.3",
                deadline(),
            ),
            Ok(WindowsAttachConnectionRoute::Companion)
        );
    }

    #[test]
    fn rejected_peer_gets_no_response_after_the_prefix_read() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let mut unread = server.try_clone().unwrap();
        let request = hello_frame();
        client.write_all(&request).unwrap();

        assert_eq!(
            serve_windows_attach_session_with_reader(
                &mut server,
                &reader(&[1, 2, 3], &[1, 2, 4]),
                &route_reader("/Program Files/Muniment/muniment.exe"),
                Some(expected_desktop_executable()),
                "1.2.3",
                deadline(),
            ),
            Err(WindowsAttachSessionError::PeerRejected(
                WindowsPeerError::WrongOwner
            ))
        );
        let mut body = vec![0_u8; request.len() - 4];
        unread.read_exact(&mut body).unwrap();
        assert_eq!(body, request[4..]);
        drop(server);
        drop(unread);
        assert!(read_all(client).is_empty());
    }

    #[test]
    fn oversized_prefix_reads_no_body_and_writes_no_response() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let mut unread = server.try_clone().unwrap();
        let body = b"body stays unread";
        client
            .write_all(&((MAX_FRAME_LENGTH as u32) + 1).to_be_bytes())
            .unwrap();
        client.write_all(body).unwrap();

        assert_eq!(
            serve_windows_attach_session_with_reader(
                &mut server,
                &reader(&[1, 2, 3], &[1, 2, 3]),
                &route_reader("/Program Files/Muniment/muniment.exe"),
                Some(expected_desktop_executable()),
                "1.2.3",
                deadline(),
            ),
            Err(WindowsAttachSessionError::MalformedFrame)
        );
        let mut unread_body = vec![0_u8; body.len()];
        unread.read_exact(&mut unread_body).unwrap();
        assert_eq!(unread_body, body);
        drop(server);
        drop(unread);
        assert!(read_all(client).is_empty());
    }

    #[test]
    fn malformed_body_writes_no_response() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&frame(b"{")).unwrap();

        assert_eq!(
            serve_windows_attach_session_with_reader(
                &mut server,
                &reader(&[1, 2, 3], &[1, 2, 3]),
                &route_reader("/Program Files/Muniment/muniment.exe"),
                Some(expected_desktop_executable()),
                "1.2.3",
                deadline(),
            ),
            Err(WindowsAttachSessionError::MalformedFrame)
        );
        drop(server);
        assert!(read_all(client).is_empty());
    }
}

#[cfg(target_os = "windows")]
#[test]
fn native_session_wrapper_accepts_a_windows_stream() {
    use std::time::Instant;

    use muniment_core::attach::{
        serve_windows_attach_session, WindowsAttachConnectionRoute, WindowsAttachSessionError,
        WindowsAttachStream,
    };

    let _: fn(
        WindowsAttachStream,
        &str,
        Instant,
    ) -> Result<WindowsAttachConnectionRoute, WindowsAttachSessionError> =
        serve_windows_attach_session;
}
