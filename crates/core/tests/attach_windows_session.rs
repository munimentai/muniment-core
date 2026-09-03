#[cfg(unix)]
mod unix_tests {
    use std::cell::Cell;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use muniment_core::attach::desktop_service_message::{
        CompanionProvenance, ThreadCreateAccepted,
    };
    use muniment_core::attach::thread_service::{
        ThreadListPage, ThreadListRequest, ThreadListService,
    };
    use muniment_core::attach::{
        decode_frame, encode_frame, serve_windows_attach_session_with_reader,
        serve_windows_attach_session_with_reader_factory, Authorization,
        DesktopClientAdmissionError, DesktopClientAuthorizedGrant, Envelope, ErrorCode,
        ErrorEnvelope, Id, Operation, Protocol, ProtocolError, Request, Welcome,
        WindowsAttachPeerReader, WindowsAttachRouteReader, WindowsAttachSessionError,
        WindowsAttachSessionOutcome, WindowsPeerError, WindowsPeerReadError, MAX_FRAME_LENGTH,
    };

    struct EmptyService;

    impl ThreadListService for EmptyService {}

    const CREATED_THREAD_ID: &str = "018f0000-0000-7000-8000-000000000200";

    #[derive(Default)]
    struct ListService {
        bound_identity: Option<String>,
        listed_workspace: Option<String>,
        create_provenance: Option<CompanionProvenance>,
    }

    impl ThreadListService for ListService {
        fn bind_authorized_client(&mut self, client_identity: &str) {
            self.bound_identity = Some(client_identity.to_owned());
        }

        fn list_threads(
            &mut self,
            workspace: &str,
            _request: ThreadListRequest,
        ) -> Result<ThreadListPage, ProtocolError> {
            self.listed_workspace = Some(workspace.to_owned());
            Ok(ThreadListPage {
                threads: Vec::new(),
                next_cursor: None,
            })
        }

        fn create_thread(
            &mut self,
            _workspace: &str,
            _request_id: &Id,
            _idempotency_key: &Id,
            provenance: CompanionProvenance,
        ) -> Result<ThreadCreateAccepted, ProtocolError> {
            self.create_provenance = Some(provenance);
            Ok(ThreadCreateAccepted {
                thread_id: CREATED_THREAD_ID.to_owned(),
            })
        }
    }

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

    struct FakeRouteReader {
        peer_pid: u32,
        image_path: PathBuf,
    }

    impl WindowsAttachRouteReader for FakeRouteReader {
        fn peer_process(&self) -> Result<(u32, PathBuf), WindowsPeerReadError> {
            Ok((self.peer_pid, self.image_path.clone()))
        }
    }

    fn reader(peer_sid: &[u8], local_sid: &[u8]) -> FakePeerReader {
        FakePeerReader {
            peer_sid: peer_sid.to_vec(),
            local_sid: local_sid.to_vec(),
        }
    }

    fn route_reader(path: &str) -> FakeRouteReader {
        FakeRouteReader {
            peer_pid: 42,
            image_path: PathBuf::from(path),
        }
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

    fn hello_frame_for_kind(kind: &str) -> Vec<u8> {
        frame(
            serde_json::json!({
                "protocol": "muniment.attach/1",
                "client": {"kind": kind, "version": "0.0.1"},
                "supported": {"min": 1, "max": 1},
                "client_nonce": "nonce",
                "authorized_client_id": "018f0000-0000-7000-8000-000000000099"
            })
            .to_string()
            .as_bytes(),
        )
    }

    fn hello_frame() -> Vec<u8> {
        hello_frame_for_kind("desktop-client")
    }

    fn read_all(mut stream: UnixStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix).unwrap();
        let length = u32::from_be_bytes(prefix) as usize;
        let mut frame = vec![0_u8; 4 + length];
        frame[..4].copy_from_slice(&prefix);
        stream.read_exact(&mut frame[4..]).unwrap();
        frame
    }

    #[test]
    fn matching_desktop_peer_serves_admitted_requests() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let session = std::thread::spawn(move || {
            let mut service = ListService::default();
            let outcome = serve_windows_attach_session_with_reader(
                &mut server,
                &reader(&[1, 2, 3], &[1, 2, 3]),
                &route_reader("/Program Files/Muniment/muniment.exe"),
                Some(expected_desktop_executable()),
                "1.2.3",
                deadline(),
                &mut service,
            );
            (outcome, service)
        });
        client.write_all(&hello_frame()).unwrap();

        let welcome_frame = read_frame(&mut client);
        let (welcome, consumed) = decode_frame::<Welcome>(&welcome_frame).unwrap().unwrap();
        assert_eq!(consumed, welcome_frame.len());
        assert_eq!(welcome.selected, 1);
        assert_eq!(welcome.desktop_version, "1.2.3");
        assert_eq!(welcome.server_nonce.len(), 32);
        assert_eq!(welcome.authorization, Authorization::Authorized);
        assert!(welcome.approval_challenge.is_empty());

        let grant_frame = read_frame(&mut client);
        let (grant, consumed) = decode_frame::<DesktopClientAuthorizedGrant>(&grant_frame)
            .unwrap()
            .unwrap();
        assert_eq!(consumed, grant_frame.len());
        assert_eq!(grant.profile_id, "desktop-owner");
        assert!(grant.workspace_scopes.is_empty());

        let request_id = Id::new("018f0000-0000-7000-8000-000000000100").unwrap();
        client
            .write_all(
                &encode_frame(&Request {
                    protocol: Protocol,
                    request_id: request_id.clone(),
                    operation: Operation::ThreadList,
                    capability: grant.capability.clone(),
                    idempotency_key: None,
                    body: serde_json::json!({"limit": 20}),
                })
                .unwrap(),
            )
            .unwrap();
        let response_frame = read_frame(&mut client);
        let (Envelope::Response(response), consumed) =
            decode_frame::<Envelope>(&response_frame).unwrap().unwrap()
        else {
            panic!("expected a service response");
        };
        assert_eq!(consumed, response_frame.len());
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.body, serde_json::json!({"threads": []}));

        let create_request_id = Id::new("018f0000-0000-7000-8000-000000000101").unwrap();
        client
            .write_all(
                &encode_frame(&Request {
                    protocol: Protocol,
                    request_id: create_request_id.clone(),
                    operation: Operation::ThreadCreate,
                    capability: grant.capability,
                    idempotency_key: Some(Id::new("018f0000-0000-7000-8000-000000000102").unwrap()),
                    body: serde_json::json!({}),
                })
                .unwrap(),
            )
            .unwrap();
        let created_frame = read_frame(&mut client);
        let (Envelope::Response(created), consumed) =
            decode_frame::<Envelope>(&created_frame).unwrap().unwrap()
        else {
            panic!("expected a service response");
        };
        assert_eq!(consumed, created_frame.len());
        assert_eq!(created.request_id, create_request_id);
        assert_eq!(
            created.body,
            serde_json::json!({"thread_id": CREATED_THREAD_ID})
        );

        client.shutdown(Shutdown::Write).unwrap();
        let (outcome, service) = session.join().unwrap();
        let WindowsAttachSessionOutcome::DesktopClient(admitted) = outcome.unwrap() else {
            panic!("expected the desktop-client route");
        };
        assert_eq!(admitted.companion_kind, "desktop-client");
        assert_eq!(admitted.companion_version, "0.0.1");
        assert_eq!(
            service.create_provenance,
            Some(CompanionProvenance {
                profile: "desktop-owner".into(),
                companion_kind: admitted.companion_kind,
                companion_version: admitted.companion_version,
                peer_uid: 0,
                peer_pid: 42,
            })
        );
        assert_eq!(service.bound_identity, Some(admitted.client_identity));
        assert_eq!(service.listed_workspace, Some(admitted.workspace));
    }

    #[test]
    fn service_open_failure_closes_after_desktop_client_admission() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame()).unwrap();
        let factory_called = Cell::new(false);

        let outcome = serve_windows_attach_session_with_reader_factory(
            &mut server,
            &reader(&[1, 2, 3], &[1, 2, 3]),
            &route_reader("/Program Files/Muniment/muniment.exe"),
            Some(expected_desktop_executable()),
            "1.2.3",
            deadline(),
            || {
                factory_called.set(true);
                Err::<EmptyService, _>("journal open failed")
            },
        );

        assert_eq!(outcome, Err(WindowsAttachSessionError::ServiceOpen));
        assert!(factory_called.get());
        drop(server);
        let response = read_all(client);
        let (_, welcome_length) = decode_frame::<Welcome>(&response).unwrap().unwrap();
        let (grant, consumed) =
            decode_frame::<DesktopClientAuthorizedGrant>(&response[welcome_length..])
                .unwrap()
                .unwrap();
        assert_eq!(welcome_length + consumed, response.len());
        assert!(!grant.capability.is_empty());
    }

    #[test]
    fn matching_desktop_presenter_is_rejected_as_unauthorized() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame_for_kind("desktop")).unwrap();

        assert_eq!(
            serve_windows_attach_session_with_reader(
                &mut server,
                &reader(&[1, 2, 3], &[1, 2, 3]),
                &route_reader("/Program Files/Muniment/muniment.exe"),
                Some(expected_desktop_executable()),
                "1.2.3",
                deadline(),
                &mut EmptyService,
            ),
            Err(WindowsAttachSessionError::ApprovalPresenterUnavailable)
        );

        drop(server);
        let response = read_all(client);
        let (error, consumed) = decode_frame::<ErrorEnvelope>(&response).unwrap().unwrap();
        assert_eq!(consumed, response.len());
        assert_eq!(error.error.code(), ErrorCode::Unauthorized);
    }

    #[test]
    fn matching_desktop_companion_reaches_companion_exchange() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .write_all(&hello_frame_for_kind("editor-extension"))
            .unwrap();

        assert_eq!(
            serve_windows_attach_session_with_reader(
                &mut server,
                &reader(&[1, 2, 3], &[1, 2, 3]),
                &route_reader("/Program Files/Muniment/muniment.exe"),
                Some(expected_desktop_executable()),
                "1.2.3",
                deadline(),
                &mut EmptyService,
            ),
            Ok(WindowsAttachSessionOutcome::Companion)
        );

        drop(server);
        let response = read_all(client);
        let (welcome, consumed) = decode_frame::<Welcome>(&response).unwrap().unwrap();
        assert_eq!(consumed, response.len());
        assert_eq!(welcome.authorization, Authorization::PairingRequired);
    }

    #[test]
    fn companion_route_does_not_open_the_desktop_service() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame()).unwrap();
        let factory_called = Cell::new(false);

        let outcome = serve_windows_attach_session_with_reader_factory(
            &mut server,
            &reader(&[1, 2, 3], &[1, 2, 3]),
            &route_reader("/Program Files/Other/other.exe"),
            Some(expected_desktop_executable()),
            "1.2.3",
            deadline(),
            || {
                factory_called.set(true);
                Ok::<_, &str>(EmptyService)
            },
        );

        assert_eq!(outcome, Ok(WindowsAttachSessionOutcome::Companion));
        assert!(!factory_called.get());
        drop(server);
        let response = read_all(client);
        let (welcome, consumed) = decode_frame::<Welcome>(&response).unwrap().unwrap();
        assert_eq!(consumed, response.len());
        assert_eq!(welcome.authorization, Authorization::PairingRequired);
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
                &mut EmptyService,
            ),
            Ok(WindowsAttachSessionOutcome::Companion)
        );

        drop(server);
        let response = read_all(client);
        let (welcome, consumed) = decode_frame::<Welcome>(&response).unwrap().unwrap();
        assert_eq!(consumed, response.len());
        assert_eq!(welcome.selected, 1);
        assert_eq!(welcome.desktop_version, "1.2.3");
        assert_eq!(welcome.server_nonce.len(), 32);
        assert_eq!(welcome.authorization, Authorization::PairingRequired);
        assert_eq!(welcome.approval_challenge.len(), 32);
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
                &mut EmptyService,
            ),
            Ok(WindowsAttachSessionOutcome::Companion)
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
                &mut EmptyService,
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
    fn oversized_desktop_frame_reads_no_body_and_writes_protocol_error() {
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
                &mut EmptyService,
            ),
            Err(WindowsAttachSessionError::DesktopClientAdmission(
                DesktopClientAdmissionError::PayloadTooLarge
            ))
        );
        let mut unread_body = vec![0_u8; body.len()];
        unread.read_exact(&mut unread_body).unwrap();
        assert_eq!(unread_body, body);
        drop(server);
        drop(unread);
        let response = read_all(client);
        let (error, consumed) = decode_frame::<ErrorEnvelope>(&response).unwrap().unwrap();
        assert_eq!(consumed, response.len());
        assert_eq!(error.error.code(), ErrorCode::PayloadTooLarge);
    }

    #[test]
    fn malformed_desktop_frame_returns_malformed_frame() {
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
                &mut EmptyService,
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
        serve_windows_attach_session, WindowsAttachSessionError, WindowsAttachSessionOutcome,
        WindowsAttachStream,
    };

    struct EmptyService;
    impl muniment_core::attach::thread_service::ThreadListService for EmptyService {}

    let _: fn(
        WindowsAttachStream,
        &str,
        Instant,
        &mut EmptyService,
    ) -> Result<WindowsAttachSessionOutcome, WindowsAttachSessionError> =
        serve_windows_attach_session::<EmptyService>;
}
