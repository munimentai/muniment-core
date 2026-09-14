#[cfg(unix)]
mod unix_tests {
    use std::cell::Cell;
    use std::collections::BTreeSet;
    use std::io::{self, Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use muniment_core::attach::desktop_service_message::{
        CompanionProvenance, ThreadCreateAccepted,
    };
    use muniment_core::attach::live_connections::LiveConnectionRegistry;
    use muniment_core::attach::thread_service::{
        ThreadListPage, ThreadListRequest, ThreadListService,
    };
    use muniment_core::attach::{
        approval_waiter_with_claims, decode_frame, encode_frame,
        serve_windows_attach_session_with_reader,
        serve_windows_attach_session_with_reader_and_state,
        serve_windows_attach_session_with_reader_factory, Approval, ApprovalCoordinator,
        ApprovalDecision, ApprovalRequest, Authorization, DesktopClientAdmissionError,
        DesktopClientAuthorizedGrant, Envelope, ErrorCode, ErrorEnvelope, Id, Operation, Protocol,
        ProtocolError, Request, Welcome, WindowsAttachPeerReader, WindowsAttachRouteReader,
        WindowsAttachSessionError, WindowsAttachSessionOutcome, WindowsPeerError,
        WindowsPeerReadError, MAX_FRAME_LENGTH,
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
        // macOS answers EINVAL once the session thread has closed its end, and a
        // read on that socket drains the reply and ends without the timeout.
        match stream.set_read_timeout(Some(Duration::from_secs(2))) {
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
            result => result.unwrap(),
        }
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
    fn installed_desktop_connects_through_the_windows_runtime_route() {
        use muniment_core::attach::{
            handshake_desktop_client, serve_windows_desktop_client_with, DesktopClientHolder,
            DesktopClientStopHandle, WindowsAttachConnectError,
        };
        use muniment_core::windows_payload::installed_desktop_executable_from;

        // Use host-absolute paths to test Windows admission over a Unix stream.
        for root in [
            "/Program Files/muniment",
            "/Users/Ada/AppData/Local/muniment",
        ] {
            let expected =
                installed_desktop_executable_from(&Path::new(root).join("muniment-runtime.exe"))
                    .unwrap();
            for (image, admitted) in [
                (Path::new(root).join("muniment-desktop.exe"), true),
                (Path::new(root).join("muniment.exe"), false),
                (
                    PathBuf::from("/build/target/release/muniment-desktop.exe"),
                    false,
                ),
            ] {
                let (client, mut server) = UnixStream::pair().unwrap();
                let expected = expected.clone();
                let session = std::thread::spawn(move || {
                    let mut service = ListService::default();
                    serve_windows_attach_session_with_reader(
                        &mut server,
                        &reader(&[1, 2, 3], &[1, 2, 3]),
                        &FakeRouteReader {
                            peer_pid: 42,
                            image_path: image,
                        },
                        Some(&expected),
                        "1.2.3",
                        deadline(),
                        &mut service,
                    )
                });
                let stop = DesktopClientStopHandle::new();
                let connect_stop = stop.clone();
                let observe_stop = stop.clone();
                let holder = DesktopClientHolder::new();
                let observed_holder = holder.clone();
                let mut stream = Some(client);
                let mut connected = false;
                serve_windows_desktop_client_with(
                    "1.2.3",
                    Duration::from_secs(1),
                    Duration::from_millis(10),
                    stop,
                    holder,
                    |status| {
                        if status {
                            connected = true;
                            assert_eq!(observed_holder.runtime_version().as_deref(), Some("1.2.3"));
                            observe_stop.stop();
                        }
                    },
                    (
                        |_| match stream.take() {
                            Some(stream) => Ok(stream),
                            None => {
                                connect_stop.stop();
                                Err(WindowsAttachConnectError::EndpointAbsent)
                            }
                        },
                        handshake_desktop_client,
                    ),
                );
                let outcome = session.join().unwrap().unwrap();
                assert_eq!(
                    connected, admitted,
                    "The connection result must match admission for {root}."
                );
                assert_eq!(
                    matches!(outcome, WindowsAttachSessionOutcome::DesktopClient(_)),
                    admitted,
                );
            }
        }
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
    fn approval_presenter_approves_companion_with_recorded_workspace() {
        let coordinator = ApprovalCoordinator::default();
        let recorded = Approval {
            profile: "desktop-owner".into(),
            workspace: "workspace-recorded".into(),
            scopes: BTreeSet::from(["thread.read".into(), "run.write".into()]),
            lifetime: Duration::from_secs(60),
        };

        let (mut presenter_client, mut presenter_server) = UnixStream::pair().unwrap();
        presenter_client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let presenter_coordinator = coordinator.clone();
        let presenter_session = std::thread::spawn(move || {
            presenter_client
                .write_all(&hello_frame_for_kind("desktop"))
                .unwrap();
            let _: Welcome = decode_frame(&read_frame(&mut presenter_client))
                .unwrap()
                .unwrap()
                .0;
            let _: DesktopClientAuthorizedGrant = decode_frame(&read_frame(&mut presenter_client))
                .unwrap()
                .unwrap()
                .0;
            let mut observed = None;
            for _ in 0..2 {
                let request_frame = read_frame(&mut presenter_client);
                let (Envelope::Request(request), _) =
                    decode_frame::<Envelope>(&request_frame).unwrap().unwrap()
                else {
                    panic!("expected an approval request");
                };
                observed = Some(request.body.clone());
                presenter_client
                    .write_all(
                        &encode_frame(&serde_json::json!({
                            "protocol": "muniment.attach/1",
                            "request_id": request.request_id,
                            "ok": true,
                            "body": {
                                "challenge": request.body["challenge"],
                                "decision": "approve"
                            }
                        }))
                        .unwrap(),
                    )
                    .unwrap();
            }
            (presenter_client, observed.unwrap())
        });
        let presenter_server_thread = std::thread::spawn(move || {
            serve_windows_attach_session_with_reader_and_state(
                &mut presenter_server,
                &reader(&[1, 2, 3], &[1, 2, 3]),
                &route_reader("/Program Files/Muniment/muniment.exe"),
                Some(expected_desktop_executable()),
                "1.2.3",
                deadline(),
                &mut EmptyService,
                None,
                presenter_coordinator,
                |_: &muniment_core::attach::PairingChallenge, _: Duration| None,
                &LiveConnectionRegistry::default(),
            )
        });

        let probe = ApprovalRequest {
            challenge: "presenter-ready".into(),
            claimed_kind: "test".into(),
            claimed_version: "1".into(),
            workspace: "probe".into(),
            scopes: BTreeSet::new(),
        };
        let ready_deadline = Instant::now() + Duration::from_secs(2);
        while !coordinator.request(probe.clone(), Duration::from_millis(50)) {
            assert!(
                Instant::now() < ready_deadline,
                "presenter did not claim coordinator"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        let (mut companion, mut companion_server) = UnixStream::pair().unwrap();
        companion
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        companion
            .write_all(&hello_frame_for_kind("editor-extension"))
            .unwrap();
        let waiter_coordinator = coordinator.clone();
        let waiter_approval = recorded.clone();
        let companion_session = std::thread::spawn(move || {
            serve_windows_attach_session_with_reader_and_state(
                &mut companion_server,
                &reader(&[1, 2, 3], &[1, 2, 3]),
                &route_reader("/Program Files/Other/other.exe"),
                Some(expected_desktop_executable()),
                "1.2.3",
                deadline(),
                &mut EmptyService,
                Some(waiter_approval.clone()),
                coordinator,
                approval_waiter_with_claims(
                    move |challenge: &muniment_core::attach::PairingChallenge,
                          kind: &str,
                          version: &str,
                          remaining: Duration| {
                        waiter_coordinator
                            .request(
                                ApprovalRequest {
                                    challenge: challenge.as_str().to_owned(),
                                    claimed_kind: kind.to_owned(),
                                    claimed_version: version.to_owned(),
                                    workspace: waiter_approval.workspace.clone(),
                                    scopes: waiter_approval.scopes.clone(),
                                },
                                remaining,
                            )
                            .then(|| ApprovalDecision::Approve(waiter_approval.clone()))
                    },
                ),
                &LiveConnectionRegistry::default(),
            )
        });

        let welcome_frame = read_frame(&mut companion);
        let (welcome, _) = decode_frame::<Welcome>(&welcome_frame).unwrap().unwrap();
        assert_eq!(welcome.authorization, Authorization::PairingRequired);
        let authorized_frame = read_frame(&mut companion);
        let (authorized, _) = decode_frame::<muniment_core::attach::Authorized>(&authorized_frame)
            .unwrap()
            .unwrap();
        assert_eq!(authorized.profile_id, recorded.profile);
        assert_eq!(
            authorized.workspace_scopes.get(&recorded.workspace),
            Some(&recorded.scopes)
        );

        companion.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            companion_session.join().unwrap(),
            Ok(WindowsAttachSessionOutcome::Companion)
        );
        let (presenter_client, observed) = presenter_session.join().unwrap();
        assert_eq!(observed["workspace"], recorded.workspace);
        assert_eq!(observed["scopes"], serde_json::json!(recorded.scopes));
        drop(presenter_client);
        assert_eq!(
            presenter_server_thread.join().unwrap(),
            Ok(WindowsAttachSessionOutcome::ApprovalPresenter)
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
