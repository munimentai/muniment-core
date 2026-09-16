#[cfg(unix)]
mod unix_tests {
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use muniment_core::attach::desktop_service_message::{
        CompanionProvenance, ThreadCreateAccepted,
    };
    use muniment_core::attach::live_connections::LiveConnectionRegistry;
    use muniment_core::attach::thread_service::ThreadListService;
    use muniment_core::attach::{
        approval_waiter_with_claims, decode_frame, encode_frame,
        serve_macos_attach_session_with_reader_and_state, Approval, ApprovalCoordinator,
        ApprovalDecision, Authorization, DesktopClientAdmissionError, DesktopClientAuthorizedGrant,
        Envelope, Id, MacosAttachRouteReader, MacosAttachSessionError, MacosAttachSessionOutcome,
        MacosPeerReadError, Operation, PeerAuthorizedGrant, Protocol, ProtocolError, Request,
        Welcome,
    };
    use muniment_core::record::CompanySummary;

    const CREATED_THREAD_ID: &str = "018f0000-0000-7000-8000-000000000200";
    const COMPANY_ID: &str = "019965a0-0000-7000-8000-000000000001";

    #[derive(Default)]
    struct TestService {
        bound_identity: Option<String>,
        create_provenance: Option<CompanionProvenance>,
    }

    impl ThreadListService for TestService {
        fn bind_authorized_client(&mut self, client_identity: &str) {
            self.bound_identity = Some(client_identity.to_owned());
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

        fn record_sql(
            &mut self,
            body: serde_json::Value,
            provenance: CompanionProvenance,
        ) -> Result<serde_json::Value, ProtocolError> {
            assert_eq!(provenance.companion_kind, "desktop-client");
            assert_eq!(body["sql"], "select 1 as n");
            Ok(
                serde_json::json!({"result": {"columns": ["n"], "csv": "n\n1\n", "row_count": 1, "truncated": false, "elapsed_ms": 0}}),
            )
        }

        fn list_companies(&mut self) -> Result<Vec<CompanySummary>, ProtocolError> {
            Ok(vec![CompanySummary {
                id: COMPANY_ID.to_owned(),
                name: "Northwind".to_owned(),
                created_at: "2026-01-01T00:00:00.000Z".to_owned(),
                owner_principal_id: "019965a0-0000-7000-8000-0000000000aa".to_owned(),
                current: true,
            }])
        }
    }

    struct StubRouteReader(Result<(u32, PathBuf), MacosPeerReadError>);

    impl MacosAttachRouteReader for StubRouteReader {
        fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError> {
            self.0.clone()
        }
    }

    fn route_reader(path: &str) -> StubRouteReader {
        StubRouteReader(Ok((42, PathBuf::from(path))))
    }

    fn expected_desktop_executable() -> &'static Path {
        Path::new("/Applications/Muniment.app/Contents/MacOS/muniment")
    }

    fn hello_frame(client_kind: &str) -> Vec<u8> {
        let body = format!(
            r#"{{"protocol":"muniment.attach/1","client":{{"kind":"{client_kind}","version":"0.0.1"}},"supported":{{"min":1,"max":1}},"client_nonce":"nonce","authorized_client_id":"018f0000-0000-7000-8000-000000000099"}}"#
        );
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body.as_bytes());
        frame
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
    fn desktop_route_serves_requests_with_live_peer_pid() {
        desktop_request_after_idle(Duration::from_secs(2), Duration::ZERO);
    }

    #[test]
    fn desktop_route_serves_a_request_after_the_handshake_bound() {
        desktop_request_after_idle(Duration::from_secs(1), Duration::from_secs(2));
    }

    fn desktop_request_after_idle(handshake_timeout: Duration, idle: Duration) {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let session = std::thread::spawn(move || {
            let mut service = TestService::default();
            let outcome = serve_macos_attach_session_with_reader_and_state(
                server,
                &route_reader("/Applications/Muniment.app/Contents/MacOS/muniment"),
                501,
                expected_desktop_executable(),
                "1.2.3",
                handshake_timeout,
                &mut service,
                None,
                ApprovalCoordinator::default(),
                approval_waiter_with_claims(
                    |_: &muniment_core::attach::PairingChallenge, _: &str, _: &str, _: Duration| {
                        None::<ApprovalDecision>
                    },
                ),
                &LiveConnectionRegistry::default(),
                |_| {},
            );
            (outcome, service)
        });
        client.write_all(&hello_frame("desktop-client")).unwrap();

        let welcome_frame = read_frame(&mut client);
        let (welcome, consumed) = decode_frame::<Welcome>(&welcome_frame).unwrap().unwrap();
        assert_eq!(consumed, welcome_frame.len());
        assert_eq!(welcome.authorization, Authorization::Authorized);

        let grant_frame = read_frame(&mut client);
        let (grant, consumed) = decode_frame::<DesktopClientAuthorizedGrant>(&grant_frame)
            .unwrap()
            .unwrap();
        assert_eq!(consumed, grant_frame.len());

        std::thread::sleep(idle);
        assert!(
            !session.is_finished(),
            "the admitted desktop session closed while idle"
        );

        let request_id = Id::new("018f0000-0000-7000-8000-000000000101").unwrap();
        client
            .write_all(
                &encode_frame(&Request {
                    protocol: Protocol,
                    request_id: request_id.clone(),
                    operation: Operation::ThreadCreate,
                    capability: grant.capability.clone(),
                    idempotency_key: Some(Id::new("018f0000-0000-7000-8000-000000000102").unwrap()),
                    body: serde_json::json!({}),
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
        assert_eq!(
            response.body,
            serde_json::json!({"thread_id": CREATED_THREAD_ID})
        );

        let list_id = Id::new("018f0000-0000-7000-8000-000000000103").unwrap();
        client
            .write_all(
                &encode_frame(&Request {
                    protocol: Protocol,
                    request_id: list_id.clone(),
                    operation: Operation::CompanyList,
                    capability: grant.capability.clone(),
                    idempotency_key: None,
                    body: serde_json::json!({}),
                })
                .unwrap(),
            )
            .unwrap();
        let list_frame = read_frame(&mut client);
        let (Envelope::Response(list), _) = decode_frame::<Envelope>(&list_frame).unwrap().unwrap()
        else {
            panic!("expected a company list response");
        };
        assert_eq!(list.request_id, list_id);
        assert_eq!(list.body["current"], COMPANY_ID);
        assert_eq!(list.body["companies"][0]["name"], "Northwind");

        let sql_id = Id::new("018f0000-0000-7000-8000-000000000104").unwrap();
        client
            .write_all(
                &encode_frame(&Request {
                    protocol: Protocol,
                    request_id: sql_id.clone(),
                    operation: Operation::RecordSql,
                    capability: grant.capability.clone(),
                    idempotency_key: None,
                    body: serde_json::json!({"sql": "select 1 as n"}),
                })
                .unwrap(),
            )
            .unwrap();
        let sql_frame = read_frame(&mut client);
        let (Envelope::Response(sql), _) = decode_frame::<Envelope>(&sql_frame).unwrap().unwrap()
        else {
            panic!("expected a record.sql response");
        };
        assert_eq!(sql.request_id, sql_id);
        assert_eq!(sql.body["result"]["csv"], "n\n1\n");

        client.shutdown(Shutdown::Write).unwrap();
        let (outcome, service) = session.join().unwrap();
        let MacosAttachSessionOutcome::DesktopClient(admitted) = outcome.unwrap() else {
            panic!("expected the desktop client route");
        };
        assert_eq!(service.bound_identity, Some(admitted.client_identity));
        assert_eq!(
            service.create_provenance,
            Some(CompanionProvenance {
                profile: "desktop-owner".into(),
                companion_kind: "desktop-client".into(),
                companion_version: "0.0.1".into(),
                peer_uid: 501,
                peer_pid: 42,
            })
        );
    }

    #[test]
    fn handshake_bound_rejects_silent_and_partial_first_frames() {
        for bytes in [vec![], vec![0], vec![0, 0, 0, 10, b'{']] {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.write_all(&bytes).unwrap();
            let outcome = serve_macos_attach_session_with_reader_and_state(
                server,
                &route_reader("/Applications/Muniment.app/Contents/MacOS/muniment"),
                501,
                expected_desktop_executable(),
                "1.2.3",
                Duration::from_millis(100),
                &mut TestService::default(),
                None,
                ApprovalCoordinator::default(),
                approval_waiter_with_claims(
                    |_: &muniment_core::attach::PairingChallenge, _: &str, _: &str, _: Duration| {
                        None::<ApprovalDecision>
                    },
                ),
                &LiveConnectionRegistry::default(),
                |_| {},
            );
            let expected = if bytes.len() < 4 {
                MacosAttachSessionError::Read
            } else {
                MacosAttachSessionError::DesktopClientAdmission(
                    DesktopClientAdmissionError::Timeout,
                )
            };
            assert_eq!(outcome, Err(expected));
        }
    }

    fn run_companion_session(route_reader: StubRouteReader) -> (String, CompanionProvenance) {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let session = std::thread::spawn(move || {
            let mut service = TestService::default();
            let mut pairing_identity = None;
            let approval = Approval {
                profile: "profile-1".into(),
                workspace: "workspace-1".into(),
                scopes: BTreeSet::from(["run.write".into()]),
                lifetime: Duration::from_secs(60),
            };
            let outcome = serve_macos_attach_session_with_reader_and_state(
                server,
                &route_reader,
                501,
                expected_desktop_executable(),
                "1.2.3",
                Duration::from_secs(2),
                &mut service,
                Some(approval.clone()),
                ApprovalCoordinator::default(),
                approval_waiter_with_claims(
                    move |_: &muniment_core::attach::PairingChallenge,
                          _: &str,
                          _: &str,
                          _: Duration| {
                        Some(ApprovalDecision::Approve(approval.clone()))
                    },
                ),
                &LiveConnectionRegistry::default(),
                |identity| pairing_identity = Some(identity.to_owned()),
            );
            (outcome, service, pairing_identity)
        });
        client.write_all(&hello_frame("editor-extension")).unwrap();

        let _: Welcome = decode_frame(&read_frame(&mut client)).unwrap().unwrap().0;
        let authorized: muniment_core::attach::Authorized =
            decode_frame(&read_frame(&mut client)).unwrap().unwrap().0;
        let request_id = Id::new("018f0000-0000-7000-8000-000000000103").unwrap();
        client
            .write_all(
                &encode_frame(&Request {
                    protocol: Protocol,
                    request_id: request_id.clone(),
                    operation: Operation::ThreadCreate,
                    capability: authorized.capability,
                    idempotency_key: Some(Id::new("018f0000-0000-7000-8000-000000000104").unwrap()),
                    body: serde_json::json!({}),
                })
                .unwrap(),
            )
            .unwrap();
        let _ = read_frame(&mut client);
        client.shutdown(Shutdown::Write).unwrap();

        let (outcome, service, pairing_identity) = session.join().unwrap();
        assert_eq!(outcome, Ok(MacosAttachSessionOutcome::Companion));
        assert_eq!(
            service.bound_identity.as_deref(),
            Some("018f0000-0000-7000-8000-000000000099")
        );
        (
            pairing_identity.unwrap(),
            service.create_provenance.unwrap(),
        )
    }

    #[test]
    fn companion_route_records_the_verified_peer_identity() {
        let (pairing_identity, provenance) =
            run_companion_session(route_reader("/Applications/Other.app/Contents/MacOS/other"));

        assert_eq!(pairing_identity, "501:42");
        assert_eq!(provenance.peer_uid, 501);
        assert_eq!(provenance.peer_pid, 42);
    }

    #[test]
    fn failed_route_read_records_zero_peer_pid() {
        let (pairing_identity, provenance) =
            run_companion_session(StubRouteReader(Err(MacosPeerReadError)));

        assert_eq!(pairing_identity, "501:0");
        assert_eq!(provenance.peer_uid, 501);
        assert_eq!(provenance.peer_pid, 0);
    }

    #[test]
    fn presenter_route_rejects_a_second_presenter() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame("desktop")).unwrap();
        let coordinator = ApprovalCoordinator::default();
        let _presenter = coordinator.claim_presenter(|_| false).unwrap();
        let outcome = serve_macos_attach_session_with_reader_and_state(
            server,
            &route_reader("/Applications/Muniment.app/Contents/MacOS/muniment"),
            501,
            expected_desktop_executable(),
            "1.2.3",
            Duration::from_secs(2),
            &mut TestService::default(),
            None,
            coordinator,
            approval_waiter_with_claims(
                |_: &muniment_core::attach::PairingChallenge, _: &str, _: &str, _: Duration| {
                    None::<ApprovalDecision>
                },
            ),
            &LiveConnectionRegistry::default(),
            |_| {},
        );

        assert_eq!(
            outcome,
            Err(MacosAttachSessionError::ApprovalPresenterUnavailable)
        );
        let _: Welcome = decode_frame(&read_frame(&mut client)).unwrap().unwrap().0;
        let _: PeerAuthorizedGrant = decode_frame(&read_frame(&mut client)).unwrap().unwrap().0;
        assert_eq!(client.read(&mut [0_u8]).unwrap(), 0);
    }

    // The desktop's presenter handshake parses the grant as a peer grant and
    // refuses one that names a profile, so the presenter route must write the
    // peer shape or the presenter never connects.
    #[test]
    fn presenter_route_grants_a_peer_grant_without_workspace_authority() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame("desktop")).unwrap();
        let coordinator = ApprovalCoordinator::default();
        let session_coordinator = coordinator.clone();
        let session = std::thread::spawn(move || {
            serve_macos_attach_session_with_reader_and_state(
                server,
                &route_reader("/Applications/Muniment.app/Contents/MacOS/muniment"),
                501,
                expected_desktop_executable(),
                "1.2.3",
                Duration::from_secs(2),
                &mut TestService::default(),
                None,
                session_coordinator,
                approval_waiter_with_claims(
                    |_: &muniment_core::attach::PairingChallenge, _: &str, _: &str, _: Duration| {
                        None::<ApprovalDecision>
                    },
                ),
                &LiveConnectionRegistry::default(),
                |_| {},
            )
        });

        let welcome: Welcome = decode_frame(&read_frame(&mut client)).unwrap().unwrap().0;
        assert_eq!(welcome.authorization, Authorization::Authorized);
        let grant: PeerAuthorizedGrant = decode_frame(&read_frame(&mut client)).unwrap().unwrap().0;
        assert_eq!(grant.capability.len(), 64);
        assert!(grant.expires_at > 0 && grant.expires_at <= 8 * 60 * 60);
        assert!(grant.idle_timeout_seconds > 0 && grant.idle_timeout_seconds <= 15 * 60);
        assert!(coordinator.claim_presenter(|_| true).is_none());

        drop(client);
        assert_eq!(
            session.join().unwrap(),
            Ok(MacosAttachSessionOutcome::ApprovalPresenter)
        );
        assert!(coordinator.claim_presenter(|_| true).is_some());
    }

    #[test]
    fn other_desktop_client_kind_uses_the_pairing_welcome_challenge() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame("editor-extension")).unwrap();
        let outcome = serve_macos_attach_session_with_reader_and_state(
            server,
            &route_reader("/Applications/Muniment.app/Contents/MacOS/muniment"),
            501,
            expected_desktop_executable(),
            "1.2.3",
            Duration::from_secs(2),
            &mut TestService::default(),
            None,
            ApprovalCoordinator::default(),
            approval_waiter_with_claims(
                |_: &muniment_core::attach::PairingChallenge, _: &str, _: &str, _: Duration| {
                    None::<ApprovalDecision>
                },
            ),
            &LiveConnectionRegistry::default(),
            |_| {},
        );

        assert_eq!(outcome, Ok(MacosAttachSessionOutcome::Companion));
        let welcome_frame = read_frame(&mut client);
        let (welcome, consumed) = decode_frame::<Welcome>(&welcome_frame).unwrap().unwrap();
        assert_eq!(consumed, welcome_frame.len());
        assert_eq!(welcome.authorization, Authorization::PairingRequired);
        assert_eq!(welcome.desktop_version, "1.2.3");
        assert_eq!(welcome.approval_challenge.len(), 32);
    }
}
