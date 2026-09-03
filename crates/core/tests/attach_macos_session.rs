#[cfg(unix)]
mod unix_tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use muniment_core::attach::desktop_service_message::{
        CompanionProvenance, ThreadCreateAccepted,
    };
    use muniment_core::attach::thread_service::ThreadListService;
    use muniment_core::attach::{
        decode_frame, encode_frame, serve_macos_attach_session_with_reader, Authorization,
        DesktopClientAuthorizedGrant, Envelope, ErrorCode, ErrorEnvelope, Id,
        MacosAttachRouteReader, MacosAttachSessionError, MacosAttachSessionOutcome,
        MacosPeerReadError, Operation, Protocol, ProtocolError, Request, Welcome,
    };

    const CREATED_THREAD_ID: &str = "018f0000-0000-7000-8000-000000000200";

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
    }

    struct StubRouteReader {
        peer_pid: u32,
        image_path: PathBuf,
    }

    impl MacosAttachRouteReader for StubRouteReader {
        fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError> {
            Ok((self.peer_pid, self.image_path.clone()))
        }
    }

    fn route_reader(path: &str) -> StubRouteReader {
        StubRouteReader {
            peer_pid: 42,
            image_path: PathBuf::from(path),
        }
    }

    fn expected_desktop_executable() -> &'static Path {
        Path::new("/Applications/Muniment.app/Contents/MacOS/muniment")
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
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
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let session = std::thread::spawn(move || {
            let mut service = TestService::default();
            let outcome = serve_macos_attach_session_with_reader(
                &mut server,
                &route_reader("/Applications/Muniment.app/Contents/MacOS/muniment"),
                expected_desktop_executable(),
                "1.2.3",
                deadline(),
                &mut service,
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

        let request_id = Id::new("018f0000-0000-7000-8000-000000000101").unwrap();
        client
            .write_all(
                &encode_frame(&Request {
                    protocol: Protocol,
                    request_id: request_id.clone(),
                    operation: Operation::ThreadCreate,
                    capability: grant.capability,
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
                peer_uid: 0,
                peer_pid: 42,
            })
        );
    }

    #[test]
    fn presenter_route_writes_protocol_error() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame("desktop")).unwrap();
        let outcome = serve_macos_attach_session_with_reader(
            &mut server,
            &route_reader("/Applications/Muniment.app/Contents/MacOS/muniment"),
            expected_desktop_executable(),
            "1.2.3",
            deadline(),
            &mut TestService::default(),
        );

        assert_eq!(
            outcome,
            Err(MacosAttachSessionError::ApprovalPresenterUnavailable)
        );
        drop(server);
        let error_frame = read_frame(&mut client);
        let (error, consumed) = decode_frame::<ErrorEnvelope>(&error_frame)
            .unwrap()
            .unwrap();
        assert_eq!(consumed, error_frame.len());
        assert_eq!(error.error.code(), ErrorCode::Unauthorized);
        assert_eq!(client.read(&mut [0_u8]).unwrap(), 0);
    }

    #[test]
    fn other_desktop_client_kind_keeps_the_companion_exchange() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&hello_frame("editor-extension")).unwrap();
        let outcome = serve_macos_attach_session_with_reader(
            &mut server,
            &route_reader("/Applications/Muniment.app/Contents/MacOS/muniment"),
            expected_desktop_executable(),
            "1.2.3",
            deadline(),
            &mut TestService::default(),
        );

        assert_eq!(outcome, Ok(MacosAttachSessionOutcome::Companion));
        drop(server);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        let (welcome, consumed) = decode_frame::<Welcome>(&response).unwrap().unwrap();
        assert_eq!(consumed, response.len());
        assert_eq!(welcome.authorization, Authorization::PairingRequired);
        assert_eq!(welcome.desktop_version, "1.2.3");
    }
}
