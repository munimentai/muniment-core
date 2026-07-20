#![cfg(target_os = "linux")]

use muniment_core::attach::linux::{
    run_authenticated_session_with, AttachAcceptError, AttachFilesystem, AttachTransport,
    AttachTransportError, PeerCredentials,
};
use muniment_core::attach::{
    decode_frame, encode_frame, Client, Hello, Id, Protocol, VersionRange, Welcome,
};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "muniment-attach-transport-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn publishes_authenticates_and_removes_a_private_socket() {
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let transport = AttachTransport::bind(&filesystem).unwrap();
    let metadata = fs::symlink_metadata(filesystem.endpoint_path()).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.mode() & 0o777, 0o600);

    let client = UnixStream::connect(filesystem.endpoint_path()).unwrap();
    let (_stream, peer) = transport.accept().unwrap();
    assert_eq!(peer.pid, std::process::id() as libc::pid_t);
    assert_eq!(peer.uid, unsafe { libc::geteuid() });
    assert_eq!(peer.gid, unsafe { libc::getegid() });
    drop(client);

    drop(transport);
    assert!(!filesystem.endpoint_path().exists());
}

#[test]
fn authenticated_pathname_peer_negotiates_then_closes() {
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let transport = AttachTransport::bind(&filesystem).unwrap();
    let mut client = UnixStream::connect(transport.local_path()).unwrap();
    let hello = encode_frame(&Hello {
        protocol: Protocol,
        client: Client {
            kind: "cli".into(),
            version: "1.0.0".into(),
        },
        supported: VersionRange { min: 1, max: 1 },
        client_nonce: "client-nonce".into(),
        authorized_client_id: Id::new("018f0000-0000-7000-8000-000000000099").unwrap(),
        authorized_client_credential: None,
    })
    .unwrap();
    for fragment in hello.chunks(3) {
        client.write_all(fragment).unwrap();
    }

    // The session receives only the stream and credentials produced by authenticated accept.
    let (server, peer) = transport.accept().unwrap();
    assert_eq!(peer.uid, unsafe { libc::geteuid() });
    run_authenticated_session_with(server, peer, "0.1.0", Duration::from_secs(1), |bytes| {
        bytes.fill(7);
        Ok(())
    })
    .unwrap();

    let mut prefix = [0; 4];
    client.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0; 4 + u32::from_be_bytes(prefix) as usize];
    frame[..4].copy_from_slice(&prefix);
    client.read_exact(&mut frame[4..]).unwrap();
    let welcome: Welcome = decode_frame(&frame).unwrap().unwrap().0;
    assert_eq!(welcome.selected, 1);
    assert_eq!(welcome.desktop_version, "0.1.0");
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn refuses_a_live_listener_and_recovers_a_stale_socket() {
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let first = AttachTransport::bind(&filesystem).unwrap();
    assert_eq!(
        AttachTransport::bind(&filesystem).unwrap_err(),
        AttachTransportError::ExistingListener
    );
    drop(first);

    let stale = UnixListener::bind(filesystem.endpoint_path()).unwrap();
    fs::set_permissions(
        filesystem.endpoint_path(),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    drop(stale);
    let recovered = AttachTransport::bind(&filesystem).unwrap();
    drop(recovered);
}

#[test]
fn stale_recovery_preserves_a_colliding_quarantine_entry() {
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let stale = UnixListener::bind(filesystem.endpoint_path()).unwrap();
    drop(stale);
    let attach_directory = filesystem.endpoint_path().parent().unwrap().to_owned();
    let mut candidate_count = 0;

    let mut recovered = None;
    for _ in 0..3 {
        match AttachTransport::bind_with_quarantine_candidate_hook(
            &filesystem,
            || {},
            || {},
            || {},
            |candidate| {
                candidate_count += 1;
                if candidate_count == 1 {
                    fs::write(attach_directory.join(candidate), b"unrelated").unwrap();
                }
            },
        ) {
            Ok(transport) => {
                recovered = Some(transport);
                break;
            }
            // A just-closed Unix listener can briefly remain connectable. Retry the
            // stale probe without weakening the production live-listener check.
            Err(AttachTransportError::ExistingListener) => continue,
            Err(error) => panic!("stale recovery failed: {error:?}"),
        }
    }
    let recovered = recovered.expect("closed stale listener was repeatedly reported as live");

    assert!(candidate_count >= 2);
    let unrelated: Vec<_> = fs::read_dir(&attach_directory)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            (fs::read(&path).ok().as_deref() == Some(b"unrelated")).then_some(path)
        })
        .collect();
    assert_eq!(unrelated.len(), 1);
    drop(recovered);
    assert_eq!(fs::read(&unrelated[0]).unwrap(), b"unrelated");
    assert!(!filesystem.endpoint_path().exists());
}

#[test]
fn refuses_unsafe_entries_and_preserves_replacements_on_drop() {
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    fs::write(filesystem.endpoint_path(), b"unrelated").unwrap();
    assert_eq!(
        AttachTransport::bind(&filesystem).unwrap_err(),
        AttachTransportError::ExistingEndpointUnsafe
    );
    fs::remove_file(filesystem.endpoint_path()).unwrap();

    let transport = AttachTransport::bind(&filesystem).unwrap();
    fs::remove_file(filesystem.endpoint_path()).unwrap();
    fs::write(filesystem.endpoint_path(), b"replacement").unwrap();
    drop(transport);
    assert_eq!(
        fs::read(filesystem.endpoint_path()).unwrap(),
        b"replacement"
    );
}

#[test]
fn refuses_directories_and_symlinks() {
    for create in [
        |path: &std::path::Path| fs::create_dir(path).unwrap(),
        |path: &std::path::Path| symlink(path.parent().unwrap(), path).unwrap(),
    ] {
        let runtime = TestDirectory::new();
        let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
        create(filesystem.endpoint_path());
        assert_eq!(
            AttachTransport::bind(&filesystem).unwrap_err(),
            AttachTransportError::ExistingEndpointUnsafe
        );
    }
}

#[test]
fn refuses_a_wrong_owner_socket_when_test_process_can_change_ownership() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let stale = UnixListener::bind(filesystem.endpoint_path()).unwrap();
    drop(stale);
    assert_eq!(
        unsafe { libc::chown(path_c_string(filesystem.endpoint_path()).as_ptr(), 1, 0) },
        0
    );
    assert_eq!(
        AttachTransport::bind(&filesystem).unwrap_err(),
        AttachTransportError::ExistingEndpointUnsafe
    );
}

#[test]
fn bind_verification_never_removes_a_replacement() {
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let error = AttachTransport::bind_with_hooks(
        &filesystem,
        || {
            fs::remove_file(filesystem.endpoint_path()).unwrap();
            fs::write(filesystem.endpoint_path(), b"replacement").unwrap();
        },
        || {},
    )
    .unwrap_err();
    assert_eq!(error, AttachTransportError::Permissions);
    assert_eq!(
        fs::read(filesystem.endpoint_path()).unwrap(),
        b"replacement"
    );
}

#[test]
fn stale_recovery_never_removes_a_replacement() {
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let stale = UnixListener::bind(filesystem.endpoint_path()).unwrap();
    drop(stale);
    for _ in 0..3 {
        let error = AttachTransport::bind_with_hooks(
            &filesystem,
            || {},
            || {
                fs::remove_file(filesystem.endpoint_path()).unwrap();
                fs::write(filesystem.endpoint_path(), b"replacement").unwrap();
            },
        )
        .unwrap_err();
        if error == AttachTransportError::ExistingListener {
            continue;
        }
        assert_eq!(error, AttachTransportError::ExistingEndpointRemove);
        assert_eq!(
            fs::read(filesystem.endpoint_path()).unwrap(),
            b"replacement"
        );
        return;
    }
    panic!("closed stale listener was repeatedly reported as live");
}

#[test]
fn stale_recovery_rollback_never_overwrites_a_raced_in_endpoint() {
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let stale = UnixListener::bind(filesystem.endpoint_path()).unwrap();
    drop(stale);
    let attach_directory = filesystem.endpoint_path().parent().unwrap().to_owned();
    let error = AttachTransport::bind_with_race_hooks(
        &filesystem,
        || {},
        || {},
        || {
            let quarantine = fs::read_dir(&attach_directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".attach-v1.sock.")
                })
                .unwrap();
            fs::remove_file(&quarantine).unwrap();
            fs::write(&quarantine, b"quarantined replacement").unwrap();
            fs::write(filesystem.endpoint_path(), b"endpoint replacement").unwrap();
        },
    )
    .unwrap_err();
    assert_eq!(error, AttachTransportError::ExistingEndpointRemove);

    let contents: Vec<Vec<u8>> = fs::read_dir(&attach_directory)
        .unwrap()
        .map(|entry| fs::read(entry.unwrap().path()).unwrap())
        .collect();
    assert_eq!(contents.len(), 2);
    assert!(contents.contains(&b"quarantined replacement".to_vec()));
    assert!(contents.contains(&b"endpoint replacement".to_vec()));
}

#[test]
fn shutdown_check_remove_race_preserves_a_replacement() {
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let transport = AttachTransport::bind(&filesystem).unwrap();
    transport.shutdown_with_hook(|| {
        fs::remove_file(filesystem.endpoint_path()).unwrap();
        fs::write(filesystem.endpoint_path(), b"replacement").unwrap();
    });
    assert_eq!(
        fs::read(filesystem.endpoint_path()).unwrap(),
        b"replacement"
    );
}

#[test]
fn rejects_a_different_uid_peer_with_complete_diagnostics_when_permitted() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let runtime = TestDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let transport = AttachTransport::bind(&filesystem).unwrap();
    // Socket permissions normally reject other UIDs before accept. Root temporarily
    // opens the test endpoint so the transport's independent credential check runs.
    fs::set_permissions(&runtime.0, fs::Permissions::from_mode(0o711)).unwrap();
    fs::set_permissions(
        filesystem.endpoint_path().parent().unwrap(),
        fs::Permissions::from_mode(0o711),
    )
    .unwrap();
    fs::set_permissions(
        filesystem.endpoint_path(),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let uid = 1;
        if unsafe { libc::setgid(uid) } != 0 || unsafe { libc::setuid(uid) } != 0 {
            unsafe { libc::_exit(2) };
        }
        let status = if UnixStream::connect(filesystem.endpoint_path()).is_ok() {
            0
        } else {
            3
        };
        unsafe { libc::_exit(status) };
    }
    let expected = PeerCredentials {
        pid: child,
        uid: 1,
        gid: 1,
    };
    assert_eq!(
        transport.accept().unwrap_err(),
        AttachAcceptError::WrongUid(expected)
    );
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

#[test]
fn displayed_errors_do_not_disclose_runtime_paths() {
    let error = AttachTransportError::EndpointMetadata;
    assert!(!error.to_string().contains("/"));
}

fn path_c_string(path: &std::path::Path) -> std::ffi::CString {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap()
}
