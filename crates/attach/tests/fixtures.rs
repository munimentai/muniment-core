use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use std::sync::{atomic::AtomicBool, Arc};

use muniment_attach::fixtures::{export, open_generation, Mode, FIXTURE_DIRECTORY};
use muniment_attach::{DesktopClientAuthorizedGrant, Hello, Operation, Request};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "muniment-attach-fixtures-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_dir(root: &Path) -> PathBuf {
    root.join(FIXTURE_DIRECTORY)
}

#[test]
fn export_is_deterministic_and_replaces_obsolete_files() {
    let root = TestDirectory::new();
    export(&root.0, Mode::Write).unwrap();
    let before = read_fixtures(&fixture_dir(&root.0));
    fs::write(fixture_dir(&root.0).join("obsolete.json"), b"obsolete\n").unwrap();

    export(&root.0, Mode::Write).unwrap();

    assert_eq!(read_fixtures(&fixture_dir(&root.0)), before);
    assert!(before.iter().all(|(_, bytes)| {
        bytes.ends_with(b"\n") && !bytes[..bytes.len() - 1].ends_with(b"\n")
    }));
}

#[test]
fn export_includes_desktop_client_admission_fixtures() {
    let root = TestDirectory::new();
    export(&root.0, Mode::Write).unwrap();
    let directory = fixture_dir(&root.0);

    let hello: Hello = serde_json::from_slice(
        &fs::read(directory.join("negotiation-hello-desktop-client.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(hello.client.kind, "desktop-client");
    assert!(hello.authorized_client_credential.is_none());

    let grant: DesktopClientAuthorizedGrant = serde_json::from_slice(
        &fs::read(directory.join("authorization-desktop-client.json")).unwrap(),
    )
    .unwrap();
    assert!(!grant.profile_id.is_empty());
    assert_eq!(grant.capability.len(), 64);
    assert_eq!(grant.workspace_scopes.len(), 1);
}

#[test]
fn export_includes_thread_mutation_requests() {
    let root = TestDirectory::new();
    export(&root.0, Mode::Write).unwrap();
    let directory = fixture_dir(&root.0);

    for (name, operation) in [
        ("request-thread-rename.json", Operation::ThreadRename),
        ("request-thread-delete.json", Operation::ThreadDelete),
    ] {
        let request: Request =
            serde_json::from_slice(&fs::read(directory.join(name)).unwrap()).unwrap();
        assert_eq!(request.operation, operation);
        assert!(request.idempotency_key.is_some());
    }
}

#[test]
fn export_includes_second_tranche_requests() {
    let root = TestDirectory::new();
    export(&root.0, Mode::Write).unwrap();
    let directory = fixture_dir(&root.0);

    for (wire_name, operation, requires_idempotency_key) in [
        ("session.status", Operation::SessionStatus, false),
        (
            "entitlement.snapshot",
            Operation::EntitlementSnapshot,
            false,
        ),
        ("device.list", Operation::DeviceList, false),
        ("session.sign_out", Operation::SessionSignOut, true),
        ("companion.list", Operation::CompanionList, false),
        ("companion.revoke", Operation::CompanionRevoke, true),
    ] {
        let name = wire_name.replace(['.', '_'], "-");
        let request: Request = serde_json::from_slice(
            &fs::read(directory.join(format!("request-{name}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(request.operation, operation);
        assert_eq!(operation.as_str(), wire_name);
        assert_eq!(
            operation.requires_idempotency_key(),
            requires_idempotency_key
        );
        assert_eq!(request.idempotency_key.is_some(), requires_idempotency_key);
    }
}

#[test]
fn export_repairs_a_stale_regular_checkout_directory() {
    let expected_root = TestDirectory::new();
    export(&expected_root.0, Mode::Write).unwrap();
    let expected = read_fixtures(&fixture_dir(&expected_root.0));

    let root = TestDirectory::new();
    let live = fixture_dir(&root.0);
    fs::create_dir_all(&live).unwrap();
    fs::write(live.join("response-run-start.json"), b"{}\n").unwrap();
    fs::write(live.join("obsolete.json"), b"obsolete\n").unwrap();
    let stale = read_fixtures(&live);
    let running = Arc::new(AtomicBool::new(true));
    let reader_live = live.clone();
    let reader_running = Arc::clone(&running);
    let reader_expected = expected.clone();
    let reader = std::thread::spawn(move || {
        while reader_running.load(Ordering::Acquire) {
            let observed = read_fixtures(&reader_live);
            assert!(
                observed == stale || observed == reader_expected,
                "checkout migration exposed a missing or partial generation"
            );
        }
    });

    export(&root.0, Mode::Write).unwrap();
    running.store(false, Ordering::Release);
    reader.join().unwrap();

    assert_eq!(read_fixtures(&live), expected);
}

#[test]
fn replacement_never_exposes_a_missing_or_partial_live_directory() {
    let root = TestDirectory::new();
    export(&root.0, Mode::Write).unwrap();
    let expected = read_fixtures(&fixture_dir(&root.0));
    let running = Arc::new(AtomicBool::new(true));
    let reader_root = root.0.clone();
    let reader_running = Arc::clone(&running);
    let reader = std::thread::spawn(move || {
        while reader_running.load(Ordering::Acquire) {
            let live = fixture_dir(&reader_root);
            assert!(
                read_fixtures(&live) == expected,
                "every leased generation must be complete"
            );
        }
    });

    for _ in 0..500 {
        export(&root.0, Mode::Write).unwrap();
    }
    running.store(false, Ordering::Release);
    reader.join().unwrap();

    let generations = fs::read_dir(fixture_dir(&root.0).parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".1.generation.")
        })
        .count();
    assert!(
        generations <= 1,
        "completed reader leases must not prevent bounded reclamation"
    );
}

#[test]
fn an_open_generation_is_pinned_until_the_reader_finishes() {
    let root = TestDirectory::new();
    export(&root.0, Mode::Write).unwrap();
    let live = fixture_dir(&root.0);
    fs::write(live.join("obsolete.json"), b"obsolete\n").unwrap();

    let generation = open_generation(&live).unwrap();
    let stale = read_generation(generation.path());
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let exporter_root = root.0.clone();
    let exporter = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        export(&exporter_root, Mode::Write).unwrap();
        finished_tx.send(()).unwrap();
    });
    started_rx.recv().unwrap();

    assert_eq!(read_generation(generation.path()), stale);
    assert!(finished_rx.try_recv().is_err());
    drop(generation);
    finished_rx.recv().unwrap();
    exporter.join().unwrap();
    assert!(!live.join("obsolete.json").exists());
}

#[test]
fn next_export_recovers_interrupted_staging_without_disturbing_live_fixtures() {
    let root = TestDirectory::new();
    export(&root.0, Mode::Write).unwrap();
    let live = fixture_dir(&root.0);
    let expected = read_fixtures(&live);
    let stale = live.with_file_name(".1.staging.999999.42");
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("partial.json"), b"partial\n").unwrap();
    let displaced = live.with_file_name(".1.staging.999999.43.displaced");
    fs::create_dir(&displaced).unwrap();
    for (name, bytes) in &expected {
        fs::write(displaced.join(name), bytes).unwrap();
    }
    let abandoned_generation = {
        let path = live.with_file_name(".1.generation.999999.44");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("partial.json"), b"partial\n").unwrap();
        path
    };
    let running = Arc::new(AtomicBool::new(true));
    let reader_live = live.clone();
    let reader_running = Arc::clone(&running);
    let reader_expected = expected.clone();
    let reader = std::thread::spawn(move || {
        while reader_running.load(Ordering::Acquire) {
            assert_eq!(read_fixtures(&reader_live), reader_expected);
        }
    });

    export(&root.0, Mode::Write).unwrap();
    running.store(false, Ordering::Release);
    reader.join().unwrap();

    assert!(!stale.exists());
    assert!(!displaced.exists());
    assert!(!abandoned_generation.exists());
    assert_eq!(read_fixtures(&live), expected);
}

#[test]
fn check_rejects_a_missing_fixture_without_writing() {
    let root = TestDirectory::new();
    export(&root.0, Mode::Write).unwrap();
    let path = fixture_dir(&root.0).join("request-run-start.json");
    fs::remove_file(&path).unwrap();

    assert!(export(&root.0, Mode::Check).is_err());
    assert!(!path.exists());
}

#[test]
fn check_rejects_an_extra_fixture_without_writing() {
    let root = TestDirectory::new();
    export(&root.0, Mode::Write).unwrap();
    let path = fixture_dir(&root.0).join("extra.json");
    fs::write(&path, b"extra\n").unwrap();

    assert!(export(&root.0, Mode::Check).is_err());
    assert_eq!(fs::read(path).unwrap(), b"extra\n");
}

#[test]
fn check_rejects_a_byte_stale_fixture_without_writing() {
    let root = TestDirectory::new();
    export(&root.0, Mode::Write).unwrap();
    let path = fixture_dir(&root.0).join("response-run-start.json");
    fs::write(&path, b"{}\n").unwrap();

    assert!(export(&root.0, Mode::Check).is_err());
    assert_eq!(fs::read(path).unwrap(), b"{}\n");
}

fn read_fixtures(directory: &Path) -> Vec<(String, Vec<u8>)> {
    let generation = open_generation(directory).unwrap();
    read_generation(generation.path())
}

fn read_generation(directory: &Path) -> Vec<(String, Vec<u8>)> {
    let mut fixtures = fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    fixtures.sort_by(|left, right| left.0.cmp(&right.0));
    fixtures
}
