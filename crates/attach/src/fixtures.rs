use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use serde::Serialize;
use serde_json::json;

use crate::{
    Authorization, Client, DesktopClientAuthorizedGrant, ErrorEnvelope, Event, EventName, Failure,
    Hello, Id, Operation, Protocol, ProtocolError, Request, Response, Success, VersionRange,
    Welcome,
};

pub const FIXTURE_DIRECTORY: &str = "muniment.attach/1";
static NEXT_EXPORT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Write,
    Check,
}

/// A stable view of one published fixture generation.
///
/// The shared publication lock is held until this value is dropped, so an
/// exporter cannot replace or reclaim the directory while a reader enumerates
/// and opens its files. Readers must resolve child paths through [`Self::path`]
/// rather than through `muniment.attach/1` again.
pub struct FixtureGeneration {
    path: PathBuf,
    _lock: File,
}

impl FixtureGeneration {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn open_generation(directory: &Path) -> io::Result<FixtureGeneration> {
    let lock_path = publication_lock_path(directory)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock_shared(&lock)?;
    let path = fs::canonicalize(directory)?;
    Ok(FixtureGeneration { path, _lock: lock })
}

pub fn export(root: &Path, mode: Mode) -> io::Result<()> {
    let expected = fixture_bytes()?;
    let target = root.join(FIXTURE_DIRECTORY);
    if mode == Mode::Check {
        if !target.exists() {
            return check(&target, &expected);
        }
        let generation = open_generation(&target)?;
        return check(generation.path(), &expected);
    }

    let parent = target
        .parent()
        .expect("the fixture directory always has a parent");
    fs::create_dir_all(parent)?;
    let _export_lock = ExportLock::acquire(&publication_lock_path(&target)?)?;
    remove_stale_staging(parent)?;
    remove_stale_generations(parent, &target)?;
    let export_id = NEXT_EXPORT.fetch_add(1, Ordering::Relaxed);
    let staging = sibling_path(&target, "staging", export_id);
    remove_if_present(&staging)?;
    fs::create_dir(&staging)?;
    for (name, bytes) in &expected {
        fs::write(staging.join(name), bytes)?;
    }

    publish(&staging, &target)?;
    // An exchange leaves the displaced directory at `staging`. Keep it for
    // readers that enumerated that generation before publication. Generations
    // from a previous exporter process are recovered on the next run.
    if staging.exists() {
        fs::rename(&staging, sibling_path(&target, "generation", export_id))?;
    }
    Ok(())
}

fn publication_lock_path(target: &Path) -> io::Result<PathBuf> {
    let parent = fs::canonicalize(
        target
            .parent()
            .expect("the fixture directory always has a parent"),
    )?;
    let identity = parent.join(
        target
            .file_name()
            .expect("the fixture directory always has a name"),
    );
    let hash = publication_identity_hash(&identity);
    Ok(std::env::temp_dir().join(format!("muniment-attach-fixtures-{hash:016x}.lock")))
}

#[cfg(unix)]
fn publication_identity_hash(identity: &Path) -> u64 {
    use std::os::unix::ffi::OsStrExt;

    identity
        .as_os_str()
        .as_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

#[cfg(windows)]
fn publication_identity_hash(identity: &Path) -> u64 {
    use std::os::windows::ffi::OsStrExt;

    identity
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

struct ExportLock {
    _file: File,
}

impl ExportLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        lock_exclusive(&file)?;
        Ok(Self { _file: file })
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    const LOCK_EX: i32 = 2;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    // SAFETY: flock only borrows the valid descriptor for the duration of the call.
    if unsafe { flock(file.as_raw_fd(), LOCK_EX) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn lock_shared(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    const LOCK_SH: i32 = 1;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    // SAFETY: flock only borrows the valid descriptor for the duration of the call.
    if unsafe { flock(file.as_raw_fd(), LOCK_SH) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_exclusive(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut core::ffi::c_void,
    }
    unsafe extern "system" {
        fn LockFileEx(
            file: *mut core::ffi::c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;
    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: std::ptr::null_mut(),
    };
    // SAFETY: the file and stack-allocated OVERLAPPED remain valid until the
    // synchronous lock request completes.
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            1,
            0,
            &mut overlapped,
        )
    } != 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_shared(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut core::ffi::c_void,
    }
    unsafe extern "system" {
        fn LockFileEx(
            file: *mut core::ffi::c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }
    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: std::ptr::null_mut(),
    };
    // SAFETY: the file and stack-allocated OVERLAPPED remain valid until the
    // synchronous lock request completes.
    if unsafe { LockFileEx(file.as_raw_handle(), 0, 0, 1, 0, &mut overlapped) } != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn remove_stale_staging(parent: &Path) -> io::Result<()> {
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".1.staging.")
        {
            remove_if_present(&entry.path())?;
        }
    }
    Ok(())
}

fn remove_stale_generations(parent: &Path, target: &Path) -> io::Result<()> {
    let live = fs::canonicalize(target).ok();
    // The exclusive publication lock proves that no reader holding an
    // `open_generation` lease can still address an older generation. This is
    // safe for generations left by this process and by a crashed exporter.
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(".1.generation.")
        {
            continue;
        }
        if live.as_ref() != Some(&fs::canonicalize(entry.path())?) {
            remove_if_present(&entry.path())?;
        }
    }
    Ok(())
}

fn publish(staging: &Path, target: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return atomic_exchange(staging, target);

    #[cfg(not(windows))]
    if !target.exists() {
        return fs::rename(staging, target);
    }

    #[cfg(not(windows))]
    atomic_exchange(staging, target)
}

#[cfg(target_os = "linux")]
fn atomic_exchange(left: &Path, right: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    const AT_FDCWD: i32 = -100;
    const RENAME_EXCHANGE: u32 = 2;
    unsafe extern "C" {
        fn renameat2(
            olddirfd: i32,
            oldpath: *const i8,
            newdirfd: i32,
            newpath: *const i8,
            flags: u32,
        ) -> i32;
    }

    let left = CString::new(left.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let right = CString::new(right.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: both C strings remain alive for the call, and renameat2 retains
    // neither pointer.
    if unsafe {
        renameat2(
            AT_FDCWD,
            left.as_ptr(),
            AT_FDCWD,
            right.as_ptr(),
            RENAME_EXCHANGE,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn atomic_exchange(left: &Path, right: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    const RENAME_SWAP: u32 = 0x0000_0002;
    unsafe extern "C" {
        fn renamex_np(from: *const i8, to: *const i8, flags: u32) -> i32;
    }

    let left = CString::new(left.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let right = CString::new(right.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: both C strings remain alive for the call, and renamex_np retains
    // neither pointer.
    if unsafe { renamex_np(left.as_ptr(), right.as_ptr(), RENAME_SWAP) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn atomic_exchange(left: &Path, right: &Path) -> io::Result<()> {
    if !right.exists() {
        return fs::rename(left, right);
    }
    replace_directory(left, right)
}

#[cfg(windows)]
fn replace_directory(source: &Path, destination: &Path) -> io::Result<()> {
    if !source.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fixture generation is not a directory",
        ));
    }

    let displaced = source.with_extension("displaced");
    remove_if_present(&displaced)?;
    fs::rename(destination, &displaced)?;
    if let Err(error) = fs::rename(source, destination) {
        fs::rename(&displaced, destination)?;
        return Err(error);
    }
    if let Err(error) = fs::rename(&displaced, source) {
        // Publication succeeded, but retain an exporter-owned name so the next
        // run can reclaim the displaced generation.
        return Err(error);
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::replace_directory;
    use std::fs;

    #[test]
    fn failed_atomic_publication_preserves_the_original_target() {
        let root = std::env::temp_dir().join(format!(
            "muniment-attach-publication-failure-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let source = root.join("not-a-directory");
        fs::write(&source, b"replacement").unwrap();
        let target = root.join("live");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("original.json"), b"original\n").unwrap();

        assert!(replace_directory(&source, &target).is_err());
        assert_eq!(
            fs::read(target.join("original.json")).unwrap(),
            b"original\n"
        );
        assert_eq!(fs::read(&source).unwrap(), b"replacement");
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios", windows)))]
compile_error!("atomic fixture publication is not implemented for this platform");

fn fixture_bytes() -> io::Result<BTreeMap<String, Vec<u8>>> {
    let mut fixtures = BTreeMap::new();
    insert(
        &mut fixtures,
        "negotiation-hello.json",
        &Hello {
            protocol: Protocol,
            client: Client {
                kind: "editor-extension".into(),
                version: "0.0.1".into(),
            },
            supported: VersionRange { min: 1, max: 1 },
            client_nonce: "fixture-client-nonce".into(),
            authorized_client_id: Id::new("018f0000-0000-7000-8000-000000000099").unwrap(),
            authorized_client_credential: None,
        },
    )?;
    insert(
        &mut fixtures,
        "negotiation-hello-desktop-client.json",
        &Hello {
            protocol: Protocol,
            client: Client {
                kind: "desktop-client".into(),
                version: "0.0.1".into(),
            },
            supported: VersionRange { min: 1, max: 1 },
            client_nonce: "fixture-client-nonce".into(),
            authorized_client_id: Id::new("018f0000-0000-7000-8000-000000000097").unwrap(),
            authorized_client_credential: None,
        },
    )?;
    insert(
        &mut fixtures,
        "negotiation-welcome.json",
        &Welcome {
            selected: 1,
            desktop_version: "0.0.1".into(),
            server_nonce: "fixture-server-nonce".into(),
            authorization: Authorization::PairingRequired,
            approval_challenge: "fixture-challenge".into(),
            handoff_nonce: None,
        },
    )?;
    insert(
        &mut fixtures,
        "negotiation-welcome-handoff.json",
        &Welcome {
            selected: 1,
            desktop_version: "0.0.1".into(),
            server_nonce: "fixture-server-nonce".into(),
            authorization: Authorization::PairingRequired,
            approval_challenge: "fixture-challenge".into(),
            handoff_nonce: Some("fixture-handoff-nonce".into()),
        },
    )?;
    insert(
        &mut fixtures,
        "authorization-authorized.json",
        &crate::authorized(
            "018f0000-0000-7000-8000-000000000098",
            "fixture-capability",
            3600,
            900,
            [("workspace-1".into(), BTreeSet::from(["thread.read".into()]))]
                .into_iter()
                .collect(),
        ),
    )?;
    insert(
        &mut fixtures,
        "authorization-desktop-client.json",
        &DesktopClientAuthorizedGrant {
            profile_id: "profile-1".into(),
            capability: "33".repeat(32),
            expires_at: 60,
            idle_timeout_seconds: 30,
            workspace_scopes: [(
                "/work/signed".into(),
                BTreeSet::from(["threads:read".into()]),
            )]
            .into_iter()
            .collect(),
        },
    )?;

    let operations = [
        ("thread-list", Operation::ThreadList),
        ("thread-open", Operation::ThreadOpen),
        ("run-open", Operation::RunOpen),
        ("run-start", Operation::RunStart),
        ("run-stream", Operation::RunStream),
        ("run-cursor-ack", Operation::RunCursorAck),
        ("run-steer", Operation::RunSteer),
        ("run-follow-up", Operation::RunFollowUp),
        ("run-cancel", Operation::RunCancel),
        ("permission-answer", Operation::PermissionAnswer),
        ("artifact-fetch", Operation::ArtifactFetch),
        ("artifact-window", Operation::ArtifactWindow),
        ("request-cancel", Operation::RequestCancel),
        ("thread-create", Operation::ThreadCreate),
        ("migration-control", Operation::MigrationControl),
        ("approval-present", Operation::ApprovalPresent),
        ("thread-rename", Operation::ThreadRename),
        ("thread-delete", Operation::ThreadDelete),
        ("session-status", Operation::SessionStatus),
        ("entitlement-snapshot", Operation::EntitlementSnapshot),
        ("device-list", Operation::DeviceList),
        ("session-sign-out", Operation::SessionSignOut),
        ("companion-list", Operation::CompanionList),
        ("companion-revoke", Operation::CompanionRevoke),
        ("session-sign-in", Operation::SessionSignIn),
        ("thread-summaries", Operation::ThreadSummaries),
        ("thread-history", Operation::ThreadHistory),
        ("run-chat-events", Operation::RunChatEvents),
        ("run-submit", Operation::RunSubmit),
        ("run-resume", Operation::RunResume),
        ("run-permission-answer", Operation::RunPermissionAnswer),
        ("thread-select", Operation::ThreadSelect),
        ("retention-recheck", Operation::RetentionRecheck),
    ];
    for (index, (name, operation)) in operations.into_iter().enumerate() {
        insert(
            &mut fixtures,
            &format!("request-{name}.json"),
            &Request {
                protocol: Protocol,
                request_id: id(100 + index as u128)?,
                operation,
                capability: "fixture-capability".into(),
                idempotency_key: operation
                    .requires_idempotency_key()
                    .then(|| id(200 + index as u128))
                    .transpose()?,
                body: request_body(operation),
            },
        )?;
    }
    insert(
        &mut fixtures,
        "response-thread-create.json",
        &Response {
            protocol: Protocol,
            request_id: id(113)?,
            ok: Success,
            body: json!({"thread_id": "00000000000000000000000000000192"}),
        },
    )?;
    insert(
        &mut fixtures,
        "response-run-start.json",
        &Response {
            protocol: Protocol,
            request_id: id(103)?,
            ok: Success,
            body: json!({
                "run_id": "00000000000000000000000000000191",
                "thread_id": "00000000000000000000000000000192",
                "committed_seq": 1,
                "accepted_at": "2026-07-17T00:00:00Z"
            }),
        },
    )?;
    insert(
        &mut fixtures,
        "response-thread-select.json",
        &Response {
            protocol: Protocol,
            request_id: id(131)?,
            ok: Success,
            body: json!({}),
        },
    )?;
    insert(
        &mut fixtures,
        "response-retention-recheck.json",
        &Response {
            protocol: Protocol,
            request_id: id(132)?,
            ok: Success,
            body: json!({}),
        },
    )?;
    insert(
        &mut fixtures,
        "response-run-submit.json",
        &Response {
            protocol: Protocol,
            request_id: id(128)?,
            ok: Success,
            body: json!({
                "run_id": "00000000000000000000000000000191",
                "thread_id": "00000000000000000000000000000192",
                "attachments": [{
                    "displayName": "main.rs",
                    "byteLength": 128,
                    "mediaType": "text/rust"
                }],
                "committed_seq": 1,
                "accepted_at": "2026-07-17T00:00:00Z"
            }),
        },
    )?;
    insert(
        &mut fixtures,
        "response-run-resume.json",
        &Response {
            protocol: Protocol,
            request_id: id(129)?,
            ok: Success,
            body: json!({
                "run_id": "00000000000000000000000000000191",
                "thread_id": "00000000000000000000000000000192",
                "committed_seq": 2,
                "accepted_at": "2026-07-17T00:00:00Z"
            }),
        },
    )?;
    insert(
        &mut fixtures,
        "response-run-cancel.json",
        &Response {
            protocol: Protocol,
            request_id: id(108)?,
            ok: Success,
            body: json!({
                "run_id": "00000000000000000000000000000191",
                "accepted_at": "2026-07-17T00:00:00Z"
            }),
        },
    )?;
    insert(
        &mut fixtures,
        "response-approval-present.json",
        &Response {
            protocol: Protocol,
            request_id: id(115)?,
            ok: Success,
            body: json!({
                "challenge": "fixture-challenge",
                "decision": "approve"
            }),
        },
    )?;

    let errors = [
        crate::ErrorCode::ProtocolIncompatible,
        crate::ErrorCode::PayloadTooLarge,
        crate::ErrorCode::MalformedFrame,
        crate::ErrorCode::IdempotencyKeyRequired,
        crate::ErrorCode::IdempotencyKeyForbidden,
        crate::ErrorCode::IdempotencyConflict,
        crate::ErrorCode::PersistenceFailed,
        crate::ErrorCode::InvalidCursor,
        crate::ErrorCode::InvalidArtifactCursor,
        crate::ErrorCode::InvalidRequest,
        crate::ErrorCode::Unauthorized,
        crate::ErrorCode::UnsupportedOperation,
        crate::ErrorCode::ThreadNotFound,
        crate::ErrorCode::MigrationNotReady,
        crate::ErrorCode::RuntimeDraining,
    ];
    for (index, code) in errors.into_iter().enumerate() {
        let (name, error) = error_fixture(code);
        insert(
            &mut fixtures,
            &format!("error-{name}.json"),
            &ErrorEnvelope {
                protocol: Protocol,
                request_id: Some(id(300 + index as u128)?),
                ok: Failure,
                error,
            },
        )?;
    }

    let events = [
        ("run-stream", EventName::RunEvent),
        ("subscription-caught-up", EventName::SubscriptionCaughtUp),
        ("permission-pending", EventName::PermissionPending),
        ("artifact-chunk", EventName::ArtifactChunk),
        ("artifact-complete", EventName::ArtifactComplete),
        ("request-cancelled", EventName::RequestCancelled),
        ("capability-revoked", EventName::CapabilityRevoked),
        ("stream-closed", EventName::StreamClosed),
        (
            "unknown",
            serde_json::from_value(json!("future.optional")).map_err(io::Error::other)?,
        ),
        ("chat-event", EventName::ChatEvent),
    ];
    for (index, (name, event)) in events.into_iter().enumerate() {
        let body = event_body(&event);
        let event_without_run_cursor = matches!(
            event,
            EventName::ArtifactChunk | EventName::ArtifactComplete | EventName::ChatEvent
        );
        insert(
            &mut fixtures,
            &format!("event-{name}.json"),
            &Event {
                protocol: Protocol,
                subscription_id: id(400)?,
                event,
                run_id: (!event_without_run_cursor).then(|| id(401)).transpose()?,
                run_seq: (!event_without_run_cursor).then_some(index as u64 + 1),
                body,
            },
        )?;
    }
    insert(
        &mut fixtures,
        "event-run-stream-tool-effect.json",
        &Event {
            protocol: Protocol,
            subscription_id: id(400)?,
            event: EventName::RunEvent,
            run_id: Some(id(401)?),
            run_seq: Some(1),
            body: json!({
                "event_type": "tool.effect.started",
                "event_version": 1,
                "recorded_at": "2026-07-17T00:00:01Z",
                "payload": {"effect_id": "tool-1", "display_name": "Search"}
            }),
        },
    )?;
    Ok(fixtures)
}

// These exhaustive matches deliberately make additions to the public wire enums
// fail to compile until their canonical fixture is defined.
fn request_body(operation: Operation) -> serde_json::Value {
    match operation {
        Operation::WorkspaceOnboard => {
            json!({"opened_directory": "/work/repo", "memory_location": "/work/repo"})
        }
        Operation::HomeEnsure => json!({}),
        Operation::ThreadList => json!({"cursor": "thread-cursor-1", "limit": 50}),
        Operation::ThreadOpen => {
            json!({"thread_id": "thread-1", "cursor": "message-cursor-1", "limit": 100})
        }
        Operation::ThreadSummaries => json!({"cursor": "thread-cursor-1", "limit": 50}),
        Operation::ThreadHistory => {
            json!({"thread_id": "thread-1", "cursor": "message-cursor-1", "limit": 100})
        }
        Operation::ThreadCreate => json!({}),
        Operation::ThreadRename => json!({"thread_id": "thread-1", "title": "Renamed thread"}),
        Operation::ThreadSelect => json!({"thread_id": "thread-1"}),
        Operation::ThreadDelete => json!({"thread_id": "thread-1"}),
        Operation::SessionStatus
        | Operation::EntitlementSnapshot
        | Operation::DeviceList
        | Operation::SessionSignOut
        | Operation::SessionSignIn
        | Operation::CompanionList => json!({}),
        Operation::CompanionRevoke => json!({"client_identity": "companion-1"}),
        Operation::RunOpen => json!({"run_id": "00000000000000000000000000000191"}),
        Operation::RunStart => {
            json!({"text": "Summarize the selected file.", "context": {"selected_file": "src/main.rs"}})
        }
        Operation::RunSubmit => json!({
            "text": "Summarize the selected file.",
            "files": ["/work/repo/src/main.rs"],
            "thread_id": null
        }),
        Operation::RunResume => {
            json!({"run_id": "00000000000000000000000000000191"})
        }
        Operation::RunPermissionAnswer => json!({
            "run_id": "00000000000000000000000000000191",
            "gate_id": "permission-1",
            "answer": {"type": "confirm", "value": true}
        }),
        Operation::RunStream => {
            json!({"run_id": "00000000000000000000000000000191", "after_run_seq": 7})
        }
        Operation::RunChatEvents => json!({}),
        Operation::RunCursorAck => {
            json!({"subscription_id": "00000000000000000000000000000190", "through_run_seq": 7})
        }
        Operation::RunSteer => {
            json!({"run_id": "00000000000000000000000000000191", "text": "Focus on error handling."})
        }
        Operation::RunFollowUp => {
            json!({"run_id": "00000000000000000000000000000191", "text": "Now suggest tests."})
        }
        Operation::RunCancel => json!({"run_id": "00000000000000000000000000000191"}),
        Operation::PermissionAnswer => {
            json!({"run_id": "00000000000000000000000000000191", "gate_id": "permission-1", "decision": "allow"})
        }
        Operation::ArtifactFetch => {
            json!({"artifact_id": "00000000000000000000000000000192"})
        }
        Operation::ArtifactWindow => {
            json!({"transfer_id": "00000000000000000000000000000190", "ack_through_chunk": -1, "max_chunks": 1})
        }
        Operation::RequestCancel => {
            json!({"kind": "request", "request_id": "00000000000000000000000000000064"})
        }
        Operation::MigrationControl => {
            json!({"handoff_nonce": "fixture-handoff-nonce", "deadline_ms": 30_000})
        }
        Operation::ApprovalPresent => json!({
            "challenge": "fixture-challenge",
            "claimed_kind": "editor-extension",
            "claimed_version": "0.0.1",
            "workspace": "workspace-1",
            "scopes": ["thread.read"],
            "deadline_ms": 120_000
        }),
        Operation::RetentionRecheck => json!({}),
    }
}

fn error_fixture(code: crate::ErrorCode) -> (&'static str, ProtocolError) {
    use crate::ErrorCode::*;
    match code {
        ProtocolIncompatible => (
            "protocol-incompatible",
            ProtocolError::protocol_incompatible(
                VersionRange { min: 1, max: 1 },
                crate::ErrorAction::UpgradeCompanion,
            ),
        ),
        PayloadTooLarge => ("payload-too-large", ProtocolError::payload_too_large()),
        MalformedFrame => ("malformed-frame", ProtocolError::malformed_frame()),
        IdempotencyKeyRequired => (
            "idempotency-key-required",
            ProtocolError::idempotency_key_required(),
        ),
        IdempotencyKeyForbidden => (
            "idempotency-key-forbidden",
            ProtocolError::idempotency_key_forbidden(),
        ),
        IdempotencyConflict => (
            "idempotency-conflict",
            ProtocolError::idempotency_conflict(),
        ),
        PersistenceFailed => ("persistence-failed", ProtocolError::persistence_failed()),
        DesktopBusy => ("desktop-busy", ProtocolError::desktop_busy()),
        InvalidCursor => ("invalid-cursor", ProtocolError::invalid_cursor()),
        InvalidArtifactCursor => (
            "invalid-artifact-cursor",
            ProtocolError::invalid_artifact_cursor(),
        ),
        InvalidRequest => ("invalid-request", ProtocolError::invalid_request()),
        ThreadNotFound => ("thread-not-found", ProtocolError::thread_not_found()),
        Unauthorized => ("unauthorized", ProtocolError::unauthorized()),
        UnsupportedOperation => (
            "unsupported-operation",
            ProtocolError::unsupported_operation(),
        ),
        MigrationNotReady => ("migration-not-ready", ProtocolError::migration_not_ready()),
        RuntimeDraining => ("runtime-draining", ProtocolError::runtime_draining()),
    }
}

fn event_body(event: &EventName) -> serde_json::Value {
    match event {
        EventName::RunEvent => json!({
            "event_type": "assistant.message",
            "event_version": 1,
            "recorded_at": "2026-07-17T00:00:00Z",
            "payload": {"withheld": true}
        }),
        EventName::ChatEvent => json!({
            "runId": "00000000000000000000000000000191",
            "threadId": "00000000000000000000000000000192",
            "phase": "running",
            "text": "Review the selected file.",
            "toolActivity": [],
            "attachments": [],
            "recalls": [],
            "appliedDiffs": []
        }),
        EventName::SubscriptionCaughtUp => json!({"through_run_seq": 7}),
        EventName::PermissionPending => {
            json!({"gate_id": "permission-1", "kind": "confirm", "title": "Allow file update?", "message": "Update src/main.rs"})
        }
        EventName::ArtifactChunk => {
            json!({
                "artifact_id": "00000000000000000000000000000192",
                "chunk_index": 0,
                "offset": 0,
                "byte_length": 7,
                "chunk_sha256": "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d",
                "data": "Zml4dHVyZQ=="
            })
        }
        EventName::ArtifactComplete => {
            json!({
                "transfer_id": "00000000000000000000000000000190",
                "artifact_id": "00000000000000000000000000000192",
                "total_bytes": 7,
                "sha256": "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d"
            })
        }
        EventName::RequestCancelled => json!({"request_id": "00000000000000000000000000000064"}),
        EventName::CapabilityRevoked => {
            json!({"capability": "fixture-capability", "reason": "authorization_revoked"})
        }
        EventName::StreamClosed => json!({"code": "cancelled", "resumable": true}),
        EventName::Unknown(name) => json!({"name": name.as_str(), "optional": true}),
    }
}

fn insert<T: Serialize>(
    fixtures: &mut BTreeMap<String, Vec<u8>>,
    name: &str,
    value: &T,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    fixtures.insert(name.into(), bytes);
    Ok(())
}

fn check(target: &Path, expected: &BTreeMap<String, Vec<u8>>) -> io::Result<()> {
    let actual_names: BTreeSet<String> = match fs::read_dir(target) {
        Ok(entries) => entries
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<_>>()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeSet::new(),
        Err(error) => return Err(error),
    };
    let expected_names: BTreeSet<String> = expected.keys().cloned().collect();
    let mut drift = Vec::new();
    for name in expected_names.difference(&actual_names) {
        drift.push(format!("missing: {}", target.join(name).display()));
    }
    for name in actual_names.difference(&expected_names) {
        drift.push(format!("extra: {}", target.join(name).display()));
    }
    for (name, bytes) in expected {
        let path = target.join(name);
        if path.exists() && fs::read(&path)? != *bytes {
            drift.push(format!("stale: {}", path.display()));
        }
    }
    if drift.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "attach fixture drift detected:\n{}\nregenerate with: cargo run -p muniment-attach --bin export-attach-fixtures -- ../protocol-fixtures",
            drift.join("\n")
        )))
    }
}

fn id(value: u128) -> io::Result<Id> {
    Id::new(format!("{value:032x}")).map_err(io::Error::other)
}

fn sibling_path(target: &Path, purpose: &str, export_id: usize) -> PathBuf {
    target.with_file_name(format!(".1.{purpose}.{}.{export_id}", std::process::id()))
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_inventory_covers_every_public_wire_variant() {
        let fixtures = fixture_bytes().unwrap();
        let operations = [
            Operation::ThreadList,
            Operation::ThreadOpen,
            Operation::ThreadSummaries,
            Operation::ThreadHistory,
            Operation::ThreadCreate,
            Operation::ThreadRename,
            Operation::ThreadSelect,
            Operation::ThreadDelete,
            Operation::SessionStatus,
            Operation::EntitlementSnapshot,
            Operation::DeviceList,
            Operation::SessionSignOut,
            Operation::SessionSignIn,
            Operation::CompanionList,
            Operation::CompanionRevoke,
            Operation::RunOpen,
            Operation::RunStart,
            Operation::RunSubmit,
            Operation::RunResume,
            Operation::RunPermissionAnswer,
            Operation::RunStream,
            Operation::RunChatEvents,
            Operation::RunCursorAck,
            Operation::RunSteer,
            Operation::RunFollowUp,
            Operation::RunCancel,
            Operation::PermissionAnswer,
            Operation::ArtifactFetch,
            Operation::ArtifactWindow,
            Operation::RequestCancel,
            Operation::MigrationControl,
            Operation::ApprovalPresent,
            Operation::RetentionRecheck,
        ];
        for operation in operations {
            let name = operation.as_str().replace(['.', '_'], "-");
            assert!(fixtures.contains_key(&format!("request-{name}.json")));
            let _ = request_body(operation);
        }

        let error_codes = [
            crate::ErrorCode::ProtocolIncompatible,
            crate::ErrorCode::PayloadTooLarge,
            crate::ErrorCode::MalformedFrame,
            crate::ErrorCode::IdempotencyKeyRequired,
            crate::ErrorCode::IdempotencyKeyForbidden,
            crate::ErrorCode::IdempotencyConflict,
            crate::ErrorCode::PersistenceFailed,
            crate::ErrorCode::InvalidCursor,
            crate::ErrorCode::InvalidArtifactCursor,
            crate::ErrorCode::InvalidRequest,
            crate::ErrorCode::ThreadNotFound,
            crate::ErrorCode::Unauthorized,
            crate::ErrorCode::UnsupportedOperation,
            crate::ErrorCode::MigrationNotReady,
            crate::ErrorCode::RuntimeDraining,
        ];
        for code in error_codes {
            let (name, _) = error_fixture(code);
            assert!(fixtures.contains_key(&format!("error-{name}.json")));
        }

        for name in [
            "event-run-stream.json",
            "event-run-stream-tool-effect.json",
            "event-chat-event.json",
            "event-subscription-caught-up.json",
            "event-permission-pending.json",
            "event-artifact-chunk.json",
            "event-artifact-complete.json",
            "event-request-cancelled.json",
            "event-capability-revoked.json",
            "event-stream-closed.json",
            "event-unknown.json",
        ] {
            assert!(fixtures.contains_key(name));
        }
        assert_eq!(
            fixtures.len(),
            73,
            "every canonical fixture must be inventoried"
        );
    }
}
