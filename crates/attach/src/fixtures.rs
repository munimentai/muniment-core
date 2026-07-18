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
    Authorization, Client, ErrorEnvelope, Event, EventName, Failure, Hello, Id, Operation,
    Protocol, ProtocolError, Request, Response, Success, VersionRange, Welcome,
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

fn fixture_bytes() -> io::Result<BTreeMap<&'static str, Vec<u8>>> {
    let request_id = id(1)?;
    let subscription_id = id(2)?;
    let run_id = id(3)?;
    let mut fixtures = BTreeMap::new();
    insert(
        &mut fixtures,
        "negotiation-hello.json",
        &Hello {
            protocol: Protocol,
            client: Client {
                kind: "editor_extension".into(),
                version: "0.0.1".into(),
            },
            supported: VersionRange { min: 1, max: 1 },
            client_nonce: "fixture-client-nonce".into(),
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
            approval_challenge: "fixture-approval-challenge".into(),
        },
    )?;
    insert(
        &mut fixtures,
        "request-run-start.json",
        &Request {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::RunStart,
            capability: "fixture-capability".into(),
            idempotency_key: Some(id(4)?),
            body: json!({"prompt":"Summarize the selected file.","workspace_id":"workspace-fixture"}),
        },
    )?;
    insert(
        &mut fixtures,
        "response-run-start.json",
        &Response {
            protocol: Protocol,
            request_id: request_id.clone(),
            ok: Success,
            body: json!({"accepted":true,"run_id":run_id.as_str()}),
        },
    )?;
    insert(
        &mut fixtures,
        "event-run-stream.json",
        &Event {
            protocol: Protocol,
            subscription_id: subscription_id.clone(),
            event: EventName::RunEvent,
            run_id: Some(run_id.clone()),
            run_seq: Some(7),
            body: json!({"kind":"assistant_message","text":"Fixture response."}),
        },
    )?;
    insert(
        &mut fixtures,
        "event-permission-pending.json",
        &Event {
            protocol: Protocol,
            subscription_id,
            event: EventName::PermissionPending,
            run_id: Some(run_id),
            run_seq: Some(8),
            body: json!({"permission_id":"permission-fixture","summary":"Allow reading the selected file?"}),
        },
    )?;
    insert(
        &mut fixtures,
        "error-protocol-incompatible.json",
        &ErrorEnvelope {
            protocol: Protocol,
            request_id: None,
            ok: Failure,
            error: ProtocolError::protocol_incompatible(
                VersionRange { min: 1, max: 1 },
                crate::ErrorAction::UpgradeCompanion,
            ),
        },
    )?;
    Ok(fixtures)
}

fn insert<T: Serialize>(
    fixtures: &mut BTreeMap<&'static str, Vec<u8>>,
    name: &'static str,
    value: &T,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    fixtures.insert(name, bytes);
    Ok(())
}

fn check(target: &Path, expected: &BTreeMap<&str, Vec<u8>>) -> io::Result<()> {
    let actual_names: BTreeSet<String> = match fs::read_dir(target) {
        Ok(entries) => entries
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<_>>()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeSet::new(),
        Err(error) => return Err(error),
    };
    let expected_names: BTreeSet<String> = expected.keys().map(|name| (*name).into()).collect();
    if actual_names != expected_names {
        return Err(io::Error::other(format!(
            "fixture file set is stale (expected {expected_names:?}, found {actual_names:?})"
        )));
    }
    for (name, bytes) in expected {
        if fs::read(target.join(name))? != *bytes {
            return Err(io::Error::other(format!("fixture is byte-stale: {name}")));
        }
    }
    Ok(())
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
