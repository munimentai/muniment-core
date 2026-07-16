#![cfg(target_os = "linux")]

use muniment_core::attach::linux::{AttachFilesystem, AttachFilesystemError};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "muniment-attach-fs-{}-{sequence}",
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
fn derives_exact_endpoint_and_reopens_private_directory() {
    let runtime = TestDirectory::new();
    let first = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    assert_eq!(
        first.endpoint_path(),
        runtime.0.join("muniment/attach-v1.sock")
    );
    assert_eq!(
        fs::metadata(runtime.0.join("muniment")).unwrap().mode() & 0o777,
        0o700
    );

    let second = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    assert_eq!(second.endpoint_path(), first.endpoint_path());
}

#[test]
fn rejects_invalid_runtime_directories() {
    let runtime = TestDirectory::new();
    let missing = runtime.0.join("missing");
    assert_eq!(
        AttachFilesystem::from_runtime_directory("relative").unwrap_err(),
        AttachFilesystemError::RuntimeDirectoryNotAbsolute
    );
    assert_eq!(
        AttachFilesystem::from_runtime_directory(&missing).unwrap_err(),
        AttachFilesystemError::RuntimeDirectoryOpen
    );

    let file = runtime.0.join("file");
    fs::write(&file, []).unwrap();
    assert_eq!(
        AttachFilesystem::from_runtime_directory(&file).unwrap_err(),
        AttachFilesystemError::RuntimeDirectoryOpen
    );

    let link = runtime.0.with_extension("link");
    symlink(&runtime.0, &link).unwrap();
    assert_eq!(
        AttachFilesystem::from_runtime_directory(&link).unwrap_err(),
        AttachFilesystemError::RuntimeDirectoryOpen
    );
    let mut link_with_trailing_slash = link.as_os_str().to_owned();
    link_with_trailing_slash.push("/");
    assert_eq!(
        AttachFilesystem::from_runtime_directory(link_with_trailing_slash).unwrap_err(),
        AttachFilesystemError::RuntimeDirectoryInvalid
    );
    fs::remove_file(link).unwrap();

    fs::set_permissions(&runtime.0, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        AttachFilesystem::from_runtime_directory(&runtime.0).unwrap_err(),
        AttachFilesystemError::RuntimeDirectoryInsecure
    );
}

#[test]
fn rejects_invalid_existing_attach_entries() {
    for setup in [
        setup_file as fn(&Path),
        setup_symlink,
        setup_insecure_directory,
    ] {
        let runtime = TestDirectory::new();
        setup(&runtime.0.join("muniment"));
        assert!(AttachFilesystem::from_runtime_directory(&runtime.0).is_err());
    }
}

fn setup_file(path: &Path) {
    fs::write(path, []).unwrap();
}

fn setup_symlink(path: &Path) {
    symlink(path.parent().unwrap(), path).unwrap();
}

fn setup_insecure_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn create_to_open_replacement_symlink_is_not_followed_or_chmodded() {
    let runtime = TestDirectory::new();
    let target = runtime.0.join("target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    let attach = runtime.0.join("muniment");

    let error = AttachFilesystem::from_runtime_directory_with_hook(&runtime.0, || {
        fs::remove_dir(&attach).unwrap();
        symlink(&target, &attach).unwrap();
    })
    .unwrap_err();

    assert_eq!(error, AttachFilesystemError::AttachDirectoryOpen);
    assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o755);
}

#[test]
fn displayed_errors_do_not_disclose_runtime_paths() {
    let secret = "/private/value-that-must-not-appear";
    let error = AttachFilesystem::from_runtime_directory(secret).unwrap_err();
    assert!(!error.to_string().contains(secret));
}

#[test]
fn rejects_wrong_owner_when_test_process_can_change_ownership() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let runtime = TestDirectory::new();
    let different_uid = 1;
    let result = unsafe { libc::chown(path_c_string(&runtime.0).as_ptr(), different_uid, 0) };
    assert_eq!(result, 0);
    assert_eq!(
        AttachFilesystem::from_runtime_directory(&runtime.0).unwrap_err(),
        AttachFilesystemError::RuntimeDirectoryWrongOwner
    );
}

fn path_c_string(path: &Path) -> std::ffi::CString {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap()
}
