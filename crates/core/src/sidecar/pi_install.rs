//! Pinned Pi archive acquisition, safe extraction, and current/previous publication.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::model_install::{
    install_model, AvailableSpace, InstallCancellation, InstallLock, ModelInstallError,
};

pub const PI_RELEASE_BASE: &str = "https://github.com/earendil-works/pi/releases/download/v0.73.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PiArtifactDescriptor {
    pub version: &'static str,
    pub archive: &'static str,
    pub byte_size: u64,
    pub sha256: &'static str,
    pub executable: &'static str,
}

/// The one older pin admitted for rollback. A pin update moves the former
/// `PI_ARTIFACT` descriptor here; arbitrary installed revision names are never
/// trusted. There is no predecessor for the first supported pin.
pub const PI_PREVIOUS_ARTIFACT: Option<PiArtifactDescriptor> = None;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const PI_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.73.1",
    archive: "pi-linux-x64.tar.gz",
    byte_size: 45_540_364,
    sha256: "00f0db9e93f6ba33deb1bb4d75b4eafede9fa5379b635a908cf967d5b37e366d",
    executable: "pi/pi",
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub const PI_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.73.1",
    archive: "pi-linux-arm64.tar.gz",
    byte_size: 44_095_594,
    sha256: "f47455b6a7ff6e43752a37c7c0a08b8054efd82cae1efc06d007c94f06a56318",
    executable: "pi/pi",
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const PI_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.73.1",
    archive: "pi-darwin-arm64.tar.gz",
    byte_size: 28_567_469,
    sha256: "c64f501cad8fa0a581257dc9e878e1b2f351f295d0d85d573fe8d7967bfb1bee",
    executable: "pi/pi",
};
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub const PI_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.73.1",
    archive: "pi-darwin-x64.tar.gz",
    byte_size: 31_000_715,
    sha256: "e59fded1f79fbc7b12e263bf43d1e358af598f6fb3c4d4f58e16d1c5ebe6b2b5",
    executable: "pi/pi",
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub const PI_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.73.1",
    archive: "pi-windows-x64.zip",
    byte_size: 48_225_045,
    sha256: "8bdb8e612a4b820f939a524652709b167ac5f1d4d1bba25988a631bff0bbe80b",
    executable: "pi/pi.exe",
};

const POINTER_HEADER: &str = "muniment-pi-pointer-v1";

pub trait PiLifecycleBoundary {
    fn sync_file(&self, path: &Path) -> Result<(), PiInstallError>;
    fn sync_directory(&self, path: &Path) -> Result<(), PiInstallError>;
    fn replace_revision(&self, staged: &Path, destination: &Path) -> Result<(), PiInstallError>;
    fn replace_pointer(&self, temporary: &Path, destination: &Path) -> Result<(), PiInstallError>;
}

/// Native durable filesystem operations. The install coordinator owns the
/// exclusive install lock while these operations run.
pub struct FsPiLifecycleBoundary;

impl PiLifecycleBoundary for FsPiLifecycleBoundary {
    fn sync_file(&self, path: &Path) -> Result<(), PiInstallError> {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| PiInstallError::Persistence)
    }
    fn sync_directory(&self, path: &Path) -> Result<(), PiInstallError> {
        #[cfg(unix)]
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| PiInstallError::Persistence)?;
        let _ = path;
        Ok(())
    }
    fn replace_revision(&self, staged: &Path, destination: &Path) -> Result<(), PiInstallError> {
        let quarantine = destination.with_extension("replaced");
        if quarantine.exists() {
            fs::remove_dir_all(&quarantine).map_err(|_| PiInstallError::Persistence)?;
        }
        if fs::symlink_metadata(destination).is_ok() {
            fs::rename(destination, &quarantine).map_err(|_| PiInstallError::Persistence)?;
        }
        fs::rename(staged, destination).map_err(|_| PiInstallError::Persistence)
    }
    fn replace_pointer(&self, temporary: &Path, destination: &Path) -> Result<(), PiInstallError> {
        replace_pointer_file(temporary, destination)
    }
}

#[cfg(not(windows))]
fn replace_pointer_file(temporary: &Path, destination: &Path) -> Result<(), PiInstallError> {
    fs::rename(temporary, destination).map_err(|_| PiInstallError::Persistence)
}

#[cfg(windows)]
fn replace_pointer_file(temporary: &Path, destination: &Path) -> Result<(), PiInstallError> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let existing: Vec<_> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let new: Vec<_> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both pointers reference NUL-terminated UTF-16 buffers that live
    // for the duration of the call. No aliases into Rust-managed memory are
    // retained by MoveFileExW.
    let replaced = unsafe {
        MoveFileExW(
            existing.as_ptr(),
            new.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(PiInstallError::Persistence)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PiDownloadRequest {
    url: String,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub deadline: Duration,
}
impl PiDownloadRequest {
    pub fn url(&self) -> &str {
        &self.url
    }
}
pub struct PiDownloadResponse<R> {
    pub status: u16,
    pub body: R,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiTransportError {
    Transient,
    Unavailable,
    Rejected,
}
pub trait PiDownloadTransport {
    type Body: Read;
    fn download(
        &mut self,
        request: &PiDownloadRequest,
    ) -> Result<PiDownloadResponse<Self::Body>, PiTransportError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiInstallError {
    InvalidStage,
    Download,
    WrongSize,
    DigestMismatch,
    UnsafeArchive,
    Persistence,
    NotInstalled,
}
impl std::fmt::Display for PiInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pi installation failed: {:?}", self)
    }
}
impl std::error::Error for PiInstallError {}
pub type CoordinatedPiInstallError = ModelInstallError<PiInstallError, PiInstallError>;

pub fn install_pi<
    T: PiDownloadTransport,
    C: InstallCancellation,
    L: InstallLock,
    S: AvailableSpace,
    B: PiLifecycleBoundary,
>(
    root: &Path,
    install_id: &str,
    transport: &mut T,
    cancellation: &C,
    lock: &mut L,
    space: &mut S,
    boundary: &B,
) -> Result<PathBuf, CoordinatedPiInstallError> {
    if !safe_component(install_id) {
        return Err(ModelInstallError::Acquisition(PiInstallError::InvalidStage));
    }
    let stage = root.join("staging").join(install_id);
    install_model(
        lock,
        space,
        cancellation,
        || Ok(PI_ARTIFACT.byte_size),
        || acquire_stage(&stage, transport),
        |stage| publish_stage(root, &stage, boundary),
    )
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
}

fn acquire_stage<T: PiDownloadTransport>(
    stage: &Path,
    transport: &mut T,
) -> Result<PathBuf, PiInstallError> {
    if stage.file_name().is_none() || stage.exists() {
        return Err(PiInstallError::InvalidStage);
    }
    fs::create_dir_all(stage).map_err(|_| PiInstallError::Persistence)?;
    let archive = stage.join(PI_ARTIFACT.archive);
    let request = PiDownloadRequest {
        url: format!("{PI_RELEASE_BASE}/{}", PI_ARTIFACT.archive),
        connect_timeout: Duration::from_secs(10),
        read_timeout: Duration::from_secs(30),
        deadline: Duration::from_secs(30 * 60),
    };
    let response = transport
        .download(&request)
        .map_err(|_| PiInstallError::Download)?;
    if response.status != 200 {
        return Err(PiInstallError::Download);
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&archive)
        .map_err(|_| PiInstallError::Persistence)?;
    let mut limited = response.body.take(PI_ARTIFACT.byte_size + 1);
    std::io::copy(&mut limited, &mut output).map_err(|_| PiInstallError::Download)?;
    output.sync_all().map_err(|_| PiInstallError::Persistence)?;
    verify_archive(&archive)?;
    extract_archive(&archive, stage)?;
    verify_executable(stage)?;
    Ok(stage.to_owned())
}

pub fn verify_archive(path: &Path) -> Result<(), PiInstallError> {
    verify_archive_for(path, PI_ARTIFACT)
}

fn verify_archive_for(path: &Path, descriptor: PiArtifactDescriptor) -> Result<(), PiInstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PiInstallError::Persistence)?;
    if !metadata.file_type().is_file() || metadata.len() != descriptor.byte_size {
        return Err(PiInstallError::WrongSize);
    }
    let mut file = File::open(path).map_err(|_| PiInstallError::Persistence)?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash).map_err(|_| PiInstallError::Persistence)?;
    if format!("{:x}", hash.finalize()) != descriptor.sha256 {
        return Err(PiInstallError::DigestMismatch);
    }
    Ok(())
}

fn safe_name(path: &Path) -> bool {
    path.components()
        .all(|part| matches!(part, Component::Normal(_)))
        && path.components().next() == Some(Component::Normal("pi".as_ref()))
}
fn extract_archive(archive: &Path, stage: &Path) -> Result<(), PiInstallError> {
    #[cfg(windows)]
    {
        let mut zip =
            zip::ZipArchive::new(File::open(archive).map_err(|_| PiInstallError::Persistence)?)
                .map_err(|_| PiInstallError::UnsafeArchive)?;
        for index in 0..zip.len() {
            let mut entry = zip
                .by_index(index)
                .map_err(|_| PiInstallError::UnsafeArchive)?;
            let enclosed = entry.enclosed_name().ok_or(PiInstallError::UnsafeArchive)?;
            if !safe_name(&enclosed) || (!entry.is_dir() && !entry.is_file()) {
                return Err(PiInstallError::UnsafeArchive);
            }
            let output = stage.join(enclosed);
            if entry.is_dir() {
                fs::create_dir_all(output).map_err(|_| PiInstallError::Persistence)?;
            } else {
                if let Some(parent) = output.parent() {
                    fs::create_dir_all(parent).map_err(|_| PiInstallError::Persistence)?;
                }
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(output)
                    .map_err(|_| PiInstallError::Persistence)?;
                std::io::copy(&mut entry, &mut out).map_err(|_| PiInstallError::Persistence)?;
            }
        }
    }
    #[cfg(not(windows))]
    {
        let decoder = flate2::read::GzDecoder::new(
            File::open(archive).map_err(|_| PiInstallError::Persistence)?,
        );
        let mut tar = tar::Archive::new(decoder);
        for item in tar.entries().map_err(|_| PiInstallError::UnsafeArchive)? {
            let mut entry = item.map_err(|_| PiInstallError::UnsafeArchive)?;
            let path = entry.path().map_err(|_| PiInstallError::UnsafeArchive)?;
            let kind = entry.header().entry_type();
            if !safe_name(&path) || !(kind.is_file() || kind.is_dir()) {
                return Err(PiInstallError::UnsafeArchive);
            }
            entry
                .unpack_in(stage)
                .map_err(|_| PiInstallError::Persistence)?;
        }
    }
    Ok(())
}

fn verify_executable(root: &Path) -> Result<PathBuf, PiInstallError> {
    verify_executable_for(root, PI_ARTIFACT)
}

fn verify_executable_for(
    root: &Path,
    descriptor: PiArtifactDescriptor,
) -> Result<PathBuf, PiInstallError> {
    let path = root.join(descriptor.executable);
    let metadata = fs::symlink_metadata(&path).map_err(|_| PiInstallError::Persistence)?;
    if !metadata.file_type().is_file() {
        return Err(PiInstallError::UnsafeArchive);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).map_err(|_| PiInstallError::Persistence)?;
    }
    Ok(path)
}

fn publish_stage<B: PiLifecycleBoundary>(
    root: &Path,
    stage: &Path,
    boundary: &B,
) -> Result<PathBuf, PiInstallError> {
    verify_archive(&stage.join(PI_ARTIFACT.archive))?;
    verify_executable(stage)?;
    let revisions = root.join("revisions");
    fs::create_dir_all(&revisions).map_err(|_| PiInstallError::Persistence)?;
    let destination = revisions.join(PI_ARTIFACT.version);
    boundary.sync_file(&stage.join(PI_ARTIFACT.archive))?;
    boundary.sync_file(&stage.join(PI_ARTIFACT.executable))?;
    boundary.sync_directory(stage)?;
    if resolve_revision(&destination, PI_ARTIFACT).is_err() {
        boundary.replace_revision(stage, &destination)?;
        boundary.sync_directory(&revisions)?;
    }
    if let Ok(current) = read_pointer(root, "current") {
        write_pointer(root, "previous", &current, boundary)?;
    }
    write_pointer(root, "current", PI_ARTIFACT.version, boundary)?;
    boundary.sync_directory(root)?;
    resolve_current(root)
}

pub fn resolve_current(root: &Path) -> Result<PathBuf, PiInstallError> {
    resolve_pointer(root, "current").or_else(|_| resolve_pointer(root, "previous"))
}

/// Atomically reactivates the retained verified predecessor after the newly
/// pinned revision fails its supervisor activation check.
pub fn rollback_to_previous<B: PiLifecycleBoundary>(
    root: &Path,
    boundary: &B,
) -> Result<PathBuf, PiInstallError> {
    rollback_to_previous_for(root, boundary, PI_ARTIFACT, PI_PREVIOUS_ARTIFACT)
}

/// Resolves the new pin for supervisor startup and rolls the durable pointer
/// back when its bounded readiness/activation check fails. The returned path
/// is always the revision the caller should launch next.
pub fn activate_or_rollback<B: PiLifecycleBoundary>(
    root: &Path,
    boundary: &B,
    activation_healthy: impl FnOnce(&Path) -> bool,
) -> Result<PathBuf, PiInstallError> {
    activate_or_rollback_for(
        root,
        boundary,
        PI_ARTIFACT,
        PI_PREVIOUS_ARTIFACT,
        activation_healthy,
    )
}

fn activate_or_rollback_for<B: PiLifecycleBoundary>(
    root: &Path,
    boundary: &B,
    current: PiArtifactDescriptor,
    retained: Option<PiArtifactDescriptor>,
    activation_healthy: impl FnOnce(&Path) -> bool,
) -> Result<PathBuf, PiInstallError> {
    let executable = resolve_pointer_for(root, "current", current, retained)?;
    if activation_healthy(&executable) {
        Ok(executable)
    } else {
        rollback_to_previous_for(root, boundary, current, retained)
    }
}

fn rollback_to_previous_for<B: PiLifecycleBoundary>(
    root: &Path,
    boundary: &B,
    current: PiArtifactDescriptor,
    retained: Option<PiArtifactDescriptor>,
) -> Result<PathBuf, PiInstallError> {
    let previous = read_pointer_for(root, "previous", current, retained)?;
    let descriptor = descriptor_for_version_from(&previous, current, retained)
        .ok_or(PiInstallError::NotInstalled)?;
    resolve_revision(&root.join("revisions").join(&previous), descriptor)?;
    write_pointer(root, "current", &previous, boundary)?;
    boundary.sync_directory(root)?;
    resolve_pointer_for(root, "current", current, retained)
}

fn resolve_pointer(root: &Path, pointer: &str) -> Result<PathBuf, PiInstallError> {
    resolve_pointer_for(root, pointer, PI_ARTIFACT, PI_PREVIOUS_ARTIFACT)
}

fn resolve_pointer_for(
    root: &Path,
    pointer: &str,
    current: PiArtifactDescriptor,
    retained: Option<PiArtifactDescriptor>,
) -> Result<PathBuf, PiInstallError> {
    let version = read_pointer_for(root, pointer, current, retained)?;
    let descriptor = descriptor_for_version_from(&version, current, retained)
        .ok_or(PiInstallError::NotInstalled)?;
    let revision = root.join("revisions").join(version);
    resolve_revision(&revision, descriptor)
}

fn descriptor_for_version_from(
    version: &str,
    current: PiArtifactDescriptor,
    retained: Option<PiArtifactDescriptor>,
) -> Option<PiArtifactDescriptor> {
    [Some(current), retained]
        .into_iter()
        .flatten()
        .find(|descriptor| descriptor.version == version)
}

fn resolve_revision(
    revision: &Path,
    descriptor: PiArtifactDescriptor,
) -> Result<PathBuf, PiInstallError> {
    verify_archive_for(&revision.join(descriptor.archive), descriptor)?;
    verify_executable_for(revision, descriptor)
}

fn read_pointer(root: &Path, name: &str) -> Result<String, PiInstallError> {
    read_pointer_for(root, name, PI_ARTIFACT, PI_PREVIOUS_ARTIFACT)
}

fn read_pointer_for(
    root: &Path,
    name: &str,
    current: PiArtifactDescriptor,
    retained: Option<PiArtifactDescriptor>,
) -> Result<String, PiInstallError> {
    let path = root.join(name);
    if !fs::symlink_metadata(&path)
        .map_err(|_| PiInstallError::NotInstalled)?
        .file_type()
        .is_file()
    {
        return Err(PiInstallError::NotInstalled);
    }
    let value = fs::read_to_string(path).map_err(|_| PiInstallError::NotInstalled)?;
    let lines: Vec<_> = value.lines().collect();
    if lines.len() != 2
        || lines[0] != POINTER_HEADER
        || descriptor_for_version_from(lines[1], current, retained).is_none()
        || !safe_component(lines[1])
    {
        return Err(PiInstallError::NotInstalled);
    }
    Ok(lines[1].to_owned())
}

fn write_pointer<B: PiLifecycleBoundary>(
    root: &Path,
    name: &str,
    version: &str,
    boundary: &B,
) -> Result<(), PiInstallError> {
    fs::create_dir_all(root).map_err(|_| PiInstallError::Persistence)?;
    let temporary = root.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| PiInstallError::Persistence)?;
    file.write_all(format!("{POINTER_HEADER}\n{version}\n").as_bytes())
        .map_err(|_| PiInstallError::Persistence)?;
    drop(file);
    boundary.sync_file(&temporary)?;
    if let Err(error) = boundary.replace_pointer(&temporary, &root.join(name)) {
        let _ = fs::remove_file(temporary);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FailingActivation;
    impl PiLifecycleBoundary for FailingActivation {
        fn sync_file(&self, _: &Path) -> Result<(), PiInstallError> {
            Ok(())
        }
        fn sync_directory(&self, _: &Path) -> Result<(), PiInstallError> {
            Ok(())
        }
        fn replace_revision(&self, _: &Path, _: &Path) -> Result<(), PiInstallError> {
            unreachable!()
        }
        fn replace_pointer(&self, _: &Path, _: &Path) -> Result<(), PiInstallError> {
            Err(PiInstallError::Persistence)
        }
    }

    #[test]
    fn interrupted_activation_preserves_the_existing_pointer() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "muniment-pi-pointer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let original = format!("{POINTER_HEADER}\n{}\n", PI_ARTIFACT.version);
        fs::write(root.join("current"), &original).unwrap();

        assert_eq!(
            write_pointer(&root, "current", PI_ARTIFACT.version, &FailingActivation),
            Err(PiInstallError::Persistence)
        );
        assert_eq!(fs::read_to_string(root.join("current")).unwrap(), original);
        assert!(!root.join(".current.tmp").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn native_failed_pointer_replacement_preserves_the_existing_pointer() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "muniment-pi-native-pointer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("current");
        let original = format!("{POINTER_HEADER}\n{}\n", PI_ARTIFACT.version);
        fs::write(&destination, &original).unwrap();

        assert_eq!(
            FsPiLifecycleBoundary.replace_pointer(&root.join("missing.tmp"), &destination),
            Err(PiInstallError::Persistence)
        );
        assert_eq!(fs::read_to_string(destination).unwrap(), original);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pin_upgrade_rolls_back_only_to_the_retained_verified_descriptor() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "muniment-pi-upgrade-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let descriptor = |version, archive| PiArtifactDescriptor {
            version,
            archive,
            byte_size: 1,
            sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            executable: "pi/pi",
        };
        let old = descriptor("0.72.0", "old.tar.gz");
        let new = descriptor("0.73.1", "new.tar.gz");
        for artifact in [old, new] {
            let revision = root.join("revisions").join(artifact.version);
            fs::create_dir_all(revision.join("pi")).unwrap();
            fs::write(revision.join(artifact.archive), b"a").unwrap();
            fs::write(revision.join(artifact.executable), b"executable").unwrap();
        }
        fs::write(
            root.join("current"),
            format!("{POINTER_HEADER}\n{}\n", new.version),
        )
        .unwrap();
        fs::write(
            root.join("previous"),
            format!("{POINTER_HEADER}\n{}\n", old.version),
        )
        .unwrap();

        let restored =
            activate_or_rollback_for(&root, &FsPiLifecycleBoundary, new, Some(old), |_| false)
                .unwrap();
        assert_eq!(restored, root.join("revisions/0.72.0/pi/pi"));
        assert_eq!(
            read_pointer_for(&root, "current", new, Some(old)).unwrap(),
            old.version
        );

        fs::write(
            root.join("current"),
            format!("{POINTER_HEADER}\n{}\n", new.version),
        )
        .unwrap();
        assert_eq!(
            rollback_to_previous_for(&root, &FailingActivation, new, Some(old)),
            Err(PiInstallError::Persistence)
        );
        assert_eq!(
            read_pointer_for(&root, "current", new, Some(old)).unwrap(),
            new.version
        );
        fs::write(root.join("previous"), format!("{POINTER_HEADER}\nother\n")).unwrap();
        assert_eq!(
            rollback_to_previous_for(&root, &FsPiLifecycleBoundary, new, Some(old)),
            Err(PiInstallError::NotInstalled)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
