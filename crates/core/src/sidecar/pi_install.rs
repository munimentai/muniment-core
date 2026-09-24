//! Pinned Pi archive acquisition, safe extraction, and current/previous publication.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::model_install::{
    install_model, AvailableSpace, InstallCancellation, InstallLock, ModelInstallError,
};

pub const PI_RELEASE_BASE: &str = "https://github.com/earendil-works/pi/releases/download/v0.87.1";
/// The candidate track equals the production pin until the nightly exercises a
/// newer release. A candidate move gives it its own descriptors again.
pub const PI_CANDIDATE_RELEASE_BASE: &str = PI_RELEASE_BASE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PiArtifactDescriptor {
    pub version: &'static str,
    pub archive: &'static str,
    pub byte_size: u64,
    pub sha256: &'static str,
    pub executable: &'static str,
}

/// The one older pin admitted for rollback; arbitrary installed revision names
/// are never trusted. The predecessor must accept the launch contract of the
/// current pin, because a launch after a rollback still builds the arguments
/// and settings of `PI_SELECTED_ARTIFACT`. 0.85.1 is the verified revision the
/// nightly ran before 0.87.1 and reads the same flags and settings keys.
pub const PI_PREVIOUS_ARTIFACT: Option<PiArtifactDescriptor> = Some(PI_PREDECESSOR_ARTIFACT);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const PI_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.87.1",
    archive: "pi-linux-x64.tar.gz",
    byte_size: 42_120_827,
    sha256: "80d78dd62d50049a006b981d994c61255bcc10e730b0c278d4ea0a755909764c",
    executable: "pi/pi",
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub const PI_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.87.1",
    archive: "pi-linux-arm64.tar.gz",
    byte_size: 42_217_308,
    sha256: "364b4a9f8491450b27a4857d4e3c780dbaf696790821c176a873e860cbbc3b89",
    executable: "pi/pi",
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const PI_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.87.1",
    archive: "pi-darwin-arm64.tar.gz",
    byte_size: 30_563_988,
    sha256: "4f8d288b78c9768d3a4ac6f61f06cd34394b82ac17d5b42d1e44a437add401b7",
    executable: "pi/pi",
};
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub const PI_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.87.1",
    archive: "pi-darwin-x64.tar.gz",
    byte_size: 33_033_993,
    sha256: "01d8ee28d7114fec4f4eeedbb7561f790853040e9bfbdeebe79437ab66ea51f5",
    executable: "pi/pi",
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub const PI_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.87.1",
    archive: "pi-windows-x64.zip",
    byte_size: 44_615_504,
    sha256: "aab2ba67baf8ff97a52d05b62d88e9e65a840c6ea8fa1029a28d62d210d4e5fc",
    executable: "pi/pi.exe",
};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const PI_PREDECESSOR_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.85.1",
    archive: "pi-linux-x64.tar.gz",
    byte_size: 42_560_927,
    sha256: "494e498f47d74d21f40b3386f6a5e921a3d49531a169cab55bbdaca0ea1fe25a",
    executable: "pi/pi",
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const PI_PREDECESSOR_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.85.1",
    archive: "pi-linux-arm64.tar.gz",
    byte_size: 42_628_180,
    sha256: "042d20ae885ee4f3b102815f3280b962c377b2e9fb44de4037908cc530eae4d4",
    executable: "pi/pi",
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PI_PREDECESSOR_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.85.1",
    archive: "pi-darwin-arm64.tar.gz",
    byte_size: 31_035_676,
    sha256: "d5f70e3c0cf7398eac239fd0261ee074d98b7ba7f6b43fe3617f052ed5b79d06",
    executable: "pi/pi",
};
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const PI_PREDECESSOR_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.85.1",
    archive: "pi-darwin-x64.tar.gz",
    byte_size: 33_544_584,
    sha256: "adb918b845625f184d8bea408d55eacaf21aa87238793c0f5b4f3b9737bce62b",
    executable: "pi/pi",
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const PI_PREDECESSOR_ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    version: "0.85.1",
    archive: "pi-windows-x64.zip",
    byte_size: 45_009_021,
    sha256: "002fa95b90d521245b9985d8f168caebc237ad56e7e30b319807dee1b2e17e1c",
    executable: "pi/pi.exe",
};

pub const PI_CANDIDATE_ARTIFACT: PiArtifactDescriptor = PI_ARTIFACT;
pub const PI_CANDIDATE_PREVIOUS_ARTIFACT: Option<PiArtifactDescriptor> = PI_PREVIOUS_ARTIFACT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PiTrack {
    artifact: PiArtifactDescriptor,
    previous: Option<PiArtifactDescriptor>,
    release_base: &'static str,
}

const fn pi_track(candidate: Option<&str>) -> PiTrack {
    if matches!(candidate, Some(value) if matches!(value.as_bytes(), [b'1'])) {
        PiTrack {
            artifact: PI_CANDIDATE_ARTIFACT,
            previous: PI_CANDIDATE_PREVIOUS_ARTIFACT,
            release_base: PI_CANDIDATE_RELEASE_BASE,
        }
    } else {
        PiTrack {
            artifact: PI_ARTIFACT,
            previous: PI_PREVIOUS_ARTIFACT,
            release_base: PI_RELEASE_BASE,
        }
    }
}

// The nightly sets this switch at build time. Installed services need no
// inherited environment, and a runtime variable cannot change the track.
const PI_SELECTED_TRACK: PiTrack = pi_track(option_env!("MUNIMENT_PI_CANDIDATE"));
pub const PI_SELECTED_ARTIFACT: PiArtifactDescriptor = PI_SELECTED_TRACK.artifact;

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
        let mut options = OpenOptions::new();
        options.read(true);
        // Windows FlushFileBuffers requires GENERIC_WRITE, even after a read-only check.
        #[cfg(windows)]
        options.write(true);
        let file = options
            .open(path)
            .map_err(|error| persistence_error("open_sync_file", error))?;
        file.sync_all()
            .map_err(|error| persistence_error("sync_file", error))
    }
    fn sync_directory(&self, path: &Path) -> Result<(), PiInstallError> {
        #[cfg(unix)]
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|error| persistence_error("sync_directory", error))?;
        let _ = path;
        Ok(())
    }
    fn replace_revision(&self, staged: &Path, destination: &Path) -> Result<(), PiInstallError> {
        let quarantine = destination.with_extension("replaced");
        if quarantine.exists() {
            fs::remove_dir_all(&quarantine)
                .map_err(|error| persistence_error("remove_replaced_revision", error))?;
        }
        if fs::symlink_metadata(destination).is_ok() {
            fs::rename(destination, &quarantine)
                .map_err(|error| persistence_error("quarantine_revision", error))?;
        }
        fs::rename(staged, destination)
            .map_err(|error| persistence_error("replace_revision", error))
    }
    fn replace_pointer(&self, temporary: &Path, destination: &Path) -> Result<(), PiInstallError> {
        replace_pointer_file(temporary, destination)
    }
}

#[cfg(not(windows))]
fn replace_pointer_file(temporary: &Path, destination: &Path) -> Result<(), PiInstallError> {
    fs::rename(temporary, destination).map_err(|error| persistence_error("replace_pointer", error))
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
        Err(persistence_error(
            "replace_pointer",
            std::io::Error::last_os_error(),
        ))
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
    PersistenceIo {
        step: &'static str,
        kind: std::io::ErrorKind,
        os_error: Option<i32>,
    },
    NotInstalled,
}
fn persistence_error(step: &'static str, error: std::io::Error) -> PiInstallError {
    PiInstallError::PersistenceIo {
        step,
        kind: error.kind(),
        os_error: error.raw_os_error(),
    }
}

impl std::fmt::Display for PiInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pi installation failed: {:?}", self)
    }
}
impl std::error::Error for PiInstallError {}
pub type CoordinatedPiInstallError = ModelInstallError<PiInstallError, PiInstallError>;

pub fn acquire_pi(
    root: &Path,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<PathBuf, CoordinatedPiInstallError> {
    use crate::model_acquisition_transport::NativeModelAcquisitionTransport;
    use crate::model_install_native::{NativeAvailableSpace, NativeInstallLock};

    if let Ok(executable) = resolve_current(root) {
        return Ok(executable);
    }
    fs::create_dir_all(root)
        .map_err(|_| ModelInstallError::Acquisition(PiInstallError::Persistence))?;
    let install_id = uuid::Uuid::new_v4().to_string();
    let result = install_pi(
        root,
        &install_id,
        &mut NativeModelAcquisitionTransport::new(),
        &|| cancelled.load(std::sync::atomic::Ordering::SeqCst),
        &mut NativeInstallLock::new(root.join("install.lock")),
        &mut NativeAvailableSpace::new(root),
        &FsPiLifecycleBoundary,
    );
    let _ = fs::remove_dir_all(root.join("staging").join(install_id));
    result
}

enum AcquiredPi {
    Current(PathBuf),
    Staged(PathBuf),
}

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
    let result = install_model(
        lock,
        space,
        cancellation,
        || Ok(PI_SELECTED_ARTIFACT.byte_size),
        || {
            // Recheck under the install lock after another run may have published Pi.
            if let Ok(executable) = resolve_pointer_for(root, "current", PI_SELECTED_ARTIFACT, None)
            {
                Ok(AcquiredPi::Current(executable))
            } else {
                acquire_stage(&stage, transport, cancellation).map(AcquiredPi::Staged)
            }
        },
        |acquired| match acquired {
            AcquiredPi::Current(executable) => Ok(executable),
            AcquiredPi::Staged(stage) => publish_stage(root, &stage, boundary),
        },
    );
    if cancellation.is_cancelled() {
        Err(ModelInstallError::Cancelled)
    } else {
        result
    }
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
    cancellation: &impl InstallCancellation,
) -> Result<PathBuf, PiInstallError> {
    if stage.file_name().is_none() || stage.exists() {
        return Err(PiInstallError::InvalidStage);
    }
    fs::create_dir_all(stage).map_err(|_| PiInstallError::Persistence)?;
    let archive = stage.join(PI_SELECTED_ARTIFACT.archive);
    let request = PiDownloadRequest {
        url: format!(
            "{}/{}",
            PI_SELECTED_TRACK.release_base, PI_SELECTED_ARTIFACT.archive
        ),
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
    let mut limited = response.body.take(PI_SELECTED_ARTIFACT.byte_size + 1);
    let mut buffer = [0; 64 * 1024];
    loop {
        if cancellation.is_cancelled() {
            return Err(PiInstallError::Download);
        }
        let count = limited
            .read(&mut buffer)
            .map_err(|_| PiInstallError::Download)?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|_| PiInstallError::Persistence)?;
    }
    output.sync_all().map_err(|_| PiInstallError::Persistence)?;
    verify_archive(&archive)?;
    extract_archive(&archive, stage)?;
    verify_executable(stage)?;
    Ok(stage.to_owned())
}

pub fn verify_archive(path: &Path) -> Result<(), PiInstallError> {
    verify_archive_for(path, PI_SELECTED_ARTIFACT)
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
#[cfg(any(windows, test))]
fn zip_entry_path(path: &Path, flat_root: bool) -> Result<PathBuf, PiInstallError> {
    if path.as_os_str().is_empty()
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(PiInstallError::UnsafeArchive);
    }
    let output = if flat_root {
        Path::new("pi").join(path)
    } else {
        path.to_owned()
    };
    if !safe_name(&output) {
        return Err(PiInstallError::UnsafeArchive);
    }
    Ok(output)
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
            // The candidate ZIP has a flat root. Keep the installed pi/ layout.
            let enclosed = zip_entry_path(
                &entry.enclosed_name().ok_or(PiInstallError::UnsafeArchive)?,
                PI_SELECTED_ARTIFACT == PI_CANDIDATE_ARTIFACT,
            )?;
            if !entry.is_dir() && !entry.is_file() {
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
    verify_executable_for(root, PI_SELECTED_ARTIFACT)
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
    verify_archive(&stage.join(PI_SELECTED_ARTIFACT.archive))?;
    verify_executable(stage)?;
    let revisions = root.join("revisions");
    fs::create_dir_all(&revisions).map_err(|error| persistence_error("create_revisions", error))?;
    let destination = revisions.join(PI_SELECTED_ARTIFACT.version);
    boundary.sync_file(&stage.join(PI_SELECTED_ARTIFACT.archive))?;
    boundary.sync_file(&stage.join(PI_SELECTED_ARTIFACT.executable))?;
    boundary.sync_directory(stage)?;
    if resolve_revision(&destination, PI_SELECTED_ARTIFACT).is_err() {
        boundary.replace_revision(stage, &destination)?;
        boundary.sync_directory(&revisions)?;
    }
    publish_pointers(root, boundary, PI_SELECTED_TRACK)?;
    resolve_current(root)
}

fn publish_pointers<B: PiLifecycleBoundary>(
    root: &Path,
    boundary: &B,
    track: PiTrack,
) -> Result<(), PiInstallError> {
    if let Ok(current) = read_pointer_for(root, "current", track.artifact, track.previous) {
        if current != track.artifact.version {
            write_pointer(root, "previous", &current, boundary)?;
        }
    }
    write_pointer(root, "current", track.artifact.version, boundary)?;
    boundary.sync_directory(root)
}

pub fn resolve_current(root: &Path) -> Result<PathBuf, PiInstallError> {
    resolve_current_for(root, PI_SELECTED_ARTIFACT)
}

pub fn resolve_current_for(
    root: &Path,
    descriptor: PiArtifactDescriptor,
) -> Result<PathBuf, PiInstallError> {
    let retained = if descriptor == PI_SELECTED_ARTIFACT {
        PI_SELECTED_TRACK.previous
    } else {
        None
    };
    // The current pointer names the pin alone, so a pin move on a host that
    // holds the predecessor acquires the pin instead of running the predecessor.
    // The previous pointer, written by a publish or a rollback, names the retained one.
    resolve_pointer_for(root, "current", descriptor, None)
        .or_else(|_| resolve_pointer_for(root, "previous", descriptor, retained))
}

/// Atomically reactivates the retained verified predecessor after the newly
/// pinned revision fails its supervisor activation check.
pub fn rollback_to_previous<B: PiLifecycleBoundary>(
    root: &Path,
    boundary: &B,
) -> Result<PathBuf, PiInstallError> {
    rollback_to_previous_for(
        root,
        boundary,
        PI_SELECTED_ARTIFACT,
        PI_SELECTED_TRACK.previous,
    )
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
        PI_SELECTED_ARTIFACT,
        PI_SELECTED_TRACK.previous,
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
    let descriptor = retained
        .filter(|descriptor| descriptor.version == previous)
        .ok_or(PiInstallError::NotInstalled)?;
    resolve_revision(&root.join("revisions").join(&previous), descriptor)?;
    write_pointer(root, "current", &previous, boundary)?;
    boundary.sync_directory(root)?;
    resolve_pointer_for(root, "current", current, retained)
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
    let archive = revision.join(descriptor.archive);
    verify_archive_for(&archive, descriptor)?;
    verify_executable_for(revision, descriptor)
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
    fs::create_dir_all(root).map_err(|error| persistence_error("create_pointer_root", error))?;
    let temporary = root.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| persistence_error("open_pointer", error))?;
    file.write_all(format!("{POINTER_HEADER}\n{version}\n").as_bytes())
        .map_err(|error| persistence_error("write_pointer", error))?;
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
    fn native_sync_preserves_files_after_read_only_verification() {
        let root = std::env::temp_dir().join(format!("muniment-pi-sync-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("pi")).unwrap();
        for name in [
            PI_SELECTED_ARTIFACT.archive,
            PI_SELECTED_ARTIFACT.executable,
            ".current.tmp",
        ] {
            let path = root.join(name);
            fs::write(&path, b"durable bytes").unwrap();
            let mut reader = File::open(&path).unwrap();
            let mut contents = Vec::new();
            reader.read_to_end(&mut contents).unwrap();
            FsPiLifecycleBoundary.sync_file(&path).unwrap();
            assert_eq!(fs::read(&path).unwrap(), contents);
        }
        // A sync must not create a missing file or hide the OS error.
        let missing = root.join("missing");
        let os_error = File::open(&missing).unwrap_err().raw_os_error();
        assert_eq!(
            FsPiLifecycleBoundary.sync_file(&missing),
            Err(PiInstallError::PersistenceIo {
                step: "open_sync_file",
                kind: std::io::ErrorKind::NotFound,
                os_error,
            })
        );
        assert!(!missing.exists());
        write_pointer(
            &root,
            "current",
            PI_SELECTED_ARTIFACT.version,
            &FsPiLifecycleBoundary,
        )
        .unwrap();
        write_pointer(
            &root,
            "current",
            PI_SELECTED_ARTIFACT.version,
            &FsPiLifecycleBoundary,
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(root.join("current")).unwrap(),
            format!("{POINTER_HEADER}\n{}\n", PI_SELECTED_ARTIFACT.version)
        );
        assert!(!root.join(".current.tmp").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_current_pointer_at_the_predecessor_means_the_pin_is_not_installed() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "muniment-pi-pin-move-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let predecessor = PI_CANDIDATE_PREVIOUS_ARTIFACT.unwrap();
        fs::write(
            root.join("current"),
            format!("{POINTER_HEADER}\n{}\n", predecessor.version),
        )
        .unwrap();
        // A host that holds the predecessor alone acquires the pin instead of running it.
        assert_eq!(
            resolve_current_for(&root, PI_CANDIDATE_ARTIFACT),
            Err(PiInstallError::NotInstalled)
        );
        assert_eq!(
            read_pointer_for(&root, "current", PI_CANDIDATE_ARTIFACT, None),
            Err(PiInstallError::NotInstalled)
        );
        // After a publish or a rollback the previous pointer names the predecessor, and that resolves.
        fs::write(
            root.join("previous"),
            format!("{POINTER_HEADER}\n{}\n", predecessor.version),
        )
        .unwrap();
        assert_eq!(
            read_pointer_for(&root, "previous", PI_CANDIDATE_ARTIFACT, Some(predecessor)),
            Ok(predecessor.version.to_owned())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_untrusted_older_revision_is_never_retained_for_rollback() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "muniment-pi-untrusted-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        // A host on a pin older than the predecessor publishes the new pin with no rollback target.
        fs::write(root.join("current"), format!("{POINTER_HEADER}\n0.73.1\n")).unwrap();
        publish_pointers(&root, &FsPiLifecycleBoundary, PI_SELECTED_TRACK).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("current")).unwrap(),
            format!("{POINTER_HEADER}\n{}\n", PI_SELECTED_ARTIFACT.version)
        );
        assert!(!root.join("previous").exists());
        fs::remove_dir_all(root).unwrap();
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

        assert!(matches!(
            FsPiLifecycleBoundary.replace_pointer(&root.join("missing.tmp"), &destination),
            Err(PiInstallError::PersistenceIo {
                step: "replace_pointer",
                kind: std::io::ErrorKind::NotFound,
                os_error: Some(_),
            })
        ));
        assert_eq!(fs::read_to_string(destination).unwrap(), original);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_the_explicit_build_switch_selects_the_candidate() {
        for switch in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("01"),
            Some("1 "),
        ] {
            let track = pi_track(switch);
            assert_eq!(track.artifact, PI_ARTIFACT);
            assert_eq!(track.release_base, PI_RELEASE_BASE);
            assert_eq!(track.previous, PI_PREVIOUS_ARTIFACT);
        }
        let candidate = pi_track(Some("1"));
        assert_eq!(candidate.artifact, PI_CANDIDATE_ARTIFACT);
        assert_eq!(candidate.release_base, PI_CANDIDATE_RELEASE_BASE);
        assert_eq!(candidate.previous, PI_CANDIDATE_PREVIOUS_ARTIFACT);
        assert_eq!(PI_ARTIFACT.version, "0.87.1");
        assert_eq!(PI_CANDIDATE_ARTIFACT.version, "0.87.1");
        assert_eq!(PI_PREVIOUS_ARTIFACT.map(|a| a.version), Some("0.85.1"));
        assert_eq!(PI_PREDECESSOR_ARTIFACT.archive, PI_ARTIFACT.archive);
        assert_eq!(PI_PREDECESSOR_ARTIFACT.executable, PI_ARTIFACT.executable);
    }

    #[test]
    fn zip_layouts_keep_entries_beneath_the_installed_pi_directory() {
        assert_eq!(
            zip_entry_path(Path::new("pi/pi.exe"), false).unwrap(),
            Path::new("pi/pi.exe")
        );
        for path in ["pi.exe", "examples/plugin/index.ts"] {
            assert_eq!(
                zip_entry_path(Path::new(path), true).unwrap(),
                Path::new("pi").join(path)
            );
            assert_eq!(
                zip_entry_path(Path::new(path), false),
                Err(PiInstallError::UnsafeArchive)
            );
        }
        for flat_root in [false, true] {
            for path in ["", ".", "..", "../pi.exe", "pi/../../pi.exe", "/pi.exe"] {
                assert_eq!(
                    zip_entry_path(Path::new(path), flat_root),
                    Err(PiInstallError::UnsafeArchive)
                );
            }
        }
    }

    #[test]
    fn both_descriptors_reject_wrong_sizes_and_digests() {
        let root =
            std::env::temp_dir().join(format!("muniment-pi-descriptors-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        for artifact in [PI_ARTIFACT, PI_PREDECESSOR_ARTIFACT] {
            assert!(artifact.byte_size > 0);
            assert_eq!(artifact.sha256.len(), 64);
            assert!(artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(safe_component(artifact.version));
            assert!(safe_component(artifact.archive));
            assert!(safe_name(Path::new(artifact.executable)));
            let archive = root.join(artifact.archive);
            fs::write(&archive, b"").unwrap();
            assert_eq!(
                verify_archive_for(&archive, artifact),
                Err(PiInstallError::WrongSize)
            );
            let file = File::create(&archive).unwrap();
            file.set_len(artifact.byte_size).unwrap();
            assert_eq!(
                verify_archive_for(&archive, artifact),
                Err(PiInstallError::DigestMismatch)
            );
            file.set_len(artifact.byte_size + 1).unwrap();
            assert_eq!(
                verify_archive_for(&archive, artifact),
                Err(PiInstallError::WrongSize)
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn activation_rolls_back_only_to_the_verified_predecessor() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "muniment-pi-upgrade-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        // Fixture bytes replace only the archive size and digest.
        let descriptor = |artifact: PiArtifactDescriptor| PiArtifactDescriptor {
            byte_size: 1,
            sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            ..artifact
        };
        let candidate = pi_track(Some("1"));
        let old = descriptor(candidate.previous.unwrap());
        let new = descriptor(candidate.artifact);
        for artifact in [old, new] {
            let revision = root.join("revisions").join(artifact.version);
            fs::create_dir_all(revision.join("pi")).unwrap();
            fs::write(revision.join(artifact.archive), b"a").unwrap();
            fs::write(revision.join(artifact.executable), b"executable").unwrap();
        }
        fs::write(
            root.join("current"),
            format!("{POINTER_HEADER}\n{}\n", old.version),
        )
        .unwrap();
        let track = PiTrack {
            artifact: new,
            previous: Some(old),
            ..candidate
        };
        publish_pointers(&root, &FsPiLifecycleBoundary, track).unwrap();
        // A repeated install must retain the verified predecessor.
        publish_pointers(&root, &FsPiLifecycleBoundary, track).unwrap();
        assert_eq!(
            read_pointer_for(&root, "previous", new, Some(old)).unwrap(),
            old.version
        );

        let candidate_path = root
            .join("revisions")
            .join(new.version)
            .join(new.executable);
        assert_eq!(
            activate_or_rollback_for(&root, &FsPiLifecycleBoundary, new, Some(old), |_| true)
                .unwrap(),
            candidate_path
        );
        let restored =
            activate_or_rollback_for(&root, &FsPiLifecycleBoundary, new, Some(old), |path| {
                assert_eq!(path, candidate_path);
                false
            })
            .unwrap();
        assert_eq!(
            restored,
            root.join("revisions")
                .join(old.version)
                .join(old.executable)
        );
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
        assert_eq!(
            rollback_to_previous_for(&root, &FsPiLifecycleBoundary, new, None),
            Err(PiInstallError::NotInstalled)
        );
        fs::write(
            root.join("revisions").join(old.version).join(old.archive),
            b"b",
        )
        .unwrap();
        assert_eq!(
            activate_or_rollback_for(&root, &FsPiLifecycleBoundary, new, Some(old), |_| false),
            Err(PiInstallError::DigestMismatch)
        );
        assert_eq!(
            read_pointer_for(&root, "current", new, Some(old)).unwrap(),
            new.version
        );
        for version in [new.version, "other", "../0.85.1", "0.73.1", ""] {
            fs::write(
                root.join("previous"),
                format!("{POINTER_HEADER}\n{version}\n"),
            )
            .unwrap();
            assert_eq!(
                rollback_to_previous_for(&root, &FsPiLifecycleBoundary, new, Some(old)),
                Err(PiInstallError::NotInstalled)
            );
            assert_eq!(
                read_pointer_for(&root, "current", new, Some(old)).unwrap(),
                new.version
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
