//! Resolves the installed Windows runtime payload from validated roots.

use crate::windows_task::{is_canonical_sid, RemovalScope, SidError};
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use crate::windows_known_folders::{windows_payload_roots, WindowsKnownFolderError};

const PAYLOAD_DIRECTORY: &str = "muniment";
const PAYLOAD_FILE_NAME: &str = "muniment-runtime.exe";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadFileKind {
    Missing,
    RegularFile,
    Directory,
    SymbolicLink,
    Other,
}

/// Injected boundary around the filesystem file-kind query.
pub trait WindowsPayloadProbe {
    fn file_kind(&self, path: &Path) -> PayloadFileKind;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadRootError {
    RelativeRoot,
    ParentPathSegment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPayloadScopes {
    pub machine_payload_path: Option<PathBuf>,
    pub per_user_payload_path: Option<PathBuf>,
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveWindowsPayloadScopesError {
    KnownFolder(WindowsKnownFolderError),
    PayloadRoot(PayloadRootError),
}

impl WindowsPayloadScopes {
    /// Builds the removal scope for an installed per-user payload.
    pub fn per_user_removal_scope(&self, user_sid: &str) -> Result<Option<RemovalScope>, SidError> {
        if !is_canonical_sid(user_sid) {
            return Err(SidError::NotCanonical);
        }
        Ok(self
            .per_user_payload_path
            .as_ref()
            .map(|payload_path| RemovalScope::PerUser {
                user_sid: user_sid.to_owned(),
                payload_path: payload_path.clone(),
                machine_payload_path: self.machine_payload_path.clone(),
            }))
    }

    /// Builds the removal scope for an installed machine payload.
    pub fn machine_removal_scope(&self) -> Option<RemovalScope> {
        self.machine_payload_path
            .as_ref()
            .map(|payload_path| RemovalScope::Machine {
                payload_path: payload_path.clone(),
                per_user_payload_path: self.per_user_payload_path.clone(),
            })
    }
}

/// Resolves the installed machine and per-user payloads from Shell known folders.
#[cfg(target_os = "windows")]
pub fn resolve_live_windows_payload_scopes(
) -> Result<WindowsPayloadScopes, LiveWindowsPayloadScopesError> {
    let roots = windows_payload_roots().map_err(LiveWindowsPayloadScopesError::KnownFolder)?;
    resolve_windows_payload_scopes(
        roots.program_files,
        roots.local_app_data,
        &WindowsNativePayloadProbe,
    )
    .map_err(LiveWindowsPayloadScopesError::PayloadRoot)
}

/// Resolves the machine and per-user payloads independently.
pub fn resolve_windows_payload_scopes(
    program_files_root: impl AsRef<Path>,
    local_app_data_root: impl AsRef<Path>,
    probe: &impl WindowsPayloadProbe,
) -> Result<WindowsPayloadScopes, PayloadRootError> {
    let program_files_root = program_files_root.as_ref();
    let local_app_data_root = local_app_data_root.as_ref();
    validate_root(program_files_root)?;
    validate_root(local_app_data_root)?;

    let machine_payload_path = payload_path(program_files_root);
    let per_user_payload_path = payload_path(local_app_data_root);
    Ok(WindowsPayloadScopes {
        machine_payload_path: (probe.file_kind(&machine_payload_path)
            == PayloadFileKind::RegularFile)
            .then_some(machine_payload_path),
        per_user_payload_path: (probe.file_kind(&per_user_payload_path)
            == PayloadFileKind::RegularFile)
            .then_some(per_user_payload_path),
    })
}

/// Resolves the machine payload first, then the per-user payload.
pub fn resolve_windows_payload(
    program_files_root: impl AsRef<Path>,
    local_app_data_root: impl AsRef<Path>,
    probe: &impl WindowsPayloadProbe,
) -> Result<Option<PathBuf>, PayloadRootError> {
    let program_files_root = program_files_root.as_ref();
    let local_app_data_root = local_app_data_root.as_ref();
    validate_root(program_files_root)?;
    validate_root(local_app_data_root)?;

    let machine_payload = payload_path(program_files_root);
    if probe.file_kind(&machine_payload) == PayloadFileKind::RegularFile {
        return Ok(Some(machine_payload));
    }

    let user_payload = payload_path(local_app_data_root);
    if probe.file_kind(&user_payload) == PayloadFileKind::RegularFile {
        return Ok(Some(user_payload));
    }

    Ok(None)
}

fn payload_path(root: &Path) -> PathBuf {
    root.join(PAYLOAD_DIRECTORY).join(PAYLOAD_FILE_NAME)
}

fn validate_root(root: &Path) -> Result<(), PayloadRootError> {
    let Some(root_text) = root.to_str() else {
        return Err(PayloadRootError::RelativeRoot);
    };
    let segments: Vec<_> = root_text.split(['\\', '/']).collect();
    if segments.contains(&"..") {
        return Err(PayloadRootError::ParentPathSegment);
    }
    if !root.is_absolute() && !is_absolute_windows_path(root_text, &segments) {
        return Err(PayloadRootError::RelativeRoot);
    }
    Ok(())
}

fn is_absolute_windows_path(path: &str, segments: &[&str]) -> bool {
    let drive_absolute = path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && matches!(path.as_bytes().get(2), Some(b'\\' | b'/'));
    let unc_absolute = (path.starts_with(r"\\") || path.starts_with("//"))
        && segments.get(2).is_some_and(|server| !server.is_empty())
        && segments.get(3).is_some_and(|share| !share.is_empty());
    drive_absolute || unc_absolute
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsNativePayloadProbe;

#[cfg(target_os = "windows")]
impl WindowsPayloadProbe for WindowsNativePayloadProbe {
    fn file_kind(&self, path: &Path) -> PayloadFileKind {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return PayloadFileKind::Missing;
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            PayloadFileKind::SymbolicLink
        } else if file_type.is_file() {
            PayloadFileKind::RegularFile
        } else if file_type.is_dir() {
            PayloadFileKind::Directory
        } else {
            PayloadFileKind::Other
        }
    }
}
