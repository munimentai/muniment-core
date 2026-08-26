//! Resolves the installed Windows runtime payload without reading known folders.

use std::path::{Path, PathBuf};

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
