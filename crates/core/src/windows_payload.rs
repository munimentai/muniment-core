//! Resolves the installed Windows runtime payload from validated roots.

use crate::windows_task::{
    is_canonical_sid, plan_task_removal, ObservedRegistration, RemovalScope, SidError,
    TaskRemovalPlan,
};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use crate::windows_known_folders::{windows_payload_roots, WindowsKnownFolderError};

const PAYLOAD_DIRECTORY: &str = "muniment";
const PAYLOAD_FILE_NAME: &str = "muniment-runtime.exe";
const DESKTOP_FILE_NAME: &str = "muniment-desktop.exe";

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedTaskRemoval {
    pub registration: ObservedRegistration,
    pub plan: TaskRemovalPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UninstallerRemovalPlan {
    pub scope: RemovalScope,
    pub tasks: Vec<PlannedTaskRemoval>,
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveWindowsPayloadScopesError {
    KnownFolder(WindowsKnownFolderError),
    PayloadRoot(PayloadRootError),
}

#[cfg(target_os = "windows")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveWindowsPayload {
    pub payload_path: PathBuf,
    pub machine_payload_root: PathBuf,
    pub user_payload_root: PathBuf,
}

/// Pairs every observed registration with its removal plan for one scope.
pub fn plan_scope_task_removals(
    scope: RemovalScope,
    registrations: &[ObservedRegistration],
) -> UninstallerRemovalPlan {
    let tasks = registrations
        .iter()
        .map(|registration| PlannedTaskRemoval {
            registration: registration.clone(),
            plan: plan_task_removal(&scope, registration),
        })
        .collect();
    UninstallerRemovalPlan { scope, tasks }
}

/// Plans every installed uninstaller scope against all observed registrations.
pub fn plan_windows_payload_removals(
    payload_scopes: &WindowsPayloadScopes,
    user_sid: &str,
    registrations: &[ObservedRegistration],
) -> Result<Vec<UninstallerRemovalPlan>, SidError> {
    let per_user_scope = payload_scopes.per_user_removal_scope(user_sid)?;
    Ok(per_user_scope
        .into_iter()
        .chain(payload_scopes.machine_removal_scope(user_sid))
        .map(|scope| plan_scope_task_removals(scope, registrations))
        .collect())
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

    /// Builds the removal scope for an installed machine payload run by `user_sid`.
    pub fn machine_removal_scope(&self, user_sid: &str) -> Option<RemovalScope> {
        self.machine_payload_path
            .as_ref()
            .map(|payload_path| RemovalScope::Machine {
                invoking_user_sid: user_sid.to_owned(),
                payload_path: payload_path.clone(),
                per_user_payload_path: self.per_user_payload_path.clone(),
            })
    }
}

/// Maps an installed Windows runtime payload to its sibling desktop executable.
pub fn installed_desktop_executable_from(runtime_payload: &Path) -> Option<PathBuf> {
    if runtime_payload.is_absolute() {
        if runtime_payload.file_name() != Some(OsStr::new(PAYLOAD_FILE_NAME)) {
            return None;
        }
        let payload_directory = runtime_payload.parent()?;
        if payload_directory.file_name() != Some(OsStr::new(PAYLOAD_DIRECTORY)) {
            return None;
        }
        return Some(payload_directory.join(DESKTOP_FILE_NAME));
    }

    // Windows paths are not absolute to std::path on non-Windows test hosts.
    let path_text = runtime_payload.to_str()?;
    let segments: Vec<_> = path_text.split(['\\', '/']).collect();
    if !is_absolute_windows_path(path_text, &segments)
        || segments.last() != Some(&PAYLOAD_FILE_NAME)
        || segments.iter().rev().nth(1) != Some(&PAYLOAD_DIRECTORY)
    {
        return None;
    }

    Some(PathBuf::from(format!(
        "{}{}",
        path_text.strip_suffix(PAYLOAD_FILE_NAME)?,
        DESKTOP_FILE_NAME
    )))
}

/// Resolves the live desktop executable beside the installed runtime payload.
#[cfg(target_os = "windows")]
pub fn resolve_live_windows_desktop_executable(
) -> Result<Option<PathBuf>, LiveWindowsPayloadScopesError> {
    Ok(resolve_live_windows_payload()?
        .and_then(|payload| installed_desktop_executable_from(&payload.payload_path)))
}

/// Resolves the installed payload and its roots from Shell known folders.
///
/// The machine payload takes precedence while it exists.
#[cfg(target_os = "windows")]
pub fn resolve_live_windows_payload(
) -> Result<Option<LiveWindowsPayload>, LiveWindowsPayloadScopesError> {
    let roots = windows_payload_roots().map_err(LiveWindowsPayloadScopesError::KnownFolder)?;
    let payload_path = resolve_windows_payload(
        &roots.program_files,
        &roots.local_app_data,
        &WindowsNativePayloadProbe,
    )
    .map_err(LiveWindowsPayloadScopesError::PayloadRoot)?;

    Ok(payload_path.map(|payload_path| LiveWindowsPayload {
        payload_path,
        machine_payload_root: roots.program_files,
        user_payload_root: roots.local_app_data,
    }))
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
