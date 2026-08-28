//! Resolves Windows paths through the Shell known-folder API.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows_sys::core::{GUID, PWSTR};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramFiles, FOLDERID_RoamingAppData, SHGetKnownFolderPath,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsKnownFolder {
    ProgramFiles,
    LocalAppData,
    RoamingAppData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsKnownFolderError {
    Query {
        folder: WindowsKnownFolder,
        hresult: i32,
    },
    MissingPath(WindowsKnownFolder),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPayloadRoots {
    pub program_files: PathBuf,
    pub local_app_data: PathBuf,
}

/// Resolves the installed payload roots without reading the environment.
pub fn windows_payload_roots() -> Result<WindowsPayloadRoots, WindowsKnownFolderError> {
    Ok(WindowsPayloadRoots {
        program_files: known_folder_path(WindowsKnownFolder::ProgramFiles, &FOLDERID_ProgramFiles)?,
        local_app_data: windows_local_app_data()?,
    })
}

/// Resolves the local application data root without reading the environment.
pub fn windows_local_app_data() -> Result<PathBuf, WindowsKnownFolderError> {
    known_folder_path(WindowsKnownFolder::LocalAppData, &FOLDERID_LocalAppData)
}

/// Resolves the roaming application data root without reading the environment.
pub fn windows_roaming_app_data() -> Result<PathBuf, WindowsKnownFolderError> {
    known_folder_path(WindowsKnownFolder::RoamingAppData, &FOLDERID_RoamingAppData)
}

fn known_folder_path(
    folder: WindowsKnownFolder,
    folder_id: &GUID,
) -> Result<PathBuf, WindowsKnownFolderError> {
    let mut path: PWSTR = std::ptr::null_mut();
    let hresult = unsafe { SHGetKnownFolderPath(folder_id, 0, std::ptr::null_mut(), &mut path) };
    let path = KnownFolderPath(path);

    if hresult < 0 {
        return Err(WindowsKnownFolderError::Query { folder, hresult });
    }
    if path.0.is_null() {
        return Err(WindowsKnownFolderError::MissingPath(folder));
    }

    let mut length = 0;
    unsafe {
        while *path.0.add(length) != 0 {
            length += 1;
        }
        Ok(PathBuf::from(OsString::from_wide(
            std::slice::from_raw_parts(path.0, length),
        )))
    }
}

struct KnownFolderPath(PWSTR);

impl Drop for KnownFolderPath {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(self.0.cast()) };
    }
}
