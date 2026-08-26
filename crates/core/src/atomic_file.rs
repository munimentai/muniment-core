use std::fs;
use std::io;
use std::path::Path;

/// Replaces `destination` with `source` atomically.
#[cfg(not(target_os = "windows"))]
pub fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

/// Replaces `destination` with `source` atomically.
#[cfg(target_os = "windows")]
pub fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    if !destination.exists() {
        return fs::rename(source, destination);
    }

    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let replaced = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            source.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if replaced == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
