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
    retry_windows_replace(|| replace_once(source, destination))
}

#[cfg(windows)]
fn retry_windows_replace(mut replace: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

    // A scanner can briefly hold either file. Limit the total retry delay to 500 milliseconds.
    for attempt in 0..=10 {
        match replace() {
            Err(error)
                if attempt < 10
                    && matches!(error.raw_os_error(), Some(code)
                        if code == ERROR_SHARING_VIOLATION as i32 || code == ERROR_ACCESS_DENIED as i32) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            result => return result,
        }
    }
    unreachable!()
}

#[cfg(windows)]
fn replace_once(source: &Path, destination: &Path) -> io::Result<()> {
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    #[test]
    fn closes_the_source_writer_while_pi_keeps_the_destination_open() {
        use std::io::{Read, Write};

        for writable in [false, true] {
            let root =
                std::env::temp_dir().join(format!("muniment-replace-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            let source = root.join("settings.tmp");
            let destination = root.join("settings.json");
            fs::write(&destination, b"old").unwrap();
            // Pi uses Node's libuv file opens, which share read, write, and delete access.
            let mut pi = fs::OpenOptions::new()
                .read(true)
                .write(writable)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(&destination)
                .unwrap();
            let mut writer = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&source)
                .unwrap();
            writer.write_all(b"new").unwrap();
            writer.sync_all().unwrap();
            let error = replace_once(&source, &destination).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(ERROR_SHARING_VIOLATION as i32));
            assert_eq!(fs::read(&destination).unwrap(), b"old");
            drop(writer);
            replace(&source, &destination).unwrap();
            assert_eq!(fs::read(&destination).unwrap(), b"new");
            assert!(!source.exists());
            let mut old = String::new();
            pi.read_to_string(&mut old).unwrap();
            assert_eq!(old, "old");
            drop(pi);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn retries_sharing_and_access_errors_until_success() {
        let mut errors = [ERROR_SHARING_VIOLATION, ERROR_ACCESS_DENIED].into_iter();
        let mut attempts = 0;
        retry_windows_replace(|| {
            attempts += 1;
            match errors.next() {
                Some(code) => Err(io::Error::from_raw_os_error(code as i32)),
                None => Ok(()),
            }
        })
        .unwrap();
        assert_eq!(attempts, 3);
    }

    #[test]
    fn bounds_retries_and_preserves_the_last_error() {
        for code in [ERROR_SHARING_VIOLATION, ERROR_ACCESS_DENIED] {
            let mut attempts = 0;
            let error = retry_windows_replace(|| {
                attempts += 1;
                Err(io::Error::from_raw_os_error(code as i32))
            })
            .unwrap_err();
            assert_eq!(attempts, 11);
            assert_eq!(error.raw_os_error(), Some(code as i32));
        }
    }

    #[test]
    fn returns_other_errors_without_retry() {
        let mut attempts = 0;
        let error = retry_windows_replace(|| {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::NotFound))
        })
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn replaces_after_a_scanner_releases_the_source() {
        for existing in [false, true] {
            let root =
                std::env::temp_dir().join(format!("muniment-replace-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            let source = root.join("settings.tmp");
            let destination = root.join("settings.json");
            fs::write(&source, b"new").unwrap();
            if existing {
                fs::write(&destination, b"old").unwrap();
            }
            let scanner = fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&source)
                .unwrap();
            // Confirm that the handle blocks both rename and ReplaceFileW before releasing it.
            let error = replace_once(&source, &destination).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(ERROR_SHARING_VIOLATION as i32));
            let release = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                drop(scanner);
            });
            let result = replace(&source, &destination);
            release.join().unwrap();
            result.unwrap();
            assert_eq!(fs::read(&destination).unwrap(), b"new");
            assert!(!source.exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn a_persistent_scanner_keeps_both_files_intact() {
        let root = std::env::temp_dir().join(format!("muniment-replace-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let source = root.join("settings.tmp");
        let destination = root.join("settings.json");
        fs::write(&source, b"new").unwrap();
        fs::write(&destination, b"old").unwrap();
        let scanner = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&source)
            .unwrap();
        let error = replace(&source, &destination).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(ERROR_SHARING_VIOLATION as i32));
        assert_eq!(fs::read(&source).unwrap(), b"new");
        assert_eq!(fs::read(&destination).unwrap(), b"old");
        drop(scanner);
        fs::remove_dir_all(root).unwrap();
    }
}
