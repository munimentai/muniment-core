use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

/// Resolves the effective user's home from the OS user database.
#[cfg(target_os = "macos")]
pub fn effective_user_home() -> io::Result<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStringExt;

    let uid = unsafe { libc::geteuid() };
    let buffer_size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let buffer_size = if buffer_size > 0 {
        usize::try_from(buffer_size).map_err(|_| io::Error::from(io::ErrorKind::NotFound))?
    } else {
        16 * 1024
    };
    let mut buffer = vec![0_u8; buffer_size];
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    let record = unsafe { record.assume_init() };
    if record.pw_dir.is_null() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    let home = unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes();
    Ok(PathBuf::from(std::ffi::OsString::from_vec(home.to_vec())))
}

/// Appends a record to an owner-only file and truncates it before it exceeds `max_bytes`.
pub fn append_owner_only_record(
    directory: &Path,
    file_name: &std::ffi::CStr,
    max_bytes: u64,
    record: &[u8],
) -> io::Result<()> {
    match fs::symlink_metadata(directory) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(error),
    }

    let mut directory_options = OpenOptions::new();
    directory_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory = directory_options.open(directory)?;
    validate_owner_only_directory(&directory.metadata()?)?;

    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_RDWR | libc::O_APPEND | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { fs::File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "diagnostic log path is unsafe",
        ));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if file.metadata()?.len().saturating_add(record.len() as u64) > max_bytes {
        file.set_len(0)?;
    }
    file.write_all(record)?;
    file.sync_data()
}

fn validate_owner_only_directory(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "diagnostic log directory is unsafe",
        ));
    }
    Ok(())
}
