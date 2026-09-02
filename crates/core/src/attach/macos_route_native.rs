use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use super::{MacosAttachRouteReader, MacosPeerReadError};

/// Reads the connected peer process from a Unix-domain stream.
pub struct NativeMacosAttachRouteReader<'stream> {
    stream: &'stream UnixStream,
}

impl<'stream> NativeMacosAttachRouteReader<'stream> {
    /// Creates a route reader for the connected stream.
    pub fn new(stream: &'stream UnixStream) -> Self {
        Self { stream }
    }
}

impl MacosAttachRouteReader for NativeMacosAttachRouteReader<'_> {
    fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError> {
        let mut process_id: libc::pid_t = 0;
        let mut process_id_length = std::mem::size_of_val(&process_id) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                self.stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut process_id as *mut libc::pid_t).cast(),
                &mut process_id_length,
            )
        } != 0
            || process_id_length as usize != std::mem::size_of_val(&process_id)
        {
            return Err(MacosPeerReadError);
        }
        let peer_pid = u32::try_from(process_id).map_err(|_| MacosPeerReadError)?;
        if peer_pid == 0 {
            return Err(MacosPeerReadError);
        }

        let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let path_length = unsafe {
            libc::proc_pidpath(
                process_id,
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len()).map_err(|_| MacosPeerReadError)?,
            )
        };
        if path_length <= 0 {
            return Err(MacosPeerReadError);
        }
        let path_length = usize::try_from(path_length).map_err(|_| MacosPeerReadError)?;
        if path_length > buffer.len() {
            return Err(MacosPeerReadError);
        }
        buffer.truncate(path_length);
        if buffer.last() == Some(&0) {
            buffer.pop();
        }
        if buffer.is_empty() || buffer.contains(&0) {
            return Err(MacosPeerReadError);
        }

        Ok((peer_pid, OsString::from_vec(buffer).into()))
    }
}
