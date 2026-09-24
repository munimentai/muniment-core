use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::raw::c_void;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

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

    fn peer_code_matches(&self, expected_desktop_executable: &Path) -> bool {
        peer_audit_token(self.stream)
            .is_some_and(|token| audit_token_satisfies(&token, expected_desktop_executable))
    }
}

/// `audit_token_t` from <bsm/audit.h>: eight 32-bit words.
type AuditToken = [u32; 8];

/// Reads the audit token the kernel recorded when the peer connected.
fn peer_audit_token(stream: &UnixStream) -> Option<AuditToken> {
    let mut token: AuditToken = [0; 8];
    let mut length = std::mem::size_of_val(&token) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut length,
        )
    };
    (result == 0 && length as usize == std::mem::size_of_val(&token)).then_some(token)
}

type CFTypeRef = *const c_void;
type OSStatus = i32;

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFAllocatorDefault: CFTypeRef;
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;
    fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: isize) -> CFTypeRef;
    fn CFDictionaryCreate(
        allocator: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFTypeRef;
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: CFTypeRef,
        buffer: *const u8,
        length: isize,
        is_directory: u8,
    ) -> CFTypeRef;
    fn CFRelease(value: CFTypeRef);
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecGuestAttributeAudit: CFTypeRef;
    fn SecCodeCopyGuestWithAttributes(
        host: CFTypeRef,
        attributes: CFTypeRef,
        flags: u32,
        guest: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecStaticCodeCreateWithPath(path: CFTypeRef, flags: u32, code: *mut CFTypeRef) -> OSStatus;
    fn SecCodeCopyDesignatedRequirement(
        code: CFTypeRef,
        flags: u32,
        requirement: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OSStatus;
}

/// Releases one owned Core Foundation reference when it drops.
struct Owned(CFTypeRef);

impl Owned {
    fn new(value: CFTypeRef) -> Option<Self> {
        (!value.is_null()).then_some(Self(value))
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) };
    }
}

/// Checks the process named by `token` against the designated requirement of the
/// installed desktop executable. The lookup by audit token fails for a process whose
/// pid version changed, so an exec after connect never passes.
fn audit_token_satisfies(token: &AuditToken, expected_desktop_executable: &Path) -> bool {
    const DEFAULT_FLAGS: u32 = 0;
    let path = expected_desktop_executable.as_os_str().as_bytes();
    unsafe {
        let Some(url) = Owned::new(CFURLCreateFromFileSystemRepresentation(
            kCFAllocatorDefault,
            path.as_ptr(),
            path.len() as isize,
            0,
        )) else {
            return false;
        };
        let mut static_code = std::ptr::null();
        if SecStaticCodeCreateWithPath(url.0, DEFAULT_FLAGS, &mut static_code) != 0 {
            return false;
        }
        let Some(static_code) = Owned::new(static_code) else {
            return false;
        };
        let mut requirement = std::ptr::null();
        if SecCodeCopyDesignatedRequirement(static_code.0, DEFAULT_FLAGS, &mut requirement) != 0 {
            return false;
        }
        let Some(requirement) = Owned::new(requirement) else {
            return false;
        };
        let Some(token_data) = Owned::new(CFDataCreate(
            kCFAllocatorDefault,
            token.as_ptr().cast(),
            std::mem::size_of_val(token) as isize,
        )) else {
            return false;
        };
        let keys = [kSecGuestAttributeAudit];
        let values = [token_data.0];
        let Some(attributes) = Owned::new(CFDictionaryCreate(
            kCFAllocatorDefault,
            keys.as_ptr(),
            values.as_ptr(),
            1,
            std::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks).cast(),
            std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks).cast(),
        )) else {
            return false;
        };
        let mut guest = std::ptr::null();
        if SecCodeCopyGuestWithAttributes(std::ptr::null(), attributes.0, DEFAULT_FLAGS, &mut guest)
            != 0
        {
            return false;
        }
        let Some(guest) = Owned::new(guest) else {
            return false;
        };
        SecCodeCheckValidity(guest.0, DEFAULT_FLAGS, requirement.0) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn connected_pair() -> (UnixStream, UnixStream, PathBuf) {
        let directory = PathBuf::from("/tmp").join(format!(
            "muniment-route-native-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("s.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server, directory)
    }

    #[test]
    fn the_peer_token_names_this_process_and_its_signature() {
        let (_client, server, directory) = connected_pair();
        let reader = NativeMacosAttachRouteReader::new(&server);
        let (pid, _) = reader.peer_process().unwrap();
        assert_eq!(pid, std::process::id());
        let token = peer_audit_token(&server).unwrap();
        // audit_token_t word 5 holds the pid.
        assert_eq!(token[5], std::process::id());
        // The test binary is the peer, so its own designated requirement admits it.
        let this_executable = std::env::current_exe().unwrap();
        assert!(reader.peer_code_matches(&this_executable));
        // Another binary's designated requirement does not.
        assert!(!reader.peer_code_matches(Path::new("/bin/ls")));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
