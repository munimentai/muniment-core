use std::cell::RefCell;
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
    code_check: RefCell<CodeCheck>,
}

/// Each status stays absent until its Security call runs.
#[derive(Debug, Default)]
struct CodeCheck {
    audit_token: bool,
    bundle: bool,
    plist_read: bool,
    sec_static_code_create_with_path: Option<OSStatus>,
    sec_static_code_create_with_path_and_attributes: Option<OSStatus>,
    sec_static_code_check_validity: Option<OSStatus>,
    sec_code_copy_designated_requirement: Option<OSStatus>,
    sec_code_copy_guest_with_attributes: Option<OSStatus>,
    sec_code_check_validity: Option<OSStatus>,
    sec_code_copy_signing_information_disk: Option<OSStatus>,
    sec_code_copy_signing_information_peer: Option<OSStatus>,
    code_hash_match: bool,
}

impl<'stream> NativeMacosAttachRouteReader<'stream> {
    /// Creates a route reader for the connected stream.
    pub fn new(stream: &'stream UnixStream) -> Self {
        Self {
            stream,
            code_check: RefCell::new(CodeCheck::default()),
        }
    }
}

fn peer_read_failure(
    operation: &str,
    process_id: libc::pid_t,
    length: usize,
    errno: Option<i32>,
) -> MacosPeerReadError {
    crate::runtime_eprintln!(
        "muniment-runtime: macos peer read failed operation={operation} peer_pid={process_id} length={length} errno={errno:?}"
    );
    MacosPeerReadError
}

impl MacosAttachRouteReader for NativeMacosAttachRouteReader<'_> {
    fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError> {
        *self.code_check.borrow_mut() = CodeCheck::default();
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
        {
            // Readiness probes connect and close without a frame.
            // XNU returns ENOTCONN if the peer closes before this read.
            let errno = std::io::Error::last_os_error().raw_os_error();
            return Err(peer_read_failure(
                "LOCAL_PEERPID",
                process_id,
                process_id_length as usize,
                errno,
            ));
        }
        if process_id_length as usize != std::mem::size_of_val(&process_id) || process_id <= 0 {
            return Err(peer_read_failure(
                "LOCAL_PEERPID-invalid-result",
                process_id,
                process_id_length as usize,
                None,
            ));
        }
        let peer_pid = process_id as u32;

        let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let path_length = unsafe {
            libc::proc_pidpath(
                process_id,
                buffer.as_mut_ptr().cast(),
                libc::PROC_PIDPATHINFO_MAXSIZE as u32,
            )
        };
        if path_length <= 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            return Err(peer_read_failure("proc_pidpath", process_id, 0, errno));
        }
        let path_length = path_length as usize;
        if path_length > buffer.len() {
            return Err(peer_read_failure(
                "proc_pidpath-invalid-length",
                process_id,
                path_length,
                None,
            ));
        }
        buffer.truncate(path_length);
        if buffer.last() == Some(&0) {
            buffer.pop();
        }
        if buffer.is_empty() || buffer.contains(&0) {
            return Err(peer_read_failure(
                "proc_pidpath-invalid-path",
                process_id,
                path_length,
                None,
            ));
        }

        Ok((peer_pid, OsString::from_vec(buffer).into()))
    }

    fn peer_code_matches(&self, expected_desktop_executable: &Path) -> bool {
        let mut check = self.code_check.borrow_mut();
        *check = CodeCheck::default();
        let Some(token) = peer_audit_token(self.stream) else {
            return false;
        };
        check.audit_token = true;
        audit_token_satisfies(&token, expected_desktop_executable, &mut check)
    }

    fn log_companion_fallback(
        &self,
        peer_pid: u32,
        path_match: bool,
        peer_image_path: Option<&Path>,
        expected_desktop_executable: &Path,
    ) {
        crate::runtime_eprintln!(
            "muniment-runtime: macos attach route=Companion peer_pid={peer_pid} path_match={path_match} peer_path={peer_image_path:?} expected_path={expected_desktop_executable:?} code_check={:?}",
            self.code_check.borrow()
        );
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
    static kCFBooleanTrue: CFTypeRef;
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;
    fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: isize) -> CFTypeRef;
    fn CFStringCreateWithCString(
        allocator: CFTypeRef,
        string: *const i8,
        encoding: u32,
    ) -> CFTypeRef;
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
    fn CFDictionaryGetValue(dictionary: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFArrayGetCount(array: CFTypeRef) -> isize;
    fn CFArrayGetValueAtIndex(array: CFTypeRef, index: isize) -> CFTypeRef;
    fn CFEqual(left: CFTypeRef, right: CFTypeRef) -> u8;
    fn CFRelease(value: CFTypeRef);
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecGuestAttributeAudit: CFTypeRef;
    static kSecGuestAttributeDynamicCode: CFTypeRef;
    static kSecGuestAttributeDynamicCodeInfoPlist: CFTypeRef;
    static kSecCodeInfoUnique: CFTypeRef;
    static kSecCodeInfoCdHashes: CFTypeRef;
    static kSecCodeAttributeArchitecture: CFTypeRef;
    fn SecCodeCopyGuestWithAttributes(
        host: CFTypeRef,
        attributes: CFTypeRef,
        flags: u32,
        guest: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecStaticCodeCreateWithPath(path: CFTypeRef, flags: u32, code: *mut CFTypeRef) -> OSStatus;
    fn SecStaticCodeCreateWithPathAndAttributes(
        path: CFTypeRef,
        flags: u32,
        attributes: CFTypeRef,
        code: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecStaticCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OSStatus;
    fn SecCodeCopyDesignatedRequirement(
        code: CFTypeRef,
        flags: u32,
        requirement: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: CFTypeRef,
        flags: u32,
        information: *mut CFTypeRef,
    ) -> OSStatus;
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
fn audit_token_satisfies(
    token: &AuditToken,
    expected_desktop_executable: &Path,
    check: &mut CodeCheck,
) -> bool {
    const DEFAULT_FLAGS: u32 = 0;
    let contents = expected_desktop_executable
        .parent()
        .filter(|parent| parent.file_name() == Some(std::ffi::OsStr::new("MacOS")))
        .and_then(Path::parent)
        .filter(|parent| parent.file_name() == Some(std::ffi::OsStr::new("Contents")));
    let bundle = contents.and_then(Path::parent);
    check.bundle = bundle.is_some();
    let plist = if let Some(contents) = contents {
        let Ok(bytes) = std::fs::read(contents.join("Info.plist")) else {
            return false;
        };
        check.plist_read = true;
        Some(bytes)
    } else {
        None
    };
    let path = bundle
        .unwrap_or(expected_desktop_executable)
        .as_os_str()
        .as_bytes();
    unsafe {
        let Some(url) = Owned::new(CFURLCreateFromFileSystemRepresentation(
            kCFAllocatorDefault,
            path.as_ptr(),
            path.len() as isize,
            u8::from(bundle.is_some()),
        )) else {
            return false;
        };
        let mut static_code = std::ptr::null();
        let status = SecStaticCodeCreateWithPath(url.0, DEFAULT_FLAGS, &mut static_code);
        check.sec_static_code_create_with_path = Some(status);
        if status != 0 {
            return false;
        }
        let Some(static_code) = Owned::new(static_code) else {
            return false;
        };
        if bundle.is_some() {
            // Validate the bundle seal before binding its plist to the live code.
            const CHECK_ALL_ARCHITECTURES: u32 = 1 << 0;
            let status = SecStaticCodeCheckValidity(
                static_code.0,
                CHECK_ALL_ARCHITECTURES,
                std::ptr::null(),
            );
            check.sec_static_code_check_validity = Some(status);
            if status != 0 {
                return false;
            }
        }
        let mut requirement = std::ptr::null();
        let status =
            SecCodeCopyDesignatedRequirement(static_code.0, DEFAULT_FLAGS, &mut requirement);
        check.sec_code_copy_designated_requirement = Some(status);
        if status != 0 {
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
        // Executable-path bundle discovery can lose the signed Info.plist binding.
        // Supply the raw plist with the audit token. Security checks its signed hash.
        // Keep both the bundle seal check and the live designated requirement check.
        let plist_data = match plist {
            Some(bytes) => {
                let Some(data) = Owned::new(CFDataCreate(
                    kCFAllocatorDefault,
                    bytes.as_ptr(),
                    bytes.len() as isize,
                )) else {
                    return false;
                };
                Some(data)
            }
            None => None,
        };
        let mut keys = vec![kSecGuestAttributeAudit];
        let mut values = vec![token_data.0];
        if let Some(data) = &plist_data {
            keys.extend([
                kSecGuestAttributeDynamicCode,
                kSecGuestAttributeDynamicCodeInfoPlist,
            ]);
            values.extend([kCFBooleanTrue, data.0]);
        }
        let Some(attributes) = Owned::new(CFDictionaryCreate(
            kCFAllocatorDefault,
            keys.as_ptr(),
            values.as_ptr(),
            keys.len() as isize,
            std::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks).cast(),
            std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks).cast(),
        )) else {
            return false;
        };
        let mut guest = std::ptr::null();
        let status = SecCodeCopyGuestWithAttributes(
            std::ptr::null(),
            attributes.0,
            DEFAULT_FLAGS,
            &mut guest,
        );
        check.sec_code_copy_guest_with_attributes = Some(status);
        if status != 0 {
            return false;
        }
        let Some(guest) = Owned::new(guest) else {
            return false;
        };
        let status = SecCodeCheckValidity(guest.0, DEFAULT_FLAGS, requirement.0);
        check.sec_code_check_validity = Some(status);
        if status != 0 {
            return false;
        }
        if bundle.is_none() {
            return true;
        }

        // Bind the live code to the installed build, not just its signing identity.
        // A replaced executable must not admit an older process with the same requirement.
        // Compare the expected bundle's hashes, not the peer clone's on-disk hashes.
        let mut peer_information = std::ptr::null();
        let status = SecCodeCopySigningInformation(guest.0, DEFAULT_FLAGS, &mut peer_information);
        check.sec_code_copy_signing_information_peer = Some(status);
        if status != 0 {
            return false;
        }
        let Some(peer_information) = Owned::new(peer_information) else {
            return false;
        };
        let peer_hash = CFDictionaryGetValue(peer_information.0, kSecCodeInfoUnique);
        if peer_hash.is_null() {
            return false;
        }
        // CdHashes covers digest algorithms, not architectures. Check both desktop slices for Rosetta.
        for architecture in [c"arm64", c"x86_64"] {
            const UTF8: u32 = 0x08000100;
            let Some(architecture) = Owned::new(CFStringCreateWithCString(
                kCFAllocatorDefault,
                architecture.as_ptr(),
                UTF8,
            )) else {
                return false;
            };
            let Some(attributes) = Owned::new(CFDictionaryCreate(
                kCFAllocatorDefault,
                &kSecCodeAttributeArchitecture,
                &architecture.0,
                1,
                std::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks).cast(),
                std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks).cast(),
            )) else {
                return false;
            };
            let mut slice = std::ptr::null();
            let status = SecStaticCodeCreateWithPathAndAttributes(
                url.0,
                DEFAULT_FLAGS,
                attributes.0,
                &mut slice,
            );
            check.sec_static_code_create_with_path_and_attributes = Some(status);
            if status != 0 {
                continue;
            }
            let Some(slice) = Owned::new(slice) else {
                return false;
            };
            let status = SecStaticCodeCheckValidity(slice.0, DEFAULT_FLAGS, std::ptr::null());
            check.sec_static_code_check_validity = Some(status);
            if status != 0 {
                return false;
            }
            let mut disk_information = std::ptr::null();
            let status =
                SecCodeCopySigningInformation(slice.0, DEFAULT_FLAGS, &mut disk_information);
            check.sec_code_copy_signing_information_disk = Some(status);
            if status != 0 {
                return false;
            }
            let Some(disk_information) = Owned::new(disk_information) else {
                return false;
            };
            let disk_hashes = CFDictionaryGetValue(disk_information.0, kSecCodeInfoCdHashes);
            if !disk_hashes.is_null()
                && (0..CFArrayGetCount(disk_hashes)).any(|index| {
                    CFEqual(CFArrayGetValueAtIndex(disk_hashes, index), peer_hash) != 0
                })
            {
                check.code_hash_match = true;
                return true;
            }
        }
        false
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
    fn signed_bundle_routes_require_the_live_signature_and_unchanged_bundle() {
        check_signed_bundle_route(false);
    }

    #[test]
    fn signed_clone_routes_require_the_live_signature_and_unchanged_bundle() {
        check_signed_bundle_route(true);
    }

    fn check_signed_bundle_route(from_clone: bool) {
        use super::super::{name_macos_attach_connection_route, MacosAttachConnectionRoute};
        use std::io::Read;
        use std::process::{Child, Command};

        struct Fixture {
            directory: PathBuf,
            child: Option<Child>,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                if let Some(child) = &mut self.child {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                let _ = std::fs::remove_dir_all(&self.directory);
            }
        }
        fn run(command: &mut Command) {
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut fixture = Fixture {
            directory: PathBuf::from("/tmp").join(format!(
                "muniment-signed-route-{}",
                uuid::Uuid::now_v7().simple()
            )),
            child: None,
        };
        let app = fixture.directory.join("Peer.app");
        let contents = app.join("Contents");
        std::fs::create_dir_all(contents.join("MacOS")).unwrap();
        let executable = contents.join("MacOS/peer");
        let plist = contents.join("Info.plist");
        let plist_bytes = br#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>peer</string>
<key>CFBundleIdentifier</key><string>ai.muniment.route-test</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>"#;
        std::fs::write(&plist, plist_bytes).unwrap();
        let source = fixture.directory.join("peer.c");
        std::fs::write(
            &source,
            r#"#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return BUILD;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(argv[1]) >= sizeof(address.sun_path)) return 2;
    strcpy(address.sun_path, argv[1]);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, (void *)&address, sizeof(address))) return 3;
    if (write(fd, "!", 1) != 1) return 4;
    char done;
    read(fd, &done, 1);
    close(fd);
    return 0;
}
"#,
        )
        .unwrap();
        let compile = |output: &Path, build: &str| {
            let mut command = Command::new("/usr/bin/clang");
            if from_clone {
                command.args(["-arch", "arm64", "-arch", "x86_64"]);
            }
            run(command
                .arg(format!("-DBUILD={build}"))
                .arg(&source)
                .arg("-o")
                .arg(output));
        };
        let sign = || {
            run(Command::new("/usr/bin/codesign")
                .args([
                    "--force",
                    "--sign",
                    "-",
                    "--identifier",
                    "ai.muniment.route-test",
                ])
                .args([
                    "--requirements",
                    "designated => identifier \"ai.muniment.route-test\"",
                ])
                .arg(&app));
        };
        compile(&executable, "1");
        sign();
        let endpoint = fixture.directory.join("s.sock");
        let listener = UnixListener::bind(&endpoint).unwrap();
        listener.set_nonblocking(true).unwrap();
        let clone = fixture.directory.join(
            "X/ai.muniment.desktop.code_sign_clone/code_sign_clone.fixture/muniment.app.bundle",
        );
        std::fs::create_dir_all(clone.parent().unwrap()).unwrap();
        run(Command::new("/usr/bin/ditto").arg(&app).arg(&clone));
        let clone_executable = clone.join("Contents/MacOS/peer");
        let peer_executable = if from_clone {
            &clone_executable
        } else {
            &executable
        };
        fixture.child = Some(
            Command::new(peer_executable)
                .arg(&endpoint)
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut server = loop {
            match listener.accept() {
                Ok((server, _)) => break server,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "The peer did not connect."
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("{error}"),
            }
        };
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        server.read_exact(&mut [0]).unwrap();
        let peer_pid = fixture.child.as_ref().unwrap().id();
        // proc_pidpath resolves /tmp to /private/tmp on macOS.
        let expected = executable.canonicalize().unwrap();
        let reader = NativeMacosAttachRouteReader::new(&server);
        assert_eq!(
            name_macos_attach_connection_route(&reader, &expected),
            MacosAttachConnectionRoute::DesktopClient { peer_pid },
            "{:?}",
            reader.code_check.borrow()
        );
        assert_eq!(reader.code_check.borrow().sec_code_check_validity, Some(0));
        assert!(reader.code_check.borrow().code_hash_match);
        assert_eq!(
            name_macos_attach_connection_route(&reader, &clone_executable),
            MacosAttachConnectionRoute::DesktopClient { peer_pid },
            "{:?}",
            reader.code_check.borrow()
        );

        std::fs::write(&plist, b"invalid plist").unwrap();
        assert_eq!(
            name_macos_attach_connection_route(&reader, &expected),
            MacosAttachConnectionRoute::Companion { peer_pid }
        );
        std::fs::write(&plist, plist_bytes).unwrap();

        // Replace the file without changing the running image or the designated requirement.
        let replacement = fixture.directory.join("replacement");
        compile(&replacement, "2");
        std::fs::rename(replacement, &executable).unwrap();
        sign();
        assert!(!reader.peer_code_matches(&expected));
        assert_eq!(reader.code_check.borrow().sec_code_check_validity, Some(0));
        assert!(!reader.code_check.borrow().code_hash_match);
        assert_eq!(
            name_macos_attach_connection_route(&reader, &expected),
            MacosAttachConnectionRoute::Companion { peer_pid }
        );
    }

    #[test]
    fn a_closed_peer_fails_the_peer_read_without_desktop_admission() {
        use super::super::{name_macos_attach_connection_route, MacosAttachConnectionRoute};
        use std::io::Read;

        let (client, mut server, directory) = connected_pair();
        drop(client);
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        assert_eq!(server.read(&mut [0]).unwrap(), 0);
        let reader = NativeMacosAttachRouteReader::new(&server);
        assert_eq!(reader.peer_process(), Err(MacosPeerReadError));
        assert_eq!(
            name_macos_attach_connection_route(&reader, &std::env::current_exe().unwrap()),
            MacosAttachConnectionRoute::Companion { peer_pid: 0 }
        );
        assert!(!reader.code_check.borrow().audit_token);
        std::fs::remove_dir_all(directory).unwrap();
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
        assert_eq!(
            super::super::name_macos_attach_connection_route(&reader, Path::new("/bin/ls")),
            super::super::MacosAttachConnectionRoute::Companion { peer_pid: pid }
        );
        // A path mismatch must not erase the failed code check from diagnostics.
        assert!(reader.code_check.borrow().audit_token);
        assert_ne!(reader.code_check.borrow().sec_code_check_validity, Some(0));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
