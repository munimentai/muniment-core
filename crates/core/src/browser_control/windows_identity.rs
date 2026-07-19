//! Windows browser executable identity verification.

use std::fmt;
use std::mem;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserProcessIdentity {
    pub pid: u32,
    pub creation_time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedBrowserProcess(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    InvalidEndpoint,
    InspectionUnavailable,
    SocketNotFound,
    AmbiguousOwner,
    OwnerChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    ExpectedExecutableInvalid,
    ProcessUnavailable,
    ProcessExecutableInvalid,
    ProcessIdentityChanged,
    ExecutableMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    OwnerResolutionFailed,
    ExecutableVerificationFailed,
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEndpoint => "connection endpoints are invalid",
            Self::InspectionUnavailable => "connection inspection is unavailable",
            Self::SocketNotFound => "connection socket was not found",
            Self::AmbiguousOwner => "connection socket owner is ambiguous",
            Self::OwnerChanged => "connection socket owner changed",
        })
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExpectedExecutableInvalid => "expected browser executable is invalid",
            Self::ProcessUnavailable => "browser process is unavailable",
            Self::ProcessExecutableInvalid => "browser process executable is invalid",
            Self::ProcessIdentityChanged => "browser process identity changed",
            Self::ExecutableMismatch => "browser executable does not match",
        })
    }
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OwnerResolutionFailed => "browser connection owner could not be resolved",
            Self::ExecutableVerificationFailed => "browser connection owner was not authorized",
        })
    }
}

impl std::error::Error for ResolutionError {}
impl std::error::Error for VerificationError {}
impl std::error::Error for AuthorizationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeReadError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProcessError {
    OpenFailed,
    ImageQueryFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpConnection {
    pub local: SocketAddr,
    pub peer: SocketAddr,
    pub pid: u32,
}

/// Injected boundary around the Windows TCP table and process APIs.
pub trait WindowsIdentityReader {
    fn tcp_connections(&self, ipv6: bool) -> Result<Vec<TcpConnection>, NativeReadError>;
    fn process_identity(&self, pid: u32) -> Result<u64, NativeProcessError>;
    fn process_image(&self, pid: u32) -> Result<(u64, PathBuf), NativeProcessError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsNativeReader;

pub fn authorize_browser_process(
    local: SocketAddr,
    peer: SocketAddr,
    expected_executable: &Path,
) -> Result<AuthorizedBrowserProcess, AuthorizationError> {
    authorize_browser_process_with_reader(local, peer, expected_executable, &WindowsNativeReader)
}

#[doc(hidden)]
pub fn authorize_browser_process_with_reader(
    local: SocketAddr,
    peer: SocketAddr,
    expected_executable: &Path,
    reader: &impl WindowsIdentityReader,
) -> Result<AuthorizedBrowserProcess, AuthorizationError> {
    let observed = resolve_browser_process_with_reader(local, peer, reader)
        .map_err(|_| AuthorizationError::OwnerResolutionFailed)?;
    verify_browser_process_with_reader(observed, expected_executable, reader)
        .map_err(|_| AuthorizationError::ExecutableVerificationFailed)
}

pub fn resolve_browser_process(
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<BrowserProcessIdentity, ResolutionError> {
    resolve_browser_process_with_reader(local, peer, &WindowsNativeReader)
}

#[doc(hidden)]
pub fn resolve_browser_process_with_reader(
    local: SocketAddr,
    peer: SocketAddr,
    reader: &impl WindowsIdentityReader,
) -> Result<BrowserProcessIdentity, ResolutionError> {
    validate_endpoints(local, peer)?;
    let first = unique_owner(local, peer, reader)?;
    let creation_time = reader
        .process_identity(first)
        .map_err(|_| ResolutionError::InspectionUnavailable)?;
    let second = unique_owner(local, peer, reader)?;
    if first != second {
        return Err(ResolutionError::OwnerChanged);
    }
    Ok(BrowserProcessIdentity {
        pid: first,
        creation_time,
    })
}

fn unique_owner(
    local: SocketAddr,
    peer: SocketAddr,
    reader: &impl WindowsIdentityReader,
) -> Result<u32, ResolutionError> {
    // The table describes the browser-owned client half of the accepted socket.
    let rows = reader
        .tcp_connections(local.is_ipv6())
        .map_err(|_| ResolutionError::InspectionUnavailable)?;
    let mut owners = rows
        .iter()
        .filter(|row| row.local == peer && row.peer == local)
        .map(|row| row.pid);
    let owner = owners.next().ok_or(ResolutionError::SocketNotFound)?;
    if owners.next().is_some() {
        return Err(ResolutionError::AmbiguousOwner);
    }
    Ok(owner)
}

fn validate_endpoints(local: SocketAddr, peer: SocketAddr) -> Result<(), ResolutionError> {
    if local.port() == 0
        || peer.port() == 0
        || !local.ip().is_loopback()
        || !peer.ip().is_loopback()
        || mem::discriminant(&local.ip()) != mem::discriminant(&peer.ip())
        || local == peer
    {
        return Err(ResolutionError::InvalidEndpoint);
    }
    Ok(())
}

pub fn verify_browser_process(
    observed: BrowserProcessIdentity,
    expected_executable: &Path,
) -> Result<AuthorizedBrowserProcess, VerificationError> {
    verify_browser_process_with_reader(observed, expected_executable, &WindowsNativeReader)
}

#[doc(hidden)]
pub fn verify_browser_process_with_reader(
    observed: BrowserProcessIdentity,
    expected_executable: &Path,
    reader: &impl WindowsIdentityReader,
) -> Result<AuthorizedBrowserProcess, VerificationError> {
    if !expected_executable.is_absolute() {
        return Err(VerificationError::ExpectedExecutableInvalid);
    }
    let (creation_time, actual) =
        reader
            .process_image(observed.pid)
            .map_err(|error| match error {
                NativeProcessError::OpenFailed => VerificationError::ProcessUnavailable,
                NativeProcessError::ImageQueryFailed => VerificationError::ProcessExecutableInvalid,
            })?;
    if creation_time != observed.creation_time {
        return Err(VerificationError::ProcessIdentityChanged);
    }
    if !actual.is_absolute() {
        return Err(VerificationError::ProcessExecutableInvalid);
    }
    if !windows_paths_equal(&actual, expected_executable) {
        return Err(VerificationError::ExecutableMismatch);
    }
    Ok(AuthorizedBrowserProcess(()))
}

fn windows_paths_equal(actual: &Path, expected: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

    fn normalized(path: &Path) -> Vec<u16> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        for character in &mut value {
            if *character == b'/' as u16 {
                *character = b'\\' as u16;
            }
        }
        let verbatim = "\\\\?\\".encode_utf16().collect::<Vec<_>>();
        if value.starts_with(&verbatim) {
            value.drain(..verbatim.len());
            let unc = "UNC\\".encode_utf16().collect::<Vec<_>>();
            if value.starts_with(&unc) {
                value.drain(..unc.len());
                value.splice(0..0, "\\\\".encode_utf16());
            }
        }
        value
    }

    let actual = normalized(actual);
    let expected = normalized(expected);
    let (Ok(actual_len), Ok(expected_len)) =
        (i32::try_from(actual.len()), i32::try_from(expected.len()))
    else {
        return false;
    };
    unsafe {
        CompareStringOrdinal(
            actual.as_ptr(),
            actual_len,
            expected.as_ptr(),
            expected_len,
            1,
        ) == CSTR_EQUAL
    }
}

impl WindowsIdentityReader for WindowsNativeReader {
    fn tcp_connections(&self, ipv6: bool) -> Result<Vec<TcpConnection>, NativeReadError> {
        native_tcp_connections(ipv6)
    }

    fn process_identity(&self, pid: u32) -> Result<u64, NativeProcessError> {
        native_process(pid, false).map(|(creation_time, _)| creation_time)
    }

    fn process_image(&self, pid: u32) -> Result<(u64, PathBuf), NativeProcessError> {
        native_process_image(pid)
    }
}

fn native_tcp_connections(ipv6: bool) -> Result<Vec<TcpConnection>, NativeReadError> {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCP_STATE_ESTAB,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let family = if ipv6 { AF_INET6 } else { AF_INET } as u32;
    let mut size = 0u32;
    let result = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if result != ERROR_INSUFFICIENT_BUFFER || size < 4 {
        return Err(NativeReadError);
    }

    for _ in 0..3 {
        let words = usize::try_from(size)
            .ok()
            .and_then(|bytes| bytes.checked_add(3))
            .map(|bytes| bytes / 4)
            .ok_or(NativeReadError)?;
        let mut buffer = vec![0u32; words];
        let result = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr().cast::<c_void>(),
                &mut size,
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if result == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if result != NO_ERROR {
            return Err(NativeReadError);
        }
        let used = usize::try_from(size).map_err(|_| NativeReadError)?;
        if used > buffer.len() * 4 || used < 4 {
            return Err(NativeReadError);
        }
        let count = buffer[0] as usize;
        let mut connections = Vec::new();
        if ipv6 {
            parse_v6_rows(&buffer, used, count, &mut connections)?;
        } else {
            parse_v4_rows(&buffer, used, count, &mut connections)?;
        }
        return Ok(connections);
    }
    fn parse_v4_rows(
        buffer: &[u32],
        used: usize,
        count: usize,
        output: &mut Vec<TcpConnection>,
    ) -> Result<(), NativeReadError> {
        let row_size = mem::size_of::<MIB_TCPROW_OWNER_PID>();
        let required = 4usize
            .checked_add(count.checked_mul(row_size).ok_or(NativeReadError)?)
            .ok_or(NativeReadError)?;
        if required > used {
            return Err(NativeReadError);
        }
        let rows: &[MIB_TCPROW_OWNER_PID] = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(4).cast(), count)
        };
        for row in rows {
            if row.dwState == MIB_TCP_STATE_ESTAB as u32 {
                output.push(TcpConnection {
                    local: (
                        std::net::Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()),
                        port(row.dwLocalPort),
                    )
                        .into(),
                    peer: (
                        std::net::Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()),
                        port(row.dwRemotePort),
                    )
                        .into(),
                    pid: row.dwOwningPid,
                });
            }
        }
        Ok(())
    }

    fn parse_v6_rows(
        buffer: &[u32],
        used: usize,
        count: usize,
        output: &mut Vec<TcpConnection>,
    ) -> Result<(), NativeReadError> {
        let row_size = mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
        let required = 4usize
            .checked_add(count.checked_mul(row_size).ok_or(NativeReadError)?)
            .ok_or(NativeReadError)?;
        if required > used {
            return Err(NativeReadError);
        }
        let rows: &[MIB_TCP6ROW_OWNER_PID] = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(4).cast(), count)
        };
        for row in rows {
            if row.dwState == MIB_TCP_STATE_ESTAB as u32 {
                output.push(TcpConnection {
                    local: std::net::SocketAddrV6::new(
                        std::net::Ipv6Addr::from(row.ucLocalAddr),
                        port(row.dwLocalPort),
                        0,
                        row.dwLocalScopeId,
                    )
                    .into(),
                    peer: std::net::SocketAddrV6::new(
                        std::net::Ipv6Addr::from(row.ucRemoteAddr),
                        port(row.dwRemotePort),
                        0,
                        row.dwRemoteScopeId,
                    )
                    .into(),
                    pid: row.dwOwningPid,
                });
            }
        }
        Ok(())
    }

    fn port(value: u32) -> u16 {
        u16::from_be(value as u16)
    }

    Err(NativeReadError)
}

fn native_process(
    pid: u32,
    query_image: bool,
) -> Result<(u64, Option<PathBuf>), NativeProcessError> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, MAX_PATH};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(NativeProcessError::OpenFailed);
    }
    struct ProcessHandle(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let handle = ProcessHandle(handle);
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(NativeProcessError::ImageQueryFailed);
    }
    let creation_time =
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if creation_time == 0 {
        return Err(NativeProcessError::ImageQueryFailed);
    }
    if !query_image {
        return Ok((creation_time, None));
    }
    let mut buffer = vec![0u16; MAX_PATH as usize];
    loop {
        let mut length =
            u32::try_from(buffer.len()).map_err(|_| NativeProcessError::ImageQueryFailed)?;
        if unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut length) } != 0
        {
            buffer.truncate(length as usize);
            return Ok((
                creation_time,
                Some(std::ffi::OsString::from_wide(&buffer).into()),
            ));
        }
        if buffer.len() >= 32_768 {
            return Err(NativeProcessError::ImageQueryFailed);
        }
        buffer.resize((buffer.len() * 2).min(32_768), 0);
    }
}

fn native_process_image(pid: u32) -> Result<(u64, PathBuf), NativeProcessError> {
    let (creation_time, image) = native_process(pid, true)?;
    image
        .map(|image| (creation_time, image))
        .ok_or(NativeProcessError::ImageQueryFailed)
}
