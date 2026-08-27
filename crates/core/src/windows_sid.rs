use std::fmt;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null_mut, NonNull};
use std::slice;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, TokenUser, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The current process token user SID in its two reusable forms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsSid {
    storage: Vec<usize>,
    byte_len: usize,
    canonical: String,
}

impl WindowsSid {
    /// Returns the owned SID bytes.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.storage.as_ptr().cast(), self.byte_len) }
    }

    /// Returns the canonical SID string.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    pub(crate) fn as_psid(&self) -> PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

/// A failure while reading the current process token user SID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsSidError {
    OpenProcessToken,
    QueryTokenUserSize,
    QueryTokenUser,
    InvalidSid,
    ConvertSidToString,
    InvalidSidString,
}

impl fmt::Display for WindowsSidError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::OpenProcessToken => "could not open the current process token",
            Self::QueryTokenUserSize => "could not get the process token user size",
            Self::QueryTokenUser => "could not read the process token user",
            Self::InvalidSid => "the process token user SID is invalid",
            Self::ConvertSidToString => "could not convert the process token user SID",
            Self::InvalidSidString => "the process token user SID string is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WindowsSidError {}

pub(crate) fn sid_byte_len(sid: PSID) -> Option<usize> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return None;
    }
    let length = unsafe { GetLengthSid(sid) } as usize;
    (length != 0).then_some(length)
}

pub(crate) fn copy_sid_bytes(sid: PSID) -> Option<Vec<u8>> {
    let length = sid_byte_len(sid)?;
    Some(unsafe { slice::from_raw_parts(sid.cast(), length) }.to_vec())
}

/// Reads the current process token user SID as owned bytes and a canonical string.
pub fn current_process_user_sid() -> Result<WindowsSid, WindowsSidError> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(WindowsSidError::OpenProcessToken);
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut length = 0;
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut length) };
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || length == 0 {
        return Err(WindowsSidError::QueryTokenUserSize);
    }

    let mut token_user = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            token_user.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(WindowsSidError::QueryTokenUser);
    }

    let sid = unsafe { (*(token_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let sid_length = sid_byte_len(sid).ok_or(WindowsSidError::InvalidSid)?;
    let mut storage = vec![0usize; sid_length.div_ceil(size_of::<usize>())];
    unsafe {
        std::ptr::copy_nonoverlapping(sid.cast::<u8>(), storage.as_mut_ptr().cast(), sid_length)
    };
    let canonical = sid_string(sid)?;

    Ok(WindowsSid {
        storage,
        byte_len: sid_length,
        canonical,
    })
}

fn sid_string(sid: PSID) -> Result<String, WindowsSidError> {
    let mut wide = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err(WindowsSidError::ConvertSidToString);
    }
    let wide = LocalWide(NonNull::new(wide).ok_or(WindowsSidError::ConvertSidToString)?);
    let length = unsafe { wide_length(wide.0.as_ptr()) };
    String::from_utf16(unsafe { slice::from_raw_parts(wide.0.as_ptr(), length) })
        .map_err(|_| WindowsSidError::InvalidSidString)
}

unsafe fn wide_length(wide: *const u16) -> usize {
    let mut length = 0;
    while unsafe { *wide.add(length) } != 0 {
        length += 1;
    }
    length
}

struct LocalWide(NonNull<u16>);

impl Drop for LocalWide {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0.as_ptr().cast()) };
    }
}
