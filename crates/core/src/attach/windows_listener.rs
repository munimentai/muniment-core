use std::ffi::{c_void, OsStr};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use std::slice;
use windows_sys::Win32::Foundation::{LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
    IsValidSid, ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};

use super::{
    verify_windows_pipe_security_with_reader, WindowsPipeAccessControlEntry,
    WindowsPipeSecurityReadError, WindowsPipeSecurityReader,
};
use crate::attach::windows_attach_pipe_path;
use crate::windows_security::OwnerSecurity;
use crate::windows_sid::current_process_user_sid;

const PIPE_ACCESS_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

/// A bound Windows attach pipe that has not accepted a connection.
pub struct WindowsAttachListener {
    path: String,
    handle: OwnedHandle,
}

impl WindowsAttachListener {
    /// Creates and verifies the current user's Windows attach pipe.
    pub fn bind() -> io::Result<Self> {
        let sid = current_process_user_sid().map_err(io::Error::other)?;
        let path = windows_attach_pipe_path(sid.as_str())
            .map_err(|_| io::Error::other("could not derive the Windows attach pipe path"))?;
        let wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();
        let mut security = OwnerSecurity::new(PIPE_ACCESS_MASK)?;
        let attributes = security.attributes();
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                0,
                0,
                0,
                &attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let reader = NativeWindowsPipeSecurityReader::read(handle.as_raw_handle())
            .map_err(|_| io::Error::other("could not read the Windows attach pipe security"))?;
        verify_windows_pipe_security_with_reader(&reader).map_err(io::Error::other)?;

        Ok(Self { path, handle })
    }

    /// Returns the bound pipe path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the bound server pipe handle.
    pub fn handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }
}

/// A native snapshot of a Windows pipe owner and DACL.
pub struct NativeWindowsPipeSecurityReader {
    owner_sid: Vec<u8>,
    protected: bool,
    entries: Vec<WindowsPipeAccessControlEntry>,
    local_sid: Vec<u8>,
}

impl NativeWindowsPipeSecurityReader {
    fn read(handle: HANDLE) -> Result<Self, WindowsPipeSecurityReadError> {
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let result = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 || descriptor.is_null() {
            return Err(WindowsPipeSecurityReadError);
        }

        let snapshot = read_security_snapshot(owner, dacl, descriptor);
        unsafe { LocalFree(descriptor) };
        let (owner_sid, protected, entries) = snapshot?;
        let local_sid = current_process_user_sid()
            .map_err(|_| WindowsPipeSecurityReadError)?
            .as_bytes()
            .to_vec();
        Ok(Self {
            owner_sid,
            protected,
            entries,
            local_sid,
        })
    }
}

impl WindowsPipeSecurityReader for NativeWindowsPipeSecurityReader {
    fn endpoint_owner_sid(&self) -> Result<Vec<u8>, WindowsPipeSecurityReadError> {
        Ok(self.owner_sid.clone())
    }

    fn dacl_is_protected(&self) -> Result<bool, WindowsPipeSecurityReadError> {
        Ok(self.protected)
    }

    fn access_control_entries(
        &self,
    ) -> Result<Vec<WindowsPipeAccessControlEntry>, WindowsPipeSecurityReadError> {
        Ok(self.entries.clone())
    }

    fn local_process_user_sid(&self) -> Result<Vec<u8>, WindowsPipeSecurityReadError> {
        Ok(self.local_sid.clone())
    }
}

fn read_security_snapshot(
    owner: PSID,
    dacl: *mut ACL,
    descriptor: *mut c_void,
) -> Result<(Vec<u8>, bool, Vec<WindowsPipeAccessControlEntry>), WindowsPipeSecurityReadError> {
    let owner_sid = copy_sid(owner)?;
    if dacl.is_null() {
        return Err(WindowsPipeSecurityReadError);
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(WindowsPipeSecurityReadError);
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(WindowsPipeSecurityReadError);
    }

    let mut entries = Vec::with_capacity(information.AceCount as usize);
    for index in 0..information.AceCount {
        let mut ace: *mut c_void = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(WindowsPipeSecurityReadError);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let (access_mask, sid, allows) = match header.AceType as u32 {
            ACCESS_ALLOWED_ACE_TYPE => {
                let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                (
                    ace.Mask,
                    (&ace.SidStart as *const u32).cast_mut().cast(),
                    true,
                )
            }
            ACCESS_DENIED_ACE_TYPE => {
                let ace = unsafe { &*ace.cast::<ACCESS_DENIED_ACE>() };
                (
                    ace.Mask,
                    (&ace.SidStart as *const u32).cast_mut().cast(),
                    false,
                )
            }
            _ => return Err(WindowsPipeSecurityReadError),
        };
        entries.push(WindowsPipeAccessControlEntry {
            sid: copy_sid(sid)?,
            access_mask,
            allows,
            inherited: u32::from(header.AceFlags) & INHERITED_ACE != 0,
        });
    }

    Ok((owner_sid, control & SE_DACL_PROTECTED != 0, entries))
}

fn copy_sid(sid: PSID) -> Result<Vec<u8>, WindowsPipeSecurityReadError> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(WindowsPipeSecurityReadError);
    }
    let length = unsafe { GetLengthSid(sid) } as usize;
    if length == 0 {
        return Err(WindowsPipeSecurityReadError);
    }
    Ok(unsafe { slice::from_raw_parts(sid.cast(), length) }.to_vec())
}
