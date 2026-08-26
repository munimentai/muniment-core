use std::ffi::c_void;
use std::fs;
use std::io::{self, Seek, SeekFrom, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAce, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorControl, InitializeAcl, InitializeSecurityDescriptor,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, LockFileEx,
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK, OPEN_EXISTING, READ_CONTROL,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::windows_sid::{current_process_user_sid, WindowsSid};

struct OwnerSecurity {
    sid: WindowsSid,
    acl: Vec<usize>,
    descriptor: SECURITY_DESCRIPTOR,
}

impl OwnerSecurity {
    fn new() -> io::Result<Self> {
        let sid = current_process_user_sid().map_err(io::Error::other)?;
        let acl_length = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() + sid.as_bytes().len()
            - size_of::<u32>();
        let mut acl = vec![0usize; acl_length.div_ceil(size_of::<usize>())];
        if unsafe { InitializeAcl(acl.as_mut_ptr().cast(), acl_length as u32, ACL_REVISION) } == 0
            || unsafe {
                AddAccessAllowedAce(
                    acl.as_mut_ptr().cast(),
                    ACL_REVISION,
                    FILE_ALL_ACCESS,
                    sid.as_psid(),
                )
            } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut descriptor = unsafe { zeroed::<SECURITY_DESCRIPTOR>() };
        if unsafe {
            InitializeSecurityDescriptor(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SECURITY_DESCRIPTOR_REVISION,
            )
        } == 0
            || unsafe {
                SetSecurityDescriptorOwner(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    sid.as_psid(),
                    0,
                )
            } == 0
            || unsafe {
                SetSecurityDescriptorDacl(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    1,
                    acl.as_ptr().cast(),
                    0,
                )
            } == 0
            || unsafe {
                SetSecurityDescriptorControl(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    SE_DACL_PROTECTED,
                    SE_DACL_PROTECTED,
                )
            } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            sid,
            acl,
            descriptor,
        })
    }

    fn sid(&self) -> PSID {
        self.sid.as_psid()
    }

    fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        let _ = &self.acl;
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&mut self.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            bInheritHandle: 0,
        }
    }
}

pub fn append_owner_only_record(
    root: &Path,
    directory: &Path,
    max_bytes: u64,
    record: &[u8],
) -> io::Result<()> {
    reject_parent_segments(root)?;
    reject_reparse_points(root)?;
    let mut security = OwnerSecurity::new()?;
    let root_handle = open_directory(root)?;
    validate_kind(root, &root_handle, true)?;

    let application_directory = directory.parent().expect("the resolver adds two segments");
    let _application_handle = create_owner_directory(application_directory, &mut security)?;
    let _directory_handle = create_owner_directory(directory, &mut security)?;

    let path = directory.join("runtime.log");
    let mut file = open_owner_file(&path, &mut security)?;
    validate_owner_access(file.as_raw_handle(), security.sid())?;
    let mut overlapped = OVERLAPPED::default();
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if file.metadata()?.len().saturating_add(record.len() as u64) > max_bytes {
        file.set_len(0)?;
    }
    file.seek(SeekFrom::End(0))?;
    file.write_all(record)?;
    file.sync_data()
}

fn reject_parent_segments(path: &Path) -> io::Result<()> {
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local application data path contains a parent segment",
        ));
    }
    Ok(())
}

fn reject_reparse_points(path: &Path) -> io::Result<()> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local application data path contains a reparse point",
            ));
        }
    }
    Ok(())
}

fn create_owner_directory(path: &Path, security: &mut OwnerSecurity) -> io::Result<OwnedHandle> {
    let wide = wide(path);
    let attributes = security.attributes();
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error);
        }
    }
    let handle = open_directory(path)?;
    validate_kind(path, &handle, true)?;
    validate_owner_access(handle.as_raw_handle(), security.sid())?;
    Ok(handle)
}

fn open_directory(path: &Path) -> io::Result<OwnedHandle> {
    open_handle(
        path,
        READ_CONTROL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        null(),
    )
}

fn open_owner_file(path: &Path, security: &mut OwnerSecurity) -> io::Result<fs::File> {
    let attributes = security.attributes();
    let created = open_handle(
        path,
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        &attributes,
    );
    let handle = match created {
        Ok(handle) => handle,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(code)
                    if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32
            ) =>
        {
            open_handle(
                path,
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null(),
            )?
        }
        Err(error) => return Err(error),
    };
    validate_kind(path, &handle, false)?;
    Ok(handle.into())
}

fn open_handle(
    path: &Path,
    access: u32,
    disposition: u32,
    flags: u32,
    attributes: *const SECURITY_ATTRIBUTES,
) -> io::Result<OwnedHandle> {
    let wide = wide(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            attributes,
            disposition,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}

fn validate_kind(path: &Path, handle: &OwnedHandle, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.is_dir() != directory
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "diagnostic path is unsafe",
        ));
    }
    let handle_metadata = fs::File::from(handle.try_clone()?).metadata()?;
    if handle_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || handle_metadata.is_dir() != directory
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "diagnostic path is unsafe",
        ));
    }
    let mut information = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if !directory && information.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "diagnostic path is unsafe",
        ));
    }
    Ok(())
}

fn validate_owner_access(handle: HANDLE, expected_owner: PSID) -> io::Result<()> {
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let validation = validate_acl(descriptor, owner, dacl, expected_owner);
    unsafe { LocalFree(descriptor) };
    validation
}

fn validate_acl(
    descriptor: *mut c_void,
    owner: PSID,
    dacl: *mut ACL,
    expected_owner: PSID,
) -> io::Result<()> {
    let mut control = 0;
    let mut revision = 0;
    if owner.is_null()
        || dacl.is_null()
        || unsafe { EqualSid(owner, expected_owner) } == 0
        || unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return unsafe_access();
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
        || information.AceCount != 1
    {
        return unsafe_access();
    }
    let mut ace: *mut c_void = null_mut();
    if unsafe { GetAce(dacl, 0, &mut ace) } == 0 {
        return unsafe_access();
    }
    let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
    let sid = unsafe { (&mut (*ace).SidStart as *mut u32).cast() };
    if unsafe { (*ace).Header.AceType } as u32 != ACCESS_ALLOWED_ACE_TYPE
        || unsafe { EqualSid(sid, expected_owner) } == 0
    {
        return unsafe_access();
    }
    Ok(())
}

fn unsafe_access() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "diagnostic path owner or access is unsafe",
    ))
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{CreateWellKnownSid, WinWorldSid};

    #[test]
    fn rejects_a_foreign_owner_sid() {
        let mut security = OwnerSecurity::new().unwrap();
        let mut world = vec![0usize; 68usize.div_ceil(size_of::<usize>())];
        let mut world_length = 68;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinWorldSid,
                    null_mut(),
                    world.as_mut_ptr().cast(),
                    &mut world_length,
                )
            },
            0
        );
        let descriptor = security.attributes().lpSecurityDescriptor;
        let expected_owner = security.sid();
        let acl = security.acl.as_mut_ptr().cast();
        assert!(validate_acl(descriptor, world.as_mut_ptr().cast(), acl, expected_owner,).is_err());
    }
}
