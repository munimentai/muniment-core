use super::{decode_client_credentials, ClientCredential, ClientCredentialStore, ProtocolError};
use crate::windows_security::OwnerSecurity;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use uuid::Uuid;
use windows_sys::Win32::Foundation::{
    LocalFree, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, MoveFileExW, CREATE_NEW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING, READ_CONTROL,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

pub fn load_client_credentials(
    path: &Path,
) -> Result<HashMap<String, ClientCredential>, ProtocolError> {
    let file = match open_file(
        path,
        GENERIC_READ | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        null(),
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(_) => return Err(ProtocolError::persistence_failed()),
    };
    let security =
        OwnerSecurity::new(FILE_ALL_ACCESS).map_err(|_| ProtocolError::persistence_failed())?;
    validate_owner_access(file.as_raw_handle(), security.sid())
        .map_err(|_| ProtocolError::persistence_failed())?;
    let value = serde_json::from_reader(file).map_err(|_| ProtocolError::persistence_failed())?;
    decode_client_credentials(value)
}

pub fn save_client_credentials(
    path: &Path,
    credentials: &HashMap<String, ClientCredential>,
) -> Result<(), ProtocolError> {
    let parent = path
        .parent()
        .ok_or_else(ProtocolError::persistence_failed)?;
    std::fs::create_dir_all(parent).map_err(|_| ProtocolError::persistence_failed())?;
    let temporary = parent.join(format!(".attach-client-credentials-{}.tmp", Uuid::now_v7()));
    let result = (|| {
        let mut security =
            OwnerSecurity::new(FILE_ALL_ACCESS).map_err(|_| ProtocolError::persistence_failed())?;
        let attributes = security.attributes();
        let file = open_file(
            &temporary,
            GENERIC_READ | GENERIC_WRITE,
            0,
            CREATE_NEW,
            &attributes,
        )
        .map_err(|_| ProtocolError::persistence_failed())?;
        serde_json::to_writer(&file, &ClientCredentialStore::new(credentials.clone()))
            .map_err(|_| ProtocolError::persistence_failed())?;
        file.sync_all()
            .map_err(|_| ProtocolError::persistence_failed())?;
        drop(file);
        replace_file(&temporary, path).map_err(|_| ProtocolError::persistence_failed())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Reads the current user's attach pipe path from its owner-only file.
///
/// A missing file reads as `NotFound`, which means no runtime has bound the pipe.
pub fn load_windows_attach_pipe_path(sid: &str) -> io::Result<String> {
    let local_app_data = crate::windows_known_folders::windows_local_app_data()
        .map_err(|_| io::Error::other("the local application data folder is unavailable"))?;
    read_pipe_name_file(&super::windows_attach_pipe_name_file(&local_app_data), sid)
}

/// Reads the current user's attach pipe path, or generates and stores a new one.
/// Only the runtime listener calls this.
pub fn load_or_create_windows_attach_pipe_path(sid: &str) -> io::Result<String> {
    let local_app_data = crate::windows_known_folders::windows_local_app_data()
        .map_err(|_| io::Error::other("the local application data folder is unavailable"))?;
    let path = super::windows_attach_pipe_name_file(&local_app_data);
    match read_pipe_name_file(&path, sid) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        result => return result,
    }
    let suffix = super::new_windows_attach_pipe_suffix()
        .map_err(|_| io::Error::other("could not generate the attach pipe suffix"))?;
    let pipe_path = super::windows_attach_pipe_path(sid, &suffix)
        .map_err(|_| io::Error::other("could not derive the attach pipe path"))?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("the attach pipe name file has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".attach-pipe-name-{}.tmp", Uuid::now_v7()));
    let result = (|| {
        let mut security = OwnerSecurity::new(FILE_ALL_ACCESS)?;
        let attributes = security.attributes();
        let file = open_file(
            &temporary,
            GENERIC_READ | GENERIC_WRITE,
            0,
            CREATE_NEW,
            &attributes,
        )?;
        std::io::Write::write_all(&mut &file, pipe_path.as_bytes())?;
        file.sync_all()?;
        drop(file);
        // No replace flag, so a name another runtime stored first wins.
        move_file_once(&temporary, &path)
    })();
    let _ = std::fs::remove_file(&temporary);
    match result {
        Ok(()) => Ok(pipe_path),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            read_pipe_name_file(&path, sid)
        }
        Err(error) => Err(error),
    }
}

fn read_pipe_name_file(path: &Path, sid: &str) -> io::Result<String> {
    let file = open_file(
        path,
        GENERIC_READ | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        null(),
    )?;
    let security = OwnerSecurity::new(FILE_ALL_ACCESS)?;
    validate_owner_access(file.as_raw_handle(), security.sid())?;
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut std::io::Read::take(&file, 256), &mut contents)?;
    super::validate_windows_attach_pipe_path(sid, contents.trim()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the attach pipe name file is invalid",
        )
    })
}

fn move_file_once(source: &Path, destination: &Path) -> io::Result<()> {
    let source = wide(source);
    let destination = wide(destination);
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn open_file(
    path: &Path,
    access: u32,
    share_mode: u32,
    disposition: u32,
    attributes: *const SECURITY_ATTRIBUTES,
) -> io::Result<std::fs::File> {
    let path = wide(path);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share_mode,
            attributes,
            disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { std::fs::File::from_raw_handle(handle) })
    }
}

fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source = wide(source);
    let destination = wide(destination);
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn validate_owner_access(handle: *mut c_void, expected_owner: PSID) -> io::Result<()> {
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
        "credential store owner or access is unsafe",
    ))
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
