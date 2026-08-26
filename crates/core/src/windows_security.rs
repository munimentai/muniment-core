use std::io;
use std::mem::{size_of, zeroed};
use windows_sys::Win32::Security::{
    AddAccessAllowedAce, InitializeAcl, InitializeSecurityDescriptor, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION,
    PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

use crate::windows_sid::{current_process_user_sid, WindowsSid};

/// An owner-only protected security descriptor and its backing storage.
pub(crate) struct OwnerSecurity {
    sid: WindowsSid,
    acl: Vec<usize>,
    descriptor: SECURITY_DESCRIPTOR,
}

impl OwnerSecurity {
    pub(crate) fn new(access_mask: u32) -> io::Result<Self> {
        let sid = current_process_user_sid().map_err(io::Error::other)?;
        let acl_length = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() + sid.as_bytes().len()
            - size_of::<u32>();
        let mut acl = vec![0usize; acl_length.div_ceil(size_of::<usize>())];
        if unsafe { InitializeAcl(acl.as_mut_ptr().cast(), acl_length as u32, ACL_REVISION) } == 0
            || unsafe {
                AddAccessAllowedAce(
                    acl.as_mut_ptr().cast(),
                    ACL_REVISION,
                    access_mask,
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

    pub(crate) fn sid(&self) -> PSID {
        self.sid.as_psid()
    }

    pub(crate) fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        let _ = &self.acl;
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&mut self.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            bInheritHandle: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn acl_mut_ptr(&mut self) -> *mut ACL {
        self.acl.as_mut_ptr().cast()
    }
}
