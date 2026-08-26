//! Windows attach pipe security verification.

use std::fmt;

/// Opaque failure from the injected Windows pipe security boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsPipeSecurityReadError;

/// An access-control entry read from a Windows attach pipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPipeAccessControlEntry {
    pub sid: Vec<u8>,
    pub access_mask: u32,
    pub allows: bool,
    pub inherited: bool,
}

/// Injected boundary around Windows pipe security and process-token reads.
pub trait WindowsPipeSecurityReader {
    fn endpoint_owner_sid(&self) -> Result<Vec<u8>, WindowsPipeSecurityReadError>;
    fn dacl_is_protected(&self) -> Result<bool, WindowsPipeSecurityReadError>;
    fn access_control_entries(
        &self,
    ) -> Result<Vec<WindowsPipeAccessControlEntry>, WindowsPipeSecurityReadError>;
    fn local_process_user_sid(&self) -> Result<Vec<u8>, WindowsPipeSecurityReadError>;
}

/// A failure returned before the Windows attach endpoint is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPipeSecurityError {
    IdentityUnavailable,
    ForeignOwner,
    UnprotectedDacl,
    UnexpectedEntrySet,
}

impl fmt::Display for WindowsPipeSecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentityUnavailable => "attach pipe security identity is unavailable",
            Self::ForeignOwner => "attach pipe has a foreign owner",
            Self::UnprotectedDacl => "attach pipe DACL is not protected",
            Self::UnexpectedEntrySet => "attach pipe has an unexpected access-control entry set",
        })
    }
}

impl std::error::Error for WindowsPipeSecurityError {}

/// Verifies a Windows attach pipe through an injected security boundary.
pub fn verify_windows_pipe_security_with_reader(
    reader: &impl WindowsPipeSecurityReader,
) -> Result<(), WindowsPipeSecurityError> {
    let owner_sid = reader
        .endpoint_owner_sid()
        .map_err(|_| WindowsPipeSecurityError::IdentityUnavailable)?;
    let local_sid = reader
        .local_process_user_sid()
        .map_err(|_| WindowsPipeSecurityError::IdentityUnavailable)?;

    if owner_sid != local_sid {
        return Err(WindowsPipeSecurityError::ForeignOwner);
    }

    let protected = reader
        .dacl_is_protected()
        .map_err(|_| WindowsPipeSecurityError::IdentityUnavailable)?;
    if !protected {
        return Err(WindowsPipeSecurityError::UnprotectedDacl);
    }

    let entries = reader
        .access_control_entries()
        .map_err(|_| WindowsPipeSecurityError::IdentityUnavailable)?;
    if entries.len() != 1
        || entries[0].sid != local_sid
        || !entries[0].allows
        || entries[0].inherited
    {
        return Err(WindowsPipeSecurityError::UnexpectedEntrySet);
    }

    Ok(())
}
