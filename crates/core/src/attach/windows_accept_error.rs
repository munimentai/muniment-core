use std::fmt;

/// A failure while accepting a Windows attach connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachAcceptError {
    DeadlineExpired,
    CreateEvent(u32),
    CreateInstance(u32),
    VerifyInstanceSecurity(Option<u32>),
    Connect(u32),
    Disconnect(u32),
    Wait(u32),
    Cancel(u32),
}

impl fmt::Display for WindowsAttachAcceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (variant, code) = match *self {
            Self::DeadlineExpired => ("DeadlineExpired", None),
            Self::CreateEvent(code) => ("CreateEvent", Some(code)),
            Self::CreateInstance(code) => ("CreateInstance", Some(code)),
            Self::VerifyInstanceSecurity(code) => ("VerifyInstanceSecurity", code),
            Self::Connect(code) => ("Connect", Some(code)),
            Self::Disconnect(code) => ("Disconnect", Some(code)),
            Self::Wait(code) => ("Wait", Some(code)),
            Self::Cancel(code) => ("Cancel", Some(code)),
        };
        match code {
            Some(code) => write!(formatter, "{variant} win32={code} (0x{code:08X})"),
            None => write!(formatter, "{variant} win32=none"),
        }
    }
}

impl std::error::Error for WindowsAttachAcceptError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_error_names_its_variant_and_code() {
        for (error, variant) in [
            (WindowsAttachAcceptError::CreateEvent(5), "CreateEvent"),
            (
                WindowsAttachAcceptError::CreateInstance(5),
                "CreateInstance",
            ),
            (
                WindowsAttachAcceptError::VerifyInstanceSecurity(Some(5)),
                "VerifyInstanceSecurity",
            ),
            (WindowsAttachAcceptError::Connect(5), "Connect"),
            (WindowsAttachAcceptError::Disconnect(5), "Disconnect"),
            (WindowsAttachAcceptError::Wait(5), "Wait"),
            (WindowsAttachAcceptError::Cancel(5), "Cancel"),
        ] {
            assert_eq!(error.to_string(), format!("{variant} win32=5 (0x00000005)"));
        }
        assert_eq!(
            WindowsAttachAcceptError::DeadlineExpired.to_string(),
            "DeadlineExpired win32=none"
        );
        assert_eq!(
            WindowsAttachAcceptError::VerifyInstanceSecurity(None).to_string(),
            "VerifyInstanceSecurity win32=none"
        );
    }
}
