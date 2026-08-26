use muniment_core::attach::{
    verify_windows_pipe_security_with_reader, WindowsPipeAccessControlEntry,
    WindowsPipeSecurityError, WindowsPipeSecurityReadError, WindowsPipeSecurityReader,
};

struct FakeSecurityReader {
    owner_sid: Result<Vec<u8>, WindowsPipeSecurityReadError>,
    protected: Result<bool, WindowsPipeSecurityReadError>,
    entries: Result<Vec<WindowsPipeAccessControlEntry>, WindowsPipeSecurityReadError>,
    local_sid: Result<Vec<u8>, WindowsPipeSecurityReadError>,
}

impl WindowsPipeSecurityReader for FakeSecurityReader {
    fn endpoint_owner_sid(&self) -> Result<Vec<u8>, WindowsPipeSecurityReadError> {
        self.owner_sid.clone()
    }

    fn dacl_is_protected(&self) -> Result<bool, WindowsPipeSecurityReadError> {
        self.protected
    }

    fn access_control_entries(
        &self,
    ) -> Result<Vec<WindowsPipeAccessControlEntry>, WindowsPipeSecurityReadError> {
        self.entries.clone()
    }

    fn local_process_user_sid(&self) -> Result<Vec<u8>, WindowsPipeSecurityReadError> {
        self.local_sid.clone()
    }
}

fn entry(sid: &[u8], allows: bool, inherited: bool) -> WindowsPipeAccessControlEntry {
    WindowsPipeAccessControlEntry {
        sid: sid.to_vec(),
        access_mask: 0x0012_019f,
        allows,
        inherited,
    }
}

fn reader(entries: Vec<WindowsPipeAccessControlEntry>) -> FakeSecurityReader {
    FakeSecurityReader {
        owner_sid: Ok(vec![1, 2, 3, 4]),
        protected: Ok(true),
        entries: Ok(entries),
        local_sid: Ok(vec![1, 2, 3, 4]),
    }
}

#[test]
fn accepts_the_owner_protected_dacl_and_single_allow_entry() {
    let reader = reader(vec![entry(&[1, 2, 3, 4], true, false)]);

    assert_eq!(verify_windows_pipe_security_with_reader(&reader), Ok(()));
}

#[test]
fn rejects_a_foreign_owner() {
    let mut reader = reader(vec![entry(&[1, 2, 3, 4], true, false)]);
    reader.owner_sid = Ok(vec![4, 3, 2, 1]);

    assert_eq!(
        verify_windows_pipe_security_with_reader(&reader),
        Err(WindowsPipeSecurityError::ForeignOwner)
    );
}

#[test]
fn rejects_an_inherited_entry() {
    let reader = reader(vec![entry(&[1, 2, 3, 4], true, true)]);

    assert_eq!(
        verify_windows_pipe_security_with_reader(&reader),
        Err(WindowsPipeSecurityError::UnexpectedEntrySet)
    );
}

#[test]
fn rejects_a_second_allow_entry() {
    let reader = reader(vec![
        entry(&[1, 2, 3, 4], true, false),
        entry(&[1, 2, 3, 4], true, false),
    ]);

    assert_eq!(
        verify_windows_pipe_security_with_reader(&reader),
        Err(WindowsPipeSecurityError::UnexpectedEntrySet)
    );
}

#[test]
fn rejects_a_deny_entry() {
    let reader = reader(vec![entry(&[1, 2, 3, 4], false, false)]);

    assert_eq!(
        verify_windows_pipe_security_with_reader(&reader),
        Err(WindowsPipeSecurityError::UnexpectedEntrySet)
    );
}

#[test]
fn rejects_an_unprotected_dacl() {
    let mut reader = reader(vec![entry(&[1, 2, 3, 4], true, false)]);
    reader.protected = Ok(false);

    assert_eq!(
        verify_windows_pipe_security_with_reader(&reader),
        Err(WindowsPipeSecurityError::UnprotectedDacl)
    );
}

#[test]
fn maps_a_failed_read_to_unavailable_identity() {
    let mut reader = reader(vec![entry(&[1, 2, 3, 4], true, false)]);
    reader.entries = Err(WindowsPipeSecurityReadError);

    assert_eq!(
        verify_windows_pipe_security_with_reader(&reader),
        Err(WindowsPipeSecurityError::IdentityUnavailable)
    );
}
