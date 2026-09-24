#![cfg(target_os = "windows")]

use muniment_core::attach::{new_windows_attach_pipe_suffix, windows_attach_pipe_path};
use muniment_core::windows_sid::current_process_user_sid;
use muniment_core::windows_task::{is_canonical_sid, task_uri};

#[test]
fn current_process_sid_is_canonical_and_accepted_by_windows_consumers() {
    let sid = current_process_user_sid().unwrap();

    assert!(!sid.as_bytes().is_empty());
    assert!(is_canonical_sid(sid.as_str()));
    assert!(
        windows_attach_pipe_path(sid.as_str(), &new_windows_attach_pipe_suffix().unwrap()).is_ok()
    );
    assert!(task_uri(sid.as_str()).is_ok());
}
