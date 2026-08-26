#![cfg(target_os = "windows")]

use muniment_core::attach::{windows_attach_pipe_path, WindowsAttachListener};
use muniment_core::windows_sid::current_process_user_sid;

#[test]
fn binds_the_current_user_pipe_and_rejects_a_second_listener() {
    let listener = WindowsAttachListener::bind().unwrap();
    let expected_path =
        windows_attach_pipe_path(current_process_user_sid().unwrap().as_str()).unwrap();

    assert_eq!(listener.path(), expected_path);
    assert!(WindowsAttachListener::bind().is_err());
}
