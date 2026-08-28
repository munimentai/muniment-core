#![cfg(target_os = "windows")]

use muniment_core::windows_known_folders::windows_payload_roots;
use muniment_core::windows_payload::{
    resolve_live_windows_payload_scopes, resolve_windows_payload_scopes, WindowsNativePayloadProbe,
};

#[test]
fn resolves_payload_roots_from_shell_known_folders() {
    let roots = windows_payload_roots().expect("Shell known folders should resolve");

    assert!(roots.program_files.is_absolute());
    assert!(roots.local_app_data.is_absolute());
    assert_ne!(roots.program_files, roots.local_app_data);
}

#[test]
fn resolves_live_payload_scopes_from_shell_known_folders() {
    let roots = windows_payload_roots().expect("Shell known folders should resolve");
    let expected = resolve_windows_payload_scopes(
        roots.program_files,
        roots.local_app_data,
        &WindowsNativePayloadProbe,
    )
    .expect("Shell known folders should be valid payload roots");

    assert_eq!(resolve_live_windows_payload_scopes(), Ok(expected));
}
