//! Pure backend logic for the Muniment desktop app.
//!
//! Nothing in this crate may depend on Tauri or any GUI toolkit: unit tests
//! here run on the shared CI runner, which has no display stack. The Pi
//! sidecar process manager and its RPC transport build on these pieces.

pub mod asr;
pub mod assistant_text;
pub mod attach;
pub mod attachment;
pub mod auth;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod browser_control;
pub mod cas;
pub mod chat_grant;
pub mod chat_profile;
#[cfg(feature = "keyring")]
pub mod chat_prompt;
pub mod chat_resume;
pub mod chat_view;
pub mod home;
pub mod import_preview;
pub mod journal;
pub mod kokoro;
pub mod memory_index;
pub mod memory_runtime;
pub mod memory_scan;
pub mod memory_secret;
pub mod model_acquisition_transport;
pub mod model_install;
pub mod model_install_native;
pub mod owned_threads;
pub mod permission_gate;
pub mod run_start;
pub mod session_thread;
pub mod sidecar;
pub mod thread_ownership;

pub use muniment_attach::{
    ensure_cross_project_home, ensure_scaffold_directory, onboard_companion_workspace,
    write_scaffold_file_if_missing,
};
