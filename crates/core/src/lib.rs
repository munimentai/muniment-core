//! Pure backend logic for the Muniment desktop app.
//!
//! Nothing in this crate may depend on Tauri or any GUI toolkit: unit tests
//! here run on the shared CI runner, which has no display stack. The Pi
//! sidecar process manager and its RPC transport build on these pieces.

pub mod asr;
pub mod attach;
pub mod attachment;
pub mod auth;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod browser_control;
pub mod cas;
pub mod home;
pub mod import_preview;
pub mod journal;
pub mod llama;
pub mod model_acquisition_transport;
pub mod model_install;
pub mod model_install_native;
pub mod sidecar;

pub use muniment_attach::{
    ensure_cross_project_home, ensure_scaffold_directory, onboard_companion_workspace,
    write_scaffold_file_if_missing,
};
