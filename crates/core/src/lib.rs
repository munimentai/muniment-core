//! Pure backend logic for the Muniment desktop app.
//!
//! Nothing in this crate may depend on Tauri or any GUI toolkit: unit tests
//! here run on the shared CI runner, which has no display stack. The Pi
//! sidecar process manager and its RPC transport build on these pieces.

pub mod auth;
pub mod cas;
pub mod journal;
pub mod sidecar;
