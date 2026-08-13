//! Companion attach server support.

mod approval;
mod artifact;
mod authorization;
#[cfg(target_os = "linux")]
mod companion_registry;
#[cfg(target_os = "linux")]
mod credential;
mod cursor;
#[cfg(target_os = "linux")]
mod desktop_service;
mod handoff;
mod handoff_probe;
mod idempotency;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
mod listener_lifecycle;
#[cfg(target_os = "linux")]
mod peer_authority;
mod quiesce;
mod runtime_activity;
mod workspace_context;

pub use approval::*;
pub use artifact::*;
pub use authorization::*;
#[cfg(target_os = "linux")]
pub use companion_registry::*;
#[cfg(target_os = "linux")]
pub use credential::*;
pub use cursor::{
    RunEventAdmission, RunStreamCursor, RunStreamError, RunStreamWindow, StreamClose,
    StreamCloseCode, MAX_RUN_STREAM_WINDOW_BYTES, MAX_RUN_STREAM_WINDOW_EVENTS,
    MAX_RUN_STREAM_WINDOW_TEXT_BYTES,
};
#[cfg(target_os = "linux")]
pub use desktop_service::*;
pub use handoff::*;
pub use handoff_probe::*;
pub use idempotency::*;
#[cfg(target_os = "linux")]
pub use listener_lifecycle::*;
pub use muniment_attach::*;
#[cfg(target_os = "linux")]
pub use peer_authority::*;
pub use quiesce::*;
pub use runtime_activity::*;
pub use workspace_context::*;
