//! Companion attach server support.

mod approval;
#[cfg(unix)]
mod approval_present;
mod artifact;
mod authorization;
#[cfg(target_os = "linux")]
mod companion_registry;
#[cfg(target_os = "linux")]
mod connection_route;
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
#[cfg(target_os = "linux")]
mod presenter_admission;
#[cfg(unix)]
mod presenter_session;
mod quiesce;
mod runtime_activity;
mod workspace_context;

pub use approval::*;
#[cfg(unix)]
pub use approval_present::*;
pub use artifact::*;
pub use authorization::*;
#[cfg(target_os = "linux")]
pub use companion_registry::*;
#[cfg(target_os = "linux")]
pub use connection_route::*;
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
#[cfg(target_os = "linux")]
pub use presenter_admission::*;
#[cfg(unix)]
pub use presenter_session::*;
pub use quiesce::*;
pub use runtime_activity::*;
pub use workspace_context::*;
