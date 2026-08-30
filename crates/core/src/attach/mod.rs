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
mod credential_store;
mod cursor;
mod deadline_io;
mod desktop_admission;
#[cfg(target_os = "linux")]
mod desktop_client_admission;
#[cfg(target_os = "linux")]
mod desktop_service;
pub mod desktop_service_message;
mod handoff;
mod handoff_probe;
mod idempotency;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
mod listener_lifecycle;
pub mod live_connections;
#[cfg(target_os = "macos")]
mod macos_listener;
#[cfg(target_os = "macos")]
mod macos_peer;
#[cfg(target_os = "linux")]
mod peer_authority;
#[cfg(unix)]
mod presented_approval;
#[cfg(target_os = "linux")]
mod presenter_admission;
#[cfg(unix)]
mod presenter_session;
mod quiesce;
mod runtime_activity;
pub mod thread_service;
#[cfg(target_os = "windows")]
mod windows_connect;
#[cfg(target_os = "windows")]
mod windows_credential;
mod windows_desktop_client;
mod windows_instance_lock;
#[cfg(target_os = "windows")]
mod windows_listener;
mod windows_peer;
#[cfg(target_os = "windows")]
mod windows_peer_native;
mod windows_pipe;
mod windows_pipe_security;
mod windows_route;
#[cfg(target_os = "windows")]
mod windows_route_native;
mod windows_session;
#[cfg(target_os = "windows")]
mod windows_stream;
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
pub use credential_store::*;
pub use cursor::{
    RunEventAdmission, RunStreamCursor, RunStreamError, RunStreamWindow, StreamClose,
    StreamCloseCode, MAX_RUN_STREAM_WINDOW_BYTES, MAX_RUN_STREAM_WINDOW_EVENTS,
    MAX_RUN_STREAM_WINDOW_TEXT_BYTES,
};
#[doc(hidden)]
pub use deadline_io::{read_exact_before, write_all_before, DeadlineStream, ReadableWait};
pub use desktop_admission::*;
#[cfg(target_os = "linux")]
pub use desktop_client_admission::*;
#[cfg(target_os = "linux")]
pub use desktop_service::*;
pub use handoff::*;
pub use handoff_probe::*;
pub use idempotency::*;
#[cfg(target_os = "linux")]
pub use listener_lifecycle::*;
#[cfg(target_os = "macos")]
pub use macos_listener::*;
#[cfg(target_os = "macos")]
pub use macos_peer::*;
pub use muniment_attach::*;
#[cfg(target_os = "linux")]
pub use peer_authority::*;
#[cfg(unix)]
pub use presented_approval::*;
#[cfg(target_os = "linux")]
pub use presenter_admission::*;
#[cfg(unix)]
pub use presenter_session::*;
pub use quiesce::*;
pub use runtime_activity::*;
pub use thread_service::CompanionRecord;
#[cfg(target_os = "windows")]
pub use windows_connect::*;
#[cfg(target_os = "windows")]
pub use windows_credential::*;
pub use windows_desktop_client::*;
pub use windows_instance_lock::*;
#[cfg(target_os = "windows")]
pub use windows_listener::*;
pub use windows_peer::*;
#[cfg(target_os = "windows")]
pub use windows_peer_native::*;
pub use windows_pipe::*;
pub use windows_pipe_security::*;
pub use windows_route::*;
#[cfg(target_os = "windows")]
pub use windows_route_native::*;
pub use windows_session::*;
#[cfg(target_os = "windows")]
pub use windows_stream::*;
pub use workspace_context::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementSnapshotResult {
    pub snapshot: crate::auth::EntitlementSnapshotView,
    pub changed_snapshot_version: Option<u64>,
}
