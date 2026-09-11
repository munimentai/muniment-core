//! Protocol-only support for attaching companion clients to Muniment.

/// Returns whether a dotted numeric runtime version meets the minimum version.
pub fn runtime_version_meets_minimum(version: &str, minimum: &str) -> bool {
    fn segments(version: &str) -> Option<Vec<u64>> {
        if version.is_empty() {
            return None;
        }
        version
            .split('.')
            .map(|segment| {
                if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()) {
                    None
                } else {
                    segment.parse().ok()
                }
            })
            .collect()
    }

    let (Some(version), Some(minimum)) = (segments(version), segments(minimum)) else {
        return false;
    };
    let segment_count = version.len().max(minimum.len());
    (0..segment_count)
        .map(|index| version.get(index).copied().unwrap_or(0))
        .cmp((0..segment_count).map(|index| minimum.get(index).copied().unwrap_or(0)))
        .is_ge()
}

#[cfg(feature = "client")]
mod chat_event_supervisor;
#[cfg(feature = "client")]
mod client;
#[cfg(all(feature = "client", target_os = "linux"))]
mod linux_connect_diagnostic;
#[cfg(all(feature = "client", target_os = "linux"))]
pub use linux_connect_diagnostic::LinuxConnectDiagnostic;
#[cfg(feature = "client")]
mod client_stream;
#[cfg(feature = "client")]
mod desktop_client;
#[cfg(feature = "client")]
mod desktop_client_holder;
#[cfg(feature = "client")]
mod desktop_client_stop;
#[cfg(feature = "client")]
mod desktop_supervisor;
mod envelope;
pub mod fixtures;
mod framing;
mod negotiation;
#[cfg(feature = "client")]
mod presenter_client;
#[cfg(feature = "client")]
mod protocol_helpers;
mod workspace;

#[cfg(feature = "client")]
pub use chat_event_supervisor::{serve_chat_events_with, ChatEventSupervisorStop};
#[cfg(feature = "client")]
pub use client::*;
#[cfg(feature = "client")]
pub use client_stream::ClientStream;
#[cfg(feature = "client")]
pub use desktop_client::{handshake_desktop_client, DesktopClient};
#[cfg(feature = "client")]
pub use desktop_client_holder::DesktopClientHolder;
#[cfg(feature = "client")]
pub use desktop_client_stop::DesktopClientStopHandle;
#[cfg(feature = "client")]
pub use desktop_supervisor::{serve_desktop_client_with, DesktopClientSupervisorStop};
pub use envelope::*;
pub use framing::*;
pub use negotiation::*;
#[cfg(feature = "client")]
pub use presenter_client::{
    handshake_approval_presenter, serve_approval_presenter_with, ApprovalPresenterClient,
    ApprovalPresenterStopHandle, ApprovalPresenterSupervisorStop,
};
pub use workspace::*;
