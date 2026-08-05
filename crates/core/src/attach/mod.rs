//! Companion attach server support.

mod approval;
mod artifact;
mod authorization;
#[cfg(target_os = "linux")]
mod credential;
mod cursor;
mod idempotency;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
mod migration_authority;

pub use approval::*;
pub use artifact::*;
pub use authorization::*;
#[cfg(target_os = "linux")]
pub use credential::*;
pub use cursor::{
    RunEventAdmission, RunStreamCursor, RunStreamError, RunStreamWindow, StreamClose,
    StreamCloseCode, MAX_RUN_STREAM_WINDOW_BYTES, MAX_RUN_STREAM_WINDOW_EVENTS,
    MAX_RUN_STREAM_WINDOW_TEXT_BYTES,
};
pub use idempotency::*;
#[cfg(target_os = "linux")]
pub use migration_authority::*;
pub use muniment_attach::*;
