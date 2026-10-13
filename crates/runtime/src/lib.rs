//! The platform-neutral Muniment runtime.
//!
//! The runtime is the one process per user that owns execution: the agent
//! child, the run journal, schedules and the attach listener. A host binary
//! supplies cloud accounts, chat grants, credential storage and the paths of
//! its own executables through [`RuntimeHost`], and registers the binary with
//! the OS service manager when it has one.

#[cfg(any(unix, target_os = "windows"))]
mod agent_schedule;
mod attach_boundaries;
#[cfg(target_os = "linux")]
mod attach_listener;
#[cfg(any(unix, target_os = "windows"))]
mod attach_service;
#[cfg(any(unix, target_os = "windows"))]
mod attach_state;
mod directories;
#[cfg(target_os = "linux")]
mod entry;
pub mod host;
mod macos_attach_loop;
#[cfg(target_os = "linux")]
mod migration;
mod reader;
mod reader_csv;
mod reader_mapping;
mod reader_secret;
mod reader_sidecar;
#[cfg(any(unix, target_os = "windows"))]
mod retention_schedule;
pub mod service;
mod sink;
mod windows_attach_loop;

pub use attach_boundaries::RuntimeAttachBoundaries;
#[cfg(target_os = "linux")]
pub use attach_listener::{
    run_attach_listener, run_bound_attach_listener, AttachListenerError, AttachListenerInputs,
};
#[cfg(any(unix, target_os = "windows"))]
pub use attach_service::compose_attach_service;
#[cfg(any(unix, target_os = "windows"))]
pub use attach_state::RuntimeAttachState;
pub use directories::{
    adopt_state_directory, config_directory, profile_directory, DirectoryUnavailableError,
};
#[cfg(target_os = "linux")]
pub use entry::{run_runtime, RunRuntimeError, RuntimeDirectories};
pub use host::RuntimeHost;
#[cfg(target_os = "macos")]
pub use macos_attach_loop::MacosAttachAcceptor;
pub use macos_attach_loop::{macos_attach_socket_path, MacosAttachBindFailure};
#[cfg(any(unix, target_os = "windows"))]
#[doc(hidden)]
pub use macos_attach_loop::{MacosAttachAcceptorWithBoundary, MacosAttachServeBoundary};
#[cfg(target_os = "linux")]
pub use migration::{
    run_migration_takeover, run_migration_takeover_with_activation, MigrationTakeoverError,
};
#[cfg(any(unix, target_os = "windows"))]
pub use retention_schedule::{start_retention_schedule, RetentionScheduleCommand};
#[cfg(any(unix, target_os = "windows"))]
pub use service::open_companion_registry;
pub use service::{
    accept_prompt, answer_permission, apply_retention, cancel_run, configure_run, create_company,
    create_thread, delete_company, delete_thread, drive_prompt, ensure_home, list_companies,
    list_companions, onboard_workspace, open_profile_storage, open_profile_storage_as,
    queue_run_message, rename_company, rename_thread, resume_run, revoke_companion, run_prompt,
    select_company, select_thread, stream_run, subscribe_run_commits, thread_page,
    thread_summaries, ConfigureRunError, PromptAcceptance, PromptLaunch, RecordRegistry,
};
pub use sink::{
    RuntimeChatEventBroadcast, RuntimeChatEventSink, RuntimeChatEventTarget,
    CHAT_EVENT_SUBSCRIBER_QUEUE_CAPACITY,
};
#[cfg(target_os = "windows")]
pub use windows_attach_loop::WindowsAttachAcceptor;
pub use windows_attach_loop::{
    run_windows_attach_accept_loop, WindowsAttachAcceptBoundary, WindowsAttachAcceptLoopExit,
    WindowsAttachAcceptOutcome, WindowsAttachStopSignal, MAX_CONSECUTIVE_FAILED_ACCEPTS,
};
