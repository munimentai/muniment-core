//! Dormant runtime service composition.

mod company;
pub(crate) mod prompt_storage;
mod reader;
mod record;
mod run;
mod threads;
mod workspace;

pub use company::{create_company, delete_company, list_companies, rename_company, select_company};
pub use record::RecordRegistry;
pub use run::{
    accept_compaction, accept_prompt, answer_permission, cancel_run, configure_run,
    drive_compaction, drive_prompt, queue_run_message, resume_run, run_prompt, ConfigureRunError,
    PromptAcceptance, PromptLaunch,
};
pub use threads::{
    apply_retention, create_thread, delete_thread, rename_thread, select_thread, stream_run,
    subscribe_run_commits, thread_page, thread_summaries,
};
#[cfg(any(unix, target_os = "windows"))]
pub use workspace::open_companion_registry;
pub use workspace::{
    ensure_home, list_companions, onboard_workspace, open_profile_storage, revoke_companion,
};

use muniment_core::journal::Provenance;
use std::collections::BTreeMap;

pub(crate) fn runtime_provenance() -> Provenance {
    Provenance {
        source: "muniment-runtime".into(),
        source_version: env!("CARGO_PKG_VERSION").into(),
        actor_id: None,
        device_id: None,
        rpc_request_id: None,
        capability_versions: None,
        extra: BTreeMap::new(),
    }
}
