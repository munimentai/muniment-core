//! The runtime's session relay publisher: the account and run operations
//! `muniment_core::relay_publisher` drives.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use muniment_core::active_run::{
    cancel_active_run, queue_message, queue_permission_answer_with_commit, ChatDelivery,
    ChatQueueRequest,
};
use muniment_core::attach::RuntimeActivityRegistry;
use muniment_core::journal::EventPayload;
use muniment_core::permission_gate::ChatPermissionAnswer;
use muniment_core::relay_encryption::{GateDecision, RelayKeys};
use muniment_core::relay_publisher::{
    relay_state_path, RelayAccount, RelayConnection, RelayPublisher, RelayRuntime,
};
use muniment_core::run_events::{ChatEventSubscription, SharedStorage};
use muniment_core::run_start::ActiveRun;
use muniment_core::serde_json;

use crate::host::RuntimeHost;
use crate::RuntimeChatEventBroadcast;

/// How long a phone's permission answer waits for its journal commit.
const ANSWER_COMMIT_TIMEOUT: Duration = Duration::from_secs(2);

struct Account {
    host: RuntimeHost,
    runtime_activity: RuntimeActivityRegistry,
    profile_directory: PathBuf,
}

impl RelayAccount for Account {
    fn keys(&self) -> Option<RelayKeys> {
        self.host.account.relay_keys(&self.profile_directory)
    }

    fn connection(&self, pair_id: &str) -> Option<RelayConnection> {
        let api_base = self.host.account.cloud_api_base()?;
        let access_token = self
            .host
            .account
            .session(&self.runtime_activity)
            .ok()?
            .tokens?
            .access_token;
        if access_token.is_empty() {
            return None;
        }
        let status = self
            .host
            .account
            .pairing_status(&access_token, &self.profile_directory)
            .ok()?;
        (status.pair?.pair_id.to_string() == pair_id).then_some(RelayConnection {
            api_base,
            access_token,
        })
    }
}

struct Runs {
    active: Arc<Mutex<Option<ActiveRun>>>,
    chat_events: RuntimeChatEventBroadcast,
    storage: SharedStorage,
}

impl RelayRuntime for Runs {
    fn subscribe(&self) -> Option<ChatEventSubscription> {
        Some(self.chat_events.subscribe())
    }

    fn stop(&self, run_id: &str) -> Result<(), String> {
        cancel_active_run(&self.active, run_id, None)
    }

    fn queue(&self, run_id: &str, delivery: ChatDelivery, text: &str) -> Result<(), String> {
        queue_message(
            &self.active,
            ChatQueueRequest {
                run_id: run_id.to_owned(),
                workspace: None,
                delivery,
                message: text.to_owned(),
            },
        )
    }

    fn answer(
        &self,
        run_id: &str,
        gate_id: &str,
        answer: ChatPermissionAnswer,
    ) -> Result<(), String> {
        queue_permission_answer_with_commit(
            &self.active,
            None,
            run_id.to_owned(),
            gate_id.to_owned(),
            answer,
        )?
        .recv_timeout(ANSWER_COMMIT_TIMEOUT)
        .map_err(|_| "The permission answer did not commit in time.".to_string())?
        .map(|_| ())
        .ok_or_else(|| "The permission answer was rejected.".to_string())
    }

    /// Reads the decision the journal recorded for a gate the desktop answered.
    fn gate_decision(&self, run_id: &str, gate_id: &str) -> Option<GateDecision> {
        let events = self.storage.lock().ok()?.journal.events(run_id).ok()?;
        events.iter().rev().find_map(|event| {
            let EventPayload::Inline { payload_json } = &event.payload else {
                return None;
            };
            if event.event_type != "permission.resolved" || payload_json["gate_id"] != gate_id {
                return None;
            }
            let answer =
                serde_json::from_value::<ChatPermissionAnswer>(payload_json["decision"].clone())
                    .ok()?;
            Some(match answer {
                ChatPermissionAnswer::Cancelled | ChatPermissionAnswer::Confirm(false) => {
                    GateDecision::Deny
                }
                _ => GateDecision::Allow,
            })
        })
    }
}

/// Starts the relay publisher for a host with a cloud. A host without one
/// gets none.
pub(crate) fn start(
    host: &RuntimeHost,
    runtime_activity: RuntimeActivityRegistry,
    profile_directory: PathBuf,
    active: Arc<Mutex<Option<ActiveRun>>>,
    chat_events: RuntimeChatEventBroadcast,
    storage: SharedStorage,
) -> Option<RelayPublisher> {
    host.account.cloud_api_base()?;
    let state_path = relay_state_path(&profile_directory);
    Some(RelayPublisher::start(
        Arc::new(Account {
            host: host.clone(),
            runtime_activity,
            profile_directory,
        }),
        Arc::new(Runs {
            active,
            chat_events,
            storage,
        }),
        state_path,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_without_a_cloud_starts_no_publisher() {
        let profile = std::env::temp_dir().join(format!(
            "muniment-relay-host-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let storage = crate::open_profile_storage(&profile).unwrap();
        let publisher = start(
            &RuntimeHost::default(),
            RuntimeActivityRegistry::default(),
            profile.clone(),
            Arc::new(Mutex::new(None)),
            RuntimeChatEventBroadcast::default(),
            storage,
        );
        assert!(publisher.is_none());
        std::fs::remove_dir_all(profile).unwrap();
    }
}
