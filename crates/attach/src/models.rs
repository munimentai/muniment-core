//! The model service's action set, carried by the `models.request` operation.
//!
//! A `models.request` body is `{"action": <action>, "data": <object>}`. The
//! runtime answers `{"result": <value>}`. An action that changes a setting, a
//! credential or a sign-in carries an idempotency key, and a read carries none.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How long a client waits for an action that answers from local files.
pub const MODELS_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a client waits for an action that lists models, probes a model,
/// asks an upstream, scans local ports or installs Pi before it answers.
pub const MODELS_LONG_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

/// One operation of the runtime's model service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAction {
    ProviderStatus,
    StoreProviderKey,
    StoreLocalProvider,
    ProviderInventory,
    SetDefaultModel,
    SetModelHidden,
    DisconnectProvider,
    StoreEndpoint,
    ClaudeCodeStatus,
    ConnectClaudeCode,
    RouterSettings,
    RouterSetEnabled,
    RouterAddAccount,
    RouterUpdateAccount,
    RouterRemoveAccount,
    RouterSetHidden,
    RouterSaveRoutes,
    RouterSetClassifier,
    RouterTestClassifier,
    RouterTestRoute,
    RouterSubscriptionStart,
    RouterRefreshQuota,
    RouterSetAssist,
    RouterConnectClassifier,
    RouterUpdateClassifier,
    RouterSelectClassifier,
    RouterDisconnectClassifier,
    ProviderScan,
    ConnectServer,
    LoginStart,
    LoginAnswer,
    LoginCancel,
}

impl ModelAction {
    /// Every action, in wire order.
    pub const ALL: [ModelAction; 32] = [
        Self::ProviderStatus,
        Self::StoreProviderKey,
        Self::StoreLocalProvider,
        Self::ProviderInventory,
        Self::SetDefaultModel,
        Self::SetModelHidden,
        Self::DisconnectProvider,
        Self::StoreEndpoint,
        Self::ClaudeCodeStatus,
        Self::ConnectClaudeCode,
        Self::RouterSettings,
        Self::RouterSetEnabled,
        Self::RouterAddAccount,
        Self::RouterUpdateAccount,
        Self::RouterRemoveAccount,
        Self::RouterSetHidden,
        Self::RouterSaveRoutes,
        Self::RouterSetClassifier,
        Self::RouterTestClassifier,
        Self::RouterTestRoute,
        Self::RouterSubscriptionStart,
        Self::RouterRefreshQuota,
        Self::RouterSetAssist,
        Self::RouterConnectClassifier,
        Self::RouterUpdateClassifier,
        Self::RouterSelectClassifier,
        Self::RouterDisconnectClassifier,
        Self::ProviderScan,
        Self::ConnectServer,
        Self::LoginStart,
        Self::LoginAnswer,
        Self::LoginCancel,
    ];

    /// Whether the action changes a setting, a credential or a sign-in, so its
    /// request carries an idempotency key.
    pub fn mutates(self) -> bool {
        !matches!(
            self,
            Self::ProviderStatus
                | Self::ProviderInventory
                | Self::ClaudeCodeStatus
                | Self::RouterSettings
                | Self::RouterTestClassifier
                | Self::RouterTestRoute
                | Self::ProviderScan
        )
    }

    /// How long a client waits for the answer.
    pub fn timeout(self) -> Duration {
        match self {
            Self::StoreProviderKey
            | Self::ProviderInventory
            | Self::StoreEndpoint
            | Self::ClaudeCodeStatus
            | Self::RouterTestClassifier
            | Self::RouterTestRoute
            | Self::RouterSubscriptionStart
            | Self::RouterRefreshQuota
            | Self::RouterConnectClassifier
            | Self::RouterUpdateClassifier
            | Self::ProviderScan
            | Self::ConnectServer
            | Self::LoginStart => MODELS_LONG_REQUEST_TIMEOUT,
            _ => MODELS_REQUEST_TIMEOUT,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProviderStatus => "provider_status",
            Self::StoreProviderKey => "store_provider_key",
            Self::StoreLocalProvider => "store_local_provider",
            Self::ProviderInventory => "provider_inventory",
            Self::SetDefaultModel => "set_default_model",
            Self::SetModelHidden => "set_model_hidden",
            Self::DisconnectProvider => "disconnect_provider",
            Self::StoreEndpoint => "store_endpoint",
            Self::ClaudeCodeStatus => "claude_code_status",
            Self::ConnectClaudeCode => "connect_claude_code",
            Self::RouterSettings => "router_settings",
            Self::RouterSetEnabled => "router_set_enabled",
            Self::RouterAddAccount => "router_add_account",
            Self::RouterUpdateAccount => "router_update_account",
            Self::RouterRemoveAccount => "router_remove_account",
            Self::RouterSetHidden => "router_set_hidden",
            Self::RouterSaveRoutes => "router_save_routes",
            Self::RouterSetClassifier => "router_set_classifier",
            Self::RouterTestClassifier => "router_test_classifier",
            Self::RouterTestRoute => "router_test_route",
            Self::RouterSubscriptionStart => "router_subscription_start",
            Self::RouterRefreshQuota => "router_refresh_quota",
            Self::RouterSetAssist => "router_set_assist",
            Self::RouterConnectClassifier => "router_connect_classifier",
            Self::RouterUpdateClassifier => "router_update_classifier",
            Self::RouterSelectClassifier => "router_select_classifier",
            Self::RouterDisconnectClassifier => "router_disconnect_classifier",
            Self::ProviderScan => "provider_scan",
            Self::ConnectServer => "connect_server",
            Self::LoginStart => "login_start",
            Self::LoginAnswer => "login_answer",
            Self::LoginCancel => "login_cancel",
        }
    }
}

/// One `models.request` body: the action and its data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequest {
    pub action: ModelAction,
    #[serde(default = "empty_object")]
    pub data: Value,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

impl ModelRequest {
    /// Reads a request body. A body with another shape, or data that is not
    /// an object, answers none.
    pub fn from_body(body: &Value) -> Option<Self> {
        serde_json::from_value::<Self>(body.clone())
            .ok()
            .filter(|request| request.data.is_object())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_round_trips_its_wire_name() {
        for action in ModelAction::ALL {
            let wire = serde_json::to_value(action).unwrap();
            assert_eq!(wire, action.as_str());
            assert_eq!(serde_json::from_value::<ModelAction>(wire).unwrap(), action);
        }
    }

    #[test]
    fn a_body_names_its_action_and_carries_object_data() {
        let request = ModelRequest::from_body(
            &serde_json::json!({"action": "router_set_enabled", "data": {"enabled": true}}),
        )
        .unwrap();
        assert_eq!(request.action, ModelAction::RouterSetEnabled);
        assert!(request.action.mutates());
        let read = ModelRequest::from_body(&serde_json::json!({"action": "router_settings"}));
        assert_eq!(read.unwrap().data, serde_json::json!({}));
        assert!(!ModelAction::RouterSettings.mutates());
        for body in [
            serde_json::json!({"action": "nothing"}),
            serde_json::json!({"action": "router_settings", "data": []}),
            serde_json::json!({"action": "router_settings", "extra": 1}),
        ] {
            assert!(ModelRequest::from_body(&body).is_none(), "{body}");
        }
    }
}
