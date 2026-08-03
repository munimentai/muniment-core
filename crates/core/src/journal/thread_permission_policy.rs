use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadPermissionDecision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadPermissionRequestKind {
    Path,
    Command,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ThreadPermissionResource {
    Path {
        path: String,
        operation: String,
    },
    Command {
        arguments: Vec<String>,
        working_directory: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadPermissionAnswerSource {
    Native,
    Acp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadPermissionPolicyDecided {
    pub policy_id: String,
    pub decision: ThreadPermissionDecision,
    pub request_kind: ThreadPermissionRequestKind,
    pub resource: ThreadPermissionResource,
    pub actor: String,
    pub answer_source: ThreadPermissionAnswerSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadPermissionPolicyRevoked {
    pub policy_id: String,
    pub actor: String,
    pub reason: String,
}
