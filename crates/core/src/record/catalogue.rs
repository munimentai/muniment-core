//! The kind catalogue and the relation vocabulary. The seventeen core kinds
//! and seventeen relations follow the schema page, and three kinds more hold
//! the mapping, the workflow and the saved view. Core kinds are identical in
//! every company and never fork.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KindDefinition {
    pub name: String,
    pub version: i64,
    pub schema: Value,
    pub title_template: String,
    pub text_template: String,
    pub states: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Relation {
    pub name: &'static str,
    /// Source kinds, or `any`.
    pub from: &'static [&'static str],
    /// Destination kinds, or `any`.
    pub to: &'static [&'static str],
}

impl Relation {
    pub fn accepts(&self, src_kind: &str, dst_kind: &str) -> bool {
        fn allows(list: &[&str], kind: &str) -> bool {
            list.contains(&"any") || list.contains(&kind)
        }
        allows(self.from, src_kind) && allows(self.to, dst_kind)
    }
}

const RELATIONS: [Relation; 17] = [
    Relation {
        name: "works_at",
        from: &["person"],
        to: &["org"],
    },
    Relation {
        name: "reports_to",
        from: &["person"],
        to: &["person"],
    },
    Relation {
        name: "member_of",
        from: &["person"],
        to: &["org"],
    },
    Relation {
        name: "owns",
        from: &["person"],
        to: &["any"],
    },
    Relation {
        name: "about",
        from: &["message", "document", "meeting"],
        to: &["any"],
    },
    Relation {
        name: "part_of",
        from: &["message", "task"],
        to: &["thread", "task"],
    },
    Relation {
        name: "participant",
        from: &["person"],
        to: &["thread", "meeting"],
    },
    Relation {
        name: "mentions",
        from: &["message", "document"],
        to: &["any"],
    },
    Relation {
        name: "billed_to",
        from: &["invoice", "subscription"],
        to: &["org"],
    },
    Relation {
        name: "concerns",
        from: &["deal", "ticket"],
        to: &["org"],
    },
    Relation {
        name: "derived_from",
        from: &["commitment", "decision"],
        to: &["message", "document"],
    },
    Relation {
        name: "duplicate_of",
        from: &["any"],
        to: &["any"],
    },
    Relation {
        name: "superseded_by",
        from: &["any"],
        to: &["any"],
    },
    Relation {
        name: "blocks",
        from: &["task"],
        to: &["task"],
    },
    Relation {
        name: "depends_on",
        from: &["service"],
        to: &["service"],
    },
    Relation {
        name: "caused_by",
        from: &["incident"],
        to: &["deploy"],
    },
    Relation {
        name: "affects",
        from: &["incident"],
        to: &["service", "org"],
    },
];

pub fn relations() -> &'static [Relation] {
    &RELATIONS
}

pub fn relation(name: &str) -> Option<&'static Relation> {
    RELATIONS.iter().find(|relation| relation.name == name)
}

#[derive(Clone, Copy)]
enum Property {
    Str,
    Num,
    Int,
    Bool,
    Date,
    DateTime,
    StrList,
    List,
    Obj,
    Enum(&'static [&'static str]),
}

impl Property {
    fn schema(self) -> Value {
        match self {
            Self::Str => json!({"type": "string"}),
            Self::Num => json!({"type": "number"}),
            Self::Int => json!({"type": "integer"}),
            Self::Bool => json!({"type": "boolean"}),
            Self::Date => json!({"type": "string", "format": "date"}),
            Self::DateTime => json!({"type": "string", "format": "date-time"}),
            Self::StrList => json!({"type": "array", "items": {"type": "string"}}),
            Self::List => json!({"type": "array"}),
            Self::Obj => json!({"type": "object"}),
            Self::Enum(values) => json!({"type": "string", "enum": values}),
        }
    }
}

fn schema(
    properties: &[(&str, Property)],
    required: &[&str],
    state_property: Option<&str>,
) -> Value {
    let mut map = Map::new();
    for (name, property) in properties {
        map.insert((*name).to_owned(), property.schema());
    }
    let mut schema = json!({
        "type": "object",
        "properties": Value::Object(map),
        "required": required,
    });
    if let Some(state_property) = state_property {
        schema["stateProperty"] = Value::String(state_property.to_owned());
    }
    schema
}

fn kind(
    name: &str,
    properties: &[(&str, Property)],
    required: &[&str],
    title_template: &str,
    text_template: &str,
    state_property: Option<&str>,
) -> KindDefinition {
    let states = state_property.and_then(|state| {
        properties.iter().find_map(|(property, definition)| {
            match (property == &state, definition) {
                (true, Property::Enum(values)) => {
                    Some(values.iter().map(|value| (*value).to_owned()).collect())
                }
                _ => None,
            }
        })
    });
    KindDefinition {
        name: name.to_owned(),
        version: 1,
        schema: schema(properties, required, state_property),
        title_template: title_template.to_owned(),
        text_template: text_template.to_owned(),
        states,
    }
}

use Property::*;

const DEAL_STAGES: &[&str] = &[
    "discovery",
    "qualification",
    "proposal",
    "negotiation",
    "won",
    "lost",
];
const TICKET_STATUSES: &[&str] = &["open", "pending", "resolved", "closed"];
const PRIORITIES: &[&str] = &["low", "medium", "high", "urgent"];
const TASK_STATUSES: &[&str] = &["todo", "in_progress", "blocked", "done", "cancelled"];
const PROJECT_STATUSES: &[&str] = &["active", "paused", "archived"];
const SUBSCRIPTION_STATES: &[&str] = &["trial", "active", "paused", "cancelled"];
const INVOICE_STATUSES: &[&str] = &["draft", "open", "paid", "void", "uncollectible"];
const INCIDENT_STATUSES: &[&str] = &["triggered", "acknowledged", "resolved"];
const COMMITMENT_STATUSES: &[&str] = &["open", "kept", "missed", "cancelled"];
const DECISION_STATUSES: &[&str] = &["proposed", "made", "reversed"];
const DIRECTIONS: &[&str] = &["inbound", "outbound"];
const LAYOUTS: &[&str] = &["table", "board", "list"];

/// The catalogue every company starts with.
pub fn core_kinds() -> Vec<KindDefinition> {
    vec![
        kind(
            "person",
            &[
                ("given_name", Str), ("family_name", Str), ("full_name", Str),
                ("salutation", Str), ("job_title", Str), ("department", Str),
                ("status", Str), ("timezone", Str), ("city", Str), ("country", Str),
            ],
            &["full_name"],
            "{full_name}",
            "{full_name}, {job_title}, {department}. {city} {country}. Status {status}.",
            None,
        ),
        kind(
            "org",
            &[
                ("name", Str), ("legal_name", Str), ("domain", Str), ("industry", Str),
                ("market_segment", Str), ("employee_band", Str), ("annual_revenue", Num),
                ("website", Str), ("city", Str), ("state", Str), ("country", Str), ("status", Str),
            ],
            &["name"],
            "{name}",
            "{name} ({legal_name}), {industry}, {market_segment}, {employee_band} employees, {domain}. {city} {state} {country}. Status {status}.",
            None,
        ),
        kind(
            "deal",
            &[
                ("name", Str), ("stage", Enum(DEAL_STAGES)), ("amount", Num), ("currency", Str),
                ("probability", Num), ("expected_close", Date), ("closed_at", DateTime),
                ("lost_reason", Str), ("competitor", Str), ("utm_source", Str), ("utm_medium", Str),
                ("utm_campaign", Str), ("utm_content", Str), ("first_response_at", DateTime),
            ],
            &["name", "stage", "expected_close"],
            "{name}",
            "{name}: {stage}, {amount} {currency}, expected close {expected_close}. {lost_reason}",
            Some("stage"),
        ),
        kind(
            "thread",
            &[
                ("subject", Str), ("medium", Str), ("channel", Str), ("topic", Str),
                ("started_at", DateTime), ("last_message_at", DateTime), ("message_count", Int),
                ("is_private", Bool),
            ],
            &["subject"],
            "{subject}",
            "{subject} in {channel} on {medium}, {message_count} messages, last {last_message_at}.",
            None,
        ),
        kind(
            "message",
            &[
                ("medium", Str), ("direction", Enum(DIRECTIONS)), ("sender", Str),
                ("recipients", StrList), ("cc", StrList), ("sent_at", DateTime),
                ("received_at", DateTime), ("body_text", Str), ("preview", Str),
                ("external_message_id", Str), ("in_reply_to", Str), ("delivery_status", Str),
                ("has_attachment", Bool),
            ],
            &["medium", "sender"],
            "{sender}: {preview}",
            "{sender} to {recipients} on {medium} at {sent_at}. {body_text}",
            None,
        ),
        kind(
            "ticket",
            &[
                ("subject", Str), ("status", Enum(TICKET_STATUSES)), ("priority", Enum(PRIORITIES)),
                ("channel", Str), ("opened_at", DateTime), ("first_response_at", DateTime),
                ("resolved_at", DateTime), ("reopened_count", Int), ("labels", StrList),
            ],
            &["subject", "status"],
            "{subject}",
            "{subject}: {status}, {priority}, opened {opened_at} on {channel}. {labels}",
            Some("status"),
        ),
        kind(
            "task",
            &[
                ("title", Str), ("external_key", Str), ("type", Str), ("status", Enum(TASK_STATUSES)),
                ("priority", Str), ("estimate", Num), ("resolution", Str), ("due_at", DateTime),
                ("completed_at", DateTime),
            ],
            &["title", "status"],
            "{title}",
            "{external_key} {title}: {status}, {priority}, due {due_at}. {resolution}",
            Some("status"),
        ),
        kind(
            "project",
            &[
                ("name", Str), ("key", Str), ("status", Enum(PROJECT_STATUSES)), ("kind_hint", Str),
                ("started_at", Date), ("target_at", Date), ("archived_at", DateTime),
            ],
            &["name"],
            "{name}",
            "{key} {name}: {status}, started {started_at}, target {target_at}.",
            Some("status"),
        ),
        kind(
            "document",
            &[
                ("title", Str), ("mime", Str), ("external_url", Str), ("extracted_text", Str),
                ("byte_size", Int), ("modified_at", DateTime), ("revision", Str),
            ],
            &["title"],
            "{title}",
            "{title} ({mime}), modified {modified_at}. {extracted_text}",
            None,
        ),
        kind(
            "meeting",
            &[
                ("title", Str), ("start_at", DateTime), ("end_at", DateTime), ("location", Str),
                ("recurrence_rule", Str), ("external_uid", Str), ("sequence", Int),
                ("transcript_text", Str),
            ],
            &["title", "start_at"],
            "{title}",
            "{title} at {start_at} until {end_at}, {location}. {transcript_text}",
            None,
        ),
        kind(
            "subscription",
            &[
                ("plan", Str), ("phase", Str), ("state", Enum(SUBSCRIPTION_STATES)),
                ("billing_period", Str), ("started_at", DateTime), ("cancelled_at", DateTime),
                ("amount", Num), ("currency", Str),
            ],
            &["plan", "state"],
            "{plan}",
            "{plan} {phase}: {state}, {amount} {currency} per {billing_period}, started {started_at}.",
            Some("state"),
        ),
        kind(
            "invoice",
            &[
                ("number", Str), ("status", Enum(INVOICE_STATUSES)), ("amount", Num), ("balance", Num),
                ("currency", Str), ("issued_at", Date), ("due_at", Date), ("period_start", Date),
                ("period_end", Date),
            ],
            &["number", "status"],
            "Invoice {number}",
            "Invoice {number}: {status}, {amount} {currency}, balance {balance}, issued {issued_at}, due {due_at}.",
            Some("status"),
        ),
        kind(
            "service",
            &[
                ("name", Str), ("tier", Str), ("lifecycle", Str), ("repo_url", Str),
                ("runbook_url", Str), ("on_call_rotation", Str),
            ],
            &["name"],
            "{name}",
            "{name}: tier {tier}, {lifecycle}, on call {on_call_rotation}.",
            None,
        ),
        kind(
            "incident",
            &[
                ("number", Str), ("title", Str), ("severity", Str), ("status", Enum(INCIDENT_STATUSES)),
                ("opened_at", DateTime), ("acknowledged_at", DateTime), ("resolved_at", DateTime),
                ("duration", Int), ("escalation_count", Int), ("postmortem_text", Str),
            ],
            &["title", "severity", "status"],
            "{number} {title}",
            "{number} {title}: {severity}, {status}, opened {opened_at}, resolved {resolved_at}. {postmortem_text}",
            Some("status"),
        ),
        kind(
            "deploy",
            &[
                ("version", Str), ("environment", Str), ("deployed_at", DateTime), ("status", Str),
                ("change_ref", Str),
            ],
            &["version", "environment"],
            "{version} to {environment}",
            "{version} to {environment} at {deployed_at}: {status}, change {change_ref}.",
            None,
        ),
        kind(
            "commitment",
            &[
                ("statement", Str), ("owner", Str), ("counterparty", Str), ("due_at", DateTime),
                ("status", Enum(COMMITMENT_STATUSES)), ("confidence", Num),
            ],
            &["statement", "owner"],
            "{statement}",
            "{owner} committed to {counterparty}: {statement}, due {due_at}, {status}.",
            Some("status"),
        ),
        kind(
            "decision",
            &[
                ("statement", Str), ("decided_at", DateTime), ("status", Enum(DECISION_STATUSES)),
                ("supersedes", Str), ("confidence", Num),
            ],
            &["statement"],
            "{statement}",
            "{statement}, {status} at {decided_at}.",
            Some("status"),
        ),
        kind(
            "mapping",
            &[
                ("source", Str), ("object", Str), ("kind", Str), ("fields", Obj), ("identity", Str),
                ("edges", List), ("cursors", Obj), ("approved", Bool),
            ],
            &["source", "object", "kind"],
            "{source} {object} to {kind}",
            "Mapping of {source} {object} onto {kind}, keyed on {identity}.",
            None,
        ),
        kind(
            "workflow",
            &[("name", Str), ("trigger", Obj), ("steps", List), ("enabled", Bool)],
            &["name", "trigger", "steps"],
            "{name}",
            "Workflow {name}.",
            None,
        ),
        kind(
            "view",
            &[
                ("name", Str), ("kind", Str), ("layout", Enum(LAYOUTS)), ("filters", List),
                ("sort", List), ("group", Str), ("columns", StrList),
            ],
            &["name", "kind", "layout"],
            "{name}",
            "View {name} over {kind} as a {layout}.",
            None,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogue_holds_twenty_kinds_and_seventeen_relations() {
        let kinds = core_kinds();
        assert_eq!(kinds.len(), 20);
        let mut names: Vec<_> = kinds.iter().map(|kind| kind.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 20);
        assert_eq!(relations().len(), 17);
    }

    #[test]
    fn a_kind_with_a_state_property_lists_its_states() {
        let deal = core_kinds()
            .into_iter()
            .find(|kind| kind.name == "deal")
            .unwrap();
        assert_eq!(deal.schema["stateProperty"], "stage");
        assert_eq!(deal.states.as_deref().unwrap().len(), 6);
        assert_eq!(
            deal.schema["required"],
            json!(["name", "stage", "expected_close"])
        );
        let person = core_kinds()
            .into_iter()
            .find(|kind| kind.name == "person")
            .unwrap();
        assert!(person.states.is_none());
    }

    #[test]
    fn relations_check_their_endpoints() {
        assert!(relation("works_at").unwrap().accepts("person", "org"));
        assert!(!relation("works_at").unwrap().accepts("org", "person"));
        assert!(relation("owns").unwrap().accepts("person", "deal"));
        assert!(relation("superseded_by")
            .unwrap()
            .accepts("x_vendor", "x_vendor"));
        assert!(relation("nope").is_none());
    }
}
