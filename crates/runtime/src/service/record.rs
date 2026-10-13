//! The open company records, their SQL tools, and the actor each request
//! runs as. One registry per runtime, so a proposal made through one request
//! is there for the commit that follows.

use crate::host::RuntimeHost;
use muniment_core::attach::ProtocolError;
use muniment_core::record::{
    CompaniesRoot, CompanyError, CompanyRecord, Operation, QueryOptions, RecordError, SqlTool,
    ValidationError, DESKTOP_ACTOR,
};
use muniment_core::serde_json::{self, json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

pub struct RecordRegistry {
    pub(super) root: CompaniesRoot,
    open: Mutex<HashMap<String, OpenRecord>>,
    pub(super) host: RuntimeHost,
}

pub(super) struct OpenRecord {
    pub(super) record: CompanyRecord,
    sql: SqlTool,
    pub(super) owner_principal_id: String,
}

struct SqlBody {
    sql: String,
    company_id: Option<String>,
}

struct ProposeBody {
    operation: Value,
    company_id: Option<String>,
}

struct CommitBody {
    proposal: String,
    company_id: Option<String>,
}

pub(super) fn text(body: &Value, key: &str) -> Result<String, ProtocolError> {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(ProtocolError::invalid_request)
}

pub(super) fn company_id(body: &Value) -> Result<Option<String>, ProtocolError> {
    match body.get("company_id") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(id)) => Ok(Some(id.clone())),
        Some(_) => Err(ProtocolError::invalid_request()),
    }
}

fn parse_sql(body: &Value) -> Result<SqlBody, ProtocolError> {
    Ok(SqlBody {
        sql: text(body, "sql")?,
        company_id: company_id(body)?,
    })
}

fn parse_propose(body: &Value) -> Result<ProposeBody, ProtocolError> {
    Ok(ProposeBody {
        operation: body
            .get("operation")
            .cloned()
            .ok_or_else(ProtocolError::invalid_request)?,
        company_id: company_id(body)?,
    })
}

fn parse_commit(body: &Value) -> Result<CommitBody, ProtocolError> {
    Ok(CommitBody {
        proposal: text(body, "proposal")?,
        company_id: company_id(body)?,
    })
}

pub(super) fn error_body(code: &str, message: impl Into<String>) -> Value {
    json!({"error": {"code": code, "message": message.into()}})
}

/// Every record failure an agent can act on, as a body it reads.
pub(super) fn record_failure(error: RecordError) -> Value {
    let code = match &error {
        RecordError::UnknownKind(_) => "unknown_kind",
        RecordError::KindExists(_)
        | RecordError::CoreKindImmutable(_)
        | RecordError::ExtensionName(_) => "catalogue",
        RecordError::UnknownRelation(_) | RecordError::RelationEndpoints { .. } => "relation",
        RecordError::Validation(ValidationError::MissingRequired { .. }) => "missing_required",
        RecordError::Validation(_) => "validation",
        RecordError::Identity(_) => "identity",
        RecordError::Unresolved(_) => "unresolved",
        RecordError::IdentityBound { .. } => "identity_bound",
        RecordError::AlreadyLinked(_) => "already_linked",
        RecordError::SameEntity | RecordError::KindMismatch { .. } => "merge",
        RecordError::EntityDeleted(_) => "superseded",
        RecordError::ProposalNotFound(_) => "proposal_not_found",
        RecordError::ProposalExpired(_) => "proposal_expired",
        RecordError::Stale(_) => "stale",
        RecordError::PrincipalNotFound(_)
        | RecordError::PrincipalDisabled(_)
        | RecordError::Delegation => "principal",
        RecordError::Sqlite(_) | RecordError::Json(_) | RecordError::UnsupportedSchema(_) => {
            "record"
        }
    };
    let mut body = error_body(code, error.to_string());
    if let RecordError::Validation(ValidationError::MissingRequired { field, prompt }) = &error {
        body["error"]["field"] = json!(field);
        body["error"]["prompt"] = json!(prompt);
    }
    body
}

impl RecordRegistry {
    pub fn new(state_directory: impl AsRef<Path>) -> Self {
        Self::with_host(state_directory, RuntimeHost::default())
    }

    /// Opens the registry with the host whose credential store and reader
    /// sidecar the network sources use.
    pub fn with_host(state_directory: impl AsRef<Path>, host: RuntimeHost) -> Self {
        Self {
            root: CompaniesRoot::new(state_directory),
            open: Mutex::new(HashMap::new()),
            host,
        }
    }

    /// The company a request names, or the current one. An absent company is
    /// a body the caller reads.
    pub(super) fn resolve_company_id(
        &self,
        company_id: Option<&str>,
    ) -> Result<Result<String, Value>, ProtocolError> {
        match company_id {
            Some(id) => Ok(Ok(id.to_owned())),
            None => match self.root.current() {
                Ok(Some(id)) => Ok(Ok(id)),
                Ok(None) => Ok(Err(error_body(
                    "no_company",
                    "No company exists yet. Create one in the desktop's Record panel.",
                ))),
                Err(error) => Err(ProtocolError::persistence_failed_with_reason(
                    error.to_string(),
                )),
            },
        }
    }

    /// Resolves the company, the current one when none is named, and opens
    /// it once. An absent or unknown company is a body the agent reads.
    pub(super) fn with_record<T>(
        &self,
        company_id: Option<&str>,
        work: impl FnOnce(&mut OpenRecord) -> Result<T, ProtocolError>,
    ) -> Result<Result<T, Value>, ProtocolError> {
        let company_id = match self.resolve_company_id(company_id)? {
            Ok(id) => id,
            Err(body) => return Ok(Err(body)),
        };
        let mut open = self
            .open
            .lock()
            .map_err(|_| ProtocolError::persistence_failed())?;
        if !open.contains_key(&company_id) {
            let summary = match self.root.list() {
                Ok(companies) => companies
                    .into_iter()
                    .find(|company| company.id == company_id),
                Err(error) => {
                    return Err(ProtocolError::persistence_failed_with_reason(
                        error.to_string(),
                    ))
                }
            };
            let Some(summary) = summary else {
                return Ok(Err(error_body(
                    "unknown_company",
                    format!("No company has id {company_id}."),
                )));
            };
            let record = self
                .root
                .open(&company_id)
                .map_err(company_protocol_error)?;
            let sql = SqlTool::open(
                &self.root.graph_path(&company_id),
                &self.root.sql_audit_path(&company_id),
            )
            .map_err(|error| ProtocolError::persistence_failed_with_reason(error.to_string()))?;
            open.insert(
                company_id.clone(),
                OpenRecord {
                    record,
                    sql,
                    owner_principal_id: summary.owner_principal_id,
                },
            );
        }
        let entry = open
            .get_mut(&company_id)
            .ok_or_else(ProtocolError::persistence_failed)?;
        work(entry).map(Ok)
    }

    /// Drops one company's open record and SQL tool, so every file handle
    /// closes before the company's directory goes.
    pub fn close(&self, company_id: &str) {
        if let Ok(mut open) = self.open.lock() {
            open.remove(company_id);
        }
    }

    /// The kind catalogue of one company, with the company id it belongs to.
    pub fn kinds(&self, _actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let named = company_id(&body)?;
        let resolved = match self.resolve_company_id(named.as_deref())? {
            Ok(id) => id,
            Err(body) => return Ok(body),
        };
        let outcome = self.with_record(Some(&resolved), |entry| {
            let kinds = entry.record.kinds().map_err(|error| {
                ProtocolError::persistence_failed_with_reason(error.to_string())
            })?;
            Ok(json!({
                "company_id": resolved,
                "kinds": kinds,
                "relations": muniment_core::record::relations(),
            }))
        })?;
        Ok(outcome.unwrap_or_else(|body| body))
    }

    /// One page of a kind's rows for the panel's table view.
    pub fn query(&self, _actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let kind = text(&body, "kind")?;
        let mut options = body.clone();
        if let Some(object) = options.as_object_mut() {
            for key in ["kind", "company_id", "client"] {
                object.remove(key);
            }
        }
        let options: QueryOptions =
            serde_json::from_value(options).map_err(|_| ProtocolError::invalid_request())?;
        let outcome = self.with_record(company_id(&body)?.as_deref(), |entry| {
            Ok(match entry.record.query(&kind, &options) {
                Ok(page) => json!({"page": page}),
                Err(error) => record_failure(error),
            })
        })?;
        Ok(outcome.unwrap_or_else(|body| body))
    }

    /// One entity with everything that touches it, for the record view.
    pub fn entity(&self, _actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let id = text(&body, "entity")?;
        let outcome = self.with_record(company_id(&body)?.as_deref(), |entry| {
            Ok(match entry.record.entity_detail(&id) {
                Ok(Some(detail)) => json!({"entity": detail}),
                Ok(None) => error_body("unknown_entity", format!("No entity has id {id}.")),
                Err(error) => record_failure(error),
            })
        })?;
        Ok(outcome.unwrap_or_else(|body| body))
    }

    /// The report over one company's live graph, with how its open count
    /// moved since the last read. The count from the last read sits in
    /// `report.json` beside the graph, so the trend needs no history table.
    pub fn report(&self, _actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let named = company_id(&body)?;
        let resolved = match self.resolve_company_id(named.as_deref())? {
            Ok(id) => id,
            Err(body) => return Ok(body),
        };
        let marker = self.root.company_directory(&resolved).join("report.json");
        let outcome = self.with_record(Some(&resolved), |entry| {
            Ok(match entry.record.report() {
                Ok(report) => {
                    let last = std::fs::read(&marker)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                        .and_then(|value| value.get("open").and_then(Value::as_i64));
                    let moved = last.map(|last| report.open as i64 - last);
                    let _ = std::fs::write(
                        &marker,
                        serde_json::to_vec(&json!({"open": report.open})).unwrap_or_default(),
                    );
                    let mut body = json!({"report": report});
                    body["report"]["moved"] = match moved {
                        Some(moved) => json!(moved),
                        None => Value::Null,
                    };
                    body["report"]["company_id"] = json!(resolved);
                    body
                }
                Err(error) => record_failure(error),
            })
        })?;
        Ok(outcome.unwrap_or_else(|body| body))
    }

    /// Runs one read-only query as the actor named.
    pub fn sql(&self, actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let request = parse_sql(&body)?;
        let outcome = self.with_record(request.company_id.as_deref(), |entry| {
            entry
                .sql
                .run(actor, &request.sql)
                .map_err(|error| ProtocolError::persistence_failed_with_reason(error.to_string()))
        })?;
        Ok(match outcome {
            Ok(Ok(result)) => json!({"result": result}),
            Ok(Err(failure)) => {
                json!({"error": {"code": "sql", "message": failure.message, "elapsed_ms": failure.elapsed_ms}})
            }
            Err(body) => body,
        })
    }

    /// Validates and resolves one operation and returns its diff, writing nothing.
    pub fn propose(&self, _actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let request = parse_propose(&body)?;
        let operation: Operation = match serde_json::from_value(request.operation.clone()) {
            Ok(operation) => operation,
            Err(error) => {
                return Ok(error_body(
                    "invalid_operation",
                    format!("The operation does not parse: {error}"),
                ))
            }
        };
        let kind_for_prompt = match &operation {
            Operation::Create { kind, .. } => Some(kind.clone()),
            _ => None,
        };
        let outcome = self.with_record(request.company_id.as_deref(), |entry| {
            Ok(match entry.record.propose(operation) {
                Ok(proposal) => json!({"proposal": proposal}),
                Err(error) => {
                    let mut body = record_failure(error);
                    if let (Some(kind), Some(field)) = (
                        kind_for_prompt.as_deref(),
                        body["error"]["field"].as_str().map(str::to_owned),
                    ) {
                        if let Ok(Some(row)) = entry.record.kind(kind) {
                            let property = row
                                .schema
                                .get("properties")
                                .and_then(|properties| properties.get(&field))
                                .cloned()
                                .or_else(|| {
                                    row.extension.as_ref().and_then(|extension| {
                                        extension
                                            .get("properties")
                                            .and_then(|properties| properties.get(&field))
                                            .cloned()
                                    })
                                });
                            if let Some(property) = property {
                                body["error"]["schema"] = property;
                            }
                        }
                    }
                    body
                }
            })
        })?;
        Ok(outcome.unwrap_or_else(|body| body))
    }

    /// Applies one proposal as the actor named. The desktop's own client is
    /// the owner. Any other actor is an agent principal acting for the owner.
    pub fn commit(&self, actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let request = parse_commit(&body)?;
        let outcome = self.with_record(request.company_id.as_deref(), |entry| {
            let principal = if actor == DESKTOP_ACTOR {
                entry.owner_principal_id.clone()
            } else {
                let owner = entry.owner_principal_id.clone();
                match entry.record.agent_principal(actor, &owner) {
                    Ok(principal) => principal.id,
                    Err(error) => return Ok(record_failure(error)),
                }
            };
            Ok(match entry.record.commit(&request.proposal, &principal) {
                Ok(result) => json!({"result": result}),
                Err(error) => record_failure(error),
            })
        })?;
        Ok(outcome.unwrap_or_else(|body| body))
    }
}

fn company_protocol_error(error: CompanyError) -> ProtocolError {
    ProtocolError::persistence_failed_with_reason(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("muniment-record-registry-{label}-{nanos}"));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn answers_no_company_until_one_exists_then_serves_the_current_one() {
        let state = state("current");
        let registry = RecordRegistry::new(&state);
        let answer = registry
            .sql("cli:claude-code", json!({"sql": "select 1"}))
            .unwrap();
        assert_eq!(answer["error"]["code"], "no_company");
        assert_eq!(
            registry.kinds("cli", json!({})).unwrap()["error"]["code"],
            "no_company"
        );

        CompaniesRoot::new(&state).create("Northwind").unwrap();
        let answer = registry
            .sql(
                "cli:claude-code",
                json!({"sql": "select count(*) as n from kind"}),
            )
            .unwrap();
        assert_eq!(answer["result"]["csv"], "n\n20\n");

        let refused = registry
            .sql("cli:claude-code", json!({"sql": "delete from kind"}))
            .unwrap();
        assert_eq!(refused["error"]["code"], "sql");

        let unknown = registry
            .sql(
                "cli",
                json!({"sql": "select 1", "company_id": "019965a0-0000-7000-8000-0000000000ff"}),
            )
            .unwrap();
        assert_eq!(unknown["error"]["code"], "unknown_company");
        // Windows refuses to unlink a file another handle still holds, so the
        // registry closes its company connections before the state root goes.
        drop(registry);
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn proposes_and_commits_as_an_agent_that_names_the_owner() {
        let state = state("commit");
        let company = CompaniesRoot::new(&state).create("Northwind").unwrap();
        let registry = RecordRegistry::new(&state);

        let missing = registry
            .propose(
                "cli:claude-code",
                json!({"operation": {"op": "create", "kind": "deal", "data": {"name": "Renewal", "amount": 96000}}}),
            )
            .unwrap();
        assert_eq!(missing["error"]["code"], "missing_required");
        assert_eq!(missing["error"]["field"], "stage");
        assert_eq!(missing["error"]["schema"]["enum"][0], "discovery");

        let proposed = registry
            .propose(
                "cli:claude-code",
                json!({"operation": {"op": "create", "kind": "org", "data": {"name": "Northwind"},
                    "identities": [{"kind": "domain", "value": "northwind.example"}]}}),
            )
            .unwrap();
        let proposal_id = proposed["proposal"]["id"].as_str().unwrap().to_owned();

        let committed = registry
            .commit(
                "cli:claude-code",
                json!({"proposal": proposal_id, "client": "claude-code"}),
            )
            .unwrap();
        assert_eq!(
            committed["result"]["on_behalf_of"],
            company.owner_principal_id
        );
        assert_ne!(committed["result"]["actor"], company.owner_principal_id);

        let again = registry
            .commit("cli:claude-code", json!({"proposal": proposal_id}))
            .unwrap();
        assert_eq!(
            again["result"]["event_seq"],
            committed["result"]["event_seq"]
        );

        let as_owner = registry
            .propose(DESKTOP_ACTOR, json!({"operation": {"op": "update", "entity": "domain:northwind.example", "data": {"industry": "Logistics"}}}))
            .unwrap();
        let owner_commit = registry
            .commit(
                DESKTOP_ACTOR,
                json!({"proposal": as_owner["proposal"]["id"]}),
            )
            .unwrap();
        assert_eq!(owner_commit["result"]["actor"], company.owner_principal_id);
        assert!(owner_commit["result"]["on_behalf_of"].is_null());

        let rows = registry
            .sql(
                DESKTOP_ACTOR,
                json!({"sql": "select verb, actor_id from recent_events"}),
            )
            .unwrap();
        assert_eq!(rows["result"]["row_count"], 2);

        let page = registry
            .query(DESKTOP_ACTOR, json!({"kind": "org", "sort": "title"}))
            .unwrap();
        assert_eq!(page["page"]["total"], 1);
        assert_eq!(page["page"]["rows"][0]["title"], "Northwind");
        let org_id = page["page"]["rows"][0]["id"].as_str().unwrap().to_owned();
        let detail = registry
            .entity(DESKTOP_ACTOR, json!({"entity": org_id}))
            .unwrap();
        assert_eq!(detail["entity"]["entity"]["data"]["industry"], "Logistics");
        assert_eq!(
            detail["entity"]["identities"][0]["value"],
            "northwind.example"
        );
        assert_eq!(detail["entity"]["events"].as_array().unwrap().len(), 2);
        assert_eq!(
            registry
                .entity(DESKTOP_ACTOR, json!({"entity": "nope"}))
                .unwrap()["error"]["code"],
            "unknown_entity"
        );
        assert_eq!(
            registry
                .query(DESKTOP_ACTOR, json!({"kind": "org", "sort": "bogus"}))
                .unwrap()["error"]["code"],
            "validation"
        );

        let kinds = registry.kinds(DESKTOP_ACTOR, json!({})).unwrap();
        assert_eq!(kinds["company_id"], company.id);
        assert_eq!(kinds["kinds"].as_array().unwrap().len(), 20);
        assert_eq!(kinds["kinds"][0]["name"], "commitment");

        let bad = registry
            .propose("cli", json!({"operation": {"op": "explode"}}))
            .unwrap();
        assert_eq!(bad["error"]["code"], "invalid_operation");
        let gone = registry.commit("cli", json!({"proposal": "nope"})).unwrap();
        assert_eq!(gone["error"]["code"], "proposal_not_found");
        // Windows refuses to unlink a file another handle still holds, so the
        // registry closes its company connections before the state root goes.
        drop(registry);
        std::fs::remove_dir_all(state).unwrap();
    }
}
