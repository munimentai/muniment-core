//! The reader operations on the record registry. `reader.describe` reads one
//! source object's fields for the panel's import. `reader.run` pages an
//! approved mapping through propose and commit as the owner's reader
//! principal, keyed on the identity so a second run updates and never
//! duplicates, draws the edges the mapping names to records another object
//! landed, and writes the cursor into the mapping. `reader.queue` answers
//! the rows the last run could not place.

use super::record::{company_id, error_body, record_failure, text, OpenRecord, RecordRegistry};
use crate::reader::{
    cursor_value, open_reader, open_sidecar, source_label, Cursor, Delta, ReaderError,
    SIDECAR_SOURCES,
};
use crate::reader_mapping::{data_differs, row_plan, Mapping, RowPlan};
use muniment_core::attach::ProtocolError;
use muniment_core::record::{
    now_string, IdentityInput, LinkInput, Operation, RecordError, Reference,
};
use muniment_core::serde_json::{self, json, Map, Value};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Rows the run reads from the source per page.
/// How many rows a describe answers beside the fields, for the card the panel
/// shows before the mapping runs.
const DESCRIBE_ROWS: usize = 12;
const RUN_PAGE: usize = 200;
/// How long one `reader.run` call works before it answers with its offset,
/// under the desktop client's request timeout.
const RUN_BUDGET: Duration = Duration::from_millis(2_500);
/// The rows one mapping reads in total.
pub const RUN_ROW_CAP: usize = 100_000;
/// Unplaced rows the queue file keeps per mapping.
const QUEUE_KEEP: usize = 500;
/// Unplaced rows one run answer carries.
const QUEUE_ANSWER: usize = 100;
/// The service principal every reader commits as, acting for the owner.
pub const READER_PRINCIPAL_LABEL: &str = "reader";

fn reader_failure(error: ReaderError) -> Value {
    error_body(error.code(), error.to_string())
}

fn queue_path(directory: PathBuf, mapping_id: &str) -> PathBuf {
    directory.join(format!("resolve-{mapping_id}.json"))
}

fn read_queue(path: &PathBuf) -> Vec<Value> {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("rows")?.as_array().cloned())
        .unwrap_or_default()
}

fn write_queue(path: &PathBuf, mapping_id: &str, rows: &[Value]) -> Result<(), ProtocolError> {
    let body = json!({"mapping": mapping_id, "written_at": now_string(), "rows": rows});
    let text = serde_json::to_vec_pretty(&body)
        .map_err(|error| ProtocolError::persistence_failed_with_reason(error.to_string()))?;
    std::fs::write(path, text)
        .map_err(|error| ProtocolError::persistence_failed_with_reason(error.to_string()))
}

enum Landed {
    Created,
    Updated,
    Unchanged,
    Unplaced(String),
}

/// The identities beside the key that the entity does not carry yet. One that
/// names another entity is left for the report, never moved.
fn new_identities(entry: &OpenRecord, plan: &RowPlan) -> Vec<IdentityInput> {
    plan.identities
        .iter()
        .filter(|identity| {
            let reference = Reference::Identity {
                kind: identity.kind.clone(),
                value: identity.value.clone(),
            };
            matches!(entry.record.resolve(&reference), Ok(None))
        })
        .cloned()
        .collect()
}

/// The links whose other end is a record the graph holds. A target no object
/// landed yet draws nothing, and a later run draws it.
fn resolved_links(entry: &OpenRecord, plan: &RowPlan) -> Vec<LinkInput> {
    plan.links
        .iter()
        .filter_map(|link| {
            let reference = Reference::Identity {
                kind: link.target.kind.clone(),
                value: link.target.value.clone(),
            };
            let target = entry.record.resolve(&reference).ok().flatten()?;
            Some(LinkInput {
                relation: link.relation.clone(),
                target: Reference::Entity(target),
                props: Map::new(),
            })
        })
        .collect()
}

/// Draws the row's links from an entity the graph already holds, one commit
/// per edge that is not there yet. Answers how many it drew.
fn link_existing(
    entry: &mut OpenRecord,
    entity_id: &str,
    plan: &RowPlan,
    principal: &str,
) -> usize {
    let mut linked = 0;
    for link in resolved_links(entry, plan) {
        if link.target == Reference::Entity(entity_id.to_owned()) {
            continue;
        }
        let proposal = entry.record.propose(Operation::Link {
            src: Reference::Entity(entity_id.to_owned()),
            relation: link.relation,
            dst: link.target,
            props: Map::new(),
        });
        if proposal
            .and_then(|proposal| entry.record.commit(&proposal.id, principal))
            .is_ok()
        {
            linked += 1;
        }
    }
    linked
}

/// Lands one planned row on the record as the reader principal and draws its
/// links, counting the edges it drew into `linked`.
fn land(
    entry: &mut OpenRecord,
    mapping: &Mapping,
    plan: &RowPlan,
    principal: &str,
    linked: &mut usize,
) -> Landed {
    let mut existing = None;
    let operation = match &plan.identity {
        Some(identity) => {
            let reference = Reference::Identity {
                kind: identity.kind.clone(),
                value: identity.value.clone(),
            };
            match entry.record.resolve(&reference) {
                Err(error) => return Landed::Unplaced(error.to_string()),
                Ok(Some(entity_id)) => {
                    let current = match entry.record.entity(&entity_id) {
                        Ok(Some(entity)) => entity,
                        Ok(None) => {
                            return Landed::Unplaced(format!(
                                "{} names entity {entity_id}, which is gone",
                                reference.text()
                            ))
                        }
                        Err(error) => return Landed::Unplaced(error.to_string()),
                    };
                    if current.kind != mapping.kind {
                        return Landed::Unplaced(format!(
                            "{} already names a {}, not a {}",
                            reference.text(),
                            current.kind,
                            mapping.kind
                        ));
                    }
                    let identities = new_identities(entry, plan);
                    if !data_differs(&current.data, &plan.data) && identities.is_empty() {
                        *linked += link_existing(entry, &entity_id, plan, principal);
                        return Landed::Unchanged;
                    }
                    existing = Some(entity_id.clone());
                    Operation::Update {
                        entity: Reference::Entity(entity_id),
                        data: plan.data.clone(),
                        identities,
                    }
                }
                Ok(None) => Operation::Create {
                    kind: mapping.kind.clone(),
                    data: plan.data.clone(),
                    identities: std::iter::once(identity.clone())
                        .chain(plan.identities.iter().cloned())
                        .collect(),
                    links: resolved_links(entry, plan),
                },
            }
        }
        None => Operation::Create {
            kind: mapping.kind.clone(),
            data: plan.data.clone(),
            identities: plan.identities.clone(),
            links: resolved_links(entry, plan),
        },
    };
    let creating = matches!(operation, Operation::Create { .. });
    let created_links = match &operation {
        Operation::Create { links, .. } => links.len(),
        _ => 0,
    };
    let proposal = match entry.record.propose(operation) {
        Ok(proposal) => proposal,
        Err(error) => return Landed::Unplaced(failure_message(error)),
    };
    // A same-title warning is a duplicate only when the title is the key. A
    // row keyed on its source's id is its own record, and the repeated title
    // is the report's finding, not the import's refusal.
    let keyed_on_title = plan
        .identity
        .as_ref()
        .is_none_or(|identity| identity.kind == "name_key");
    if creating && keyed_on_title && !proposal.warnings.is_empty() {
        return Landed::Unplaced(proposal.warnings.join(" "));
    }
    match entry.record.commit(&proposal.id, principal) {
        Ok(_) if creating => {
            *linked += created_links;
            Landed::Created
        }
        Ok(_) => {
            if let Some(entity_id) = existing {
                *linked += link_existing(entry, &entity_id, plan, principal);
            }
            Landed::Updated
        }
        Err(error) => Landed::Unplaced(failure_message(error)),
    }
}

fn failure_message(error: RecordError) -> String {
    record_failure(error)["error"]["message"]
        .as_str()
        .unwrap_or("the record refused the row")
        .to_owned()
}

impl RecordRegistry {
    /// The objects one connected source holds, so the panel offers them.
    pub fn reader_objects(&self, _actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let source = text(&body, "source")?;
        Ok(
            match open_reader(&self.host, &source, "").and_then(|reader| reader.objects()) {
                Ok(objects) => {
                    json!({"source": source, "label": source_label(&source), "objects": objects})
                }
                Err(error) => reader_failure(error),
            },
        )
    }

    /// Stores one source's secret after one read proves it. A key the source
    /// refuses is not kept.
    pub fn reader_connect(&self, _actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let source = text(&body, "source")?;
        let secret = text(&body, "secret")?;
        if !SIDECAR_SOURCES.contains(&source.as_str()) {
            return Ok(reader_failure(ReaderError::UnknownSource(source)));
        }
        let objects = match open_sidecar(&self.host, &source, secret.clone())
            .and_then(|reader| reader.objects())
        {
            Ok(objects) => objects,
            Err(error) => return Ok(reader_failure(error)),
        };
        if let Err(reason) =
            crate::reader_secret::write(self.host.credentials.as_ref(), &source, &secret)
        {
            return Ok(error_body("secret_store", reason));
        }
        Ok(
            json!({"connected": {"source": source, "label": source_label(&source), "objects": objects}}),
        )
    }

    /// One source object's fields and samples, so the panel maps it, and its
    /// first rows, so the panel shows the first record as a card and pages
    /// through the rest before anything lands.
    pub fn reader_describe(&self, _actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let source = text(&body, "source")?;
        let object = text(&body, "object")?;
        let reader = match open_reader(&self.host, &source, &object) {
            Ok(reader) => reader,
            Err(error) => return Ok(reader_failure(error)),
        };
        Ok(match reader.describe(&object) {
            Ok(description) => {
                let rows = reader
                    .page(&object, None, DESCRIBE_ROWS)
                    .map(|page| page.rows)
                    .unwrap_or_default();
                json!({"description": description, "rows": rows})
            }
            Err(error) => reader_failure(error),
        })
    }

    /// Runs one approved mapping from `offset` for the run budget, lands each
    /// row, writes the cursor into the mapping, and answers where it stands.
    pub fn reader_run(&self, _actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let mapping_id = text(&body, "mapping")?;
        let start = body
            .get("offset")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .min(RUN_ROW_CAP as u64) as usize;
        let company = match self.resolve_company_id(company_id(&body)?.as_deref())? {
            Ok(id) => id,
            Err(body) => return Ok(body),
        };
        let queue_path = queue_path(self.root.company_directory(&company), &mapping_id);
        let outcome = self.with_record(Some(&company), |entry| {
            let entity = match entry.record.entity(&mapping_id) {
                Ok(Some(entity)) => entity,
                Ok(None) => {
                    return Ok(error_body(
                        "unknown_entity",
                        format!("No entity has id {mapping_id}."),
                    ))
                }
                Err(error) => return Ok(record_failure(error)),
            };
            let mapping = match Mapping::from_entity(&entity) {
                Ok(mapping) => mapping,
                Err(reason) => {
                    return Ok(error_body(
                        "mapping",
                        format!("The mapping cannot run: {reason}."),
                    ))
                }
            };
            if !mapping.approved {
                return Ok(error_body(
                    "mapping_unapproved",
                    "Commit the mapping with approved set before running it.",
                ));
            }
            let kind = match entry.record.kind(&mapping.kind) {
                Ok(Some(kind)) => kind,
                Ok(None) => {
                    return Ok(error_body(
                        "unknown_kind",
                        format!("kind {} is not in the catalogue", mapping.kind),
                    ))
                }
                Err(error) => return Ok(record_failure(error)),
            };
            let reader = match open_reader(&self.host, &mapping.source, &mapping.object) {
                Ok(reader) => reader,
                Err(error) => return Ok(reader_failure(error)),
            };
            let principal = entry
                .record
                .service_principal(READER_PRINCIPAL_LABEL, &entry.owner_principal_id)
                .map_err(|error| ProtocolError::persistence_failed_with_reason(error.to_string()))?
                .id;

            // Delta first: the run reports whether the file moved since the
            // cursor, and it lands every row either way, because the identity
            // keeps a repeat from duplicating.
            let changed = match &mapping.cursor {
                Some(previous) => match reader.delta(&mapping.object, previous) {
                    Ok(Delta::Unchanged) => false,
                    Ok(Delta::Changed { .. }) => true,
                    Ok(Delta::Gone) => {
                        return Ok(reader_failure(ReaderError::UnknownObject(
                            mapping.object.clone(),
                        )))
                    }
                    Err(error) => return Ok(reader_failure(error)),
                },
                None => true,
            };
            let began = Instant::now();
            let mut cursor = Cursor {
                offset: start,
                hash: String::new(),
                token: if start == 0 {
                    None
                } else {
                    mapping
                        .cursor
                        .as_ref()
                        .and_then(|cursor| cursor.token.clone())
                },
            };
            let mut counted;
            let mut total;
            let mut created = 0_usize;
            let mut updated = 0_usize;
            let mut unchanged = 0_usize;
            let mut linked = 0_usize;
            let mut unplaced: Vec<Value> = Vec::new();
            let mut done = false;
            let mut label = String::new();
            loop {
                let page = match reader.page(&mapping.object, Some(&cursor), RUN_PAGE) {
                    Ok(page) => page,
                    Err(error) => return Ok(reader_failure(error)),
                };
                if cursor.hash.is_empty() {
                    if let Ok(objects) = reader.objects() {
                        label = objects
                            .into_iter()
                            .find(|object| object.name == mapping.object)
                            .map(|object| object.label)
                            .unwrap_or_default();
                    }
                }
                cursor.hash = page.hash.clone();
                counted = page.counted;
                total = page.total.min(RUN_ROW_CAP);
                for (index, row) in page.rows.iter().enumerate() {
                    let number = page.offset + index + 1;
                    if number > RUN_ROW_CAP {
                        break;
                    }
                    let landed = match row_plan(&mapping, &kind, row) {
                        Ok(plan) => match land(entry, &mapping, &plan, &principal, &mut linked) {
                            Landed::Unplaced(reason) => Err((plan.title, reason)),
                            other => Ok(other),
                        },
                        Err(refusal) => Err((refusal.title, refusal.reason)),
                    };
                    match landed {
                        Ok(Landed::Created) => created += 1,
                        Ok(Landed::Updated) => updated += 1,
                        Ok(Landed::Unchanged) => unchanged += 1,
                        Ok(Landed::Unplaced(_)) => {}
                        Err((title, reason)) => {
                            let cells: Map<String, Value> = mapping
                                .fields
                                .keys()
                                .chain(mapping.identity.iter().map(|spec| &spec.column))
                                .filter_map(|column| {
                                    row.get(column).map(|cell| {
                                        (
                                            column.clone(),
                                            Value::String(cell.chars().take(200).collect()),
                                        )
                                    })
                                })
                                .collect();
                            unplaced.push(json!({
                                "row": number,
                                "title": title,
                                "reason": reason,
                                "cells": Value::Object(cells),
                            }));
                        }
                    }
                }
                cursor.offset = (page.offset + page.rows.len()).min(total);
                match page.next {
                    Some(next) if cursor.offset < RUN_ROW_CAP => {
                        cursor.offset = next.offset;
                        cursor.token = next.token;
                    }
                    _ => {
                        cursor.token = None;
                        done = true;
                        break;
                    }
                }
                if began.elapsed() >= RUN_BUDGET {
                    break;
                }
            }

            let ran_at = now_string();
            let mut data = Map::new();
            data.insert(
                "cursors".to_owned(),
                cursor_value(&cursor, total, &ran_at, done),
            );
            let cursor_written = entry
                .record
                .propose(Operation::Update {
                    entity: Reference::Entity(mapping_id.clone()),
                    data,
                    identities: Vec::new(),
                })
                .and_then(|proposal| entry.record.commit(&proposal.id, &principal))
                .map(|_| ())
                .map_err(failure_message);

            let kept = if start == 0 {
                unplaced.clone()
            } else {
                let mut rows = read_queue(&queue_path);
                rows.extend(unplaced.iter().cloned());
                rows
            };
            let kept: Vec<Value> = kept.into_iter().take(QUEUE_KEEP).collect();
            write_queue(&queue_path, &mapping_id, &kept)?;

            let mut run = json!({
                "mapping": mapping_id,
                "source": mapping.source,
                "object": mapping.object,
                "label": label,
                "kind": mapping.kind,
                "identity": mapping.identity.as_ref().map(|spec| spec.text()),
                "offset": start,
                "next_offset": cursor.offset,
                "done": done,
                "total": total,
                "counted": counted,
                "changed": changed,
                "hash": cursor.hash,
                "created": created,
                "updated": updated,
                "unchanged": unchanged,
                "linked": linked,
                "unplaced": unplaced.len(),
                "queued": kept.len(),
                "ran_at": ran_at,
                "queue": unplaced.iter().take(QUEUE_ANSWER).cloned().collect::<Vec<_>>(),
            });
            if let Err(reason) = cursor_written {
                run["cursor_error"] = Value::String(reason);
            }
            Ok(json!({"run": run}))
        })?;
        Ok(outcome.unwrap_or_else(|body| body))
    }

    /// The rows a mapping's last run could not place, with their reasons.
    pub fn reader_queue(&self, _actor: &str, body: Value) -> Result<Value, ProtocolError> {
        let mapping_id = text(&body, "mapping")?;
        let company = match self.resolve_company_id(company_id(&body)?.as_deref())? {
            Ok(id) => id,
            Err(body) => return Ok(body),
        };
        let path = queue_path(self.root.company_directory(&company), &mapping_id);
        let rows = read_queue(&path);
        Ok(json!({"queue": {"mapping": mapping_id, "rows": rows}}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use muniment_core::record::{CompaniesRoot, DESKTOP_ACTOR};

    fn state(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("muniment-reader-service-{label}-{nanos}"));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn propose_and_commit(registry: &RecordRegistry, operation: Value) -> Value {
        let proposed = registry
            .propose(DESKTOP_ACTOR, json!({"operation": operation}))
            .unwrap();
        assert!(proposed["proposal"]["id"].is_string(), "{proposed}");
        registry
            .commit(
                DESKTOP_ACTOR,
                json!({"proposal": proposed["proposal"]["id"]}),
            )
            .unwrap()
    }

    #[test]
    fn describes_a_file_and_lands_its_rows_once() {
        let state = state("run");
        let company = CompaniesRoot::new(&state).create("Northwind").unwrap();
        let registry = RecordRegistry::new(&state);
        let csv = state.join("customers.csv");
        std::fs::write(
            &csv,
            "Company,Website,Employees,Since\nNorthwind,northwind.example,120,2020-01-15\nContoso,https://contoso.example,40,2021-06-01\nNo Site,,7,2019-12-31\nGmail Co,gmail.com,3,2022-02-02\nBad Count,fabrikam.example,many,2019-12-31\n",
        )
        .unwrap();
        let object = csv.to_string_lossy().into_owned();

        let described = registry
            .reader_describe(DESKTOP_ACTOR, json!({"source": "csv", "object": object}))
            .unwrap();
        assert_eq!(described["description"]["rows"], 5);
        assert_eq!(described["description"]["fields"][1]["guess"], "domain");
        assert_eq!(
            registry
                .reader_describe(
                    DESKTOP_ACTOR,
                    json!({"source": "csv", "object": "/nowhere.csv"})
                )
                .unwrap()["error"]["code"],
            "unknown_object"
        );
        assert_eq!(
            registry
                .reader_describe(
                    DESKTOP_ACTOR,
                    json!({"source": "abacus", "object": "customers"})
                )
                .unwrap()["error"]["code"],
            "unknown_source"
        );
        std::env::set_var("MUNIMENT_READER_SECRET_STRIPE", "");
        assert_eq!(
            registry
                .reader_describe(
                    DESKTOP_ACTOR,
                    json!({"source": "stripe", "object": "customers"})
                )
                .unwrap()["error"]["code"],
            "not_connected"
        );
        assert_eq!(
            registry
                .reader_objects(DESKTOP_ACTOR, json!({"source": "stripe"}))
                .unwrap()["error"]["code"],
            "not_connected"
        );
        assert_eq!(
            registry
                .reader_connect(DESKTOP_ACTOR, json!({"source": "abacus", "secret": "x"}))
                .unwrap()["error"]["code"],
            "unknown_source"
        );
        std::env::remove_var("MUNIMENT_READER_SECRET_STRIPE");

        let unapproved = propose_and_commit(
            &registry,
            json!({"op": "create", "kind": "mapping", "data": {
                "source": "csv", "object": object, "kind": "org",
                "fields": {"Company": "name", "Website": "domain", "Employees": "x_missing"},
                "identity": "domain:Website"
            }}),
        );
        let unapproved_id = unapproved["result"]["entity_ids"][0].as_str().unwrap();
        assert_eq!(
            registry
                .reader_run(DESKTOP_ACTOR, json!({"mapping": unapproved_id}))
                .unwrap()["error"]["code"],
            "mapping_unapproved"
        );

        let committed = propose_and_commit(
            &registry,
            json!({"op": "create", "kind": "mapping", "data": {
                "source": "csv", "object": object, "kind": "org",
                "fields": {"Company": "name", "Website": "domain", "Employees": "x_headcount"},
                "identity": "domain:Website", "approved": true
            }}),
        );
        let mapping_id = committed["result"]["entity_ids"][0]
            .as_str()
            .unwrap()
            .to_owned();
        // x_headcount is not a property yet, so every row is unplaced.
        let run = registry
            .reader_run(DESKTOP_ACTOR, json!({"mapping": mapping_id}))
            .unwrap();
        assert_eq!(run["run"]["unplaced"], 5, "{run}");
        assert_eq!(run["run"]["created"], 0);
        assert!(run["run"]["done"].as_bool().unwrap());
        assert!(run["run"]["changed"].as_bool().unwrap());
        assert!(run["run"]["queue"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("x_headcount is not a property of org"));

        registry
            .with_record(Some(&company.id), |entry| {
                entry
                    .record
                    .extend_kind("org", "x_headcount", json!({"type": "integer"}))
                    .unwrap();
                Ok(())
            })
            .unwrap()
            .unwrap();
        let run = registry
            .reader_run(DESKTOP_ACTOR, json!({"mapping": mapping_id}))
            .unwrap()["run"]
            .clone();
        assert_eq!(run["created"], 2, "{run}");
        assert_eq!(run["updated"], 0);
        assert_eq!(run["unplaced"], 3);
        assert_eq!(run["total"], 5);
        // The first run wrote the cursor, so the file reads as unchanged.
        assert!(!run["changed"].as_bool().unwrap());
        assert_eq!(run["next_offset"], 5);
        let reasons: Vec<&str> = run["queue"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["reason"].as_str().unwrap())
            .collect();
        assert!(reasons[0].contains("no identity"), "{reasons:?}");
        assert!(reasons[1].contains("mail provider"), "{reasons:?}");
        assert_eq!(reasons[2], "Employees: many is not a whole number");
        assert_eq!(run["queue"][0]["title"], "No Site");
        assert_eq!(run["queue"][2]["title"], "Bad Count");
        assert_eq!(run["queue"][2]["cells"]["Website"], "fabrikam.example");

        let queue = registry
            .reader_queue(DESKTOP_ACTOR, json!({"mapping": mapping_id}))
            .unwrap();
        assert_eq!(queue["queue"]["rows"].as_array().unwrap().len(), 3);

        let page = registry
            .query(DESKTOP_ACTOR, json!({"kind": "org", "sort": "title"}))
            .unwrap();
        assert_eq!(page["page"]["total"], 2);
        assert_eq!(page["page"]["rows"][0]["title"], "Contoso");
        assert_eq!(page["page"]["rows"][1]["data"]["x_headcount"], 120);
        let detail = registry
            .entity(
                DESKTOP_ACTOR,
                json!({"entity": page["page"]["rows"][1]["id"]}),
            )
            .unwrap();
        assert_eq!(
            detail["entity"]["identities"][0]["value"],
            "northwind.example"
        );
        let actor = detail["entity"]["events"][0]["actor_id"].as_str().unwrap();
        assert_ne!(actor, company.owner_principal_id);
        assert_eq!(
            detail["entity"]["events"][0]["on_behalf_of"],
            company.owner_principal_id
        );

        let mapping = registry
            .entity(DESKTOP_ACTOR, json!({"entity": mapping_id}))
            .unwrap();
        assert_eq!(mapping["entity"]["entity"]["data"]["cursors"]["offset"], 5);
        assert_eq!(
            mapping["entity"]["entity"]["data"]["cursors"]["complete"],
            true
        );
        assert!(mapping["entity"]["entity"]["data"]["cursors"]["hash"].is_string());

        // A second run over the same file changes nothing.
        let again = registry
            .reader_run(DESKTOP_ACTOR, json!({"mapping": mapping_id}))
            .unwrap()["run"]
            .clone();
        assert_eq!(again["created"], 0);
        assert_eq!(again["unchanged"], 2);
        assert!(!again["changed"].as_bool().unwrap());

        // An edited cell updates the row it keys.
        std::fs::write(
            &csv,
            "Company,Website,Employees,Since\nNorthwind Traders,northwind.example,130,2020-01-15\n",
        )
        .unwrap();
        let third = registry
            .reader_run(DESKTOP_ACTOR, json!({"mapping": mapping_id}))
            .unwrap()["run"]
            .clone();
        assert_eq!(third["updated"], 1, "{third}");
        assert!(third["changed"].as_bool().unwrap());
        let page = registry
            .query(DESKTOP_ACTOR, json!({"kind": "org", "search": "Traders"}))
            .unwrap();
        assert_eq!(page["page"]["total"], 1);
        assert_eq!(page["page"]["rows"][0]["data"]["x_headcount"], 130);
        assert_eq!(
            registry
                .reader_queue(DESKTOP_ACTOR, json!({"mapping": mapping_id}))
                .unwrap()["queue"]["rows"]
                .as_array()
                .unwrap()
                .len(),
            0
        );

        assert_eq!(
            registry
                .reader_run(DESKTOP_ACTOR, json!({"mapping": "nope"}))
                .unwrap()["error"]["code"],
            "unknown_entity"
        );
        let org_id = page["page"]["rows"][0]["id"].as_str().unwrap();
        assert_eq!(
            registry
                .reader_run(DESKTOP_ACTOR, json!({"mapping": org_id}))
                .unwrap()["error"]["code"],
            "mapping"
        );
        // Windows refuses to unlink a file another handle still holds, so the
        // registry closes its company connections before the state root goes.
        drop(registry);
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn links_rows_to_records_another_object_landed_and_keeps_an_email_beside_the_key() {
        let state = state("links");
        CompaniesRoot::new(&state).create("Northwind").unwrap();
        let registry = RecordRegistry::new(&state);
        let customers = state.join("customers.csv");
        std::fs::write(
            &customers,
            "id,name,email\ncus_1,Northwind,ann@northwind.example\ncus_2,Contoso,\n",
        )
        .unwrap();
        let people = state.join("people.csv");
        std::fs::write(&people, "id,name,email\nper_1,Ann,ann@northwind.example\n").unwrap();
        let subscriptions = state.join("subscriptions.csv");
        std::fs::write(
            &subscriptions,
            "id,customer,plan,state\nsub_1,cus_1,Team,active\nsub_2,cus_9,Solo,trial\n",
        )
        .unwrap();
        let run = |object: &std::path::Path, data: Value| {
            let mut data = data;
            data["source"] = json!("csv");
            data["object"] = json!(object.to_string_lossy());
            data["approved"] = json!(true);
            let committed = propose_and_commit(
                &registry,
                json!({"op": "create", "kind": "mapping", "data": data}),
            );
            let mapping_id = committed["result"]["entity_ids"][0].as_str().unwrap();
            registry
                .reader_run(DESKTOP_ACTOR, json!({"mapping": mapping_id}))
                .unwrap()["run"]
                .clone()
        };

        // The subscriptions land first, so their customers are not there to link.
        let first = run(
            &subscriptions,
            json!({"kind": "subscription", "fields": {"plan": "plan", "state": "state"},
                   "identity": "external:csv:subscriptions:id",
                   "edges": [{"relation": "billed_to", "identity": "external:csv:customers:customer"}]}),
        );
        assert_eq!(first["created"], 2, "{first}");
        assert_eq!(first["linked"], 0);

        let orgs = run(
            &customers,
            json!({"kind": "org", "fields": {"name": "name"}, "identity": "external:csv:customers:id"}),
        );
        assert_eq!(orgs["created"], 2, "{orgs}");

        // A second run over unchanged rows draws the edge the first could not.
        let second = run(
            &subscriptions,
            json!({"kind": "subscription", "fields": {"plan": "plan", "state": "state"},
                   "identity": "external:csv:subscriptions:id",
                   "edges": [{"relation": "billed_to", "identity": "external:csv:customers:customer"}]}),
        );
        assert_eq!(second["unchanged"], 2, "{second}");
        assert_eq!(second["linked"], 1);
        let team = registry
            .query(
                DESKTOP_ACTOR,
                json!({"kind": "subscription", "search": "Team"}),
            )
            .unwrap();
        let team = registry
            .entity(
                DESKTOP_ACTOR,
                json!({"entity": team["page"]["rows"][0]["id"]}),
            )
            .unwrap();
        let edges = team["entity"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1, "{team}");
        assert_eq!(edges[0]["relation"], "billed_to");
        assert_eq!(edges[0]["dst_title"], "Northwind");
        // The edge is drawn once.
        let third = run(
            &subscriptions,
            json!({"kind": "subscription", "fields": {"plan": "plan", "state": "state"},
                   "identity": "external:csv:subscriptions:id",
                   "edges": [{"relation": "billed_to", "identity": "external:csv:customers:customer"}]}),
        );
        assert_eq!(third["linked"], 0, "{third}");

        // A person keyed on the source id keeps the email as an identity.
        let persons = run(
            &people,
            json!({"kind": "person", "fields": {"name": "full_name", "email": "email"},
                   "identity": "external:csv:people:id"}),
        );
        assert_eq!(persons["created"], 1, "{persons}");
        let ann = registry
            .query(DESKTOP_ACTOR, json!({"kind": "person"}))
            .unwrap();
        let ann = registry
            .entity(
                DESKTOP_ACTOR,
                json!({"entity": ann["page"]["rows"][0]["id"]}),
            )
            .unwrap();
        let identities: Vec<(&str, &str)> = ann["entity"]["identities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|identity| {
                (
                    identity["kind"].as_str().unwrap(),
                    identity["value"].as_str().unwrap(),
                )
            })
            .collect();
        assert!(
            identities.contains(&("email", "ann@northwind.example")),
            "{identities:?}"
        );
        assert!(
            identities.contains(&("external", "csv:people:per_1")),
            "{identities:?}"
        );
        drop(registry);
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn keys_on_the_title_without_an_identity_column_and_queues_a_collision() {
        let state = state("title");
        CompaniesRoot::new(&state).create("Northwind").unwrap();
        let registry = RecordRegistry::new(&state);
        propose_and_commit(
            &registry,
            json!({"op": "create", "kind": "org", "data": {"name": "Contoso Ltd"}}),
        );
        let csv = state.join("orgs.csv");
        std::fs::write(
            &csv,
            "Name;Industry\nNorthwind;Shipping\nContoso, Ltd.;Software\nNorthwind;Logistics\n",
        )
        .unwrap();
        let committed = propose_and_commit(
            &registry,
            json!({"op": "create", "kind": "mapping", "data": {
                "source": "csv", "object": csv.to_string_lossy(), "kind": "org",
                "fields": {"Name": "name", "Industry": "industry"}, "approved": true
            }}),
        );
        let mapping_id = committed["result"]["entity_ids"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let run = registry
            .reader_run(DESKTOP_ACTOR, json!({"mapping": mapping_id}))
            .unwrap()["run"]
            .clone();
        assert_eq!(run["created"], 1, "{run}");
        assert_eq!(run["updated"], 1);
        assert_eq!(run["unplaced"], 1);
        assert!(run["queue"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("already exists"));
        let page = registry
            .query(DESKTOP_ACTOR, json!({"kind": "org", "search": "Northwind"}))
            .unwrap();
        assert_eq!(page["page"]["total"], 1);
        assert_eq!(page["page"]["rows"][0]["data"]["industry"], "Logistics");
        // Windows refuses to unlink a file another handle still holds, so the
        // registry closes its company connections before the state root goes.
        drop(registry);
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn lands_rows_that_share_a_title_under_different_source_ids() {
        let state = state("shared-title");
        CompaniesRoot::new(&state).create("Northwind").unwrap();
        let registry = RecordRegistry::new(&state);
        let csv = state.join("orgs.csv");
        std::fs::write(
            &csv,
            "Name;Website\nAcme;acme.example\nAcme;acme.co.example\n",
        )
        .unwrap();
        let committed = propose_and_commit(
            &registry,
            json!({"op": "create", "kind": "mapping", "data": {
                "source": "csv", "object": csv.to_string_lossy(), "kind": "org",
                "fields": {"Name": "name", "Website": "domain"},
                "identity": "domain:Website", "approved": true
            }}),
        );
        let mapping_id = committed["result"]["entity_ids"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let run = registry
            .reader_run(DESKTOP_ACTOR, json!({"mapping": mapping_id}))
            .unwrap()["run"]
            .clone();
        assert_eq!(run["created"], 2, "{run}");
        assert_eq!(run["unplaced"], 0, "{run}");
        let page = registry
            .query(DESKTOP_ACTOR, json!({"kind": "org", "search": "Acme"}))
            .unwrap();
        assert_eq!(page["page"]["total"], 2);
        // Windows refuses to unlink a file another handle still holds, so the
        // registry closes its company connections before the state root goes.
        drop(registry);
        std::fs::remove_dir_all(state).unwrap();
    }
}
