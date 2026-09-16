//! The write path. propose validates against the kind, resolves every
//! reference, and returns a diff with a proposal id. It writes nothing. commit
//! applies that diff in one transaction and appends one event. A repeated
//! commit on a spent proposal returns the first result and writes nothing.

use super::catalogue::relation;
use super::identity::{name_key, normalize_identity, IdentityKind};
use super::validate::validate;
use super::{
    now_string, render_template, CompanyRecord, KindRow, PrincipalType, RecordError,
    PROPOSAL_TTL_SECONDS,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Something that names one entity: `entity:<id>` or `<identity kind>:<value>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reference {
    Entity(String),
    Identity { kind: String, value: String },
}

impl Reference {
    pub fn parse(text: &str) -> Option<Self> {
        let (kind, value) = text.split_once(':')?;
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        Some(match kind.trim() {
            "entity" => Self::Entity(value.to_owned()),
            kind => Self::Identity {
                kind: kind.to_owned(),
                value: value.to_owned(),
            },
        })
    }

    pub fn text(&self) -> String {
        match self {
            Self::Entity(id) => format!("entity:{id}"),
            Self::Identity { kind, value } => format!("{kind}:{value}"),
        }
    }
}

impl Serialize for Reference {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text())
    }
}

impl<'de> Deserialize<'de> for Reference {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "{text} is not a reference such as entity:<id> or email:<address>"
            ))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityInput {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LinkInput {
    pub relation: String,
    pub target: Reference,
    #[serde(default)]
    pub props: Map<String, Value>,
}

/// What propose takes: a create, an update, a link or a merge.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Operation {
    Create {
        kind: String,
        #[serde(default)]
        data: Map<String, Value>,
        #[serde(default)]
        identities: Vec<IdentityInput>,
        #[serde(default)]
        links: Vec<LinkInput>,
    },
    Update {
        entity: Reference,
        #[serde(default)]
        data: Map<String, Value>,
        #[serde(default)]
        identities: Vec<IdentityInput>,
    },
    Link {
        src: Reference,
        relation: String,
        dst: Reference,
        #[serde(default)]
        props: Map<String, Value>,
    },
    Merge {
        loser: Reference,
        survivor: Reference,
    },
    Delete {
        entity: Reference,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntitySnapshot {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub body_text: Option<String>,
    pub state: Option<String>,
    pub data: Value,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalIdentity {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProposalLink {
    pub id: String,
    pub src_id: String,
    pub relation: String,
    pub dst_id: String,
    pub props: Value,
}

/// The change commit applies, fully resolved. Ids are allotted at propose
/// time so the diff names what will exist.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Diff {
    Create {
        after: EntitySnapshot,
        identities: Vec<ProposalIdentity>,
        links: Vec<ProposalLink>,
    },
    Update {
        before: EntitySnapshot,
        after: EntitySnapshot,
        identities: Vec<ProposalIdentity>,
    },
    Link {
        link: ProposalLink,
        src_title: String,
        dst_title: String,
    },
    Merge {
        loser: EntitySnapshot,
        survivor: EntitySnapshot,
        link: ProposalLink,
        identities_moved: usize,
    },
    /// A soft delete: the row keeps its data and history and leaves every
    /// live read, and a later merge or link cannot name it.
    Delete { before: EntitySnapshot },
}

impl Diff {
    fn verb(&self) -> &'static str {
        match self {
            Self::Create { .. } => "created",
            Self::Update { .. } => "updated",
            Self::Link { .. } => "linked",
            Self::Merge { .. } => "merged",
            Self::Delete { .. } => "deleted",
        }
    }

    /// The entity the event names first.
    pub fn entity_id(&self) -> &str {
        match self {
            Self::Create { after, .. } | Self::Update { after, .. } => &after.id,
            Self::Link { link, .. } => &link.src_id,
            Self::Merge { survivor, .. } => &survivor.id,
            Self::Delete { before } => &before.id,
        }
    }

    fn edge_id(&self) -> Option<&str> {
        match self {
            Self::Link { link, .. } | Self::Merge { link, .. } => Some(&link.id),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub expires_at: String,
    pub resolved: BTreeMap<String, String>,
    pub warnings: Vec<String>,
    pub diff: Diff,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommitResult {
    pub proposal: String,
    pub event_id: String,
    pub event_seq: i64,
    pub entity_ids: Vec<String>,
    pub edge_id: Option<String>,
    pub actor: String,
    pub on_behalf_of: Option<String>,
    pub committed_at: String,
}

pub(super) struct StoredProposal {
    proposal: Proposal,
    expires: chrono::DateTime<chrono::Utc>,
    committed: Option<CommitResult>,
}

struct ResolvedIdentity {
    kind: IdentityKind,
    value: String,
}

impl CompanyRecord {
    /// Validates, resolves and returns the diff. Nothing is written.
    pub fn propose(&mut self, operation: Operation) -> Result<Proposal, RecordError> {
        self.sweep_proposals();
        let mut resolved = BTreeMap::new();
        let mut warnings = Vec::new();
        let diff = match operation {
            Operation::Create {
                kind,
                data,
                identities,
                links,
            } => {
                self.propose_create(kind, data, identities, links, &mut resolved, &mut warnings)?
            }
            Operation::Update {
                entity,
                data,
                identities,
            } => self.propose_update(entity, data, identities, &mut resolved)?,
            Operation::Link {
                src,
                relation,
                dst,
                props,
            } => self.propose_link(src, relation, dst, props, &mut resolved)?,
            Operation::Merge { loser, survivor } => {
                self.propose_merge(loser, survivor, &mut resolved)?
            }
            Operation::Delete { entity } => {
                let id = self.resolve_required(&entity, &mut resolved)?;
                Diff::Delete {
                    before: existing_snapshot(self.require_entity(&id)?),
                }
            }
        };
        let expires = chrono::Utc::now() + chrono::Duration::seconds(PROPOSAL_TTL_SECONDS);
        let proposal = Proposal {
            id: uuid::Uuid::now_v7().to_string(),
            expires_at: expires.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            resolved,
            warnings,
            diff,
        };
        self.proposals.insert(
            proposal.id.clone(),
            StoredProposal {
                proposal: proposal.clone(),
                expires,
                committed: None,
            },
        );
        Ok(proposal)
    }

    /// Applies one proposal in one transaction and appends one event. A spent
    /// proposal returns its first result.
    pub fn commit(&mut self, proposal_id: &str, actor: &str) -> Result<CommitResult, RecordError> {
        let stored = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| RecordError::ProposalNotFound(proposal_id.to_owned()))?;
        if let Some(result) = &stored.committed {
            return Ok(result.clone());
        }
        if stored.expires < chrono::Utc::now() {
            self.proposals.remove(proposal_id);
            return Err(RecordError::ProposalExpired(proposal_id.to_owned()));
        }
        let diff = stored.proposal.diff.clone();
        let principal = self
            .principal(actor)?
            .ok_or_else(|| RecordError::PrincipalNotFound(actor.to_owned()))?;
        if principal.disabled_at.is_some() {
            return Err(RecordError::PrincipalDisabled(actor.to_owned()));
        }
        let on_behalf_of = match principal.principal_type {
            PrincipalType::Human => None,
            _ => principal.on_behalf_of.clone(),
        };
        let now = now_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (before, entity_ids) = apply(&transaction, &diff, &now)?;
        let seq: i64 =
            transaction.query_row("select coalesce(max(seq), 0) + 1 from event", [], |row| {
                row.get(0)
            })?;
        let event_id = uuid::Uuid::now_v7().to_string();
        transaction.execute(
            "insert into event (id, seq, at, actor_id, on_behalf_of, verb, entity_id, edge_id, before, after, source)
             values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event_id,
                seq,
                now,
                actor,
                on_behalf_of,
                diff.verb(),
                diff.entity_id(),
                diff.edge_id(),
                before.map(|value| serde_json::to_string(&value)).transpose()?,
                serde_json::to_string(&diff)?,
                format!("proposal:{proposal_id}"),
            ],
        )?;
        transaction.commit()?;
        let result = CommitResult {
            proposal: proposal_id.to_owned(),
            event_id,
            event_seq: seq,
            entity_ids,
            edge_id: diff.edge_id().map(str::to_owned),
            actor: actor.to_owned(),
            on_behalf_of,
            committed_at: now,
        };
        if let Some(stored) = self.proposals.get_mut(proposal_id) {
            stored.committed = Some(result.clone());
        }
        Ok(result)
    }

    /// The proposals that still wait for a commit.
    pub fn pending_proposals(&self) -> Vec<&Proposal> {
        self.proposals
            .values()
            .filter(|stored| stored.committed.is_none())
            .map(|stored| &stored.proposal)
            .collect()
    }

    fn sweep_proposals(&mut self) {
        let now = chrono::Utc::now();
        self.proposals.retain(|_, stored| stored.expires >= now);
    }

    fn propose_create(
        &self,
        kind: String,
        data: Map<String, Value>,
        identities: Vec<IdentityInput>,
        links: Vec<LinkInput>,
        resolved: &mut BTreeMap<String, String>,
        warnings: &mut Vec<String>,
    ) -> Result<Diff, RecordError> {
        let kind_row = self.require_kind(&kind)?;
        validate(&kind, &kind_row.schema, kind_row.extension.as_ref(), &data)?;
        let id = uuid::Uuid::now_v7().to_string();
        let now = now_string();
        let after = snapshot(&kind_row, id.clone(), Value::Object(data), now);
        let identities = self.resolve_identities(identities, None)?;
        let mut proposal_links = Vec::new();
        for link in links {
            let target = self.resolve_required(&link.target, resolved)?;
            let target_kind = self.require_entity(&target)?.kind;
            check_relation(&link.relation, &kind, &target_kind)?;
            proposal_links.push(ProposalLink {
                id: uuid::Uuid::now_v7().to_string(),
                src_id: id.clone(),
                relation: link.relation,
                dst_id: target,
                props: Value::Object(link.props),
            });
        }
        for near in self.same_title(&kind, &after.title, None)? {
            warnings.push(format!(
                "A {kind} titled {} already exists, entity:{}",
                near.1, near.0
            ));
        }
        Ok(Diff::Create {
            after,
            identities: identities
                .into_iter()
                .map(|identity| ProposalIdentity {
                    kind: identity.kind.as_str().to_owned(),
                    value: identity.value,
                })
                .collect(),
            links: proposal_links,
        })
    }

    fn propose_update(
        &self,
        entity: Reference,
        data: Map<String, Value>,
        identities: Vec<IdentityInput>,
        resolved: &mut BTreeMap<String, String>,
    ) -> Result<Diff, RecordError> {
        let id = self.resolve_required(&entity, resolved)?;
        let current = self.require_entity(&id)?;
        let kind_row = self.require_kind(&current.kind)?;
        let mut merged = current.data.as_object().cloned().unwrap_or_default();
        for (field, value) in data {
            if value.is_null() {
                merged.remove(&field);
            } else {
                merged.insert(field, value);
            }
        }
        validate(
            &current.kind,
            &kind_row.schema,
            kind_row.extension.as_ref(),
            &merged,
        )?;
        let before = EntitySnapshot {
            id: current.id.clone(),
            kind: current.kind.clone(),
            title: current.title.clone(),
            body_text: current.body_text.clone(),
            state: current.state.clone(),
            data: current.data.clone(),
            updated_at: current.updated_at.clone(),
        };
        let after = snapshot(&kind_row, id.clone(), Value::Object(merged), now_string());
        let identities = self.resolve_identities(identities, Some(&id))?;
        Ok(Diff::Update {
            before,
            after,
            identities: identities
                .into_iter()
                .map(|identity| ProposalIdentity {
                    kind: identity.kind.as_str().to_owned(),
                    value: identity.value,
                })
                .collect(),
        })
    }

    fn propose_link(
        &self,
        src: Reference,
        relation_name: String,
        dst: Reference,
        props: Map<String, Value>,
        resolved: &mut BTreeMap<String, String>,
    ) -> Result<Diff, RecordError> {
        let src_id = self.resolve_required(&src, resolved)?;
        let dst_id = self.resolve_required(&dst, resolved)?;
        if src_id == dst_id {
            return Err(RecordError::SameEntity);
        }
        let src_entity = self.require_entity(&src_id)?;
        let dst_entity = self.require_entity(&dst_id)?;
        check_relation(&relation_name, &src_entity.kind, &dst_entity.kind)?;
        let open: Option<String> = self
            .connection
            .query_row(
                "select id from edge where src_id = ?1 and relation = ?2 and dst_id = ?3 and valid_to is null",
                params![src_id, relation_name, dst_id],
                |row| row.get(0),
            )
            .optional()?;
        if open.is_some() {
            return Err(RecordError::AlreadyLinked(relation_name));
        }
        Ok(Diff::Link {
            link: ProposalLink {
                id: uuid::Uuid::now_v7().to_string(),
                src_id,
                relation: relation_name,
                dst_id,
                props: Value::Object(props),
            },
            src_title: src_entity.title,
            dst_title: dst_entity.title,
        })
    }

    fn propose_merge(
        &self,
        loser: Reference,
        survivor: Reference,
        resolved: &mut BTreeMap<String, String>,
    ) -> Result<Diff, RecordError> {
        let loser_id = self.resolve_required(&loser, resolved)?;
        let survivor_id = self.resolve_required(&survivor, resolved)?;
        if loser_id == survivor_id {
            return Err(RecordError::SameEntity);
        }
        let loser = self.require_entity(&loser_id)?;
        let survivor = self.require_entity(&survivor_id)?;
        if loser.kind != survivor.kind {
            return Err(RecordError::KindMismatch {
                loser: loser.kind,
                survivor: survivor.kind,
            });
        }
        let identities_moved: i64 = self.connection.query_row(
            "select count(*) from identity where entity_id = ?1",
            params![loser_id],
            |row| row.get(0),
        )?;
        Ok(Diff::Merge {
            link: ProposalLink {
                id: uuid::Uuid::now_v7().to_string(),
                src_id: loser_id.clone(),
                relation: "superseded_by".to_owned(),
                dst_id: survivor_id.clone(),
                props: Value::Object(Map::new()),
            },
            loser: existing_snapshot(loser),
            survivor: existing_snapshot(survivor),
            identities_moved: identities_moved as usize,
        })
    }

    fn resolve_required(
        &self,
        reference: &Reference,
        resolved: &mut BTreeMap<String, String>,
    ) -> Result<String, RecordError> {
        let id = self
            .resolve(reference)?
            .ok_or_else(|| RecordError::Unresolved(reference.text()))?;
        resolved.insert(reference.text(), id.clone());
        Ok(id)
    }

    fn require_entity(&self, id: &str) -> Result<super::EntityRow, RecordError> {
        let entity = self
            .entity(id)?
            .ok_or_else(|| RecordError::Unresolved(format!("entity:{id}")))?;
        if entity.deleted_at.is_some() {
            return Err(RecordError::EntityDeleted(id.to_owned()));
        }
        Ok(entity)
    }

    /// Normalizes each identity and refuses one that names another entity.
    fn resolve_identities(
        &self,
        identities: Vec<IdentityInput>,
        owner: Option<&str>,
    ) -> Result<Vec<ResolvedIdentity>, RecordError> {
        let mut resolved = Vec::new();
        for identity in identities {
            let kind = IdentityKind::parse(&identity.kind)
                .ok_or_else(|| super::IdentityError::UnknownKind(identity.kind.clone()))?;
            let value = normalize_identity(kind, &identity.value)?;
            let bound: Option<String> = self
                .connection
                .query_row(
                    "select entity_id from identity where kind = ?1 and value = ?2",
                    params![kind.as_str(), value],
                    |row| row.get(0),
                )
                .optional()?;
            match bound {
                Some(entity_id) if Some(entity_id.as_str()) != owner => {
                    return Err(RecordError::IdentityBound {
                        kind: kind.as_str().to_owned(),
                        value,
                        entity_id,
                    });
                }
                Some(_) => {}
                None => resolved.push(ResolvedIdentity { kind, value }),
            }
        }
        Ok(resolved)
    }

    fn same_title(
        &self,
        kind: &str,
        title: &str,
        except: Option<&str>,
    ) -> Result<Vec<(String, String)>, RecordError> {
        let key = name_key(title);
        if key.is_empty() {
            return Ok(Vec::new());
        }
        let mut statement = self.connection.prepare(
            "select id, title from entity where kind = ?1 and deleted_at is null order by updated_at desc limit 200",
        )?;
        let rows = statement
            .query_map(params![kind], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter(|(id, candidate)| except != Some(id.as_str()) && name_key(candidate) == key)
            .collect())
    }
}

fn check_relation(relation_name: &str, src_kind: &str, dst_kind: &str) -> Result<(), RecordError> {
    let relation = relation(relation_name)
        .ok_or_else(|| RecordError::UnknownRelation(relation_name.to_owned()))?;
    if !relation.accepts(src_kind, dst_kind) {
        return Err(RecordError::RelationEndpoints {
            relation: relation_name.to_owned(),
            src_kind: src_kind.to_owned(),
            dst_kind: dst_kind.to_owned(),
        });
    }
    Ok(())
}

fn snapshot(kind: &KindRow, id: String, data: Value, updated_at: String) -> EntitySnapshot {
    let mut title = render_template(&kind.title_template, &data);
    if title.is_empty() {
        title = ["name", "title", "subject", "statement", "full_name"]
            .iter()
            .find_map(|field| data.get(*field).and_then(Value::as_str))
            .map(str::to_owned)
            .unwrap_or_else(|| kind.name.clone());
    }
    let body_text = render_template(&kind.text_template, &data);
    let state = kind
        .state_property()
        .and_then(|property| data.get(property))
        .and_then(Value::as_str)
        .map(str::to_owned);
    EntitySnapshot {
        id,
        kind: kind.name.clone(),
        title,
        body_text: (!body_text.is_empty()).then_some(body_text),
        state,
        data,
        updated_at,
    }
}

fn existing_snapshot(entity: super::EntityRow) -> EntitySnapshot {
    EntitySnapshot {
        id: entity.id,
        kind: entity.kind,
        title: entity.title,
        body_text: entity.body_text,
        state: entity.state,
        data: entity.data,
        updated_at: entity.updated_at,
    }
}

/// Applies the diff. Returns the `before` value for the event and the entity
/// ids the commit touched.
fn apply(
    transaction: &Transaction<'_>,
    diff: &Diff,
    now: &str,
) -> Result<(Option<Value>, Vec<String>), RecordError> {
    match diff {
        Diff::Create {
            after,
            identities,
            links,
        } => {
            transaction.execute(
                "insert into entity (id, kind, title, body_text, state, data, created_at, updated_at, deleted_at)
                 values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, null)",
                params![
                    after.id,
                    after.kind,
                    after.title,
                    after.body_text,
                    after.state,
                    serde_json::to_string(&after.data)?,
                    now,
                ],
            )?;
            insert_identities(transaction, &after.id, identities, now)?;
            for link in links {
                insert_edge(transaction, link, now)?;
            }
            Ok((
                None,
                std::iter::once(after.id.clone())
                    .chain(links.iter().map(|link| link.dst_id.clone()))
                    .collect(),
            ))
        }
        Diff::Update {
            before,
            after,
            identities,
        } => {
            let current: Option<String> = transaction
                .query_row(
                    "select updated_at from entity where id = ?1 and deleted_at is null",
                    params![before.id],
                    |row| row.get(0),
                )
                .optional()?;
            if current.as_deref() != Some(before.updated_at.as_str()) {
                return Err(RecordError::Stale(before.id.clone()));
            }
            transaction.execute(
                "update entity set title = ?2, body_text = ?3, state = ?4, data = ?5, updated_at = ?6 where id = ?1",
                params![
                    after.id,
                    after.title,
                    after.body_text,
                    after.state,
                    serde_json::to_string(&after.data)?,
                    now,
                ],
            )?;
            insert_identities(transaction, &after.id, identities, now)?;
            Ok((Some(serde_json::to_value(before)?), vec![after.id.clone()]))
        }
        Diff::Link { link, .. } => {
            for id in [&link.src_id, &link.dst_id] {
                let live: Option<String> = transaction
                    .query_row(
                        "select id from entity where id = ?1 and deleted_at is null",
                        params![id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if live.is_none() {
                    return Err(RecordError::Stale(id.clone()));
                }
            }
            insert_edge(transaction, link, now)?;
            Ok((None, vec![link.src_id.clone(), link.dst_id.clone()]))
        }
        Diff::Merge {
            loser,
            survivor,
            link,
            ..
        } => {
            for entity in [loser, survivor] {
                let current: Option<String> = transaction
                    .query_row(
                        "select updated_at from entity where id = ?1 and deleted_at is null",
                        params![entity.id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if current.as_deref() != Some(entity.updated_at.as_str()) {
                    return Err(RecordError::Stale(entity.id.clone()));
                }
            }
            insert_edge(transaction, link, now)?;
            transaction.execute(
                "update identity set entity_id = ?2 where entity_id = ?1",
                params![loser.id, survivor.id],
            )?;
            transaction.execute(
                "update entity set deleted_at = ?2, updated_at = ?2 where id = ?1",
                params![loser.id, now],
            )?;
            transaction.execute(
                "update entity set updated_at = ?2 where id = ?1",
                params![survivor.id, now],
            )?;
            Ok((
                Some(serde_json::json!({"loser": loser, "survivor": survivor})),
                vec![survivor.id.clone(), loser.id.clone()],
            ))
        }
        Diff::Delete { before } => {
            let current: Option<String> = transaction
                .query_row(
                    "select updated_at from entity where id = ?1 and deleted_at is null",
                    params![before.id],
                    |row| row.get(0),
                )
                .optional()?;
            if current.as_deref() != Some(before.updated_at.as_str()) {
                return Err(RecordError::Stale(before.id.clone()));
            }
            transaction.execute(
                "update entity set deleted_at = ?2, updated_at = ?2 where id = ?1",
                params![before.id, now],
            )?;
            Ok((Some(serde_json::to_value(before)?), vec![before.id.clone()]))
        }
    }
}

fn insert_identities(
    transaction: &Transaction<'_>,
    entity_id: &str,
    identities: &[ProposalIdentity],
    now: &str,
) -> Result<(), RecordError> {
    for identity in identities {
        let bound: Option<String> = transaction
            .query_row(
                "select entity_id from identity where kind = ?1 and value = ?2",
                params![identity.kind, identity.value],
                |row| row.get(0),
            )
            .optional()?;
        match bound {
            Some(other) if other != entity_id => {
                return Err(RecordError::IdentityBound {
                    kind: identity.kind.clone(),
                    value: identity.value.clone(),
                    entity_id: other,
                });
            }
            Some(_) => {}
            None => {
                transaction.execute(
                    "insert into identity (kind, value, entity_id, source, confidence, first_seen)
                     values (?1, ?2, ?3, 'proposal', 1.0, ?4)",
                    params![identity.kind, identity.value, entity_id, now],
                )?;
            }
        }
    }
    Ok(())
}

fn insert_edge(
    transaction: &Transaction<'_>,
    link: &ProposalLink,
    now: &str,
) -> Result<(), RecordError> {
    transaction.execute(
        "insert into edge (id, src_id, relation, dst_id, props, valid_from, valid_to, source, confidence)
         values (?1, ?2, ?3, ?4, ?5, ?6, null, 'proposal', 1.0)",
        params![
            link.id,
            link.src_id,
            link.relation,
            link.dst_id,
            serde_json::to_string(&link.props)?,
            now,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Fixture {
        directory: std::path::PathBuf,
        record: CompanyRecord,
        human: String,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let directory = std::env::temp_dir()
                .join(format!("muniment-record-{label}-{}", uuid::Uuid::now_v7()));
            std::fs::create_dir_all(&directory).unwrap();
            let mut record = CompanyRecord::open(directory.join("graph.sqlite3")).unwrap();
            let human = record
                .create_principal(PrincipalType::Human, "owner", None)
                .unwrap()
                .id;
            Self {
                directory,
                record,
                human,
            }
        }

        fn create(&mut self, operation: Operation) -> (Proposal, CommitResult) {
            let proposal = self.record.propose(operation).unwrap();
            let result = self.record.commit(&proposal.id, &self.human).unwrap();
            (proposal, result)
        }

        fn org(&mut self, name: &str, domain: &str) -> String {
            let (_, result) = self.create(Operation::Create {
                kind: "org".into(),
                data: json!({"name": name}).as_object().unwrap().clone(),
                identities: vec![IdentityInput {
                    kind: "domain".into(),
                    value: domain.into(),
                }],
                links: vec![],
            });
            result.entity_ids[0].clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn every_write_appends_one_event_in_sequence() {
        let mut fixture = Fixture::new("events");
        assert_eq!(fixture.record.event_count().unwrap(), 0);
        let org = fixture.org("Northwind Traders", "northwind.example");
        assert_eq!(fixture.record.event_count().unwrap(), 1);

        let (_, person) = fixture.create(Operation::Create {
            kind: "person".into(),
            data: object(json!({"full_name": "Elena Vasquez", "job_title": "VP Sales"})),
            identities: vec![IdentityInput {
                kind: "email".into(),
                value: "Elena.Vasquez@northwind.example".into(),
            }],
            links: vec![LinkInput {
                relation: "works_at".into(),
                target: Reference::Identity {
                    kind: "domain".into(),
                    value: "northwind.example".into(),
                },
                props: Map::new(),
            }],
        });
        assert_eq!(fixture.record.event_count().unwrap(), 2);
        let person_id = person.entity_ids[0].clone();

        fixture.create(Operation::Update {
            entity: Reference::parse("email:elena.vasquez@northwind.example").unwrap(),
            data: object(json!({"city": "Lisbon"})),
            identities: vec![],
        });
        fixture.create(Operation::Link {
            src: Reference::Entity(person_id.clone()),
            relation: "owns".into(),
            dst: Reference::Entity(org.clone()),
            props: Map::new(),
        });
        assert_eq!(fixture.record.event_count().unwrap(), 4);

        let events = fixture.record.events(&person_id).unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.verb.as_str())
                .collect::<Vec<_>>(),
            ["created", "updated", "linked"]
        );
        assert_eq!(
            events.iter().map(|event| event.seq).collect::<Vec<_>>(),
            [2, 3, 4]
        );
        assert!(events
            .iter()
            .all(|event| uuid::Uuid::parse_str(&event.id).is_ok()));
        assert!(events.iter().all(|event| event.actor_id == fixture.human));
        assert!(events.iter().all(|event| event.on_behalf_of.is_none()));
        assert!(events[1].before.is_some());

        let entity = fixture.record.entity(&person_id).unwrap().unwrap();
        assert_eq!(entity.title, "Elena Vasquez");
        assert_eq!(entity.data["city"], "Lisbon");
        assert_eq!(fixture.record.edges(&person_id).unwrap().len(), 2);
        assert_eq!(fixture.record.search("Elena", 10).unwrap()[0].id, person_id);
        assert_eq!(fixture.record.search("Ele", 10).unwrap()[0].id, person_id);
    }

    #[test]
    fn a_delete_leaves_the_live_reads_and_keeps_the_history() {
        let mut fixture = Fixture::new("delete");
        let org = fixture.org("Northwind Traders", "northwind.example");
        let (proposal, result) = fixture.create(Operation::Delete {
            entity: Reference::Entity(org.clone()),
        });
        assert!(matches!(proposal.diff, Diff::Delete { ref before } if before.id == org));
        assert_eq!(result.entity_ids, std::slice::from_ref(&org));
        let entity = fixture.record.entity(&org).unwrap().unwrap();
        assert!(entity.deleted_at.is_some());
        assert!(fixture.record.entities("org", 10).unwrap().is_empty());
        assert!(fixture.record.search("Northwind", 10).unwrap().is_empty());
        let verbs: Vec<String> = fixture
            .record
            .events(&org)
            .unwrap()
            .into_iter()
            .map(|event| event.verb)
            .collect();
        assert_eq!(verbs, ["created", "deleted"]);
        assert!(matches!(
            fixture.record.propose(Operation::Delete {
                entity: Reference::Entity(org.clone()),
            }),
            Err(RecordError::EntityDeleted(_))
        ));
        assert!(matches!(
            fixture.record.propose(Operation::Update {
                entity: Reference::parse("domain:northwind.example").unwrap(),
                data: Map::new(),
                identities: vec![],
            }),
            Err(RecordError::EntityDeleted(_))
        ));
    }

    #[test]
    fn an_external_identity_names_one_entity_and_a_second_claim_is_refused() {
        let mut fixture = Fixture::new("external");
        let (_, first) = fixture.create(Operation::Create {
            kind: "org".into(),
            data: object(json!({"name": "Northwind"})),
            identities: vec![IdentityInput {
                kind: "external".into(),
                value: "Salesforce:Account:0015g00000Xy".into(),
            }],
            links: vec![],
        });
        let resolved = fixture
            .record
            .resolve(&Reference::parse("external:salesforce:Account:0015g00000Xy").unwrap())
            .unwrap();
        assert_eq!(resolved.as_deref(), Some(first.entity_ids[0].as_str()));

        let second = fixture.record.propose(Operation::Create {
            kind: "org".into(),
            data: object(json!({"name": "Northwind Traders"})),
            identities: vec![IdentityInput {
                kind: "external".into(),
                value: "salesforce:Account:0015g00000Xy".into(),
            }],
            links: vec![],
        });
        assert!(matches!(second, Err(RecordError::IdentityBound { .. })));
        assert_eq!(fixture.record.event_count().unwrap(), 1);
    }

    #[test]
    fn no_write_bypasses_kind_validation() {
        let mut fixture = Fixture::new("validation");
        let unknown_kind = fixture.record.propose(Operation::Create {
            kind: "widget".into(),
            data: Map::new(),
            identities: vec![],
            links: vec![],
        });
        assert!(matches!(unknown_kind, Err(RecordError::UnknownKind(_))));

        let unknown_property = fixture.record.propose(Operation::Create {
            kind: "deal".into(),
            data: object(json!({"name": "N", "stage": "won", "expected_close": "2026-09-16", "color": "red"})),
            identities: vec![],
            links: vec![],
        });
        assert!(matches!(
            unknown_property,
            Err(RecordError::Validation(
                super::super::ValidationError::UnknownProperty(_)
            ))
        ));

        let missing = fixture.record.propose(Operation::Create {
            kind: "deal".into(),
            data: object(json!({"name": "Northwind renewal FY27", "amount": 96000})),
            identities: vec![],
            links: vec![],
        });
        match missing {
            Err(RecordError::Validation(super::super::ValidationError::MissingRequired {
                field,
                prompt,
            })) => {
                assert_eq!(field, "stage");
                assert!(prompt.contains("required for kind deal"));
            }
            other => panic!("expected a missing field, got {other:?}"),
        }

        let bad_enum = fixture.record.propose(Operation::Create {
            kind: "deal".into(),
            data: object(json!({"name": "N", "stage": "open", "expected_close": "2026-09-16"})),
            identities: vec![],
            links: vec![],
        });
        assert!(matches!(bad_enum, Err(RecordError::Validation(_))));

        let (_, deal) = fixture.create(Operation::Create {
            kind: "deal".into(),
            data: object(json!({"name": "N", "stage": "won", "expected_close": "2026-09-16"})),
            identities: vec![],
            links: vec![],
        });
        let entity = fixture.record.entity(&deal.entity_ids[0]).unwrap().unwrap();
        assert_eq!(entity.state.as_deref(), Some("won"));

        let bad_update = fixture.record.propose(Operation::Update {
            entity: Reference::Entity(deal.entity_ids[0].clone()),
            data: object(json!({"amount": "lots"})),
            identities: vec![],
        });
        assert!(matches!(bad_update, Err(RecordError::Validation(_))));

        let person = fixture.create(Operation::Create {
            kind: "person".into(),
            data: object(json!({"full_name": "Dana"})),
            identities: vec![],
            links: vec![],
        });
        let wrong_relation = fixture.record.propose(Operation::Link {
            src: Reference::Entity(deal.entity_ids[0].clone()),
            relation: "works_at".into(),
            dst: Reference::Entity(person.1.entity_ids[0].clone()),
            props: Map::new(),
        });
        assert!(matches!(
            wrong_relation,
            Err(RecordError::RelationEndpoints { .. })
        ));
        assert_eq!(fixture.record.event_count().unwrap(), 2);
    }

    #[test]
    fn a_spent_proposal_commits_once_and_a_stale_one_is_refused() {
        let mut fixture = Fixture::new("spent");
        let org = fixture.org("Northwind", "northwind.example");
        let proposal = fixture
            .record
            .propose(Operation::Update {
                entity: Reference::Entity(org.clone()),
                data: object(json!({"industry": "Logistics"})),
                identities: vec![],
            })
            .unwrap();
        let first = fixture.record.commit(&proposal.id, &fixture.human).unwrap();
        let second = fixture.record.commit(&proposal.id, &fixture.human).unwrap();
        assert_eq!(first, second);
        assert_eq!(fixture.record.event_count().unwrap(), 2);

        let stale = fixture
            .record
            .propose(Operation::Update {
                entity: Reference::Entity(org.clone()),
                data: object(json!({"industry": "Shipping"})),
                identities: vec![],
            })
            .unwrap();
        let fresh = fixture
            .record
            .propose(Operation::Update {
                entity: Reference::Entity(org.clone()),
                data: object(json!({"city": "Porto"})),
                identities: vec![],
            })
            .unwrap();
        fixture.record.commit(&fresh.id, &fixture.human).unwrap();
        assert!(matches!(
            fixture.record.commit(&stale.id, &fixture.human),
            Err(RecordError::Stale(_))
        ));
        assert!(matches!(
            fixture.record.commit("nope", &fixture.human),
            Err(RecordError::ProposalNotFound(_))
        ));
        assert_eq!(fixture.record.pending_proposals().len(), 1);
    }

    #[test]
    fn a_merge_keeps_the_loser_reachable_and_moves_its_identities() {
        let mut fixture = Fixture::new("merge");
        let survivor = fixture.org("Northwind Traders", "northwind.example");
        let (loser_proposal, loser_result) = fixture.create(Operation::Create {
            kind: "org".into(),
            data: object(json!({"name": "Northwind Traders Inc."})),
            identities: vec![IdentityInput {
                kind: "external".into(),
                value: "hubspot:company:88".into(),
            }],
            links: vec![],
        });
        assert_eq!(loser_proposal.warnings.len(), 1);
        assert!(loser_proposal.warnings[0].contains("already exists"));
        let loser = loser_result.entity_ids[0].clone();

        let (proposal, result) = fixture.create(Operation::Merge {
            loser: Reference::Entity(loser.clone()),
            survivor: Reference::parse("domain:northwind.example").unwrap(),
        });
        assert!(matches!(
            proposal.diff,
            Diff::Merge {
                identities_moved: 1,
                ..
            }
        ));
        assert_eq!(result.entity_ids, vec![survivor.clone(), loser.clone()]);

        let loser_row = fixture.record.entity(&loser).unwrap().unwrap();
        assert!(loser_row.deleted_at.is_some());
        let edges = fixture.record.edges(&loser).unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].relation, "superseded_by");
        assert_eq!(edges[0].dst_id, survivor);
        let identities = fixture.record.identities(&survivor).unwrap();
        assert!(identities
            .iter()
            .any(|identity| identity.value == "hubspot:company:88"));
        assert!(fixture.record.identities(&loser).unwrap().is_empty());
        let events = fixture.record.events(&survivor).unwrap();
        assert_eq!(events.last().unwrap().verb, "merged");
        assert!(events
            .last()
            .unwrap()
            .before
            .as_ref()
            .unwrap()
            .get("loser")
            .is_some());

        let again = fixture.record.propose(Operation::Update {
            entity: Reference::Entity(loser),
            data: Map::new(),
            identities: vec![],
        });
        assert!(matches!(again, Err(RecordError::EntityDeleted(_))));
    }

    #[test]
    fn an_agent_names_its_human_and_the_event_carries_both() {
        let mut fixture = Fixture::new("agent");
        assert!(matches!(
            fixture
                .record
                .create_principal(PrincipalType::Agent, "claude", None),
            Err(RecordError::Delegation)
        ));
        let human = fixture.human.clone();
        let agent = fixture
            .record
            .create_principal(PrincipalType::Agent, "claude", Some(&human))
            .unwrap();
        let proposal = fixture
            .record
            .propose(Operation::Create {
                kind: "org".into(),
                data: object(json!({"name": "Northwind"})),
                identities: vec![],
                links: vec![],
            })
            .unwrap();
        let result = fixture.record.commit(&proposal.id, &agent.id).unwrap();
        assert_eq!(result.actor, agent.id);
        assert_eq!(result.on_behalf_of.as_deref(), Some(human.as_str()));
        let events = fixture.record.events(&result.entity_ids[0]).unwrap();
        assert_eq!(events[0].on_behalf_of.as_deref(), Some(human.as_str()));
        assert!(fixture.record.commit(&proposal.id, "missing").is_ok());
    }

    #[test]
    fn extension_kinds_and_properties_stay_under_the_prefix() {
        let mut fixture = Fixture::new("extension");
        assert!(matches!(
            fixture
                .record
                .extend_kind("deal", "renewal_risk", json!({"type": "string"})),
            Err(RecordError::ExtensionName(_))
        ));
        fixture
            .record
            .extend_kind(
                "deal",
                "x_renewal_risk",
                json!({"type": "string", "enum": ["low", "high"]}),
            )
            .unwrap();
        let (_, deal) = fixture.create(Operation::Create {
            kind: "deal".into(),
            data: object(json!({"name": "N", "stage": "won", "expected_close": "2026-09-16", "x_renewal_risk": "low"})),
            identities: vec![],
            links: vec![],
        });
        assert_eq!(
            fixture
                .record
                .entity(&deal.entity_ids[0])
                .unwrap()
                .unwrap()
                .data["x_renewal_risk"],
            "low"
        );

        let definition = super::super::KindDefinition {
            name: "x_vendor".into(),
            version: 1,
            schema: json!({"type": "object", "properties": {"x_name": {"type": "string"}}, "required": ["x_name"]}),
            title_template: "{x_name}".into(),
            text_template: "Vendor {x_name}.".into(),
            states: None,
        };
        fixture
            .record
            .define_extension_kind(definition.clone())
            .unwrap();
        assert!(matches!(
            fixture.record.define_extension_kind(definition),
            Err(RecordError::KindExists(_))
        ));
        let core_named = super::super::KindDefinition {
            name: "vendor".into(),
            version: 1,
            schema: json!({"type": "object", "properties": {}}),
            title_template: String::new(),
            text_template: String::new(),
            states: None,
        };
        assert!(matches!(
            fixture.record.define_extension_kind(core_named),
            Err(RecordError::ExtensionName(_))
        ));
        let (_, vendor) = fixture.create(Operation::Create {
            kind: "x_vendor".into(),
            data: object(json!({"x_name": "Acme"})),
            identities: vec![],
            links: vec![],
        });
        assert_eq!(
            fixture
                .record
                .entity(&vendor.entity_ids[0])
                .unwrap()
                .unwrap()
                .title,
            "Acme"
        );
        assert_eq!(fixture.record.kinds().unwrap().len(), 21);
        assert_eq!(
            fixture.record.kinds().unwrap().last().unwrap().name,
            "x_vendor"
        );
    }

    #[test]
    fn operations_round_trip_through_json() {
        let operation: Operation = serde_json::from_value(json!({
            "op": "create",
            "kind": "deal",
            "data": {"name": "Northwind renewal FY27", "amount": 96000},
            "links": [{"relation": "concerns", "target": "domain:northwind.example"}]
        }))
        .unwrap();
        match &operation {
            Operation::Create { links, .. } => assert_eq!(
                links[0].target,
                Reference::Identity {
                    kind: "domain".into(),
                    value: "northwind.example".into()
                }
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            serde_json::to_value(Reference::parse("external:salesforce:Contact:003").unwrap())
                .unwrap(),
            json!("external:salesforce:Contact:003")
        );
        assert!(serde_json::from_value::<Reference>(json!("nocolon")).is_err());
    }
}
