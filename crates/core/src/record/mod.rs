//! The company record: one SQLite graph per company, the kind catalogue, and
//! the propose and commit write path. A model never writes a row. propose
//! validates against the kind, resolves every identity and returns a diff.
//! commit applies that diff in one transaction and appends one event.

mod catalogue;
mod companies;
mod identity;
mod propose;
mod schema;
mod validate;

pub use catalogue::{core_kinds, relations, KindDefinition, Relation};
pub use companies::{CompaniesRoot, CompanyError, CompanySummary, COMPANIES_DIRECTORY_NAME};
pub use identity::{name_key, normalize_identity, IdentityError, IdentityKind};
pub use propose::{
    CommitResult, Diff, EntitySnapshot, IdentityInput, LinkInput, Operation, Proposal,
    ProposalIdentity, ProposalLink, Reference,
};
pub use validate::ValidationError;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

/// A proposal waits this long for its commit before it expires.
pub const PROPOSAL_TTL_SECONDS: i64 = 3600;

/// One open company graph with its in-memory proposals.
pub struct CompanyRecord {
    connection: Connection,
    proposals: BTreeMap<String, propose::StoredProposal>,
}

/// One row of the kind catalogue, with the company's extension beside it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KindRow {
    pub name: String,
    pub version: i64,
    pub schema: Value,
    pub title_template: String,
    pub text_template: String,
    pub states: Option<Vec<String>>,
    pub extension: Option<Value>,
}

impl KindRow {
    /// The property whose value fills `entity.state`, when the kind has one.
    pub fn state_property(&self) -> Option<&str> {
        self.schema.get("stateProperty").and_then(Value::as_str)
    }

    /// Whether the kind belongs to a company rather than the core catalogue.
    pub fn is_extension_kind(&self) -> bool {
        self.name.starts_with(EXTENSION_PREFIX)
    }
}

/// Every tenant property and every tenant kind carries this prefix.
pub const EXTENSION_PREFIX: &str = "x_";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntityRow {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub body_text: Option<String>,
    pub state: Option<String>,
    pub data: Value,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EdgeRow {
    pub id: String,
    pub src_id: String,
    pub relation: String,
    pub dst_id: String,
    pub props: Value,
    pub valid_from: String,
    pub valid_to: Option<String>,
    pub source: String,
    pub confidence: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityRow {
    pub kind: String,
    pub value: String,
    pub entity_id: String,
    pub source: String,
    pub confidence: f64,
    pub first_seen: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventRow {
    pub id: String,
    pub seq: i64,
    pub at: String,
    pub actor_id: String,
    pub on_behalf_of: Option<String>,
    pub verb: String,
    pub entity_id: Option<String>,
    pub edge_id: Option<String>,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub source: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    Human,
    Service,
    Job,
    Agent,
}

impl PrincipalType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Service => "service",
            Self::Job => "job",
            Self::Agent => "agent",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "human" => Some(Self::Human),
            "service" => Some(Self::Service),
            "job" => Some(Self::Job),
            "agent" => Some(Self::Agent),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrincipalRow {
    pub id: String,
    #[serde(rename = "type")]
    pub principal_type: PrincipalType,
    pub entity_id: Option<String>,
    pub on_behalf_of: Option<String>,
    pub label: String,
    pub disabled_at: Option<String>,
}

#[derive(Debug)]
pub enum RecordError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    UnsupportedSchema(i64),
    UnknownKind(String),
    KindExists(String),
    CoreKindImmutable(String),
    ExtensionName(String),
    UnknownRelation(String),
    RelationEndpoints {
        relation: String,
        src_kind: String,
        dst_kind: String,
    },
    Validation(ValidationError),
    Identity(IdentityError),
    Unresolved(String),
    IdentityBound {
        kind: String,
        value: String,
        entity_id: String,
    },
    AlreadyLinked(String),
    SameEntity,
    KindMismatch {
        loser: String,
        survivor: String,
    },
    EntityDeleted(String),
    ProposalNotFound(String),
    ProposalExpired(String),
    Stale(String),
    PrincipalNotFound(String),
    PrincipalDisabled(String),
    Delegation,
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "record database failed: {error}"),
            Self::Json(error) => write!(formatter, "record JSON failed: {error}"),
            Self::UnsupportedSchema(version) => {
                write!(formatter, "record schema version {version} is newer than this app")
            }
            Self::UnknownKind(kind) => write!(formatter, "kind {kind} is not in the catalogue"),
            Self::KindExists(kind) => write!(formatter, "kind {kind} already exists"),
            Self::CoreKindImmutable(kind) => {
                write!(formatter, "kind {kind} is core and never changes")
            }
            Self::ExtensionName(name) => write!(
                formatter,
                "{name} must start with {EXTENSION_PREFIX} and carry only letters, digits and underscores"
            ),
            Self::UnknownRelation(relation) => {
                write!(formatter, "relation {relation} is not in the vocabulary")
            }
            Self::RelationEndpoints {
                relation,
                src_kind,
                dst_kind,
            } => write!(
                formatter,
                "relation {relation} does not run from {src_kind} to {dst_kind}"
            ),
            Self::Validation(error) => write!(formatter, "{error}"),
            Self::Identity(error) => write!(formatter, "{error}"),
            Self::Unresolved(reference) => {
                write!(formatter, "{reference} resolves to no entity")
            }
            Self::IdentityBound {
                kind,
                value,
                entity_id,
            } => write!(
                formatter,
                "{kind}:{value} already names entity {entity_id}"
            ),
            Self::AlreadyLinked(relation) => {
                write!(formatter, "an open {relation} edge already joins these entities")
            }
            Self::SameEntity => formatter.write_str("the two references name one entity"),
            Self::KindMismatch { loser, survivor } => write!(
                formatter,
                "a merge joins one kind, and these are {loser} and {survivor}"
            ),
            Self::EntityDeleted(id) => write!(formatter, "entity {id} is superseded"),
            Self::ProposalNotFound(id) => write!(formatter, "proposal {id} is unknown"),
            Self::ProposalExpired(id) => write!(formatter, "proposal {id} expired"),
            Self::Stale(id) => write!(
                formatter,
                "entity {id} changed after the proposal, so propose again"
            ),
            Self::PrincipalNotFound(id) => write!(formatter, "principal {id} is unknown"),
            Self::PrincipalDisabled(id) => write!(formatter, "principal {id} is disabled"),
            Self::Delegation => {
                formatter.write_str("a principal that is not a human must name the human it acts for")
            }
        }
    }
}

impl std::error::Error for RecordError {}

impl From<rusqlite::Error> for RecordError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for RecordError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<ValidationError> for RecordError {
    fn from(error: ValidationError) -> Self {
        Self::Validation(error)
    }
}

impl From<IdentityError> for RecordError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

pub(crate) fn now_string() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn parse_json_column(text: Option<String>) -> Result<Option<Value>, RecordError> {
    text.map(|text| serde_json::from_str(&text))
        .transpose()
        .map_err(RecordError::Json)
}

impl CompanyRecord {
    /// Opens or creates one company graph, migrates it and seeds the catalogue.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RecordError> {
        let connection = schema::open_connection(path.as_ref())?;
        Ok(Self {
            connection,
            proposals: BTreeMap::new(),
        })
    }

    /// Every kind in the catalogue, core first, then the company's own.
    pub fn kinds(&self) -> Result<Vec<KindRow>, RecordError> {
        let mut statement = self.connection.prepare(
            "select k.name, k.version, k.schema, k.title_template, k.text_template, k.states, e.schema
             from kind k left join kind_extension e on e.kind_name = k.name
             order by k.name like 'x\\_%' escape '\\', k.name",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?;
        let mut kinds = Vec::new();
        for row in rows {
            let (name, version, schema, title_template, text_template, states, extension) = row?;
            kinds.push(KindRow {
                name,
                version,
                schema: serde_json::from_str(&schema)?,
                title_template,
                text_template,
                states: parse_json_column(states)?
                    .map(serde_json::from_value)
                    .transpose()?,
                extension: parse_json_column(extension)?,
            });
        }
        Ok(kinds)
    }

    pub fn kind(&self, name: &str) -> Result<Option<KindRow>, RecordError> {
        Ok(self.kinds()?.into_iter().find(|kind| kind.name == name))
    }

    fn require_kind(&self, name: &str) -> Result<KindRow, RecordError> {
        self.kind(name)?
            .ok_or_else(|| RecordError::UnknownKind(name.to_owned()))
    }

    /// Adds one company property to a kind. The name carries the `x_` prefix,
    /// so a core property is never redefined.
    pub fn extend_kind(
        &mut self,
        kind: &str,
        property: &str,
        property_schema: Value,
    ) -> Result<KindRow, RecordError> {
        let row = self.require_kind(kind)?;
        if !is_extension_name(property) {
            return Err(RecordError::ExtensionName(property.to_owned()));
        }
        let mut extension = row
            .extension
            .unwrap_or_else(|| serde_json::json!({"type": "object", "properties": {}}));
        let properties = extension
            .as_object_mut()
            .and_then(|object| {
                object
                    .entry("properties")
                    .or_insert_with(|| Value::Object(Default::default()))
                    .as_object_mut()
            })
            .ok_or_else(|| RecordError::ExtensionName(property.to_owned()))?;
        properties.insert(property.to_owned(), property_schema);
        let version: i64 = self.connection.query_row(
            "select coalesce(max(version), 0) + 1 from kind_extension where kind_name = ?1",
            params![kind],
            |row| row.get(0),
        )?;
        self.connection.execute(
            "insert into kind_extension (kind_name, version, schema) values (?1, ?2, ?3)
             on conflict (kind_name) do update set version = excluded.version, schema = excluded.schema",
            params![kind, version, serde_json::to_string(&extension)?],
        )?;
        self.require_kind(kind)
    }

    /// Defines one company kind. Its name and every property carry the `x_`
    /// prefix, and the core catalogue never gains a row this way.
    pub fn define_extension_kind(
        &mut self,
        definition: KindDefinition,
    ) -> Result<KindRow, RecordError> {
        if !is_extension_name(&definition.name) {
            return Err(RecordError::ExtensionName(definition.name));
        }
        if self.kind(&definition.name)?.is_some() {
            return Err(RecordError::KindExists(definition.name));
        }
        let properties = definition
            .schema
            .get("properties")
            .and_then(Value::as_object)
            .ok_or_else(|| RecordError::ExtensionName(definition.name.clone()))?;
        if let Some(bad) = properties.keys().find(|key| !is_extension_name(key)) {
            return Err(RecordError::ExtensionName(bad.to_owned()));
        }
        schema::insert_kind(&self.connection, &definition)?;
        self.require_kind(&definition.name)
    }

    /// Creates one principal. A principal that is not a human names the human
    /// it acts for, and the schema refuses one that does not.
    pub fn create_principal(
        &mut self,
        principal_type: PrincipalType,
        label: &str,
        on_behalf_of: Option<&str>,
    ) -> Result<PrincipalRow, RecordError> {
        let id = uuid::Uuid::now_v7().to_string();
        let result = self.connection.execute(
            "insert into principal (id, type, entity_id, on_behalf_of, label, disabled_at)
             values (?1, ?2, null, ?3, ?4, null)",
            params![id, principal_type.as_str(), on_behalf_of, label],
        );
        match result {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(RecordError::Delegation);
            }
            Err(error) => return Err(error.into()),
        }
        self.principal(&id)?
            .ok_or_else(|| RecordError::PrincipalNotFound(id))
    }

    pub fn principal(&self, id: &str) -> Result<Option<PrincipalRow>, RecordError> {
        self.connection
            .query_row(
                "select id, type, entity_id, on_behalf_of, label, disabled_at from principal where id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?
            .map(|(id, principal_type, entity_id, on_behalf_of, label, disabled_at)| {
                Ok(PrincipalRow {
                    id,
                    principal_type: PrincipalType::parse(&principal_type)
                        .ok_or_else(|| RecordError::UnsupportedSchema(0))?,
                    entity_id,
                    on_behalf_of,
                    label,
                    disabled_at,
                })
            })
            .transpose()
    }

    pub fn entity(&self, id: &str) -> Result<Option<EntityRow>, RecordError> {
        self.connection
            .query_row(
                "select id, kind, title, body_text, state, data, created_at, updated_at, deleted_at
                 from entity where id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Option<String>>(8)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(id, kind, title, body_text, state, data, created_at, updated_at, deleted_at)| {
                    Ok(EntityRow {
                        id,
                        kind,
                        title,
                        body_text,
                        state,
                        data: serde_json::from_str(&data)?,
                        created_at,
                        updated_at,
                        deleted_at,
                    })
                },
            )
            .transpose()
    }

    /// Lists the live entities of one kind, newest change first.
    pub fn entities(&self, kind: &str, limit: usize) -> Result<Vec<EntityRow>, RecordError> {
        let mut statement = self.connection.prepare(
            "select id from entity where kind = ?1 and deleted_at is null
             order by updated_at desc limit ?2",
        )?;
        let ids = statement
            .query_map(params![kind, limit as i64], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter()
            .filter_map(|id| self.entity(id).transpose())
            .collect()
    }

    pub fn identities(&self, entity_id: &str) -> Result<Vec<IdentityRow>, RecordError> {
        let mut statement = self.connection.prepare(
            "select kind, value, entity_id, source, confidence, first_seen from identity
             where entity_id = ?1 order by kind, value",
        )?;
        let rows = statement.query_map(params![entity_id], |row| {
            Ok(IdentityRow {
                kind: row.get(0)?,
                value: row.get(1)?,
                entity_id: row.get(2)?,
                source: row.get(3)?,
                confidence: row.get(4)?,
                first_seen: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Every edge that touches one entity, open and closed.
    pub fn edges(&self, entity_id: &str) -> Result<Vec<EdgeRow>, RecordError> {
        let mut statement = self.connection.prepare(
            "select id, src_id, relation, dst_id, props, valid_from, valid_to, source, confidence
             from edge where src_id = ?1 or dst_id = ?1 order by valid_from, id",
        )?;
        let rows = statement.query_map(params![entity_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, f64>(8)?,
            ))
        })?;
        let mut edges = Vec::new();
        for row in rows {
            let (id, src_id, relation, dst_id, props, valid_from, valid_to, source, confidence) =
                row?;
            edges.push(EdgeRow {
                id,
                src_id,
                relation,
                dst_id,
                props: serde_json::from_str(&props)?,
                valid_from,
                valid_to,
                source,
                confidence,
            });
        }
        Ok(edges)
    }

    /// The events that touched one entity, in append order.
    pub fn events(&self, entity_id: &str) -> Result<Vec<EventRow>, RecordError> {
        let mut statement = self.connection.prepare(
            "select id, seq, at, actor_id, on_behalf_of, verb, entity_id, edge_id, before, after, source
             from event where entity_id = ?1 order by seq",
        )?;
        let rows = statement.query_map(params![entity_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (
                id,
                seq,
                at,
                actor_id,
                on_behalf_of,
                verb,
                entity_id,
                edge_id,
                before,
                after,
                source,
            ) = row?;
            events.push(EventRow {
                id,
                seq,
                at,
                actor_id,
                on_behalf_of,
                verb,
                entity_id,
                edge_id,
                before: parse_json_column(before)?,
                after: parse_json_column(after)?,
                source,
            });
        }
        Ok(events)
    }

    pub fn event_count(&self) -> Result<i64, RecordError> {
        self.connection
            .query_row("select count(*) from event", [], |row| row.get(0))
            .map_err(Into::into)
    }

    /// Full-text search over titles and prose, live entities only.
    pub fn search(&self, text: &str, limit: usize) -> Result<Vec<EntityRow>, RecordError> {
        let query = text
            .split_whitespace()
            .map(|word| format!("\"{}\"", word.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" ");
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let mut statement = self.connection.prepare(
            "select s.entity_id from entity_search s join entity e on e.id = s.entity_id
             where entity_search match ?1 and e.deleted_at is null order by rank limit ?2",
        )?;
        let ids = statement
            .query_map(params![query, limit as i64], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter()
            .filter_map(|id| self.entity(id).transpose())
            .collect()
    }

    /// Resolves one reference to an entity id, or reports that nothing holds it.
    pub fn resolve(&self, reference: &Reference) -> Result<Option<String>, RecordError> {
        match reference {
            Reference::Entity(id) => Ok(self.entity(id)?.map(|entity| entity.id)),
            Reference::Identity { kind, value } => {
                let kind = IdentityKind::parse(kind)
                    .ok_or_else(|| IdentityError::UnknownKind(kind.clone()))?;
                let value = normalize_identity(kind, value)?;
                self.connection
                    .query_row(
                        "select entity_id from identity where kind = ?1 and value = ?2",
                        params![kind.as_str(), value],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(Into::into)
            }
        }
    }
}

pub(crate) fn is_extension_name(name: &str) -> bool {
    name.starts_with(EXTENSION_PREFIX)
        && name.len() > EXTENSION_PREFIX.len()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Fills `{property}` tokens from the data and collapses the whitespace left
/// behind by an absent value.
pub fn render_template(template: &str, data: &Value) -> String {
    let mut output = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                let key = &after[..end];
                if let Some(value) = data.get(key) {
                    output.push_str(&value_text(value));
                }
                rest = &after[end + 1..];
            }
            None => {
                output.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    output.push_str(rest);
    output
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" ,", ",")
        .replace(" .", ".")
}

fn value_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Array(items) => items.iter().map(value_text).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_templates_and_collapses_absent_values() {
        let data = serde_json::json!({"name": "Northwind", "amount": 96000, "tags": ["a", "b"]});
        assert_eq!(
            render_template("{name}: {stage}, {amount} {currency}.", &data),
            "Northwind:, 96000."
        );
        assert_eq!(render_template("{tags} {missing", &data), "a, b {missing");
    }

    #[test]
    fn extension_names_carry_the_prefix() {
        assert!(is_extension_name("x_renewal_risk"));
        assert!(!is_extension_name("renewal_risk"));
        assert!(!is_extension_name("x_"));
        assert!(!is_extension_name("x_Renewal"));
    }
}
