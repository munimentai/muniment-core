//! The eight tables in SQLite dialect, the search index and the catalogue seed.

use super::catalogue::{core_kinds, KindDefinition};
use super::RecordError;
use rusqlite::{params, Connection, TransactionBehavior};
use std::path::Path;
use std::time::Duration;

pub(super) const SCHEMA_VERSION: i64 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// One company is one file, so no key carries a tenant id. Every id is a
/// UUIDv7 string. `event.seq` is the append order the writer assigns inside
/// its transaction, and nothing autoincrements.
const DDL: &str = r#"
create table kind (
    name text primary key,
    version integer not null,
    schema text not null,
    title_template text not null,
    text_template text not null,
    states text
);

create table kind_extension (
    kind_name text primary key references kind(name),
    version integer not null,
    schema text not null
);

create table principal (
    id text primary key,
    type text not null check (type in ('human', 'service', 'job', 'agent')),
    entity_id text,
    on_behalf_of text,
    label text not null,
    disabled_at text,
    constraint delegated_must_name_a_human check (type = 'human' or on_behalf_of is not null)
);

create table entity (
    id text primary key,
    kind text not null references kind(name),
    title text not null,
    body_text text,
    state text,
    data text not null default '{}',
    created_at text not null,
    updated_at text not null,
    deleted_at text
);
create index entity_kind_updated on entity (kind, updated_at desc);

create table identity (
    kind text not null,
    value text not null,
    entity_id text not null references entity(id),
    source text not null,
    confidence real not null default 1.0,
    first_seen text not null,
    primary key (kind, value)
);
create index identity_entity on identity (entity_id);

create table edge (
    id text primary key,
    src_id text not null references entity(id),
    relation text not null,
    dst_id text not null references entity(id),
    props text not null default '{}',
    valid_from text not null,
    valid_to text,
    source text not null,
    confidence real not null default 1.0
);
create index edge_src_open on edge (src_id, relation) where valid_to is null;
create index edge_dst_open on edge (dst_id, relation) where valid_to is null;

create table event (
    id text primary key,
    seq integer not null unique,
    at text not null,
    actor_id text not null references principal(id),
    on_behalf_of text,
    verb text not null,
    entity_id text,
    edge_id text,
    before text,
    after text,
    source text
);
create index event_entity on event (entity_id, seq);

create table fact_source (
    id text primary key,
    target_kind text not null check (target_kind in ('entity', 'edge', 'field')),
    target_id text not null,
    field text,
    artifact_id text not null references entity(id),
    quote text not null,
    start_char integer,
    end_char integer,
    extractor text not null,
    confidence real not null,
    extracted_at text not null
);
create index fact_source_target on fact_source (target_id);

create virtual table entity_search using fts5(entity_id unindexed, title, body_text);

create trigger entity_search_insert after insert on entity begin
    insert into entity_search (entity_id, title, body_text)
    values (new.id, new.title, coalesce(new.body_text, ''));
end;
create trigger entity_search_update after update of title, body_text on entity begin
    delete from entity_search where entity_id = old.id;
    insert into entity_search (entity_id, title, body_text)
    values (new.id, new.title, coalesce(new.body_text, ''));
end;
create trigger entity_search_delete after delete on entity begin
    delete from entity_search where entity_id = old.id;
end;
"#;

pub(super) fn open_connection(path: &Path) -> Result<Connection, RecordError> {
    let mut connection = Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(RecordError::UnsupportedSchema(version));
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if version < 1 {
        transaction.execute_batch(DDL)?;
    }
    for kind in core_kinds() {
        insert_kind(&transaction, &kind)?;
    }
    refresh_views(&transaction)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(connection)
}

/// The base columns every kind view carries before its own properties.
const VIEW_BASE_COLUMNS: [&str; 5] = ["id", "title", "state", "created_at", "updated_at"];

/// Rebuilds one view per kind, `v_<kind>`, with a column per property, plus
/// the three graph views. A view is the SQL-native form of a skill, and the
/// catalogue is the one source, so no view is written by hand.
pub(super) fn refresh_views(connection: &Connection) -> Result<(), RecordError> {
    let mut statement = connection.prepare(
        "select k.name, k.schema, e.schema from kind k
         left join kind_extension e on e.kind_name = k.name order by k.name",
    )?;
    let kinds = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (name, schema, extension) in kinds {
        let mut columns: Vec<String> = Vec::new();
        for text in std::iter::once(Some(schema))
            .chain(std::iter::once(extension))
            .flatten()
        {
            let value: serde_json::Value = serde_json::from_str(&text)?;
            if let Some(properties) = value.get("properties").and_then(|p| p.as_object()) {
                for property in properties.keys() {
                    if !VIEW_BASE_COLUMNS.contains(&property.as_str())
                        && !columns.contains(property)
                        && property
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    {
                        columns.push(property.clone());
                    }
                }
            }
        }
        let mut select: Vec<String> = VIEW_BASE_COLUMNS
            .iter()
            .map(|column| format!("\"{column}\""))
            .collect();
        select.extend(
            columns
                .iter()
                .map(|column| format!("json_extract(data, '$.{column}') as \"{column}\"")),
        );
        connection.execute_batch(&format!(
            "drop view if exists \"v_{name}\";
             create view \"v_{name}\" as select {} from entity
             where kind = '{name}' and deleted_at is null;",
            select.join(", ")
        ))?;
    }
    connection.execute_batch(
        "drop view if exists edges_open;
         create view edges_open as
             select e.id, e.relation, e.src_id, s.kind as src_kind, s.title as src_title,
                    e.dst_id, d.kind as dst_kind, d.title as dst_title,
                    e.props, e.valid_from, e.source, e.confidence
             from edge e join entity s on s.id = e.src_id join entity d on d.id = e.dst_id
             where e.valid_to is null;
         drop view if exists entity_identities;
         create view entity_identities as
             select i.kind, i.value, i.entity_id, e.kind as entity_kind, e.title, i.source,
                    i.confidence, i.first_seen
             from identity i join entity e on e.id = i.entity_id;
         drop view if exists recent_events;
         create view recent_events as
             select v.seq, v.at, v.verb, v.actor_id, v.on_behalf_of, v.entity_id,
                    e.kind as entity_kind, e.title, v.edge_id, v.source
             from event v left join entity e on e.id = v.entity_id order by v.seq desc;",
    )?;
    Ok(())
}

/// Writes one kind row. An existing row moves to the new definition only when
/// the definition's version is higher, so a company keeps a newer catalogue.
pub(super) fn insert_kind(
    connection: &Connection,
    kind: &KindDefinition,
) -> Result<(), RecordError> {
    let states = kind
        .states
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    connection.execute(
        "insert into kind (name, version, schema, title_template, text_template, states)
         values (?1, ?2, ?3, ?4, ?5, ?6)
         on conflict (name) do update set
             version = excluded.version,
             schema = excluded.schema,
             title_template = excluded.title_template,
             text_template = excluded.text_template,
             states = excluded.states
         where excluded.version > kind.version",
        params![
            kind.name,
            kind.version,
            serde_json::to_string(&kind.schema)?,
            kind.title_template,
            kind.text_template,
            states,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::CompanyRecord;
    use super::*;

    fn temporary_graph(label: &str) -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("muniment-record-{label}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&directory).unwrap();
        directory.join("graph.sqlite3")
    }

    #[test]
    fn opens_migrates_and_seeds_twenty_kinds_once() {
        let path = temporary_graph("seed");
        let record = CompanyRecord::open(&path).unwrap();
        let kinds = record.kinds().unwrap();
        assert_eq!(kinds.len(), 20);
        assert!(kinds
            .iter()
            .all(|kind| kind.schema.get("properties").is_some()));
        drop(record);

        let record = CompanyRecord::open(&path).unwrap();
        assert_eq!(record.kinds().unwrap().len(), 20);
        let version: i64 = record
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let mode: String = record
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn views_follow_the_catalogue_and_its_extensions() {
        let path = temporary_graph("views");
        let mut record = CompanyRecord::open(&path).unwrap();
        let views: Vec<String> = record
            .connection
            .prepare("select name from sqlite_master where type = 'view' order by name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(views.len(), 23);
        assert!(views.contains(&"v_deal".to_owned()));
        assert!(views.contains(&"edges_open".to_owned()));
        let deal_columns: Vec<String> = record
            .connection
            .prepare("select name from pragma_table_info('v_deal')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(&deal_columns[..5], VIEW_BASE_COLUMNS);
        assert!(deal_columns.contains(&"expected_close".to_owned()));
        let task_columns: Vec<String> = record
            .connection
            .prepare("select name from pragma_table_info('v_task')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            task_columns
                .iter()
                .filter(|c| c.as_str() == "title")
                .count(),
            1
        );

        record
            .extend_kind(
                "deal",
                "x_renewal_risk",
                serde_json::json!({"type": "string"}),
            )
            .unwrap();
        let deal_columns: Vec<String> = record
            .connection
            .prepare("select name from pragma_table_info('v_deal')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(deal_columns.contains(&"x_renewal_risk".to_owned()));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_newer_file_is_refused() {
        let path = temporary_graph("newer");
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        assert!(matches!(
            CompanyRecord::open(&path),
            Err(RecordError::UnsupportedSchema(_))
        ));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
