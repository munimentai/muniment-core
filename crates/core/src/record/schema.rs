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
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(connection)
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
