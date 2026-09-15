//! The read-only SQL tool. The agent is a data-science team on a read
//! replica, and on a laptop the replica is a second connection with every
//! control from the SQLite security guidance set at open and never changed
//! on a live connection. Every query lands in an audit file beside the graph.

use super::RecordError;
use rusqlite::config::DbConfig;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Rows a result may hold before it is cut.
pub const ROW_CAP: usize = 500;
/// Bytes a result's CSV may hold before it is cut.
pub const BYTE_CAP: usize = 64 * 1024;
/// Wall time one query may take before the progress handler interrupts it.
pub const TIME_LIMIT: Duration = Duration::from_secs(5);
/// The process-wide SQLite heap ceiling the tool installs.
pub const HEAP_LIMIT_BYTES: i64 = 512 * 1024 * 1024;
const PROGRESS_OPS: i32 = 1000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlResult {
    pub columns: Vec<String>,
    /// Header row, then one row per line. Empty cells are NULL.
    pub csv: String,
    pub row_count: usize,
    pub truncated: bool,
    pub elapsed_ms: u64,
}

/// A query the agent can correct: the message goes back to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlFailure {
    pub message: String,
    pub elapsed_ms: u64,
}

pub struct SqlTool {
    connection: Connection,
    audit: Connection,
    deadline: Arc<Mutex<Option<Instant>>>,
}

impl SqlTool {
    /// Opens the graph read-only with every limit set, and the audit file.
    pub fn open(graph: &Path, audit: &Path) -> Result<Self, RecordError> {
        let connection = Connection::open_with_flags(
            graph,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.pragma_update(None, "query_only", true)?;
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, true)?;
        for (limit, value) in [
            (Limit::SQLITE_LIMIT_ATTACHED, 0),
            (Limit::SQLITE_LIMIT_VDBE_OP, 25_000),
            (Limit::SQLITE_LIMIT_SQL_LENGTH, 100_000),
            (Limit::SQLITE_LIMIT_LENGTH, 1_000_000),
            (Limit::SQLITE_LIMIT_COLUMN, 100),
            (Limit::SQLITE_LIMIT_EXPR_DEPTH, 100),
            (Limit::SQLITE_LIMIT_COMPOUND_SELECT, 3),
            (Limit::SQLITE_LIMIT_FUNCTION_ARG, 8),
            (Limit::SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 50),
            (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 10),
            (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 10),
        ] {
            connection.set_limit(limit, value);
        }
        // SAFETY: sqlite3_hard_heap_limit64 takes one integer and touches no
        // pointer. It sets a process-wide ceiling and answers the prior one.
        unsafe {
            rusqlite::ffi::sqlite3_hard_heap_limit64(HEAP_LIMIT_BYTES);
        }
        connection.authorizer(Some(authorize));
        let deadline: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let watched = Arc::clone(&deadline);
        connection.progress_handler(
            PROGRESS_OPS,
            Some(move || {
                watched
                    .lock()
                    .map(|deadline| deadline.is_some_and(|deadline| Instant::now() > deadline))
                    .unwrap_or(true)
            }),
        );
        let audit = Connection::open(audit)?;
        audit.pragma_update(None, "journal_mode", "WAL")?;
        audit.execute_batch(
            "create table if not exists query (
                id text primary key,
                at text not null,
                principal text not null,
                sql text not null,
                row_count integer,
                byte_count integer,
                elapsed_ms integer not null,
                error text
            );",
        )?;
        Ok(Self {
            connection,
            audit,
            deadline,
        })
    }

    /// Runs one statement and records it. A SQL error is a result the agent
    /// reads, not a failure of the tool.
    pub fn run(
        &mut self,
        principal: &str,
        sql: &str,
    ) -> Result<Result<SqlResult, SqlFailure>, RecordError> {
        let started = Instant::now();
        if let Ok(mut deadline) = self.deadline.lock() {
            *deadline = Some(started + TIME_LIMIT);
        }
        let outcome = execute(&self.connection, sql);
        if let Ok(mut deadline) = self.deadline.lock() {
            *deadline = None;
        }
        let elapsed_ms = started.elapsed().as_millis() as u64;
        let outcome = match outcome {
            Ok((columns, csv, row_count, truncated)) => Ok(SqlResult {
                columns,
                csv,
                row_count,
                truncated,
                elapsed_ms,
            }),
            Err(error) => Err(SqlFailure {
                message: failure_message(&error),
                elapsed_ms,
            }),
        };
        self.audit.execute(
            "insert into query (id, at, principal, sql, row_count, byte_count, elapsed_ms, error)
             values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                uuid::Uuid::now_v7().to_string(),
                super::now_string(),
                principal,
                sql,
                outcome.as_ref().ok().map(|result| result.row_count as i64),
                outcome.as_ref().ok().map(|result| result.csv.len() as i64),
                elapsed_ms as i64,
                outcome
                    .as_ref()
                    .err()
                    .map(|failure| failure.message.clone()),
            ],
        )?;
        Ok(outcome)
    }

    /// The last queries in the audit file, newest first, for the review of
    /// what the agent keeps asking.
    pub fn recent_queries(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, Option<String>)>, RecordError> {
        let mut statement = self
            .audit
            .prepare("select sql, error from query order by at desc limit ?1")?;
        let rows = statement
            .query_map(params![limit as i64], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

fn authorize(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select
        | AuthAction::Read { .. }
        | AuthAction::Function { .. }
        | AuthAction::Recursive => Authorization::Allow,
        _ => Authorization::Deny,
    }
}

fn execute(
    connection: &Connection,
    sql: &str,
) -> Result<(Vec<String>, String, usize, bool), rusqlite::Error> {
    let mut statement = connection.prepare(sql)?;
    if !single_statement(sql, &statement) {
        return Err(rusqlite::Error::MultipleStatement);
    }
    let columns: Vec<String> = statement
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let mut csv = String::new();
    push_row(
        &mut csv,
        columns.iter().map(|column| column.as_str().to_owned()),
    );
    let mut rows = statement.query([])?;
    let mut row_count = 0;
    let mut truncated = false;
    while let Some(row) = rows.next()? {
        if row_count >= ROW_CAP || csv.len() >= BYTE_CAP {
            truncated = true;
            break;
        }
        let cells = (0..columns.len()).map(|index| cell_text(row.get_ref(index)));
        push_row(&mut csv, cells.map(|cell| cell.unwrap_or_default()));
        row_count += 1;
    }
    Ok((columns, csv, row_count, truncated))
}

/// SQLite prepares the first statement and keeps the rest as a tail rusqlite
/// does not expose, so the prepared text is compared with the input. With no
/// bound parameters the expanded text is the statement's own source.
fn single_statement(sql: &str, statement: &rusqlite::Statement<'_>) -> bool {
    let trim = |text: &str| text.trim().trim_end_matches(';').trim_end().to_owned();
    statement
        .expanded_sql()
        .is_some_and(|prepared| trim(&prepared) == trim(sql))
}

fn cell_text(value: Result<ValueRef<'_>, rusqlite::Error>) -> Option<String> {
    match value.ok()? {
        ValueRef::Null => None,
        ValueRef::Integer(number) => Some(number.to_string()),
        ValueRef::Real(number) => Some(number.to_string()),
        ValueRef::Text(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => Some(format!("<blob {} bytes>", bytes.len())),
    }
}

fn push_row(csv: &mut String, cells: impl Iterator<Item = String>) {
    let mut first = true;
    for cell in cells {
        if !first {
            csv.push(',');
        }
        first = false;
        if cell.contains([',', '"', '\n', '\r']) {
            csv.push('"');
            csv.push_str(&cell.replace('"', "\"\""));
            csv.push('"');
        } else {
            csv.push_str(&cell);
        }
    }
    csv.push('\n');
}

fn failure_message(error: &rusqlite::Error) -> String {
    match error {
        rusqlite::Error::SqliteFailure(code, Some(message))
            if code.code == rusqlite::ErrorCode::OperationInterrupted =>
        {
            format!(
                "the query ran past {} seconds and was stopped: {message}",
                TIME_LIMIT.as_secs()
            )
        }
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == rusqlite::ErrorCode::OperationInterrupted =>
        {
            format!(
                "the query ran past {} seconds and was stopped",
                TIME_LIMIT.as_secs()
            )
        }
        rusqlite::Error::SqliteFailure(_, Some(message)) => message.clone(),
        rusqlite::Error::MultipleStatement => "one statement per query".to_owned(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CompanyRecord, IdentityInput, Operation, PrincipalType};
    use super::*;
    use serde_json::json;

    fn fixture(label: &str) -> (std::path::PathBuf, SqlTool) {
        let directory =
            std::env::temp_dir().join(format!("muniment-sql-{label}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&directory).unwrap();
        let graph = directory.join("graph.sqlite3");
        let mut record = CompanyRecord::open(&graph).unwrap();
        let human = record
            .create_principal(PrincipalType::Human, "owner", None)
            .unwrap()
            .id;
        let proposal = record
            .propose(Operation::Create {
                kind: "org".into(),
                data: json!({"name": "Northwind, Traders", "industry": "Logistics"})
                    .as_object()
                    .unwrap()
                    .clone(),
                identities: vec![IdentityInput {
                    kind: "domain".into(),
                    value: "northwind.example".into(),
                }],
                links: vec![],
            })
            .unwrap();
        record.commit(&proposal.id, &human).unwrap();
        let tool = SqlTool::open(&graph, &directory.join("sql-audit.sqlite3")).unwrap();
        (directory, tool)
    }

    #[test]
    fn reads_views_as_csv_and_audits_the_query() {
        let (directory, mut tool) = fixture("reads");
        let result = tool
            .run("agent", "select name, industry from v_org order by name")
            .unwrap()
            .unwrap();
        assert_eq!(result.columns, ["name", "industry"]);
        assert_eq!(
            result.csv,
            "name,industry\n\"Northwind, Traders\",Logistics\n"
        );
        assert_eq!(result.row_count, 1);
        assert!(!result.truncated);
        let identities = tool
            .run("agent", "select kind, value from entity_identities")
            .unwrap()
            .unwrap();
        assert_eq!(identities.csv, "kind,value\ndomain,northwind.example\n");
        let recent = tool.recent_queries(10).unwrap();
        assert_eq!(recent.len(), 2);
        assert!(recent.iter().all(|(_, error)| error.is_none()));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn refuses_every_write_and_returns_the_error_to_the_agent() {
        let (directory, mut tool) = fixture("writes");
        for sql in [
            "insert into entity (id, kind, title, data, created_at, updated_at) values ('x', 'org', 'x', '{}', '', '')",
            "update entity set title = 'x'",
            "delete from entity",
            "create table t (x)",
            "drop table entity",
            "attach database ':memory:' as other",
            "pragma journal_mode = delete",
            "select 1; select 2",
        ] {
            let outcome = tool.run("agent", sql).unwrap();
            let failure = match outcome {
                Err(failure) => failure,
                Ok(result) => panic!("{sql} passed the read-only tool: {result:?}"),
            };
            assert!(!failure.message.is_empty(), "{sql}");
        }
        let count = tool
            .run("agent", "select count(*) as n from entity")
            .unwrap()
            .unwrap();
        assert_eq!(count.csv, "n\n1\n");
        let recent = tool.recent_queries(20).unwrap();
        assert_eq!(
            recent.iter().filter(|(_, error)| error.is_some()).count(),
            8
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn caps_rows_and_stops_a_runaway_query() {
        let (directory, mut tool) = fixture("caps");
        let result = tool
            .run(
                "agent",
                "with recursive n(x) as (select 1 union all select x + 1 from n where x < 2000) select x from n",
            )
            .unwrap()
            .unwrap();
        assert_eq!(result.row_count, ROW_CAP);
        assert!(result.truncated);

        let failure = tool
            .run(
                "agent",
                "with recursive n(x) as (select 1 union all select x + 1 from n) select count(*) from n",
            )
            .unwrap()
            .unwrap_err();
        assert!(failure.message.contains("stopped"), "{}", failure.message);
        assert!(failure.elapsed_ms >= TIME_LIMIT.as_millis() as u64);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
