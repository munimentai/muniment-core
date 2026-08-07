//! Rebuildable lexical search over the visible Muniment Home.

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{ambient_authority, fs::Dir};
use rusqlite::{params, Connection, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub const DEFAULT_ITEM_CAP: usize = 5;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(250);
const HOME_DIRECTORIES: [&str; 4] = ["agents", "memory", "projects", "sessions"];
const MAX_FILES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DIRECTORY_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetrievalLimits {
    pub item_cap: usize,
    pub character_budget: usize,
    pub timeout: Duration,
}

impl RetrievalLimits {
    pub fn defaults(minimum_cacheable_prefix_characters: usize) -> Self {
        Self {
            item_cap: DEFAULT_ITEM_CAP,
            character_budget: minimum_cacheable_prefix_characters,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn lowered_by(self, request: Option<Self>) -> Result<Self, MemoryIndexError> {
        let Some(request) = request else {
            return Ok(self);
        };
        if request.item_cap > self.item_cap
            || request.character_budget > self.character_budget
            || request.timeout > self.timeout
        {
            return Err(MemoryIndexError::LimitRaised);
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryItem {
    pub path: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallRecord {
    pub files: Vec<String>,
    pub item_cap: usize,
    pub character_budget: usize,
    pub timeout_milliseconds: u64,
    pub query: String,
    pub thread: String,
    pub source_file_state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySearchResult {
    pub items: Vec<MemoryItem>,
    pub recall: RecallRecord,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReindexReport {
    pub indexed: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: usize,
}

#[derive(Debug)]
pub enum MemoryIndexError {
    Io(io::Error),
    Sqlite(rusqlite::Error),
    LimitRaised,
    TimedOut,
    SecretRejected,
    InvalidPath,
    InvalidToolArguments,
}

impl From<io::Error> for MemoryIndexError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for MemoryIndexError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// One conversation-scoped declaration. Its serialized bytes never depend on a turn.
pub struct MemorySearchSession {
    tool_definition: Vec<u8>,
    declaration_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelMemoryCapability {
    pub minimum_cacheable_prefix_characters: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemorySearchCall {
    pub query: String,
    pub item_count: Option<usize>,
    pub character_budget: Option<usize>,
    pub timeout_milliseconds: Option<u64>,
}

/// Owns the selected Home, model limit, tool declaration, and recall receipts.
pub struct MemoryRuntimeSession {
    index: MemoryIndex,
    thread: String,
    configured: RetrievalLimits,
    declaration: MemorySearchSession,
    recalls: Vec<RecallRecord>,
}

impl MemoryRuntimeSession {
    pub fn open(
        home: impl Into<PathBuf>,
        database: impl Into<PathBuf>,
        thread: impl Into<String>,
        capability: ModelMemoryCapability,
    ) -> Self {
        Self::open_with_timeout(home, database, thread, capability, DEFAULT_TIMEOUT)
    }

    pub fn open_with_timeout(
        home: impl Into<PathBuf>,
        database: impl Into<PathBuf>,
        thread: impl Into<String>,
        capability: ModelMemoryCapability,
        timeout: Duration,
    ) -> Self {
        let mut configured =
            RetrievalLimits::defaults(capability.minimum_cacheable_prefix_characters);
        configured.timeout = timeout;
        Self {
            index: MemoryIndex::new(home, database),
            thread: thread.into(),
            configured,
            declaration: MemorySearchSession::default(),
            recalls: Vec::new(),
        }
    }

    pub fn tool_definition_for_turn(&self) -> &[u8] {
        self.declaration.tool_definition_for_turn()
    }

    pub fn tool_declaration_count(&self) -> usize {
        self.declaration.declaration_count()
    }

    pub fn call(&mut self, arguments: &[u8]) -> Result<MemorySearchResult, MemoryIndexError> {
        let call: MemorySearchCall = serde_json::from_slice(arguments)
            .map_err(|_| MemoryIndexError::InvalidToolArguments)?;
        let requested = if call.item_count.is_none()
            && call.character_budget.is_none()
            && call.timeout_milliseconds.is_none()
        {
            None
        } else {
            Some(RetrievalLimits {
                item_cap: call.item_count.unwrap_or(self.configured.item_cap),
                character_budget: call
                    .character_budget
                    .unwrap_or(self.configured.character_budget),
                timeout: Duration::from_millis(
                    call.timeout_milliseconds
                        .unwrap_or(self.configured.timeout.as_millis() as u64),
                ),
            })
        };
        let result = self
            .index
            .search(&self.thread, &call.query, self.configured, requested)?;
        self.recalls.push(result.recall.clone());
        Ok(result)
    }

    pub fn recall_records(&self) -> &[RecallRecord] {
        &self.recalls
    }
}

impl Default for MemorySearchSession {
    fn default() -> Self {
        let definition = json!({
            "name": "memory-search",
            "description": "Search the Markdown files in the Muniment Home.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "query": {"type": "string"},
                    "itemCount": {"type": "integer", "minimum": 0},
                    "characterBudget": {"type": "integer", "minimum": 0},
                    "timeoutMilliseconds": {"type": "integer", "minimum": 0}
                },
                "required": ["query"]
            }
        });
        Self {
            tool_definition: serde_json::to_vec(&definition).expect("static tool definition"),
            declaration_count: 1,
        }
    }
}

impl MemorySearchSession {
    pub fn tool_definition_for_turn(&self) -> &[u8] {
        &self.tool_definition
    }

    pub fn declaration_count(&self) -> usize {
        self.declaration_count
    }
}

pub struct MemoryIndex {
    home: PathBuf,
    database: PathBuf,
}

impl MemoryIndex {
    pub fn new(home: impl Into<PathBuf>, database: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            database: database.into(),
        }
    }

    pub fn search(
        &self,
        thread: &str,
        query: &str,
        configured: RetrievalLimits,
        requested: Option<RetrievalLimits>,
    ) -> Result<MemorySearchResult, MemoryIndexError> {
        let limits = configured.lowered_by(requested)?;
        if limits.timeout.is_zero() {
            return Err(MemoryIndexError::TimedOut);
        }
        let deadline = Instant::now() + limits.timeout;
        let mut connection = self.open(deadline)?;
        self.reindex_connection(&mut connection, deadline)
            .map_err(|error| normalize_timeout(error, deadline))?;
        check_deadline(deadline)?;

        let state = source_state(&connection).map_err(|error| sqlite_error(error, deadline))?;
        let mut items = Vec::new();
        if limits.item_cap > 0 && limits.character_budget > 0 && !query.trim().is_empty() {
            let expression = match_expression(query);
            if !expression.is_empty() {
                let mut statement = connection
                    .prepare(
                        "SELECT path, content FROM memory_fts WHERE memory_fts MATCH ?1 \
                     ORDER BY bm25(memory_fts), path LIMIT ?2",
                    )
                    .map_err(|error| sqlite_error(error, deadline))?;
                let rows =
                    statement.query_map(params![expression, limits.item_cap as i64], |row| {
                        Ok(MemoryItem {
                            path: row.get(0)?,
                            content: row.get(1)?,
                        })
                    })?;
                let mut used = 0;
                for row in rows {
                    check_deadline(deadline)?;
                    let mut item = row.map_err(|error| sqlite_error(error, deadline))?;
                    let remaining = limits.character_budget.saturating_sub(used);
                    if remaining == 0 {
                        break;
                    }
                    item.content = take_characters(&item.content, remaining);
                    used += item.content.chars().count();
                    items.push(item);
                }
            }
        }
        let files = items.iter().map(|item| item.path.clone()).collect();
        Ok(MemorySearchResult {
            items,
            recall: RecallRecord {
                files,
                item_cap: limits.item_cap,
                character_budget: limits.character_budget,
                timeout_milliseconds: limits.timeout.as_millis().min(u64::MAX as u128) as u64,
                query: query.to_owned(),
                thread: thread.to_owned(),
                source_file_state: state,
            },
        })
    }

    pub fn reindex(&self) -> Result<ReindexReport, MemoryIndexError> {
        self.reindex_with_deadline(Instant::now() + DEFAULT_TIMEOUT)
    }

    pub fn reindex_with_deadline(
        &self,
        deadline: Instant,
    ) -> Result<ReindexReport, MemoryIndexError> {
        let mut connection = self.open(deadline)?;
        self.reindex_connection(&mut connection, deadline)
            .map_err(|error| normalize_timeout(error, deadline))
    }

    fn open(&self, deadline: Instant) -> Result<Connection, MemoryIndexError> {
        if let Some(parent) = self.database.parent() {
            fs::create_dir_all(parent)?
        }
        let connection = Connection::open(&self.database)?;
        connection.progress_handler(100, Some(move || Instant::now() >= deadline));
        connection
            .execute_batch(
                "PRAGMA journal_mode = OFF;
             PRAGMA synchronous = OFF;
             PRAGMA temp_store = MEMORY;
             CREATE TABLE IF NOT EXISTS memory_files (
                path TEXT PRIMARY KEY NOT NULL,
                content_hash TEXT NOT NULL
             );
             CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(path UNINDEXED, content);",
            )
            .map_err(|error| sqlite_error(error, deadline))?;
        Ok(connection)
    }

    fn reindex_connection(
        &self,
        connection: &mut Connection,
        deadline: Instant,
    ) -> Result<ReindexReport, MemoryIndexError> {
        let documents = scan_home(&self.home, deadline)?;
        let transaction = connection.transaction()?;
        let existing = existing_hashes(&transaction)?;
        let mut report = ReindexReport::default();
        for (path, document) in &documents {
            check_deadline(deadline)?;
            if existing.get(path) == Some(&document.hash) {
                report.unchanged += 1;
                continue;
            }
            transaction.execute("DELETE FROM memory_fts WHERE path = ?1", [path])?;
            transaction.execute(
                "INSERT INTO memory_fts(path, content) VALUES (?1, ?2)",
                params![path, document.content],
            )?;
            transaction.execute(
                "INSERT INTO memory_files(path, content_hash) VALUES (?1, ?2)
                 ON CONFLICT(path) DO UPDATE SET content_hash = excluded.content_hash",
                params![path, document.hash],
            )?;
            report.indexed.push(path.clone());
        }
        for path in existing
            .keys()
            .filter(|path| !documents.contains_key(*path))
        {
            check_deadline(deadline)?;
            transaction.execute("DELETE FROM memory_fts WHERE path = ?1", [path])?;
            transaction.execute("DELETE FROM memory_files WHERE path = ?1", [path])?;
            report.removed.push(path.clone());
        }
        transaction.commit()?;
        Ok(report)
    }
}

fn sqlite_error(error: rusqlite::Error, deadline: Instant) -> MemoryIndexError {
    if Instant::now() >= deadline {
        MemoryIndexError::TimedOut
    } else {
        MemoryIndexError::Sqlite(error)
    }
}

fn normalize_timeout(error: MemoryIndexError, deadline: Instant) -> MemoryIndexError {
    if Instant::now() >= deadline {
        MemoryIndexError::TimedOut
    } else {
        error
    }
}

struct Document {
    content: String,
    hash: String,
}

fn scan_home(
    home: &Path,
    deadline: Instant,
) -> Result<BTreeMap<String, Document>, MemoryIndexError> {
    let home = home.to_owned();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(scan_home_with_hook(&home, deadline, || {}));
    });
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| MemoryIndexError::TimedOut)?
}

fn scan_home_with_hook(
    home: &Path,
    deadline: Instant,
    after_collection: impl FnOnce(),
) -> Result<BTreeMap<String, Document>, MemoryIndexError> {
    let home_directory = open_home_directory(home)?;
    let mut files = Vec::new();
    for directory in HOME_DIRECTORIES {
        let Ok(open_directory) = home_directory.open_dir_nofollow(directory) else {
            continue;
        };
        collect_markdown(
            &open_directory,
            Path::new(directory),
            &mut files,
            0,
            deadline,
        )?;
    }
    files.sort();
    files.truncate(MAX_FILES);
    after_collection();
    let mut documents = BTreeMap::new();
    for path in files {
        check_deadline(deadline)?;
        let Ok(file) = open_relative_file(&home_directory, &path) else {
            continue;
        };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_FILE_BYTES {
            continue;
        }
        let bytes = read_utf8_bytes_blocking(file, metadata.len() as usize, deadline)?;
        let Ok(content) = String::from_utf8(bytes) else {
            continue;
        };
        let relative = path.to_string_lossy().replace('\\', "/");
        let hash = format!("{:x}", Sha256::digest(content.as_bytes()));
        documents.insert(relative, Document { content, hash });
    }
    Ok(documents)
}

fn open_home_directory(home: &Path) -> Result<Dir, MemoryIndexError> {
    let parent = home.parent().ok_or(MemoryIndexError::InvalidPath)?;
    let name = home.file_name().ok_or(MemoryIndexError::InvalidPath)?;
    let parent = Dir::open_ambient_dir(parent, ambient_authority())?;
    parent.open_dir_nofollow(name).map_err(MemoryIndexError::Io)
}

fn open_relative_file(home: &Dir, relative: &Path) -> io::Result<fs::File> {
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let name = relative
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid memory path"))?;
    let mut directory = home.try_clone()?;
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid memory path",
            ));
        };
        directory = directory.open_dir_nofollow(component)?;
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    directory
        .open_with(name, &options)
        .map(|file| file.into_std())
}

#[cfg(test)]
fn read_utf8_bytes(
    reader: impl Read + Send + 'static,
    capacity: usize,
    deadline: Instant,
) -> Result<Vec<u8>, MemoryIndexError> {
    check_deadline(deadline)?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = read_utf8_bytes_blocking(reader, capacity, deadline);
        let _ = sender.send(result);
    });
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| MemoryIndexError::TimedOut)?
}

fn read_utf8_bytes_blocking(
    mut reader: impl Read,
    capacity: usize,
    deadline: Instant,
) -> Result<Vec<u8>, MemoryIndexError> {
    let mut bytes = Vec::with_capacity(capacity.min(MAX_FILE_BYTES as usize));
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        check_deadline(deadline)?;
        let remaining = (MAX_FILE_BYTES as usize + 1).saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(MemoryIndexError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "memory file exceeds the size limit",
            )));
        }
        let amount = chunk.len().min(remaining);
        let read = reader.read(&mut chunk[..amount])?;
        if read == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_FILE_BYTES as usize {
            return Err(MemoryIndexError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "memory file exceeds the size limit",
            )));
        }
    }
}

fn collect_markdown(
    directory: &Dir,
    relative_directory: &Path,
    files: &mut Vec<PathBuf>,
    depth: usize,
    deadline: Instant,
) -> Result<(), MemoryIndexError> {
    check_deadline(deadline)?;
    if depth > MAX_DIRECTORY_DEPTH {
        return Ok(());
    }
    let mut entries = directory.entries()?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        check_deadline(deadline)?;
        if files.len() >= MAX_FILES {
            break;
        }
        let kind = entry.file_type()?;
        let path = relative_directory.join(entry.file_name());
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            let child = directory.open_dir_nofollow(entry.file_name())?;
            collect_markdown(&child, &path, files, depth + 1, deadline)?;
        } else if kind.is_file()
            && path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("md"))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn existing_hashes(
    transaction: &Transaction<'_>,
) -> Result<BTreeMap<String, String>, rusqlite::Error> {
    let mut statement = transaction.prepare("SELECT path, content_hash FROM memory_files")?;
    let hashes = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect();
    hashes
}

fn source_state(connection: &Connection) -> Result<String, rusqlite::Error> {
    let mut statement =
        connection.prepare("SELECT path, content_hash FROM memory_files ORDER BY path")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut digest = Sha256::new();
    for row in rows {
        let (path, hash) = row?;
        digest.update(path.as_bytes());
        digest.update([0]);
        digest.update(hash.as_bytes());
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn match_expression(query: &str) -> String {
    query
        .split_whitespace()
        .map(|term| {
            term.trim_matches(|character: char| !character.is_alphanumeric() && character != '_')
        })
        .filter(|term| !term.is_empty())
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn take_characters(value: &str, count: usize) -> String {
    value.chars().take(count).collect()
}

fn check_deadline(deadline: Instant) -> Result<(), MemoryIndexError> {
    if Instant::now() >= deadline {
        Err(MemoryIndexError::TimedOut)
    } else {
        Ok(())
    }
}

/// Writes one relative Home record after the shared secret rules accept it.
pub fn write_memory_record(
    home: &Path,
    relative: &Path,
    content: &str,
) -> Result<(), MemoryIndexError> {
    if crate::home::memory_record_contains_secret(content) {
        return Err(MemoryIndexError::SecretRejected);
    }
    if relative.is_absolute()
        || relative.extension().and_then(|value| value.to_str()) != Some("md")
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || !relative.components().next().is_some_and(|part| {
            HOME_DIRECTORIES
                .iter()
                .any(|directory| part.as_os_str() == *directory)
        })
    {
        return Err(MemoryIndexError::InvalidPath);
    }
    let plan = crate::home::OnboardingHomeWritePlan {
        writes: vec![crate::home::HomeWrite {
            relative_path: relative.to_string_lossy().replace('\\', "/"),
            contents: content.to_owned(),
        }],
    };
    crate::home::persist_onboarding_home_write_plan(home, &plan).map_err(|error| match error {
        crate::home::OnboardingHomePersistenceError::SecretRejected => {
            MemoryIndexError::SecretRejected
        }
        crate::home::OnboardingHomePersistenceError::InvalidHome
        | crate::home::OnboardingHomePersistenceError::InvalidPlan => MemoryIndexError::InvalidPath,
        crate::home::OnboardingHomePersistenceError::Io(error) => MemoryIndexError::Io(error),
        other => MemoryIndexError::Io(io::Error::other(other.to_string())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "muniment-memory-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(root.join("memory")).unwrap();
            Self { root }
        }
        fn file(&self, name: &str, content: &str) {
            fs::write(self.root.join("memory").join(name), content).unwrap()
        }
        fn index(&self) -> MemoryIndex {
            MemoryIndex::new(&self.root, self.root.join("cache/index.sqlite3"))
        }
        fn limits(items: usize, characters: usize) -> RetrievalLimits {
            RetrievalLimits {
                item_cap: items,
                character_budget: characters,
                timeout: Duration::from_secs(5),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn deleted_database_rebuilds_from_files() {
        let fixture = Fixture::new();
        fixture.file("one.md", "orchid fact");
        fixture.file("two.md", "another orchid fact");
        let before = fixture
            .index()
            .search("thread", "orchid", Fixture::limits(5, 1000), None)
            .unwrap();
        fs::remove_file(fixture.root.join("cache/index.sqlite3")).unwrap();
        let after = fixture
            .index()
            .search("thread", "orchid", Fixture::limits(5, 1000), None)
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(after.items.len(), 2);
    }

    #[test]
    fn edit_reindexes_only_changed_file() {
        let fixture = Fixture::new();
        for number in 0..8 {
            fixture.file(&format!("{number}.md"), "stable pear");
        }
        assert_eq!(
            fixture
                .index()
                .reindex_with_deadline(Instant::now() + Duration::from_secs(60))
                .unwrap()
                .indexed
                .len(),
            8
        );
        fixture.file("3.md", "changed pear");
        let report = fixture
            .index()
            .reindex_with_deadline(Instant::now() + Duration::from_secs(60))
            .unwrap();
        assert_eq!(report.indexed, ["memory/3.md"]);
        assert_eq!(report.unchanged, 7);
        assert!(report.removed.is_empty());
    }

    #[test]
    fn result_obeys_both_caps() {
        let fixture = Fixture::new();
        for number in 0..10 {
            fixture.file(
                &format!("{number}.md"),
                &format!("cobalt {}", "x".repeat(100)),
            );
        }
        let result = fixture
            .index()
            .search("thread", "cobalt", Fixture::limits(3, 47), None)
            .unwrap();
        assert!(result.items.len() <= 3);
        assert_eq!(result.items.len(), 1);
        assert!(
            result
                .items
                .iter()
                .map(|item| item.content.chars().count())
                .sum::<usize>()
                <= 47
        );
        assert_eq!(
            result
                .items
                .iter()
                .map(|item| item.content.chars().count())
                .sum::<usize>(),
            47
        );
    }

    #[test]
    fn selection_is_stable_in_thread() {
        let fixture = Fixture::new();
        for number in 0..7 {
            fixture.file(&format!("{number}.md"), "violet equal rank");
        }
        fixture
            .index()
            .reindex_with_deadline(Instant::now() + Duration::from_secs(60))
            .unwrap();
        let connection = Connection::open(fixture.root.join("cache/index.sqlite3")).unwrap();
        connection.execute("DELETE FROM memory_fts", []).unwrap();
        for number in (0..7).rev() {
            connection
                .execute(
                    "INSERT INTO memory_fts(path, content) VALUES (?1, ?2)",
                    params![format!("memory/{number}.md"), "violet equal rank"],
                )
                .unwrap();
        }
        let first = fixture
            .index()
            .search("same-thread", "violet", Fixture::limits(5, 1000), None)
            .unwrap();
        let second = fixture
            .index()
            .search("same-thread", "violet", Fixture::limits(5, 1000), None)
            .unwrap();
        assert_eq!(first.items, second.items);
        assert_eq!(first.items.len(), 5);
        assert_eq!(
            first
                .items
                .iter()
                .map(|item| item.path.as_str())
                .collect::<Vec<_>>(),
            [
                "memory/0.md",
                "memory/1.md",
                "memory/2.md",
                "memory/3.md",
                "memory/4.md"
            ]
        );
    }

    #[test]
    fn tool_definition_is_byte_identical_between_turns() {
        let session = MemorySearchSession::default();
        let first = session.tool_definition_for_turn().to_vec();
        let second = session.tool_definition_for_turn().to_vec();
        assert_eq!(first, second);
        assert!(!first.is_empty());
        assert_eq!(session.declaration_count(), 1);
    }

    #[test]
    fn runtime_session_declares_once_and_records_real_searches_across_turns() {
        let fixture = Fixture::new();
        let mut session = MemoryRuntimeSession::open_with_timeout(
            &fixture.root,
            fixture.root.join("cache/runtime.sqlite3"),
            "thread-runtime",
            ModelMemoryCapability {
                minimum_cacheable_prefix_characters: 30,
            },
            Duration::from_secs(60),
        );
        let first_definition = session.tool_definition_for_turn().as_ptr();
        let first = session.call(br#"{"query":"saffron"}"#).unwrap();
        let second_definition = session.tool_definition_for_turn().as_ptr();
        let second = session.call(br#"{"query":"saffron"}"#).unwrap();

        assert_eq!(first_definition, second_definition);
        assert_eq!(session.tool_declaration_count(), 1);
        assert_eq!(first.items, second.items);
        assert!(first.items.is_empty());
        assert_eq!(session.recall_records(), &[first.recall, second.recall]);
        assert_eq!(session.recall_records()[0].character_budget, 30);
    }

    #[test]
    fn write_rejects_credential_shaped_record() {
        let fixture = Fixture::new();
        let path = Path::new("memory/rejected.md");
        let result = write_memory_record(
            &fixture.root,
            path,
            "api_key = sk-proj-abcdefghijklmnopqrstuvwxyz123456",
        );
        assert!(matches!(result, Err(MemoryIndexError::SecretRejected)));
        assert!(!fixture.root.join(path).exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_cannot_follow_replaced_parent_outside_home() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let outside = Fixture::new();
        symlink(
            outside.root.join("memory"),
            fixture.root.join("memory/link"),
        )
        .unwrap();
        let result = write_memory_record(
            &fixture.root,
            Path::new("memory/link/escaped.md"),
            "safe text",
        );
        assert!(result.is_err());
        assert!(!outside.root.join("memory/escaped.md").exists());
    }

    #[test]
    fn raised_limits_and_zero_boundaries_fail_closed() {
        assert_eq!(
            RetrievalLimits::defaults(8_192),
            RetrievalLimits {
                item_cap: 5,
                character_budget: 8_192,
                timeout: Duration::from_millis(250),
            }
        );
        let configured = Fixture::limits(5, 100);
        assert!(matches!(
            configured.lowered_by(Some(Fixture::limits(6, 100))),
            Err(MemoryIndexError::LimitRaised)
        ));
        let fixture = Fixture::new();
        fixture.file("one.md", "amber fact");
        let empty = fixture
            .index()
            .search("thread", "amber", Fixture::limits(0, 0), None)
            .unwrap();
        assert!(empty.items.is_empty());
        assert_eq!(empty.recall.files, Vec::<String>::new());
        assert_eq!(empty.recall.item_cap, 0);
        assert_eq!(empty.recall.character_budget, 0);
        assert_eq!(empty.recall.query, "amber");
        assert_eq!(empty.recall.thread, "thread");
        assert_eq!(empty.recall.source_file_state.len(), 64);
        assert!(matches!(
            fixture.index().search(
                "thread",
                "amber",
                RetrievalLimits {
                    timeout: Duration::ZERO,
                    ..configured
                },
                None
            ),
            Err(MemoryIndexError::TimedOut)
        ));
    }

    #[test]
    fn file_read_uses_the_search_deadline() {
        struct SlowReader;
        impl Read for SlowReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                std::thread::sleep(Duration::from_millis(5));
                buffer[0] = b'x';
                Ok(1)
            }
        }

        let result = read_utf8_bytes(SlowReader, 1, Instant::now() + Duration::from_millis(1));
        assert!(matches!(result, Err(MemoryIndexError::TimedOut)));
    }

    #[cfg(unix)]
    #[test]
    fn replacement_during_scan_cannot_index_outside_content() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let outside = Fixture::new();
        fixture.file("replace.md", "inside marigold");
        outside.file("secret.md", "outside marigold credential");
        let selected = fixture.root.join("memory/replace.md");
        let result = scan_home_with_hook(
            &fixture.root,
            Instant::now() + Duration::from_secs(5),
            || {
                fs::remove_file(&selected).unwrap();
                symlink(outside.root.join("memory/secret.md"), &selected).unwrap();
            },
        )
        .unwrap();

        assert!(!result.contains_key("memory/replace.md"));
        assert!(result
            .values()
            .all(|document| !document.content.contains("outside marigold credential")));
    }
}
