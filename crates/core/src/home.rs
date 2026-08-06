use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{ambient_authority, fs::Dir};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
};

use crate::import_preview::ExtractedEntry;

const CONFIG_FILE: &str = "home.json";
const HOME_DIRECTORIES: [&str; 4] = ["memory", "agents", "projects", "sessions"];
const ONBOARDING_IMPORT_MAX_SLUG_BYTES: usize = 48;

/// Maximum number of approved originals in one onboarding write plan.
pub const ONBOARDING_IMPORT_MAX_ENTRIES: usize = 128;
/// Maximum size of any Markdown payload in one onboarding write plan.
pub const ONBOARDING_IMPORT_MAX_DOCUMENT_BYTES: usize = 64 * 1024;
/// Maximum combined size of all Markdown payloads in one onboarding write plan.
pub const ONBOARDING_IMPORT_MAX_TOTAL_BYTES: usize = 256 * 1024;
const ONBOARDING_IMPORT_LOCK_FILE: &str = ".onboarding-import.lock";
const ONBOARDING_IMPORT_MAX_PLAN_WRITES: usize = ONBOARDING_IMPORT_MAX_ENTRIES + 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HomeWrite {
    /// A normalized, `/`-separated path relative to Muniment Home.
    pub relative_path: String,
    /// The complete UTF-8 Markdown file contents.
    pub contents: String,
}

impl HomeWrite {
    pub fn relative_path(&self) -> &Path {
        Path::new(&self.relative_path)
    }

    pub fn bytes(&self) -> &[u8] {
        self.contents.as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingHomeWritePlan {
    pub writes: Vec<HomeWrite>,
}

impl OnboardingHomeWritePlan {
    pub fn writes(&self) -> &[HomeWrite] {
        &self.writes
    }
}

/// An explicit import time accepted by the pure plan compiler.
pub trait OnboardingImportTimestamp {
    fn import_date(self) -> Result<chrono::NaiveDate, OnboardingHomeWritePlanError>;
}

impl OnboardingImportTimestamp for chrono::NaiveDate {
    fn import_date(self) -> Result<chrono::NaiveDate, OnboardingHomeWritePlanError> {
        Ok(self)
    }
}

impl OnboardingImportTimestamp for &str {
    fn import_date(self) -> Result<chrono::NaiveDate, OnboardingHomeWritePlanError> {
        chrono::DateTime::parse_from_rfc3339(self)
            .map(|timestamp| timestamp.date_naive())
            .map_err(|_| OnboardingHomeWritePlanError::InvalidTimestamp)
    }
}

/// Stable failure modes for compiling approved onboarding files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingHomeWritePlanError {
    EmptyInput,
    InvalidTimestamp,
    UnsafeMetadata,
    TooManyEntries,
    DocumentBytesExceeded,
    DestinationCollision,
    TotalBytesExceeded,
}

impl fmt::Display for OnboardingHomeWritePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyInput => "The onboarding import input is empty.",
            Self::InvalidTimestamp => "The onboarding import timestamp is invalid.",
            Self::UnsafeMetadata => "The onboarding import metadata is unsafe.",
            Self::TooManyEntries => "The onboarding import contains too many entries.",
            Self::DocumentBytesExceeded => "An onboarding import document is too large.",
            Self::DestinationCollision => "The onboarding import destinations collide.",
            Self::TotalBytesExceeded => "The onboarding import plan is too large.",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OnboardingHomeWritePlanError {}

/// Stable failure modes for persisting a confirmed onboarding write plan.
#[derive(Debug)]
pub enum OnboardingHomePersistenceError {
    InvalidHome,
    InvalidPlan,
    TooManyEntries,
    DocumentBytesExceeded,
    TotalBytesExceeded,
    DestinationConflict { relative_path: String },
    Io(io::Error),
}

impl fmt::Display for OnboardingHomePersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHome => formatter.write_str("The Muniment Home is invalid."),
            Self::InvalidPlan => formatter.write_str("The onboarding write plan is invalid."),
            Self::TooManyEntries => {
                formatter.write_str("The onboarding write plan contains too many entries.")
            }
            Self::DocumentBytesExceeded => {
                formatter.write_str("An onboarding write plan document is too large.")
            }
            Self::TotalBytesExceeded => {
                formatter.write_str("The onboarding write plan is too large.")
            }
            Self::DestinationConflict { relative_path } => {
                write!(
                    formatter,
                    "The onboarding destination already exists: {relative_path}"
                )
            }
            Self::Io(_) => formatter.write_str("The onboarding write plan could not be saved."),
        }
    }
}

impl std::error::Error for OnboardingHomePersistenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for OnboardingHomePersistenceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Persists a confirmed write plan without replacing any existing Home entry.
pub fn persist_onboarding_home_write_plan(
    home: &Path,
    plan: &OnboardingHomeWritePlan,
) -> Result<(), OnboardingHomePersistenceError> {
    persist_onboarding_home_write_plan_with_hook(
        home,
        plan,
        |_, file| file.sync_all(),
        |_, _| Ok(()),
        |_, parent, temporary_name| parent.remove_file(temporary_name),
    )
}

fn persist_onboarding_home_write_plan_with_hook(
    home: &Path,
    plan: &OnboardingHomeWritePlan,
    mut stage_sync: impl FnMut(usize, &File) -> io::Result<()>,
    mut before_publish: impl FnMut(usize, &Dir) -> io::Result<()>,
    mut remove_temporary: impl FnMut(usize, &Dir, &str) -> io::Result<()>,
) -> Result<(), OnboardingHomePersistenceError> {
    let relative_destinations = validate_persistence_plan(plan)?;
    let home = validate_persistence_home(home)?;
    let home_dir = open_validated_home(&home)?;
    let mut lock_options = cap_std::fs::OpenOptions::new();
    lock_options
        .create(true)
        .read(true)
        .write(true)
        .follow(FollowSymlinks::No);
    let lock = home_dir
        .open_with(ONBOARDING_IMPORT_LOCK_FILE, &lock_options)?
        .into_std();
    lock.lock_exclusive()?;

    for (relative_path, destination) in &relative_destinations {
        match home_dir.symlink_metadata(destination) {
            Ok(_) => {
                return Err(OnboardingHomePersistenceError::DestinationConflict {
                    relative_path: relative_path.clone(),
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    struct StagedWrite {
        relative_path: String,
        parent_path: PathBuf,
        parent: Dir,
        destination_name: std::ffi::OsString,
        temporary_name: String,
        identity: Option<same_file::Handle>,
    }

    let mut staged = Vec::with_capacity(plan.writes.len());
    let mut published = Vec::with_capacity(plan.writes.len());
    let result = (|| {
        for (index, ((relative_path, destination), write)) in
            relative_destinations.iter().zip(&plan.writes).enumerate()
        {
            let parent_path = destination
                .parent()
                .ok_or(OnboardingHomePersistenceError::InvalidPlan)?;
            let parent = create_import_parent_directories(&home_dir, parent_path)?;
            let destination_name = destination
                .file_name()
                .ok_or(OnboardingHomePersistenceError::InvalidPlan)?
                .to_owned();
            let temporary_name = format!(
                ".{}.{}.tmp",
                destination_name
                    .to_str()
                    .ok_or(OnboardingHomePersistenceError::InvalidPlan)?,
                uuid::Uuid::new_v4()
            );
            let mut options = cap_std::fs::OpenOptions::new();
            options
                .create_new(true)
                .write(true)
                .follow(FollowSymlinks::No);
            let mut file = parent.open_with(&temporary_name, &options)?.into_std();
            staged.push(StagedWrite {
                relative_path: relative_path.clone(),
                parent_path: parent_path.to_owned(),
                parent,
                destination_name,
                temporary_name,
                identity: None,
            });
            file.write_all(write.bytes())?;
            file.flush()?;
            stage_sync(index, &file)?;
            let identity = same_file::Handle::from_file(file.try_clone()?)?;
            staged[index].identity = Some(identity);
        }

        for (index, write) in staged.iter().enumerate() {
            before_publish(index, &write.parent)?;
            let current_parent = open_existing_parent(&home_dir, &write.parent_path)
                .map_err(|_| OnboardingHomePersistenceError::InvalidPlan)?;
            if !same_open_directory(&write.parent, &current_parent)? {
                return Err(OnboardingHomePersistenceError::InvalidPlan);
            }
            write
                .parent
                .hard_link(
                    &write.temporary_name,
                    &write.parent,
                    &write.destination_name,
                )
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        OnboardingHomePersistenceError::DestinationConflict {
                            relative_path: write.relative_path.clone(),
                        }
                    } else {
                        error.into()
                    }
                })?;
            published.push(index);
            sync_open_directory(&write.parent)?;
        }
        Ok(())
    })();

    for (index, write) in staged.iter().enumerate() {
        let _ = remove_temporary(index, &write.parent, &write.temporary_name);
    }
    for write in &staged {
        let _ = sync_open_directory(&write.parent);
    }
    if result.is_err() {
        for &index in published.iter().rev() {
            let write = &staged[index];
            if is_published_file(
                &write.parent,
                &write.destination_name,
                write
                    .identity
                    .as_ref()
                    .expect("published writes have a recorded identity"),
            )
            .unwrap_or(false)
            {
                let _ = write.parent.remove_file(&write.destination_name);
            }
        }
        for write in &staged {
            let _ = sync_open_directory(&write.parent);
        }
    }
    result
}

fn validate_persistence_plan(
    plan: &OnboardingHomeWritePlan,
) -> Result<Vec<(String, PathBuf)>, OnboardingHomePersistenceError> {
    if plan.writes.is_empty() {
        return Err(OnboardingHomePersistenceError::InvalidPlan);
    }
    if plan.writes.len() > ONBOARDING_IMPORT_MAX_PLAN_WRITES {
        return Err(OnboardingHomePersistenceError::TooManyEntries);
    }
    let mut unique = BTreeSet::new();
    let mut total_bytes = 0usize;
    let mut relative_paths = Vec::with_capacity(plan.writes.len());
    for write in &plan.writes {
        let path = Path::new(&write.relative_path);
        let mut segments = write.relative_path.split('/');
        if write.relative_path.is_empty()
            || write.relative_path.contains('\0')
            || write.relative_path.contains('\\')
            || write.relative_path.starts_with('/')
            || segments
                .next()
                .is_some_and(|segment| segment.ends_with(':'))
            || segments.any(|segment| segment.is_empty() || segment == "." || segment == "..")
            || path.is_absolute()
            || !write.relative_path.ends_with(".md")
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || !unique.insert(write.relative_path.to_ascii_lowercase())
        {
            return Err(OnboardingHomePersistenceError::InvalidPlan);
        }
        if write.bytes().len() > ONBOARDING_IMPORT_MAX_DOCUMENT_BYTES {
            return Err(OnboardingHomePersistenceError::DocumentBytesExceeded);
        }
        total_bytes = total_bytes
            .checked_add(write.bytes().len())
            .ok_or(OnboardingHomePersistenceError::TotalBytesExceeded)?;
        if total_bytes > ONBOARDING_IMPORT_MAX_TOTAL_BYTES {
            return Err(OnboardingHomePersistenceError::TotalBytesExceeded);
        }
        relative_paths.push((write.relative_path.clone(), path.to_path_buf()));
    }
    Ok(relative_paths)
}

fn validate_persistence_home(home: &Path) -> Result<PathBuf, OnboardingHomePersistenceError> {
    validate_home(home).map_err(|_| OnboardingHomePersistenceError::InvalidHome)?;
    let selected_metadata =
        fs::symlink_metadata(home).map_err(|_| OnboardingHomePersistenceError::InvalidHome)?;
    if selected_metadata.file_type().is_symlink() || !selected_metadata.is_dir() {
        return Err(OnboardingHomePersistenceError::InvalidHome);
    }
    let home = fs::canonicalize(home).map_err(|_| OnboardingHomePersistenceError::InvalidHome)?;
    validate_home(&home).map_err(|_| OnboardingHomePersistenceError::InvalidHome)?;
    Ok(home)
}

fn open_validated_home(home: &Path) -> Result<Dir, OnboardingHomePersistenceError> {
    let parent = home
        .parent()
        .ok_or(OnboardingHomePersistenceError::InvalidHome)?;
    let name = home
        .file_name()
        .ok_or(OnboardingHomePersistenceError::InvalidHome)?;
    let parent = Dir::open_ambient_dir(parent, ambient_authority())
        .map_err(|_| OnboardingHomePersistenceError::InvalidHome)?;
    parent
        .open_dir_nofollow(name)
        .map_err(|_| OnboardingHomePersistenceError::InvalidHome)
}

fn create_import_parent_directories(
    home: &Dir,
    parent: &Path,
) -> Result<Dir, OnboardingHomePersistenceError> {
    let mut current = home.try_clone()?;
    for component in parent.components() {
        let name = component.as_os_str();
        match current.open_dir_nofollow(name) {
            Ok(next) => current = next,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match current.create_dir(name) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
                sync_open_directory(&current)?;
                current = current
                    .open_dir_nofollow(name)
                    .map_err(|_| OnboardingHomePersistenceError::InvalidPlan)?;
            }
            Err(_) => return Err(OnboardingHomePersistenceError::InvalidPlan),
        }
    }
    Ok(current)
}

fn open_existing_parent(home: &Dir, parent: &Path) -> io::Result<Dir> {
    let mut current = home.try_clone()?;
    for component in parent.components() {
        current = current.open_dir_nofollow(component.as_os_str())?;
    }
    Ok(current)
}

#[cfg(unix)]
fn same_open_directory(first: &Dir, second: &Dir) -> io::Result<bool> {
    use cap_fs_ext::MetadataExt;
    let first = first.dir_metadata()?;
    let second = second.dir_metadata()?;
    Ok(first.dev() == second.dev() && first.ino() == second.ino())
}

#[cfg(windows)]
fn same_open_directory(first: &Dir, second: &Dir) -> io::Result<bool> {
    Ok(
        same_file::Handle::from_file(first.try_clone()?.into_std_file())?
            == same_file::Handle::from_file(second.try_clone()?.into_std_file())?,
    )
}

fn is_published_file(
    parent: &Dir,
    destination: impl AsRef<Path>,
    identity: &same_file::Handle,
) -> io::Result<bool> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let destination = parent.open_with(destination, &options)?.into_std();
    Ok(same_file::Handle::from_file(destination)? == *identity)
}

#[cfg(not(target_os = "windows"))]
fn sync_open_directory(directory: &Dir) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe { fs::File::from_raw_fd(descriptor) }.sync_all()
}

#[cfg(target_os = "windows")]
fn sync_open_directory(_directory: &Dir) -> io::Result<()> {
    Ok(())
}

/// Compiles complete, bounded Markdown writes without accessing the filesystem.
pub fn compile_onboarding_home_write_plan<T: OnboardingImportTimestamp>(
    approved_entries: &[ExtractedEntry],
    import_timestamp: T,
) -> Result<OnboardingHomeWritePlan, OnboardingHomeWritePlanError> {
    let import_date = import_timestamp
        .import_date()?
        .format("%Y-%m-%d")
        .to_string();
    if approved_entries.is_empty()
        || approved_entries.iter().any(|entry| {
            entry.source_name.trim().is_empty()
                || entry.source_provenance.trim().is_empty()
                || entry.text.is_empty()
        })
    {
        return Err(OnboardingHomeWritePlanError::EmptyInput);
    }
    if approved_entries.len() > ONBOARDING_IMPORT_MAX_ENTRIES {
        return Err(OnboardingHomeWritePlanError::TooManyEntries);
    }

    let mut destinations = Vec::with_capacity(approved_entries.len());
    let mut total_bytes = 0;

    for (index, entry) in approved_entries.iter().enumerate() {
        reject_unsafe_metadata(&entry.source_name)?;
        reject_unsafe_metadata(&entry.source_provenance)?;
        let mut identity = entry.source_provenance.as_bytes().to_vec();
        identity.push(0);
        identity.extend_from_slice(entry.source_name.as_bytes());
        identity.extend_from_slice(&(index as u64).to_be_bytes());
        destinations.push(format!(
            "memory/imports/{import_date}-{}-{}.md",
            safe_slug(&entry.source_name),
            short_digest(&identity)
        ));
        let provenance_len = json_string_len(&entry.source_provenance)?;
        let frontmatter_len = "---\nsource: \nimport_date: \n---\n"
            .len()
            .checked_add(provenance_len)
            .and_then(|length| length.checked_add(import_date.len()))
            .ok_or(OnboardingHomeWritePlanError::DocumentBytesExceeded)?;
        add_payload_len(
            &mut total_bytes,
            frontmatter_len
                .checked_add(entry.text.len())
                .ok_or(OnboardingHomeWritePlanError::DocumentBytesExceeded)?,
        )?;
    }

    let mut unique_destinations = BTreeSet::new();
    if destinations
        .iter()
        .any(|path| !unique_destinations.insert(path.clone()))
    {
        return Err(OnboardingHomeWritePlanError::DestinationCollision);
    }

    let mut writes = Vec::with_capacity(destinations.len());
    let mut destinations = destinations.into_iter();
    for entry in approved_entries {
        let mut contents = format!(
            "---\nsource: {}\nimport_date: {}\n---\n",
            yaml_string(&entry.source_provenance),
            import_date
        );
        contents.push_str(&entry.text);
        writes.push(HomeWrite {
            relative_path: destinations.next().expect("entry destination exists"),
            contents,
        });
    }
    Ok(OnboardingHomeWritePlan { writes })
}

fn add_payload_len(
    total: &mut usize,
    payload_len: usize,
) -> Result<(), OnboardingHomeWritePlanError> {
    if payload_len > ONBOARDING_IMPORT_MAX_DOCUMENT_BYTES {
        return Err(OnboardingHomeWritePlanError::DocumentBytesExceeded);
    }
    *total = total
        .checked_add(payload_len)
        .ok_or(OnboardingHomeWritePlanError::TotalBytesExceeded)?;
    if *total > ONBOARDING_IMPORT_MAX_TOTAL_BYTES {
        return Err(OnboardingHomeWritePlanError::TotalBytesExceeded);
    }
    Ok(())
}

fn reject_unsafe_metadata(value: &str) -> Result<(), OnboardingHomeWritePlanError> {
    if value.chars().any(|character| character == '\0') {
        Err(OnboardingHomeWritePlanError::UnsafeMetadata)
    } else {
        Ok(())
    }
}

fn short_digest(value: &[u8]) -> String {
    let digest = format!("{:x}", Sha256::digest(value));
    digest[..12].to_owned()
}

fn json_string_len(value: &str) -> Result<usize, OnboardingHomeWritePlanError> {
    struct ByteCounter(usize);

    impl io::Write for ByteCounter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("serialized string length overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| OnboardingHomeWritePlanError::TotalBytesExceeded)?;
    Ok(counter.0)
}

fn safe_slug(input: &str) -> String {
    let mut slug = String::new();
    let mut separator = false;
    for character in input.chars() {
        if character.is_ascii_alphanumeric() {
            if slug.len() == ONBOARDING_IMPORT_MAX_SLUG_BYTES {
                break;
            }
            slug.push(character.to_ascii_lowercase());
            separator = false;
        } else if !slug.is_empty() && !separator && slug.len() < ONBOARDING_IMPORT_MAX_SLUG_BYTES {
            slug.push('-');
            separator = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "item".to_owned()
    } else {
        slug
    }
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

#[cfg(test)]
mod onboarding_write_plan_tests {
    use super::*;
    use crate::import_preview::EntryKind;

    const TIMESTAMP: &str = "2026-07-21T15:04:05Z";

    fn entry(name: &str, provenance: &str, text: &str) -> ExtractedEntry {
        ExtractedEntry {
            source_name: name.to_owned(),
            kind: EntryKind::Markdown,
            text: text.to_owned(),
            source_provenance: provenance.to_owned(),
        }
    }

    #[test]
    fn plans_are_ordered_serializable_and_byte_deterministic() {
        let entries = vec![entry("notes.md", "export:notes.md", "Hello\n")];
        let first = compile_onboarding_home_write_plan(&entries, TIMESTAMP).unwrap();
        let second = compile_onboarding_home_write_plan(&entries, TIMESTAMP).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        assert_eq!(first.writes.len(), 1);
        assert!(first.writes[0].relative_path.starts_with("memory/imports/"));
    }

    #[test]
    fn duplicate_and_path_like_names_are_safely_disambiguated() {
        let entries = vec![
            entry("../../CON.md", "export:first", "one"),
            entry("../../CON.md", "export:second", "two"),
        ];
        let plan = compile_onboarding_home_write_plan(&entries, TIMESTAMP).unwrap();
        let mut case_folded = BTreeSet::new();

        for write in &plan.writes {
            assert!(write.relative_path.starts_with("memory/imports/"));
            assert!(!write.relative_path.contains(".."));
            assert!(!write.relative_path.contains('\\'));
            assert!(case_folded.insert(write.relative_path.to_ascii_lowercase()));
        }
    }

    #[test]
    fn frontmatter_is_escaped_and_original_body_is_verbatim() {
        let original = "Unicode: café 🦀\n\n---\nmultiline\r\n";
        let provenance = "archive.zip\n---\nsource: forged\nquote: \"yes\"";
        let plan = compile_onboarding_home_write_plan(
            &[entry("memory.md", provenance, original)],
            TIMESTAMP,
        )
        .unwrap();
        let imported = &plan.writes.last().unwrap().contents;
        let (_, body) = imported
            .strip_prefix("---\n")
            .unwrap()
            .split_once("\n---\n")
            .unwrap();

        assert_eq!(body.as_bytes(), original.as_bytes());
        assert!(imported.starts_with("---\nsource: \"archive.zip\\n---\\nsource: forged"));
        assert!(imported.contains("\nimport_date: 2026-07-21\n---\n"));
    }

    #[test]
    fn rejects_invalid_timestamp_and_unsafe_metadata() {
        let entries = [entry("notes.md", "export:notes.md", "text")];
        assert_eq!(
            compile_onboarding_home_write_plan(&entries, "2026-07-21"),
            Err(OnboardingHomeWritePlanError::InvalidTimestamp)
        );
        assert_eq!(
            compile_onboarding_home_write_plan(
                &[entry("notes.md", "bad\0source", "text")],
                TIMESTAMP,
            ),
            Err(OnboardingHomeWritePlanError::UnsafeMetadata)
        );
    }

    #[test]
    fn enforces_entry_document_and_aggregate_bounds_without_truncation() {
        let too_many = (0..=ONBOARDING_IMPORT_MAX_ENTRIES)
            .map(|index| entry(&format!("{index}.md"), &format!("source:{index}"), "x"))
            .collect::<Vec<_>>();
        assert_eq!(
            compile_onboarding_home_write_plan(&too_many, TIMESTAMP),
            Err(OnboardingHomeWritePlanError::TooManyEntries)
        );

        let oversized = "é".repeat(ONBOARDING_IMPORT_MAX_DOCUMENT_BYTES / 2);
        assert_eq!(
            compile_onboarding_home_write_plan(
                &[entry("large.md", "source:large", &oversized)],
                TIMESTAMP,
            ),
            Err(OnboardingHomeWritePlanError::DocumentBytesExceeded)
        );

        let aggregate = (0..5)
            .map(|index| {
                entry(
                    &format!("{index}.md"),
                    &format!("source:{index}"),
                    &"x".repeat(60_000),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            compile_onboarding_home_write_plan(&aggregate, TIMESTAMP),
            Err(OnboardingHomeWritePlanError::TotalBytesExceeded)
        );
    }

    fn persistence_test_home(name: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!(
            "muniment-persistence-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&home).unwrap();
        scaffold_home(&home).unwrap();
        home
    }

    #[test]
    fn later_publication_collision_rolls_back_only_this_attempt() {
        let home = persistence_test_home("rollback");
        let plan = OnboardingHomeWritePlan {
            writes: vec![
                HomeWrite {
                    relative_path: "memory/first.md".into(),
                    contents: "first".into(),
                },
                HomeWrite {
                    relative_path: "memory/second.md".into(),
                    contents: "planned second".into(),
                },
            ],
        };

        let result = persist_onboarding_home_write_plan_with_hook(
            &home,
            &plan,
            |_, file| file.sync_all(),
            |index, parent| {
                if index == 1 {
                    parent.write("second.md", b"user collision")?;
                }
                Ok(())
            },
            |_, parent, temporary_name| parent.remove_file(temporary_name),
        );
        assert!(matches!(
            result,
            Err(OnboardingHomePersistenceError::DestinationConflict { relative_path })
                if relative_path == "memory/second.md"
        ));
        assert!(!home.join("memory/first.md").exists());
        assert_eq!(
            fs::read(home.join("memory/second.md")).unwrap(),
            b"user collision"
        );
        assert!(!fs::read_dir(home.join("memory")).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));

        fs::remove_file(home.join("memory/second.md")).unwrap();
        persist_onboarding_home_write_plan(&home, &plan).unwrap();
        assert_eq!(fs::read(home.join("memory/first.md")).unwrap(), b"first");
        assert_eq!(
            fs::read(home.join("memory/second.md")).unwrap(),
            b"planned second"
        );
        fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn swapped_parent_symlink_cannot_redirect_publication_outside_home() {
        use std::os::unix::fs::symlink;

        let home = persistence_test_home("parent-swap");
        let outside = persistence_test_home("outside");
        fs::create_dir(home.join("memory/imports")).unwrap();
        let plan = OnboardingHomeWritePlan {
            writes: vec![HomeWrite {
                relative_path: "memory/imports/new.md".into(),
                contents: "planned".into(),
            }],
        };
        let result = persist_onboarding_home_write_plan_with_hook(
            &home,
            &plan,
            |_, file| file.sync_all(),
            |_, _| {
                fs::rename(
                    home.join("memory/imports"),
                    home.join("memory/pinned-imports"),
                )?;
                symlink(&outside, home.join("memory/imports"))?;
                Ok(())
            },
            |_, parent, temporary_name| parent.remove_file(temporary_name),
        );

        assert!(matches!(
            result,
            Err(OnboardingHomePersistenceError::InvalidPlan)
        ));
        assert!(!outside.join("new.md").exists());
        assert!(!home.join("memory/pinned-imports/new.md").exists());
        assert!(!fs::read_dir(home.join("memory/pinned-imports"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
        fs::remove_dir_all(home).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn staging_failure_removes_temporary_file_without_publishing() {
        let home = persistence_test_home("staging-failure");
        let plan = OnboardingHomeWritePlan {
            writes: vec![HomeWrite {
                relative_path: "memory/new.md".into(),
                contents: "planned".into(),
            }],
        };

        let result = persist_onboarding_home_write_plan_with_hook(
            &home,
            &plan,
            |_, _| Err(io::Error::other("injected staging sync failure")),
            |_, _| Ok(()),
            |_, parent, temporary_name| parent.remove_file(temporary_name),
        );

        assert!(matches!(
            result,
            Err(OnboardingHomePersistenceError::Io(error))
                if error.to_string() == "injected staging sync failure"
        ));
        assert!(!home.join("memory/new.md").exists());
        assert!(!fs::read_dir(home.join("memory")).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn cleanup_failure_after_publication_keeps_published_files() {
        let home = persistence_test_home("cleanup-failure");
        let plan = OnboardingHomeWritePlan {
            writes: vec![
                HomeWrite {
                    relative_path: "memory/first.md".into(),
                    contents: "first".into(),
                },
                HomeWrite {
                    relative_path: "memory/second.md".into(),
                    contents: "second".into(),
                },
            ],
        };

        persist_onboarding_home_write_plan_with_hook(
            &home,
            &plan,
            |_, file| file.sync_all(),
            |_, _| Ok(()),
            |index, parent, temporary_name| {
                if index == 0 {
                    Err(io::Error::other("injected temporary cleanup failure"))
                } else {
                    parent.remove_file(temporary_name)
                }
            },
        )
        .unwrap();

        assert_eq!(fs::read(home.join("memory/first.md")).unwrap(), b"first");
        assert_eq!(fs::read(home.join("memory/second.md")).unwrap(), b"second");
        assert_eq!(
            fs::read_dir(home.join("memory"))
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".tmp")
                })
                .count(),
            1
        );
        fs::remove_dir_all(home).unwrap();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeErrorKind {
    InvalidInput,
    Io,
}

#[derive(Debug)]
pub struct HomeError {
    kind: HomeErrorKind,
    message: &'static str,
    source: Option<io::Error>,
}

impl HomeError {
    fn io(message: &'static str, source: io::Error) -> Self {
        Self {
            kind: HomeErrorKind::Io,
            message,
            source: Some(source),
        }
    }

    fn invalid(message: &'static str) -> Self {
        Self {
            kind: HomeErrorKind::InvalidInput,
            message,
            source: None,
        }
    }

    pub fn kind(&self) -> HomeErrorKind {
        self.kind
    }
}

impl fmt::Display for HomeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for HomeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[derive(Deserialize, Serialize)]
struct HomeConfig {
    location: PathBuf,
}

pub fn configured_home(config_dir: &Path) -> Result<Option<PathBuf>, HomeError> {
    let bytes = match fs::read(config_dir.join(CONFIG_FILE)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(HomeError::io(
                "The saved Home location could not be read.",
                error,
            ))
        }
    };
    let config: HomeConfig = serde_json::from_slice(&bytes)
        .map_err(|_| HomeError::invalid("The saved Home location is invalid."))?;
    validate_home(&config.location)?;
    Ok(Some(config.location))
}

pub fn confirm_home(config_dir: &Path, home: &Path) -> Result<(), HomeError> {
    validate_home(home)?;
    validate_config_location(config_dir, home)?;
    scaffold_home(home)?;
    persist_home(config_dir, home)
}

/// Validates a Home selection without creating it or recording configuration.
pub fn validate_home_selection(config_dir: &Path, home: &Path) -> Result<(), HomeError> {
    validate_home(home)?;
    validate_config_location(config_dir, home)
}

fn validate_config_location(config_dir: &Path, home: &Path) -> Result<(), HomeError> {
    let config_dir = normalized_absolute(config_dir)?;
    let home = normalized_absolute(home)?;
    if config_dir.starts_with(&home) {
        return Err(HomeError::invalid(
            "Muniment Home cannot contain the app configuration folder.",
        ));
    }
    Ok(())
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, HomeError> {
    if !path.is_absolute() {
        return Err(HomeError::invalid("The folder location is invalid."));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(HomeError::invalid("The folder location is invalid."));
                }
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    let mut existing = normalized.as_path();
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(existing) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(
                    existing
                        .file_name()
                        .ok_or_else(|| HomeError::invalid("The folder location is invalid."))?,
                );
                existing = existing
                    .parent()
                    .ok_or_else(|| HomeError::invalid("The folder location is invalid."))?;
            }
            Err(error) => {
                return Err(HomeError::io(
                    "The folder location could not be inspected.",
                    error,
                ))
            }
        }
    }
}

pub fn scaffold_home(home: &Path) -> Result<(), HomeError> {
    create_visible_directory(home)?;
    for name in HOME_DIRECTORIES {
        let directory = home.join(name);
        create_visible_directory(&directory)?;
        let heading = format!("# {}\n", name[..1].to_uppercase() + &name[1..]);
        muniment_attach::write_scaffold_file_if_missing(
            &directory.join("README.md"),
            heading.as_bytes(),
        )
        .map_err(|error| HomeError::io("Muniment Home README could not be created.", error))?;
    }
    Ok(())
}

fn validate_home(home: &Path) -> Result<(), HomeError> {
    if !home.is_absolute() || home.parent().is_none() {
        return Err(HomeError::invalid(
            "Choose an absolute folder other than a filesystem root.",
        ));
    }
    let name = home
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| HomeError::invalid("The Home folder location is invalid."))?;
    if name.starts_with('.') {
        return Err(HomeError::invalid(
            "Muniment Home must be a visible folder, not a dot-directory.",
        ));
    }
    Ok(())
}

fn create_visible_directory(path: &Path) -> Result<(), HomeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(
            HomeError::invalid("A Muniment Home scaffold path is not a directory."),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(path)
            .map_err(|error| HomeError::io("Muniment Home could not be created.", error)),
        Err(error) => Err(HomeError::io(
            "Muniment Home could not be inspected.",
            error,
        )),
    }
}

fn persist_home(config_dir: &Path, home: &Path) -> Result<(), HomeError> {
    fs::create_dir_all(config_dir)
        .map_err(|error| HomeError::io("The Home selection could not be saved.", error))?;
    let contents = serde_json::to_vec_pretty(&HomeConfig {
        location: home.to_path_buf(),
    })
    .map_err(|_| HomeError::invalid("The Home selection could not be saved."))?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(config_dir.join("home.lock"))
        .map_err(|error| HomeError::io("The Home selection could not be saved.", error))?;
    lock.lock_exclusive()
        .map_err(|error| HomeError::io("The Home selection could not be saved.", error))?;

    let destination = config_dir.join(CONFIG_FILE);
    let temporary = config_dir.join(format!("home.json.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        io::Write::write_all(&mut file, &contents)?;
        file.sync_all()?;
        replace_file(&temporary, &destination)?;
        sync_directory(config_dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| HomeError::io("The Home selection could not be saved.", error))
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(not(target_os = "windows"))]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    if destination.exists() {
        // Windows rename does not replace an existing file atomically.
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
        let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let replaced = unsafe {
            ReplaceFileW(
                destination.as_ptr(),
                source.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if replaced == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    } else {
        fs::rename(source, destination)
    }
}

#[cfg(target_os = "windows")]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::replace_file;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn failed_replacement_preserves_the_previous_file() {
        let root = std::env::temp_dir().join(format!(
            "muniment-home-replace-failure-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let destination = root.join("home.json");
        fs::write(&destination, b"previous configuration").unwrap();

        assert!(replace_file(&root.join("missing.tmp"), &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"previous configuration");
        fs::remove_dir_all(root).unwrap();
    }
}
