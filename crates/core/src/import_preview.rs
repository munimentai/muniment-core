//! Bounded, read-only preview of a user-selected assistant export ZIP.
//!
//! This slice deliberately does the *least* that a later import needs: it
//! inspects one explicitly chosen archive and returns a deterministic manifest
//! of its supported text entries. Nothing here extracts a member, writes to
//! disk, walks parent or home directories, or invokes the required model.
//! automatic discovery of `~/.claude`, `~/.codex`, Cursor, or Cline is
//! intentionally out of scope so this cannot become a background disk walk.
//!
//! Every bound below is enforced before or during decompression, and every
//! rejection maps to a stable [`PreviewErrorKind`] suitable for later UI copy.
//! Following OWASP archive guidance, declared header sizes are never trusted:
//! expanded bytes are counted as they stream and decompression stops the
//! instant a bound is exceeded.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use zip::result::ZipError;

/// Maximum on-disk size of the archive itself, in bytes (64 MiB).
pub const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum number of members the archive may declare.
pub const MAX_ENTRY_COUNT: usize = 4096;
/// Maximum expanded size of any single member, in bytes (4 MiB).
pub const MAX_ENTRY_EXPANDED_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum expanded size across all previewed members, in bytes (16 MiB).
pub const MAX_TOTAL_EXPANDED_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum number of path components a normalized entry name may have.
pub const MAX_PATH_DEPTH: usize = 16;
/// Maximum number of bytes retained from each entry as a preview excerpt.
pub const MAX_EXCERPT_BYTES: usize = 4 * 1024;

/// Kind of a supported, previewable text member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    Text,
    Markdown,
    Json,
}

/// One previewed member: its normalized name, true expanded size, and a
/// bounded excerpt that never splits a UTF-8 character.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewEntry {
    pub name: String,
    pub kind: EntryKind,
    pub byte_size: u64,
    pub excerpt: String,
    pub excerpt_truncated: bool,
}

/// Deterministic manifest for one archive, in archive index order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewManifest {
    pub entries: Vec<PreviewEntry>,
    pub total_byte_size: u64,
}

/// Full text retained for one explicitly selected archive member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedEntry {
    pub source_name: String,
    pub kind: EntryKind,
    pub text: String,
    /// Stable provenance identifier, independent of the archive's local path.
    pub source_provenance: String,
}

/// Stable, typed failure modes. Serialized as camelCase strings so a later UI
/// can branch on the kind and supply its own copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PreviewErrorKind {
    /// Extraction was requested without selecting any members.
    EmptySelection,
    /// A requested name was not already in normalized archive-name form.
    InvalidSelection,
    /// The same normalized member was selected more than once.
    DuplicateSelection,
    /// A requested member is a directory rather than a text file.
    DirectorySelection,
    /// A requested member does not exist in the independently read archive.
    UnknownSelection,
    /// The path does not exist or is not a regular file.
    NotFound,
    /// The archive is larger than [`MAX_ARCHIVE_BYTES`].
    ArchiveTooLarge,
    /// The bytes are not a readable ZIP archive.
    InvalidArchive,
    /// The archive declares more than [`MAX_ENTRY_COUNT`] members.
    TooManyEntries,
    /// A member expands past [`MAX_ENTRY_EXPANDED_BYTES`].
    EntryTooLarge,
    /// The previewed members together expand past [`MAX_TOTAL_EXPANDED_BYTES`].
    TotalTooLarge,
    /// An absolute or parent-traversal (`..`) entry path.
    PathTraversal,
    /// An entry path nests deeper than [`MAX_PATH_DEPTH`].
    PathTooDeep,
    /// Two members normalize to the same name.
    DuplicateEntry,
    /// A member is encrypted.
    Encrypted,
    /// A symlink-like member.
    Symlink,
    /// A member whose type is not previewable text/Markdown/JSON.
    UnsupportedEntry,
    /// A text member that is not valid UTF-8.
    InvalidText,
    /// The file could not be read.
    Io,
}

impl PreviewErrorKind {
    /// A neutral fallback message; the UI is expected to key off the kind.
    pub fn message(self) -> &'static str {
        match self {
            PreviewErrorKind::EmptySelection => "At least one archive entry must be selected.",
            PreviewErrorKind::InvalidSelection => {
                "A selected archive entry name is not normalized."
            }
            PreviewErrorKind::DuplicateSelection => "An archive entry was selected more than once.",
            PreviewErrorKind::DirectorySelection => "A selected archive entry is a directory.",
            PreviewErrorKind::UnknownSelection => "A selected archive entry could not be found.",
            PreviewErrorKind::NotFound => "The selected file could not be found.",
            PreviewErrorKind::ArchiveTooLarge => "The selected archive is too large to preview.",
            PreviewErrorKind::InvalidArchive => "The selected file is not a readable ZIP archive.",
            PreviewErrorKind::TooManyEntries => "The archive contains too many entries to preview.",
            PreviewErrorKind::EntryTooLarge => "An entry in the archive is too large to preview.",
            PreviewErrorKind::TotalTooLarge => {
                "The archive expands to more data than can be previewed."
            }
            PreviewErrorKind::PathTraversal => "The archive contains an unsafe entry path.",
            PreviewErrorKind::PathTooDeep => "The archive contains an entry nested too deeply.",
            PreviewErrorKind::DuplicateEntry => "The archive contains duplicate entry names.",
            PreviewErrorKind::Encrypted => "The archive contains an encrypted entry.",
            PreviewErrorKind::Symlink => "The archive contains a symbolic link entry.",
            PreviewErrorKind::UnsupportedEntry => "The archive contains an unsupported entry.",
            PreviewErrorKind::InvalidText => {
                "The archive contains a text entry that is not valid UTF-8."
            }
            PreviewErrorKind::Io => "The selected file could not be read.",
        }
    }
}

impl std::fmt::Display for PreviewErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for PreviewErrorKind {}

/// Reads one explicitly chosen ZIP path and returns its bounded preview
/// manifest. Fails closed with a typed kind and never extracts, writes, or
/// scans anything outside the given file.
pub fn preview_export_zip(archive_path: &Path) -> Result<PreviewManifest, PreviewErrorKind> {
    let (file, _) = open_validated_archive(archive_path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| PreviewErrorKind::InvalidArchive)?;
    if archive.len() > MAX_ENTRY_COUNT {
        return Err(PreviewErrorKind::TooManyEntries);
    }

    let mut entries = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut total_expanded: u64 = 0;

    for index in 0..archive.len() {
        let mut member = match archive.by_index(index) {
            Ok(member) => member,
            Err(ZipError::UnsupportedArchive(message))
                if message == ZipError::PASSWORD_REQUIRED =>
            {
                return Err(PreviewErrorKind::Encrypted)
            }
            Err(_) => return Err(PreviewErrorKind::InvalidArchive),
        };

        if member.encrypted() {
            return Err(PreviewErrorKind::Encrypted);
        }

        // Normalize (and safety-check) every member's path, including
        // directories, so a traversal entry is rejected regardless of type.
        let name = normalize_entry_name(member.name())?;

        if member.is_symlink() {
            return Err(PreviewErrorKind::Symlink);
        }
        if member.is_dir() {
            // Structural directory entries carry no content to preview.
            continue;
        }

        let kind = classify(&name).ok_or(PreviewErrorKind::UnsupportedEntry)?;

        if !seen.insert(name.clone()) {
            return Err(PreviewErrorKind::DuplicateEntry);
        }

        let remaining_total = MAX_TOTAL_EXPANDED_BYTES - total_expanded;
        let cap = MAX_ENTRY_EXPANDED_BYTES.min(remaining_total);
        // Read one byte past the cap so an over-limit entry is detectable, and
        // let the bounded reader halt decompression the moment the cap is hit.
        let mut bytes = Vec::new();
        member
            .by_ref()
            .take(cap + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PreviewErrorKind::InvalidArchive)?;
        let expanded = bytes.len() as u64;
        if expanded > MAX_ENTRY_EXPANDED_BYTES {
            return Err(PreviewErrorKind::EntryTooLarge);
        }
        if expanded > remaining_total {
            return Err(PreviewErrorKind::TotalTooLarge);
        }
        total_expanded += expanded;

        let text = String::from_utf8(bytes).map_err(|_| PreviewErrorKind::InvalidText)?;
        let (excerpt, excerpt_truncated) = excerpt_of(&text);
        entries.push(PreviewEntry {
            name,
            kind,
            byte_size: expanded,
            excerpt,
            excerpt_truncated,
        });
    }

    Ok(PreviewManifest {
        entries,
        total_byte_size: total_expanded,
    })
}

/// Re-opens and validates one explicitly chosen ZIP, returning full UTF-8 text
/// only for the normalized member names in `selected_names`. The entire
/// archive is streamed through the same bounds as preview, while selected
/// output is sorted by source name for deterministic downstream handling.
pub fn extract_selected_zip_entries(
    archive_path: &Path,
    selected_names: &[String],
) -> Result<Vec<ExtractedEntry>, PreviewErrorKind> {
    if selected_names.is_empty() {
        return Err(PreviewErrorKind::EmptySelection);
    }

    let mut selected = std::collections::BTreeSet::new();
    for requested in selected_names {
        let normalized = normalize_entry_name(requested)?;
        if normalized != *requested {
            return Err(PreviewErrorKind::InvalidSelection);
        }
        if classify(&normalized).is_none() {
            return Err(PreviewErrorKind::UnsupportedEntry);
        }
        if !selected.insert(normalized) {
            return Err(PreviewErrorKind::DuplicateSelection);
        }
    }

    let (file, archive_digest) = open_validated_archive(archive_path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| PreviewErrorKind::InvalidArchive)?;
    if archive.len() > MAX_ENTRY_COUNT {
        return Err(PreviewErrorKind::TooManyEntries);
    }

    let mut archive_names = std::collections::BTreeSet::new();
    let mut extracted = std::collections::BTreeMap::new();
    let mut total_expanded = 0u64;
    for index in 0..archive.len() {
        let mut member = match archive.by_index(index) {
            Ok(member) => member,
            Err(ZipError::UnsupportedArchive(message))
                if message == ZipError::PASSWORD_REQUIRED =>
            {
                return Err(PreviewErrorKind::Encrypted)
            }
            Err(_) => return Err(PreviewErrorKind::InvalidArchive),
        };
        if member.encrypted() {
            return Err(PreviewErrorKind::Encrypted);
        }
        let name = normalize_entry_name(member.name())?;
        if member.is_symlink() {
            return Err(PreviewErrorKind::Symlink);
        }
        if member.is_dir() {
            if selected.contains(&name) {
                return Err(PreviewErrorKind::DirectorySelection);
            }
            continue;
        }
        let kind = classify(&name).ok_or(PreviewErrorKind::UnsupportedEntry)?;
        if !archive_names.insert(name.clone()) {
            return Err(PreviewErrorKind::DuplicateEntry);
        }

        let remaining_total = MAX_TOTAL_EXPANDED_BYTES - total_expanded;
        let cap = MAX_ENTRY_EXPANDED_BYTES.min(remaining_total);
        let mut bytes = Vec::new();
        member
            .by_ref()
            .take(cap + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PreviewErrorKind::InvalidArchive)?;
        let expanded = bytes.len() as u64;
        if expanded > MAX_ENTRY_EXPANDED_BYTES {
            return Err(PreviewErrorKind::EntryTooLarge);
        }
        if expanded > remaining_total {
            return Err(PreviewErrorKind::TotalTooLarge);
        }
        total_expanded += expanded;
        let text = String::from_utf8(bytes).map_err(|_| PreviewErrorKind::InvalidText)?;

        if selected.contains(&name) {
            let content_digest = hex_digest(Sha256::digest(text.as_bytes()));
            extracted.insert(
                name.clone(),
                ExtractedEntry {
                    source_provenance: format!(
                        "assistant-export-zip:v1:{archive_digest}:{content_digest}:{name}"
                    ),
                    source_name: name,
                    kind,
                    text,
                },
            );
        }
    }

    if extracted.len() != selected.len() {
        return Err(PreviewErrorKind::UnknownSelection);
    }
    Ok(extracted.into_values().collect())
}

/// Opens the selected path without following a final-component symlink, then
/// validates and hashes that opened object. The returned reader exposes only
/// the bytes covered by the digest, so later growth cannot evade the bound.
fn open_validated_archive(
    archive_path: &Path,
) -> Result<(BoundedArchiveReader, String), PreviewErrorKind> {
    open_validated_archive_with_open_hook(archive_path, || {})
}

fn open_validated_archive_with_open_hook(
    archive_path: &Path,
    after_open: impl FnOnce(),
) -> Result<(BoundedArchiveReader, String), PreviewErrorKind> {
    let mut file = open_archive_no_follow(archive_path)?;
    after_open();
    validate_opened_archive(&file)?;

    let mut hasher = Sha256::new();
    let mut byte_count = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let remaining = MAX_ARCHIVE_BYTES + 1 - byte_count;
        if remaining == 0 {
            return Err(PreviewErrorKind::ArchiveTooLarge);
        }
        let read = file
            .by_ref()
            .take(remaining)
            .read(&mut buffer)
            .map_err(|_| PreviewErrorKind::Io)?;
        if read == 0 {
            break;
        }
        byte_count += read as u64;
        hasher.update(&buffer[..read]);
    }
    if byte_count > MAX_ARCHIVE_BYTES {
        return Err(PreviewErrorKind::ArchiveTooLarge);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| PreviewErrorKind::Io)?;
    Ok((
        BoundedArchiveReader {
            file,
            length: byte_count,
        },
        hex_digest(hasher.finalize()),
    ))
}

fn validate_opened_archive(file: &File) -> Result<(), PreviewErrorKind> {
    let metadata = file.metadata().map_err(|_| PreviewErrorKind::Io)?;
    if !metadata.file_type().is_file() {
        return Err(PreviewErrorKind::NotFound);
    }
    if metadata.len() > MAX_ARCHIVE_BYTES {
        return Err(PreviewErrorKind::ArchiveTooLarge);
    }
    Ok(())
}

fn open_archive_no_follow(path: &Path) -> Result<File, PreviewErrorKind> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound || is_symlink_open_error(&error) {
            PreviewErrorKind::NotFound
        } else {
            PreviewErrorKind::Io
        }
    })
}

#[cfg(unix)]
fn is_symlink_open_error(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_open_error(_error: &std::io::Error) -> bool {
    false
}

struct BoundedArchiveReader {
    file: File,
    length: u64,
}

impl Read for BoundedArchiveReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let position = self.file.stream_position()?;
        let remaining = self.length.saturating_sub(position);
        self.file.by_ref().take(remaining).read(buffer)
    }
}

impl Seek for BoundedArchiveReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let current = self.file.stream_position()? as i128;
        let target = match position {
            SeekFrom::Start(offset) => offset as i128,
            SeekFrom::End(offset) => self.length as i128 + offset as i128,
            SeekFrom::Current(offset) => current + offset as i128,
        };
        if !(0..=self.length as i128).contains(&target) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek outside validated archive",
            ));
        }
        self.file.seek(SeekFrom::Start(target as u64))
    }
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;
    bytes
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        })
}

/// Normalizes a raw archive entry name into a `/`-joined relative path,
/// rejecting absolute, parent-traversal, backslash, and over-deep paths.
fn normalize_entry_name(raw: &str) -> Result<String, PreviewErrorKind> {
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(PreviewErrorKind::PathTraversal);
    }
    let mut components = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => continue,
            ".." => return Err(PreviewErrorKind::PathTraversal),
            part if part.contains('\\') => return Err(PreviewErrorKind::PathTraversal),
            part => components.push(part),
        }
    }
    if components.is_empty() {
        // A bare `/`, `.`, or empty name has no usable member path.
        return Err(PreviewErrorKind::UnsupportedEntry);
    }
    if components.len() > MAX_PATH_DEPTH {
        return Err(PreviewErrorKind::PathTooDeep);
    }
    Ok(components.join("/"))
}

/// Maps a normalized name's extension to a supported preview kind, or `None`
/// for anything this slice does not preview.
fn classify(name: &str) -> Option<EntryKind> {
    let extension = name
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "txt" | "text" => Some(EntryKind::Text),
        "md" | "markdown" => Some(EntryKind::Markdown),
        "json" => Some(EntryKind::Json),
        _ => None,
    }
}

/// Returns a bounded excerpt of `text` plus whether it was truncated, never
/// splitting a multi-byte UTF-8 character.
fn excerpt_of(text: &str) -> (String, bool) {
    if text.len() <= MAX_EXCERPT_BYTES {
        return (text.to_string(), false);
    }
    let mut end = MAX_EXCERPT_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn build_zip(path: &Path, name: &str, body: &[u8]) {
        let mut writer = ZipWriter::new(File::create(path).unwrap());
        writer
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(body).unwrap();
        writer.finish().unwrap();
    }

    #[test]
    fn path_replacement_after_open_cannot_redirect_preview() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "muniment-opened-archive-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("export.zip");
        let original = directory.join("original.zip");
        let alternate = directory.join("alternate.zip");
        build_zip(&path, "original.txt", b"opened file");
        build_zip(&alternate, "alternate.txt", b"redirected file");

        let (reader, _) = open_validated_archive_with_open_hook(&path, || {
            std::fs::rename(&path, &original).unwrap();
            std::os::unix::fs::symlink(&alternate, &path).unwrap();
        })
        .unwrap();
        let mut archive = zip::ZipArchive::new(reader).unwrap();
        let mut member = archive.by_index(0).unwrap();
        let mut body = String::new();
        member.read_to_string(&mut body).unwrap();

        assert_eq!(member.name(), "original.txt");
        assert_eq!(body, "opened file");
        assert_eq!(
            open_validated_archive(&path).map(|_| ()),
            Err(PreviewErrorKind::NotFound)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
