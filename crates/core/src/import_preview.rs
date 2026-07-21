//! Bounded, read-only preview of a user-selected assistant export ZIP.
//!
//! This slice deliberately does the *least* that a later import needs: it
//! inspects one explicitly chosen archive and returns a deterministic manifest
//! of its supported text entries. Nothing here extracts a member, writes to
//! disk, walks parent or home directories, or invokes the required model —
//! automatic discovery of `~/.claude`, `~/.codex`, Cursor, or Cline is
//! intentionally out of scope so this cannot become a background disk walk.
//!
//! Every bound below is enforced before or during decompression, and every
//! rejection maps to a stable [`PreviewErrorKind`] suitable for later UI copy.
//! Following OWASP archive guidance, declared header sizes are never trusted:
//! expanded bytes are counted as they stream and decompression stops the
//! instant a bound is exceeded.

use serde::Serialize;
use std::fs;
use std::io::Read;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

/// Stable, typed failure modes. Serialized as camelCase strings so a later UI
/// can branch on the kind and supply its own copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PreviewErrorKind {
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
    let metadata = match fs::symlink_metadata(archive_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PreviewErrorKind::NotFound)
        }
        Err(_) => return Err(PreviewErrorKind::Io),
    };
    // The archive itself must be a plain file, not a directory or a symlink
    // that could redirect the read to an unbounded target elsewhere.
    if !metadata.file_type().is_file() {
        return Err(PreviewErrorKind::NotFound);
    }
    if metadata.len() > MAX_ARCHIVE_BYTES {
        return Err(PreviewErrorKind::ArchiveTooLarge);
    }

    let file = fs::File::open(archive_path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => PreviewErrorKind::NotFound,
        _ => PreviewErrorKind::Io,
    })?;
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
