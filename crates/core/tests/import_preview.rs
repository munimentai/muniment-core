//! Behavioural coverage for the read-only export-ZIP preview: a valid mixed
//! export succeeds, every archive hazard fails closed with its typed kind, and
//! the filesystem is untouched whether the preview succeeds or fails.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use muniment_core::import_preview::{
    preview_export_zip, EntryKind, PreviewErrorKind, MAX_ENTRY_COUNT, MAX_ENTRY_EXPANDED_BYTES,
    MAX_EXCERPT_BYTES, MAX_TOTAL_EXPANDED_BYTES,
};
use zip::write::SimpleFileOptions;
use zip::{AesMode, ZipWriter};

struct Temp(PathBuf);

impl Temp {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "muniment-import-preview-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

enum Member<'a> {
    Dir(&'a str),
    File(&'a str, &'a [u8]),
    Symlink(&'a str, &'a str),
    Encrypted(&'a str, &'a [u8]),
}

fn build_zip(path: &Path, members: &[Member<'_>]) {
    let mut writer = ZipWriter::new(std::fs::File::create(path).unwrap());
    let options = SimpleFileOptions::default().unix_permissions(0o644);
    for member in members {
        match member {
            Member::Dir(name) => writer.add_directory(*name, options).unwrap(),
            Member::File(name, bytes) => {
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            Member::Symlink(name, target) => {
                writer.add_symlink(*name, *target, options).unwrap();
            }
            Member::Encrypted(name, bytes) => {
                writer
                    .start_file(
                        *name,
                        options.with_aes_encryption(AesMode::Aes256, "secret"),
                    )
                    .unwrap();
                writer.write_all(bytes).unwrap();
            }
        }
    }
    writer.finish().unwrap();
}

/// A recursive snapshot of a directory tree: relative path -> file bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, relative: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(root.join(relative)).unwrap() {
            let entry = entry.unwrap();
            let path = relative.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(path, std::fs::read(entry.path()).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, Path::new(""), &mut out);
    out
}

#[test]
fn previews_a_valid_mixed_export_without_touching_the_filesystem() {
    let temp = Temp::new("valid");
    let archive = temp.join("export.zip");
    build_zip(
        &archive,
        &[
            Member::Dir("conversations/"),
            Member::File("conversations/chat.md", b"# Title\n\nHello world."),
            Member::File("conversations/./notes.txt", b"plain notes"),
            Member::File("data/messages.json", b"{\"role\":\"user\"}"),
        ],
    );
    let before = snapshot(&temp.0);

    let manifest = preview_export_zip(&archive).unwrap();

    assert_eq!(manifest.entries.len(), 3);
    // Deterministic archive order, normalized names, true expanded sizes.
    assert_eq!(manifest.entries[0].name, "conversations/chat.md");
    assert_eq!(manifest.entries[0].kind, EntryKind::Markdown);
    assert_eq!(manifest.entries[0].byte_size, 21);
    assert_eq!(manifest.entries[0].excerpt, "# Title\n\nHello world.");
    assert!(!manifest.entries[0].excerpt_truncated);
    assert_eq!(manifest.entries[1].name, "conversations/notes.txt");
    assert_eq!(manifest.entries[1].kind, EntryKind::Text);
    assert_eq!(manifest.entries[2].name, "data/messages.json");
    assert_eq!(manifest.entries[2].kind, EntryKind::Json);
    assert_eq!(manifest.total_byte_size, 21 + 11 + 15);

    assert_eq!(snapshot(&temp.0), before, "preview must not write anything");
}

#[test]
fn excerpt_is_bounded_and_reports_truncation() {
    let temp = Temp::new("excerpt");
    let archive = temp.join("export.zip");
    let body = vec![b'a'; MAX_EXCERPT_BYTES + 500];
    build_zip(&archive, &[Member::File("big.txt", &body)]);

    let manifest = preview_export_zip(&archive).unwrap();
    let entry = &manifest.entries[0];
    assert_eq!(entry.byte_size, body.len() as u64);
    assert_eq!(entry.excerpt.len(), MAX_EXCERPT_BYTES);
    assert!(entry.excerpt_truncated);
}

fn assert_rejected(name: &str, members: &[Member<'_>], expected: PreviewErrorKind) {
    let temp = Temp::new(name);
    let archive = temp.join("export.zip");
    build_zip(&archive, members);
    let before = snapshot(&temp.0);

    assert_eq!(preview_export_zip(&archive), Err(expected), "case {name}");
    assert_eq!(
        snapshot(&temp.0),
        before,
        "failed preview must not write anything ({name})"
    );
}

#[test]
fn rejects_parent_traversal_paths() {
    assert_rejected(
        "traversal",
        &[Member::File("../escape.txt", b"nope")],
        PreviewErrorKind::PathTraversal,
    );
}

#[test]
fn rejects_absolute_paths() {
    assert_rejected(
        "absolute",
        &[Member::File("/etc/passwd.txt", b"nope")],
        PreviewErrorKind::PathTraversal,
    );
}

#[test]
fn rejects_duplicate_normalized_names() {
    assert_rejected(
        "duplicate",
        &[
            Member::File("a/note.txt", b"first"),
            Member::File("a/./note.txt", b"second"),
        ],
        PreviewErrorKind::DuplicateEntry,
    );
}

#[test]
fn rejects_symlink_like_entries() {
    assert_rejected(
        "symlink",
        &[Member::Symlink("link.txt", "/etc/passwd")],
        PreviewErrorKind::Symlink,
    );
}

#[test]
fn rejects_encrypted_entries() {
    assert_rejected(
        "encrypted",
        &[Member::Encrypted("secret.txt", b"classified")],
        PreviewErrorKind::Encrypted,
    );
}

#[test]
fn rejects_unsupported_entry_types() {
    assert_rejected(
        "unsupported",
        &[Member::File("image.png", b"\x89PNG\r\n")],
        PreviewErrorKind::UnsupportedEntry,
    );
}

#[test]
fn rejects_malformed_utf8_text() {
    assert_rejected(
        "utf8",
        &[Member::File("bad.txt", &[0xff, 0xfe, 0x00])],
        PreviewErrorKind::InvalidText,
    );
}

#[test]
fn rejects_too_many_entries() {
    let temp = Temp::new("count");
    let archive = temp.join("export.zip");
    let mut writer = ZipWriter::new(std::fs::File::create(&archive).unwrap());
    let options = SimpleFileOptions::default();
    for index in 0..(MAX_ENTRY_COUNT + 1) {
        writer
            .start_file(format!("note-{index}.txt"), options)
            .unwrap();
        writer.write_all(b"x").unwrap();
    }
    writer.finish().unwrap();

    assert_eq!(
        preview_export_zip(&archive),
        Err(PreviewErrorKind::TooManyEntries)
    );
}

#[test]
fn rejects_a_single_oversized_entry() {
    let temp = Temp::new("entry-size");
    let archive = temp.join("export.zip");
    // Compresses to almost nothing on disk, but expands past the per-entry cap.
    let body = vec![b'a'; (MAX_ENTRY_EXPANDED_BYTES + 1) as usize];
    build_zip(&archive, &[Member::File("huge.txt", &body)]);

    assert_eq!(
        preview_export_zip(&archive),
        Err(PreviewErrorKind::EntryTooLarge)
    );
}

#[test]
fn rejects_cumulative_oversized_entries() {
    let temp = Temp::new("total-size");
    let archive = temp.join("export.zip");
    // Each entry stays under the per-entry cap; together they exceed the total,
    // and each has a distinct name so duplicate detection never fires first.
    let per_entry = MAX_ENTRY_EXPANDED_BYTES - 1;
    let count = (MAX_TOTAL_EXPANDED_BYTES / per_entry) + 2;
    let body = vec![b'a'; per_entry as usize];
    let mut writer = ZipWriter::new(std::fs::File::create(&archive).unwrap());
    let options = SimpleFileOptions::default();
    for index in 0..count {
        writer
            .start_file(format!("note-{index}.txt"), options)
            .unwrap();
        writer.write_all(&body).unwrap();
    }
    writer.finish().unwrap();

    assert_eq!(
        preview_export_zip(&archive),
        Err(PreviewErrorKind::TotalTooLarge)
    );
}

#[test]
fn rejects_invalid_and_missing_archives() {
    let temp = Temp::new("invalid");
    let not_a_zip = temp.join("garbage.zip");
    std::fs::write(&not_a_zip, b"this is not a zip archive").unwrap();
    assert_eq!(
        preview_export_zip(&not_a_zip),
        Err(PreviewErrorKind::InvalidArchive)
    );

    assert_eq!(
        preview_export_zip(&temp.join("missing.zip")),
        Err(PreviewErrorKind::NotFound)
    );

    assert_eq!(
        preview_export_zip(&temp.0),
        Err(PreviewErrorKind::NotFound),
        "a directory is not a previewable archive"
    );
}
