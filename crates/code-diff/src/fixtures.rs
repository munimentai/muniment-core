use std::{collections::BTreeMap, fs, io, path::Path};

use crate::{
    canonical_bytes, CodeDiff, DiffFile, DiffHunk, DiffLine, DiffLineKind, DiffLineSegment,
    DiffLineSegmentKind, DiffStatus,
};

pub const FIXTURE_DIRECTORY: &str = "code-diff/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Write,
    Check,
}

pub fn export(root: &Path, mode: Mode) -> io::Result<()> {
    let target = root.join(FIXTURE_DIRECTORY);
    let expected = fixture_bytes()?;
    if mode == Mode::Check {
        return check(&target, &expected);
    }
    fs::create_dir_all(&target)?;
    for entry in fs::read_dir(&target)? {
        let path = entry?.path();
        if path.is_file() {
            fs::remove_file(path)?;
        }
    }
    for (name, bytes) in expected {
        fs::write(target.join(name), bytes)?;
    }
    Ok(())
}

fn fixture_bytes() -> io::Result<BTreeMap<String, Vec<u8>>> {
    let empty = CodeDiff {
        schema_version: 1,
        id: "fixture-empty".into(),
        files: vec![],
        truncated: false,
    };
    let modified = CodeDiff {
        schema_version: 1,
        id: "fixture-modified".into(),
        files: vec![text_file(
            "src/message.txt",
            "src/message.txt",
            DiffStatus::Modified,
        )],
        truncated: false,
    };
    let added = CodeDiff {
        schema_version: 1,
        id: "fixture-added".into(),
        files: vec![DiffFile {
            old_path: None,
            new_path: Some("new.txt".into()),
            status: DiffStatus::Added,
            old_mode: None,
            new_mode: Some("100644".into()),
            binary: false,
            hunks: vec![],
        }],
        truncated: false,
    };
    let deleted = CodeDiff {
        schema_version: 1,
        id: "fixture-deleted".into(),
        files: vec![DiffFile {
            old_path: Some("old.txt".into()),
            new_path: None,
            status: DiffStatus::Deleted,
            old_mode: Some("100644".into()),
            new_mode: None,
            binary: false,
            hunks: vec![],
        }],
        truncated: false,
    };
    let renamed = CodeDiff {
        schema_version: 1,
        id: "fixture-renamed".into(),
        files: vec![text_file(
            "old-name.txt",
            "new-name.txt",
            DiffStatus::Renamed,
        )],
        truncated: false,
    };
    let binary = CodeDiff {
        schema_version: 1,
        id: "fixture-binary".into(),
        files: vec![DiffFile {
            old_path: Some("assets/icon.png".into()),
            new_path: Some("assets/icon.png".into()),
            status: DiffStatus::Modified,
            old_mode: Some("100644".into()),
            new_mode: Some("100644".into()),
            binary: true,
            hunks: vec![],
        }],
        truncated: false,
    };
    let truncated = CodeDiff {
        schema_version: 1,
        id: "fixture-truncated".into(),
        files: vec![text_file(
            "src/large.txt",
            "src/large.txt",
            DiffStatus::Modified,
        )],
        truncated: true,
    };
    let values = [
        ("added.json", added),
        ("deleted.json", deleted),
        ("empty.json", empty),
        ("modified.json", modified),
        ("renamed.json", renamed),
        ("binary.json", binary),
        ("truncated.json", truncated),
    ];
    let mut fixtures = BTreeMap::new();
    for (name, value) in values {
        value.validate().map_err(io::Error::other)?;
        let mut bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
        bytes.push(b'\n');
        fixtures.insert(name.into(), bytes);
        fixtures.insert(
            name.replace(".json", ".canonical.json"),
            canonical_bytes(&value).map_err(io::Error::other)?,
        );
    }
    Ok(fixtures)
}

fn text_file(old_path: &str, new_path: &str, status: DiffStatus) -> DiffFile {
    DiffFile {
        old_path: Some(old_path.into()),
        new_path: Some(new_path.into()),
        status,
        old_mode: Some("100644".into()),
        new_mode: Some("100644".into()),
        binary: false,
        hunks: vec![DiffHunk {
            old_start: 1,
            old_count: 1,
            new_start: 1,
            new_count: 1,
            header: "@@ -1 +1 @@".into(),
            lines: vec![
                DiffLine {
                    kind: DiffLineKind::Deletion,
                    old_line_number: Some(1),
                    new_line_number: None,
                    text: "Hello world".into(),
                    segments: vec![
                        DiffLineSegment {
                            kind: DiffLineSegmentKind::Plain,
                            text: "Hello ".into(),
                        },
                        DiffLineSegment {
                            kind: DiffLineSegmentKind::Deletion,
                            text: "world".into(),
                        },
                    ],
                },
                DiffLine {
                    kind: DiffLineKind::Addition,
                    old_line_number: None,
                    new_line_number: Some(1),
                    text: "Hello Muniment".into(),
                    segments: vec![
                        DiffLineSegment {
                            kind: DiffLineSegmentKind::Plain,
                            text: "Hello ".into(),
                        },
                        DiffLineSegment {
                            kind: DiffLineSegmentKind::Addition,
                            text: "Muniment".into(),
                        },
                    ],
                },
            ],
        }],
    }
}

fn check(target: &Path, expected: &BTreeMap<String, Vec<u8>>) -> io::Result<()> {
    let mut actual = BTreeMap::new();
    if target.exists() {
        for entry in fs::read_dir(target)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                actual.insert(
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path())?,
                );
            }
        }
    }
    if &actual == expected {
        Ok(())
    } else {
        Err(io::Error::other(
            "code-diff fixture drift detected. Run cargo run -p muniment-code-diff --bin export-code-diff-fixtures -- ../protocol-fixtures",
        ))
    }
}
