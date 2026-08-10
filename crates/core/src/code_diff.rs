use std::collections::{BTreeMap, BTreeSet};

use muniment_code_diff::{
    CodeDiff, DiffFile, DiffHunk, DiffLine, DiffLineKind, DiffLineSegment, DiffLineSegmentKind,
    DiffStatus,
};
use uuid::Uuid;

const CONTEXT_LINES: usize = 3;

/// Computes the changed files between two in-memory trees.
pub fn compute_code_diff(
    current: &BTreeMap<String, Vec<u8>>,
    staged: &BTreeMap<String, Vec<u8>>,
) -> CodeDiff {
    let paths: BTreeSet<_> = current.keys().chain(staged.keys()).collect();
    let mut files = Vec::new();

    for path in paths {
        let old = current.get(path);
        let new = staged.get(path);
        if old == new {
            continue;
        }

        let (status, old_path, new_path) = match (old, new) {
            (None, Some(_)) => (DiffStatus::Added, None, Some(path.clone())),
            (Some(_), None) => (DiffStatus::Deleted, Some(path.clone()), None),
            (Some(_), Some(_)) => (DiffStatus::Modified, Some(path.clone()), Some(path.clone())),
            (None, None) => unreachable!(),
        };
        let binary = old.into_iter().chain(new).any(|bytes| is_binary(bytes));
        let hunks = if binary {
            Vec::new()
        } else {
            text_hunks(
                old.map_or("", |bytes| std::str::from_utf8(bytes).unwrap()),
                new.map_or("", |bytes| std::str::from_utf8(bytes).unwrap()),
            )
        };

        files.push(DiffFile {
            old_path,
            new_path,
            status,
            old_mode: None,
            new_mode: None,
            binary,
            hunks,
        });
    }

    let diff = CodeDiff {
        schema_version: 1,
        id: Uuid::now_v7().to_string(),
        files,
        truncated: false,
    };
    debug_assert!(diff.validate().is_ok());
    diff
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0) || std::str::from_utf8(bytes).is_err()
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TextLine<'a> {
    text: &'a str,
    terminated: bool,
}

#[derive(Clone, Copy)]
enum Edit<'a> {
    Context(TextLine<'a>),
    Addition(TextLine<'a>),
    Deletion(TextLine<'a>),
}

fn text_hunks<'a>(old: &'a str, new: &'a str) -> Vec<DiffHunk> {
    let edits = edit_script(text_lines(old), text_lines(new));
    let changes: Vec<_> = edits
        .iter()
        .enumerate()
        .filter_map(|(index, edit)| (!matches!(edit, Edit::Context(_))).then_some(index))
        .collect();
    if changes.is_empty() {
        return Vec::new();
    }

    let mut ranges = Vec::new();
    for change in changes {
        let start = context_before(&edits, change);
        let end = context_after(&edits, change);
        if let Some((_, previous_end)) = ranges.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        ranges.push((start, end));
    }

    let positions = line_positions(&edits);
    ranges
        .into_iter()
        .map(|(start, end)| make_hunk(&edits[start..end], positions[start]))
        .collect()
}

fn text_lines(text: &str) -> Vec<TextLine<'_>> {
    text.split_inclusive('\n')
        .map(|line| {
            let terminated = line.ends_with('\n');
            let text = line.strip_suffix('\n').unwrap_or(line);
            let text = if terminated {
                text.strip_suffix('\r').unwrap_or(text)
            } else {
                text
            };
            TextLine { text, terminated }
        })
        .collect()
}

fn edit_script<'a>(old: Vec<TextLine<'a>>, new: Vec<TextLine<'a>>) -> Vec<Edit<'a>> {
    let mut lengths = vec![vec![0usize; new.len() + 1]; old.len() + 1];
    for old_index in (0..old.len()).rev() {
        for new_index in (0..new.len()).rev() {
            lengths[old_index][new_index] = if old[old_index] == new[new_index] {
                lengths[old_index + 1][new_index + 1] + 1
            } else {
                lengths[old_index + 1][new_index].max(lengths[old_index][new_index + 1])
            };
        }
    }

    let (mut old_index, mut new_index) = (0, 0);
    let mut edits = Vec::new();
    while old_index < old.len() || new_index < new.len() {
        if old_index < old.len() && new_index < new.len() && old[old_index] == new[new_index] {
            edits.push(Edit::Context(old[old_index]));
            old_index += 1;
            new_index += 1;
        } else if new_index < new.len()
            && (old_index == old.len()
                || lengths[old_index][new_index + 1] >= lengths[old_index + 1][new_index])
        {
            edits.push(Edit::Addition(new[new_index]));
            new_index += 1;
        } else {
            edits.push(Edit::Deletion(old[old_index]));
            old_index += 1;
        }
    }
    edits
}

fn context_before(edits: &[Edit<'_>], change: usize) -> usize {
    let mut start = change;
    let mut context = 0;
    while start > 0 && context < CONTEXT_LINES {
        start -= 1;
        if matches!(edits[start], Edit::Context(_)) {
            context += 1;
        }
    }
    start
}

fn context_after(edits: &[Edit<'_>], change: usize) -> usize {
    let mut end = change + 1;
    let mut context = 0;
    while end < edits.len() && context < CONTEXT_LINES {
        if matches!(edits[end], Edit::Context(_)) {
            context += 1;
        }
        end += 1;
    }
    end
}

fn line_positions(edits: &[Edit<'_>]) -> Vec<(u64, u64)> {
    let (mut old_line, mut new_line) = (1, 1);
    let mut positions = Vec::with_capacity(edits.len());
    for edit in edits {
        positions.push((old_line, new_line));
        match edit {
            Edit::Context(_) => {
                old_line += 1;
                new_line += 1;
            }
            Edit::Addition(_) => new_line += 1,
            Edit::Deletion(_) => old_line += 1,
        }
    }
    positions
}

fn make_hunk(edits: &[Edit<'_>], position: (u64, u64)) -> DiffHunk {
    let old_count = edits
        .iter()
        .filter(|edit| !matches!(edit, Edit::Addition(_)))
        .count() as u64;
    let new_count = edits
        .iter()
        .filter(|edit| !matches!(edit, Edit::Deletion(_)))
        .count() as u64;
    let old_start = if old_count == 0 {
        position.0 - 1
    } else {
        position.0
    };
    let new_start = if new_count == 0 {
        position.1 - 1
    } else {
        position.1
    };
    let mut old_line = position.0;
    let mut new_line = position.1;
    let lines = edits
        .iter()
        .map(|edit| {
            let (kind, text, old_number, new_number) = match edit {
                Edit::Context(line) => {
                    let numbers = (Some(old_line), Some(new_line));
                    old_line += 1;
                    new_line += 1;
                    (DiffLineKind::Context, line.text, numbers.0, numbers.1)
                }
                Edit::Addition(line) => {
                    let number = new_line;
                    new_line += 1;
                    (DiffLineKind::Addition, line.text, None, Some(number))
                }
                Edit::Deletion(line) => {
                    let number = old_line;
                    old_line += 1;
                    (DiffLineKind::Deletion, line.text, Some(number), None)
                }
            };
            DiffLine {
                kind,
                old_line_number: old_number,
                new_line_number: new_number,
                text: text.to_owned(),
                segments: vec![DiffLineSegment {
                    kind: DiffLineSegmentKind::Plain,
                    text: text.to_owned(),
                }],
            }
        })
        .collect();

    DiffHunk {
        old_start,
        old_count,
        new_start,
        new_count,
        header: format!("@@ -{old_start},{old_count} +{new_start},{new_count} @@"),
        lines,
    }
}
