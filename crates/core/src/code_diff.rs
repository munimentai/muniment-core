use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use muniment_code_diff::{
    canonical_bytes, CodeDiff, DiffFile, DiffHunk, DiffLine, DiffLineKind, DiffLineSegment,
    DiffLineSegmentKind, DiffStatus,
};
use uuid::Uuid;

const CONTEXT_LINES: usize = 3;
const MAX_CHANGED_FILES: usize = 200;
const MAX_RENDERED_LINES: usize = 20_000;
const MAX_CANONICAL_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeCodeDiffError {
    TooManyChangedFiles,
}

impl fmt::Display for ComputeCodeDiffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a code diff must not contain more than 200 changed files")
    }
}

impl Error for ComputeCodeDiffError {}

/// Computes the changed files between two in-memory trees.
pub fn compute_code_diff(
    current: &BTreeMap<String, Vec<u8>>,
    staged: &BTreeMap<String, Vec<u8>>,
) -> Result<CodeDiff, ComputeCodeDiffError> {
    let paths: BTreeSet<_> = current.keys().chain(staged.keys()).collect();
    let deleted_paths: Vec<_> = current
        .keys()
        .filter(|path| !staged.contains_key(*path))
        .collect();
    let added_paths: Vec<_> = staged
        .keys()
        .filter(|path| !current.contains_key(*path))
        .collect();
    let mut paired_added_paths = BTreeSet::new();
    let mut renamed_paths = BTreeMap::new();
    for old_path in deleted_paths {
        if let Some(new_path) = added_paths.iter().find(|new_path| {
            !paired_added_paths.contains(*new_path)
                && current.get(old_path) == staged.get(**new_path)
        }) {
            paired_added_paths.insert(*new_path);
            renamed_paths.insert(old_path, *new_path);
        }
    }

    let mut changes = BTreeMap::new();
    for path in paths {
        let old = current.get(path);
        let new = staged.get(path);
        if old == new || paired_added_paths.contains(path) {
            continue;
        }
        if let Some(new_path) = renamed_paths.get(path) {
            changes.insert(
                *new_path,
                (Some(path), Some(*new_path), DiffStatus::Renamed),
            );
            continue;
        }
        let change = match (old, new) {
            (None, Some(_)) => (None, Some(path), DiffStatus::Added),
            (Some(_), None) => (Some(path), None, DiffStatus::Deleted),
            (Some(_), Some(_)) => (Some(path), Some(path), DiffStatus::Modified),
            (None, None) => unreachable!(),
        };
        changes.insert(path, change);
    }
    if changes.len() > MAX_CHANGED_FILES {
        return Err(ComputeCodeDiffError::TooManyChangedFiles);
    }

    let mut files = Vec::new();
    let mut rendered_lines = 0usize;
    let mut truncated = false;

    for (_, (old_path, new_path, status)) in changes {
        let old = old_path.and_then(|path| current.get(path));
        let new = new_path.and_then(|path| staged.get(path));
        let binary = old.into_iter().chain(new).any(|bytes| is_binary(bytes));
        let mut hunks = if binary || status == DiffStatus::Renamed {
            Vec::new()
        } else {
            text_hunks(
                old.map_or("", |bytes| std::str::from_utf8(bytes).unwrap()),
                new.map_or("", |bytes| std::str::from_utf8(bytes).unwrap()),
            )
        };

        let included_hunks = hunks
            .iter()
            .take_while(|hunk| {
                let Some(next_rendered_lines) = rendered_lines.checked_add(hunk.lines.len()) else {
                    truncated = true;
                    return false;
                };
                if next_rendered_lines > MAX_RENDERED_LINES {
                    truncated = true;
                    return false;
                }
                rendered_lines = next_rendered_lines;
                true
            })
            .count();
        if included_hunks < hunks.len() {
            hunks.truncate(included_hunks);
        }

        files.push(DiffFile {
            old_path: old_path.cloned(),
            new_path: new_path.cloned(),
            status,
            old_mode: None,
            new_mode: None,
            binary,
            hunks,
        });
        if truncated {
            break;
        }
    }

    let mut diff = CodeDiff {
        schema_version: 1,
        id: Uuid::now_v7().to_string(),
        files,
        truncated,
    };
    truncate_to_canonical_byte_limit(&mut diff);
    debug_assert!(diff.validate().is_ok());
    Ok(diff)
}

fn truncate_to_canonical_byte_limit(diff: &mut CodeDiff) {
    if canonical_bytes(diff)
        .expect("the producer creates a valid code diff")
        .len()
        <= MAX_CANONICAL_BYTES
    {
        return;
    }

    diff.truncated = true;
    while canonical_bytes(diff)
        .expect("the producer creates a valid code diff")
        .len()
        > MAX_CANONICAL_BYTES
    {
        let Some(last_file) = diff.files.last_mut() else {
            break;
        };
        if last_file.hunks.pop().is_none() {
            diff.files.pop();
        }
    }
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
                || lengths[old_index][new_index + 1] > lengths[old_index + 1][new_index])
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
    let mut lines: Vec<_> = edits
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
    add_intra_line_segments(&mut lines);

    DiffHunk {
        old_start,
        old_count,
        new_start,
        new_count,
        header: format!("@@ -{old_start},{old_count} +{new_start},{new_count} @@"),
        lines,
    }
}

fn add_intra_line_segments(lines: &mut [DiffLine]) {
    let mut index = 0;
    while index < lines.len() {
        if lines[index].kind != DiffLineKind::Deletion {
            index += 1;
            continue;
        }

        let deletion_start = index;
        while index < lines.len() && lines[index].kind == DiffLineKind::Deletion {
            index += 1;
        }
        let addition_start = index;
        while index < lines.len() && lines[index].kind == DiffLineKind::Addition {
            index += 1;
        }

        let pair_count = (addition_start - deletion_start).min(index - addition_start);
        for offset in 0..pair_count {
            let deletion = deletion_start + offset;
            let addition = addition_start + offset;
            if let Some((deletion_segments, addition_segments)) =
                changed_word_segments(&lines[deletion].text, &lines[addition].text)
            {
                lines[deletion].segments = deletion_segments;
                lines[addition].segments = addition_segments;
            }
        }
    }
}

fn changed_word_segments(
    deletion: &str,
    addition: &str,
) -> Option<(Vec<DiffLineSegment>, Vec<DiffLineSegment>)> {
    let deletion_words = word_spans(deletion);
    let addition_words = word_spans(addition);
    let mut leading = 0;
    while leading < deletion_words.len()
        && leading < addition_words.len()
        && deletion[deletion_words[leading].0..deletion_words[leading].1]
            == addition[addition_words[leading].0..addition_words[leading].1]
    {
        leading += 1;
    }

    if leading == deletion_words.len() && leading == addition_words.len() {
        return None;
    }

    let mut trailing = 0;
    while trailing < deletion_words.len() - leading
        && trailing < addition_words.len() - leading
        && deletion[deletion_words[deletion_words.len() - trailing - 1].0
            ..deletion_words[deletion_words.len() - trailing - 1].1]
            == addition[addition_words[addition_words.len() - trailing - 1].0
                ..addition_words[addition_words.len() - trailing - 1].1]
    {
        trailing += 1;
    }

    if leading == 0 && trailing == 0 {
        return None;
    }

    Some((
        line_segments(
            deletion,
            &deletion_words,
            leading,
            trailing,
            DiffLineSegmentKind::Deletion,
        ),
        line_segments(
            addition,
            &addition_words,
            leading,
            trailing,
            DiffLineSegmentKind::Addition,
        ),
    ))
}

fn word_spans(text: &str) -> Vec<(usize, usize)> {
    let mut words = Vec::new();
    let mut start = None;
    for (index, character) in text.char_indices() {
        if character.is_whitespace() {
            if let Some(start) = start.take() {
                words.push((start, index));
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(start) = start {
        words.push((start, text.len()));
    }
    words
}

fn line_segments(
    text: &str,
    words: &[(usize, usize)],
    leading: usize,
    trailing: usize,
    changed_kind: DiffLineSegmentKind,
) -> Vec<DiffLineSegment> {
    if leading + trailing == words.len() {
        return vec![DiffLineSegment {
            kind: DiffLineSegmentKind::Plain,
            text: text.to_owned(),
        }];
    }

    let changed_start = words.get(leading).map_or(text.len(), |word| word.0);
    let changed_end = words
        .get(words.len().saturating_sub(trailing + 1))
        .map_or(changed_start, |word| word.1);
    let mut segments = Vec::new();
    for (kind, segment) in [
        (DiffLineSegmentKind::Plain, &text[..changed_start]),
        (changed_kind, &text[changed_start..changed_end]),
        (DiffLineSegmentKind::Plain, &text[changed_end..]),
    ] {
        if !segment.is_empty() {
            segments.push(DiffLineSegment {
                kind,
                text: segment.to_owned(),
            });
        }
    }
    segments
}

#[cfg(test)]
mod canonical_byte_limit_tests {
    use super::*;

    fn added_hunk(text_len: usize) -> DiffHunk {
        let text = "x".repeat(text_len);
        DiffHunk {
            old_start: 0,
            old_count: 0,
            new_start: 1,
            new_count: 1,
            header: String::new(),
            lines: vec![DiffLine {
                kind: DiffLineKind::Addition,
                old_line_number: None,
                new_line_number: Some(1),
                text: text.clone(),
                segments: vec![DiffLineSegment {
                    kind: DiffLineSegmentKind::Addition,
                    text,
                }],
            }],
        }
    }

    fn added_file(path: String, hunks: Vec<DiffHunk>) -> DiffFile {
        DiffFile {
            old_path: None,
            new_path: Some(path),
            status: DiffStatus::Added,
            old_mode: None,
            new_mode: None,
            binary: false,
            hunks,
        }
    }

    fn diff(files: Vec<DiffFile>) -> CodeDiff {
        CodeDiff {
            schema_version: 1,
            id: "test".to_owned(),
            files,
            truncated: false,
        }
    }

    #[test]
    fn keeps_every_file_and_hunk_near_the_canonical_byte_limit() {
        let mut diff = diff(vec![added_file(
            "a.txt".to_owned(),
            vec![added_hunk((MAX_CANONICAL_BYTES - 1_000) / 2)],
        )]);
        let original = diff.clone();
        let size = canonical_bytes(&diff).unwrap().len();
        assert!(size <= MAX_CANONICAL_BYTES);
        assert!(size > MAX_CANONICAL_BYTES - 2_000);

        truncate_to_canonical_byte_limit(&mut diff);

        assert_eq!(diff, original);
    }

    #[test]
    fn oversized_multi_hunk_diff_keeps_fitting_leading_hunks() {
        let hunks = vec![added_hunk(400_000); 3];
        let mut diff = diff(vec![added_file("a.txt".to_owned(), hunks)]);

        truncate_to_canonical_byte_limit(&mut diff);

        assert!(diff.truncated);
        assert_eq!(diff.files.len(), 1);
        assert_eq!(diff.files[0].hunks.len(), 2);
        assert!(canonical_bytes(&diff).unwrap().len() <= MAX_CANONICAL_BYTES);
    }

    #[test]
    fn oversized_multi_file_diff_drops_only_trailing_files() {
        let files = (0..3)
            .map(|index| {
                let path = format!("{index}-{}", "x".repeat(700_000));
                let mut file = added_file(path, Vec::new());
                file.binary = true;
                file
            })
            .collect();
        let mut diff = diff(files);

        truncate_to_canonical_byte_limit(&mut diff);

        assert!(diff.truncated);
        assert_eq!(diff.files.len(), 2);
        assert!(diff.files[0].new_path.as_ref().unwrap().starts_with("0-"));
        assert!(diff.files[1].new_path.as_ref().unwrap().starts_with("1-"));
        assert!(canonical_bytes(&diff).unwrap().len() <= MAX_CANONICAL_BYTES);
    }
}
