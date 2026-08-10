use std::collections::BTreeMap;

use muniment_code_diff::{DiffLineKind, DiffLineSegmentKind, DiffStatus};
use muniment_core::code_diff::compute_code_diff;
use uuid::{Uuid, Version};

fn tree(files: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    files
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec()))
        .collect()
}

#[test]
fn computes_sorted_valid_files_with_a_uuid_v7() {
    let current = tree(&[("b.txt", b"old"), ("d.txt", b"gone"), ("same", b"x")]);
    let staged = tree(&[("a.txt", b"new"), ("b.txt", b"new"), ("same", b"x")]);

    let diff = compute_code_diff(&current, &staged);

    diff.validate().unwrap();
    assert_eq!(
        Uuid::parse_str(&diff.id).unwrap().get_version(),
        Some(Version::SortRand)
    );
    assert_eq!(diff.files.len(), 3);
    assert_eq!(diff.files[0].new_path.as_deref(), Some("a.txt"));
    assert_eq!(diff.files[0].status, DiffStatus::Added);
    assert_eq!(diff.files[1].status, DiffStatus::Modified);
    assert_eq!(diff.files[2].old_path.as_deref(), Some("d.txt"));
    assert_eq!(diff.files[2].status, DiffStatus::Deleted);
    assert!(!diff.truncated);
}

#[test]
fn treats_nul_and_invalid_utf8_as_binary() {
    let current = tree(&[("invalid", b"text"), ("nul", b"text")]);
    let staged = tree(&[("invalid", &[0xff]), ("nul", b"a\0b")]);

    let diff = compute_code_diff(&current, &staged);

    assert!(diff
        .files
        .iter()
        .all(|file| file.binary && file.hunks.is_empty()));
}

#[test]
fn emits_three_context_lines_and_consistent_hunk_metadata() {
    let old = b"zero\none\ntwo\nthree\nfour\nfive\nsix\nseven\neight";
    let new = b"zero\none\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight";
    let diff = compute_code_diff(&tree(&[("file", old)]), &tree(&[("file", new)]));
    let hunk = &diff.files[0].hunks[0];

    assert_eq!((hunk.old_start, hunk.old_count), (1, 7));
    assert_eq!((hunk.new_start, hunk.new_count), (1, 7));
    assert_eq!(hunk.header, "@@ -1,7 +1,7 @@");
    assert_eq!(
        hunk.lines
            .iter()
            .filter(|line| line.kind == DiffLineKind::Context)
            .count(),
        6
    );
    for line in &hunk.lines {
        assert_eq!(line.segments.len(), 1);
        assert_eq!(line.segments[0].kind, DiffLineSegmentKind::Plain);
        assert_eq!(line.segments[0].text, line.text);
    }
}

#[test]
fn reports_zero_start_for_an_empty_side() {
    let added = compute_code_diff(&BTreeMap::new(), &tree(&[("file", b"one\ntwo")]));
    let deleted = compute_code_diff(&tree(&[("file", b"one\ntwo")]), &BTreeMap::new());

    let added_hunk = &added.files[0].hunks[0];
    assert_eq!((added_hunk.old_start, added_hunk.old_count), (0, 0));
    assert_eq!((added_hunk.new_start, added_hunk.new_count), (1, 2));
    let deleted_hunk = &deleted.files[0].hunks[0];
    assert_eq!((deleted_hunk.old_start, deleted_hunk.old_count), (1, 2));
    assert_eq!((deleted_hunk.new_start, deleted_hunk.new_count), (0, 0));
}

#[test]
fn separates_distant_changes_into_hunks() {
    let old = b"0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14";
    let new = b"changed\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\nchanged";
    let diff = compute_code_diff(&tree(&[("file", old)]), &tree(&[("file", new)]));

    assert_eq!(diff.files[0].hunks.len(), 2);
    assert_eq!(diff.files[0].hunks[0].lines.len(), 5);
    assert_eq!(diff.files[0].hunks[1].lines.len(), 5);
}

#[test]
fn reports_an_added_final_newline() {
    let diff = compute_code_diff(&tree(&[("file", b"a")]), &tree(&[("file", b"a\n")]));
    let hunk = &diff.files[0].hunks[0];

    assert_eq!((hunk.old_start, hunk.old_count), (1, 1));
    assert_eq!((hunk.new_start, hunk.new_count), (1, 1));
    assert_eq!(hunk.lines.len(), 2);
    assert_eq!(hunk.lines[0].kind, DiffLineKind::Addition);
    assert_eq!(hunk.lines[0].text, "a");
    assert_eq!(hunk.lines[1].kind, DiffLineKind::Deletion);
    assert_eq!(hunk.lines[1].text, "a");
}

#[test]
fn reports_a_removed_final_newline() {
    let diff = compute_code_diff(&tree(&[("file", b"a\n")]), &tree(&[("file", b"a")]));
    let hunk = &diff.files[0].hunks[0];

    assert_eq!((hunk.old_start, hunk.old_count), (1, 1));
    assert_eq!((hunk.new_start, hunk.new_count), (1, 1));
    assert_eq!(hunk.lines.len(), 2);
    assert_eq!(hunk.lines[0].kind, DiffLineKind::Addition);
    assert_eq!(hunk.lines[0].text, "a");
    assert_eq!(hunk.lines[1].kind, DiffLineKind::Deletion);
    assert_eq!(hunk.lines[1].text, "a");
}
