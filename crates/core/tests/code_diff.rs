use std::collections::BTreeMap;

use muniment_code_diff::{DiffLineKind, DiffLineSegmentKind, DiffStatus};
use muniment_core::code_diff::{compute_code_diff, ComputeCodeDiffError};
use uuid::{Uuid, Version};

fn tree(files: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    files
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec()))
        .collect()
}

fn assert_segments_match_lines(diff: &muniment_code_diff::CodeDiff) {
    for line in diff
        .files
        .iter()
        .flat_map(|file| &file.hunks)
        .flat_map(|hunk| &hunk.lines)
    {
        assert_eq!(
            line.segments
                .iter()
                .map(|segment| segment.text.as_str())
                .collect::<String>(),
            line.text
        );
    }
}

fn added_files(count: usize) -> BTreeMap<String, Vec<u8>> {
    (0..count)
        .map(|index| (format!("{index:03}.txt"), Vec::new()))
        .collect()
}

fn lines(count: usize) -> Vec<u8> {
    (0..count)
        .map(|index| format!("line {index}\n"))
        .collect::<String>()
        .into_bytes()
}

#[test]
fn accepts_two_hundred_changed_files_and_rejects_more() {
    let current = BTreeMap::new();
    let diff = compute_code_diff(&current, &added_files(200)).unwrap();

    assert_eq!(diff.files.len(), 200);
    assert_eq!(
        compute_code_diff(&current, &added_files(201)),
        Err(ComputeCodeDiffError::TooManyChangedFiles)
    );
}

#[test]
fn counts_each_rename_as_one_changed_file() {
    let current: BTreeMap<_, _> = (0..201)
        .map(|index| (format!("old-{index:03}"), index.to_string().into_bytes()))
        .collect();
    let staged: BTreeMap<_, _> = (0..201)
        .map(|index| (format!("new-{index:03}"), index.to_string().into_bytes()))
        .collect();

    let diff = compute_code_diff(
        &current
            .iter()
            .take(200)
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect(),
        &staged
            .iter()
            .take(200)
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect(),
    )
    .unwrap();

    diff.validate().unwrap();
    assert_eq!(diff.files.len(), 200);
    assert_eq!(
        compute_code_diff(&current, &staged),
        Err(ComputeCodeDiffError::TooManyChangedFiles)
    );
}

#[test]
fn unchanged_files_do_not_count_toward_the_file_limit() {
    let unchanged = added_files(201);

    let diff = compute_code_diff(&unchanged, &unchanged).unwrap();

    assert!(diff.files.is_empty());
}

#[test]
fn keeps_exactly_twenty_thousand_rendered_lines() {
    let staged = BTreeMap::from([("file.txt".to_owned(), lines(20_000))]);

    let diff = compute_code_diff(&BTreeMap::new(), &staged).unwrap();

    assert_eq!(diff.files[0].hunks[0].lines.len(), 20_000);
    assert!(!diff.truncated);
}

#[test]
fn truncates_at_complete_hunks_in_stable_path_order() {
    let current = BTreeMap::from([(
        "b.txt".to_owned(),
        b"0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14".to_vec(),
    )]);
    let staged = BTreeMap::from([
        ("a.txt".to_owned(), lines(19_995)),
        (
            "b.txt".to_owned(),
            b"changed\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\nchanged".to_vec(),
        ),
        ("c.txt".to_owned(), b"omitted line\n".to_vec()),
    ]);

    let diff = compute_code_diff(&current, &staged).unwrap();

    diff.validate().unwrap();
    assert!(diff.truncated);
    assert_eq!(diff.files.len(), 2);
    assert_eq!(diff.files[0].hunks[0].lines.len(), 19_995);
    assert_eq!(diff.files[1].hunks.len(), 1);
    assert_eq!(diff.files[1].hunks[0].lines.len(), 5);
}

#[test]
fn computes_sorted_valid_files_with_a_uuid_v7() {
    let current = tree(&[("b.txt", b"old"), ("d.txt", b"gone"), ("same", b"x")]);
    let staged = tree(&[("a.txt", b"new"), ("b.txt", b"new"), ("same", b"x")]);

    let diff = compute_code_diff(&current, &staged).unwrap();

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
fn reports_an_exact_content_rename_without_hunks() {
    let diff = compute_code_diff(
        &tree(&[("old.txt", b"same bytes")]),
        &tree(&[("a.txt", b"added"), ("new.txt", b"same bytes")]),
    )
    .unwrap();

    diff.validate().unwrap();
    assert_eq!(diff.files.len(), 2);
    assert_eq!(diff.files[0].new_path.as_deref(), Some("a.txt"));
    assert_eq!(diff.files[1].status, DiffStatus::Renamed);
    assert_eq!(diff.files[1].old_path.as_deref(), Some("old.txt"));
    assert_eq!(diff.files[1].new_path.as_deref(), Some("new.txt"));
    assert!(!diff.files[1].binary);
    assert!(diff.files[1].hunks.is_empty());
}

#[test]
fn pairs_identical_rename_candidates_once_in_path_order() {
    let current = tree(&[("old-a", b"same"), ("old-b", b"same")]);
    let staged = tree(&[("new-a", b"same"), ("new-b", b"same")]);

    let diff = compute_code_diff(&current, &staged).unwrap();

    diff.validate().unwrap();
    assert_eq!(diff.files.len(), 2);
    assert_eq!(diff.files[0].old_path.as_deref(), Some("old-a"));
    assert_eq!(diff.files[0].new_path.as_deref(), Some("new-a"));
    assert_eq!(diff.files[1].old_path.as_deref(), Some("old-b"));
    assert_eq!(diff.files[1].new_path.as_deref(), Some("new-b"));
    assert!(diff
        .files
        .iter()
        .all(|file| file.status == DiffStatus::Renamed && file.hunks.is_empty()));
}

#[test]
fn keeps_one_byte_changes_as_added_and_deleted_files() {
    let diff = compute_code_diff(&tree(&[("old", b"abc")]), &tree(&[("new", b"abd")])).unwrap();

    diff.validate().unwrap();
    assert_eq!(diff.files.len(), 2);
    assert_eq!(diff.files[0].status, DiffStatus::Added);
    assert_eq!(diff.files[1].status, DiffStatus::Deleted);
}

#[test]
fn reports_an_exact_binary_rename_without_hunks() {
    let diff = compute_code_diff(&tree(&[("old", b"a\0b")]), &tree(&[("new", b"a\0b")])).unwrap();

    diff.validate().unwrap();
    assert_eq!(diff.files.len(), 1);
    assert_eq!(diff.files[0].status, DiffStatus::Renamed);
    assert!(diff.files[0].binary);
    assert!(diff.files[0].hunks.is_empty());
}

#[test]
fn treats_nul_and_invalid_utf8_as_binary() {
    let current = tree(&[("invalid", b"text"), ("nul", b"text")]);
    let staged = tree(&[("invalid", &[0xff]), ("nul", b"a\0b")]);

    let diff = compute_code_diff(&current, &staged).unwrap();

    assert!(diff
        .files
        .iter()
        .all(|file| file.binary && file.hunks.is_empty()));
}

#[test]
fn emits_three_context_lines_and_consistent_hunk_metadata() {
    let old = b"zero\none\ntwo\nthree\nfour\nfive\nsix\nseven\neight";
    let new = b"zero\none\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight";
    let diff = compute_code_diff(&tree(&[("file", old)]), &tree(&[("file", new)])).unwrap();
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
}

#[test]
fn emits_word_segments_for_paired_lines() {
    let old = b"context\nHello old wide world\ndeleted alone";
    let new = b"context\nHello new small world\nadded one\nadded two";
    let diff = compute_code_diff(&tree(&[("file", old)]), &tree(&[("file", new)])).unwrap();
    let lines = &diff.files[0].hunks[0].lines;

    diff.validate().unwrap();
    assert_segments_match_lines(&diff);
    assert_eq!(lines[0].segments.len(), 1);
    assert_eq!(lines[0].segments[0].kind, DiffLineSegmentKind::Plain);
    assert_eq!(
        lines[1]
            .segments
            .iter()
            .map(|segment| (segment.kind, segment.text.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (DiffLineSegmentKind::Plain, "Hello "),
            (DiffLineSegmentKind::Deletion, "old wide"),
            (DiffLineSegmentKind::Plain, " world"),
        ]
    );
    assert_eq!(
        lines[3]
            .segments
            .iter()
            .map(|segment| (segment.kind, segment.text.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (DiffLineSegmentKind::Plain, "Hello "),
            (DiffLineSegmentKind::Addition, "new small"),
            (DiffLineSegmentKind::Plain, " world"),
        ]
    );
    for line in [lines.last().unwrap(), &lines[2]] {
        assert_eq!(line.segments.len(), 1);
        assert_eq!(line.segments[0].kind, DiffLineSegmentKind::Plain);
    }
}

#[test]
fn matches_the_modified_fixture_segment_shape() {
    let diff = compute_code_diff(
        &tree(&[("file", b"Hello world")]),
        &tree(&[("file", b"Hello Muniment")]),
    )
    .unwrap();
    let lines = &diff.files[0].hunks[0].lines;

    assert_eq!(lines[0].segments[0].text, "Hello ");
    assert_eq!(lines[0].segments[1].kind, DiffLineSegmentKind::Deletion);
    assert_eq!(lines[0].segments[1].text, "world");
    assert_eq!(lines[1].segments[0].text, "Hello ");
    assert_eq!(lines[1].segments[1].kind, DiffLineSegmentKind::Addition);
    assert_eq!(lines[1].segments[1].text, "Muniment");
}

#[test]
fn emits_word_segments_when_only_one_line_has_middle_words() {
    for (old, new, expected) in [
        (
            b"Hello world".as_slice(),
            b"Hello brave world".as_slice(),
            vec![
                vec![(DiffLineSegmentKind::Plain, "Hello world")],
                vec![
                    (DiffLineSegmentKind::Plain, "Hello "),
                    (DiffLineSegmentKind::Addition, "brave"),
                    (DiffLineSegmentKind::Plain, " world"),
                ],
            ],
        ),
        (
            b"Hello brave world".as_slice(),
            b"Hello world".as_slice(),
            vec![
                vec![
                    (DiffLineSegmentKind::Plain, "Hello "),
                    (DiffLineSegmentKind::Deletion, "brave"),
                    (DiffLineSegmentKind::Plain, " world"),
                ],
                vec![(DiffLineSegmentKind::Plain, "Hello world")],
            ],
        ),
    ] {
        let diff = compute_code_diff(&tree(&[("file", old)]), &tree(&[("file", new)])).unwrap();
        let lines = &diff.files[0].hunks[0].lines;

        diff.validate().unwrap();
        assert_segments_match_lines(&diff);
        assert_eq!(
            lines
                .iter()
                .map(|line| {
                    line.segments
                        .iter()
                        .map(|segment| (segment.kind, segment.text.as_str()))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[test]
fn keeps_full_rewrites_plain_and_all_segments_match_their_lines() {
    let current = tree(&[
        ("modified", b"old words"),
        ("spacing", b"same words"),
        ("deleted", b"gone"),
    ]);
    let staged = tree(&[
        ("modified", b"new text"),
        ("spacing", b"same  words"),
        ("added", b"here"),
    ]);
    let diff = compute_code_diff(&current, &staged).unwrap();

    diff.validate().unwrap();
    assert_segments_match_lines(&diff);
    for line in diff
        .files
        .iter()
        .flat_map(|file| &file.hunks)
        .flat_map(|hunk| &hunk.lines)
    {
        assert_eq!(line.segments.len(), 1);
        assert_eq!(line.segments[0].kind, DiffLineSegmentKind::Plain);
    }
}

#[test]
fn reports_zero_start_for_an_empty_side() {
    let added = compute_code_diff(&BTreeMap::new(), &tree(&[("file", b"one\ntwo")])).unwrap();
    let deleted = compute_code_diff(&tree(&[("file", b"one\ntwo")]), &BTreeMap::new()).unwrap();

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
    let diff = compute_code_diff(&tree(&[("file", old)]), &tree(&[("file", new)])).unwrap();

    assert_eq!(diff.files[0].hunks.len(), 2);
    assert_eq!(diff.files[0].hunks[0].lines.len(), 5);
    assert_eq!(diff.files[0].hunks[1].lines.len(), 5);
}

#[test]
fn reports_an_added_final_newline() {
    let diff = compute_code_diff(&tree(&[("file", b"a")]), &tree(&[("file", b"a\n")])).unwrap();
    let hunk = &diff.files[0].hunks[0];

    assert_eq!((hunk.old_start, hunk.old_count), (1, 1));
    assert_eq!((hunk.new_start, hunk.new_count), (1, 1));
    assert_eq!(hunk.lines.len(), 2);
    assert_eq!(hunk.lines[0].kind, DiffLineKind::Deletion);
    assert_eq!(hunk.lines[0].text, "a");
    assert_eq!(hunk.lines[1].kind, DiffLineKind::Addition);
    assert_eq!(hunk.lines[1].text, "a");
}

#[test]
fn reports_a_removed_final_newline() {
    let diff = compute_code_diff(&tree(&[("file", b"a\n")]), &tree(&[("file", b"a")])).unwrap();
    let hunk = &diff.files[0].hunks[0];

    assert_eq!((hunk.old_start, hunk.old_count), (1, 1));
    assert_eq!((hunk.new_start, hunk.new_count), (1, 1));
    assert_eq!(hunk.lines.len(), 2);
    assert_eq!(hunk.lines[0].kind, DiffLineKind::Deletion);
    assert_eq!(hunk.lines[0].text, "a");
    assert_eq!(hunk.lines[1].kind, DiffLineKind::Addition);
    assert_eq!(hunk.lines[1].text, "a");
}
