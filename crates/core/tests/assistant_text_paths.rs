use muniment_core::assistant_text::{posix_absolute_path_candidate, scan, PathCandidate};

#[test]
fn matches_root_and_components() {
    for path in ["/", "/usr/local/bin", "/.", "/../src", "/資料/é"] {
        assert_eq!(
            posix_absolute_path_candidate(path, 0),
            PathCandidate::Matched(0..path.len()),
            "{path:?}"
        );
    }
}

#[test]
fn requires_a_path_boundary() {
    for boundary in ["", "(", "[", "{", ":", "=", ",", ";", " ", "\t", "\r", "\n"] {
        let content = format!("{boundary}/tmp");
        assert_eq!(
            posix_absolute_path_candidate(&content, boundary.len()),
            PathCandidate::Matched(boundary.len()..content.len()),
            "{boundary:?}"
        );
    }

    assert_eq!(
        posix_absolute_path_candidate("x/tmp", 1),
        PathCandidate::None
    );
}

#[test]
fn excludes_each_terminator_from_the_range() {
    for terminator in *b"\0 \t\r\n'\"`<>|" {
        let content = format!("/tmp{}tail", char::from(terminator));
        assert_eq!(
            posix_absolute_path_candidate(&content, 0),
            PathCandidate::Matched(0..4),
            "{terminator:?}"
        );
    }
}

#[test]
fn rejects_invalid_component_grammar() {
    for content in ["//tmp", "/tmp/", "/tmp//file", "/tmp\\file"] {
        assert_eq!(
            posix_absolute_path_candidate(content, 0),
            PathCandidate::None,
            "{content:?}"
        );
    }
}

#[test]
fn classifies_only_candidates_beyond_the_span_as_over_span() {
    let maximum = format!("/{}", "a".repeat(4_095));
    assert_eq!(
        posix_absolute_path_candidate(&maximum, 0),
        PathCandidate::Matched(0..4_096)
    );

    let over_span = format!("{maximum}a");
    assert_eq!(
        posix_absolute_path_candidate(&over_span, 0),
        PathCandidate::OverSpan
    );
}

#[test]
fn scan_does_not_apply_the_path_candidate() {
    let content = "/workspace/secret.txt";
    let result = scan(content, true);
    assert!(result.matches.is_empty());
    assert_eq!(result.withhold_from, None);
}
