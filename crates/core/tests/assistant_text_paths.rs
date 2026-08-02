use muniment_core::assistant_text::{
    classify_posix_absolute_path, classify_windows_absolute_path, posix_absolute_path_candidate,
    scan, scan_with_workspace, windows_absolute_path_candidate, PathCandidate, PathClassification,
    Rule,
};
#[cfg(unix)]
use std::fs;
use std::{io, path::Path};

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
fn workspace_scan_releases_an_in_scope_path() {
    let content = "open /workspace/secret.txt now";
    let result = scan_with_workspace(content, true, Path::new("/workspace"), |path| {
        Ok::<_, io::Error>(path.to_path_buf())
    });
    assert!(result.matches.is_empty());
    assert_eq!(result.withhold_from, None);
}

#[test]
fn workspace_scan_preserves_a_secret_inside_a_released_path() {
    let content = format!("/workspace/sk-{}", "a".repeat(20));
    let expected = scan(&content, true);
    let actual = scan_with_workspace(&content, true, Path::new("/workspace"), |path| {
        Ok::<_, io::Error>(path.to_path_buf())
    });

    assert_eq!(actual, expected);
}

#[test]
fn workspace_scan_withholds_an_escape_and_a_validation_error() {
    let content = "open /workspace/../outside.txt now";
    let result = scan_with_workspace(content, true, Path::new("/workspace"), |path| {
        Ok::<_, io::Error>(match path.to_str().unwrap() {
            "/workspace" => "/canonical/workspace".into(),
            "/workspace/../outside.txt" => "/canonical/outside.txt".into(),
            path => panic!("unexpected path: {path}"),
        })
    });
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].range, 5..30);
    assert_eq!(result.matches[0].rule, Rule::PathPosixAbsolute);
    assert_eq!(result.withhold_from, None);

    let content = "open /workspace/missing.txt now";
    let result = scan_with_workspace(content, true, Path::new("/workspace"), |_| {
        Err::<std::path::PathBuf, _>(io::Error::other("validation failed"))
    });
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].range, 5..27);
    assert_eq!(result.matches[0].rule, Rule::PathPosixAbsolute);
    assert_eq!(result.withhold_from, None);
}

#[test]
fn workspace_scan_withholds_an_over_span_path_without_validation() {
    let content = format!("safe /{}", "a".repeat(4_096));
    let result = scan_with_workspace(
        &content,
        true,
        Path::new("/workspace"),
        |_| -> io::Result<std::path::PathBuf> {
            panic!("an over-span candidate must not reach scope validation")
        },
    );
    assert!(result.matches.is_empty());
    assert_eq!(result.withhold_from, Some(5));
}

#[test]
fn workspace_scan_leaves_safe_text_and_secret_behavior_unchanged() {
    let safe = "ordinary safe text";
    let result = scan_with_workspace(
        safe,
        true,
        Path::new("/workspace"),
        |_| -> io::Result<std::path::PathBuf> {
            panic!("safe text must not reach scope validation")
        },
    );
    assert!(result.matches.is_empty());
    assert_eq!(result.withhold_from, None);

    let content = "safe token=0123456789 text";
    for complete in [false, true] {
        let expected = scan(content, complete);
        let actual = scan_with_workspace(
            content,
            complete,
            Path::new("/workspace"),
            |_| -> io::Result<std::path::PathBuf> {
                panic!("secret text must not reach scope validation")
            },
        );
        assert_eq!(actual, expected, "{complete}");
    }
}

#[test]
#[cfg(unix)]
fn releases_the_workspace_root_descendants_and_non_ascii_paths() {
    let root = std::env::temp_dir().join(format!("muniment-path-scope-{}", uuid::Uuid::new_v4()));
    let descendant = root.join("資料").join("é.txt");
    fs::create_dir_all(descendant.parent().unwrap()).unwrap();
    fs::write(&descendant, b"test").unwrap();

    for path in [&root, &descendant] {
        let content = path.to_str().unwrap();
        assert_eq!(
            classify_posix_absolute_path(content, 0, &root, |path| path.canonicalize()),
            PathClassification::Released(0..content.len())
        );
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn withholds_traversal_symlink_escape_missing_paths_and_validation_errors() {
    let base = std::env::temp_dir().join(format!("muniment-path-scope-{}", uuid::Uuid::new_v4()));
    let root = base.join("workspace");
    let outside = base.join("outside.txt");
    fs::create_dir_all(&root).unwrap();
    fs::write(&outside, b"test").unwrap();

    let traversal = root.join("..").join("outside.txt");
    let missing = root.join("missing.txt");
    for path in [&outside, &traversal, &missing] {
        let content = path.to_str().unwrap();
        assert_eq!(
            classify_posix_absolute_path(content, 0, &root, |path| path.canonicalize()),
            PathClassification::Withheld(0)
        );
    }

    std::os::unix::fs::symlink(&outside, root.join("escape.txt")).unwrap();
    let escape = root.join("escape.txt");
    let content = escape.to_str().unwrap();
    assert_eq!(
        classify_posix_absolute_path(content, 0, &root, |path| path.canonicalize()),
        PathClassification::Withheld(0)
    );

    assert_eq!(
        classify_posix_absolute_path(root.to_str().unwrap(), 0, &root, |_| {
            Err::<std::path::PathBuf, _>("error")
        }),
        PathClassification::Withheld(0)
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn withholds_over_span_candidates_without_scope_validation() {
    let content = format!("/{}", "a".repeat(4_096));
    assert_eq!(
        classify_posix_absolute_path(&content, 0, Path::new("/workspace"), |_| -> io::Result<_> {
            panic!("an over-span candidate must not reach scope validation")
        }),
        PathClassification::Withheld(0)
    );

    assert_eq!(
        classify_posix_absolute_path(
            "not a path",
            0,
            Path::new("/workspace"),
            |_| -> io::Result<_> { panic!("a non-candidate must not reach scope validation") }
        ),
        PathClassification::None
    );
}

#[test]
fn matches_each_windows_root_and_components() {
    for path in [
        "C:\\",
        "z:\\src\\main.rs",
        "\\\\server\\share\\",
        "\\\\server\\share\\資料\\é",
        "\\\\?\\C:\\",
        "\\\\?\\z:\\src\\main.rs",
        "\\\\?\\UNC\\server\\share\\",
        "\\\\?\\UNC\\server\\share\\.\\..",
    ] {
        assert_eq!(
            windows_absolute_path_candidate(path, 0),
            PathCandidate::Matched(0..path.len()),
            "{path:?}"
        );
    }
}

#[test]
fn windows_paths_require_a_boundary_and_stop_before_terminators() {
    for boundary in ["", "(", "[", "{", ":", "=", ",", ";", " ", "\t", "\r", "\n"] {
        let content = format!("{boundary}C:\\tmp");
        assert_eq!(
            windows_absolute_path_candidate(&content, boundary.len()),
            PathCandidate::Matched(boundary.len()..content.len()),
            "{boundary:?}"
        );
    }
    assert_eq!(
        windows_absolute_path_candidate("xC:\\tmp", 1),
        PathCandidate::None
    );

    for terminator in *b"\0 \t\r\n'\"`<>|" {
        let content = format!("C:\\tmp{}tail", char::from(terminator));
        assert_eq!(
            windows_absolute_path_candidate(&content, 0),
            PathCandidate::Matched(0..6),
            "{terminator:?}"
        );
    }
}

#[test]
fn windows_paths_reject_invalid_roots_and_components() {
    for content in [
        "C:/tmp",
        "C:\\tmp/child",
        "C:\\tmp\\",
        "C:\\\\tmp",
        "\\\\server\\share",
        "\\\\server\\\\",
        "\\\\?\\C:/tmp",
        "\\\\?\\UNC\\server\\share",
        "\\\\?\\unc\\server\\share\\",
    ] {
        assert_eq!(
            windows_absolute_path_candidate(content, 0),
            PathCandidate::None,
            "{content:?}"
        );
    }
}

#[test]
fn windows_paths_exceed_the_span_only_after_the_limit() {
    let maximum = format!("C:\\{}", "a".repeat(131_065));
    assert_eq!(maximum.len(), 131_068);
    assert_eq!(
        windows_absolute_path_candidate(&maximum, 0),
        PathCandidate::Matched(0..131_068)
    );

    let terminated = format!("{maximum} ");
    assert_eq!(
        windows_absolute_path_candidate(&terminated, 0),
        PathCandidate::Matched(0..131_068)
    );

    let over_span = format!("{maximum}a");
    assert_eq!(
        windows_absolute_path_candidate(&over_span, 0),
        PathCandidate::OverSpan
    );
}

#[test]
fn scan_does_not_apply_the_windows_path_candidate() {
    let result = scan("C:\\workspace\\secret.txt", true);
    assert!(result.matches.is_empty());
    assert_eq!(result.withhold_from, None);
}

#[test]
#[cfg(windows)]
fn classifies_each_windows_path_form_inside_the_canonical_workspace() {
    let workspace = Path::new("C:\\workspace");
    for candidate in [
        "C:\\workspace\\drive.txt",
        "\\\\server\\share\\workspace\\unc.txt",
        "\\\\?\\C:\\workspace\\extended.txt",
        "\\\\?\\UNC\\server\\share\\workspace\\extended-unc.txt",
    ] {
        assert_eq!(
            classify_windows_absolute_path(candidate, 0, workspace, |path| {
                let canonical = match path.to_str().unwrap() {
                    "C:\\workspace" => "C:\\canonical-workspace",
                    "C:\\workspace\\drive.txt" => "C:\\canonical-workspace\\drive.txt",
                    "\\\\server\\share\\workspace\\unc.txt" => "C:\\canonical-workspace\\unc.txt",
                    "\\\\?\\C:\\workspace\\extended.txt" => "C:\\canonical-workspace\\extended.txt",
                    "\\\\?\\UNC\\server\\share\\workspace\\extended-unc.txt" => {
                        "C:\\canonical-workspace\\extended-unc.txt"
                    }
                    path => panic!("unexpected path: {path}"),
                };
                Ok::<_, io::Error>(canonical.into())
            }),
            PathClassification::Released(0..candidate.len()),
            "{candidate:?}"
        );
    }
}

#[test]
#[cfg(windows)]
fn withholds_windows_scope_failures() {
    let workspace = Path::new("C:\\workspace");
    for candidate in [
        "C:\\outside.txt",
        "C:\\workspace\\..\\outside.txt",
        "C:\\workspace\\reparse.txt",
        "C:\\workspace\\missing.txt",
    ] {
        assert_eq!(
            classify_windows_absolute_path(candidate, 0, workspace, |path| {
                match path.to_str().unwrap() {
                    "C:\\workspace" => Ok("C:\\canonical-workspace".into()),
                    "C:\\workspace\\missing.txt" => {
                        Err(io::Error::new(io::ErrorKind::NotFound, "missing path"))
                    }
                    _ => Ok("C:\\outside\\file.txt".into()),
                }
            }),
            PathClassification::Withheld(0),
            "{candidate:?}"
        );
    }

    assert_eq!(
        classify_windows_absolute_path("C:\\workspace\\file.txt", 0, workspace, |_| {
            Err::<std::path::PathBuf, _>(io::Error::other("validation failed"))
        }),
        PathClassification::Withheld(0)
    );
}

#[test]
fn withholds_over_span_windows_candidates_without_scope_validation() {
    let content = format!("C:\\{}", "a".repeat(131_066));
    assert_eq!(
        classify_windows_absolute_path(
            &content,
            0,
            Path::new("C:\\workspace"),
            |_| -> io::Result<_> {
                panic!("an over-span candidate must not reach scope validation")
            }
        ),
        PathClassification::Withheld(0)
    );

    assert_eq!(
        classify_windows_absolute_path(
            "not a path",
            0,
            Path::new("C:\\workspace"),
            |_| -> io::Result<_> { panic!("a non-candidate must not reach scope validation") }
        ),
        PathClassification::None
    );
}
