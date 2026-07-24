use chrono::NaiveDate;
use muniment_core::{
    home::{
        compile_onboarding_home_write_plan, persist_onboarding_home_write_plan, scaffold_home,
        HomeWrite, OnboardingHomePersistenceError, OnboardingHomeWritePlan,
        OnboardingHomeWritePlanError, ONBOARDING_IMPORT_MAX_DOCUMENT_BYTES,
        ONBOARDING_IMPORT_MAX_ENTRIES, ONBOARDING_IMPORT_MAX_TOTAL_BYTES,
    },
    import_preview::{EntryKind, ExtractedEntry},
    llama::OnboardingTriageReport,
};
use std::{
    fs,
    path::{Component, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Barrier},
};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempHome(PathBuf);

impl TempHome {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "muniment-onboarding-{name}-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        scaffold_home(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn public_plan(writes: &[(&str, &str)]) -> OnboardingHomeWritePlan {
    OnboardingHomeWritePlan {
        writes: writes
            .iter()
            .map(|(relative_path, contents)| HomeWrite {
                relative_path: (*relative_path).into(),
                contents: (*contents).into(),
            })
            .collect(),
    }
}

fn report(agents: &[&str]) -> OnboardingTriageReport {
    OnboardingTriageReport::parse(&format!(
        "## User type\nBuilder\n## Proposed Home layout\nKeep projects organized.\n## Starter agents\n{}",
        agents
            .iter()
            .map(|agent| format!("- {agent}"))
            .collect::<Vec<_>>()
            .join("\n")
    ))
    .unwrap()
}

fn entry(name: &str, provenance: &str, text: &str) -> ExtractedEntry {
    ExtractedEntry {
        source_name: name.into(),
        kind: EntryKind::Markdown,
        text: text.into(),
        source_provenance: provenance.into(),
    }
}

#[test]
fn compiles_multiple_sources_deterministically_and_preserves_verbatim_bodies() {
    let report = report(&["Research / reviewer", "../../Shell runner"]);
    let entries = vec![
        entry(
            "../../notes.md",
            "claude-export:one\nquoted",
            "first\r\n---\n\0last",
        ),
        entry("/absolute.json", "codex-export:two", "second body\n"),
    ];
    let date = NaiveDate::from_ymd_opt(2026, 7, 21).unwrap();

    let first = compile_onboarding_home_write_plan(&report, &entries, date).unwrap();
    let second = compile_onboarding_home_write_plan(&report, &entries, date).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.writes().len(), 5);

    for write in first.writes() {
        let path = write.relative_path();
        assert!(!path.is_absolute());
        assert!(path.starts_with("memory") || path.starts_with("agents"));
        assert!(!path
            .components()
            .any(|part| matches!(part, Component::ParentDir)));
    }
    assert!(first.writes()[1]
        .relative_path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("agent-research-reviewer-"));
    assert!(first.writes()[2]
        .relative_path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("agent-shell-runner-"));

    for (write, original) in first.writes()[3..].iter().zip(&entries) {
        let frontmatter = format!(
            "---\nsource: {}\nimport_date: 2026-07-21\n---\n",
            serde_json::to_string(&original.source_provenance).unwrap()
        );
        assert!(write.bytes().starts_with(frontmatter.as_bytes()));
        assert_eq!(
            &write.bytes()[frontmatter.len()..],
            original.text.as_bytes()
        );
    }
}

#[test]
fn rejects_empty_inputs_and_disambiguates_duplicate_destinations() {
    let valid_report = report(&["One", "Two"]);
    let date = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
    assert_eq!(
        compile_onboarding_home_write_plan(&valid_report, &[], date),
        Err(OnboardingHomeWritePlanError::EmptyInput)
    );
    assert_eq!(
        compile_onboarding_home_write_plan(&valid_report, &[entry("x", "p", "")], date),
        Err(OnboardingHomeWritePlanError::EmptyInput)
    );

    let duplicate = entry("same.md", "same-source", "body");
    let duplicate_plan =
        compile_onboarding_home_write_plan(&valid_report, &[duplicate.clone(), duplicate], date)
            .unwrap();
    assert_ne!(
        duplicate_plan.writes()[3].relative_path(),
        duplicate_plan.writes()[4].relative_path()
    );
    let disambiguated = compile_onboarding_home_write_plan(
        &report(&["../", "\\"]),
        &[entry("x", "p", "body")],
        date,
    )
    .unwrap();
    assert_ne!(
        disambiguated.writes()[1].relative_path(),
        disambiguated.writes()[2].relative_path()
    );
}

#[test]
fn revalidates_publicly_constructed_reports() {
    let date = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
    let entries = [entry("x", "p", "body")];
    let mut invalid = report(&["One", "Two"]);
    invalid.user_type.clear();
    assert_eq!(
        compile_onboarding_home_write_plan(&invalid, &entries, date),
        Err(OnboardingHomeWritePlanError::EmptyInput)
    );

    for (agents, expected) in [
        (vec![], OnboardingHomeWritePlanError::EmptyInput),
        (
            vec!["One".into()],
            OnboardingHomeWritePlanError::InvalidReport,
        ),
        (vec!["".into()], OnboardingHomeWritePlanError::EmptyInput),
        (
            vec!["One".into(); 4],
            OnboardingHomeWritePlanError::InvalidReport,
        ),
    ] {
        let invalid = OnboardingTriageReport {
            user_type: "Builder".into(),
            proposed_home_layout: "Layout".into(),
            starter_agents: agents,
        };
        assert_eq!(
            compile_onboarding_home_write_plan(&invalid, &entries, date),
            Err(expected)
        );
    }

    let mut invalid = report(&["One", "Two"]);
    invalid.proposed_home_layout = "x".repeat(32 * 1024);
    assert_eq!(
        compile_onboarding_home_write_plan(&invalid, &entries, date),
        Err(OnboardingHomeWritePlanError::InvalidReport)
    );
}

#[test]
fn enforces_entry_count_and_total_byte_bounds() {
    let report = report(&["One", "Two"]);
    let date = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
    let too_many = (0..=ONBOARDING_IMPORT_MAX_ENTRIES)
        .map(|index| entry(&format!("{index}.md"), "source", "x"))
        .collect::<Vec<_>>();
    assert_eq!(
        compile_onboarding_home_write_plan(&report, &too_many, date),
        Err(OnboardingHomeWritePlanError::TooManyEntries)
    );

    let too_large = entry(
        "large.md",
        "source",
        &"x".repeat(ONBOARDING_IMPORT_MAX_TOTAL_BYTES),
    );
    assert_eq!(
        compile_onboarding_home_write_plan(&report, &[too_large], date),
        Err(OnboardingHomeWritePlanError::DocumentBytesExceeded)
    );

    let oversized_aggregate = [
        entry("one.md", "source-one", &"x".repeat(200 * 1024)),
        entry("two.md", "source-two", &"y".repeat(200 * 1024)),
    ];
    assert_eq!(
        compile_onboarding_home_write_plan(&report, &oversized_aggregate, date),
        Err(OnboardingHomeWritePlanError::DocumentBytesExceeded)
    );
}

#[test]
fn persists_multiple_markdown_files_byte_for_byte() {
    let home = TempHome::new("success");
    let plan = public_plan(&[
        ("memory/imports/one.md", "first\r\n\0body"),
        ("agents/two.md", "# café 🦀\n"),
    ]);

    persist_onboarding_home_write_plan(&home.0, &plan).unwrap();

    assert_eq!(
        fs::read(home.0.join("memory/imports/one.md")).unwrap(),
        b"first\r\n\0body"
    );
    assert_eq!(
        fs::read(home.0.join("agents/two.md")).unwrap(),
        "# café 🦀\n".as_bytes()
    );
    assert!(!fs::read_dir(home.0.join("memory/imports"))
        .unwrap()
        .any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
}

#[test]
fn rejects_unsafe_duplicate_and_oversized_public_plans_before_writing() {
    let home = TempHome::new("invalid");
    for path in [
        "../outside.md",
        "/absolute.md",
        "C:/absolute.md",
        "memory//unnormalized.md",
        "memory/./unnormalized.md",
        "memory/not-markdown.txt",
        "memory/nul\0name.md",
    ] {
        assert!(matches!(
            persist_onboarding_home_write_plan(&home.0, &public_plan(&[(path, "body")])),
            Err(OnboardingHomePersistenceError::InvalidPlan)
        ));
    }

    let duplicate = public_plan(&[("memory/same.md", "one"), ("memory/same.md", "two")]);
    assert!(matches!(
        persist_onboarding_home_write_plan(&home.0, &duplicate),
        Err(OnboardingHomePersistenceError::InvalidPlan)
    ));
    let case_duplicate = public_plan(&[("memory/Same.md", "one"), ("memory/same.md", "two")]);
    assert!(matches!(
        persist_onboarding_home_write_plan(&home.0, &case_duplicate),
        Err(OnboardingHomePersistenceError::InvalidPlan)
    ));

    let oversized = OnboardingHomeWritePlan {
        writes: vec![HomeWrite {
            relative_path: "memory/large.md".into(),
            contents: "x".repeat(ONBOARDING_IMPORT_MAX_DOCUMENT_BYTES + 1),
        }],
    };
    assert!(matches!(
        persist_onboarding_home_write_plan(&home.0, &oversized),
        Err(OnboardingHomePersistenceError::DocumentBytesExceeded)
    ));

    let too_many = OnboardingHomeWritePlan {
        writes: (0..ONBOARDING_IMPORT_MAX_ENTRIES + 5)
            .map(|index| HomeWrite {
                relative_path: format!("memory/{index}.md"),
                contents: "x".into(),
            })
            .collect(),
    };
    assert!(matches!(
        persist_onboarding_home_write_plan(&home.0, &too_many),
        Err(OnboardingHomePersistenceError::TooManyEntries)
    ));

    let aggregate = OnboardingHomeWritePlan {
        writes: (0..5)
            .map(|index| HomeWrite {
                relative_path: format!("memory/aggregate-{index}.md"),
                contents: "x".repeat(60_000),
            })
            .collect(),
    };
    assert!(matches!(
        persist_onboarding_home_write_plan(&home.0, &aggregate),
        Err(OnboardingHomePersistenceError::TotalBytesExceeded)
    ));
    assert!(!home.0.join("memory/large.md").exists());
}

#[test]
fn collision_preflight_preserves_user_files_and_allows_a_clean_retry() {
    let home = TempHome::new("collision");
    let user_file = home.0.join("memory/user.md");
    fs::write(&user_file, b"user-authored content").unwrap();
    let plan = public_plan(&[
        ("agents/new.md", "new agent"),
        ("memory/user.md", "replacement"),
    ]);

    match persist_onboarding_home_write_plan(&home.0, &plan) {
        Err(OnboardingHomePersistenceError::DestinationConflict { relative_path }) => {
            assert_eq!(relative_path, "memory/user.md")
        }
        result => panic!("expected a typed destination conflict, got {result:?}"),
    }
    assert_eq!(fs::read(&user_file).unwrap(), b"user-authored content");
    assert!(!home.0.join("agents/new.md").exists());

    fs::remove_file(&user_file).unwrap();
    persist_onboarding_home_write_plan(&home.0, &plan).unwrap();
    assert_eq!(fs::read(&user_file).unwrap(), b"replacement");
    assert_eq!(
        fs::read(home.0.join("agents/new.md")).unwrap(),
        b"new agent"
    );
}

#[test]
fn directories_at_destinations_are_typed_conflicts() {
    let home = TempHome::new("directory-conflict");
    fs::create_dir(home.0.join("memory/existing.md")).unwrap();

    assert!(matches!(
        persist_onboarding_home_write_plan(
            &home.0,
            &public_plan(&[("memory/existing.md", "replacement")])
        ),
        Err(OnboardingHomePersistenceError::DestinationConflict { relative_path })
            if relative_path == "memory/existing.md"
    ));
    assert!(home.0.join("memory/existing.md").is_dir());
}

#[test]
fn concurrent_attempts_serialize_and_never_replace_the_winner() {
    let home = TempHome::new("concurrent");
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for contents in ["first", "second"] {
        let home = home.0.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            let plan = public_plan(&[("memory/race.md", contents)]);
            barrier.wait();
            persist_onboarding_home_write_plan(&home, &plan)
        }));
    }
    barrier.wait();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(OnboardingHomePersistenceError::DestinationConflict { relative_path })
                    if relative_path == "memory/race.md"
            ))
            .count(),
        1
    );
    let contents = fs::read(home.0.join("memory/race.md")).unwrap();
    assert!(contents == b"first" || contents == b"second");
}

#[cfg(unix)]
#[test]
fn symlinks_at_destinations_are_typed_conflicts() {
    use std::os::unix::fs::symlink;

    let home = TempHome::new("symlink-conflict");
    let user_file = home.0.join("user-file");
    fs::write(&user_file, b"user-authored content").unwrap();
    symlink(&user_file, home.0.join("memory/existing.md")).unwrap();

    assert!(matches!(
        persist_onboarding_home_write_plan(
            &home.0,
            &public_plan(&[("memory/existing.md", "replacement")])
        ),
        Err(OnboardingHomePersistenceError::DestinationConflict { relative_path })
            if relative_path == "memory/existing.md"
    ));
    assert_eq!(fs::read(user_file).unwrap(), b"user-authored content");
}
