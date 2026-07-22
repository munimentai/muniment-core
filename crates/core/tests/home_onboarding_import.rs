use chrono::NaiveDate;
use muniment_core::{
    home::{
        compile_onboarding_home_write_plan, OnboardingHomeWritePlanError,
        ONBOARDING_IMPORT_MAX_ENTRIES, ONBOARDING_IMPORT_MAX_TOTAL_BYTES,
    },
    import_preview::{EntryKind, ExtractedEntry},
    llama::OnboardingTriageReport,
};
use std::path::Component;

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
