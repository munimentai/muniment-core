use muniment_core::assistant_text::projector::{Projection, Projector, ProjectorError};
use std::path::Path;

fn projector() -> Projector<impl FnMut(&Path) -> Result<std::path::PathBuf, ()>> {
    Projector::new("/workspace", |path: &Path| Ok(path.to_path_buf()))
}

#[test]
fn withholds_a_provider_token_split_across_envelopes() {
    let mut projector = projector();
    assert!(projector.push(4, "safe AKIAAAAA").unwrap().is_empty());
    assert!(projector.push(5, "AAAAAAAAAAAA end").unwrap().is_empty());

    assert_eq!(
        projector.finish().unwrap(),
        vec![
            Projection {
                run_seq: 4,
                text: Some("safe ".into()),
                withheld: false,
            },
            Projection {
                run_seq: 5,
                text: Some(" end".into()),
                withheld: false,
            },
        ]
    );
}

#[test]
fn releases_safe_text_byte_for_byte_after_suffix_pruning() {
    let first = "é ".repeat(40_000);
    let second = "z ".repeat(40_000);
    let mut projector = projector();
    assert!(projector.push(1, &first).unwrap().is_empty());
    let mut projections = projector.push(2, &second).unwrap();
    projections.extend(projector.finish().unwrap());

    assert_eq!(projections.len(), 2);
    assert_eq!(projections[0].text.as_deref(), Some(first.as_str()));
    assert_eq!(projections[1].text.as_deref(), Some(second.as_str()));
}

#[test]
fn an_overlong_assignment_withholds_everything_from_its_label() {
    let mut projector = projector();
    let overlong = format!("safe token={} later", "a".repeat(151));
    let projections = projector.push(10, &overlong).unwrap();
    assert_eq!(
        projections,
        vec![Projection {
            run_seq: 10,
            text: Some("safe ".into()),
            withheld: false,
        }]
    );
    assert_eq!(
        projector.push(11, "never released").unwrap(),
        vec![Projection {
            run_seq: 11,
            text: None,
            withheld: true,
        }]
    );
    assert!(projector.finish().unwrap().is_empty());
}

#[test]
fn rejects_empty_deltas_and_input_after_finish() {
    let mut projector = projector();
    assert_eq!(
        projector.push(1, ""),
        Err(ProjectorError::Ledger(
            muniment_core::assistant_text::ledger::LedgerError::ZeroLengthEnvelope
        ))
    );
    assert!(projector.finish().unwrap().is_empty());
    assert_eq!(projector.push(2, "text"), Err(ProjectorError::Finished));
    assert_eq!(projector.finish(), Err(ProjectorError::Finished));
}

#[test]
fn applies_workspace_scope_through_the_injected_canonicalizer() {
    let mut projector = projector();
    assert!(projector
        .push(1, "inside /workspace/file ")
        .unwrap()
        .is_empty());
    assert!(projector.push(2, "outside /other/file").unwrap().is_empty());

    assert_eq!(
        projector.finish().unwrap(),
        vec![
            Projection {
                run_seq: 1,
                text: Some("inside /workspace/file ".into()),
                withheld: false,
            },
            Projection {
                run_seq: 2,
                text: Some("outside ".into()),
                withheld: false,
            },
        ]
    );
}
