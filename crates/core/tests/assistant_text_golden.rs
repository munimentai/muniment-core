use muniment_core::assistant_text::projector::{Projection, Projector};
use serde::Deserialize;
use std::{collections::BTreeSet, path::Path};

const INPUTS: &str = include_str!("fixtures/assistant-text-v1-inputs.json");
const EXPECTED: &str = include_str!("fixtures/assistant-text-v1-expected.json");

#[derive(Deserialize)]
struct Inputs {
    rule_set: String,
    approved_workspace: String,
    boundary_cases: Vec<BoundaryCase>,
    three_delta: ThreeDelta,
    terminal: Terminal,
    paths: Paths,
}

#[derive(Deserialize)]
struct BoundaryCase {
    name: String,
    secret: String,
    safe_before: String,
    safe_after: String,
}

#[derive(Deserialize)]
struct ThreeDelta {
    secret: String,
    safe_before: String,
    safe_after: String,
    split_after: [usize; 2],
}

#[derive(Deserialize)]
struct Terminal {
    secret: String,
    safe_before: String,
}

#[derive(Deserialize)]
struct Paths {
    inside: String,
    outside: String,
}

#[derive(Deserialize)]
struct Expected {
    rule_set: String,
    boundary_cases: Vec<BoundaryExpected>,
    three_delta: Vec<GoldenProjection>,
    terminal: Vec<GoldenProjection>,
    paths: PathExpected,
}

#[derive(Deserialize)]
struct BoundaryExpected {
    name: String,
    projections: Vec<GoldenProjection>,
}

#[derive(Deserialize)]
struct PathExpected {
    inside: Vec<GoldenProjection>,
    outside: Vec<GoldenProjection>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct GoldenProjection {
    run_seq: u64,
    text: Option<String>,
    withheld: bool,
}

fn fixtures() -> (Inputs, Expected) {
    let inputs: Inputs = serde_json::from_str(INPUTS).expect("input fixture must parse");
    let expected: Expected = serde_json::from_str(EXPECTED).expect("expected fixture must parse");
    assert_eq!(inputs.rule_set, "assistant-text-v1");
    assert_eq!(expected.rule_set, inputs.rule_set);
    (inputs, expected)
}

fn project(workspace: &str, deltas: &[(u64, String)]) -> Vec<Projection> {
    let mut projector = Projector::new(workspace, |path: &Path| Ok::<_, ()>(path.to_path_buf()));
    let mut projections = Vec::new();
    for (run_seq, text) in deltas {
        projections.extend(projector.push(*run_seq, text).unwrap());
    }
    projections.extend(projector.finish().unwrap());
    projections
}

fn assert_golden(actual: &[Projection], expected: &[GoldenProjection]) {
    let actual: Vec<_> = actual
        .iter()
        .map(|projection| GoldenProjection {
            run_seq: projection.run_seq,
            text: projection.text.clone(),
            withheld: projection.withheld,
        })
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn each_secret_rule_withholds_at_every_adjacent_delta_boundary() {
    let (inputs, expected) = fixtures();
    let names: BTreeSet<_> = inputs
        .boundary_cases
        .iter()
        .map(|case| case.name.as_str())
        .collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "secret.assignment",
            "secret.jwt",
            "secret.pem-private-key",
            "secret.provider-token",
        ])
    );

    for case in &inputs.boundary_cases {
        let golden = expected
            .boundary_cases
            .iter()
            .find(|golden| golden.name == case.name)
            .expect("each input must have expected projections");
        assert_eq!(golden.projections.len(), 2);
        for boundary in 1..case.secret.len() {
            assert!(case.secret.is_char_boundary(boundary));
            let deltas = [
                (
                    golden.projections[0].run_seq,
                    format!("{}{}", case.safe_before, &case.secret[..boundary]),
                ),
                (
                    golden.projections[1].run_seq,
                    format!("{}{}", &case.secret[boundary..], case.safe_after),
                ),
            ];
            let actual = project(&inputs.approved_workspace, &deltas);
            assert_golden(&actual, &golden.projections);
            let released: String = actual
                .iter()
                .filter_map(|item| item.text.as_deref())
                .collect();
            assert_eq!(released, format!("{}{}", case.safe_before, case.safe_after));
            assert!(
                !released.contains(&case.secret),
                "{} at {boundary}",
                case.name
            );
        }
    }
}

#[test]
fn three_deltas_and_a_terminal_secret_match_the_goldens() {
    let (inputs, expected) = fixtures();
    let [first, second] = inputs.three_delta.split_after;
    assert!(first < second && second < inputs.three_delta.secret.len());
    let three_deltas = [
        (
            200,
            format!(
                "{}{}",
                inputs.three_delta.safe_before,
                &inputs.three_delta.secret[..first]
            ),
        ),
        (201, inputs.three_delta.secret[first..second].to_owned()),
        (
            202,
            format!(
                "{}{}",
                &inputs.three_delta.secret[second..],
                inputs.three_delta.safe_after
            ),
        ),
    ];
    assert_golden(
        &project(&inputs.approved_workspace, &three_deltas),
        &expected.three_delta,
    );

    let terminal = [
        (300, inputs.terminal.safe_before.clone()),
        (301, inputs.terminal.secret.clone()),
    ];
    assert_golden(
        &project(&inputs.approved_workspace, &terminal),
        &expected.terminal,
    );
}

#[test]
fn workspace_injection_releases_only_the_approved_path() {
    let (inputs, expected) = fixtures();
    assert_golden(
        &project(&inputs.approved_workspace, &[(400, inputs.paths.inside)]),
        &expected.paths.inside,
    );
    assert_golden(
        &project(&inputs.approved_workspace, &[(401, inputs.paths.outside)]),
        &expected.paths.outside,
    );
}
