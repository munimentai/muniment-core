use muniment_core::assistant_text::ledger::{Ledger, LedgerError, Projection};
use std::ops::Range;

fn one(range: Range<u64>) -> Vec<Range<u64>> {
    std::iter::once(range).collect()
}

fn resolve_one(
    ledger: &mut Ledger,
    released_up_to: u64,
    withheld_range: Range<u64>,
) -> Result<Vec<Projection>, LedgerError> {
    ledger.resolve(released_up_to, std::slice::from_ref(&withheld_range))
}

#[test]
fn emits_completed_envelopes_once_in_push_order() {
    let mut ledger = Ledger::new();
    ledger.push(7, 4).unwrap();
    ledger.push(3, 3).unwrap();
    ledger.push(9, 2).unwrap();

    assert!(ledger.resolve(3, &[]).unwrap().is_empty());
    assert_eq!(
        ledger.resolve(7, &[]).unwrap(),
        vec![
            Projection {
                run_seq: 7,
                released_ranges: one(0..4),
            },
            Projection {
                run_seq: 3,
                released_ranges: one(4..7),
            },
        ]
    );
    assert!(ledger.resolve(7, &[]).unwrap().is_empty());
    assert_eq!(
        ledger.resolve(9, &[]).unwrap(),
        vec![Projection {
            run_seq: 9,
            released_ranges: one(7..9),
        }]
    );
}

#[test]
fn excludes_overlapping_withheld_ranges_and_emits_fully_withheld_envelope() {
    let mut ledger = Ledger::new();
    ledger.push(1, 10).unwrap();
    ledger.push(2, 5).unwrap();

    assert_eq!(
        ledger.resolve(15, &[2..5, 4..8, 10..15]).unwrap(),
        vec![
            Projection {
                run_seq: 1,
                released_ranges: vec![0..2, 8..10],
            },
            Projection {
                run_seq: 2,
                released_ranges: vec![],
            },
        ]
    );
}

#[test]
fn splits_a_withheld_range_across_envelopes() {
    let mut ledger = Ledger::new();
    ledger.push(1, 5).unwrap();
    ledger.push(2, 5).unwrap();

    let projections = resolve_one(&mut ledger, 10, 3..7).unwrap();
    assert_eq!(projections[0].released_ranges, vec![0..3]);
    assert_eq!(projections[1].released_ranges, vec![7..10]);
}

#[test]
fn retains_withheld_ranges_until_a_partial_envelope_completes() {
    let mut ledger = Ledger::new();
    ledger.push(4, 10).unwrap();

    assert!(resolve_one(&mut ledger, 5, 2..4).unwrap().is_empty());
    assert_eq!(
        resolve_one(&mut ledger, 10, 7..9).unwrap()[0].released_ranges,
        vec![0..2, 4..7, 9..10]
    );
}

#[test]
fn rejected_pushes_leave_spans_unchanged() {
    let mut ledger = Ledger::new();
    assert_eq!(ledger.push(1, 0), Err(LedgerError::ZeroLengthEnvelope));
    ledger.push(2, u64::MAX).unwrap();
    assert_eq!(ledger.push(3, 1), Err(LedgerError::StreamOffsetOverflow));
    assert_eq!(ledger.resolve(u64::MAX, &[]).unwrap()[0].run_seq, 2);
}

#[test]
fn rejected_resolves_leave_state_unchanged() {
    let mut ledger = Ledger::new();
    ledger.push(1, 5).unwrap();
    ledger.push(2, 5).unwrap();
    assert!(ledger.resolve(5, &[]).is_ok());

    assert_eq!(ledger.resolve(4, &[]), Err(LedgerError::BoundaryRegressed));
    assert_eq!(
        resolve_one(&mut ledger, 10, 8..11),
        Err(LedgerError::WithheldRangePastBoundary)
    );
    assert_eq!(
        resolve_one(&mut ledger, 10, 7..7),
        Err(LedgerError::InvalidWithheldRange)
    );
    assert_eq!(
        ledger.resolve(11, &[]),
        Err(LedgerError::BoundaryPastStream)
    );
    assert_eq!(ledger.resolve(10, &[]).unwrap()[0].run_seq, 2);
}
