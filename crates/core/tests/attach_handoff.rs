use muniment_core::attach::{PreparedHandoffError, PreparedHandoffSlot};
use std::time::{Duration, Instant};

#[test]
fn accepts_a_valid_preparation_and_matches_only_its_nonce() {
    let now = Instant::now();
    let mut slot = PreparedHandoffSlot::new();

    slot.prepare("handoff-nonce", 30_000, now).unwrap();

    assert!(slot.matches("handoff-nonce", now));
    assert!(!slot.matches("another-nonce", now));
}

#[test]
fn rejects_a_second_live_preparation() {
    let now = Instant::now();
    let mut slot = PreparedHandoffSlot::new();
    slot.prepare("first-nonce", 1_000, now).unwrap();

    assert_eq!(
        slot.prepare("second-nonce", 1_000, now),
        Err(PreparedHandoffError::AlreadyPrepared)
    );
    assert!(slot.matches("first-nonce", now));
    assert!(!slot.matches("second-nonce", now));
}

#[test]
fn rejects_invalid_nonces() {
    let now = Instant::now();

    for (nonce, expected) in [
        ("".to_owned(), PreparedHandoffError::EmptyNonce),
        ("a".repeat(129), PreparedHandoffError::NonceTooLong),
        (
            "line\nbreak".to_owned(),
            PreparedHandoffError::NonceNotPrintableAscii,
        ),
        (
            "non-ascii-é".to_owned(),
            PreparedHandoffError::NonceNotPrintableAscii,
        ),
    ] {
        assert_eq!(
            PreparedHandoffSlot::new().prepare(nonce, 1, now),
            Err(expected)
        );
    }

    PreparedHandoffSlot::new()
        .prepare("a".repeat(128), 1, now)
        .unwrap();
}

#[test]
fn rejects_deadlines_outside_the_bound() {
    let now = Instant::now();

    for deadline_ms in [0, 60_001, u64::MAX] {
        assert_eq!(
            PreparedHandoffSlot::new().prepare("nonce", deadline_ms, now),
            Err(PreparedHandoffError::DeadlineOutOfRange)
        );
    }

    PreparedHandoffSlot::new()
        .prepare("nonce", 60_000, now)
        .unwrap();
}

#[test]
fn the_deadline_is_exclusive_and_an_expired_preparation_can_be_replaced() {
    let now = Instant::now();
    let deadline = now + Duration::from_millis(10);
    let mut slot = PreparedHandoffSlot::new();
    slot.prepare("old-nonce", 10, now).unwrap();

    assert!(slot.matches("old-nonce", deadline - Duration::from_nanos(1)));
    assert!(!slot.matches("old-nonce", deadline));
    assert!(!slot.matches("old-nonce", deadline + Duration::from_nanos(1)));

    slot.prepare("new-nonce", 20, deadline).unwrap();
    assert!(slot.matches("new-nonce", deadline));
    assert!(!slot.matches("old-nonce", deadline));
}

#[test]
fn cancel_clears_the_preparation_and_allows_another() {
    let now = Instant::now();
    let mut slot = PreparedHandoffSlot::new();
    slot.prepare("old-nonce", 1_000, now).unwrap();

    slot.cancel();

    assert!(!slot.matches("old-nonce", now));
    slot.prepare("new-nonce", 1_000, now).unwrap();
    assert!(slot.matches("new-nonce", now));
}

#[test]
fn debug_output_does_not_disclose_nonces() {
    let now = Instant::now();
    let secret = "secret-handoff-nonce";
    let mut slot = PreparedHandoffSlot::new();
    slot.prepare(secret, 1_000, now).unwrap();

    assert!(!format!("{slot:?}").contains(secret));
    for error in [
        PreparedHandoffError::AlreadyPrepared,
        PreparedHandoffError::EmptyNonce,
        PreparedHandoffError::NonceTooLong,
        PreparedHandoffError::NonceNotPrintableAscii,
        PreparedHandoffError::DeadlineOutOfRange,
    ] {
        assert!(!format!("{error:?}").contains(secret));
    }
}
