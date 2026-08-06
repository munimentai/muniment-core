use muniment_core::auth::EntitlementSnapshotTracker;

#[test]
fn first_observation_does_not_report_a_change() {
    let tracker = EntitlementSnapshotTracker::new();
    assert_eq!(tracker.observe(Some(1)), None);
}

#[test]
fn unchanged_version_does_not_report_a_change() {
    let tracker = EntitlementSnapshotTracker::new();
    tracker.observe(Some(1));
    assert_eq!(tracker.observe(Some(1)), None);
}

#[test]
fn changed_version_reports_the_next_version() {
    let tracker = EntitlementSnapshotTracker::new();
    tracker.observe(Some(1));
    assert_eq!(tracker.observe(Some(2)), Some(2));
}

#[test]
fn none_stores_an_unobserved_value() {
    let tracker = EntitlementSnapshotTracker::new();
    tracker.observe(Some(1));
    assert_eq!(tracker.observe(None), None);
    assert_eq!(tracker.observe(Some(2)), None);
}

#[test]
fn clear_makes_the_same_version_a_first_observation_again() {
    let tracker = EntitlementSnapshotTracker::new();
    tracker.observe(Some(1));
    tracker.clear();
    assert_eq!(tracker.observe(Some(1)), None);
}
