use muniment_core::journal::{EventEnvelope, EventPayload, Provenance};
use muniment_runtime_core::open_profile_storage;
use std::collections::BTreeMap;

mod common;
use common::TemporaryProfile;

fn started_event(run_id: &str) -> EventEnvelope {
    EventEnvelope {
        event_id: "018f0000-0000-7000-8000-000000000001".into(),
        run_id: run_id.into(),
        run_seq: 1,
        event_type: "run.started".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-08-11T00:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: "{}".parse().unwrap(),
        },
        provenance: Provenance {
            source: "service-test".into(),
            source_version: "1".into(),
            actor_id: None,
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        },
        extra: BTreeMap::new(),
    }
}

#[test]
fn opens_fresh_profile_storage() {
    let profile = TemporaryProfile::new("service-fresh", false);

    let storage = open_profile_storage(&profile.profile).unwrap();
    let mut storage = storage.lock().unwrap();

    assert!(profile.profile.join("runs.sqlite3").is_file());
    assert!(profile.profile.join("cas").is_dir());
    assert!(storage.journal.run_event_types().unwrap().is_empty());
}

#[test]
fn reconciles_an_interrupted_run_when_reopened() {
    let profile = TemporaryProfile::new("service-reopen", false);
    let run_id = "018f0000-0000-7000-8000-000000000002";
    {
        let storage = open_profile_storage(&profile.profile).unwrap();
        storage
            .lock()
            .unwrap()
            .journal
            .append(0, &started_event(run_id))
            .unwrap();
    }

    let storage = open_profile_storage(&profile.profile).unwrap();
    let mut storage = storage.lock().unwrap();
    let events = storage.journal.events(run_id).unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event_type, "run.needs_attention");
    assert_eq!(events[1].provenance.source, "muniment-runtime");
    assert_eq!(
        events[1].provenance.source_version,
        env!("CARGO_PKG_VERSION")
    );
}
