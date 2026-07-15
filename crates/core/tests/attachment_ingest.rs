use muniment_core::attachment::{
    ingest_attachment, AttachmentIngestError, AttachmentMetadata, AttachmentValidationError,
    ChatAttachment, ATTACHMENT_EVENT_TYPE, ATTACHMENT_EVENT_VERSION,
};
use muniment_core::cas::LocalCas;
use muniment_core::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const RUN: &str = "0190a100-0000-7000-8000-000000000001";

struct Fixture {
    root: PathBuf,
    cas: LocalCas,
    journal: RunJournal,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "muniment-attachment-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self {
            cas: LocalCas::open(&root.join("cas")).unwrap(),
            journal: RunJournal::open(root.join("journal.sqlite3")).unwrap(),
            root,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn event(seq: u64, attachment: ChatAttachment) -> EventEnvelope {
    EventEnvelope {
        event_id: format!("0190a100-0000-7000-8000-{seq:012}"),
        run_id: RUN.into(),
        run_seq: seq,
        event_type: "replaced.by.ingest".into(),
        event_version: 99,
        envelope_version: 1,
        recorded_at: "2026-07-15T12:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Attachment { attachment },
        provenance: Provenance {
            source: "test".into(),
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

struct GeneratedReader {
    remaining: u64,
    reads: usize,
}

impl Read for GeneratedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        self.reads += 1;
        let count = usize::try_from(self.remaining.min(buffer.len() as u64).min(8191)).unwrap();
        buffer[..count].fill(0x5a);
        self.remaining -= count as u64;
        Ok(count)
    }
}

#[test]
fn streams_multiple_buffers_and_round_trips_safe_metadata_and_reference() {
    let mut fixture = Fixture::new();
    let length = 3 * 64 * 1024 + 17;
    let mut reader = GeneratedReader {
        remaining: length,
        reads: 0,
    };
    let attachment = ingest_attachment(
        &fixture.cas,
        &mut fixture.journal,
        0,
        &mut reader,
        AttachmentMetadata {
            display_name: r"C:\Users\Ada\contract.pdf",
            byte_length: length,
            media_type: Some("Application/PDF"),
        },
        |attachment| event(1, attachment),
    )
    .unwrap();

    assert!(reader.reads > 3);
    assert_eq!(attachment.display_name(), "contract.pdf");
    assert_eq!(attachment.media_type(), Some("application/pdf"));
    assert!(fixture.cas.has(attachment.sha256()).unwrap());
    assert_eq!(
        fixture.journal.referenced_hashes().unwrap(),
        HashSet::from([attachment.sha256().clone()])
    );
    let stored = fixture.journal.events(RUN).unwrap().pop().unwrap();
    assert_eq!(stored.event_type, ATTACHMENT_EVENT_TYPE);
    assert_eq!(stored.event_version, ATTACHMENT_EVENT_VERSION);
    assert_eq!(
        stored.payload,
        EventPayload::Attachment {
            attachment: attachment.clone()
        }
    );
    let serialized = serde_json::to_string(&stored).unwrap();
    assert!(!serialized.contains("Users"));
}

#[test]
fn rejects_unsafe_metadata_and_declared_size_mismatch() {
    for name in ["", "  ", "/", "../..", "safe/\n"] {
        let mut fixture = Fixture::new();
        let error = ingest_attachment(
            &fixture.cas,
            &mut fixture.journal,
            0,
            &mut Cursor::new(b"x"),
            AttachmentMetadata {
                display_name: name,
                byte_length: 1,
                media_type: None,
            },
            |attachment| event(1, attachment),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            AttachmentIngestError::Validation(AttachmentValidationError::InvalidDisplayName)
        ));
    }

    let mut fixture = Fixture::new();
    let error = ingest_attachment(
        &fixture.cas,
        &mut fixture.journal,
        0,
        &mut Cursor::new(b"abc"),
        AttachmentMetadata {
            display_name: "report.txt",
            byte_length: 4,
            media_type: Some("text/plain; charset=utf-8"),
        },
        |attachment| event(1, attachment),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        AttachmentIngestError::Validation(AttachmentValidationError::InvalidMediaType(_))
    ));

    let error = ingest_attachment(
        &fixture.cas,
        &mut fixture.journal,
        0,
        &mut Cursor::new(b"abc"),
        AttachmentMetadata {
            display_name: "report.txt",
            byte_length: 4,
            media_type: Some("text/plain"),
        },
        |attachment| event(1, attachment),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        AttachmentIngestError::ByteCountMismatch {
            declared: 4,
            actual: 3,
            ..
        }
    ));
    assert!(fixture.journal.events(RUN).unwrap().is_empty());
}

#[test]
fn duplicate_content_deduplicates_and_append_failure_leaves_only_an_orphan() {
    let mut fixture = Fixture::new();
    let first = ingest_attachment(
        &fixture.cas,
        &mut fixture.journal,
        0,
        &mut Cursor::new(b"same"),
        AttachmentMetadata {
            display_name: "first.txt",
            byte_length: 4,
            media_type: Some("text/plain"),
        },
        |attachment| event(1, attachment),
    )
    .unwrap();
    let error = ingest_attachment(
        &fixture.cas,
        &mut fixture.journal,
        0,
        &mut Cursor::new(b"same"),
        AttachmentMetadata {
            display_name: "second.txt",
            byte_length: 4,
            media_type: None,
        },
        |attachment| event(2, attachment),
    )
    .unwrap_err();
    let failed = match error {
        AttachmentIngestError::JournalAppend { attachment, .. } => attachment,
        other => panic!("unexpected error: {other}"),
    };
    assert_eq!(failed.sha256(), first.sha256());
    assert_eq!(fixture.cas.object_hashes().unwrap().count(), 1);
    assert_eq!(
        fixture.journal.referenced_hashes().unwrap(),
        HashSet::from([first.sha256().clone()])
    );

    let orphan_error = ingest_attachment(
        &fixture.cas,
        &mut fixture.journal,
        0,
        &mut Cursor::new(b"orphan"),
        AttachmentMetadata {
            display_name: "orphan.bin",
            byte_length: 6,
            media_type: None,
        },
        |attachment| event(2, attachment),
    )
    .unwrap_err();
    let orphan = match orphan_error {
        AttachmentIngestError::JournalAppend { attachment, .. } => attachment,
        other => panic!("unexpected error: {other}"),
    };
    assert!(fixture.cas.has(orphan.sha256()).unwrap());
    assert!(!fixture
        .journal
        .referenced_hashes()
        .unwrap()
        .contains(orphan.sha256()));
    assert_eq!(
        fixture
            .cas
            .collect_unreferenced(&fixture.journal.referenced_hashes().unwrap())
            .unwrap(),
        HashSet::from([orphan.sha256().clone()])
    );
}

#[test]
fn attachment_hash_deserialization_is_validated() {
    let invalid = json!({
        "sha256": "../not-a-hash",
        "display_name": "safe.txt",
        "byte_length": 1
    });
    assert!(serde_json::from_value::<ChatAttachment>(invalid).is_err());
}
