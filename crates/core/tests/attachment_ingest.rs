use muniment_core::attachment::{
    ingest_attachment, prepare_pi_images, AttachmentDeliveryError, AttachmentIngestError,
    AttachmentMetadata, AttachmentValidationError, ChatAttachment, ATTACHMENT_EVENT_TYPE,
    ATTACHMENT_EVENT_VERSION, MAX_DELIVERY_DISPLAY_NAME_CHARS, MAX_PI_IMAGE_BYTES,
    MAX_PI_IMAGE_COUNT, MAX_PI_IMAGE_TOTAL_BYTES,
};
use muniment_core::cas::LocalCas;
use muniment_core::journal::reducer::{project_chat, ReduceError};
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

fn attachment() -> ChatAttachment {
    serde_json::from_value(json!({
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "display_name": "evidence.txt",
        "byte_length": 8
    }))
    .unwrap()
}

fn inline_event(seq: u64, event_type: &str, payload_json: serde_json::Value) -> EventEnvelope {
    let mut event = event(seq, attachment());
    event.event_type = event_type.into();
    event.event_version = 1;
    event.payload = EventPayload::Inline { payload_json };
    event
}

fn attachment_event(seq: u64) -> EventEnvelope {
    let mut event = event(seq, attachment());
    event.event_type = ATTACHMENT_EVENT_TYPE.into();
    event.event_version = ATTACHMENT_EVENT_VERSION;
    event
}

fn stored_attachment_event(
    fixture: &Fixture,
    seq: u64,
    display_name: &str,
    bytes: &[u8],
    declared_length: u64,
) -> EventEnvelope {
    let hash = fixture.cas.put(bytes).unwrap();
    let attachment = serde_json::from_value(json!({
        "sha256": hash,
        "display_name": display_name,
        "byte_length": declared_length
    }))
    .unwrap();
    event(seq, attachment)
}

fn jpeg_with_size(minimum_size: usize) -> Vec<u8> {
    let mut jpeg = vec![0xff, 0xd8];
    while jpeg.len() + 4 < minimum_size {
        let payload_length = (minimum_size - jpeg.len() - 4).min(65_533);
        jpeg.extend_from_slice(&[0xff, 0xfe]);
        jpeg.extend_from_slice(&u16::try_from(payload_length + 2).unwrap().to_be_bytes());
        jpeg.resize(jpeg.len() + payload_length, b'x');
    }
    let mut encoded = Cursor::new(Vec::new());
    image::DynamicImage::new_rgb8(1, 1)
        .write_to(&mut encoded, image::ImageFormat::Jpeg)
        .unwrap();
    jpeg.extend_from_slice(&encoded.into_inner()[2..]);
    jpeg
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

    let mut started = stored.clone();
    started.run_seq = 1;
    started.event_type = "run.started".into();
    started.event_version = 1;
    started.payload = EventPayload::Inline {
        payload_json: json!({}),
    };
    let mut projected_event = stored.clone();
    projected_event.run_seq = 2;
    let projection = project_chat(&[started.clone(), projected_event.clone()]).unwrap();
    assert_eq!(projection.attachments.len(), 1);
    assert_eq!(projection.attachments[0].display_name, "contract.pdf");
    assert_eq!(projection.attachments[0].byte_length, length);
    assert_eq!(
        projection.attachments[0].media_type.as_deref(),
        Some("application/pdf")
    );
    let public = serde_json::to_string(&projection.attachments).unwrap();
    assert!(!public.contains("sha256"));
    assert!(!public.contains("Users"));

    projected_event.event_version = 2;
    assert!(matches!(
        project_chat(&[started.clone(), projected_event.clone()]),
        Err(ReduceError::UnsupportedSafetyEvent { .. })
    ));
    projected_event.event_version = 1;
    projected_event.payload = EventPayload::Inline {
        payload_json: json!({}),
    };
    assert!(matches!(
        project_chat(&[started, projected_event]),
        Err(ReduceError::MissingAttachmentPayload { .. })
    ));
}

#[test]
fn attachment_projection_rejects_non_executable_and_terminal_states() {
    let pending = vec![
        inline_event(1, "run.started", json!({})),
        inline_event(
            2,
            "permission.requested",
            json!({"gate_id":"g","kind":"confirm","title":"Allow?","message":"Proceed?"}),
        ),
        attachment_event(3),
    ];
    assert!(matches!(
        project_chat(&pending),
        Err(ReduceError::InvalidTransition { .. })
    ));

    let needs_attention = vec![
        inline_event(1, "run.started", json!({})),
        inline_event(2, "run.needs_attention", json!({"reason":"interrupted"})),
        attachment_event(3),
    ];
    assert!(matches!(
        project_chat(&needs_attention),
        Err(ReduceError::InvalidTransition { .. })
    ));

    for terminal in ["run.completed", "run.cancelled", "run.failed"] {
        let events = vec![
            inline_event(1, "run.started", json!({})),
            inline_event(2, terminal, json!({})),
            attachment_event(3),
        ];
        assert!(matches!(
            project_chat(&events),
            Err(ReduceError::InvalidTransition { .. })
        ));
    }
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

#[test]
fn delivery_errors_name_each_image_that_crosses_a_limit() {
    let fixture = Fixture::new();
    let long_name = format!("{}.jpg", "x".repeat(MAX_DELIVERY_DISPLAY_NAME_CHARS + 20));
    let oversized = jpeg_with_size(usize::try_from(MAX_PI_IMAGE_BYTES + 1).unwrap());
    let oversized_event =
        stored_attachment_event(&fixture, 1, &long_name, &oversized, oversized.len() as u64);
    let error = prepare_pi_images(&fixture.cas, &[oversized_event]).unwrap_err();
    let AttachmentDeliveryError::ImageSizeLimit { display_name } = error else {
        panic!("expected the image size limit")
    };
    assert_eq!(
        display_name.chars().count(),
        MAX_DELIVERY_DISPLAY_NAME_CHARS
    );
    assert!(display_name.ends_with('…'));

    let small = jpeg_with_size(1);
    let mut count_events = Vec::new();
    for index in 0..=MAX_PI_IMAGE_COUNT {
        let name = format!("image-{}.jpg", index + 1);
        count_events.push(stored_attachment_event(
            &fixture,
            index as u64 + 1,
            &name,
            &small,
            small.len() as u64,
        ));
    }
    assert!(matches!(
        prepare_pi_images(&fixture.cas, &count_events),
        Err(AttachmentDeliveryError::ImageCountLimit { display_name })
            if display_name == "image-11.jpg"
    ));

    let image_size = usize::try_from(MAX_PI_IMAGE_TOTAL_BYTES / 3 + 1).unwrap();
    let medium = jpeg_with_size(image_size);
    let total_events = (1..=3)
        .map(|index| {
            stored_attachment_event(
                &fixture,
                index,
                &format!("scan-{index}.jpg"),
                &medium,
                medium.len() as u64,
            )
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        prepare_pi_images(&fixture.cas, &total_events),
        Err(AttachmentDeliveryError::ImageTotalSizeLimit { display_name })
            if display_name == "scan-3.jpg"
    ));
}

#[test]
fn ambiguous_image_error_carries_its_display_name() {
    let fixture = Fixture::new();
    let bytes = b"\xff\xd8\xffmalformed\xff\xd9";
    let candidate = stored_attachment_event(&fixture, 1, "unclear.jpg", bytes, bytes.len() as u64);

    assert!(matches!(
        prepare_pi_images(&fixture.cas, &[candidate]),
        Err(AttachmentDeliveryError::AmbiguousFormat { display_name })
            if display_name == "unclear.jpg"
    ));
}
