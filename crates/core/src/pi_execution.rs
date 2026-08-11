use std::sync::mpsc::Sender;
use std::time::Duration;

use serde_json::json;

use crate::attachment::{prepare_pi_images, AttachmentDeliveryError};
use crate::journal::reducer::ChatProjector;
use crate::run_events::{append_emit, ChatEventSink, SharedStorage};
use crate::sidecar::pi_chat::{PiChatEvent, PiImageContent, PromptCommand};
use crate::sidecar::{PiRpcWiring, PiSessionLocator, SidecarSupervisor};

pub const RPC_TIMEOUT: Duration = Duration::from_secs(30);

pub struct PiRuntime {
    pub supervisor: SidecarSupervisor,
    pub wiring: PiRpcWiring,
}

pub struct ResumeAttempt {
    result: Option<Sender<Result<(), String>>>,
}

impl ResumeAttempt {
    pub fn new(result: Option<Sender<Result<(), String>>>) -> Self {
        Self { result }
    }

    pub fn accepted(&mut self) {
        if let Some(result) = self.result.take() {
            let _ = result.send(Ok(()));
        }
    }
}

impl Drop for ResumeAttempt {
    fn drop(&mut self) {
        if let Some(result) = self.result.take() {
            let _ = result.send(Err("This reply could not be resumed. Try again.".into()));
        }
    }
}

pub fn attachment_error() -> String {
    "One or more selected files could not be added. Check the files and try again.".into()
}

pub fn attachment_delivery_error(error: AttachmentDeliveryError) -> String {
    match error {
        AttachmentDeliveryError::ImageSizeLimit { display_name } => format!(
            "{display_name} exceeds the 10 MB image limit. Choose a smaller image before sending again."
        ),
        AttachmentDeliveryError::ImageCountLimit { display_name } => format!(
            "{display_name} crosses the 10-image limit. Remove an image before sending again."
        ),
        AttachmentDeliveryError::ImageTotalSizeLimit { display_name } => format!(
            "{display_name} crosses the 20 MB total image limit. Remove images or choose smaller images before sending again."
        ),
        AttachmentDeliveryError::AmbiguousFormat { display_name } => format!(
            "{display_name} has an image format Muniment cannot verify. Choose a PNG, JPEG, GIF, or WebP image before sending again."
        ),
        AttachmentDeliveryError::Storage(_) | AttachmentDeliveryError::InvalidStoredLength => {
            attachment_error()
        }
    }
}

pub fn prepared_pi_images(
    storage: &SharedStorage,
    run_id: &str,
) -> Result<Vec<PiImageContent>, String> {
    let mut storage = storage.lock().map_err(|_| attachment_error())?;
    let events = storage
        .journal
        .events(run_id)
        .map_err(|_| attachment_error())?;
    prepare_pi_images(&storage.cas, &events)
        .map_err(attachment_delivery_error)
        .map(|images| {
            images
                .into_iter()
                .map(|image| PiImageContent::new(image.data, image.mime_type))
                .collect()
        })
}

pub fn prepared_pi_prompt<'a>(
    storage: &SharedStorage,
    run_id: &str,
    prompt: &'a str,
) -> Result<PromptCommand<'a>, String> {
    prepared_pi_images(storage, run_id).map(|images| PromptCommand::with_images(prompt, images))
}

#[derive(Debug)]
pub enum PreparedPromptError {
    Start,
    SessionRoot,
    Binding,
    Journal,
}

#[allow(clippy::too_many_arguments)]
pub fn coordinate_prepared_prompt<T>(
    sink: &impl ChatEventSink,
    journal: &SharedStorage,
    projector: &mut ChatProjector,
    run_id: &str,
    seq: &mut u64,
    subject: Option<&str>,
    submit: impl FnOnce() -> Result<(T, PiSessionLocator, Vec<PiChatEvent>), PreparedPromptError>,
) -> Result<(T, Vec<PiChatEvent>), PreparedPromptError> {
    let (handle, locator, buffered_events) = submit()?;
    append_emit(
        sink,
        journal,
        projector,
        run_id,
        seq,
        "runtime.pi_session.bound",
        json!({"run_id": run_id, "locator": locator.as_str()}),
        subject,
    )
    .map_err(|_| PreparedPromptError::Journal)?;
    append_emit(
        sink,
        journal,
        projector,
        run_id,
        seq,
        "model.prompt.accepted",
        json!({}),
        subject,
    )
    .map_err(|_| PreparedPromptError::Journal)?;
    Ok((handle, buffered_events))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use chrono::{SecondsFormat, Utc};
    use uuid::Uuid;

    use crate::attachment::{ingest_attachment, AttachmentMetadata};
    use crate::cas::LocalCas;
    use crate::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
    use crate::run_events::{ChatEvent, ChatStorage};

    #[derive(Default)]
    struct TestSink;

    impl ChatEventSink for TestSink {
        fn provenance(&self) -> (&str, &str) {
            ("test", "0.0.0")
        }

        fn deliver(&self, _event: ChatEvent) -> Result<(), ()> {
            Ok(())
        }
    }

    fn storage() -> (std::path::PathBuf, SharedStorage) {
        let root = std::env::temp_dir().join(format!("muniment-pi-execution-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let storage = Arc::new(Mutex::new(ChatStorage {
            journal: RunJournal::open(root.join("runs.sqlite3")).unwrap(),
            cas: LocalCas::open(&root.join("cas")).unwrap(),
        }));
        (root, storage)
    }

    fn attachment_event(run_id: &str, run_seq: u64) -> EventEnvelope {
        EventEnvelope {
            event_id: Uuid::now_v7().to_string(),
            run_id: run_id.into(),
            run_seq,
            event_type: String::new(),
            event_version: 0,
            envelope_version: 1,
            recorded_at: Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
            occurred_at: None,
            correlation_id: None,
            causation_id: None,
            payload: EventPayload::Inline {
                payload_json: json!({}),
            },
            provenance: Provenance {
                source: "pi-execution-test".into(),
                source_version: env!("CARGO_PKG_VERSION").into(),
                actor_id: None,
                device_id: None,
                rpc_request_id: None,
                capability_versions: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        }
    }

    fn ingest(storage: &SharedStorage, run_id: &str, run_seq: u64, name: &str, bytes: &[u8]) {
        let mut storage = storage.lock().unwrap();
        let ChatStorage { journal, cas } = &mut *storage;
        ingest_attachment(
            cas,
            journal,
            run_seq - 1,
            &mut Cursor::new(bytes),
            AttachmentMetadata {
                display_name: name,
                byte_length: bytes.len() as u64,
                media_type: None,
            },
            |attachment| EventEnvelope {
                payload: EventPayload::Attachment { attachment },
                ..attachment_event(run_id, run_seq)
            },
        )
        .unwrap();
    }

    fn png() -> Vec<u8> {
        STANDARD
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
            .unwrap()
    }

    #[test]
    fn coordinate_prepared_prompt_submits_before_it_appends_coordinator_events() {
        let (root, storage) = storage();
        let run_id = Uuid::now_v7().to_string();
        let mut projector = ChatProjector::new();
        let mut seq = 0;
        append_emit(
            &TestSink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "run.started",
            json!({}),
            Some("owner"),
        )
        .unwrap();
        ingest(&storage, &run_id, 2, "first.txt", b"first attachment");
        ingest(&storage, &run_id, 3, "second.txt", b"second attachment");
        for event in storage
            .lock()
            .unwrap()
            .journal
            .events(&run_id)
            .unwrap()
            .into_iter()
            .skip(1)
        {
            projector.apply(&event).unwrap();
        }
        seq = 3;
        std::fs::write(root.join("session.jsonl"), "{}\n").unwrap();
        let (locator, _) = crate::sidecar::validate_pi_session(&root, "session.jsonl").unwrap();

        let (handle, buffered) = coordinate_prepared_prompt(
            &TestSink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            Some("owner"),
            || {
                let mut storage = storage.lock().unwrap();
                let events = storage.journal.events(&run_id).unwrap();
                assert_eq!(events.len(), 3);
                for event in &events[1..] {
                    let EventPayload::Attachment { attachment } = &event.payload else {
                        panic!("attachment payload")
                    };
                    storage.cas.verify(attachment.sha256()).unwrap();
                }
                Ok(("handle", locator, vec![PiChatEvent::Completed]))
            },
        )
        .unwrap();

        assert_eq!(handle, "handle");
        assert_eq!(buffered, vec![PiChatEvent::Completed]);
        let events = storage.lock().unwrap().journal.events(&run_id).unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            [
                "run.started",
                "chat.attachment.ingested",
                "chat.attachment.ingested",
                "runtime.pi_session.bound",
                "model.prompt.accepted"
            ]
        );
        drop(events);
        drop(storage);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prepared_pi_images_preserve_journal_order_and_omit_unsupported_files() {
        let (root, storage) = storage();
        let run_id = Uuid::now_v7().to_string();
        let gif_data = "R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==";
        ingest(&storage, &run_id, 1, "renamed.bin", &png());
        ingest(
            &storage,
            &run_id,
            2,
            "notes.png",
            b"durable but not an image",
        );
        ingest(
            &storage,
            &run_id,
            3,
            "second.dat",
            &STANDARD.decode(gif_data).unwrap(),
        );

        assert_eq!(
            prepared_pi_images(&storage, &run_id).unwrap(),
            vec![
                PiImageContent::new(STANDARD.encode(png()), "image/png"),
                PiImageContent::new(gif_data, "image/gif"),
            ]
        );
        drop(storage);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prepared_pi_prompt_keeps_the_prompt_and_adds_prepared_images() {
        let (root, storage) = storage();
        let run_id = Uuid::now_v7().to_string();
        ingest(&storage, &run_id, 1, "image.png", &png());

        let command = prepared_pi_prompt(&storage, &run_id, "Describe this image.").unwrap();

        assert_eq!(command.message, "Describe this image.");
        assert_eq!(
            command.images,
            vec![PiImageContent::new(STANDARD.encode(png()), "image/png")]
        );

        let text_only = prepared_pi_prompt(&storage, "run-without-images", "Hello.").unwrap();
        assert_eq!(text_only, PromptCommand::new("Hello."));
        drop(storage);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resume_attempt_reports_acceptance_and_every_early_return() {
        let (sender, receiver) = std::sync::mpsc::channel();
        drop(ResumeAttempt::new(Some(sender)));
        assert_eq!(
            receiver.recv().unwrap().unwrap_err(),
            "This reply could not be resumed. Try again."
        );

        let (sender, receiver) = std::sync::mpsc::channel();
        let mut attempt = ResumeAttempt::new(Some(sender));
        attempt.accepted();
        drop(attempt);
        assert_eq!(receiver.recv().unwrap(), Ok(()));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn delivery_errors_name_the_limit_and_recovery() {
        assert_eq!(
            attachment_delivery_error(AttachmentDeliveryError::ImageSizeLimit {
                display_name: "photo.jpg".into(),
            }),
            "photo.jpg exceeds the 10 MB image limit. Choose a smaller image before sending again."
        );
        assert_eq!(
            attachment_delivery_error(AttachmentDeliveryError::ImageCountLimit {
                display_name: "eleventh.png".into(),
            }),
            "eleventh.png crosses the 10-image limit. Remove an image before sending again."
        );
        assert_eq!(
            attachment_delivery_error(AttachmentDeliveryError::ImageTotalSizeLimit {
                display_name: "last.gif".into(),
            }),
            "last.gif crosses the 20 MB total image limit. Remove images or choose smaller images before sending again."
        );
        assert_eq!(
            attachment_delivery_error(AttachmentDeliveryError::AmbiguousFormat {
                display_name: "unclear.webp".into(),
            }),
            "unclear.webp has an image format Muniment cannot verify. Choose a PNG, JPEG, GIF, or WebP image before sending again."
        );
    }

    #[test]
    fn storage_and_stored_length_errors_keep_the_generic_message() {
        assert_eq!(
            attachment_delivery_error(AttachmentDeliveryError::Storage(
                crate::cas::CasError::InvalidHash("invalid".into()),
            )),
            attachment_error()
        );
        assert_eq!(
            attachment_delivery_error(AttachmentDeliveryError::InvalidStoredLength),
            attachment_error()
        );
    }
}
