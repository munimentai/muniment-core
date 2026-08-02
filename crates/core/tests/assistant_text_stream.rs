use muniment_core::assistant_text::stream::{
    AssistantText, EmittableEvent, RunStreamProjector, StreamError,
};
use serde_json::{json, Value};
use std::path::Path;

fn stream() -> RunStreamProjector<impl FnMut(&Path) -> Result<std::path::PathBuf, ()>> {
    RunStreamProjector::new("/workspace", |path: &Path| Ok(path.to_path_buf()))
}

fn delta(text: &str) -> Value {
    json!({"text": text, "content_disclosure": "released"})
}

fn event(run_seq: u64, assistant_text: AssistantText) -> EmittableEvent {
    EmittableEvent {
        run_seq,
        assistant_text,
    }
}

#[test]
fn holds_later_events_until_an_earlier_delta_resolves() {
    let mut stream = stream();
    assert_eq!(
        stream.push(1, "run.started", &json!({})).unwrap(),
        vec![event(1, AssistantText::NotDelta)]
    );
    assert!(stream
        .push(2, "model.stream.delta", &delta("safe AKIAAAAA"))
        .unwrap()
        .is_empty());
    assert!(stream
        .push(3, "tool.effect.started", &json!({}))
        .unwrap()
        .is_empty());
    assert!(stream
        .push(4, "model.stream.delta", &delta("AAAAAAAAAAAA end"))
        .unwrap()
        .is_empty());

    assert_eq!(
        stream.push(5, "run.completed", &json!({})).unwrap(),
        vec![
            event(2, AssistantText::Released("safe ".into())),
            event(3, AssistantText::NotDelta),
            event(4, AssistantText::Released(" end".into())),
            event(5, AssistantText::NotDelta),
        ]
    );
}

#[test]
fn a_later_delta_resolves_a_pending_safe_delta() {
    let mut stream = stream();
    stream.push(1, "run.started", &json!({})).unwrap();
    assert!(stream
        .push(2, "model.stream.delta", &delta("ordinary candidate"))
        .unwrap()
        .is_empty());
    let continuation = "z ".repeat(40_000);
    assert_eq!(
        stream
            .push(3, "model.stream.delta", &delta(&continuation))
            .unwrap(),
        vec![event(
            2,
            AssistantText::Released("ordinary candidate".into())
        )]
    );
}

#[test]
fn missing_disclosure_feeds_no_text_to_the_matchers() {
    let mut stream = stream();
    stream.push(1, "run.started", &json!({})).unwrap();
    assert_eq!(
        stream
            .push(
                2,
                "model.stream.delta",
                &json!({"text": "AKIAAAAAAAAAAAAAAAAA"})
            )
            .unwrap(),
        vec![event(2, AssistantText::Withheld)]
    );
    assert_eq!(
        stream
            .push(3, "model.stream.delta", &delta("safe text "))
            .unwrap(),
        Vec::<EmittableEvent>::new()
    );
    assert_eq!(
        stream.push(4, "run.failed", &json!({})).unwrap(),
        vec![
            event(3, AssistantText::Released("safe text ".into())),
            event(4, AssistantText::NotDelta),
        ]
    );
}

#[test]
fn replay_into_a_fresh_stream_is_identical() {
    let inputs = [
        (1, "run.started", json!({})),
        (2, "model.stream.delta", delta("safe AKIAAAAA")),
        (3, "model.stream.delta", delta("AAAAAAAAAAAA end")),
        (4, "run.cancelled", json!({})),
    ];
    let replay = || {
        let mut stream = stream();
        inputs
            .iter()
            .flat_map(|(seq, kind, payload)| stream.push(*seq, kind, payload).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(replay(), replay());
}

#[test]
fn rejects_gaps_and_missing_delta_text_without_advancing() {
    let mut stream = stream();
    assert_eq!(
        stream.push(2, "run.started", &json!({})),
        Err(StreamError::InvalidRunSequence)
    );
    assert_eq!(
        stream.push(
            1,
            "model.stream.delta",
            &json!({"content_disclosure": "released"})
        ),
        Err(StreamError::MissingDeltaText)
    );
    assert_eq!(
        stream.push(1, "run.started", &json!({})).unwrap(),
        vec![event(1, AssistantText::NotDelta)]
    );
}

#[test]
fn rejects_events_after_the_terminal_event() {
    let mut stream = stream();
    stream.push(1, "run.completed", &json!({})).unwrap();
    assert_eq!(
        stream.push(2, "run.started", &json!({})),
        Err(StreamError::Projector(
            muniment_core::assistant_text::projector::ProjectorError::Finished
        ))
    );
}
