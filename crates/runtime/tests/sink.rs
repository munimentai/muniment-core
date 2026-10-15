use std::fs;
use std::sync::mpsc::{self, TryRecvError};
use std::sync::Arc;

use muniment_core::attach::SignedWorkspaceApproval;
use muniment_core::chat_launch::ChatGrant;
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::pi_launch::{
    pi_launch_config, pi_launch_config_for_executable, PiLaunchBoundaries, PiLaunchError,
};
use muniment_core::run_events::{ChatEvent, ChatEventSink, ChatTextDelta};
use muniment_runtime_core::{
    open_profile_storage, RuntimeChatEventBroadcast, RuntimeChatEventSink,
    CHAT_EVENT_SUBSCRIBER_QUEUE_CAPACITY, CHAT_REPLAY_MAX_BYTES, CHAT_REPLAY_MAX_EVENTS,
};

mod common;
use common::{fixture_grant, TemporaryProfile};

fn event() -> ChatEvent {
    ChatEvent {
        run_id: "run-1".into(),
        thread_id: None,
        phase: "running".into(),
        text: "hello".into(),
        prompt_accepted: false,
        turn_started: false,
        routing_stage: None,
        prompt_storage_notice: None,
        failure_reason: None,
        receipt: None,
        tool_activity: Vec::new(),
        attachments: Vec::new(),
        recalls: Vec::new(),
        applied_diffs: Vec::new(),
        pending_permission: None,
        delta: None,
        seq: None,
    }
}

fn grant() -> ChatGrant {
    ChatGrant {
        workspace: "/work".into(),
        virtual_key: "secret-key".into(),
        ..fixture_grant()
    }
}

fn memory_runtime(profile: &TemporaryProfile) -> Arc<ApplicationMemoryRuntime> {
    Arc::new(ApplicationMemoryRuntime::new(
        profile.config.clone(),
        profile.profile.join("memory"),
    ))
}

fn recorded_broadcast(workspace: &str) -> RuntimeChatEventBroadcast {
    let approval = SignedWorkspaceApproval::default();
    approval.record(workspace.into());
    RuntimeChatEventBroadcast::new(approval)
}

#[test]
fn delivers_to_an_optional_subscriber() {
    let profile = TemporaryProfile::new("sink-subscriber", false);
    let (subscriber, events) = mpsc::channel();
    let sink = RuntimeChatEventSink::with_subscriber(
        &profile.profile,
        Some(subscriber),
        memory_runtime(&profile),
        "thread-1".into(),
    );

    sink.deliver(event()).unwrap();

    let delivered = events.recv().unwrap();
    assert_eq!(delivered.run_id, "run-1");
    assert_eq!(delivered.thread_id.as_deref(), Some("thread-1"));
    assert_eq!(delivered.text, "hello");
}

#[test]
fn succeeds_without_a_subscriber() {
    let profile = TemporaryProfile::new("sink-no-subscriber", false);

    RuntimeChatEventSink::with_subscriber(
        &profile.profile,
        None,
        memory_runtime(&profile),
        "thread-1".into(),
    )
    .deliver(event())
    .unwrap();
}

#[test]
fn clears_a_dropped_subscriber() {
    let profile = TemporaryProfile::new("sink-dropped-subscriber", false);
    let (subscriber, events) = mpsc::channel();
    let sink = RuntimeChatEventSink::with_subscriber(
        &profile.profile,
        Some(subscriber),
        memory_runtime(&profile),
        "thread-1".into(),
    );
    drop(events);

    sink.deliver(event()).unwrap();
    sink.deliver(event()).unwrap();
}

#[test]
fn broadcasts_each_event_to_every_live_subscriber() {
    let profile = TemporaryProfile::new("sink-broadcast", false);
    let broadcast = recorded_broadcast("workspace-a");
    let first = broadcast.subscribe();
    let second = broadcast.subscribe();
    let sink = RuntimeChatEventSink::new(
        &profile.profile,
        broadcast,
        memory_runtime(&profile),
        "thread-1".into(),
        "workspace-a".into(),
    );

    sink.deliver(event()).unwrap();

    assert_eq!(first.recv().unwrap().text, "hello");
    assert_eq!(second.recv().unwrap().text, "hello");
}

#[test]
fn stamps_the_run_thread_id_on_every_broadcast_event() {
    let profile = TemporaryProfile::new("sink-broadcast-thread", false);
    let broadcast = recorded_broadcast("workspace-a");
    let subscriber = broadcast.subscribe();
    let sink = RuntimeChatEventSink::new(
        &profile.profile,
        broadcast,
        memory_runtime(&profile),
        "thread-1".into(),
        "workspace-a".into(),
    );

    let mut event = event();
    event.thread_id = Some("other-thread".into());
    sink.deliver(event).unwrap();

    let delivered = subscriber.recv().unwrap();
    assert_eq!(delivered.run_id, "run-1");
    assert_eq!(delivered.thread_id.as_deref(), Some("thread-1"));
}

#[test]
fn removes_a_dropped_broadcast_subscriber_without_delivery() {
    let broadcast = recorded_broadcast("workspace-a");
    let dropped = broadcast.subscribe();
    let remaining = broadcast.subscribe();
    assert_eq!(broadcast.subscriber_count(), 2);

    drop(dropped);

    assert_eq!(broadcast.subscriber_count(), 1);
    let profile = TemporaryProfile::new("sink-drop-broadcast", false);
    let sink = RuntimeChatEventSink::new(
        &profile.profile,
        broadcast.clone(),
        memory_runtime(&profile),
        "thread-1".into(),
        "workspace-a".into(),
    );
    sink.deliver(event()).unwrap();
    assert_eq!(remaining.recv().unwrap().text, "hello");
    assert_eq!(broadcast.full_queue_drop_count(), 0);
}

#[test]
fn drops_a_subscriber_when_its_bounded_queue_is_full() {
    let profile = TemporaryProfile::new("sink-full-broadcast", false);
    let broadcast = recorded_broadcast("workspace-a");
    let stalled = broadcast.subscribe();
    let sink = RuntimeChatEventSink::new(
        &profile.profile,
        broadcast.clone(),
        memory_runtime(&profile),
        "thread-1".into(),
        "workspace-a".into(),
    );

    for _ in 0..=CHAT_EVENT_SUBSCRIBER_QUEUE_CAPACITY {
        sink.deliver(event()).unwrap();
    }
    for _ in 0..CHAT_EVENT_SUBSCRIBER_QUEUE_CAPACITY {
        stalled.recv().unwrap();
    }
    assert!(stalled.recv().is_err());
    assert_eq!(broadcast.full_queue_drop_count(), 1);

    let live = broadcast.subscribe();
    sink.deliver(event()).unwrap();
    assert_eq!(live.recv().unwrap().text, "hello");
    assert_eq!(broadcast.full_queue_drop_count(), 1);
}

#[test]
fn drives_pi_launch_config_over_the_profile_directory() {
    let profile = TemporaryProfile::new("sink-launch-config", true);
    let _storage = open_profile_storage(&profile.profile).unwrap();
    let pi_install = profile.profile.join("pi-install");
    fs::create_dir(&pi_install).unwrap();
    let memory_runtime = memory_runtime(&profile);
    let extension = memory_runtime.agent_extension_path();
    fs::create_dir_all(extension.parent().unwrap()).unwrap();
    fs::write(&extension, "export default function () {}\n").unwrap();
    let sink = RuntimeChatEventSink::with_subscriber(
        &profile.profile,
        None,
        memory_runtime,
        "thread-1".into(),
    );

    assert_eq!(
        pi_launch_config(&sink, Some(&pi_install), &grant(), None).unwrap_err(),
        PiLaunchError::UnresolvableExecutable
    );
    assert_eq!(
        sink.pi_session_root().unwrap(),
        profile.profile.join("sessions")
    );
    assert_eq!(
        sink.pi_install_root().unwrap(),
        profile.profile.join("harness")
    );
    assert_eq!(sink.memory_agent_extension_path(), Some(extension.clone()));
    let config =
        pi_launch_config_for_executable(&sink, common::build_pi_stub(), &grant(), None).unwrap();
    assert_eq!(
        config.working_directory,
        Some(profile.root.join("home/sessions/Untitled-thread1"))
    );
    assert!(config.args.windows(2).any(|args| {
        args == [
            "--session-dir",
            fs::canonicalize(profile.profile.join("sessions"))
                .unwrap()
                .to_string_lossy()
                .as_ref(),
        ]
    }));
    assert!(config
        .args
        .windows(2)
        .any(|args| { args == ["--extension", extension.to_string_lossy().as_ref()] }));
}

#[test]
fn withholds_a_mismatched_broadcast_and_keeps_the_subscription() {
    let profile = TemporaryProfile::new("sink-broadcast-mismatch", false);
    let broadcast = recorded_broadcast("workspace-a");
    let subscriber = broadcast.subscribe();
    let mismatched = RuntimeChatEventSink::new(
        &profile.profile,
        broadcast.clone(),
        memory_runtime(&profile),
        "thread-1".into(),
        "workspace-b".into(),
    );
    let matched = RuntimeChatEventSink::new(
        &profile.profile,
        broadcast.clone(),
        memory_runtime(&profile),
        "thread-1".into(),
        "workspace-a".into(),
    );

    mismatched.deliver(event()).unwrap();

    assert!(matches!(subscriber.try_recv(), Err(TryRecvError::Empty)));
    assert_eq!(broadcast.subscriber_count(), 1);

    matched.deliver(event()).unwrap();
    assert_eq!(subscriber.recv().unwrap().text, "hello");
}

#[test]
fn local_broadcast_needs_the_marker_not_signed_workspace_approval() {
    let profile = TemporaryProfile::new("sink-local", false);
    fs::create_dir_all(&profile.config).unwrap();
    let marker = profile
        .config
        .join(muniment_core::local_mode::LOCAL_MODE_MARKER);
    let approval = SignedWorkspaceApproval::default();
    let broadcast = RuntimeChatEventBroadcast::new(approval.clone())
        .with_config_directory(profile.config.clone());
    let subscriber = broadcast.subscribe();
    let local = RuntimeChatEventSink::new(
        &profile.profile,
        broadcast.clone(),
        memory_runtime(&profile),
        "thread-local".into(),
        "local".into(),
    );
    let cloud = RuntimeChatEventSink::new(
        &profile.profile,
        broadcast,
        memory_runtime(&profile),
        "thread-cloud".into(),
        "workspace-a".into(),
    );

    local.deliver(event()).unwrap();
    assert!(matches!(subscriber.try_recv(), Err(TryRecvError::Empty)));
    fs::write(&marker, b"").unwrap();
    local.deliver(event()).unwrap();
    let delivered = subscriber.try_recv().unwrap();
    assert_eq!(delivered.text, "hello");
    assert_eq!(delivered.thread_id.as_deref(), Some("thread-local"));
    assert!(approval.approval().is_none());

    let started = std::time::Instant::now();
    let mut acquiring = event();
    acquiring.phase = "acquiring-pi".into();
    acquiring.text.clear();
    local.deliver(acquiring.clone()).unwrap();
    assert_eq!(subscriber.try_recv().unwrap().phase, "acquiring-pi");
    let reason = "Reply setup failed. Check your connection and storage, then retry.";
    let mut failed = acquiring;
    failed.phase = "failed".into();
    failed.failure_reason = Some(reason.into());
    local.deliver(failed).unwrap();
    let delivered = subscriber.try_recv().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
    assert_eq!(delivered.phase, "failed");
    assert_eq!(delivered.failure_reason.as_deref(), Some(reason));
    assert!(delivered.text.is_empty());
    assert_eq!(delivered.thread_id.as_deref(), Some("thread-local"));

    // Local mode must not expose events from an older signed workspace.
    approval.record("workspace-a".into());
    cloud.deliver(event()).unwrap();
    assert!(matches!(subscriber.try_recv(), Err(TryRecvError::Empty)));
    fs::remove_file(&marker).unwrap();
    local.deliver(event()).unwrap();
    assert!(matches!(subscriber.try_recv(), Err(TryRecvError::Empty)));
    cloud.deliver(event()).unwrap();
    assert_eq!(
        subscriber.try_recv().unwrap().thread_id.as_deref(),
        Some("thread-cloud")
    );

    // A directory at the marker path does not activate local mode.
    fs::create_dir(&marker).unwrap();
    local.deliver(event()).unwrap();
    assert!(matches!(subscriber.try_recv(), Err(TryRecvError::Empty)));
    approval.clear();
    cloud.deliver(event()).unwrap();
    assert!(matches!(subscriber.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn withholds_an_unrecorded_broadcast_and_reads_the_workspace_at_delivery() {
    let profile = TemporaryProfile::new("sink-broadcast-unrecorded", false);
    let approval = SignedWorkspaceApproval::default();
    let broadcast = RuntimeChatEventBroadcast::new(approval.clone());
    let subscriber = broadcast.subscribe();
    let sink = RuntimeChatEventSink::new(
        &profile.profile,
        broadcast.clone(),
        memory_runtime(&profile),
        "thread-1".into(),
        "workspace-a".into(),
    );

    sink.deliver(event()).unwrap();

    assert!(matches!(subscriber.try_recv(), Err(TryRecvError::Empty)));
    assert_eq!(broadcast.subscriber_count(), 1);

    approval.record("workspace-a".into());
    sink.deliver(event()).unwrap();
    assert_eq!(subscriber.recv().unwrap().text, "hello");

    approval.clear();
    sink.deliver(event()).unwrap();
    assert!(matches!(subscriber.try_recv(), Err(TryRecvError::Empty)));
    assert_eq!(broadcast.subscriber_count(), 1);
}

fn whole(run_id: &str, phase: &str, text: &str) -> ChatEvent {
    ChatEvent {
        run_id: run_id.into(),
        phase: phase.into(),
        text: text.into(),
        ..event()
    }
}

fn text_delta(run_id: &str, text: &str, text_start: usize) -> ChatEvent {
    ChatEvent {
        delta: Some(ChatTextDelta::new(text_start)),
        ..whole(run_id, "streaming", text)
    }
}

fn workspace_sink(
    profile: &TemporaryProfile,
    broadcast: &RuntimeChatEventBroadcast,
) -> RuntimeChatEventSink {
    RuntimeChatEventSink::new(
        &profile.profile,
        broadcast.clone(),
        memory_runtime(profile),
        "thread-1".into(),
        "workspace-a".into(),
    )
}

fn drain(subscription: &muniment_core::run_events::ChatEventSubscription) -> Vec<ChatEvent> {
    std::iter::from_fn(|| subscription.try_recv().ok()).collect()
}

#[test]
fn a_new_subscriber_gets_the_whole_state_of_each_live_run_first() {
    let profile = TemporaryProfile::new("sink-attach-snapshot", false);
    let broadcast = recorded_broadcast("workspace-a");
    let watcher = broadcast.subscribe();
    let sink = workspace_sink(&profile, &broadcast);
    for event in [
        whole("run-1", "thinking", ""),
        text_delta("run-1", "Hé", 0),
        text_delta("run-1", "llo", 2),
        whole("run-2", "complete", "done"),
    ] {
        sink.deliver(event).unwrap();
    }
    let seen = drain(&watcher);
    let current = seen.last().unwrap().seq.unwrap();
    assert!(seen
        .windows(2)
        .all(|pair| pair[1].seq.unwrap() == pair[0].seq.unwrap() + 1));

    let late = broadcast.subscribe();
    let caught_up = drain(&late);
    assert_eq!(caught_up.len(), 1, "only the live run has a whole state");
    let snapshot = &caught_up[0];
    assert!(snapshot.delta.is_none());
    assert_eq!(snapshot.run_id, "run-1");
    assert_eq!(snapshot.phase, "streaming");
    assert_eq!(snapshot.text, "Héllo");
    assert_eq!(snapshot.thread_id.as_deref(), Some("thread-1"));
    assert_eq!(snapshot.seq, Some(current));

    sink.deliver(text_delta("run-1", " world", 5)).unwrap();
    let next = late.try_recv().unwrap();
    assert_eq!(next.delta.as_ref().unwrap().text_start, 5);
    assert_eq!(next.seq, Some(current + 1));
}

#[test]
fn a_resume_within_the_replay_budget_gets_the_missed_events() {
    let profile = TemporaryProfile::new("sink-resume-replay", false);
    let broadcast = recorded_broadcast("workspace-a");
    let first = broadcast.subscribe();
    let sink = workspace_sink(&profile, &broadcast);
    sink.deliver(whole("run-1", "thinking", "")).unwrap();
    sink.deliver(text_delta("run-1", "one", 0)).unwrap();
    let cursor = drain(&first).last().unwrap().seq;
    drop(first);
    sink.deliver(text_delta("run-1", " two", 3)).unwrap();
    sink.deliver(whole("run-1", "complete", "one two")).unwrap();

    let resumed = broadcast.subscribe_after(cursor);
    let missed = drain(&resumed);
    assert_eq!(missed.len(), 2);
    assert_eq!(missed[0].text, " two");
    assert_eq!(missed[0].delta.as_ref().unwrap().text_start, 3);
    assert_eq!(missed[0].seq, cursor.map(|cursor| cursor + 1));
    assert!(missed[1].delta.is_none());
    assert_eq!(missed[1].phase, "complete");
    assert_eq!(missed[1].seq, cursor.map(|cursor| cursor + 2));

    let current = broadcast.subscribe_after(missed[1].seq);
    assert!(drain(&current).is_empty());
}

#[test]
fn a_resume_past_the_replay_budget_gets_one_whole_state_per_changed_run() {
    let profile = TemporaryProfile::new("sink-resume-snapshot", false);
    let broadcast = recorded_broadcast("workspace-a");
    let first = broadcast.subscribe();
    let sink = workspace_sink(&profile, &broadcast);
    sink.deliver(whole("run-0", "complete", "settled earlier"))
        .unwrap();
    sink.deliver(whole("run-1", "thinking", "")).unwrap();
    let cursor = drain(&first).last().unwrap().seq;
    drop(first);
    let mut text = String::new();
    for _ in 0..=CHAT_REPLAY_MAX_EVENTS {
        sink.deliver(text_delta("run-1", "ab", text.len())).unwrap();
        text.push_str("ab");
    }
    sink.deliver(whole("run-2", "complete", "done")).unwrap();

    let resumed = broadcast.subscribe_after(cursor);
    let states = drain(&resumed);
    let runs: Vec<_> = states.iter().map(|state| state.run_id.as_str()).collect();
    assert_eq!(runs, ["run-1", "run-2"]);
    assert!(states.iter().all(|state| state.delta.is_none()));
    assert_eq!(states[0].text, text);
    assert_eq!(states[0].phase, "streaming");
    let current = cursor.unwrap() + CHAT_REPLAY_MAX_EVENTS as u64 + 2;
    assert!(states.iter().all(|state| state.seq == Some(current)));

    // A few events past the byte budget also answer whole states.
    let big = "x".repeat(CHAT_REPLAY_MAX_BYTES / 2);
    sink.deliver(text_delta("run-1", &big, text.len())).unwrap();
    sink.deliver(text_delta("run-1", &big, text.len() + big.len()))
        .unwrap();
    sink.deliver(text_delta("run-1", "!", text.len() + 2 * big.len()))
        .unwrap();
    let resumed = broadcast.subscribe_after(Some(current));
    let states = drain(&resumed);
    assert_eq!(states.len(), 1);
    assert!(states[0].delta.is_none());
    assert_eq!(states[0].text.len(), text.len() + 2 * big.len() + 1);
    assert_eq!(states[0].seq, Some(current + 3));
}

#[test]
fn a_cursor_the_stream_never_reached_gets_the_live_whole_states() {
    let profile = TemporaryProfile::new("sink-resume-unknown", false);
    let broadcast = recorded_broadcast("workspace-a");
    let sink = workspace_sink(&profile, &broadcast);
    sink.deliver(whole("run-1", "pending-permission", "Allow?"))
        .unwrap();
    sink.deliver(whole("run-2", "failed", "")).unwrap();

    let ahead = broadcast.subscribe_after(Some(u64::MAX));
    let states = drain(&ahead);
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].phase, "pending-permission");

    // A cursor from an earlier runtime falls before this stream.
    let earlier = broadcast.subscribe_after(Some(1));
    let runs: Vec<_> = drain(&earlier)
        .into_iter()
        .map(|state| state.run_id)
        .collect();
    assert_eq!(runs, ["run-1", "run-2"]);
}

#[test]
fn catching_up_reads_only_the_workspace_the_gate_allows_now() {
    let profile = TemporaryProfile::new("sink-resume-workspace", false);
    let approval = SignedWorkspaceApproval::default();
    approval.record("workspace-a".into());
    let broadcast = RuntimeChatEventBroadcast::new(approval.clone());
    let first = broadcast.subscribe();
    let sink = workspace_sink(&profile, &broadcast);
    sink.deliver(whole("run-1", "thinking", "")).unwrap();
    let cursor = drain(&first).last().unwrap().seq.map(|seq| seq - 1);

    approval.record("workspace-b".into());
    assert!(drain(&broadcast.subscribe()).is_empty());
    assert!(drain(&broadcast.subscribe_after(cursor)).is_empty());
    approval.record("workspace-a".into());
    assert_eq!(drain(&broadcast.subscribe_after(cursor)).len(), 1);
}
