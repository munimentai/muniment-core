use std::sync::{mpsc, Arc, Mutex};

use muniment_core::attach::RuntimeActivityRegistry;
use muniment_core::serde_json::{self, Value};
use muniment_core::session_thread::SessionThread;
use muniment_runtime_core::{
    accept_prompt, drive_prompt, open_profile_storage, RuntimeChatEventTarget, RuntimeHost,
};

mod common;
use common::{local_grant, stage_pi_stub, TemporaryProfile};

#[test]
fn a_prompt_sets_its_thinking_level_before_pi_hears_it_and_only_when_it_changes() {
    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    let temporary = TemporaryProfile::new("thinking-level", true);
    let descriptor = stage_pi_stub(&temporary.root);
    let state = muniment_core::state_root::state_directory().unwrap();
    let agent = muniment_core::state_root::agent_directory(&state);
    std::fs::create_dir_all(&agent).unwrap();
    std::fs::write(
        agent.join("settings.json"),
        r#"{"modelThinkingLevels":{"stub/stub-model":"low"}}"#,
    )
    .unwrap();
    let requests = temporary.root.join("requests.jsonl");
    std::env::set_var("PI_RESUME_STUB_REASONING", "1");
    std::env::set_var("PI_RESUME_STUB_REQUESTS", &requests);
    let storage = open_profile_storage(&temporary.profile).unwrap();
    let runtime = Arc::new(Mutex::new(None));
    let activity = RuntimeActivityRegistry::new();
    let active = Arc::new(Mutex::new(None));
    let session_thread = SessionThread::default();
    let mut thread_id = None;

    // Each run starts a stub Pi at medium. No level asks for the model's
    // saved level, and medium needs no command.
    for (index, level) in [Some("high"), None, Some("medium")].into_iter().enumerate() {
        let (sender, events) = mpsc::channel();
        let (accepted, launch) = accept_prompt(
            &RuntimeHost::default(),
            &temporary.profile,
            Arc::clone(&storage),
            Arc::clone(&runtime),
            &activity,
            &temporary.config,
            format!("018f0000-0000-7000-8000-{index:012}"),
            format!("prompt {index}"),
            thread_id.clone(),
            &session_thread,
            false,
            String::new(),
            None,
            Vec::new(),
            local_grant(),
            Arc::clone(&active),
            RuntimeChatEventTarget::Subscriber(Some(sender)),
            Some(descriptor),
        )
        .unwrap();
        thread_id = Some(accepted.thread_id);
        drive_prompt(launch.with_thinking_level(level.map(str::to_owned)));
        assert_eq!(events.try_iter().last().unwrap().phase, "complete");
    }

    let sent: Vec<String> = std::fs::read_to_string(&requests)
        .unwrap()
        .lines()
        .map(|line| {
            let request: Value = serde_json::from_str(line).unwrap();
            match request["level"].as_str() {
                Some(level) => format!("{} {level}", request["type"].as_str().unwrap()),
                None => request["type"].as_str().unwrap().to_owned(),
            }
        })
        .collect();
    assert_eq!(
        sent,
        [
            "set_thinking_level high",
            "prompt",
            "set_thinking_level low",
            "prompt",
            "prompt"
        ]
    );
}
