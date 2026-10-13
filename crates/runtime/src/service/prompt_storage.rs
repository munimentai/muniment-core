use muniment_core::chat_prompt::store_prompt;
use muniment_core::runtime_eprintln as eprintln;

/// Leaves the execution copy in memory when the keyring refuses prompt history.
pub(crate) fn store_prompt_or_notice(
    run_id: &str,
    prompt: &str,
    subject: Option<&str>,
) -> Option<String> {
    store_prompt(run_id, prompt, subject).err().map(|error| {
        let notice = format!(
            "Prompt text stays in runtime memory for this run. The keyring refused prompt history: {error:?}."
        );
        eprintln!("muniment-runtime: run {run_id}: {notice}");
        notice
    })
}
