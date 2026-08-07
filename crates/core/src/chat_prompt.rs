use keyring::Entry;

const PROMPT_SERVICE: &str = "ai.muniment.desktop.chat";
const PROMPT_USER: &str = "protected-prompts";

#[derive(Debug)]
pub enum ChatPromptError {
    Entry(keyring::Error),
    Store(keyring::Error),
    Load(keyring::Error),
}

pub fn prompt_user(subject: Option<&str>, run_id: &str) -> String {
    subject.filter(|value| !value.is_empty()).map_or_else(
        || format!("{PROMPT_USER}:{run_id}"),
        |value| format!("{PROMPT_USER}:{value}:{run_id}"),
    )
}

pub fn store_prompt(
    run_id: &str,
    prompt: &str,
    subject: Option<&str>,
) -> Result<(), ChatPromptError> {
    let user = prompt_user(subject, run_id);
    let entry = Entry::new(PROMPT_SERVICE, &user).map_err(ChatPromptError::Entry)?;
    entry.set_password(prompt).map_err(ChatPromptError::Store)
}

pub fn load_prompt(run_id: &str, subject: Option<&str>) -> Result<Option<String>, ChatPromptError> {
    let user = prompt_user(subject, run_id);
    let entry = Entry::new(PROMPT_SERVICE, &user).map_err(ChatPromptError::Entry)?;
    match entry.get_password() {
        Ok(prompt) => Ok(Some(prompt)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(ChatPromptError::Load(error)),
    }
}
