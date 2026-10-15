//! The Pi runs the adapter makes outside a conversation: the model list, the
//! thinking levels of each model, a one-reply model probe and a provider
//! sign-in. Only this adapter starts Pi and reads its frames.

use std::io::{BufRead, BufReader, Lines, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

use super::PiRpcEngine;
use crate::sidecar::pi_install::{acquire_pi, resolve_current_for, PI_SELECTED_ARTIFACT};

const LOGIN_EXTENSION: &str = include_str!("muniment_login.mjs");
const LOGIN_EXTENSION_FILE: &str = "muniment-login.mjs";
const LIST_MODELS_TIMEOUT: Duration = Duration::from_secs(30);
const MODEL_LIST_REQUEST: &str = "muniment-model-thinking";
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const SIGN_IN_START_ERROR: &str = "The sign-in could not start. Try again.";

/// One model Pi can serve, as its `--list-models` table names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PiModelRow {
    pub provider: String,
    pub id: String,
    pub context: String,
    pub max_out: String,
    pub thinking: bool,
    pub images: bool,
}

/// The thinking levels one model supports, as Pi's model objects report them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PiModelThinking {
    pub provider: String,
    pub id: String,
    pub levels: Vec<&'static str>,
}

/// What a sign-in's pages say: the HTML Pi's callback server answers with
/// after a redirect that carried a code, and after one that did not.
pub struct SignInPages {
    pub success: String,
    pub failure: String,
}

/// A running sign-in: the Pi process and its stdin, where prompt answers go.
pub struct PiSignIn {
    child: Child,
    stdin: ChildStdin,
}

/// The sign-in's frames, read on their own thread.
pub struct PiSignInSteps {
    lines: Lines<BufReader<ChildStdout>>,
}

/// One step a sign-in reports.
#[derive(Debug, PartialEq)]
pub enum SignInStep {
    /// A step for the user: a login stage, or a prompt with its id. The
    /// payload is the `local-mode-login` event body without the provider.
    Event(Value),
    /// The login command answered, so the sign-in is over.
    Finished,
    /// A frame that carries nothing for the user.
    Other,
}

impl PiRpcEngine {
    /// Replaces the root Pi installs under, for a host with another state root.
    pub fn with_harness_root(mut self, harness_root: impl Into<PathBuf>) -> Self {
        self.harness_root = Some(harness_root.into());
        self
    }

    /// The pinned Pi under the harness root, once a run or a sign-in installed it.
    pub fn executable(&self) -> Option<PathBuf> {
        resolve_current_for(self.harness_root.as_deref()?, PI_SELECTED_ARTIFACT).ok()
    }

    /// The pinned Pi, downloaded first when nothing installed it yet. The
    /// install lock keeps this and a run's download from racing.
    pub fn acquire_executable(&self) -> Option<PathBuf> {
        self.executable().or_else(|| {
            let cancelled = std::sync::atomic::AtomicBool::new(false);
            acquire_pi(self.harness_root.as_deref()?, &cancelled).ok()
        })
    }

    fn cli(&self, executable: &Path, agent: &Path) -> Command {
        let mut command = Command::new(executable);
        command
            .env("PI_CODING_AGENT_DIR", agent)
            .env("PI_OFFLINE", "1")
            .env_remove("BUN_BE_BUN")
            .stdin(Stdio::null());
        command
    }

    /// Every model Pi can serve from the agent directory, by provider. An
    /// absent Pi, a failure or a timeout answers an empty list.
    pub fn list_models(&self) -> Vec<PiModelRow> {
        let (Some(executable), Some(agent)) = (self.executable(), self.agent_directory.as_deref())
        else {
            return Vec::new();
        };
        let mut command = self.cli(&executable, agent);
        command.arg("--list-models");
        run_with_timeout(command, LIST_MODELS_TIMEOUT)
            .filter(|output| output.status.success())
            .map(|output| parse_model_table(&String::from_utf8_lossy(&output.stdout)))
            .unwrap_or_default()
    }

    /// The thinking levels of every model Pi can serve, from the model objects
    /// its RPC mode answers. Pi runs without extensions, so a model an
    /// extension registers is absent. An absent Pi, a failure or a timeout
    /// answers an empty list.
    pub fn list_model_thinking(&self) -> Vec<PiModelThinking> {
        let (Some(executable), Some(agent)) = (self.executable(), self.agent_directory.as_deref())
        else {
            return Vec::new();
        };
        let mut command = self.cli(&executable, agent);
        command
            .args([
                "--mode",
                "rpc",
                "--no-session",
                "--no-extensions",
                "--no-skills",
                "--no-context-files",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let Ok(mut child) = command.spawn() else {
            return Vec::new();
        };
        let (stdin, stdout) = (child.stdin.take(), child.stdout.take());
        let models = stdin.zip(stdout).and_then(|(mut stdin, stdout)| {
            let request = json!({ "id": MODEL_LIST_REQUEST, "type": "get_available_models" });
            writeln!(stdin, "{request}").ok()?;
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let answer = BufReader::new(stdout)
                    .lines()
                    .map_while(Result::ok)
                    .filter_map(|line| serde_json::from_str::<Value>(&line).ok())
                    .find(|frame| {
                        frame.get("id").and_then(Value::as_str) == Some(MODEL_LIST_REQUEST)
                    });
                let _ = sender.send(answer);
            });
            let answer = receiver.recv_timeout(LIST_MODELS_TIMEOUT).ok().flatten();
            drop(stdin);
            answer
        });
        let _ = child.kill();
        let _ = child.wait();
        models
            .map(|frame| parse_model_thinking(&frame))
            .unwrap_or_default()
    }

    /// Whether one short exchange with the model comes back as a reply. An
    /// account plan serves some of a provider's models and refuses the rest,
    /// and only the provider says which.
    pub fn model_answers(&self, provider: &str, model: &str) -> bool {
        let (Some(executable), Some(agent)) = (self.executable(), self.agent_directory.as_deref())
        else {
            return false;
        };
        let mut command = self.cli(&executable, agent);
        command
            .args(["-ne", "-p", "--provider", provider, "--model", model])
            .arg("Reply with the single word ready.");
        run_with_timeout(command, PROBE_TIMEOUT).is_some_and(|output| {
            let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
            output.status.success() && !text.trim().is_empty() && !text.contains("error")
        })
    }

    /// Starts Pi's own sign-in for one provider in `agent`, the directory
    /// whose `auth.json` receives the credential. Pi runs in RPC mode with the
    /// login extension alone, so a package that fails to load cannot stop the
    /// sign-in. A first sign-in may install Pi.
    pub fn start_sign_in(
        &self,
        agent: &Path,
        provider: &str,
        pages: SignInPages,
    ) -> Result<(PiSignIn, PiSignInSteps), String> {
        let executable = self
            .acquire_executable()
            .ok_or_else(|| SIGN_IN_START_ERROR.to_string())?;
        let extension = write_extension(agent)?;
        let mut child = Command::new(executable)
            .args(["--mode", "rpc", "--no-extensions", "--extension"])
            .arg(&extension)
            .env("PI_CODING_AGENT_DIR", agent)
            .env("PI_OFFLINE", "1")
            .env("MUNIMENT_LOGIN_SUCCESS_HTML", pages.success)
            .env("MUNIMENT_LOGIN_ERROR_HTML", pages.failure)
            .env_remove("BUN_BE_BUN")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| SIGN_IN_START_ERROR.to_string())?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let (Some(mut stdin), Some(stdout)) = (stdin, stdout) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SIGN_IN_START_ERROR.into());
        };
        let prompt = json!({ "id": "login", "type": "prompt", "message": format!("/muniment-login {provider} oauth") });
        if writeln!(stdin, "{prompt}").is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SIGN_IN_START_ERROR.into());
        }
        Ok((
            PiSignIn { child, stdin },
            PiSignInSteps {
                lines: BufReader::new(stdout).lines(),
            },
        ))
    }
}

impl PiSignIn {
    /// Answers one prompt: a value, a confirmation, or a cancel when both are none.
    pub fn answer(
        &mut self,
        id: &str,
        value: Option<String>,
        confirmed: Option<bool>,
    ) -> std::io::Result<()> {
        let mut response = json!({ "type": "extension_ui_response", "id": id });
        match (value, confirmed) {
            (Some(value), _) => response["value"] = value.into(),
            (None, Some(confirmed)) => response["confirmed"] = confirmed.into(),
            (None, None) => response["cancelled"] = true.into(),
        }
        writeln!(self.stdin, "{response}")
    }

    /// Stops Pi and waits for it to exit.
    pub fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Iterator for PiSignInSteps {
    type Item = SignInStep;

    /// The next step, until Pi closes its output.
    fn next(&mut self) -> Option<SignInStep> {
        loop {
            let line = self.lines.next()?.ok()?;
            let Ok(frame) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            return Some(sign_in_step(&frame));
        }
    }
}

/// Whether a prompt is Pi's paste fallback for the browser redirect.
pub fn is_paste_prompt(title: &str) -> bool {
    let title = title.to_ascii_lowercase();
    title.contains("authorization code") || title.contains("redirect url")
}

/// Turns one RPC frame into a sign-in step.
fn sign_in_step(frame: &Value) -> SignInStep {
    match frame.get("type").and_then(Value::as_str) {
        Some("extension_ui_request") => {
            let id = frame.get("id").and_then(Value::as_str).unwrap_or_default();
            let title = frame
                .get("title")
                .or_else(|| frame.get("message"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let event = match frame.get("method").and_then(Value::as_str) {
                Some("notify") => serde_json::from_str::<Value>(title).ok().filter(|payload| {
                    payload.get("muniment").and_then(Value::as_str) == Some("login")
                }),
                Some("select") => Some(json!({
                    "stage": "prompt",
                    "id": id,
                    "kind": "select",
                    "title": title,
                    "options": frame.get("options").cloned().unwrap_or_else(|| json!([])),
                })),
                Some("input") => Some(json!({
                    "stage": "prompt",
                    "id": id,
                    "kind": "input",
                    "title": title,
                    "placeholder": frame.get("placeholder").cloned().unwrap_or(Value::Null),
                })),
                Some("confirm") => {
                    Some(json!({ "stage": "prompt", "id": id, "kind": "confirm", "title": title }))
                }
                _ => None,
            };
            event.map_or(SignInStep::Other, SignInStep::Event)
        }
        Some("response") if frame.get("command").and_then(Value::as_str) == Some("prompt") => {
            SignInStep::Finished
        }
        _ => SignInStep::Other,
    }
}

fn write_extension(agent: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(agent).map_err(|_| SIGN_IN_START_ERROR.to_string())?;
    let path = agent.join(LOGIN_EXTENSION_FILE);
    if std::fs::read(&path).ok().as_deref() != Some(LOGIN_EXTENSION.as_bytes()) {
        let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
        std::fs::write(&temporary, LOGIN_EXTENSION).map_err(|_| SIGN_IN_START_ERROR.to_string())?;
        crate::atomic_file::replace(&temporary, &path).map_err(|_| {
            let _ = std::fs::remove_file(&temporary);
            SIGN_IN_START_ERROR.to_string()
        })?;
    }
    Ok(path)
}

/// Parses Pi's `--list-models` table: a header row, then one row per model.
pub fn parse_model_table(output: &str) -> Vec<PiModelRow> {
    let mut rows = Vec::new();
    for line in output
        .lines()
        .skip_while(|line| !line.starts_with("provider"))
        .skip(1)
    {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 6 {
            continue;
        }
        rows.push(PiModelRow {
            provider: columns[0].to_owned(),
            id: columns[1].to_owned(),
            context: columns[2].to_owned(),
            max_out: columns[3].to_owned(),
            thinking: columns[4] == "yes",
            images: columns[5] == "yes",
        });
    }
    rows
}

/// Reads Pi's `get_available_models` answer: each model's provider, id and
/// the thinking levels it supports. A refusal answers an empty list.
pub fn parse_model_thinking(frame: &Value) -> Vec<PiModelThinking> {
    if frame.get("success").and_then(Value::as_bool) != Some(true) {
        return Vec::new();
    }
    frame
        .pointer("/data/models")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|model| {
            Some(PiModelThinking {
                provider: model.get("provider")?.as_str()?.to_owned(),
                id: model.get("id")?.as_str()?.to_owned(),
                levels: super::supported_thinking_levels(model),
            })
        })
        .collect()
}

fn run_with_timeout(mut command: Command, timeout: Duration) -> Option<std::process::Output> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(command.output());
    });
    receiver.recv_timeout(timeout).ok().and_then(Result::ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_model_table_parses_pis_list_models_output() {
        let output = "provider  model        context  max-out  thinking  images\nollama    llama3.2:3b  128K     16.4K    no        no\nopenai-codex  gpt-5.5  400K  128K  yes  yes\n";
        let rows = parse_model_table(output);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            PiModelRow {
                provider: "ollama".into(),
                id: "llama3.2:3b".into(),
                context: "128K".into(),
                max_out: "16.4K".into(),
                thinking: false,
                images: false
            }
        );
        assert_eq!(rows[1].provider, "openai-codex");
        assert!(rows[1].thinking && rows[1].images);
        assert!(
            parse_model_table("No models available. Use /login to log into a provider.\n")
                .is_empty()
        );
    }

    #[test]
    fn the_model_answer_names_each_models_thinking_levels() {
        let frame = json!({
            "id": MODEL_LIST_REQUEST, "type": "response", "command": "get_available_models",
            "success": true, "data": {"models": [
                {"provider": "ollama", "id": "llama3.2:3b", "reasoning": false},
                {"provider": "openai", "id": "gpt-5.5", "reasoning": true,
                 "thinkingLevelMap": {"off": "none", "minimal": null, "xhigh": "xhigh"}},
                {"provider": "broken"}
            ]}
        });
        assert_eq!(
            parse_model_thinking(&frame),
            [
                PiModelThinking {
                    provider: "ollama".into(),
                    id: "llama3.2:3b".into(),
                    levels: vec!["off"],
                },
                PiModelThinking {
                    provider: "openai".into(),
                    id: "gpt-5.5".into(),
                    levels: vec!["off", "low", "medium", "high", "xhigh"],
                },
            ]
        );
        let refused = json!({"id": MODEL_LIST_REQUEST, "type": "response", "success": false});
        assert!(parse_model_thinking(&refused).is_empty());
    }

    #[test]
    fn notify_frames_carry_the_login_stage_and_prompts_carry_their_id() {
        let notify = json!({
            "type": "extension_ui_request", "id": "n1", "method": "notify",
            "message": "{\"muniment\":\"login\",\"stage\":\"event\",\"event\":{\"type\":\"auth_url\",\"url\":\"https://x\"}}",
            "notifyType": "info"
        });
        let SignInStep::Event(event) = sign_in_step(&notify) else {
            panic!("a login notify is a step");
        };
        assert_eq!(event["event"]["url"], "https://x");

        let stray = json!({ "type": "extension_ui_request", "id": "n2", "method": "notify", "message": "3 entries" });
        assert_eq!(sign_in_step(&stray), SignInStep::Other);

        let select = json!({ "type": "extension_ui_request", "id": "s1", "method": "select", "title": "Method", "options": ["Browser", "Device"] });
        let SignInStep::Event(event) = sign_in_step(&select) else {
            panic!("a select is a prompt");
        };
        assert_eq!(event["stage"], "prompt");
        assert_eq!(event["kind"], "select");
        assert_eq!(event["id"], "s1");
        assert_eq!(event["options"], json!(["Browser", "Device"]));

        let input = json!({ "type": "extension_ui_request", "id": "i1", "method": "input", "title": "Paste the code", "placeholder": "http://localhost:1455/auth/callback" });
        let SignInStep::Event(event) = sign_in_step(&input) else {
            panic!("an input is a prompt");
        };
        assert_eq!(event["kind"], "input");

        let done =
            json!({ "id": "login", "type": "response", "command": "prompt", "success": true });
        assert_eq!(sign_in_step(&done), SignInStep::Finished);
        let other = json!({ "type": "response", "command": "get_state", "success": true });
        assert_eq!(sign_in_step(&other), SignInStep::Other);
    }

    #[test]
    fn the_extension_registers_the_login_command_and_reports_each_stage() {
        assert!(LOGIN_EXTENSION.contains(".registerCommand(\"muniment-login\""));
        for stage in ["\"start\"", "\"event\"", "\"done\"", "\"failed\""] {
            assert!(LOGIN_EXTENSION.contains(stage), "{stage}");
        }
        assert!(LOGIN_EXTENSION.contains("ctx.ui.select("));
        assert!(LOGIN_EXTENSION.contains("ctx.ui.input("));
    }

    #[test]
    fn the_paste_prompt_is_the_redirect_fallback() {
        assert!(is_paste_prompt(
            "Complete login in your browser, or paste the authorization code / redirect URL here:"
        ));
        assert!(!is_paste_prompt("Paste your API key"));
    }

    #[test]
    fn no_installed_pi_lists_nothing_and_answers_no_probe() {
        let root = std::env::temp_dir().join(format!("muniment-pi-cli-{}", uuid::Uuid::new_v4()));
        let engine = PiRpcEngine::new(None)
            .with_agent_directory(root.join("agent"))
            .with_harness_root(root.join("harness"));
        assert_eq!(engine.executable(), None);
        assert!(engine.list_models().is_empty());
        assert!(engine.list_model_thinking().is_empty());
        assert!(!engine.model_answers("ollama", "llama3.2:3b"));
    }
}
