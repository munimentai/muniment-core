use crate::runtime_eprintln as eprintln;
use crate::sidecar::{LineReader, SidecarEvent, SidecarSupervisor};
use std::sync::mpsc::Receiver;

pub(super) struct RunDiagnostics {
    run_id: String,
    pub outcome: &'static str,
    pub failed: bool,
    pub prompt_submitted: bool,
    stderr: Option<LineReader>,
    lifecycle: Option<Receiver<SidecarEvent>>,
}

impl RunDiagnostics {
    pub fn new(run_id: &str) -> Self {
        eprintln!("muniment-runtime: run_id={run_id} run_start");
        Self {
            run_id: run_id.into(),
            outcome: "unknown",
            failed: true,
            prompt_submitted: false,
            stderr: None,
            lifecycle: None,
        }
    }

    pub fn prompt_failed(&mut self, error: &str) {
        self.outcome = "unknown_prompt_not_acknowledged";
        eprintln!(
            "muniment-runtime: run_id={} first_event absent prompt_error={error:?}",
            self.run_id
        );
        self.log_stderr();
    }

    pub fn readiness_failed(
        &mut self,
        status: crate::sidecar::SidecarStatus,
        timeout: std::time::Duration,
    ) {
        self.outcome = "not_started_pi_not_ready";
        eprintln!(
            "muniment-runtime: run_id={} pi_spawn rejected cause=pi_not_ready status={status:?} readiness_bound_ms={}",
            self.run_id,
            timeout.as_millis()
        );
        self.log_stderr();
    }

    /// The first `Error:` line Pi wrote, for a failure reason the shell shows.
    pub fn stderr_error(&self) -> Option<String> {
        self.stderr
            .as_ref()
            .map(LineReader::stderr_tail)
            .unwrap_or_default()
            .iter()
            .map(|line| line.trim())
            .find(|line| line.starts_with("Error:"))
            .map(|line| line.chars().take(320).collect())
    }

    fn log_stderr(&self) {
        let tail = self
            .stderr
            .as_ref()
            .map(LineReader::stderr_tail)
            .unwrap_or_default();
        eprintln!("{}", stderr_line(&self.run_id, tail));
    }

    pub fn spawned(&mut self, supervisor: &SidecarSupervisor) {
        self.stderr = Some(supervisor.io().stderr);
        self.lifecycle = Some(supervisor.subscribe());
        self.log_lifecycle();
    }

    pub fn log_lifecycle(&self) {
        if let Some(events) = &self.lifecycle {
            for event in events.try_iter() {
                // JSON escapes child output so each transition occupies one log line.
                let detail: String = format!("{event:?}").chars().take(8192).collect();
                let detail = serde_json::to_string(&detail).unwrap();
                eprintln!("muniment-runtime: run_id={} pi_spawn {detail}", self.run_id);
            }
        }
    }
}

impl Drop for RunDiagnostics {
    fn drop(&mut self) {
        self.log_lifecycle();
        if !self.prompt_submitted {
            eprintln!(
                "muniment-runtime: run_id={} first_event absent prompt_not_submitted",
                self.run_id
            );
        }
        if self.lifecycle.is_none() {
            eprintln!(
                "muniment-runtime: run_id={} pi_spawn not_started",
                self.run_id
            );
        }
        eprintln!(
            "muniment-runtime: run_id={} provider_request outcome={} source=pi_stream",
            self.run_id, self.outcome
        );
        if self.failed {
            self.log_stderr();
        }
    }
}

pub(super) fn config_error_line(run_id: &str, error: &crate::pi_launch::PiLaunchError) -> String {
    match error {
        crate::pi_launch::PiLaunchError::RejectedConfig { step, cause } => format!(
            "muniment-runtime: run_id={run_id} pi_spawn config_error=RejectedConfig step={step} error={}",
            serde_json::to_string(&crate::pi_launch::diagnostic_text(cause)).unwrap()
        ),
        _ => format!("muniment-runtime: run_id={run_id} pi_spawn config_error={error:?}"),
    }
}

fn stderr_line(run_id: &str, tail: Vec<String>) -> String {
    // Keep diagnostics bounded even when Pi emits a long stderr line.
    let tail: Vec<String> = tail
        .into_iter()
        .rev()
        .take(20)
        .map(|line| line.chars().take(4096).collect())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!(
        "muniment-runtime: run_id={run_id} pi_stderr_tail={}",
        serde_json::to_string(&tail).unwrap()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_failure_names_the_run_step_and_redacted_cause() {
        let error = crate::pi_launch::PiLaunchError::rejected(
            "package_install",
            "The agent runtime package install failed: exit status: 1\nstderr_tail=registry refused password=hidden-value",
        );
        let line = config_error_line("run-config", &error);
        assert!(line.contains(
            "run_id=run-config pi_spawn config_error=RejectedConfig step=package_install"
        ));
        assert!(line.contains("exit status: 1"));
        assert!(line.contains("stderr_tail=registry refused"));
        assert!(!line.contains("hidden-value"));
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn config_log_redacts_terminal_escapes_and_multiline_credentials() {
        for input in [
            "password\u{1b}[0m=short",
            "{\"password\":\n\"opaque-credential\"}",
            "{\"password\":\n\n\"opaque-credential\"}",
            "{\"password\":\"\nopaque-credential\n\"}",
            "{\"password\":\"short\",\"token\":\n\"opaque-credential\"}",
            "{\"password\":\"token=short\nopaque-credential\n\"}",
            "{\"password\":\"escaped\\\"\nopaque-credential\n\"}",
            "password\u{1b}]0;title\u{7}=short",
            "password\u{1b}]0;title\u{1b}\\=short",
            "password\u{9b}0m=short",
            "password\u{1b}[\n0m=short",
        ] {
            let cause = format!("registry refused\n{input}\nlast diagnostic");
            for cause in [
                cause.clone(),
                crate::pi_packages::captured_stderr_for_test(cause.as_bytes()),
            ] {
                let error = crate::pi_launch::PiLaunchError::rejected("package_install", &cause);
                // Check both the constructor and the formatter's defense against a raw cause.
                let raw = crate::pi_launch::PiLaunchError::RejectedConfig {
                    step: "package_install",
                    cause,
                };
                for error in [error, raw] {
                    let line = config_error_line("run-config", &error);
                    assert!(line.contains("run_id=run-config"), "{line}");
                    assert!(line.contains("step=package_install"), "{line}");
                    assert!(line.contains("registry refused"), "{line}");
                    assert!(line.contains("last diagnostic"), "{line}");
                    assert!(line.contains("[redacted]"), "{line}");
                    assert!(!line.contains("short"), "{line}");
                    assert!(!line.contains("opaque-credential"), "{line}");
                    assert!(!line.contains("title"), "{line}");
                    assert_eq!(line.lines().count(), 1);
                }
            }
        }
    }

    #[test]
    fn config_log_suppresses_credentials_after_stderr_overflow() {
        for hidden_header in ["password:", "-----BEGIN PRIVATE KEY-----"] {
            let input = format!(
                "registry refused\n{}{hidden_header}\nopaque-credential\nlast diagnostic",
                " ".repeat(65_536),
            );
            let cause = crate::pi_packages::captured_stderr_for_test(input.as_bytes());
            let error = crate::pi_launch::PiLaunchError::rejected("package_install", cause);
            let line = config_error_line("run-overflow", &error);
            assert!(line.contains("run_id=run-overflow"), "{line}");
            assert!(line.contains("step=package_install"), "{line}");
            assert!(line.contains("registry refused"), "{line}");
            assert!(line.contains("[redacted]"), "{line}");
            assert!(!line.contains("opaque-credential"), "{line}");
            assert!(!line.contains("last diagnostic"), "{line}");
        }
    }

    #[test]
    fn config_log_redacts_multiline_environment_secrets_before_stderr_tail_bounds() {
        const SECRET: &str = "opaque-part-one\nopaque-part-two";
        // A child process scopes the environment without mutating concurrent tests.
        if std::env::var("PROBE_PASSWORD").as_deref() != Ok(SECRET) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "chat_coordinate::diagnostics::tests::config_log_redacts_multiline_environment_secrets_before_stderr_tail_bounds",
                    "--nocapture",
                ])
                .env("PROBE_PASSWORD", SECRET)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        for input in [
            SECRET.to_owned(),
            SECRET.replace('\n', "\r\n"),
            format!("{SECRET}\n{}last diagnostic", "detail\n".repeat(18)),
            format!("{SECRET}\n{}\nlast diagnostic", "x ".repeat(2032)),
            format!("{}{SECRET}", "x ".repeat(4090)),
            "opaque-part-two".into(),
        ] {
            let cause = crate::pi_packages::captured_stderr_for_test(input.as_bytes());
            assert!(!cause.contains("opaque"), "{cause}");
            assert!(!cause.contains("part-"), "{cause}");
            assert!(!cause.contains("two"), "{cause}");
            let error = crate::pi_launch::PiLaunchError::rejected("package_install", cause);
            let line = config_error_line("run-environment", &error);
            assert!(line.contains("run_id=run-environment"), "{line}");
            assert!(line.contains("step=package_install"), "{line}");
            assert!(line.contains("[redacted]"), "{line}");
            assert!(!line.contains("opaque-part"), "{line}");
            assert!(!line.contains("part-two"), "{line}");
            assert_eq!(line.lines().count(), 1);
        }
    }

    #[test]
    fn stderr_tail_is_bounded_and_stays_on_one_runtime_line() {
        let mut tail: Vec<_> = (0..25).map(|index| format!("detail {index}")).collect();
        tail.push("child\nline\r\n".repeat(1000));
        let line = stderr_line("run-1", tail);
        assert!(line.starts_with("muniment-runtime: run_id=run-1 pi_stderr_tail="));
        assert_eq!(line.lines().count(), 1);
        let parsed: Vec<String> =
            serde_json::from_str(line.split_once("pi_stderr_tail=").unwrap().1).unwrap();
        assert_eq!(parsed.len(), 20);
        assert_eq!(parsed[0], "detail 6");
        assert_eq!(parsed[19].chars().count(), 4096);
        assert!(stderr_line("run-2", Vec::new()).ends_with("=[]"));
    }
}
