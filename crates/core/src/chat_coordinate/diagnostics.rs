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
