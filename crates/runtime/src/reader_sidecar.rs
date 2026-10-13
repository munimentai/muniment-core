//! Network readers run in the Go sidecar, `muniment-reader`, one process per
//! call: the runtime writes one JSON request on its stdin and reads one JSON
//! answer on its stdout. The source's secret travels in the environment and
//! never on the command line, and the sidecar holds no state and no SQLite.

use crate::reader::{Cursor, Delta, Description, ObjectInfo, Page, Reader, ReaderError};
use muniment_core::serde_json::{self, json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// The environment variable that carries the source's secret to the sidecar.
pub const SECRET_VARIABLE: &str = "MUNIMENT_READER_SECRET";
/// How long one sidecar call may take before the runtime gives up on it.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// The most bytes one answer may hold.
const ANSWER_CAP: usize = 32 * 1024 * 1024;
/// The sidecar the host installed, or the one `MUNIMENT_READER_BIN` names
/// for a checkout that runs the runtime from its target directory.
pub fn sidecar_executable(installed: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("MUNIMENT_READER_BIN") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    installed
        .filter(|sidecar| sidecar.is_file())
        .map(Path::to_path_buf)
}

pub struct SidecarReader {
    source: String,
    executable: PathBuf,
    secret: String,
}

impl SidecarReader {
    pub fn new(source: &str, executable: PathBuf, secret: String) -> Self {
        Self {
            source: source.to_owned(),
            executable,
            secret,
        }
    }

    /// Runs one call and answers its body, or the failure the sidecar named.
    fn call(&self, request: Value) -> Result<Value, ReaderError> {
        let mut child = Command::new(&self.executable)
            .arg(&self.source)
            .env(SECRET_VARIABLE, &self.secret)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| ReaderError::Source {
                code: "reader_missing".to_owned(),
                message: format!("The {} reader did not start: {error}.", self.source),
            })?;
        let request = serde_json::to_vec(&request).map_err(|error| ReaderError::Source {
            code: "invalid_request".to_owned(),
            message: error.to_string(),
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(&request);
        }
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            if let Some(stdout) = stdout.as_mut() {
                let _ = stdout.take(ANSWER_CAP as u64).read_to_end(&mut out);
            }
            let mut err = Vec::new();
            if let Some(stderr) = stderr.as_mut() {
                let _ = stderr.take(64 * 1024).read_to_end(&mut err);
            }
            let _ = sender.send((out, err));
        });
        let (out, err) = match receiver.recv_timeout(CALL_TIMEOUT) {
            Ok(streams) => streams,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ReaderError::Source {
                    code: "timeout".to_owned(),
                    message: format!(
                        "The {} reader did not answer within {} seconds.",
                        self.source,
                        CALL_TIMEOUT.as_secs()
                    ),
                });
            }
        };
        let status = child.wait().map_err(|error| ReaderError::Source {
            code: "source".to_owned(),
            message: error.to_string(),
        })?;
        let body: Value = match serde_json::from_slice(&out) {
            Ok(body) => body,
            Err(_) => {
                let stderr = String::from_utf8_lossy(&err).trim().to_owned();
                return Err(ReaderError::Source {
                    code: "source".to_owned(),
                    message: if stderr.is_empty() {
                        format!(
                            "The {} reader answered nothing readable and exited with {status}.",
                            self.source
                        )
                    } else {
                        format!("The {} reader failed: {stderr}", self.source)
                    },
                });
            }
        };
        if let Some(error) = body.get("error") {
            return Err(ReaderError::Source {
                code: error
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("source")
                    .to_owned(),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("The reader refused the call.")
                    .to_owned(),
            });
        }
        Ok(body)
    }

    fn read<T: for<'de> muniment_core::serde::Deserialize<'de>>(
        &self,
        request: Value,
        key: &str,
    ) -> Result<T, ReaderError> {
        let body = self.call(request)?;
        let value = body.get(key).cloned().ok_or_else(|| ReaderError::Source {
            code: "source".to_owned(),
            message: format!("The {} reader answered without {key}.", self.source),
        })?;
        serde_json::from_value(value).map_err(|error| ReaderError::Source {
            code: "source".to_owned(),
            message: format!(
                "The {} reader's {key} does not parse: {error}.",
                self.source
            ),
        })
    }
}

impl Reader for SidecarReader {
    fn objects(&self) -> Result<Vec<ObjectInfo>, ReaderError> {
        self.read(json!({"call": "objects"}), "objects")
    }

    fn describe(&self, object: &str) -> Result<Description, ReaderError> {
        self.read(json!({"call": "describe", "object": object}), "description")
    }

    fn page(
        &self,
        object: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<Page, ReaderError> {
        self.read(
            json!({"call": "page", "object": object, "cursor": cursor, "limit": limit}),
            "page",
        )
    }

    fn delta(&self, object: &str, cursor: &Cursor) -> Result<Delta, ReaderError> {
        self.read(
            json!({"call": "delta", "object": object, "cursor": cursor}),
            "delta",
        )
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // A shell script stands in for the sidecar: it echoes the request's call
    // back inside a canned answer, or fails the way the sidecar fails.
    fn stub(label: &str, script: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "muniment-reader-sidecar-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("muniment-reader");
        // Write in a child so concurrent test spawns cannot inherit the writer.
        // An inherited writer can make exec fail with ETXTBSY after this thread closes it.
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg("printf '%s\\n' \"$2\" > \"$1\" && chmod 755 \"$1\"")
            .arg("stub")
            .arg(&path)
            .arg(format!("#!/bin/sh\n{script}"))
            .status()
            .unwrap();
        assert!(status.success(), "The fixture writer failed: {status}");
        path
    }

    #[test]
    fn calls_the_sidecar_with_the_secret_and_reads_each_answer() {
        let path = stub(
            "answers",
            r#"request=$(cat)
[ "$1" = "stripe" ] || { echo '{"error":{"code":"unknown_source","message":"no"}}'; exit 1; }
[ "$MUNIMENT_READER_SECRET" = "sk_test" ] || { echo '{"error":{"code":"not_connected","message":"no key"}}'; exit 1; }
case "$request" in
  *'"call":"objects"'*) echo '{"objects":[{"name":"customers","label":"Customers"}]}' ;;
  *'"call":"describe"'*) echo '{"description":{"source":"stripe","object":"customers","label":"Customers","fields":[{"name":"id","guess":"id","samples":["cus_1"],"filled":1}],"rows":1,"bytes":0,"hash":"9","counted":false}}' ;;
  *'"call":"page"'*) echo '{"page":{"rows":[{"id":"cus_1","name":"Northwind"}],"offset":0,"total":1,"hash":"9","next":{"offset":1,"hash":"9","token":"cus_1"},"counted":false}}' ;;
  *'"call":"delta"'*) echo '{"delta":{"state":"changed","hash":"10"}}' ;;
  *) echo '{"error":{"code":"unknown_call","message":"what"}}' ;;
esac"#,
        );
        let reader = SidecarReader::new("stripe", path.clone(), "sk_test".into());
        let objects = reader.objects().unwrap();
        assert_eq!(objects[0].name, "customers");
        let description = reader.describe("customers").unwrap();
        assert_eq!(description.fields[0].guess, "id");
        assert!(!description.counted);
        let page = reader.page("customers", None, 100).unwrap();
        assert_eq!(page.rows[0]["name"], "Northwind");
        assert_eq!(page.next.as_ref().unwrap().token.as_deref(), Some("cus_1"));
        assert_eq!(
            reader.delta("customers", &Cursor::default()).unwrap(),
            Delta::Changed { hash: "10".into() }
        );

        let refused = SidecarReader::new("stripe", path.clone(), "wrong".into())
            .objects()
            .unwrap_err();
        assert_eq!(refused.code(), "not_connected");
        assert_eq!(refused.to_string(), "no key");
        let unknown = SidecarReader::new("quickbooks", path.clone(), "sk_test".into())
            .objects()
            .unwrap_err();
        assert_eq!(unknown.code(), "unknown_source");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn names_a_sidecar_that_is_missing_or_answers_nothing_readable() {
        let missing = SidecarReader::new(
            "stripe",
            PathBuf::from("/nowhere/muniment-reader"),
            "k".into(),
        )
        .objects()
        .unwrap_err();
        assert_eq!(missing.code(), "reader_missing");
        let path = stub("garbage", "cat >/dev/null; echo 'boom' >&2; exit 3");
        let garbage = SidecarReader::new("stripe", path.clone(), "k".into())
            .objects()
            .unwrap_err();
        assert_eq!(garbage.code(), "source");
        assert!(garbage.to_string().contains("boom"), "{garbage}");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        let env = std::env::temp_dir().join("muniment-reader-env-probe");
        std::fs::write(&env, "#!/bin/sh\nexit 0\n").unwrap();
        std::env::set_var("MUNIMENT_READER_BIN", &env);
        assert_eq!(sidecar_executable(None), Some(env.clone()));
        std::env::remove_var("MUNIMENT_READER_BIN");
        std::fs::remove_file(env).unwrap();
    }
}
