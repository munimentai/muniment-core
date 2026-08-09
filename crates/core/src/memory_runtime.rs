use crate as muniment_core;
use muniment_core::memory_index::{
    MemoryIndexError, MemoryRuntimeSession, MemorySearchResult, ModelMemoryCapability,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub struct ApplicationMemoryRuntime {
    config: PathBuf,
    database_root: PathBuf,
    sessions: Mutex<BTreeMap<String, Arc<Mutex<MemoryRuntimeSession>>>>,
}

impl ApplicationMemoryRuntime {
    pub fn new(config: PathBuf, database_root: PathBuf) -> Self {
        Self {
            config,
            database_root,
            sessions: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn open_session(
        &self,
        session: &str,
        thread: &str,
        capability: ModelMemoryCapability,
    ) -> Result<(), MemoryIndexError> {
        let home = muniment_core::home::configured_home(&self.config)
            .map_err(|error| MemoryIndexError::Io(std::io::Error::other(error.to_string())))?
            .ok_or(MemoryIndexError::InvalidPath)?;
        let database = self.database_root.join("memory-index.sqlite3");
        self.open_session_for_home(session, thread, capability, &home, database);
        if let Err(error) = self.write_agent_extension(session) {
            self.close_session(session);
            return Err(error);
        }
        Ok(())
    }

    fn build_session(&self, session: &str) {
        self.build_session_with_timeout(
            session,
            muniment_core::memory_index::DEFAULT_BUILD_TIMEOUT,
        );
    }

    fn build_session_with_timeout(&self, session: &str, timeout: std::time::Duration) {
        if let Some(session) = self.session(session) {
            let session = session
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = session.build_with_timeout(timeout);
        }
    }

    fn write_agent_extension(&self, session: &str) -> Result<(), MemoryIndexError> {
        let definition = self
            .tool_definition_for_turn(session)
            .ok_or(MemoryIndexError::InvalidToolArguments)?;
        let encoded = serde_json::to_string(
            std::str::from_utf8(&definition).map_err(|_| MemoryIndexError::InvalidToolArguments)?,
        )
        .map_err(|_| MemoryIndexError::InvalidToolArguments)?;
        let source = format!(
            "const definition = JSON.parse({encoded});\nexport default function (pi) {{\n  pi.registerTool({{\n    name: definition.name,\n    label: \"Memory search\",\n    description: definition.description,\n    parameters: definition.inputSchema,\n    async execute(_id, arguments, _signal, _update, context) {{\n      const value = await context.ui.editor(\"muniment:memory-search\", JSON.stringify(arguments));\n      if (value === undefined) throw new Error(\"The memory search failed.\");\n      const result = JSON.parse(value);\n      return {{ content: [{{ type: \"text\", text: JSON.stringify(result) }}], details: result.recall }};\n    }}\n  }});\n}}\n"
        );
        std::fs::create_dir_all(&self.database_root).map_err(MemoryIndexError::Io)?;
        let temporary = self
            .database_root
            .join(format!(".memory-search-extension.{}.tmp", Uuid::now_v7()));
        if let Err(error) = std::fs::write(&temporary, source) {
            let _ = std::fs::remove_file(&temporary);
            return Err(MemoryIndexError::Io(error));
        }
        if let Err(error) = replace_extension(&temporary, &self.agent_extension_path()) {
            let _ = std::fs::remove_file(&temporary);
            return Err(MemoryIndexError::Io(error));
        }
        Ok(())
    }

    pub fn agent_extension_path(&self) -> PathBuf {
        self.database_root.join("memory-search-extension.js")
    }

    pub fn open_session_for_home(
        &self,
        session: &str,
        thread: &str,
        capability: ModelMemoryCapability,
        home: &Path,
        database: PathBuf,
    ) {
        self.insert_session(session, thread, capability, home, database);
        self.build_session(session);
    }

    fn insert_session(
        &self,
        session: &str,
        thread: &str,
        capability: ModelMemoryCapability,
        home: &Path,
        database: PathBuf,
    ) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                session.to_owned(),
                Arc::new(Mutex::new(MemoryRuntimeSession::open(
                    home, database, thread, capability,
                ))),
            );
    }

    pub fn tool_definition_for_turn(&self, session: &str) -> Option<Vec<u8>> {
        let session = self.session(session)?;
        let definition = session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tool_definition_for_turn()
            .to_vec();
        Some(definition)
    }

    pub fn dispatch_tool_call(
        &self,
        session: &str,
        name: &str,
        arguments: &[u8],
    ) -> Result<MemorySearchResult, MemoryIndexError> {
        if name != "memory-search" {
            return Err(MemoryIndexError::InvalidToolArguments);
        }
        let session = self
            .session(session)
            .ok_or(MemoryIndexError::InvalidToolArguments)?;
        let result = session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .call(arguments);
        result
    }

    pub fn close_session(&self, session: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(session);
    }

    fn session(&self, session: &str) -> Option<Arc<Mutex<MemoryRuntimeSession>>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(session)
            .cloned()
    }
}

#[cfg(not(windows))]
fn replace_extension(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(temporary, destination)
}

#[cfg(windows)]
fn replace_extension(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let temporary: Vec<_> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<_> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: Both pointers reference NUL-terminated UTF-16 buffers that live for the call.
    // MoveFileExW retains neither pointer.
    let replaced = unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier};

    #[test]
    fn agent_extension_contains_the_session_scoped_declaration() {
        let root = std::env::temp_dir().join(format!("muniment-app-memory-{}", Uuid::now_v7()));
        let home = root.join("home");
        fs::create_dir_all(home.join("memory")).unwrap();
        fs::write(home.join("memory/fact.md"), "saffron belongs in the pantry").unwrap();
        let runtime = ApplicationMemoryRuntime::new(root.join("config"), root.join("cache"));
        runtime.open_session_for_home(
            "session-1",
            "thread-1",
            ModelMemoryCapability {
                minimum_cacheable_prefix_characters: 100,
            },
            &home,
            root.join("cache/index.sqlite3"),
        );
        runtime.write_agent_extension("session-1").unwrap();
        let source = fs::read_to_string(runtime.agent_extension_path()).unwrap();
        assert!(source.contains("pi.registerTool"));
        assert!(source.contains("memory-search"));
        assert!(source.contains("text: JSON.stringify(result)"));
        assert!(!source.contains("if (result.error)"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_timed_out_session_build_does_not_block_the_extension() {
        let root = std::env::temp_dir().join(format!("muniment-app-memory-{}", Uuid::now_v7()));
        let home = root.join("home");
        fs::create_dir_all(home.join("memory")).unwrap();
        fs::write(home.join("memory/fact.md"), "saffron belongs in the pantry").unwrap();
        let runtime = ApplicationMemoryRuntime::new(root.join("config"), root.join("cache"));
        runtime.insert_session(
            "session-1",
            "thread-1",
            ModelMemoryCapability {
                minimum_cacheable_prefix_characters: 100,
            },
            &home,
            root.join("cache/index.sqlite3"),
        );

        runtime.build_session_with_timeout("session-1", std::time::Duration::ZERO);
        runtime.write_agent_extension("session-1").unwrap();

        assert!(runtime.agent_extension_path().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_slow_build_in_one_session_does_not_block_another_session_search() {
        let root = std::env::temp_dir().join(format!("muniment-app-memory-{}", Uuid::now_v7()));
        let home = root.join("home");
        fs::create_dir_all(home.join("memory")).unwrap();
        fs::write(home.join("memory/fact.md"), "saffron belongs in the pantry").unwrap();
        let runtime = Arc::new(ApplicationMemoryRuntime::new(
            root.join("config"),
            root.join("cache"),
        ));
        for session in ["slow-build", "search"] {
            runtime.insert_session(
                session,
                session,
                ModelMemoryCapability {
                    minimum_cacheable_prefix_characters: 100,
                },
                &home,
                root.join(format!("cache/{session}.sqlite3")),
            );
        }
        runtime.build_session("search");

        let slow_session = runtime.session("slow-build").unwrap();
        let slow_session_guard = slow_session.lock().unwrap();
        let (build_started, wait_for_build) = mpsc::channel();
        let (build_finished, check_build) = mpsc::channel();
        let build_runtime = Arc::clone(&runtime);
        let build = std::thread::spawn(move || {
            build_started.send(()).unwrap();
            build_runtime.build_session("slow-build");
            build_finished.send(()).unwrap();
        });
        wait_for_build.recv().unwrap();

        let (search_finished, wait_for_search) = mpsc::channel();
        let search_runtime = Arc::clone(&runtime);
        let search = std::thread::spawn(move || {
            search_finished
                .send(search_runtime.dispatch_tool_call(
                    "search",
                    "memory-search",
                    br#"{"query":"saffron"}"#,
                ))
                .unwrap();
        });
        let result = wait_for_search.recv_timeout(std::time::Duration::from_secs(1));
        assert!(matches!(
            check_build.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(slow_session_guard);
        build.join().unwrap();
        search.join().unwrap();

        assert_eq!(result.unwrap().unwrap().items.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dispatch_for_a_closed_session_returns_invalid_tool_arguments() {
        let root = std::env::temp_dir().join(format!("muniment-app-memory-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).unwrap();
        let runtime = ApplicationMemoryRuntime::new(root.join("config"), root.join("cache"));
        runtime.insert_session(
            "closed",
            "thread",
            ModelMemoryCapability {
                minimum_cacheable_prefix_characters: 100,
            },
            &root.join("home"),
            root.join("cache/index.sqlite3"),
        );
        runtime.close_session("closed");

        let error = runtime
            .dispatch_tool_call("closed", "memory-search", br#"{"query":"saffron"}"#)
            .unwrap_err();

        assert!(matches!(error, MemoryIndexError::InvalidToolArguments));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_agent_extension_writes_never_expose_partial_source() {
        let root = std::env::temp_dir().join(format!("muniment-app-memory-{}", Uuid::now_v7()));
        let runtime = Arc::new(ApplicationMemoryRuntime::new(
            root.join("config"),
            root.join("cache"),
        ));
        runtime.open_session_for_home(
            "session-1",
            "thread-1",
            ModelMemoryCapability {
                minimum_cacheable_prefix_characters: 100,
            },
            &root.join("home"),
            root.join("cache/index.sqlite3"),
        );
        runtime.write_agent_extension("session-1").unwrap();
        let expected = fs::read(runtime.agent_extension_path()).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let completed = Arc::new(AtomicUsize::new(0));
        let writers: Vec<_> = (0..2)
            .map(|_| {
                let runtime = Arc::clone(&runtime);
                let barrier = Arc::clone(&barrier);
                let completed = Arc::clone(&completed);
                std::thread::spawn(move || {
                    barrier.wait();
                    let result =
                        (0..100).try_for_each(|_| runtime.write_agent_extension("session-1"));
                    completed.fetch_add(1, Ordering::Release);
                    result.unwrap();
                })
            })
            .collect();

        barrier.wait();
        while completed.load(Ordering::Acquire) < 2 {
            assert_eq!(fs::read(runtime.agent_extension_path()).unwrap(), expected);
        }
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(fs::read(runtime.agent_extension_path()).unwrap(), expected);
        fs::remove_dir_all(root).unwrap();
    }
}
