# 0030 — Declare the public core boundary

- Status: accepted

## Decision

The port set belongs in `munimentai/muniment` under FSL, with its tests.
This boundary moves no source files.
A staying module may depend on the port set.
Nothing in the port set may depend on a staying module, `muniment-desktop`, or `tauri`.
The exceptions below block a clean port until their follow-ups remove those edges.

The tables cover every workspace crate and every top-level `muniment-core` module, including platform-gated and private modules.
Module rows name the module below `muniment-core`.

## Port

| Kind | Name | Why |
| --- | --- | --- |
| crate | muniment-core | It holds the local runtime logic and storage contracts. |
| crate | muniment-attach | It defines the reader and companion protocol without the shell. |
| crate | muniment-code-diff | It defines portable code-diff values and fixtures. |
| crate | muniment-cli | It gives the local runtime a shell-free client. |
| crate | muniment-acp | It adapts ACP agents to the runtime. |
| crate | muniment-runtime | It owns the user-level runtime service. |
| module | active_run | It controls active runs and permission answers. |
| module | asr | It owns on-device speech recognition. |
| module | assistant_text | It scans and projects assistant replies. |
| module | atomic_file | It publishes local files atomically. |
| module | attach | It serves and secures runtime connections. |
| module | attachment | It stores run attachments in CAS. |
| module | cas | It owns content-addressed storage. |
| module | chat_coordinate | It coordinates runs and permission policy. |
| module | chat_profile | It opens profile storage without a window. |
| module | chat_prompt | It protects prompts through the system keyring. |
| module | chat_resume | It resumes journaled runs. |
| module | chat_view | It defines serializable run projections, not entitlement UI. |
| module | code_diff | It exposes the portable code-diff contract. |
| module | code_diff_apply | It applies verified write plans. |
| module | code_diff_effect | It journals approved file writes. |
| module | code_diff_journal | It projects code-diff events. |
| module | code_diff_observe | It verifies workspace state before writes. |
| module | code_diff_staging | It stages file operations. |
| module | home | It owns the local memory filesystem. |
| module | import_preview | It previews bounded assistant exports. |
| module | journal | It owns the run journal and reader projections. |
| module | kokoro | It owns on-device read-aloud. |
| module | local_mode | It reads the local-mode marker without an account. |
| module | memory_failure | It defines memory-search failures. |
| module | memory_index | It indexes local memory. |
| module | memory_runtime | It coordinates memory sessions. |
| module | memory_secret | It rejects secrets from memory writes. |
| module | model_acquisition_transport | It downloads pinned model artifacts. |
| module | model_artifact | It verifies and publishes model artifacts. |
| module | model_install | It coordinates model installation. |
| module | model_install_native | It adapts model installation to native filesystems. |
| module | onnx_runtime | It loads the native inference runtime. |
| module | owned_threads | It selects owned journal threads. |
| module | permission_gate | It enforces per-thread permission answers. |
| module | pi_execution | It executes Pi runs. |
| module | pi_launch | It configures Pi launches. |
| module | pi_packages | It installs Pi extension packages. |
| module | pi_settings | It writes Pi runtime settings. |
| module | retention_record | It records retention choices. |
| module | router_classifier | It classifies routes locally without cloud metadata. |
| module | run_events | It appends and projects run events. |
| module | run_preparation | It prepares journaled runs. |
| module | run_start | It starts runtime runs. |
| module | session_thread | It binds sessions to journal threads. |
| module | sidecar | It supervises Pi and its RPC transport. |
| module | thread_history | It reads journal-backed thread history. |
| module | thread_ownership | It checks journal subject ownership. |
| module | user_diagnostics | It diagnoses user-level runtime services. |
| module | windows_known_folders | It resolves Windows runtime paths. |
| module | windows_payload | It resolves installed runtime payloads. |
| module | windows_security | It secures Windows runtime objects. |
| module | windows_sid | It identifies the Windows runtime user. |
| module | windows_task | It defines Windows runtime task values. |
| module | windows_task_service | It manages the Windows runtime task. |
| module | windows_user_diagnostics | It diagnoses the Windows runtime service. |
| module | write_plan | It defines immutable file write plans. |

## Stay

| Kind | Name | Why |
| --- | --- | --- |
| crate | muniment-desktop | It owns the Tauri shell and entitlement projection UI. |
| module | auth | It implements cloud-native auth and entitlement contracts. |
| module | browser_control | It implements browser-control identity and transport. |
| module | chat_grant | It implements cloud grants and receipts, including the shared local grant value. |

The `browser-control/` extension and the remote-control design study also stay in this repository.
Neither is a workspace crate or a top-level core module.
The reader interface stays small and hand-guarded through the attach protocol and journal projections.
The boundary does not authorize wider reader access or a protocol change.

## Check and follow-ups

`scripts/check-core-boundary.sh` reads both tables and rejects missing, duplicate, or unknown inventory entries.
It checks every port crate with Cargo's all-target dependency tree, including build and test dependencies.
It rejects the shell, Tauri packages, and other staying crates without exceptions.
It tests each port crate without root default features.
The core test enables `keyring` to include prompt and thread-history tests.
CI runs this check in the smoke job, including pushes to `main` and changes to this record.

`desktop-integration` fences the three staying modules and remains a default feature for desktop callers.
A core build with only `keyring` cannot compile because the port modules still import staying contracts.
The check explicitly enables `desktop-integration` for the core test as a bounded exception.
The runtime also enables core default features through its dependency declaration.
These two feature edges remain exceptions until callers use port-owned contracts.
The check reports these exceptions rather than claiming a shell-free build also excludes staying modules.

The named source edges in `scripts/check-core-boundary.py` form the follow-up list, including test callers.
Each entry names one source file and one staying module.
The check rejects new edges and stale entries, so a removed edge requires removal of its exception.
There are no wildcard exceptions.

1. Extract port-owned session, device, and entitlement values from `auth` for attach and runtime callers.
2. Separate cloud grants and receipts from the local launch value in `chat_grant`.
3. Extract process readers from `browser_control` for attach identity checks.
4. Separate staying contract tests from port tests without dropping their coverage.
5. Remove the runtime default-feature edge and the check's explicit `desktop-integration` feature edge.

The module scan covers all Rust source and test files in port crates, regardless of host platform.
It reserves staying module identifiers outside staying source files.
It rejects root glob imports, alternate root aliases, and source includes that could hide an edge.
A source include needs a boundary review before the port set can use it.
Cargo compilation checks the enabled code paths as well.
Linux tests do not prove Windows compilation, which remains a desktop CI preflight check.
