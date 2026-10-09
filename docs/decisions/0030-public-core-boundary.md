# 0030 — Declare the public core boundary

- Status: accepted

## Decision

The port set lives in `munimentai/muniment-core` under FSL, with its tests.
The desktop (`munimentai/muniment`) and the factory consume it.
Nothing in the port set may depend on a staying module, a staying crate, or `tauri`.
The staying modules live in the desktop's `muniment-desktop-integration` crate.

The tables cover every workspace crate and every top-level `muniment-core` module, including platform-gated and private modules.
Module rows name the module below `muniment-core`.
A module that `muniment-core` re-exports from another workspace crate keeps its row.

## Port

| Kind | Name | Why |
| --- | --- | --- |
| crate | muniment-core | It holds the local runtime logic and storage contracts. |
| crate | muniment-attach | It defines the reader and companion protocol without the shell. |
| crate | muniment-atomic-file | It publishes local files atomically. |
| crate | muniment-code-diff | It defines portable code-diff values and fixtures. |
| crate | muniment-pins | It pins Pi, its extension packages, and the Claude Code version. |
| crate | muniment-router | It selects provider accounts and routes model requests. |
| module | account | It defines the session, device, pairing, and entitlement values attach carries. |
| module | agent_templates | It imports bounded public agent templates. |
| module | agents | It stores persistent agents and their conversations. |
| module | memory_files | It manages user profiles and recoverable memory files. |
| module | model_router | It selects local provider accounts and routes model requests. |
| module | projects | It scopes threads and generated files to project folders. |
| module | extend | It manages local extensions and per-chat capability snapshots. |
| module | creations | It stores local agent and artifact creation contracts. |
| module | project_context | It provides project context to the local harness. |
| module | workspace_names | It resolves stable names for local workspace folders. |
| module | active_run | It controls active runs and permission answers. |
| module | asr | It owns on-device speech recognition. |
| module | assistant_text | It scans and projects assistant replies. |
| module | atomic_file | It publishes local files atomically. |
| module | attach | It serves and secures runtime connections. |
| module | attachment | It stores run attachments in CAS. |
| module | browser_agent | It runs the browser loop a decision model drives. |
| module | cas | It owns content-addressed storage. |
| module | chat_coordinate | It coordinates runs and permission policy. |
| module | chat_launch | It defines the launch value a run starts Pi with and answers gateway requests. |
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
| module | endpoint_models | It lists the models an OpenAI-compatible endpoint serves. |
| module | harness_scan | It counts durable assistant memory in user-level roots. |
| module | home | It owns the local memory filesystem. |
| module | http | It shares HTTP agent configuration and OS certificate verification. |
| module | import_preview | It previews bounded assistant exports. |
| module | journal | It owns the run journal and reader projections. |
| module | kokoro | It owns on-device read-aloud. |
| module | launch_facts | It states the facts of a launch to the model: its model, earlier models, host, shell and working directory. |
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
| module | process_reader | It reads Linux process identities for attach peer checks. |
| module | provider_models | It discovers and caches models from configured providers. |
| module | record | It owns the company record: the SQLite graph, the catalogue and the write path. |
| module | retention_record | It records retention choices. |
| module | router_classifier | It classifies routes locally without cloud metadata. |
| module | run_events | It appends and projects run events. |
| module | run_preparation | It prepares journaled runs. |
| module | run_start | It starts runtime runs. |
| module | runtime_diagnostics | It writes bounded runtime diagnostics. |
| module | session_thread | It binds sessions to journal threads. |
| module | sidecar | It supervises Pi and its RPC transport. |
| module | state_root | It resolves the one state root every local file sits under. |
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
| crate | muniment-desktop-integration | It holds the desktop-only modules below. |
| module | auth | It implements cloud-native auth and entitlement contracts. |
| module | browser_control | It implements browser-control identity and transport. |
| module | chat_grant | It issues cloud grants and fetches cloud receipts. |

The reader interface stays small and hand-guarded through the attach protocol and journal projections.
The boundary does not authorize wider reader access or a protocol change.

## Host contracts

The host supplies desktop behavior through port-owned values and traits.
`account` holds the values that sign-in, device, pairing, and entitlement calls answer.
`RunAttachBoundaries` carries those calls, and the core only serializes their answers.
`chat_launch::ChatGrant` is the launch value. `ChatGrant::local` serves local mode.
`PiLaunchBoundaries` issues replacement cloud grants, inspects the cloud session, and fetches cloud receipts.
Its defaults answer that the cloud is unavailable, so a host without cloud accounts runs locally.
`PiLaunchBoundaries::browser_host` answers the host's browser for the `browser` tool. Its default answers none.
`process_reader` reads Linux process identities for attach peers and for the desktop's browser control.

## Check

`scripts/check-core-boundary.sh` reads both tables and rejects missing, duplicate, or unknown inventory entries.
It rejects a staying module declared in `muniment-core` and a core default feature.
It checks every port crate with Cargo's all-target dependency tree, including build and test dependencies.
It rejects the shell, Tauri packages, and other staying crates.
It tests each port crate without default features.
The core test enables `keyring` to include prompt and thread-history tests.
CI runs this check on every push and pull request.

The module scan covers all Rust source and test files in port crates, regardless of host platform.
It finds staying module names in module declarations, paths, and grouped imports in every port source file.
No file has an exception. A field or a local variable with such a name is not a module path.
It rejects root glob imports, alternate root aliases, and source includes that could hide an edge.
A source include needs a boundary review. The reviewed includes are named in the check.
Cargo compilation checks the enabled code paths as well.
Linux and macOS tests do not prove Windows compilation, so CI checks the workspace on Windows.
