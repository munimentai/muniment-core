# 0027 — Restore the pinned model artifact lifecycle

- Status: accepted
- Date: 2026-09-04
- Supersedes: ADR 0021
- Context: owner ruling 2026-09-04

## Context

The desktop ships local models again. A bad model update needs a proven rollback path.
The repository carried this path before MUNIDESK-680 removed it under the cloud ingress ruling.
The old module named a llama runtime that the desktop no longer serves.
The classifier now uses a bundled ONNX encoder.
A separate extractor arrives as a downloaded artifact.

## Decision

`src-tauri/core/src/model_artifact.rs` owns the generic artifact descriptor and verification contract.
A descriptor pins the artifact name, version, byte size, and SHA-256 digest.
It also records the source URL, file name, and license.
Verification rejects missing files, non-files, wrong sizes, unreadable files, and digest mismatches.

`src-tauri/core/src/model_artifact/acquisition.rs` restores bounded downloads and resumable `.part` files.
The acquisition code verifies completed bytes before it makes a stage ready for publication.
`model_acquisition_transport.rs` keeps `checked_initial_url` separate from `checked_redirect_url`.
The initial URL uses the pinned provider origin.
Each redirect URL must match the provider CDN policy.

`src-tauri/core/src/model_artifact/lifecycle.rs` restores staging and atomic publication.
The lifecycle writes `current`, `previous`, and `rejected` pointers.
Publication holds `install.lock` through `publish_lock_held` and `replace_revision`.
A failed activation rejects the current version and restores the verified previous version.
The rollback uses installed bytes and does not download the artifact again.

`NativeInstallLock` remains the process lock for `install.lock`.
The operating system releases its advisory lock when a process exits.
Concurrent processes cannot stage the same artifact while another installer holds the lock.

The classifier ships in the desktop bundle and does not use the downloader.
The extractor uses the restored descriptor, acquisition, verification, and lifecycle contracts.
This split avoids a runtime-specific module name and supports any pinned model file.

## Consequences

- Every downloaded model artifact has an exact identity and integrity pin.
- Interrupted downloads resume from verified staging state.
- Readers only resolve published versions.
- A failed model update has one verified rollback version.
- The bundled classifier and downloaded extractor use distinct delivery paths.
