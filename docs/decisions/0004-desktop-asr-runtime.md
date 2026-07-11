# 0004 — Pin the desktop ASR runtime and Parakeet artifact

- Status: accepted
- Date: 2026-07-10
- Context: ROADMAP Phase 3 item 15; harness-spec §6.7

## Context

Desktop dictation must run on CPU on macOS, Windows, and Linux and must not
send voice bytes off the machine. NVIDIA's upstream Parakeet checkpoint is a
NeMo/Transformers artifact, not input that sherpa-onnx can consume directly.
The runtime and the converted ONNX graphs therefore both need reproducible
identities before capture code or distribution work begins.

## Considered alternatives

- Use NVIDIA's upstream NeMo files directly. Rejected: this does not define a
  sherpa-onnx integration and would add a different, heavier runtime boundary.
- Convert the NVIDIA checkpoint ourselves. Rejected for this phase: conversion
  settings and toolchain would become another artifact Muniment must reproduce,
  test, publish, and support.
- Use the converted float32 Parakeet v3 graphs. Rejected in favor of the
  publisher's INT8 conversion for the CPU and memory requirement; quality and
  speed still require the validation below.
- Use Qwen3-ASR or whisper.cpp. Deferred as evaluation/fallback options; neither
  displaces the roadmap decision without comparative target-hardware evidence.

## Decision

Pin **sherpa-onnx v1.13.2**, tag commit
`13d0ae6c539d2809d32f5eaa3ef1db0c459d0b24`, and the offline transducer model
**sherpa-onnx-nemo-parakeet-tdt-0.6b-v3-int8**. The conversion is published by
sherpa-onnx maintainer `csukuangfj` and is pinned to Hugging Face revision
`2bda32ec70b097a55adaa07d9a7173915b43cc78`; `main` is not an artifact identity.
It derives from NVIDIA `parakeet-tdt-0.6b-v3` (upstream revision
`7c35754d166cca382ad1e53e68b01e7c575f3a1d`).

The required model files are:

| Filename | Byte size | SHA-256 |
| --- | ---: | --- |
| `encoder.int8.onnx` | 652,184,281 | `acfc2b4456377e15d04f0243af540b7fe7c992f8d898d751cf134c3a55fd2247` |
| `decoder.int8.onnx` | 11,845,275 | `179e50c43d1a9de79c8a24149a2f9bac6eb5981823f2a2ed88d655b24248db4e` |
| `joiner.int8.onnx` | 6,355,277 | `3164c13fc2821009440d20fcb5fdc78bff28b4db2f8d0f0b329101719c0948b3` |
| `tokens.txt` | 93,939 | `d58544679ea4bc6ac563d1f545eb7d474bd6cfa467f0a6e2c1dc1c7d37e3c35d` |

Every file URL is
`https://huggingface.co/csukuangfj/sherpa-onnx-nemo-parakeet-tdt-0.6b-v3-int8/resolve/2bda32ec70b097a55adaa07d9a7173915b43cc78/<filename>`.
The three LFS sizes and digests come from Hugging Face's revision metadata;
the token-table values were reproduced by downloading that immutable URL and
running `wc -c` and `sha256sum`. Future acquisition must verify size and digest
before making the complete four-file set available to the recognizer.

This is an **utterance-final/offline** recognizer, not streaming. The future
capture layer supplies mono, 16 kHz PCM, converted at the boundary to normalized
`float32` samples. VAD may delimit short utterances and make repeated offline
decodes appear incremental, but that is simulated streaming and must not be
described as token streaming. For each utterance the first transcript is the
final ASR transcript; Gemma polish begins only after that result.

The 25 supported languages are Bulgarian (`bg`), Croatian (`hr`), Czech (`cs`),
Danish (`da`), Dutch (`nl`), English (`en`), Estonian (`et`), Finnish (`fi`),
French (`fr`), German (`de`), Greek (`el`), Hungarian (`hu`), Italian (`it`),
Latvian (`lv`), Lithuanian (`lt`), Maltese (`mt`), Polish (`pl`), Portuguese
(`pt`), Romanian (`ro`), Slovak (`sk`), Slovenian (`sl`), Spanish (`es`),
Swedish (`sv`), Russian (`ru`), and Ukrainian (`uk`). Language detection is
automatic; this decision does not promise equal quality across languages.

### Licenses and distribution notices

The NVIDIA model card declares the model CC BY 4.0 and permits commercial and
non-commercial use. Distribution must include the CC BY 4.0 text or link,
credit NVIDIA and the `parakeet-tdt-0.6b-v3` model by name, link the source model
and this converted revision, retain supplied notices, identify the ONNX/INT8
artifact as a conversion, and label any later Muniment modifications without
implying endorsement.

sherpa-onnx v1.13.2 is Apache License 2.0. Desktop distributions must include
its license, preserve copyright, patent, attribution, and NOTICE material
shipped by the release, and mark modified source files if Muniment modifies
them. The release's bundled third-party notices and licenses (including ONNX
Runtime) must be carried into the application's third-party notices. A release
cannot ship until the generated notice inventory has been reviewed against the
actual native bundle.

### Integration and packaging boundary

`muniment_core` will own microphone lifecycle, PCM buffering/VAD, and the
in-process sherpa-onnx offline recognizer through its C API. The webview receives
transcript text and state only, never microphone PCM. ASR is not a managed
network service or child process and does not use `SidecarSupervisor`.

The native boundary must expose no socket or HTTP path. Capture samples remain
in process memory (apart from explicit user recordings added by a separate
feature), and neither PCM nor derived voice features may be passed to Pi,
llama-server, the control plane, telemetry, or crash reports. Only transcript
text crosses into the existing local Gemma polish contract. This makes the ASR
path loopback/local in the stronger sense that it performs no network I/O at
all.

The desktop build will compile/link the v1.13.2 C API and its CPU ONNX Runtime
dependency for Tauri's desktop targets: macOS universal2 (`x86_64` + `arm64`),
Windows `x86_64`, and Linux `x86_64`. The resulting libraries are packaged as
Tauri native resources beside the four verified model files, with platform
loader paths fixed at build time. CI must fail on an unrecognized target or a
runtime/model digest mismatch. Linux ARM64 may be added by a later explicit
target decision; iOS, Android, CUDA, and other mobile/GPU artifacts are out of
scope.

### Follow-up validation matrix

No live-dictation UX claim is accepted by this ADR. Before integration is
declared ready, run the same release build with warm and cold starts on at least
these representative machines (or documented CPU-equivalent replacements):

| Tier | Required target | Corpus |
| --- | --- | --- |
| Low Windows | 4-core Intel Core i5-8250U, 8 GB RAM | fixtures below |
| Low Linux | 4-core Intel Core i5-8250U, 8 GB RAM | fixtures below |
| Mid Windows/Linux | 6-core AMD Ryzen 5 5500U, 16 GB RAM | fixtures below |
| Low macOS | Apple M1, 8 GB RAM | fixtures below |
| Mid macOS | current base Apple Silicon, 16 GB RAM | fixtures below |

For 5 s, 15 s, and 60 s clean and noisy utterances, report cold model-load time;
CPU real-time factor (`decode wall time / audio duration`); p50/p95 latency from
first PCM to first transcript and to final transcript; and process peak RSS.
Because recognition is offline, first and final ASR latency will normally be
the same; report both so a later simulated-streaming design remains comparable.
The minimum gate is RTF ≤ 1.0 and p95 final latency ≤ 1.0 s after end-of-speech
on every target, with peak RSS ≤ 2.0 GiB and no crash or unbounded growth over
100 consecutive utterances.

Quality checks use a versioned, human-transcribed set containing accents,
punctuation, names/org jargon, numbers, self-corrections, background noise, and
at least English plus one fixture for every claimed language. Report per-language
word error rate (character error rate where word segmentation is unsuitable),
named-entity accuracy, and deletion/substitution counts before Gemma polish.
The gate is no regression against the same float32 conversion and no material
loss of names, numbers, or negation. Exact numeric quality thresholds require a
product-approved corpus and are deliberately not invented here.

## Consequences

The choice is build-ready and reproducible, avoids CUDA and network inference,
and preserves the existing Gemma polish boundary. It adds roughly 670 MB of
model files plus target-native runtime libraries to desktop distribution and
requires CC BY 4.0 attribution and Apache/third-party notices.

INT8 improves the CPU packaging proposition but does not prove acceptable
latency, memory, or transcription quality. Failure of the validation gates
reopens the artifact/recognizer decision rather than weakening the on-device
privacy requirement. Acquisition, atomic publication, update/rollback,
recovery, removal, and notice delivery are decided by [ADR
0005](0005-asr-model-lifecycle.md). Capture UI, VAD selection, bindings, native
binaries, model weights, and application integration remain follow-up work.

## Sources

- NVIDIA model card and license: <https://huggingface.co/nvidia/parakeet-tdt-0.6b-v3/tree/7c35754d166cca382ad1e53e68b01e7c575f3a1d>
- Immutable converted artifact: <https://huggingface.co/csukuangfj/sherpa-onnx-nemo-parakeet-tdt-0.6b-v3-int8/tree/2bda32ec70b097a55adaa07d9a7173915b43cc78>
- sherpa-onnx v1.13.2 release: <https://github.com/k2-fsa/sherpa-onnx/releases/tag/v1.13.2>
- Offline Parakeet model documentation: <https://k2-fsa.github.io/sherpa/onnx/pretrained_models/offline-transducer/nemo-transducer-models.html>
- Offline microphone recognition: <https://k2-fsa.github.io/sherpa/onnx/tauri/vad-asr-mic.html>
- CC BY 4.0: <https://creativecommons.org/licenses/by/4.0/legalcode>
- Apache License 2.0: <https://github.com/k2-fsa/sherpa-onnx/blob/v1.13.2/LICENSE>
