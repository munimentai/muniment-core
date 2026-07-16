# Offline ASR third-party notices

Muniment packages the CPU-only shared libraries from sherpa-onnx **v1.13.2**
(commit `13d0ae6c539d2809d32f5eaa3ef1db0c459d0b24`) and its ONNX Runtime
**v1.24.4** dependency. No CUDA or mobile runtime is included.

The checked-in files were extracted without modification from these upstream
release archives (SHA-256 from the v1.13.2 release `checksum.txt`):

| Target | Upstream archive | SHA-256 |
| --- | --- | --- |
| Linux x86_64 | `sherpa-onnx-v1.13.2-linux-x64-shared-no-tts-lib.tar.bz2` | `1c66f4ec57cbf6a608f09e373796346943702251f75d08c45e8f47345a960ee6` |
| macOS universal2 | `sherpa-onnx-v1.13.2-osx-universal2-shared-no-tts-lib.tar.bz2` | `117150cf014ed913b1f5aee75eccfafa7957919b6efe8b9a3974bbcb5f7d6020` |
| Windows x86_64 | `sherpa-onnx-v1.13.2-win-x64-shared-MD-Release-no-tts-lib.tar.bz2` | `6ddd96bd875349b0580d0bbfd70fb08694ad1b7ef9f02966005aec5c7824b700` |

- `sherpa-onnx-LICENSE.txt` is the sherpa-onnx Apache License 2.0 text.
- `onnxruntime-LICENSE.txt` is the ONNX Runtime MIT license.
- `onnxruntime-ThirdPartyNotices.txt` is the notice inventory supplied for the
  packaged ONNX Runtime revision.

The separately installed Parakeet model is NVIDIA `parakeet-tdt-0.6b-v3`,
converted to ONNX/INT8 by the sherpa-onnx project. It is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) and pinned to the
converted revision `2bda32ec70b097a55adaa07d9a7173915b43cc78`.
