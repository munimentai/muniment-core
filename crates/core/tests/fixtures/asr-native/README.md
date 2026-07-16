# Native ASR smoke fixture

These three minimal ONNX graphs model the NeMo transducer ABI used by the
pinned Parakeet configuration. The encoder emits one frame, the decoder carries
its two recurrent states, and the joiner deterministically emits the
`fixture` token. They contain no trained weights or production model data.

The fixture exists only to exercise recognizer creation, stream creation,
16 kHz waveform acceptance, native decode, result extraction, and handle
cleanup in offline CI.
