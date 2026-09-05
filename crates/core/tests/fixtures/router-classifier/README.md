# Router classifier fixtures

These minimal ONNX graphs contain one `Identity` node and the classifier class-list metadata. They hold no trained weights.

Run this command from the repository root to regenerate both graphs:

```sh
python3 src-tauri/core/tests/fixtures/router-classifier/generate.py
```

`contract.onnx` stores the required class order. `reordered.onnx` places `route.local` first to test closed failure.
