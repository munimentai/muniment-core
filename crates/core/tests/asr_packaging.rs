use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

const RUNTIME: &str = "../third-party/sherpa-onnx-v1.13.2";
type RuntimeFile = (&'static str, &'static str, &'static str);
type PlatformCase = (&'static str, &'static str, &'static [RuntimeFile]);

#[test]
fn every_supported_target_bundles_the_pinned_linked_runtime_at_its_loader_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cases: &[PlatformCase] = &[
        (
            "linux",
            "$ORIGIN/../lib/muniment/asr-runtime",
            &[
                (
                    "linux-x86_64/libsherpa-onnx-c-api.so",
                    "libsherpa-onnx-c-api.so",
                    "33e09c24dabb94f749cae7f97d9dd3317944695dd68a6c09d316a863b81ea011",
                ),
                (
                    "linux-x86_64/libonnxruntime.so",
                    "libonnxruntime.so",
                    "88468d42d3381c18a7bd3f99a01f07293ff8c9e38f71fd5bcc5fa08c101d31bf",
                ),
            ],
        ),
        (
            "macos",
            "@executable_path/../Resources/asr-runtime",
            &[
                (
                    "macos-universal2/libsherpa-onnx-c-api.dylib",
                    "libsherpa-onnx-c-api.dylib",
                    "b7b0a34667834cb03a227d13130a08e990204fcc8dd9a5c9d532224266a18afd",
                ),
                (
                    "macos-universal2/libonnxruntime.1.24.4.dylib",
                    "libonnxruntime.1.24.4.dylib",
                    "e9a9534fc92910d9bd6ffd155c13ce7920417c652c5c1920178520880627513e",
                ),
            ],
        ),
        (
            "windows",
            "executable directory",
            &[
                (
                    "windows-x86_64/sherpa-onnx-c-api.dll",
                    "sherpa-onnx-c-api.dll",
                    "ee59933bb110fe8badf886a85fe3caaee0cf0d1a28497028b67ec711375c0cca",
                ),
                (
                    "windows-x86_64/onnxruntime.dll",
                    "onnxruntime.dll",
                    "8b695444d1a35ed0c8338b8c14438b3be5e0a3b222b88b1e7b4ce8753f135b50",
                ),
                (
                    "windows-x86_64/onnxruntime_providers_shared.dll",
                    "onnxruntime_providers_shared.dll",
                    "ebc55b0f28e8a79cbf78e810a7f510ba70e75a2dfbcfcc6aca31ab2b8710a59a",
                ),
            ],
        ),
    ];
    let build_script = fs::read_to_string(root.join("../build.rs")).unwrap();

    for (platform, loader_path, files) in cases {
        let config: Value = serde_json::from_slice(
            &fs::read(root.join(format!("../tauri.{platform}.conf.json"))).unwrap(),
        )
        .unwrap();
        let resources = config["bundle"]["resources"].as_object().unwrap();
        if *platform != "windows" {
            assert!(build_script.contains(loader_path));
        }

        for (source, filename, expected_hash) in *files {
            let source_key = format!("third-party/sherpa-onnx-v1.13.2/{source}");
            let destination = resources[&source_key].as_str().unwrap();
            let expected_destination = if *platform == "windows" {
                filename.to_string()
            } else {
                format!("asr-runtime/{filename}")
            };
            assert_eq!(destination, expected_destination);

            let bundled = root.join(RUNTIME).join(source);
            assert_eq!(sha256(&bundled), *expected_hash);
            let linked = root.join(RUNTIME).join("link").join(filename);
            assert_eq!(sha256(&linked), *expected_hash);
        }
    }
}

fn sha256(path: &PathBuf) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}
