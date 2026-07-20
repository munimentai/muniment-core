use std::fs;
use std::path::Path;

use serde_json::Value;

const NOTICE_SOURCE: &str = "../THIRD_PARTY_NOTICES.md";
const NOTICE_DESTINATION: &str = "third-party-notices/THIRD_PARTY_NOTICES.md";
const LLAMA_CPP_MIT_NOTICE: &str = r#"MIT License

Copyright (c) 2023-2026 The ggml authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."#;

#[test]
fn packaged_apps_include_the_pinned_llama_cpp_mit_notice() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let notice = fs::read_to_string(root.join("../..").join("THIRD_PARTY_NOTICES.md")).unwrap();

    assert!(notice.contains("## llama.cpp b10068"));
    assert!(notice.contains(LLAMA_CPP_MIT_NOTICE));

    let build_script = fs::read_to_string(root.join("../build.rs")).unwrap();
    assert!(build_script.contains("require(\"../THIRD_PARTY_NOTICES.md\")"));

    for platform in ["linux", "macos", "windows"] {
        let config: Value = serde_json::from_slice(
            &fs::read(root.join(format!("../tauri.{platform}.conf.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            config["bundle"]["resources"][NOTICE_SOURCE],
            NOTICE_DESTINATION
        );
    }
}
