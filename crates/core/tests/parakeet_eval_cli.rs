use std::fs;
use std::process::Command;

#[test]
fn valid_corpus_does_not_produce_report_without_verified_model() {
    let root = std::env::temp_dir().join(format!(
        "muniment-parakeet-eval-no-model-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("empty-model-root")).unwrap();
    for duration in [5, 15, 60] {
        let mut writer = hound::WavWriter::create(
            root.join(format!("{duration}.wav")),
            hound::WavSpec {
                channels: 1,
                sample_rate: 16_000,
                bits_per_sample: 16,
                sample_format: hound::SampleFormat::Int,
            },
        )
        .unwrap();
        for _ in 0..duration * 16_000 {
            writer.write_sample(0_i16).unwrap();
        }
        writer.finalize().unwrap();
    }
    let cases: Vec<_> = ["clean", "noisy"]
        .into_iter()
        .flat_map(|audio_class| {
            [5, 15, 60].into_iter().map(move |duration| {
                serde_json::json!({
                    "id": format!("{audio_class}-{duration}"),
                    "language": "en",
                    "audio_class": audio_class,
                    "duration_seconds": duration,
                    "audio_path": format!("{duration}.wav")
                })
            })
        })
        .collect();
    let manifest = root.join("corpus.json");
    fs::write(
        &manifest,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "cases": cases
        }))
        .unwrap(),
    )
    .unwrap();
    let output = root.join("report.json");

    let result = Command::new(env!("CARGO_BIN_EXE_parakeet-eval"))
        .args([
            "--model-root",
            root.join("empty-model-root").to_str().unwrap(),
            "--manifest",
            manifest.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--machine-tier",
            "test-tier",
        ])
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("parakeet-eval:"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());
    fs::remove_dir_all(root).unwrap();
}
