use std::path::PathBuf;
use std::time::Instant;

use muniment_core::asr::validation::{load_manifest, run_cases, MAX_ENDURANCE_DECODE_COUNT};
use muniment_core::asr::{
    AsrRevisionLifecycle, OfflineParakeetRecognizer, PARAKEET_MODEL_MANIFEST,
    PARAKEET_MODEL_MANIFESTS,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("parakeet-eval: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = Arguments::parse(std::env::args_os().skip(1))?;
    let manifest = load_manifest(&arguments.manifest)?;
    let lifecycle = AsrRevisionLifecycle::new(
        arguments.model_root,
        &PARAKEET_MODEL_MANIFESTS,
        &PARAKEET_MODEL_MANIFEST,
    )
    .map_err(|error| error.to_string())?;
    let load_started = Instant::now();
    let recognizer = OfflineParakeetRecognizer::from_verified_current(&lifecycle)
        .map_err(|error| error.to_string())?;
    let load_seconds = load_started.elapsed().as_secs_f64();
    let report = run_cases(
        &manifest,
        arguments
            .manifest
            .parent()
            .unwrap_or(std::path::Path::new(".")),
        &recognizer,
        load_seconds,
        PARAKEET_MODEL_MANIFEST.revision,
        &arguments.machine_tier,
        arguments.endurance_decode_count,
    )?;
    let json = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    std::fs::write(&arguments.output, json)
        .map_err(|error| format!("write {}: {error}", arguments.output.display()))?;
    Ok(())
}

struct Arguments {
    model_root: PathBuf,
    manifest: PathBuf,
    output: PathBuf,
    machine_tier: String,
    endurance_decode_count: Option<usize>,
}

impl Arguments {
    fn parse(arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<Self, String> {
        let mut model_root = None;
        let mut manifest = None;
        let mut output = None;
        let mut machine_tier = None;
        let mut endurance_decode_count = None;
        let mut arguments = arguments;
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or_else(usage)?;
            match flag.to_str() {
                Some("--model-root") if model_root.is_none() => model_root = Some(value.into()),
                Some("--manifest") if manifest.is_none() => manifest = Some(value.into()),
                Some("--output") if output.is_none() => output = Some(value.into()),
                Some("--machine-tier") if machine_tier.is_none() => {
                    machine_tier = value.into_string().ok()
                }
                Some("--endurance-utterances") if endurance_decode_count.is_none() => {
                    endurance_decode_count = Some(
                        value
                            .to_str()
                            .and_then(|value| value.parse::<usize>().ok())
                            .filter(|count| (1..=MAX_ENDURANCE_DECODE_COUNT).contains(count))
                            .ok_or_else(|| {
                                format!(
                                    "--endurance-utterances must be between 1 and {MAX_ENDURANCE_DECODE_COUNT}"
                                )
                            })?,
                    )
                }
                _ => return Err(usage()),
            }
        }
        let parsed = Self {
            model_root: model_root.ok_or_else(usage)?,
            manifest: manifest.ok_or_else(usage)?,
            output: output.ok_or_else(usage)?,
            machine_tier: machine_tier.ok_or_else(usage)?,
            endurance_decode_count,
        };
        if parsed.machine_tier.trim().is_empty() {
            return Err("--machine-tier must not be empty".into());
        }
        if parsed.output == parsed.manifest {
            return Err("--output must differ from --manifest".into());
        }
        Ok(parsed)
    }
}

fn usage() -> String {
    "usage: parakeet-eval --model-root <ASR lifecycle root> --manifest <corpus.json> --output <report.json> --machine-tier <tier> [--endurance-utterances <1..=100>]".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_all_named_arguments() {
        assert!(
            Arguments::parse(["--manifest", "corpus.json"].into_iter().map(Into::into)).is_err()
        );
        assert!(Arguments::parse(["--wat", "x"].into_iter().map(Into::into)).is_err());
        assert!(Arguments::parse(
            [
                "--model-root",
                "model",
                "--manifest",
                "same.json",
                "--output",
                "same.json",
                "--machine-tier",
                "tier",
            ]
            .into_iter()
            .map(Into::into)
        )
        .is_err());
    }

    #[test]
    fn validates_endurance_utterance_bounds() {
        let arguments = |count: &str| {
            Arguments::parse(
                [
                    "--model-root",
                    "model",
                    "--manifest",
                    "corpus.json",
                    "--output",
                    "report.json",
                    "--machine-tier",
                    "tier",
                    "--endurance-utterances",
                    count,
                ]
                .into_iter()
                .map(Into::into),
            )
        };
        assert!(arguments("0").is_err());
        assert!(arguments("101").is_err());
        assert!(arguments("nope").is_err());
        assert_eq!(arguments("100").unwrap().endurance_decode_count, Some(100));
    }
}
