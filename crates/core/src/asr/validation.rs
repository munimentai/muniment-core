//! Manifest and report types for reproducible offline ASR validation.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::OfflineParakeetRecognizer;

pub const CORPUS_SCHEMA_VERSION: u32 = 1;
pub const REPORT_SCHEMA_VERSION: u32 = 2;
pub const MAX_ENDURANCE_DECODE_COUNT: usize = 100;
pub const REQUIRED_DURATIONS_SECONDS: [f64; 3] = [5.0, 15.0, 60.0];
pub const MATRIX_DURATION_TOLERANCE_SECONDS: f64 = 0.25;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusManifest {
    pub schema_version: u32,
    pub cases: Vec<CorpusCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusCase {
    pub id: String,
    pub language: String,
    pub audio_class: AudioClass,
    pub duration_seconds: f64,
    pub audio_path: PathBuf,
    pub reference_transcript: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AudioClass {
    Clean,
    Noisy,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ValidationReport {
    pub schema_version: u32,
    pub model_revision: String,
    pub platform: Platform,
    pub machine_tier: String,
    pub decode_run: DecodeRunReport,
    pub cases: Vec<CaseReport>,
    pub aggregate: AggregateReport,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct DecodeRunReport {
    pub requested_decode_count: usize,
    pub completed_decode_count: usize,
    /// Current resident memory immediately before the first decode, or null when unsupported.
    pub start_process_resident_memory_bytes: Option<u64>,
    /// Current resident memory immediately after the final decode, or null when unsupported.
    pub end_process_resident_memory_bytes: Option<u64>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct CaseReport {
    pub id: String,
    pub language: String,
    pub audio_class: String,
    pub duration_seconds: f64,
    pub decode_wall_seconds: f64,
    pub real_time_factor: f64,
    pub first_transcript_latency_seconds: f64,
    pub final_transcript_latency_seconds: f64,
    pub transcript: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub word_error: Option<WordError>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct WordError {
    pub word_error_rate: f64,
    pub insertions: u64,
    pub deletions: u64,
    pub substitutions: u64,
    pub reference_words: u64,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct AggregateReport {
    pub cold_model_load_seconds: f64,
    pub p50_first_transcript_latency_seconds: f64,
    pub p95_first_transcript_latency_seconds: f64,
    pub p50_final_transcript_latency_seconds: f64,
    pub p95_final_transcript_latency_seconds: f64,
    pub p50_post_eos_decode_latency_seconds: f64,
    pub p95_post_eos_decode_latency_seconds: f64,
    /// Null when the operating system has no supported peak-RSS measurement.
    pub process_peak_rss_bytes: Option<u64>,
}

pub trait ValidationDecoder {
    fn decode(&self, sample_rate: u32, samples: &[f32]) -> Result<String, String>;
}

impl ValidationDecoder for OfflineParakeetRecognizer {
    fn decode(&self, sample_rate: u32, samples: &[f32]) -> Result<String, String> {
        self.decode(sample_rate, samples)
            .map_err(|error| error.to_string())
    }
}

pub fn load_manifest(path: &Path) -> Result<CorpusManifest, String> {
    let bytes = fs::read(path).map_err(|error| format!("read corpus manifest: {error}"))?;
    let manifest: CorpusManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse corpus manifest: {error}"))?;
    validate_manifest(&manifest, path.parent().unwrap_or(Path::new(".")))?;
    Ok(manifest)
}

pub fn validate_manifest(manifest: &CorpusManifest, base: &Path) -> Result<(), String> {
    if manifest.schema_version != CORPUS_SCHEMA_VERSION {
        return Err(format!(
            "unsupported corpus schema version {}",
            manifest.schema_version
        ));
    }
    if manifest.cases.is_empty() {
        return Err("corpus manifest must contain at least one case".into());
    }
    let mut ids = HashSet::new();
    for case in &manifest.cases {
        if case.id.trim().is_empty() || !ids.insert(&case.id) {
            return Err(format!("case id is empty or duplicated: {:?}", case.id));
        }
        if case.language.trim().is_empty() {
            return Err(format!("case {} has no language", case.id));
        }
        if !case.duration_seconds.is_finite() || case.duration_seconds <= 0.0 {
            return Err(format!("case {} has an invalid duration", case.id));
        }
        if case.audio_path.as_os_str().is_empty() || case.audio_path.is_absolute() {
            return Err(format!(
                "case {} audio_path must be a relative path",
                case.id
            ));
        }
        let audio = base.join(&case.audio_path);
        if !audio.is_file() {
            return Err(format!(
                "case {} audio file is missing: {}",
                case.id,
                audio.display()
            ));
        }
        if case
            .reference_transcript
            .as_ref()
            .is_some_and(|text| text.trim().is_empty())
        {
            return Err(format!(
                "case {} has an empty reference transcript",
                case.id
            ));
        }
    }
    for audio_class in [AudioClass::Clean, AudioClass::Noisy] {
        for required_duration in REQUIRED_DURATIONS_SECONDS {
            if !manifest.cases.iter().any(|case| {
                case.audio_class == audio_class
                    && (case.duration_seconds - required_duration).abs()
                        <= MATRIX_DURATION_TOLERANCE_SECONDS
            }) {
                return Err(format!(
                    "corpus manifest is missing required {} {required_duration}-second case (tolerance +/- {MATRIX_DURATION_TOLERANCE_SECONDS} seconds)",
                    match audio_class {
                        AudioClass::Clean => "clean",
                        AudioClass::Noisy => "noisy",
                    }
                ));
            }
        }
    }
    Ok(())
}

pub fn run_cases(
    manifest: &CorpusManifest,
    manifest_directory: &Path,
    decoder: &dyn ValidationDecoder,
    cold_model_load_seconds: f64,
    model_revision: &str,
    machine_tier: &str,
    endurance_decode_count: Option<usize>,
) -> Result<ValidationReport, String> {
    if machine_tier.trim().is_empty() {
        return Err("machine tier must not be empty".into());
    }
    if endurance_decode_count.is_some_and(|count| count == 0 || count > MAX_ENDURANCE_DECODE_COUNT)
    {
        return Err(format!(
            "endurance decode count must be between 1 and {MAX_ENDURANCE_DECODE_COUNT}"
        ));
    }
    let requested_decode_count = endurance_decode_count.unwrap_or(manifest.cases.len());
    let mut cases = Vec::with_capacity(manifest.cases.len().min(requested_decode_count));
    let mut first_latencies = Vec::with_capacity(requested_decode_count);
    let mut final_latencies = Vec::with_capacity(requested_decode_count);
    let mut post_eos_latencies = Vec::with_capacity(requested_decode_count);
    let start_process_resident_memory_bytes = process_resident_memory_bytes();
    for decode_index in 0..requested_decode_count {
        let case = &manifest.cases[decode_index % manifest.cases.len()];
        let (sample_rate, samples, actual_duration) =
            read_wav(&manifest_directory.join(&case.audio_path))?;
        let tolerance = (1.0 / sample_rate as f64).max(0.001);
        if (actual_duration - case.duration_seconds).abs() > tolerance {
            return Err(format!(
                "case {} manifest duration does not match its audio",
                case.id
            ));
        }
        let started = Instant::now();
        let transcript = decoder.decode(sample_rate, &samples)?;
        let wall = started.elapsed().as_secs_f64();
        first_latencies.push(case.duration_seconds + wall);
        final_latencies.push(case.duration_seconds + wall);
        post_eos_latencies.push(wall);
        if decode_index < manifest.cases.len() {
            cases.push(CaseReport {
                id: case.id.clone(),
                language: case.language.clone(),
                audio_class: match case.audio_class {
                    AudioClass::Clean => "clean",
                    AudioClass::Noisy => "noisy",
                }
                .into(),
                duration_seconds: case.duration_seconds,
                decode_wall_seconds: wall,
                real_time_factor: wall / case.duration_seconds,
                first_transcript_latency_seconds: case.duration_seconds + wall,
                final_transcript_latency_seconds: case.duration_seconds + wall,
                word_error: case
                    .reference_transcript
                    .as_deref()
                    .map(|reference| word_error(reference, &transcript)),
                transcript,
            });
        }
    }
    let end_process_resident_memory_bytes = process_resident_memory_bytes();
    first_latencies.sort_by(f64::total_cmp);
    final_latencies.sort_by(f64::total_cmp);
    post_eos_latencies.sort_by(f64::total_cmp);
    Ok(ValidationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        model_revision: model_revision.into(),
        platform: Platform {
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
        },
        machine_tier: machine_tier.into(),
        decode_run: DecodeRunReport {
            requested_decode_count,
            completed_decode_count: requested_decode_count,
            start_process_resident_memory_bytes,
            end_process_resident_memory_bytes,
        },
        aggregate: AggregateReport {
            cold_model_load_seconds,
            p50_first_transcript_latency_seconds: percentile(&first_latencies, 0.50),
            p95_first_transcript_latency_seconds: percentile(&first_latencies, 0.95),
            p50_final_transcript_latency_seconds: percentile(&final_latencies, 0.50),
            p95_final_transcript_latency_seconds: percentile(&final_latencies, 0.95),
            p50_post_eos_decode_latency_seconds: percentile(&post_eos_latencies, 0.50),
            p95_post_eos_decode_latency_seconds: percentile(&post_eos_latencies, 0.95),
            process_peak_rss_bytes: process_peak_rss_bytes(),
        },
        cases,
    })
}

#[cfg(test)]
fn aggregate_latencies(cases: &[CaseReport]) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let mut first: Vec<_> = cases
        .iter()
        .map(|case| case.first_transcript_latency_seconds)
        .collect();
    let mut final_: Vec<_> = cases
        .iter()
        .map(|case| case.final_transcript_latency_seconds)
        .collect();
    let mut post_eos: Vec<_> = cases.iter().map(|case| case.decode_wall_seconds).collect();
    first.sort_by(f64::total_cmp);
    final_.sort_by(f64::total_cmp);
    post_eos.sort_by(f64::total_cmp);
    (first, final_, post_eos)
}

fn read_wav(path: &Path) -> Result<(u32, Vec<f32>, f64), String> {
    let mut reader = hound::WavReader::open(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let spec = reader.spec();
    if spec.channels != 1 || spec.sample_rate != 16_000 {
        return Err(format!("{} must be mono 16 kHz WAV", path.display()));
    }
    let samples = match spec.sample_format {
        hound::SampleFormat::Float if spec.bits_per_sample == 32 => reader
            .samples::<f32>()
            .map(|value| value.map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?,
        hound::SampleFormat::Int if spec.bits_per_sample <= 16 => {
            let scale = (1_u64 << (spec.bits_per_sample - 1)) as f32;
            reader
                .samples::<i16>()
                .map(|value| value.map(|v| v as f32 / scale).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?
        }
        _ => {
            return Err(format!(
                "{} must contain 16-bit PCM or 32-bit float samples",
                path.display()
            ))
        }
    };
    if samples.is_empty() {
        return Err(format!("{} contains no audio samples", path.display()));
    }
    let duration = samples.len() as f64 / spec.sample_rate as f64;
    Ok((spec.sample_rate, samples, duration))
}

pub fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    debug_assert!(!sorted.is_empty());
    let index = ((sorted.len() as f64 * quantile).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index]
}

pub fn word_error(reference: &str, hypothesis: &str) -> WordError {
    let reference: Vec<String> = reference
        .split_whitespace()
        .map(|word| word.to_lowercase())
        .collect();
    let hypothesis: Vec<String> = hypothesis
        .split_whitespace()
        .map(|word| word.to_lowercase())
        .collect();
    let mut cells = vec![vec![(0_u64, 0_u64, 0_u64); hypothesis.len() + 1]; reference.len() + 1];
    for (i, row) in cells.iter_mut().enumerate().skip(1) {
        row[0] = (0, i as u64, 0);
    }
    for (j, cell) in cells[0].iter_mut().enumerate().skip(1) {
        *cell = (j as u64, 0, 0);
    }
    for i in 1..=reference.len() {
        for j in 1..=hypothesis.len() {
            if reference[i - 1] == hypothesis[j - 1] {
                cells[i][j] = cells[i - 1][j - 1];
                continue;
            }
            let candidates = [
                add(cells[i][j - 1], 0),
                add(cells[i - 1][j], 1),
                add(cells[i - 1][j - 1], 2),
            ];
            cells[i][j] = *candidates
                .iter()
                .min_by_key(|&&(ins, del, sub)| (ins + del + sub, sub, del, ins))
                .unwrap();
        }
    }
    let (insertions, deletions, substitutions) = cells[reference.len()][hypothesis.len()];
    let errors = insertions + deletions + substitutions;
    WordError {
        word_error_rate: if reference.is_empty() {
            if hypothesis.is_empty() {
                0.0
            } else {
                1.0
            }
        } else {
            errors as f64 / reference.len() as f64
        },
        insertions,
        deletions,
        substitutions,
        reference_words: reference.len() as u64,
    }
}

fn add(value: (u64, u64, u64), kind: usize) -> (u64, u64, u64) {
    let mut values = [value.0, value.1, value.2];
    values[kind] += 1;
    (values[0], values[1], values[2])
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn process_peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the supplied rusage on success.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    let rss = unsafe { usage.assume_init() }.ru_maxrss;
    if rss < 0 {
        return None;
    }
    #[cfg(target_os = "linux")]
    return (rss as u64).checked_mul(1024);
    #[cfg(target_os = "macos")]
    return Some(rss as u64);
}

#[cfg(target_os = "windows")]
fn process_peak_rss_bytes() -> Option<u64> {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut counters = std::mem::MaybeUninit::<PROCESS_MEMORY_COUNTERS>::zeroed();
    // SAFETY: the pseudo-handle is valid in this process and the buffer has
    // exactly the size reported to GetProcessMemoryInfo.
    let succeeded = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            counters.as_mut_ptr(),
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if succeeded == 0 {
        None
    } else {
        Some(unsafe { counters.assume_init() }.PeakWorkingSetSize as u64)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn process_peak_rss_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn process_resident_memory_bytes() -> Option<u64> {
    let statm = fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    resident_pages.checked_mul(page_size as u64)
}

#[cfg(target_os = "macos")]
fn process_resident_memory_bytes() -> Option<u64> {
    #[repr(C)]
    struct ProcTaskInfo {
        virtual_size: u64,
        resident_size: u64,
        total_user: u64,
        total_system: u64,
        threads_user: u64,
        threads_system: u64,
        policy: i32,
        faults: i32,
        pageins: i32,
        cow_faults: i32,
        messages_sent: i32,
        messages_received: i32,
        syscalls_mach: i32,
        syscalls_unix: i32,
        context_switches: i32,
        thread_count: i32,
        running_thread_count: i32,
        priority: i32,
    }

    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;
    }

    const PROC_PIDTASKINFO: libc::c_int = 4;
    let mut info = std::mem::MaybeUninit::<ProcTaskInfo>::uninit();
    let size = std::mem::size_of::<ProcTaskInfo>();
    let bytes = unsafe {
        proc_pidinfo(
            libc::getpid(),
            PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size as libc::c_int,
        )
    };
    if bytes != size as libc::c_int {
        None
    } else {
        Some(unsafe { info.assume_init() }.resident_size)
    }
}

#[cfg(target_os = "windows")]
fn process_resident_memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut counters = std::mem::MaybeUninit::<PROCESS_MEMORY_COUNTERS>::zeroed();
    let succeeded = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            counters.as_mut_ptr(),
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if succeeded == 0 {
        None
    } else {
        Some(unsafe { counters.assume_init() }.WorkingSetSize as u64)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn process_resident_memory_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeDecoder(AtomicUsize);

    impl ValidationDecoder for FakeDecoder {
        fn decode(&self, sample_rate: u32, samples: &[f32]) -> Result<String, String> {
            assert_eq!(sample_rate, 16_000);
            assert_eq!(samples.len(), 160);
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok("hello brave world".into())
        }
    }

    #[test]
    fn word_error_counts_are_deterministic() {
        assert_eq!(
            word_error("one two three", "zero one four three five"),
            WordError {
                word_error_rate: 1.0,
                insertions: 2,
                deletions: 0,
                substitutions: 1,
                reference_words: 3
            }
        );
        assert_eq!(word_error("", "extra").word_error_rate, 1.0);
    }

    #[test]
    fn nearest_rank_percentiles_cover_short_samples() {
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 0.50), 2.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 0.95), 4.0);
        assert_eq!(percentile(&[1.0], 0.95), 1.0);
    }

    #[test]
    fn validation_rejects_bad_manifests_and_runs_through_fake_boundary() {
        let root = std::env::temp_dir().join(format!(
            "muniment-asr-validation-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let audio_path = root.join("tiny.wav");
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: 16_000,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut writer = hound::WavWriter::create(&audio_path, spec).unwrap();
        for _ in 0..160 {
            writer.write_sample(0_i16).unwrap();
        }
        writer.finalize().unwrap();
        let manifest = CorpusManifest {
            schema_version: 1,
            cases: vec![CorpusCase {
                id: "tiny".into(),
                language: "en".into(),
                audio_class: AudioClass::Clean,
                duration_seconds: 0.01,
                audio_path: "tiny.wav".into(),
                reference_transcript: Some("hello world".into()),
            }],
        };
        let decoder = FakeDecoder(AtomicUsize::new(0));
        let report = run_cases(&manifest, &root, &decoder, 1.25, "revision", "tier", None).unwrap();
        assert_eq!(decoder.0.load(Ordering::Relaxed), 1);
        assert_eq!(report.cases[0].word_error.as_ref().unwrap().insertions, 1);
        assert_eq!(report.aggregate.cold_model_load_seconds, 1.25);
        assert_eq!(report.decode_run.requested_decode_count, 1);
        assert_eq!(report.decode_run.completed_decode_count, 1);

        let serialized = serde_json::to_string(&report).unwrap();
        assert!(serialized
            .starts_with(r#"{"schema_version":2,"model_revision":"revision","platform":{"os":"#));
        assert!(serialized.contains(r#""machine_tier":"tier","decode_run":{"requested_decode_count":1,"completed_decode_count":1"#));

        let mut invalid = manifest;
        invalid.cases[0].duration_seconds = 0.0;
        assert!(validate_manifest(&invalid, &root)
            .unwrap_err()
            .contains("invalid duration"));
        invalid.cases[0].duration_seconds = 0.01;
        invalid.cases.push(CorpusCase {
            id: "tiny".into(),
            language: "en".into(),
            audio_class: AudioClass::Noisy,
            duration_seconds: 0.01,
            audio_path: "missing.wav".into(),
            reference_transcript: None,
        });
        assert!(validate_manifest(&invalid, &root)
            .unwrap_err()
            .contains("duplicated"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn report_json_field_order_and_null_measurements_are_stable() {
        let report = ValidationReport {
            schema_version: REPORT_SCHEMA_VERSION,
            model_revision: "rev".into(),
            platform: Platform {
                os: "test-os".into(),
                architecture: "test-arch".into(),
            },
            machine_tier: "test-tier".into(),
            decode_run: DecodeRunReport {
                requested_decode_count: 1,
                completed_decode_count: 1,
                start_process_resident_memory_bytes: None,
                end_process_resident_memory_bytes: None,
            },
            cases: Vec::new(),
            aggregate: AggregateReport {
                cold_model_load_seconds: 1.0,
                p50_first_transcript_latency_seconds: 2.0,
                p95_first_transcript_latency_seconds: 3.0,
                p50_final_transcript_latency_seconds: 4.0,
                p95_final_transcript_latency_seconds: 5.0,
                p50_post_eos_decode_latency_seconds: 0.2,
                p95_post_eos_decode_latency_seconds: 0.3,
                process_peak_rss_bytes: None,
            },
        };
        assert_eq!(
            serde_json::to_string(&report).unwrap(),
            r#"{"schema_version":2,"model_revision":"rev","platform":{"os":"test-os","architecture":"test-arch"},"machine_tier":"test-tier","decode_run":{"requested_decode_count":1,"completed_decode_count":1,"start_process_resident_memory_bytes":null,"end_process_resident_memory_bytes":null},"cases":[],"aggregate":{"cold_model_load_seconds":1.0,"p50_first_transcript_latency_seconds":2.0,"p95_first_transcript_latency_seconds":3.0,"p50_final_transcript_latency_seconds":4.0,"p95_final_transcript_latency_seconds":5.0,"p50_post_eos_decode_latency_seconds":0.2,"p95_post_eos_decode_latency_seconds":0.3,"process_peak_rss_bytes":null}}"#
        );
    }

    #[test]
    fn endurance_run_counts_decodes_and_keeps_case_reports_bounded() {
        let root = std::env::temp_dir().join(format!(
            "muniment-asr-endurance-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let mut writer = hound::WavWriter::create(
            root.join("tiny.wav"),
            hound::WavSpec {
                channels: 1,
                sample_rate: 16_000,
                bits_per_sample: 16,
                sample_format: hound::SampleFormat::Int,
            },
        )
        .unwrap();
        for _ in 0..160 {
            writer.write_sample(0_i16).unwrap();
        }
        writer.finalize().unwrap();
        let manifest = CorpusManifest {
            schema_version: CORPUS_SCHEMA_VERSION,
            cases: vec![CorpusCase {
                id: "tiny".into(),
                language: "en".into(),
                audio_class: AudioClass::Clean,
                duration_seconds: 0.01,
                audio_path: "tiny.wav".into(),
                reference_transcript: None,
            }],
        };
        let decoder = FakeDecoder(AtomicUsize::new(0));
        let report = run_cases(
            &manifest,
            &root,
            &decoder,
            0.0,
            "revision",
            "tier",
            Some(MAX_ENDURANCE_DECODE_COUNT),
        )
        .unwrap();
        assert_eq!(decoder.0.load(Ordering::Relaxed), 100);
        assert_eq!(report.decode_run.requested_decode_count, 100);
        assert_eq!(report.decode_run.completed_decode_count, 100);
        #[cfg(target_os = "linux")]
        {
            assert!(report
                .decode_run
                .start_process_resident_memory_bytes
                .is_some());
            assert!(report
                .decode_run
                .end_process_resident_memory_bytes
                .is_some());
        }
        assert_eq!(report.cases.len(), 1);
        assert!(
            serde_json::to_value(report).unwrap()["decode_run"]
                .as_object()
                .unwrap()
                .len()
                == 4
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn endurance_decode_failure_aborts_without_a_report() {
        struct FailingDecoder(AtomicUsize);
        impl ValidationDecoder for FailingDecoder {
            fn decode(&self, _: u32, _: &[f32]) -> Result<String, String> {
                let count = self.0.fetch_add(1, Ordering::Relaxed) + 1;
                if count == 3 {
                    Err("decode failed".into())
                } else {
                    Ok(String::new())
                }
            }
        }

        let root =
            std::env::temp_dir().join(format!("muniment-asr-failure-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let mut writer = hound::WavWriter::create(
            root.join("tiny.wav"),
            hound::WavSpec {
                channels: 1,
                sample_rate: 16_000,
                bits_per_sample: 16,
                sample_format: hound::SampleFormat::Int,
            },
        )
        .unwrap();
        for _ in 0..160 {
            writer.write_sample(0_i16).unwrap();
        }
        writer.finalize().unwrap();
        let manifest = CorpusManifest {
            schema_version: 1,
            cases: vec![CorpusCase {
                id: "tiny".into(),
                language: "en".into(),
                audio_class: AudioClass::Clean,
                duration_seconds: 0.01,
                audio_path: "tiny.wav".into(),
                reference_transcript: None,
            }],
        };
        let decoder = FailingDecoder(AtomicUsize::new(0));
        assert_eq!(
            run_cases(
                &manifest,
                &root,
                &decoder,
                0.0,
                "revision",
                "tier",
                Some(100)
            )
            .unwrap_err(),
            "decode failed"
        );
        assert_eq!(decoder.0.load(Ordering::Relaxed), 3);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_requires_each_clean_and_noisy_duration_slot() {
        let root = std::env::temp_dir().join(format!(
            "muniment-asr-matrix-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("fixture.wav"), b"fixture").unwrap();

        let make_manifest = || CorpusManifest {
            schema_version: CORPUS_SCHEMA_VERSION,
            cases: [AudioClass::Clean, AudioClass::Noisy]
                .into_iter()
                .flat_map(|audio_class| {
                    REQUIRED_DURATIONS_SECONDS
                        .into_iter()
                        .map(move |duration_seconds| CorpusCase {
                            id: format!("{audio_class:?}-{duration_seconds}"),
                            language: "en".into(),
                            audio_class,
                            duration_seconds,
                            audio_path: "fixture.wav".into(),
                            reference_transcript: None,
                        })
                })
                .collect(),
        };

        validate_manifest(&make_manifest(), &root).unwrap();
        for audio_class in [AudioClass::Clean, AudioClass::Noisy] {
            for required_duration in REQUIRED_DURATIONS_SECONDS {
                let mut manifest = make_manifest();
                manifest.cases.retain(|case| {
                    case.audio_class != audio_class || case.duration_seconds != required_duration
                });
                let error = validate_manifest(&manifest, &root).unwrap_err();
                assert!(error.contains(&format!("{required_duration}-second")));
            }
        }

        let mut within_tolerance = make_manifest();
        within_tolerance.cases[0].duration_seconds =
            REQUIRED_DURATIONS_SECONDS[0] + MATRIX_DURATION_TOLERANCE_SECONDS;
        validate_manifest(&within_tolerance, &root).unwrap();
        within_tolerance.cases[0].duration_seconds += f64::EPSILON * 8.0;
        assert!(validate_manifest(&within_tolerance, &root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn aggregate_latency_percentiles_use_each_documented_reference_point() {
        let case = |first, final_, post_eos| CaseReport {
            id: String::new(),
            language: String::new(),
            audio_class: String::new(),
            duration_seconds: 1.0,
            decode_wall_seconds: post_eos,
            real_time_factor: post_eos,
            first_transcript_latency_seconds: first,
            final_transcript_latency_seconds: final_,
            transcript: String::new(),
            word_error: None,
        };
        let cases = vec![
            case(4.0, 40.0, 0.4),
            case(1.0, 10.0, 0.1),
            case(3.0, 30.0, 0.3),
        ];
        let (first, final_, post_eos) = aggregate_latencies(&cases);
        assert_eq!(percentile(&first, 0.50), 3.0);
        assert_eq!(percentile(&first, 0.95), 4.0);
        assert_eq!(percentile(&final_, 0.50), 30.0);
        assert_eq!(percentile(&final_, 0.95), 40.0);
        assert_eq!(percentile(&post_eos, 0.50), 0.3);
        assert_eq!(percentile(&post_eos, 0.95), 0.4);
    }
}
