//! Narrow, utterance-final boundary around sherpa-onnx's unsafe C API wrapper.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use sherpa_onnx::{
    OfflineRecognizer, OfflineRecognizerConfig, OfflineStream, OfflineTransducerModelConfig,
};

use super::{AsrLifecycleError, AsrRevisionLifecycle};

pub const SAMPLE_RATE: u32 = 16_000;

/// The SentencePiece vocabulary that hotword encoding reads. Hotwords mode
/// derives it from the verified `tokens.txt` inside the revision directory.
const HOTWORDS_BPE_VOCAB: &str = "hotwords-bpe.vocab";
/// The decoder adds this boost twice per matched token, so it starts low.
const HOTWORDS_SCORE: f32 = 1.5;
const HOTWORDS_MAX_ACTIVE_PATHS: i32 = 4;

/// The search a recognizer runs. The native decoder is fixed when the
/// recognizer is created, so a change of mode needs a new recognizer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ParakeetDecoding {
    /// Greedy search. It ignores custom vocabulary.
    #[default]
    Greedy,
    /// Modified beam search that biases each decode toward its custom vocabulary.
    Hotwords,
}

/// A bounded custom vocabulary that the native hotword parser accepts.
///
/// The parser reads a newline or `/` as an entry break and a word that starts
/// with `:` as a numeric score. A malformed score aborts the process, and a NUL
/// byte cannot cross the C boundary, so construction drops every entry that
/// carries one of these.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParakeetHotwords {
    encoded: String,
    len: usize,
}

impl ParakeetHotwords {
    pub const MAX_ENTRIES: usize = 256;
    pub const MAX_ENTRY_CHARS: usize = 64;

    /// Trims and squeezes each entry, drops unsafe, empty and repeated
    /// entries, and keeps at most [`Self::MAX_ENTRIES`] in input order.
    pub fn new<S: AsRef<str>>(entries: &[S]) -> Self {
        let mut accepted: Vec<String> = Vec::new();
        for entry in entries {
            if accepted.len() == Self::MAX_ENTRIES {
                break;
            }
            if let Some(entry) = sanitize_hotword(entry.as_ref()) {
                if !accepted.contains(&entry) {
                    accepted.push(entry);
                }
            }
        }
        Self {
            len: accepted.len(),
            encoded: accepted.join("\n"),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

fn sanitize_hotword(entry: &str) -> Option<String> {
    let parts: Vec<&str> = entry.split_whitespace().collect();
    let entry = parts.join(" ");
    let safe = !entry.is_empty()
        && entry.chars().count() <= ParakeetHotwords::MAX_ENTRY_CHARS
        && !entry
            .chars()
            .any(|character| character.is_control() || character == '/')
        && !parts.iter().any(|part| part.starts_with(':'));
    safe.then_some(entry)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OfflineRecognitionError {
    Verification(AsrLifecycleError),
    InvalidSampleRate,
    NonFiniteSamples,
    SamplesNotNormalized,
    TooManySamples,
    NativeRecognizerUnavailable,
    NativeDecodeFailed,
}

impl std::fmt::Debug for OfflineRecognitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verification(error) => f.debug_tuple("Verification").field(error).finish(),
            Self::InvalidSampleRate => f.write_str("InvalidSampleRate"),
            Self::NonFiniteSamples => f.write_str("NonFiniteSamples"),
            Self::SamplesNotNormalized => f.write_str("SamplesNotNormalized"),
            Self::TooManySamples => f.write_str("TooManySamples"),
            Self::NativeRecognizerUnavailable => f.write_str("NativeRecognizerUnavailable"),
            Self::NativeDecodeFailed => f.write_str("NativeDecodeFailed"),
        }
    }
}

impl std::fmt::Display for OfflineRecognitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Verification(_) => "the current ASR model failed verification",
            Self::InvalidSampleRate => "ASR input must be 16 kHz mono audio",
            Self::NonFiniteSamples => "ASR input contains an invalid sample",
            Self::SamplesNotNormalized => "ASR input samples must be normalized",
            Self::TooManySamples => "ASR input is too large",
            Self::NativeRecognizerUnavailable => "the offline recognizer could not be created",
            Self::NativeDecodeFailed => "offline recognition failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for OfflineRecognitionError {}

trait RecognizerBackend: Send + Sync {
    /// Decodes with per-stream hotwords when `hotwords` is set.
    fn decode(
        &self,
        samples: &[f32],
        hotwords: Option<&str>,
    ) -> Result<String, OfflineRecognitionError>;
}

struct SherpaBackend(OfflineRecognizer);

impl RecognizerBackend for SherpaBackend {
    fn decode(
        &self,
        samples: &[f32],
        hotwords: Option<&str>,
    ) -> Result<String, OfflineRecognitionError> {
        self.decode_inner(
            samples,
            hotwords,
            false,
            #[cfg(test)]
            None,
        )
    }
}

impl SherpaBackend {
    fn decode_inner(
        &self,
        samples: &[f32],
        hotwords: Option<&str>,
        fail_after_stream: bool,
        #[cfg(test)] release_count: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    ) -> Result<String, OfflineRecognitionError> {
        let handle = match hotwords {
            Some(hotwords) => self.0.create_stream_with_hotwords(hotwords),
            None => self.0.create_stream(),
        };
        let stream = NativeStream {
            handle,
            #[cfg(test)]
            release_count,
        };
        if fail_after_stream {
            return Err(OfflineRecognitionError::NativeDecodeFailed);
        }
        stream.accept_waveform(SAMPLE_RATE as i32, samples);
        self.0.decode(&stream.handle);
        stream
            .get_result()
            .map(|result| result.text)
            .ok_or(OfflineRecognitionError::NativeDecodeFailed)
    }
}

/// Owns one native stream so its C handle is released on every return path.
struct NativeStream {
    handle: OfflineStream,
    #[cfg(test)]
    release_count: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

impl std::ops::Deref for NativeStream {
    type Target = OfflineStream;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

#[cfg(test)]
impl Drop for NativeStream {
    fn drop(&mut self) {
        if let Some(count) = &self.release_count {
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // `handle` is dropped immediately after this hook and destroys the
        // actual sherpa-onnx stream pointer.
    }
}

/// An offline recognizer bound to the lifecycle's verified current Parakeet revision.
///
/// Callers cannot provide model filenames or network endpoints. Construction first
/// resolves and re-verifies the pinned four-file manifest.
pub struct OfflineParakeetRecognizer {
    backend: Box<dyn RecognizerBackend>,
    decoding: ParakeetDecoding,
}

impl OfflineParakeetRecognizer {
    pub fn from_verified_current(
        lifecycle: &AsrRevisionLifecycle,
    ) -> Result<Self, OfflineRecognitionError> {
        Self::from_verified_current_with_decoding(lifecycle, ParakeetDecoding::Greedy)
    }

    /// Creates a recognizer that runs `decoding`. Hotwords mode first writes
    /// the vocabulary it derives from the verified token table.
    pub fn from_verified_current_with_decoding(
        lifecycle: &AsrRevisionLifecycle,
        decoding: ParakeetDecoding,
    ) -> Result<Self, OfflineRecognitionError> {
        let directory = lifecycle
            .resolve_current()
            .map_err(OfflineRecognitionError::Verification)?;
        Self::from_directory(&directory, decoding)
    }

    fn from_directory(
        directory: &Path,
        decoding: ParakeetDecoding,
    ) -> Result<Self, OfflineRecognitionError> {
        let mut config = parakeet_config(directory, decoding)?;
        if decoding == ParakeetDecoding::Hotwords {
            let (_, token_count) = write_bpe_vocab(directory)?;
            // The native top-k reads past its buffer when the beam is wider
            // than the vocabulary.
            config.max_active_paths = config
                .max_active_paths
                .min(i32::try_from(token_count).unwrap_or(i32::MAX));
        }
        let recognizer = OfflineRecognizer::create(&config)
            .ok_or(OfflineRecognitionError::NativeRecognizerUnavailable)?;
        Ok(Self {
            backend: Box::new(SherpaBackend(recognizer)),
            decoding,
        })
    }

    pub fn decoding(&self) -> ParakeetDecoding {
        self.decoding
    }

    /// Decodes one complete mono utterance and returns its final transcript.
    pub fn decode(
        &self,
        sample_rate: u32,
        samples: &[f32],
    ) -> Result<String, OfflineRecognitionError> {
        self.decode_with_hotwords(sample_rate, samples, &ParakeetHotwords::default())
    }

    /// Decodes one utterance biased toward `hotwords`. Greedy mode ignores them.
    pub fn decode_with_hotwords(
        &self,
        sample_rate: u32,
        samples: &[f32],
        hotwords: &ParakeetHotwords,
    ) -> Result<String, OfflineRecognitionError> {
        if sample_rate != SAMPLE_RATE {
            return Err(OfflineRecognitionError::InvalidSampleRate);
        }
        if samples.len() > i32::MAX as usize {
            return Err(OfflineRecognitionError::TooManySamples);
        }
        if samples.iter().any(|sample| !sample.is_finite()) {
            return Err(OfflineRecognitionError::NonFiniteSamples);
        }
        if samples.iter().any(|sample| !(-1.0..=1.0).contains(sample)) {
            return Err(OfflineRecognitionError::SamplesNotNormalized);
        }
        let hotwords = (self.decoding == ParakeetDecoding::Hotwords && !hotwords.is_empty())
            .then_some(hotwords.encoded.as_str());
        self.backend.decode(samples, hotwords)
    }
}

/// Derives a SentencePiece vocabulary of `piece score` lines from a token
/// table of `piece id` lines. Special `<...>` tokens are left out, and each
/// regular piece scores lower than the piece before it.
fn derive_bpe_vocab(tokens_txt: &str) -> Result<String, OfflineRecognitionError> {
    let mut vocab = String::new();
    let mut first_regular = None;
    for (index, line) in tokens_txt.lines().enumerate() {
        let mut fields = line.split_whitespace();
        let (Some(piece), Some(id), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err(OfflineRecognitionError::NativeRecognizerUnavailable);
        };
        if id.parse::<usize>() != Ok(index) {
            return Err(OfflineRecognitionError::NativeRecognizerUnavailable);
        }
        if piece.len() >= 2 && piece.starts_with('<') && piece.ends_with('>') {
            continue;
        }
        let first = *first_regular.get_or_insert(index);
        vocab.push_str(&format!("{piece} {}\n", -((index - first) as i64)));
    }
    if vocab.is_empty() {
        return Err(OfflineRecognitionError::NativeRecognizerUnavailable);
    }
    Ok(vocab)
}

/// Writes the derived vocabulary beside the verified token table through a
/// rename, so a reader never sees a partial file. Identical content stays in
/// place. It reports whether it wrote the file and the token table's size.
fn write_bpe_vocab(directory: &Path) -> Result<(bool, usize), OfflineRecognitionError> {
    static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

    let tokens = fs::read_to_string(directory.join("tokens.txt"))
        .map_err(|_| OfflineRecognitionError::NativeRecognizerUnavailable)?;
    let vocab = derive_bpe_vocab(&tokens)?;
    let token_count = tokens.lines().count();
    let target = directory.join(HOTWORDS_BPE_VOCAB);
    if fs::read(&target).is_ok_and(|existing| existing == vocab.as_bytes()) {
        return Ok((false, token_count));
    }
    let temporary = directory.join(format!(
        ".{HOTWORDS_BPE_VOCAB}.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
    ));
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(vocab.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&temporary, &target));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
        .map(|()| (true, token_count))
        .map_err(|_| OfflineRecognitionError::NativeRecognizerUnavailable)
}

fn parakeet_config(
    directory: &Path,
    decoding: ParakeetDecoding,
) -> Result<OfflineRecognizerConfig, OfflineRecognitionError> {
    let path = |filename: &str| {
        directory
            .join(filename)
            .to_str()
            .map(str::to_owned)
            .ok_or(OfflineRecognitionError::NativeRecognizerUnavailable)
    };
    let mut config = OfflineRecognizerConfig::default();
    config.model_config.transducer = OfflineTransducerModelConfig {
        encoder: Some(path("encoder.int8.onnx")?),
        decoder: Some(path("decoder.int8.onnx")?),
        joiner: Some(path("joiner.int8.onnx")?),
    };
    config.model_config.tokens = Some(path("tokens.txt")?);
    config.model_config.provider = Some("cpu".into());
    config.model_config.model_type = Some("nemo_transducer".into());
    config.model_config.num_threads = 2;
    match decoding {
        ParakeetDecoding::Greedy => config.decoding_method = Some("greedy_search".into()),
        ParakeetDecoding::Hotwords => {
            config.decoding_method = Some("modified_beam_search".into());
            config.max_active_paths = HOTWORDS_MAX_ACTIVE_PATHS;
            config.hotwords_file = None;
            config.hotwords_score = HOTWORDS_SCORE;
            config.model_config.modeling_unit = Some("bpe".into());
            config.model_config.bpe_vocab = Some(path(HOTWORDS_BPE_VOCAB)?);
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asr::{AsrArtifactDescriptor, AsrArtifactManifest};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct FakeBackend {
        calls: Arc<AtomicUsize>,
        fail: bool,
        hotwords: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    }

    impl FakeBackend {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self {
                calls,
                fail: false,
                hotwords: Arc::default(),
            }
        }
    }

    impl RecognizerBackend for FakeBackend {
        fn decode(
            &self,
            _samples: &[f32],
            hotwords: Option<&str>,
        ) -> Result<String, OfflineRecognitionError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.hotwords
                .lock()
                .unwrap()
                .push(hotwords.map(str::to_owned));
            if self.fail {
                Err(OfflineRecognitionError::NativeDecodeFailed)
            } else {
                Ok("fixture transcript".into())
            }
        }
    }

    #[test]
    fn greedy_configuration_carries_no_hotword_settings() {
        let config =
            parakeet_config(Path::new("verified-revision"), ParakeetDecoding::Greedy).unwrap();
        assert_eq!(config.decoding_method.as_deref(), Some("greedy_search"));
        assert_eq!(config.max_active_paths, 4);
        assert_eq!(config.hotwords_file, None);
        assert_eq!(config.hotwords_score, 0.0);
        assert_eq!(config.model_config.modeling_unit, None);
        assert_eq!(config.model_config.bpe_vocab, None);
        assert_eq!(config.model_config.num_threads, 2);
    }

    #[test]
    fn hotwords_configuration_runs_beam_search_over_the_derived_vocabulary() {
        let config =
            parakeet_config(Path::new("verified-revision"), ParakeetDecoding::Hotwords).unwrap();
        assert_eq!(
            config.decoding_method.as_deref(),
            Some("modified_beam_search")
        );
        assert_eq!(config.max_active_paths, 4);
        assert_eq!(config.hotwords_file, None);
        assert_eq!(config.hotwords_score, 1.5);
        assert_eq!(config.model_config.modeling_unit.as_deref(), Some("bpe"));
        assert_eq!(
            config.model_config.bpe_vocab.as_deref(),
            Some("verified-revision/hotwords-bpe.vocab")
        );
        assert_eq!(
            config.model_config.tokens.as_deref(),
            Some("verified-revision/tokens.txt")
        );
        assert_eq!(
            config.model_config.model_type.as_deref(),
            Some("nemo_transducer")
        );
    }

    #[test]
    fn derives_scored_regular_pieces_from_the_token_table() {
        assert_eq!(
            derive_bpe_vocab("<unk> 0\n<pad> 1\n0 2\n▁s 3\ner 4\n<blk> 5\n").unwrap(),
            "0 0\n▁s -1\ner -2\n"
        );
        assert_eq!(
            derive_bpe_vocab("▁fixture 0\n<blk> 1").unwrap(),
            "▁fixture 0\n"
        );
        assert_eq!(derive_bpe_vocab("< 0\n> 1\n").unwrap(), "< 0\n> -1\n");
    }

    #[test]
    fn refuses_a_malformed_token_table() {
        for tokens in [
            "",
            "<unk> 0\n<blk> 1\n",
            "▁a 0\n▁b 2\n",
            "▁a 1\n",
            "▁a\n",
            "▁a 0 extra\n",
            "▁a x\n",
            "▁a -1\n",
        ] {
            assert!(derive_bpe_vocab(tokens).is_err(), "{tokens:?}");
        }
    }

    #[test]
    fn hotwords_are_trimmed_squeezed_and_deduplicated() {
        let hotwords =
            ParakeetHotwords::new(&["  Muniment ", "New \t York", "", "   ", "Muniment"]);
        assert_eq!(hotwords.encoded, "Muniment\nNew York");
        assert_eq!(hotwords.len(), 2);
        assert!(!hotwords.is_empty());
        assert!(ParakeetHotwords::new::<&str>(&[]).is_empty());
        assert!(ParakeetHotwords::default().is_empty());
    }

    #[test]
    fn hotwords_drop_entries_the_native_parser_misreads() {
        let hotwords = ParakeetHotwords::new(&[
            "nul\0byte",
            "bell\u{7}",
            "a/b",
            ":)",
            "score :1.5",
            "word :x",
            "keep:colon",
            "#tag",
            "line\nbreak",
        ]);
        assert_eq!(hotwords.encoded, "keep:colon\n#tag\nline break");
    }

    #[test]
    fn hotwords_cap_entry_length_and_count() {
        let longest = "a".repeat(ParakeetHotwords::MAX_ENTRY_CHARS);
        let too_long = "b".repeat(ParakeetHotwords::MAX_ENTRY_CHARS + 1);
        let hotwords = ParakeetHotwords::new(&[longest.as_str(), too_long.as_str()]);
        assert_eq!(hotwords.encoded, longest);

        let many: Vec<String> = (0..ParakeetHotwords::MAX_ENTRIES + 10)
            .map(|index| format!("word{index}"))
            .collect();
        let hotwords = ParakeetHotwords::new(&many);
        assert_eq!(hotwords.len(), ParakeetHotwords::MAX_ENTRIES);
        assert!(hotwords.encoded.ends_with("word255"));
    }

    #[test]
    fn only_hotwords_mode_passes_a_non_empty_vocabulary_to_the_backend() {
        let words = ParakeetHotwords::new(&["Muniment", "Zylaxis"]);
        let mut recorded = Vec::new();
        for decoding in [ParakeetDecoding::Greedy, ParakeetDecoding::Hotwords] {
            let backend = FakeBackend::new(Arc::default());
            let hotwords = backend.hotwords.clone();
            let recognizer = OfflineParakeetRecognizer {
                backend: Box::new(backend),
                decoding,
            };
            assert_eq!(recognizer.decoding(), decoding);
            recognizer.decode(SAMPLE_RATE, &[0.0]).unwrap();
            recognizer
                .decode_with_hotwords(SAMPLE_RATE, &[0.0], &ParakeetHotwords::default())
                .unwrap();
            recognizer
                .decode_with_hotwords(SAMPLE_RATE, &[0.0], &words)
                .unwrap();
            recorded.push(hotwords.lock().unwrap().clone());
        }
        assert_eq!(recorded[0], vec![None, None, None]);
        assert_eq!(
            recorded[1],
            vec![None, None, Some("Muniment\nZylaxis".to_owned())]
        );
    }

    #[test]
    fn maps_only_the_four_pinned_parakeet_paths_and_cpu_configuration() {
        let config =
            parakeet_config(Path::new("verified-revision"), ParakeetDecoding::Greedy).unwrap();
        assert_eq!(
            config.model_config.transducer.encoder.as_deref(),
            Some("verified-revision/encoder.int8.onnx")
        );
        assert_eq!(
            config.model_config.transducer.decoder.as_deref(),
            Some("verified-revision/decoder.int8.onnx")
        );
        assert_eq!(
            config.model_config.transducer.joiner.as_deref(),
            Some("verified-revision/joiner.int8.onnx")
        );
        assert_eq!(
            config.model_config.tokens.as_deref(),
            Some("verified-revision/tokens.txt")
        );
        assert_eq!(config.model_config.provider.as_deref(), Some("cpu"));
        assert_eq!(
            config.model_config.model_type.as_deref(),
            Some("nemo_transducer")
        );
    }

    #[test]
    fn invalid_audio_is_rejected_before_native_code() {
        let calls = Arc::new(AtomicUsize::new(0));
        let words = ParakeetHotwords::new(&["Muniment"]);
        let recognizer = OfflineParakeetRecognizer {
            backend: Box::new(FakeBackend::new(calls.clone())),
            decoding: ParakeetDecoding::Hotwords,
        };
        assert_eq!(
            recognizer.decode(44_100, &[0.0]),
            Err(OfflineRecognitionError::InvalidSampleRate)
        );
        assert_eq!(
            recognizer.decode(SAMPLE_RATE, &[f32::NAN]),
            Err(OfflineRecognitionError::NonFiniteSamples)
        );
        assert_eq!(
            recognizer.decode(SAMPLE_RATE, &[1.01]),
            Err(OfflineRecognitionError::SamplesNotNormalized)
        );
        assert_eq!(
            recognizer.decode_with_hotwords(44_100, &[0.0], &words),
            Err(OfflineRecognitionError::InvalidSampleRate)
        );
        assert_eq!(
            recognizer.decode_with_hotwords(SAMPLE_RATE, &[f32::NAN], &words),
            Err(OfflineRecognitionError::NonFiniteSamples)
        );
        assert_eq!(
            recognizer.decode_with_hotwords(SAMPLE_RATE, &[1.01], &words),
            Err(OfflineRecognitionError::SamplesNotNormalized)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn native_failure_is_typed_and_backend_resources_are_released() {
        let releases = Arc::new(AtomicUsize::new(0));
        let backend = native_fixture_backend();
        assert_eq!(
            backend.decode_inner(&[0.0; 160], None, true, Some(releases.clone())),
            Err(OfflineRecognitionError::NativeDecodeFailed)
        );
        assert_eq!(releases.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn native_fixture_decodes_with_hotwords_and_writes_the_vocabulary_once() {
        let directory = std::env::temp_dir().join(format!(
            "muniment-recognizer-hotwords-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/asr-native");
        for entry in std::fs::read_dir(&fixture).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), directory.join(entry.file_name())).unwrap();
        }

        // The fixture vocabulary holds two tokens, so the beam narrows to two.
        let recognizer =
            OfflineParakeetRecognizer::from_directory(&directory, ParakeetDecoding::Hotwords)
                .unwrap();
        assert_eq!(recognizer.decoding(), ParakeetDecoding::Hotwords);
        let vocab = directory.join(HOTWORDS_BPE_VOCAB);
        assert_eq!(std::fs::read_to_string(&vocab).unwrap(), "▁fixture 0\n");
        assert!(recognizer
            .decode(SAMPLE_RATE, &[0.0; 16_000])
            .unwrap()
            .contains("fixture"));
        let words = ParakeetHotwords::new(&["fixture", "zebra", ":)", "a/b"]);
        assert_eq!(words.len(), 2);
        assert!(recognizer
            .decode_with_hotwords(SAMPLE_RATE, &[0.0; 16_000], &words)
            .unwrap()
            .contains("fixture"));

        assert_eq!(write_bpe_vocab(&directory).unwrap(), (false, 2));
        OfflineParakeetRecognizer::from_directory(&directory, ParakeetDecoding::Hotwords).unwrap();
        assert_eq!(write_bpe_vocab(&directory).unwrap(), (false, 2));
        std::fs::write(&vocab, "corrupt").unwrap();
        assert_eq!(write_bpe_vocab(&directory).unwrap(), (true, 2));
        assert_eq!(std::fs::read_to_string(&vocab).unwrap(), "▁fixture 0\n");
        assert!(std::fs::read_dir(&directory).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));

        let greedy =
            OfflineParakeetRecognizer::from_directory(&directory, ParakeetDecoding::Greedy)
                .unwrap();
        assert!(greedy
            .decode_with_hotwords(SAMPLE_RATE, &[0.0; 16_000], &words)
            .unwrap()
            .contains("fixture"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn native_fixture_returns_one_final_transcript() {
        let recognizer = OfflineParakeetRecognizer {
            backend: Box::new(native_fixture_backend()),
            decoding: ParakeetDecoding::Greedy,
        };
        let transcript = recognizer.decode(SAMPLE_RATE, &[0.0; 16_000]).unwrap();
        assert!(transcript.contains("fixture"));
    }

    fn native_fixture_backend() -> SherpaBackend {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/asr-native");
        let config = parakeet_config(&fixture, ParakeetDecoding::Greedy).unwrap();
        SherpaBackend(OfflineRecognizer::create(&config).expect("create fixture recognizer"))
    }

    #[test]
    fn construction_refuses_an_unverified_current_revision() {
        static FILES: [AsrArtifactDescriptor; 4] = [
            AsrArtifactDescriptor {
                filename: "encoder.int8.onnx",
                byte_size: 1,
                sha256: "00",
            },
            AsrArtifactDescriptor {
                filename: "decoder.int8.onnx",
                byte_size: 1,
                sha256: "00",
            },
            AsrArtifactDescriptor {
                filename: "joiner.int8.onnx",
                byte_size: 1,
                sha256: "00",
            },
            AsrArtifactDescriptor {
                filename: "tokens.txt",
                byte_size: 1,
                sha256: "00",
            },
        ];
        static MANIFEST: AsrArtifactManifest = AsrArtifactManifest {
            identity: "fixture",
            revision: "bad",
            artifacts: &FILES,
            additional_artifact: None,
        };
        static MANIFESTS: [&AsrArtifactManifest; 1] = [&MANIFEST];
        let root = std::env::temp_dir().join(format!(
            "muniment-recognizer-refusal-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("revisions/bad")).unwrap();
        std::fs::write(
            root.join("current"),
            "muniment-asr-pointer-v1\nfixture\nbad\n",
        )
        .unwrap();
        let lifecycle = AsrRevisionLifecycle::new(root.clone(), &MANIFESTS, &MANIFEST).unwrap();

        assert!(matches!(
            OfflineParakeetRecognizer::from_verified_current(&lifecycle),
            Err(OfflineRecognitionError::Verification(_))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}
