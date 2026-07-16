//! Verified, frame-at-a-time boundary around sherpa-onnx Silero VAD.

use std::path::Path;

use sherpa_onnx::{SileroVadModelConfig, VadModelConfig, VoiceActivityDetector};

use super::{
    utterance::VoiceActivity, verify_artifact, AsrArtifactDescriptor, AsrModelSetVerificationError,
    PARAKEET_MODEL_MANIFEST,
};

pub const VAD_SAMPLE_RATE: u32 = 16_000;
pub const VAD_FRAME_SIZE: usize = 512;
const VAD_BUFFER_SECONDS: f32 = 30.0;

pub const SILERO_VAD_ARTIFACT: AsrArtifactDescriptor = PARAKEET_MODEL_MANIFEST
    .additional_artifact
    .unwrap()
    .artifact;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VadError {
    Verification(AsrModelSetVerificationError),
    InvalidSampleRate,
    InvalidFrameSize,
    NonFiniteSamples,
    SamplesNotNormalized,
    NativeDetectorUnavailable,
}

impl std::fmt::Debug for VadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verification(error) => f.debug_tuple("Verification").field(error).finish(),
            Self::InvalidSampleRate => f.write_str("InvalidSampleRate"),
            Self::InvalidFrameSize => f.write_str("InvalidFrameSize"),
            Self::NonFiniteSamples => f.write_str("NonFiniteSamples"),
            Self::SamplesNotNormalized => f.write_str("SamplesNotNormalized"),
            Self::NativeDetectorUnavailable => f.write_str("NativeDetectorUnavailable"),
        }
    }
}

impl std::fmt::Display for VadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Verification(_) => "the voice activity model failed verification",
            Self::InvalidSampleRate => "voice activity input must be 16 kHz mono audio",
            Self::InvalidFrameSize => "voice activity input has an invalid frame size",
            Self::NonFiniteSamples => "voice activity input contains an invalid sample",
            Self::SamplesNotNormalized => "voice activity input samples must be normalized",
            Self::NativeDetectorUnavailable => "the voice activity detector could not be created",
        })
    }
}

impl std::error::Error for VadError {}

/// Narrow decision seam used by the pure-core dictation pipeline.
pub trait VadDecisionSource {
    fn detect(&mut self, samples: &[f32]) -> Result<VoiceActivity, VadError>;
    fn discontinuity(&mut self);
}

trait VadBackend: Send {
    fn detect(&mut self, samples: &[f32]) -> VoiceActivity;
    fn reset(&mut self);
}

struct SherpaVadBackend(VoiceActivityDetector);

impl VadBackend for SherpaVadBackend {
    fn detect(&mut self, samples: &[f32]) -> VoiceActivity {
        self.0.accept_waveform(samples);
        if self.0.detected() {
            VoiceActivity::Speech
        } else {
            VoiceActivity::NonSpeech
        }
    }

    fn reset(&mut self) {
        self.0.reset();
        self.0.clear();
    }
}

trait VadBackendFactory {
    fn create(&self, config: &VadModelConfig) -> Option<Box<dyn VadBackend>>;
}

struct SherpaVadFactory;

impl VadBackendFactory for SherpaVadFactory {
    fn create(&self, config: &VadModelConfig) -> Option<Box<dyn VadBackend>> {
        VoiceActivityDetector::create(config, VAD_BUFFER_SECONDS)
            .map(|detector| Box::new(SherpaVadBackend(detector)) as Box<dyn VadBackend>)
    }
}

/// A detector owning one native VAD handle constructed only after artifact verification.
pub struct SileroVoiceActivityDetector {
    backend: Box<dyn VadBackend>,
}

impl SileroVoiceActivityDetector {
    /// Verifies the explicitly supplied installed model file before native construction.
    pub fn from_installed_path(path: impl AsRef<Path>) -> Result<Self, VadError> {
        Self::from_path_with(path.as_ref(), &SILERO_VAD_ARTIFACT, &SherpaVadFactory)
    }

    fn from_path_with(
        path: &Path,
        descriptor: &AsrArtifactDescriptor,
        factory: &dyn VadBackendFactory,
    ) -> Result<Self, VadError> {
        verify_artifact(path, descriptor).map_err(VadError::Verification)?;
        let config = silero_config(path)?;
        let backend = factory
            .create(&config)
            .ok_or(VadError::NativeDetectorUnavailable)?;
        Ok(Self { backend })
    }

    pub fn detect(&mut self, sample_rate: u32, samples: &[f32]) -> Result<VoiceActivity, VadError> {
        if sample_rate != VAD_SAMPLE_RATE {
            return Err(VadError::InvalidSampleRate);
        }
        if samples.len() != VAD_FRAME_SIZE {
            return Err(VadError::InvalidFrameSize);
        }
        if samples.iter().any(|sample| !sample.is_finite()) {
            return Err(VadError::NonFiniteSamples);
        }
        if samples.iter().any(|sample| !(-1.0..=1.0).contains(sample)) {
            return Err(VadError::SamplesNotNormalized);
        }
        Ok(self.backend.detect(samples))
    }

    /// Clears model history after a capture discontinuity or a new session.
    pub fn reset(&mut self) {
        self.backend.reset();
    }

    pub fn discontinuity(&mut self) {
        self.reset();
    }
}

impl VadDecisionSource for SileroVoiceActivityDetector {
    fn detect(&mut self, samples: &[f32]) -> Result<VoiceActivity, VadError> {
        SileroVoiceActivityDetector::detect(self, VAD_SAMPLE_RATE, samples)
    }

    fn discontinuity(&mut self) {
        SileroVoiceActivityDetector::discontinuity(self);
    }
}

fn silero_config(path: &Path) -> Result<VadModelConfig, VadError> {
    let model = path
        .to_str()
        .map(str::to_owned)
        .ok_or(VadError::NativeDetectorUnavailable)?;
    Ok(VadModelConfig {
        silero_vad: SileroVadModelConfig {
            model: Some(model),
            threshold: 0.5,
            min_silence_duration: 0.5,
            min_speech_duration: 0.25,
            window_size: VAD_FRAME_SIZE as i32,
            max_speech_duration: 20.0,
        },
        sample_rate: VAD_SAMPLE_RATE as i32,
        num_threads: 1,
        provider: Some("cpu".into()),
        debug: false,
        ..VadModelConfig::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    const FIXTURE: AsrArtifactDescriptor = AsrArtifactDescriptor {
        filename: "ignored",
        byte_size: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    };

    #[derive(Default)]
    struct State {
        creates: usize,
        detects: usize,
        resets: usize,
        drops: usize,
        speech: bool,
    }

    struct FakeBackend(Arc<Mutex<State>>);
    impl VadBackend for FakeBackend {
        fn detect(&mut self, _: &[f32]) -> VoiceActivity {
            let mut state = self.0.lock().unwrap();
            state.detects += 1;
            if state.speech {
                VoiceActivity::Speech
            } else {
                VoiceActivity::NonSpeech
            }
        }
        fn reset(&mut self) {
            self.0.lock().unwrap().resets += 1;
        }
    }
    impl Drop for FakeBackend {
        fn drop(&mut self) {
            self.0.lock().unwrap().drops += 1;
        }
    }

    struct FakeFactory {
        state: Arc<Mutex<State>>,
        fail: bool,
    }
    impl VadBackendFactory for FakeFactory {
        fn create(&self, config: &VadModelConfig) -> Option<Box<dyn VadBackend>> {
            let silero = &config.silero_vad;
            assert_eq!(config.sample_rate, 16_000);
            assert_eq!(config.num_threads, 1);
            assert_eq!(config.provider.as_deref(), Some("cpu"));
            assert!(silero.model.as_deref().is_some_and(|path| {
                path.contains("muniment-vad-valid") || path.contains("muniment-vad-create-fail")
            }));
            assert_eq!(silero.window_size, 512);
            assert_eq!(silero.threshold, 0.5);
            assert_eq!(silero.min_speech_duration, 0.25);
            assert_eq!(silero.min_silence_duration, 0.5);
            assert_eq!(silero.max_speech_duration, 20.0);
            self.state.lock().unwrap().creates += 1;
            (!self.fail).then(|| Box::new(FakeBackend(self.state.clone())) as Box<dyn VadBackend>)
        }
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("muniment-vad-{name}-{}", std::process::id()))
    }

    #[test]
    fn verifies_and_maps_config_before_creation() {
        let path = fixture_path("valid");
        std::fs::write(&path, b"abc").unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let detector = SileroVoiceActivityDetector::from_path_with(
            &path,
            &FIXTURE,
            &FakeFactory {
                state: state.clone(),
                fail: false,
            },
        )
        .unwrap();
        assert_eq!(state.lock().unwrap().creates, 1);
        drop(detector);
        assert_eq!(state.lock().unwrap().drops, 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_bad_artifacts_without_calling_native_factory() {
        let path = fixture_path("bad");
        std::fs::write(&path, b"abd").unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        assert!(matches!(
            SileroVoiceActivityDetector::from_path_with(
                &path,
                &FIXTURE,
                &FakeFactory {
                    state: state.clone(),
                    fail: false
                }
            ),
            Err(VadError::Verification(
                AsrModelSetVerificationError::DigestMismatch
            ))
        ));
        assert_eq!(state.lock().unwrap().creates, 0);
        std::fs::remove_file(path).unwrap();

        let missing = fixture_path("missing");
        assert!(matches!(
            SileroVoiceActivityDetector::from_path_with(
                &missing,
                &FIXTURE,
                &FakeFactory {
                    state: state.clone(),
                    fail: false
                }
            ),
            Err(VadError::Verification(
                AsrModelSetVerificationError::Missing
            ))
        ));
        let directory = fixture_path("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(matches!(
            SileroVoiceActivityDetector::from_path_with(
                &directory,
                &FIXTURE,
                &FakeFactory {
                    state: state.clone(),
                    fail: false
                }
            ),
            Err(VadError::Verification(
                AsrModelSetVerificationError::NotRegularFile
            ))
        ));
        assert_eq!(state.lock().unwrap().creates, 0);
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn validates_frames_before_decision_and_propagates_decisions() {
        let state = Arc::new(Mutex::new(State {
            speech: true,
            ..State::default()
        }));
        let mut detector = SileroVoiceActivityDetector {
            backend: Box::new(FakeBackend(state.clone())),
        };
        assert_eq!(
            detector.detect(8_000, &[0.0; 512]),
            Err(VadError::InvalidSampleRate)
        );
        assert_eq!(
            detector.detect(16_000, &[0.0; 511]),
            Err(VadError::InvalidFrameSize)
        );
        let mut invalid = [0.0; 512];
        invalid[0] = f32::NAN;
        assert_eq!(
            detector.detect(16_000, &invalid),
            Err(VadError::NonFiniteSamples)
        );
        invalid[0] = 1.01;
        assert_eq!(
            detector.detect(16_000, &invalid),
            Err(VadError::SamplesNotNormalized)
        );
        assert_eq!(state.lock().unwrap().detects, 0);
        assert_eq!(
            detector.detect(16_000, &[0.0; 512]),
            Ok(VoiceActivity::Speech)
        );
        assert_eq!(state.lock().unwrap().detects, 1);
    }

    #[test]
    fn reset_discontinuity_creation_failure_and_cleanup_are_typed() {
        let path = fixture_path("create-fail");
        std::fs::write(&path, b"abc").unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        assert!(matches!(
            SileroVoiceActivityDetector::from_path_with(
                &path,
                &FIXTURE,
                &FakeFactory {
                    state: state.clone(),
                    fail: true
                }
            ),
            Err(VadError::NativeDetectorUnavailable)
        ));
        assert_eq!(state.lock().unwrap().drops, 0);
        let mut detector = SileroVoiceActivityDetector {
            backend: Box::new(FakeBackend(state.clone())),
        };
        detector.reset();
        detector.discontinuity();
        assert_eq!(state.lock().unwrap().resets, 2);
        drop(detector);
        assert_eq!(state.lock().unwrap().drops, 1);
        std::fs::remove_file(path).unwrap();
    }
}
