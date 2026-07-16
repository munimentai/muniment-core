//! Deterministic utterance boundaries for offline ASR decoding.
//!
//! Each emitted [`Utterance`] is one complete boundary for an offline decode.
//! Emissions are repeated offline recognizer inputs and must not be presented as
//! token streaming.

use std::collections::VecDeque;

use super::recognizer::SAMPLE_RATE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceActivity {
    Speech,
    NonSpeech,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtteranceConfig {
    pub pre_roll_samples: usize,
    pub min_speech_samples: usize,
    pub trailing_silence_samples: usize,
    pub max_utterance_samples: usize,
    pub max_buffered_samples: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtteranceConfigError {
    ZeroLimit,
    MinimumSpeechExceedsMaximum,
    BoundaryDurationsExceedMaximum,
    BufferTooSmall,
    SampleCountOverflow,
    BufferCapacityUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtteranceInputError {
    NonFiniteSample,
    SampleNotNormalized,
}

/// Owned mono 16 kHz PCM for exactly one offline recognition call.
#[derive(Debug, Clone, PartialEq)]
pub struct Utterance {
    pub samples: Vec<f32>,
}

/// Fixed-memory segmenter driven by voice-activity decisions supplied by its caller.
pub struct UtteranceSegmenter {
    config: UtteranceConfig,
    pre_roll: VecDeque<f32>,
    active: Vec<f32>,
    speech_samples: usize,
    trailing_samples: usize,
    continuation_qualified: bool,
}

impl UtteranceSegmenter {
    pub const SAMPLE_RATE: u32 = SAMPLE_RATE;

    pub fn new(config: UtteranceConfig) -> Result<Self, UtteranceConfigError> {
        if config.pre_roll_samples == 0
            || config.min_speech_samples == 0
            || config.trailing_silence_samples == 0
            || config.max_utterance_samples == 0
            || config.max_buffered_samples == 0
        {
            return Err(UtteranceConfigError::ZeroLimit);
        }
        if config.min_speech_samples > config.max_utterance_samples {
            return Err(UtteranceConfigError::MinimumSpeechExceedsMaximum);
        }
        let boundary_samples = config
            .pre_roll_samples
            .checked_add(config.min_speech_samples)
            .and_then(|samples| samples.checked_add(config.trailing_silence_samples))
            .ok_or(UtteranceConfigError::SampleCountOverflow)?;
        if boundary_samples > config.max_utterance_samples {
            return Err(UtteranceConfigError::BoundaryDurationsExceedMaximum);
        }
        if config.pre_roll_samples > config.max_buffered_samples
            || config.max_utterance_samples > config.max_buffered_samples
        {
            return Err(UtteranceConfigError::BufferTooSmall);
        }

        let mut pre_roll = VecDeque::new();
        pre_roll
            .try_reserve_exact(config.pre_roll_samples)
            .map_err(|_| UtteranceConfigError::BufferCapacityUnavailable)?;
        let mut active = Vec::new();
        active
            .try_reserve_exact(config.max_utterance_samples)
            .map_err(|_| UtteranceConfigError::BufferCapacityUnavailable)?;

        Ok(Self {
            config,
            pre_roll,
            active,
            speech_samples: 0,
            trailing_samples: 0,
            continuation_qualified: false,
        })
    }

    /// Consumes one sequential PCM frame with the detector decision for that frame.
    pub fn push_frame(
        &mut self,
        samples: &[f32],
        activity: VoiceActivity,
    ) -> Result<Vec<Utterance>, UtteranceInputError> {
        validate_samples(samples)?;
        let mut emitted = Vec::new();
        for &sample in samples {
            self.push_sample(sample, activity, &mut emitted);
        }
        Ok(emitted)
    }

    /// Finishes hold-to-talk input, emitting a qualifying partial utterance.
    pub fn flush(&mut self) -> Option<Utterance> {
        let utterance = (!self.active.is_empty()
            && self.speech_samples >= self.config.min_speech_samples)
            .then(|| Utterance {
                samples: std::mem::take(&mut self.active),
            });
        self.clear();
        utterance
    }

    /// Drops all partial audio after an input discontinuity such as queue overflow.
    pub fn discontinuity(&mut self) {
        self.clear();
    }

    /// Current retained sample count, exposed for fixed-memory contract checks.
    pub fn buffered_samples(&self) -> usize {
        self.pre_roll.len() + self.active.len()
    }

    pub fn max_buffered_samples(&self) -> usize {
        self.config.max_buffered_samples
    }

    fn push_sample(&mut self, sample: f32, activity: VoiceActivity, emitted: &mut Vec<Utterance>) {
        if self.active.is_empty() && self.speech_samples == 0 {
            if activity == VoiceActivity::NonSpeech {
                self.continuation_qualified = false;
                self.retain_pre_roll(sample);
                return;
            }
            self.active.extend(self.pre_roll.drain(..));
            if self.continuation_qualified {
                self.speech_samples = self.config.min_speech_samples - 1;
                self.continuation_qualified = false;
            }
        }

        self.active.push(sample);
        match activity {
            VoiceActivity::Speech => {
                self.speech_samples += 1;
                self.trailing_samples = 0;
            }
            VoiceActivity::NonSpeech => self.trailing_samples += 1,
        }

        if self.trailing_samples == self.config.trailing_silence_samples {
            self.finish_active(emitted, true);
        } else if self.active.len() == self.config.max_utterance_samples {
            self.finish_active(emitted, false);
        }
    }

    fn finish_active(&mut self, emitted: &mut Vec<Utterance>, preserve_discarded_tail: bool) {
        let qualified = self.speech_samples >= self.config.min_speech_samples;
        if qualified {
            emitted.push(Utterance {
                samples: std::mem::take(&mut self.active),
            });
        } else if preserve_discarded_tail {
            let keep = self.trailing_samples.min(self.config.pre_roll_samples);
            let keep_from = self.active.len().saturating_sub(keep);
            let tail: Vec<_> = self.active.drain(keep_from..).collect();
            self.pre_roll.extend(tail);
            self.active.clear();
        } else {
            self.active.clear();
        }
        if qualified && !preserve_discarded_tail {
            self.speech_samples = 0;
            self.continuation_qualified = true;
        } else {
            self.speech_samples = 0;
            self.trailing_samples = 0;
            self.continuation_qualified = false;
        }
    }

    fn retain_pre_roll(&mut self, sample: f32) {
        if self.pre_roll.len() == self.config.pre_roll_samples {
            self.pre_roll.pop_front();
        }
        self.pre_roll.push_back(sample);
    }

    fn clear(&mut self) {
        self.pre_roll.clear();
        self.active.clear();
        self.speech_samples = 0;
        self.trailing_samples = 0;
        self.continuation_qualified = false;
    }
}

pub(super) fn validate_samples(samples: &[f32]) -> Result<(), UtteranceInputError> {
    for sample in samples {
        if !sample.is_finite() {
            return Err(UtteranceInputError::NonFiniteSample);
        }
        if !(-1.0..=1.0).contains(sample) {
            return Err(UtteranceInputError::SampleNotNormalized);
        }
    }
    Ok(())
}
