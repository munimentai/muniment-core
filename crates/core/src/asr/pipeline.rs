//! Fixed-memory composition of PCM reframing, voice activity, and utterances.

use super::{
    utterance::{
        validate_samples, Utterance, UtteranceConfig, UtteranceConfigError, UtteranceInputError,
        UtteranceSegmenter,
    },
    VadDecisionSource, VadError, VAD_FRAME_SIZE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DictationPipelineError {
    Vad(VadError),
    InvalidPcm(UtteranceInputError),
}

impl std::fmt::Display for DictationPipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vad(error) => error.fmt(f),
            Self::InvalidPcm(_) => f.write_str("dictation input contains an invalid PCM sample"),
        }
    }
}

impl std::error::Error for DictationPipelineError {}

impl From<VadError> for DictationPipelineError {
    fn from(value: VadError) -> Self {
        Self::Vad(value)
    }
}

impl From<UtteranceInputError> for DictationPipelineError {
    fn from(value: UtteranceInputError) -> Self {
        Self::InvalidPcm(value)
    }
}

/// A failed push together with every utterance completed before the failure.
#[derive(Debug, Clone, PartialEq)]
pub struct DictationPipelinePushError {
    pub error: DictationPipelineError,
    pub emitted: Vec<Utterance>,
}

impl std::fmt::Display for DictationPipelinePushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for DictationPipelinePushError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Pure-core streaming pipeline for normalized mono 16 kHz PCM.
pub struct DictationPipeline<D> {
    decider: D,
    segmenter: UtteranceSegmenter,
    partial_frame: Vec<f32>,
}

impl<D: VadDecisionSource> DictationPipeline<D> {
    pub fn new(decider: D, config: UtteranceConfig) -> Result<Self, UtteranceConfigError> {
        Ok(Self {
            decider,
            segmenter: UtteranceSegmenter::new(config)?,
            partial_frame: Vec::with_capacity(VAD_FRAME_SIZE),
        })
    }

    /// Consumes arbitrary-length sequential PCM and returns completed utterances.
    /// On failure, the error carries any utterances completed by earlier frames in this push.
    pub fn push(
        &mut self,
        mut samples: &[f32],
    ) -> Result<Vec<Utterance>, DictationPipelinePushError> {
        // Validate the complete caller-owned push before advancing any streaming state.
        validate_samples(samples).map_err(|error| DictationPipelinePushError {
            error: error.into(),
            emitted: Vec::new(),
        })?;

        let mut emitted = Vec::new();
        while !samples.is_empty() {
            let take = (VAD_FRAME_SIZE - self.partial_frame.len()).min(samples.len());
            self.partial_frame.extend_from_slice(&samples[..take]);
            samples = &samples[take..];

            if self.partial_frame.len() == VAD_FRAME_SIZE {
                let result = self
                    .decider
                    .detect(&self.partial_frame)
                    .map_err(DictationPipelineError::from)
                    .and_then(|activity| {
                        self.segmenter
                            .push_frame(&self.partial_frame, activity)
                            .map_err(DictationPipelineError::from)
                    });
                self.partial_frame.clear();
                match result {
                    Ok(utterances) => emitted.extend(utterances),
                    Err(error) => return Err(DictationPipelinePushError { error, emitted }),
                }
            }
        }
        Ok(emitted)
    }

    /// Ends hold-to-talk input. Any final partial (less than 512-sample) frame is discarded.
    pub fn flush(&mut self) -> Option<Utterance> {
        self.partial_frame.clear();
        self.segmenter.flush()
    }

    /// Drops partial audio and resets decision and segmentation history after capture loss.
    pub fn discontinuity(&mut self) {
        self.partial_frame.clear();
        self.decider.discontinuity();
        self.segmenter.discontinuity();
    }

    /// Total samples currently retained by the reframer and segmenter.
    pub fn buffered_samples(&self) -> usize {
        self.partial_frame.len() + self.segmenter.buffered_samples()
    }

    /// Maximum retained samples: the segmenter bound plus one incomplete VAD frame.
    pub fn max_buffered_samples(&self) -> usize {
        self.segmenter
            .max_buffered_samples()
            .saturating_add(VAD_FRAME_SIZE - 1)
    }
}
