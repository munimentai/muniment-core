use std::{cell::Cell, rc::Rc};

use muniment_core::asr::{
    utterance::{
        Utterance, UtteranceConfig, UtteranceConfigError, UtteranceInputError, VoiceActivity,
    },
    DictationPipeline, DictationPipelineError, DictationPipelinePushError, VadDecisionSource,
    VadError, VAD_FRAME_SIZE,
};

struct FakeDecider {
    decisions: usize,
    discontinuities: Rc<Cell<usize>>,
}

impl VadDecisionSource for FakeDecider {
    fn detect(&mut self, samples: &[f32]) -> Result<VoiceActivity, VadError> {
        assert_eq!(samples.len(), VAD_FRAME_SIZE);
        self.decisions += 1;
        Ok(if samples[0] > 0.25 {
            VoiceActivity::Speech
        } else {
            VoiceActivity::NonSpeech
        })
    }

    fn discontinuity(&mut self) {
        self.discontinuities.set(self.discontinuities.get() + 1);
    }
}

fn config() -> UtteranceConfig {
    UtteranceConfig {
        pre_roll_samples: VAD_FRAME_SIZE,
        min_speech_samples: VAD_FRAME_SIZE * 2,
        trailing_silence_samples: VAD_FRAME_SIZE,
        max_utterance_samples: VAD_FRAME_SIZE * 8,
        max_buffered_samples: VAD_FRAME_SIZE * 8,
    }
}

fn pipeline(counter: Rc<Cell<usize>>) -> DictationPipeline<FakeDecider> {
    DictationPipeline::new(
        FakeDecider {
            decisions: 0,
            discontinuities: counter,
        },
        config(),
    )
    .unwrap()
}

fn samples(utterances: Vec<Utterance>) -> Vec<Vec<f32>> {
    utterances
        .into_iter()
        .map(|utterance| utterance.samples)
        .collect()
}

fn run(stream: &[f32], chunk_size: usize) -> Vec<Vec<f32>> {
    let mut pipeline = pipeline(Rc::new(Cell::new(0)));
    let mut output = Vec::new();
    for chunk in stream.chunks(chunk_size) {
        output.extend(samples(pipeline.push(chunk).unwrap()));
        assert!(pipeline.buffered_samples() <= pipeline.max_buffered_samples());
    }
    if let Some(utterance) = pipeline.flush() {
        output.push(utterance.samples);
    }
    assert_eq!(pipeline.buffered_samples(), 0);
    output
}

#[test]
fn emitted_utterances_are_invariant_to_pcm_push_boundaries() {
    let mut stream = Vec::new();
    stream.extend(vec![0.1; VAD_FRAME_SIZE]);
    stream.extend(vec![0.5; VAD_FRAME_SIZE * 2]);
    stream.extend(vec![-0.1; VAD_FRAME_SIZE]);
    stream.extend(vec![0.8; VAD_FRAME_SIZE * 3]);
    stream.extend(vec![0.0; 137]);

    let expected = run(&stream, VAD_FRAME_SIZE);
    assert_eq!(expected.len(), 2);
    for chunk_size in [1, 160, 1_000] {
        assert_eq!(run(&stream, chunk_size), expected);
    }
}

#[test]
fn flush_discards_only_the_incomplete_frame_and_flushes_qualified_audio() {
    let mut pipeline = pipeline(Rc::new(Cell::new(0)));
    pipeline.push(&vec![0.5; VAD_FRAME_SIZE * 2 + 123]).unwrap();

    assert_eq!(
        pipeline.flush().unwrap().samples,
        vec![0.5; VAD_FRAME_SIZE * 2]
    );
    assert_eq!(pipeline.buffered_samples(), 0);
}

#[test]
fn discontinuity_resets_every_partial_state() {
    let resets = Rc::new(Cell::new(0));
    let mut pipeline = pipeline(resets.clone());
    pipeline.push(&vec![0.1; VAD_FRAME_SIZE]).unwrap();
    pipeline.push(&vec![0.5; VAD_FRAME_SIZE + 17]).unwrap();
    assert!(pipeline.buffered_samples() > 0);

    pipeline.discontinuity();

    assert_eq!(resets.get(), 1);
    assert_eq!(pipeline.buffered_samples(), 0);
    pipeline.push(&vec![0.5; VAD_FRAME_SIZE * 2]).unwrap();
    assert_eq!(
        pipeline.flush().unwrap().samples,
        vec![0.5; VAD_FRAME_SIZE * 2]
    );
}

#[test]
fn construction_reuses_segmenter_configuration_errors() {
    let mut invalid = config();
    invalid.max_buffered_samples = 0;
    assert!(matches!(
        DictationPipeline::new(
            FakeDecider {
                decisions: 0,
                discontinuities: Rc::new(Cell::new(0)),
            },
            invalid,
        ),
        Err(UtteranceConfigError::ZeroLimit)
    ));
}

#[test]
fn input_and_decision_failures_remain_typed_and_do_not_wedge_reframing() {
    let mut pipeline = pipeline(Rc::new(Cell::new(0)));
    let mut invalid = vec![0.0; VAD_FRAME_SIZE];
    invalid[0] = f32::NAN;
    assert_eq!(
        pipeline.push(&invalid),
        Err(DictationPipelinePushError {
            error: DictationPipelineError::InvalidPcm(UtteranceInputError::NonFiniteSample),
            emitted: Vec::new(),
        })
    );
    assert_eq!(pipeline.buffered_samples(), 0);

    struct FailingDecider;
    impl VadDecisionSource for FailingDecider {
        fn detect(&mut self, _: &[f32]) -> Result<VoiceActivity, VadError> {
            Err(VadError::NativeDetectorUnavailable)
        }
        fn discontinuity(&mut self) {}
    }
    let mut pipeline = DictationPipeline::new(FailingDecider, config()).unwrap();
    assert_eq!(
        pipeline.push(&vec![0.0; VAD_FRAME_SIZE]),
        Err(DictationPipelinePushError {
            error: DictationPipelineError::Vad(VadError::NativeDetectorUnavailable),
            emitted: Vec::new(),
        })
    );
    assert_eq!(pipeline.buffered_samples(), 0);
}

#[test]
fn invalid_pcm_is_rejected_before_an_earlier_frame_can_be_consumed() {
    let mut pipeline = pipeline(Rc::new(Cell::new(0)));
    let mut input = vec![0.5; VAD_FRAME_SIZE * 3];
    input.push(f32::NAN);

    let error = pipeline.push(&input).unwrap_err();
    assert_eq!(
        error,
        DictationPipelinePushError {
            error: DictationPipelineError::InvalidPcm(UtteranceInputError::NonFiniteSample),
            emitted: Vec::new(),
        }
    );
    assert_eq!(pipeline.buffered_samples(), 0);

    input.pop();
    assert!(pipeline.push(&input).unwrap().is_empty());
    assert_eq!(
        pipeline.flush().unwrap().samples,
        vec![0.5; VAD_FRAME_SIZE * 3]
    );
}

#[test]
fn utterances_emitted_before_a_later_decider_failure_are_returned_with_the_error() {
    struct LaterFailingDecider {
        calls: usize,
    }
    impl VadDecisionSource for LaterFailingDecider {
        fn detect(&mut self, samples: &[f32]) -> Result<VoiceActivity, VadError> {
            self.calls += 1;
            if self.calls == 4 {
                Err(VadError::NativeDetectorUnavailable)
            } else if samples[0] > 0.25 {
                Ok(VoiceActivity::Speech)
            } else {
                Ok(VoiceActivity::NonSpeech)
            }
        }
        fn discontinuity(&mut self) {}
    }

    let mut pipeline = DictationPipeline::new(LaterFailingDecider { calls: 0 }, config()).unwrap();
    let mut input = vec![0.5; VAD_FRAME_SIZE * 2];
    input.extend(vec![0.0; VAD_FRAME_SIZE * 2]);

    let error = pipeline.push(&input).unwrap_err();
    assert_eq!(
        error.error,
        DictationPipelineError::Vad(VadError::NativeDetectorUnavailable)
    );
    assert_eq!(
        samples(error.emitted),
        vec![input[..VAD_FRAME_SIZE * 3].to_vec()]
    );
    assert_eq!(pipeline.buffered_samples(), 0);
}
