use muniment_core::asr::utterance::{
    UtteranceConfig, UtteranceConfigError, UtteranceSegmenter, VoiceActivity,
};

fn config() -> UtteranceConfig {
    UtteranceConfig {
        pre_roll_samples: 2,
        min_speech_samples: 3,
        trailing_silence_samples: 2,
        max_utterance_samples: 8,
        max_buffered_samples: 8,
    }
}

fn values(utterances: Vec<muniment_core::asr::utterance::Utterance>) -> Vec<Vec<f32>> {
    utterances.into_iter().map(|value| value.samples).collect()
}

#[test]
fn validates_every_bound_and_overflow_prone_relationship() {
    for field in 0..5 {
        let mut value = config();
        match field {
            0 => value.pre_roll_samples = 0,
            1 => value.min_speech_samples = 0,
            2 => value.trailing_silence_samples = 0,
            3 => value.max_utterance_samples = 0,
            _ => value.max_buffered_samples = 0,
        }
        assert_eq!(
            UtteranceSegmenter::new(value).err(),
            Some(UtteranceConfigError::ZeroLimit)
        );
    }
    let mut value = config();
    value.min_speech_samples = 9;
    assert_eq!(
        UtteranceSegmenter::new(value).err(),
        Some(UtteranceConfigError::MinimumSpeechExceedsMaximum)
    );
    let mut value = config();
    value.trailing_silence_samples = 4;
    assert_eq!(
        UtteranceSegmenter::new(value).err(),
        Some(UtteranceConfigError::BoundaryDurationsExceedMaximum)
    );
    let mut value = config();
    value.pre_roll_samples = usize::MAX;
    assert_eq!(
        UtteranceSegmenter::new(value).err(),
        Some(UtteranceConfigError::SampleCountOverflow)
    );
    let mut value = config();
    value.max_buffered_samples = 7;
    assert_eq!(
        UtteranceSegmenter::new(value).err(),
        Some(UtteranceConfigError::BufferTooSmall)
    );
}

#[test]
fn rejects_buffer_capacities_that_cannot_be_allocated() {
    let value = UtteranceConfig {
        pre_roll_samples: 1,
        min_speech_samples: 1,
        trailing_silence_samples: 1,
        max_utterance_samples: usize::MAX,
        max_buffered_samples: usize::MAX,
    };

    assert_eq!(
        UtteranceSegmenter::new(value).err(),
        Some(UtteranceConfigError::BufferCapacityUnavailable)
    );
}

#[test]
fn retains_bounded_pre_roll_and_closes_on_silence() {
    let mut segmenter = UtteranceSegmenter::new(config()).unwrap();
    segmenter
        .push_frame(&[0.1, 0.2, 0.3], VoiceActivity::NonSpeech)
        .unwrap();
    assert!(segmenter
        .push_frame(&[0.4, 0.5, 0.6], VoiceActivity::Speech)
        .unwrap()
        .is_empty());
    assert_eq!(
        values(
            segmenter
                .push_frame(&[0.7, 0.8], VoiceActivity::NonSpeech)
                .unwrap()
        ),
        vec![vec![0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]]
    );
}

#[test]
fn rejects_short_noise_and_flushes_only_qualified_speech() {
    let mut segmenter = UtteranceSegmenter::new(config()).unwrap();
    segmenter
        .push_frame(&[0.1, 0.2], VoiceActivity::Speech)
        .unwrap();
    assert!(segmenter
        .push_frame(&[0.3, 0.4], VoiceActivity::NonSpeech)
        .unwrap()
        .is_empty());
    assert!(segmenter.flush().is_none());
    segmenter
        .push_frame(&[0.5, 0.6, 0.7], VoiceActivity::Speech)
        .unwrap();
    assert_eq!(segmenter.flush().unwrap().samples, vec![0.5, 0.6, 0.7]);
}

#[test]
fn rejected_speech_is_not_reused_when_pre_roll_exceeds_trailing_silence() {
    let mut segmenter = UtteranceSegmenter::new(UtteranceConfig {
        pre_roll_samples: 4,
        min_speech_samples: 3,
        trailing_silence_samples: 2,
        max_utterance_samples: 9,
        max_buffered_samples: 9,
    })
    .unwrap();
    segmenter
        .push_frame(&[0.1, 0.2], VoiceActivity::Speech)
        .unwrap();
    assert!(segmenter
        .push_frame(&[0.3, 0.4], VoiceActivity::NonSpeech)
        .unwrap()
        .is_empty());
    segmenter
        .push_frame(&[0.5, 0.6, 0.7], VoiceActivity::Speech)
        .unwrap();

    assert_eq!(
        segmenter.flush().unwrap().samples,
        vec![0.3, 0.4, 0.5, 0.6, 0.7]
    );
}

#[test]
fn maximum_splits_continuous_speech_without_loss_or_duplication() {
    let mut segmenter = UtteranceSegmenter::new(config()).unwrap();
    let input: Vec<_> = (1..=19).map(|n| n as f32 / 20.0).collect();
    let mut output = values(segmenter.push_frame(&input, VoiceActivity::Speech).unwrap());
    output.push(segmenter.flush().unwrap().samples);
    assert_eq!(
        output.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![8, 8, 3]
    );
    assert_eq!(output.concat(), input);
}

#[test]
fn flush_emits_a_short_continuous_speech_remainder_after_maximum_split() {
    let mut segmenter = UtteranceSegmenter::new(config()).unwrap();
    let input: Vec<_> = (1..=9).map(|n| n as f32 / 10.0).collect();
    let mut output = values(segmenter.push_frame(&input, VoiceActivity::Speech).unwrap());
    output.push(segmenter.flush().unwrap().samples);

    assert_eq!(output.iter().map(Vec::len).collect::<Vec<_>>(), vec![8, 1]);
    assert_eq!(output.concat(), input);
}

#[test]
fn trailing_silence_emits_a_short_continuous_speech_remainder_after_maximum_split() {
    let mut segmenter = UtteranceSegmenter::new(config()).unwrap();
    let speech: Vec<_> = (1..=9).map(|n| n as f32 / 10.0).collect();
    let mut output = values(
        segmenter
            .push_frame(&speech, VoiceActivity::Speech)
            .unwrap(),
    );
    output.extend(values(
        segmenter
            .push_frame(&[-0.1, -0.2], VoiceActivity::NonSpeech)
            .unwrap(),
    ));

    assert_eq!(output.iter().map(Vec::len).collect::<Vec<_>>(), vec![8, 3]);
    assert_eq!(output.concat(), [speech, vec![-0.1, -0.2]].concat());
}

#[test]
fn trailing_silence_after_exact_maximum_split_does_not_emit_an_utterance() {
    let mut segmenter = UtteranceSegmenter::new(config()).unwrap();
    let speech: Vec<_> = (1..=8).map(|n| n as f32 / 10.0).collect();

    assert_eq!(
        values(
            segmenter
                .push_frame(&speech, VoiceActivity::Speech)
                .unwrap()
        ),
        vec![speech]
    );
    assert!(segmenter
        .push_frame(&[-0.1, -0.2], VoiceActivity::NonSpeech)
        .unwrap()
        .is_empty());
    assert!(segmenter.flush().is_none());
}

#[test]
fn decisions_are_invariant_to_pcm_chunk_boundaries() {
    fn run(chunks: &[&[f32]]) -> Vec<Vec<f32>> {
        let mut segmenter = UtteranceSegmenter::new(config()).unwrap();
        let mut output = Vec::new();
        for chunk in chunks {
            output.extend(values(
                segmenter.push_frame(chunk, VoiceActivity::Speech).unwrap(),
            ));
        }
        if let Some(last) = segmenter.flush() {
            output.push(last.samples);
        }
        output
    }
    let samples = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6];
    assert_eq!(
        run(&[&samples]),
        run(&[&samples[..1], &samples[1..4], &samples[4..]])
    );
}

#[test]
fn discontinuity_drops_both_pre_roll_and_partial_speech() {
    let mut segmenter = UtteranceSegmenter::new(config()).unwrap();
    segmenter
        .push_frame(&[0.1], VoiceActivity::NonSpeech)
        .unwrap();
    segmenter
        .push_frame(&[0.2, 0.3], VoiceActivity::Speech)
        .unwrap();
    segmenter.discontinuity();
    segmenter
        .push_frame(&[0.4, 0.5, 0.6], VoiceActivity::Speech)
        .unwrap();
    assert_eq!(segmenter.flush().unwrap().samples, vec![0.4, 0.5, 0.6]);
}

#[test]
fn retained_storage_never_exceeds_the_configured_bound() {
    let mut segmenter = UtteranceSegmenter::new(config()).unwrap();
    for index in 0..100 {
        let activity = if index % 7 < 4 {
            VoiceActivity::Speech
        } else {
            VoiceActivity::NonSpeech
        };
        segmenter.push_frame(&[0.1], activity).unwrap();
        assert!(segmenter.buffered_samples() <= segmenter.max_buffered_samples());
    }
}
