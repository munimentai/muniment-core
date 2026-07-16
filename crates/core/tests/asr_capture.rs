use muniment_core::asr::capture::bounded_pcm_channel;

#[test]
fn normalizes_downmixes_and_sanitizes_native_samples() {
    let (mut producer, consumer) = bounded_pcm_channel(2, 16_000, 8).unwrap();
    producer.push_i16(&[i16::MAX, i16::MIN, 16_384, 16_384]);
    let samples = consumer.drain();
    assert!((samples[0] + 1.0 / 65_536.0).abs() < 0.000_001);
    assert!((samples[1] - 0.5).abs() < 0.000_001);

    let (mut producer, consumer) = bounded_pcm_channel(1, 16_000, 4).unwrap();
    producer.push_f32(&[f32::NAN, 2.0, -2.0]);
    assert_eq!(consumer.drain(), vec![0.0, 1.0, -1.0]);
}

#[test]
fn resamples_to_documented_one_sample_duration_tolerance() {
    for source_rate in [8_000, 44_100, 48_000] {
        let (mut producer, consumer) = bounded_pcm_channel(1, source_rate, 20_000).unwrap();
        producer.push_f32(&vec![0.25; source_rate as usize]);
        let output = consumer.drain();
        assert!(output.len().abs_diff(16_000) <= 1);
        if source_rate <= 16_000 {
            assert!(output.iter().all(|sample| *sample == 0.25));
        } else {
            assert!(output[100..]
                .iter()
                .all(|sample| (*sample - 0.25).abs() < 0.000_01));
        }
    }
}

fn sine(rate: u32, frequency: f32, sample_count: usize) -> Vec<f32> {
    (0..sample_count)
        .map(|index| (2.0 * std::f32::consts::PI * frequency * index as f32 / rate as f32).sin())
        .collect()
}

fn rms(samples: &[f32]) -> f32 {
    (samples.iter().map(|sample| sample * sample).sum::<f32>() / samples.len() as f32).sqrt()
}

#[test]
fn downsampling_preserves_speech_and_rejects_above_nyquist_content_across_chunks() {
    let source_rate = 48_000;
    let speech = sine(source_rate, 1_000.0, source_rate as usize);
    let aliasing = sine(source_rate, 12_000.0, source_rate as usize);

    let convert_in_chunks = |input: &[f32]| {
        let (mut producer, consumer) = bounded_pcm_channel(1, source_rate, 20_000).unwrap();
        for chunk in input.chunks(137) {
            producer.push_f32(chunk);
        }
        consumer.drain()
    };
    let speech_output = convert_in_chunks(&speech);
    let rejected_output = convert_in_chunks(&aliasing);

    assert!(speech_output.len().abs_diff(16_000) <= 1);
    assert!(rejected_output.len().abs_diff(16_000) <= 1);
    // Ignore the short causal-filter startup transient when comparing content.
    assert!(rms(&speech_output[100..]) > 0.65);
    assert!(rms(&rejected_output[100..]) < 0.02);
}

#[test]
fn downsampling_transients_remain_finite_and_normalized() {
    let source_rate = 48_000;
    let (mut producer, consumer) = bounded_pcm_channel(1, source_rate, 20_000).unwrap();
    let input: Vec<f32> = (0..source_rate)
        .map(|index| if (index / 31) % 2 == 0 { 1.0 } else { -1.0 })
        .collect();

    for chunk in input.chunks(113) {
        producer.push_f32(chunk);
    }

    let output = consumer.drain();
    assert!(output.len().abs_diff(16_000) <= 1);
    assert!(output
        .iter()
        .all(|sample| sample.is_finite() && (-1.0..=1.0).contains(sample)));
}

#[test]
fn preserves_frames_and_resampler_state_across_callback_chunks() {
    let (mut producer, consumer) = bounded_pcm_channel(2, 16_000, 8).unwrap();
    producer.push_f32(&[0.2]);
    producer.push_f32(&[0.4, 0.6, 0.8]);
    assert_eq!(consumer.drain(), vec![0.3, 0.70000005]);
}

#[test]
fn overflow_is_bounded_and_counted_without_reordering_queued_audio() {
    let (mut producer, consumer) = bounded_pcm_channel(1, 16_000, 2).unwrap();
    producer.push_u16(&[32_768, 49_152, 65_535]);
    assert_eq!(consumer.drain(), vec![0.0, 0.5]);
    assert_eq!(consumer.dropped_samples(), 1);
}
