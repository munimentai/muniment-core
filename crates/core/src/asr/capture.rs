//! Bounded conversion boundary between native input callbacks and ASR consumers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;

use super::recognizer::SAMPLE_RATE;

const LOW_PASS_TAPS: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureConfigError {
    ZeroChannels,
    ZeroSampleRate,
    ZeroCapacity,
}

/// The callback-owned half of a fixed-capacity PCM queue.
pub struct PcmProducer {
    sender: SyncSender<f32>,
    channels: usize,
    source_rate: u32,
    channel_sum: f64,
    channel_offset: usize,
    resample_accumulator: u32,
    low_pass: Option<LowPassFilter>,
    gap: Arc<GapState>,
}

/// Fixed-memory anti-alias filter used before reducing a device sample rate.
struct LowPassFilter {
    coefficients: [f64; LOW_PASS_TAPS],
    history: [f32; LOW_PASS_TAPS],
    cursor: usize,
}

impl LowPassFilter {
    fn new(source_rate: u32) -> Self {
        // Leave a small transition band below the 8 kHz output Nyquist limit.
        let cutoff = 0.45 * f64::from(SAMPLE_RATE) / f64::from(source_rate);
        let midpoint = (LOW_PASS_TAPS - 1) as f64 / 2.0;
        let mut coefficients = [0.0; LOW_PASS_TAPS];
        for (index, coefficient) in coefficients.iter_mut().enumerate() {
            let offset = index as f64 - midpoint;
            let sinc = if offset == 0.0 {
                2.0 * cutoff
            } else {
                (2.0 * std::f64::consts::PI * cutoff * offset).sin()
                    / (std::f64::consts::PI * offset)
            };
            // Blackman window gives useful stop-band rejection for speech input.
            let phase = 2.0 * std::f64::consts::PI * index as f64 / (LOW_PASS_TAPS - 1) as f64;
            let window = 0.42 - 0.5 * phase.cos() + 0.08 * (2.0 * phase).cos();
            *coefficient = sinc * window;
        }
        let gain: f64 = coefficients.iter().sum();
        for coefficient in &mut coefficients {
            *coefficient /= gain;
        }
        Self {
            coefficients,
            history: [0.0; LOW_PASS_TAPS],
            cursor: 0,
        }
    }

    fn process(&mut self, sample: f32) -> f32 {
        self.history[self.cursor] = sample;
        let mut output = 0.0;
        let mut history_index = self.cursor;
        for coefficient in &self.coefficients {
            output += coefficient * f64::from(self.history[history_index]);
            history_index = if history_index == 0 {
                LOW_PASS_TAPS - 1
            } else {
                history_index - 1
            };
        }
        self.cursor = (self.cursor + 1) % LOW_PASS_TAPS;
        output as f32
    }
}

/// The consumer-owned half. Reading never occurs on the native audio thread.
pub struct PcmConsumer {
    receiver: Receiver<f32>,
    gap: Arc<GapState>,
}

/// A zero count permits enqueueing; a nonzero count both records drops and
/// latches the producer closed until the consumer observes the gap.
struct GapState(AtomicU64);

impl GapState {
    fn is_latched(&self) -> bool {
        self.0.load(Ordering::Acquire) != 0
    }

    fn record_drop(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    fn dropped_samples(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn take_dropped_samples(&self) -> u64 {
        self.0.swap(0, Ordering::AcqRel)
    }
}

pub fn bounded_pcm_channel(
    channels: u16,
    source_rate: u32,
    capacity_samples: usize,
) -> Result<(PcmProducer, PcmConsumer), CaptureConfigError> {
    if channels == 0 {
        return Err(CaptureConfigError::ZeroChannels);
    }
    if source_rate == 0 {
        return Err(CaptureConfigError::ZeroSampleRate);
    }
    if capacity_samples == 0 {
        return Err(CaptureConfigError::ZeroCapacity);
    }
    let (sender, receiver) = mpsc::sync_channel(capacity_samples);
    let gap = Arc::new(GapState(AtomicU64::new(0)));
    Ok((
        PcmProducer {
            sender,
            channels: usize::from(channels),
            source_rate,
            channel_sum: 0.0,
            channel_offset: 0,
            resample_accumulator: 0,
            low_pass: (source_rate > SAMPLE_RATE).then(|| LowPassFilter::new(source_rate)),
            gap: gap.clone(),
        },
        PcmConsumer { receiver, gap },
    ))
}

impl PcmProducer {
    pub fn push_f32(&mut self, samples: &[f32]) {
        self.push(samples.iter().map(|sample| {
            if sample.is_finite() {
                sample.clamp(-1.0, 1.0)
            } else {
                0.0
            }
        }));
    }

    pub fn push_i16(&mut self, samples: &[i16]) {
        self.push(samples.iter().map(|sample| f32::from(*sample) / 32_768.0));
    }

    pub fn push_u16(&mut self, samples: &[u16]) {
        self.push(
            samples
                .iter()
                .map(|sample| (f32::from(*sample) - 32_768.0) / 32_768.0),
        );
    }

    fn push(&mut self, samples: impl Iterator<Item = f32>) {
        for sample in samples {
            self.channel_sum += f64::from(sample);
            self.channel_offset += 1;
            if self.channel_offset != self.channels {
                continue;
            }
            let mut mono = (self.channel_sum / self.channels as f64) as f32;
            self.channel_sum = 0.0;
            self.channel_offset = 0;

            if let Some(filter) = &mut self.low_pass {
                mono = filter.process(mono);
            }
            mono = if mono.is_finite() {
                mono.clamp(-1.0, 1.0)
            } else {
                0.0
            };

            self.resample_accumulator += SAMPLE_RATE;
            while self.resample_accumulator >= self.source_rate {
                self.resample_accumulator -= self.source_rate;
                if self.gap.is_latched() {
                    self.gap.record_drop();
                    continue;
                }
                match self.sender.try_send(mono) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        self.gap.record_drop();
                    }
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
        }
    }
}

impl PcmConsumer {
    pub fn drain(&self) -> Vec<f32> {
        let mut samples = Vec::new();
        loop {
            match self.receiver.try_recv() {
                Ok(sample) => samples.push(sample),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return samples,
            }
        }
    }

    pub fn dropped_samples(&self) -> u64 {
        self.gap.dropped_samples()
    }

    /// Reports and resets drops since the previous observation.
    pub fn take_dropped_samples(&self) -> u64 {
        self.gap.take_dropped_samples()
    }
}

#[cfg(test)]
mod overflow_tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn taking_drops_resets_the_overflow_counter() {
        let (mut producer, consumer) = bounded_pcm_channel(1, SAMPLE_RATE, 1).unwrap();
        producer.push_f32(&[0.1, 0.2, 0.3]);
        assert_eq!(consumer.drain(), vec![0.1]);
        assert_eq!(consumer.take_dropped_samples(), 2);
        assert_eq!(consumer.take_dropped_samples(), 0);
        producer.push_f32(&[0.4]);
        assert_eq!(consumer.drain(), vec![0.4]);
    }

    #[test]
    fn racing_drop_starts_a_new_gap_before_later_pcm_is_accepted() {
        let (mut producer, consumer) = bounded_pcm_channel(1, SAMPLE_RATE, 1).unwrap();
        producer.push_f32(&[0.1, 0.2]);
        assert_eq!(consumer.drain(), vec![0.1]);

        // Pause the producer after it observes the old latch, then reset the
        // consumer side. Its late drop must atomically relatch a new gap.
        let observed = Arc::new(Barrier::new(2));
        let reset = Arc::new(Barrier::new(2));
        let gap = producer.gap.clone();
        let producer_thread = thread::spawn({
            let observed = observed.clone();
            let reset = reset.clone();
            move || {
                assert!(gap.is_latched());
                observed.wait();
                reset.wait();
                gap.record_drop();
            }
        });
        observed.wait();
        assert_eq!(consumer.take_dropped_samples(), 1);
        reset.wait();
        producer_thread.join().unwrap();

        producer.push_f32(&[0.3]);
        assert!(consumer.drain().is_empty());
        assert_eq!(consumer.take_dropped_samples(), 2);
        producer.push_f32(&[0.4]);
        assert_eq!(consumer.drain(), vec![0.4]);
    }
}
