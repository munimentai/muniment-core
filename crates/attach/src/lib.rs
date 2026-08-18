//! Protocol-only support for attaching companion clients to Muniment.

/// Returns whether a dotted numeric runtime version meets the minimum version.
pub fn runtime_version_meets_minimum(version: &str, minimum: &str) -> bool {
    fn segments(version: &str) -> Option<Vec<u64>> {
        if version.is_empty() {
            return None;
        }
        version
            .split('.')
            .map(|segment| {
                if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()) {
                    None
                } else {
                    segment.parse().ok()
                }
            })
            .collect()
    }

    let (Some(version), Some(minimum)) = (segments(version), segments(minimum)) else {
        return false;
    };
    let segment_count = version.len().max(minimum.len());
    (0..segment_count)
        .map(|index| version.get(index).copied().unwrap_or(0))
        .cmp((0..segment_count).map(|index| minimum.get(index).copied().unwrap_or(0)))
        .is_ge()
}

#[cfg(feature = "client")]
mod client;
mod envelope;
pub mod fixtures;
mod framing;
mod negotiation;
mod workspace;

#[cfg(feature = "client")]
pub use client::*;
pub use envelope::*;
pub use framing::*;
pub use negotiation::*;
pub use workspace::*;
