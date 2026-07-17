//! Protocol-only support for attaching companion clients to Muniment.

#[cfg(feature = "client")]
mod client;
mod envelope;
mod framing;
mod negotiation;

#[cfg(feature = "client")]
pub use client::*;
pub use envelope::*;
pub use framing::*;
pub use negotiation::*;
