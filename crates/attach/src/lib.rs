//! Protocol-only support for attaching companion clients to Muniment.

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
