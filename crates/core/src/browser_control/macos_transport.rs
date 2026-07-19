//! macOS composition of the shared fail-closed browser-control transport.

// Keep the opening-handshake and pairing policy identical on Linux and macOS.
include!("linux_transport.rs");
