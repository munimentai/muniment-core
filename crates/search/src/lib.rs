//! Keyless web search.
//!
//! The engine queries Brave, DuckDuckGo, Wikipedia, Yahoo and Bing the way a
//! browser does and merges their result pages.
//!
//! - [`engines`] builds each engine's search URL, parses its page and judges
//!   whether the engine blocked the request.
//! - [`transport`] sends one GET: `ureq` with rustls by default, and libcurl
//!   for Brave with the `curl` feature.
//! - [`session`] keeps one cookie jar, referer, pace and cooldown per engine.
//! - [`metasearch`] queries the enabled engines in parallel and merges them.

pub mod engines;
pub mod metasearch;
pub mod session;
pub mod transport;

pub use engines::{EngineId, SearchResult, TimeRange};
pub use metasearch::{Config, EngineReport, EngineStatus, Metasearch, Outcome, Query};
pub use transport::{Response, Transport, TransportError};
