//! Keyless web search.
//!
//! The engine queries Brave, DuckDuckGo, Wikipedia, Yahoo and Bing the way a
//! browser does, merges their result pages, and answers in the SearXNG JSON
//! format on a loopback port, so a SearXNG client reaches it with a base URL
//! and a bearer token.
//!
//! - [`engines`] builds each engine's search URL, parses its page and judges
//!   whether the engine blocked the request.
//! - [`transport`] sends one GET: `ureq` with rustls by default, and the
//!   system `curl` program for Brave when one is on `PATH`.
//! - [`session`] keeps one cookie jar, referer, pace and cooldown per engine.
//! - [`metasearch`] queries the enabled engines in parallel and merges them.
//! - [`server`] serves `GET /search` on `127.0.0.1`.

pub mod engines;
pub mod metasearch;
pub mod server;
pub mod session;
pub mod transport;

pub use engines::{EngineId, SearchResult, TimeRange};
pub use metasearch::{Config, EngineReport, EngineStatus, Metasearch, Outcome, Query};
pub use server::{Endpoint, Handle};
pub use transport::{Response, Transport, TransportError};
