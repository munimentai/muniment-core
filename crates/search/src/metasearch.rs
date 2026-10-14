//! Metasearch: query the enabled engines in parallel, merge their pages by
//! URL, interleave them by rank, and apply domain filters and the count.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;

use crate::engines::{EngineId, SearchResult, TimeRange, PAGE_RESULTS};
use crate::session::{Pacing, Session, SessionError};
use crate::transport::{default_factory, TransportFactory};

/// The most results one search returns.
pub const MAX_COUNT: usize = 20;

/// Which engines run, in which order, and how they are paced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The enabled engines. Earlier engines win ties when results interleave.
    pub engines: Vec<EngineId>,
    pub pacing: Pacing,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            engines: EngineId::ALL.to_vec(),
            pacing: Pacing::default(),
        }
    }
}

/// One search request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The query as typed. `site:` and `-site:` terms in it filter by domain.
    pub text: String,
    pub time_range: Option<TimeRange>,
    /// How many results to return, from 1 to [`MAX_COUNT`].
    pub count: usize,
}

impl Query {
    pub fn new(text: impl Into<String>) -> Self {
        Query {
            text: text.into(),
            time_range: None,
            count: PAGE_RESULTS,
        }
    }
}

/// A merged result and the engines that listed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Merged {
    #[serde(flatten)]
    pub result: SearchResult,
    pub engines: Vec<EngineId>,
}

/// What one engine did for a search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum EngineStatus {
    Answered(usize),
    Blocked(String),
    CoolingDown(u64),
    Failed(String),
    /// The engine cannot limit results to the requested time range, or has no
    /// terms left to search for.
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineReport {
    pub engine: EngineId,
    #[serde(flatten)]
    pub status: EngineStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub results: Vec<Merged>,
    pub engines: Vec<EngineReport>,
}

impl Outcome {
    /// Whether any engine answered, even with no results.
    pub fn answered(&self) -> bool {
        self.engines
            .iter()
            .any(|report| matches!(report.status, EngineStatus::Answered(_)))
    }
}

/// The engine sessions behind every search. Searches may run concurrently,
/// and requests to one engine wait for each other.
pub struct Metasearch {
    order: Vec<EngineId>,
    sessions: HashMap<EngineId, Mutex<Session>>,
}

impl Metasearch {
    pub fn new(config: Config) -> Self {
        Self::with_transport(config, default_factory())
    }

    /// Uses `factory` to build each engine session's transport.
    pub fn with_transport(config: Config, factory: TransportFactory) -> Self {
        let mut order = Vec::new();
        for engine in config.engines {
            if !order.contains(&engine) {
                order.push(engine);
            }
        }
        let sessions = order
            .iter()
            .map(|&engine| {
                let session = Session::new(engine, factory.clone(), config.pacing);
                (engine, Mutex::new(session))
            })
            .collect();
        Metasearch { order, sessions }
    }

    /// The enabled engines in order.
    pub fn engines(&self) -> &[EngineId] {
        &self.order
    }

    pub fn search(&self, query: &Query) -> Outcome {
        let filters = DomainFilters::parse(&query.text);
        let reports: Vec<(EngineId, Result<Vec<SearchResult>, EngineStatus>)> =
            std::thread::scope(|scope| {
                let running: Vec<_> = self
                    .order
                    .iter()
                    .map(|&engine| {
                        let filters = &filters;
                        scope.spawn(move || (engine, self.run(engine, query, filters)))
                    })
                    .collect();
                running
                    .into_iter()
                    .map(|thread| thread.join().expect("an engine thread"))
                    .collect()
            });
        let mut pages = Vec::new();
        let mut engines = Vec::new();
        for (engine, outcome) in reports {
            let status = match outcome {
                Ok(results) => {
                    let status = EngineStatus::Answered(results.len());
                    pages.push((engine, results));
                    status
                }
                Err(status) => status,
            };
            engines.push(EngineReport { engine, status });
        }
        let count = query.count.clamp(1, MAX_COUNT);
        let results = merge(pages)
            .into_iter()
            .filter(|merged| filters.allows(&merged.result.url))
            .take(count)
            .collect();
        Outcome { results, engines }
    }

    fn run(
        &self,
        engine: EngineId,
        query: &Query,
        filters: &DomainFilters,
    ) -> Result<Vec<SearchResult>, EngineStatus> {
        if query
            .time_range
            .is_some_and(|range| !engine.supports(range))
        {
            return Err(EngineStatus::Skipped);
        }
        let text = filters.engine_query(engine);
        if text.is_empty() {
            return Err(EngineStatus::Skipped);
        }
        let mut session = self.sessions[&engine]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        session
            .search(&text, query.time_range)
            .map_err(|error| match error {
                SessionError::Blocked(reason) => EngineStatus::Blocked(reason),
                SessionError::CoolingDown { remaining } => {
                    EngineStatus::CoolingDown(remaining.as_secs())
                }
                SessionError::Transport(error) => EngineStatus::Failed(error.to_string()),
            })
    }
}

/// Interleaves engine pages by rank: every engine's first result in engine
/// order, then every second result, and so on. A URL another engine already
/// listed adds that engine to the earlier entry instead.
pub fn merge(pages: Vec<(EngineId, Vec<SearchResult>)>) -> Vec<Merged> {
    let longest = pages.iter().map(|(_, page)| page.len()).max().unwrap_or(0);
    let mut merged: Vec<Merged> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for rank in 0..longest {
        for (engine, page) in &pages {
            let Some(result) = page.get(rank) else {
                continue;
            };
            let key = normalize_url(&result.url);
            match seen.get(&key) {
                Some(&index) => {
                    let entry = &mut merged[index];
                    if !entry.engines.contains(engine) {
                        entry.engines.push(*engine);
                    }
                    if entry.result.snippet.is_empty() {
                        entry.result.snippet = result.snippet.clone();
                    }
                }
                None => {
                    seen.insert(key, merged.len());
                    merged.push(Merged {
                        result: result.clone(),
                        engines: vec![*engine],
                    });
                }
            }
        }
    }
    merged
}

/// The key two listings of one page share: no scheme, no `www.`, no
/// fragment, no trailing slash, and a decoded path.
pub fn normalize_url(raw: &str) -> String {
    let Ok(url) = url::Url::parse(raw.trim()) else {
        return raw.trim().to_owned();
    };
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    let path = percent_encoding::percent_decode_str(url.path()).decode_utf8_lossy();
    let path = path.trim_end_matches('/');
    let query = url
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    format!("{host}{port}{path}{query}")
}

/// The `site:` and `-site:` terms of a query and the plain terms around them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainFilters {
    pub plain: String,
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
}

impl DomainFilters {
    /// Splits `query` into plain terms and domain filters. An `OR` between
    /// two `site:` terms joins them and is dropped with them.
    pub fn parse(query: &str) -> Self {
        let tokens: Vec<&str> = query.split_whitespace().collect();
        let site = |token: &str| -> Option<(bool, String)> {
            let (blocked, rest) = match token.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, token),
            };
            let domain = rest.strip_prefix("site:")?;
            normalize_domain(domain).map(|domain| (blocked, domain))
        };
        let mut filters = DomainFilters::default();
        let mut plain = Vec::new();
        for (index, token) in tokens.iter().enumerate() {
            if let Some((blocked, domain)) = site(token) {
                let list = if blocked {
                    &mut filters.blocked
                } else {
                    &mut filters.allowed
                };
                if !list.contains(&domain) {
                    list.push(domain);
                }
                continue;
            }
            let joins_sites = *token == "OR"
                && index > 0
                && site(tokens[index - 1]).is_some()
                && tokens
                    .get(index + 1)
                    .is_some_and(|next| site(next).is_some());
            if !joins_sites {
                plain.push(*token);
            }
        }
        filters.plain = plain.join(" ");
        filters
    }

    /// The query `engine` receives: the plain terms, followed by the domain
    /// terms for an engine that reads them.
    pub fn engine_query(&self, engine: EngineId) -> String {
        if !engine.reads_site_terms() {
            return self.plain.clone();
        }
        let mut parts = Vec::new();
        if !self.plain.is_empty() {
            parts.push(self.plain.clone());
        }
        let allowed: Vec<String> = self
            .allowed
            .iter()
            .map(|domain| format!("site:{domain}"))
            .collect();
        if !allowed.is_empty() {
            parts.push(allowed.join(" OR "));
        }
        parts.extend(self.blocked.iter().map(|domain| format!("-site:{domain}")));
        parts.join(" ")
    }

    /// Whether a result URL passes the filters.
    pub fn allows(&self, url: &str) -> bool {
        if self.allowed.is_empty() && self.blocked.is_empty() {
            return true;
        }
        let Some(host) = url::Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        else {
            return false;
        };
        let matches = |domain: &String| host == *domain || host.ends_with(&format!(".{domain}"));
        (self.allowed.is_empty() || self.allowed.iter().any(matches))
            && !self.blocked.iter().any(matches)
    }
}

fn normalize_domain(raw: &str) -> Option<String> {
    let lower = raw.trim().to_ascii_lowercase();
    let without_scheme = lower
        .split_once("://")
        .map_or(lower.as_str(), |(_, rest)| rest);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_end_matches('.');
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(url: &str, snippet: &str) -> SearchResult {
        SearchResult {
            title: url.to_owned(),
            url: url.to_owned(),
            snippet: snippet.to_owned(),
        }
    }

    #[test]
    fn domain_terms_leave_the_plain_query() {
        let filters = DomainFilters::parse(
            "tokio select site:docs.rs OR site:https://www.tokio.rs/ -site:reddit.com",
        );
        assert_eq!(filters.plain, "tokio select");
        assert_eq!(filters.allowed, vec!["docs.rs", "tokio.rs"]);
        assert_eq!(filters.blocked, vec!["reddit.com"]);
        assert_eq!(filters.engine_query(EngineId::Wikipedia), "tokio select");
        assert_eq!(
            filters.engine_query(EngineId::Bing),
            "tokio select site:docs.rs OR site:tokio.rs -site:reddit.com"
        );
        assert_eq!(DomainFilters::parse("cats OR dogs").plain, "cats OR dogs");
    }

    #[test]
    fn domain_filters_match_hosts_and_subdomains() {
        let filters = DomainFilters::parse("x site:rust-lang.org -site:blog.rust-lang.org");
        assert!(filters.allows("https://doc.rust-lang.org/std/"));
        assert!(filters.allows("https://rust-lang.org/"));
        assert!(!filters.allows("https://blog.rust-lang.org/post"));
        assert!(!filters.allows("https://notrust-lang.org/"));
        assert!(DomainFilters::parse("x").allows("anything"));
    }

    #[test]
    fn urls_normalize_across_scheme_www_fragment_and_trailing_slash() {
        assert_eq!(
            normalize_url("https://www.Example.com/a/#top"),
            normalize_url("http://example.com/a")
        );
        assert_eq!(
            normalize_url("https://en.wikipedia.org/wiki/MLX_%28framework%29"),
            normalize_url("https://en.wikipedia.org/wiki/MLX_(framework)")
        );
        assert_ne!(
            normalize_url("https://example.com/a?x=1"),
            normalize_url("https://example.com/a?x=2")
        );
    }

    #[test]
    fn merge_interleaves_by_rank_and_joins_duplicates() {
        let merged = merge(vec![
            (
                EngineId::Brave,
                vec![result("https://a.com/", ""), result("https://b.com/", "b")],
            ),
            (
                EngineId::Bing,
                vec![
                    result("https://c.com/", "c"),
                    result("https://www.a.com", "a"),
                ],
            ),
        ]);
        let urls: Vec<_> = merged.iter().map(|m| m.result.url.as_str()).collect();
        assert_eq!(urls, ["https://a.com/", "https://c.com/", "https://b.com/"]);
        assert_eq!(merged[0].engines, [EngineId::Brave, EngineId::Bing]);
        assert_eq!(merged[0].result.snippet, "a");
    }
}
