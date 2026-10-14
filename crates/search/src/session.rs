//! One engine's browsing state: its transport and cookie jar, the last page
//! for a same-origin referer, the pace between requests, and the cooldown
//! after a block.

use std::time::{Duration, Instant};

use crate::engines::{self, EngineId, SearchResult, TimeRange};
use crate::transport::{Response, Transport, TransportError, TransportFactory};

/// How a session paces and rests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pacing {
    /// The shortest and longest gap between two requests to the same engine.
    /// Each gap is a random length in between.
    pub min_gap: Duration,
    pub max_gap: Duration,
    /// How long an engine rests after it blocks a request.
    pub cooldown: Duration,
}

impl Default for Pacing {
    fn default() -> Self {
        Pacing {
            min_gap: Duration::from_secs(1),
            max_gap: Duration::from_secs(3),
            cooldown: Duration::from_secs(600),
        }
    }
}

/// Why a session returned no results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The engine refused the request. The session rests for the cooldown.
    Blocked(String),
    /// The engine is still resting after a block.
    CoolingDown {
        remaining: Duration,
    },
    Transport(TransportError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Blocked(reason) => write!(f, "blocked: {reason}"),
            SessionError::CoolingDown { remaining } => {
                write!(f, "cooling down for {}s", remaining.as_secs())
            }
            SessionError::Transport(error) => write!(f, "{error}"),
        }
    }
}

pub struct Session {
    engine: EngineId,
    factory: TransportFactory,
    transport: Box<dyn Transport>,
    pacing: Pacing,
    referer: Option<String>,
    visited_home: bool,
    last_request: Option<Instant>,
    blocked_until: Option<Instant>,
}

impl Session {
    pub fn new(engine: EngineId, factory: TransportFactory, pacing: Pacing) -> Self {
        let transport = factory(engine);
        Session {
            engine,
            factory,
            transport,
            pacing,
            referer: None,
            visited_home: false,
            last_request: None,
            blocked_until: None,
        }
    }

    pub fn engine(&self) -> EngineId {
        self.engine
    }

    /// The time left on the cooldown, when the engine is resting.
    pub fn cooling(&self) -> Option<Duration> {
        self.blocked_until
            .and_then(|until| until.checked_duration_since(Instant::now()))
            .filter(|remaining| !remaining.is_zero())
    }

    /// Searches the engine for `query`. A first search opens the engine's home
    /// page before it, as a person would.
    pub fn search(
        &mut self,
        query: &str,
        range: Option<TimeRange>,
    ) -> Result<Vec<SearchResult>, SessionError> {
        if let Some(remaining) = self.cooling() {
            return Err(SessionError::CoolingDown { remaining });
        }
        if self.blocked_until.take().is_some() {
            // A block may stick to the cookies, so a rested engine starts clean.
            self.transport = (self.factory)(self.engine);
            self.referer = None;
            self.visited_home = false;
        }
        if let (false, Some(home)) = (self.visited_home, self.engine.home_url()) {
            let page = self.navigate(home)?;
            if let Some(reason) = engines::blocked(self.engine, page.status, &page.final_url, 1) {
                return Err(self.block(format!("home page {reason}")));
            }
            self.visited_home = true;
        }
        let page = self.navigate(&engines::search_url(self.engine, query, range))?;
        let results = engines::parse(self.engine, &page.body);
        match engines::blocked(self.engine, page.status, &page.final_url, results.len()) {
            Some(reason) => Err(self.block(reason)),
            None => Ok(results),
        }
    }

    fn block(&mut self, reason: String) -> SessionError {
        self.blocked_until = Some(Instant::now() + self.pacing.cooldown);
        SessionError::Blocked(reason)
    }

    /// Waits out the gap since the last request, sends one GET with a
    /// same-origin referer, and retries once on a reset connection.
    fn navigate(&mut self, url: &str) -> Result<Response, SessionError> {
        self.wait_gap();
        let referer = self
            .referer
            .clone()
            .filter(|referer| same_origin(referer, url));
        let mut sent = self.transport.get(url, referer.as_deref());
        if matches!(sent, Err(TransportError::ConnectionReset(_))) {
            sent = self.transport.get(url, referer.as_deref());
        }
        self.last_request = Some(Instant::now());
        let page = sent.map_err(SessionError::Transport)?;
        self.referer = Some(page.final_url.clone());
        Ok(page)
    }

    fn wait_gap(&self) {
        let Some(last) = self.last_request else {
            return;
        };
        let gap = random_between(self.pacing.min_gap, self.pacing.max_gap);
        if let Some(rest) = gap.checked_sub(last.elapsed()) {
            std::thread::sleep(rest);
        }
    }
}

fn random_between(low: Duration, high: Duration) -> Duration {
    if high <= low {
        return low;
    }
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).expect("the platform's random source");
    let span = (high - low).as_millis() as u64 + 1;
    low + Duration::from_millis(u64::from_le_bytes(bytes) % span)
}

fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    type Log = Arc<Mutex<Vec<(String, Option<String>)>>>;

    /// Answers from a script and logs each URL and referer.
    struct Scripted {
        log: Log,
        answers: Arc<Mutex<Vec<Result<Response, TransportError>>>>,
    }

    impl Transport for Scripted {
        fn get(&mut self, url: &str, referer: Option<&str>) -> Result<Response, TransportError> {
            self.log
                .lock()
                .unwrap()
                .push((url.to_owned(), referer.map(str::to_owned)));
            self.answers.lock().unwrap().remove(0)
        }
    }

    fn ok(url: &str, body: &str) -> Result<Response, TransportError> {
        Ok(Response {
            status: 200,
            final_url: url.to_owned(),
            body: body.to_owned(),
        })
    }

    fn session(
        engine: EngineId,
        answers: Vec<Result<Response, TransportError>>,
        pacing: Pacing,
    ) -> (Session, Log, Arc<Mutex<usize>>) {
        let log: Log = Arc::default();
        let built = Arc::new(Mutex::new(0));
        let answers = Arc::new(Mutex::new(answers));
        let factory: TransportFactory = {
            let (log, built) = (log.clone(), built.clone());
            Arc::new(move |_| {
                *built.lock().unwrap() += 1;
                Box::new(Scripted {
                    log: log.clone(),
                    answers: answers.clone(),
                }) as Box<dyn Transport>
            })
        };
        (Session::new(engine, factory, pacing), log, built)
    }

    const DDG_PAGE: &str = r#"<div class="result__body"><a class="result__a" href="https://example.com/">Example</a><a class="result__snippet">Snippet</a></div>"#;

    fn quick() -> Pacing {
        Pacing {
            min_gap: Duration::ZERO,
            max_gap: Duration::ZERO,
            cooldown: Duration::from_secs(600),
        }
    }

    #[test]
    fn a_first_search_opens_the_home_page_and_sends_it_as_referer() {
        let home = "https://html.duckduckgo.com/html/";
        let (mut session, log, _) = session(
            EngineId::DuckDuckGo,
            vec![ok(home, "home"), ok(home, DDG_PAGE), ok(home, DDG_PAGE)],
            quick(),
        );
        assert_eq!(session.search("rust", None).unwrap().len(), 1);
        assert_eq!(session.search("tokio", None).unwrap().len(), 1);
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0], (home.to_owned(), None));
        assert_eq!(log[1].1.as_deref(), Some(home));
    }

    #[test]
    fn a_reset_connection_is_retried_once() {
        let url = "https://html.duckduckgo.com/html/";
        let reset = || Err(TransportError::ConnectionReset("reset".into()));
        let (mut session, log, _) = session(
            EngineId::DuckDuckGo,
            vec![reset(), ok(url, "home"), reset(), reset()],
            quick(),
        );
        assert!(matches!(
            session.search("rust", None),
            Err(SessionError::Transport(TransportError::ConnectionReset(_)))
        ));
        assert_eq!(log.lock().unwrap().len(), 4);
    }

    #[test]
    fn a_block_starts_a_cooldown_and_a_rested_engine_gets_a_fresh_transport() {
        let blocked = Ok(Response {
            status: 429,
            final_url: "https://search.brave.com/search".into(),
            body: String::new(),
        });
        let pacing = Pacing {
            cooldown: Duration::from_millis(50),
            ..quick()
        };
        let brave_page = r#"<div class="snippet" data-type="web"><a href="https://example.com/"><div class="title">T</div></a></div>"#;
        let (mut session, log, built) = session(
            EngineId::Brave,
            vec![blocked, ok("https://search.brave.com/search", brave_page)],
            pacing,
        );
        assert!(matches!(
            session.search("rust", None),
            Err(SessionError::Blocked(_))
        ));
        assert!(matches!(
            session.search("rust", None),
            Err(SessionError::CoolingDown { .. })
        ));
        assert_eq!(log.lock().unwrap().len(), 1);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(session.search("rust", None).unwrap().len(), 1);
        assert_eq!(*built.lock().unwrap(), 2);
    }

    #[test]
    fn requests_to_one_engine_keep_the_minimum_gap() {
        let url = "https://search.brave.com/search";
        let page = r#"<div class="snippet" data-type="web"><a href="https://example.com/"><div class="title">T</div></a></div>"#;
        let pacing = Pacing {
            min_gap: Duration::from_millis(120),
            max_gap: Duration::from_millis(150),
            cooldown: Duration::from_secs(1),
        };
        let (mut session, _, _) =
            session(EngineId::Brave, vec![ok(url, page), ok(url, page)], pacing);
        session.search("a", None).unwrap();
        let started = Instant::now();
        session.search("b", None).unwrap();
        assert!(started.elapsed() >= Duration::from_millis(120));
    }
}
