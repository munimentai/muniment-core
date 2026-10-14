//! A stand-in for the engines: each engine answers a fixed page built from a
//! list of result URLs, and every request is logged.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use muniment_search::session::Pacing;
use muniment_search::transport::TransportFactory;
use muniment_search::{Config, EngineId, Metasearch, Response, Transport, TransportError};

pub type Requests = Arc<Mutex<Vec<(EngineId, String)>>>;

/// What one engine answers to a search.
#[derive(Clone)]
pub enum Answer {
    Results(Vec<&'static str>),
    Status(u16),
}

#[derive(Clone, Default)]
pub struct Engines {
    answers: HashMap<EngineId, Answer>,
    pub requests: Requests,
}

impl Engines {
    pub fn answer(mut self, engine: EngineId, answer: Answer) -> Self {
        self.answers.insert(engine, answer);
        self
    }

    pub fn factory(&self) -> TransportFactory {
        let engines = self.clone();
        Arc::new(move |engine| {
            Box::new(Fake {
                engine,
                engines: engines.clone(),
            }) as Box<dyn Transport>
        })
    }

    pub fn metasearch(&self, engines: &[EngineId]) -> Metasearch {
        let config = Config {
            engines: engines.to_vec(),
            pacing: Pacing {
                min_gap: Duration::ZERO,
                max_gap: Duration::ZERO,
                cooldown: Duration::from_secs(600),
            },
        };
        Metasearch::with_transport(config, self.factory())
    }

    /// The search URLs `engine` received, home pages left out.
    pub fn searches(&self, engine: EngineId) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(seen, url)| *seen == engine && Some(url.as_str()) != engine.home_url())
            .map(|(_, url)| url.clone())
            .collect()
    }
}

struct Fake {
    engine: EngineId,
    engines: Engines,
}

impl Transport for Fake {
    fn get(&mut self, url: &str, _referer: Option<&str>) -> Result<Response, TransportError> {
        self.engines
            .requests
            .lock()
            .unwrap()
            .push((self.engine, url.to_owned()));
        if Some(url) == self.engine.home_url() {
            return Ok(Response {
                status: 200,
                final_url: url.to_owned(),
                body: "<html></html>".into(),
            });
        }
        let answer = self
            .engines
            .answers
            .get(&self.engine)
            .cloned()
            .unwrap_or(Answer::Results(Vec::new()));
        Ok(match answer {
            Answer::Results(urls) => Response {
                status: 200,
                final_url: url.to_owned(),
                body: page(self.engine, &urls),
            },
            Answer::Status(status) => Response {
                status,
                final_url: url.to_owned(),
                body: String::new(),
            },
        })
    }
}

/// A result page in `engine`'s own markup listing `urls`.
pub fn page(engine: EngineId, urls: &[&str]) -> String {
    let entry = |n: usize, url: &str| {
        let (title, snippet) = (format!("Title {n}"), format!("About {url}"));
        match engine {
            EngineId::Brave => format!(
                r#"<div class="snippet" data-type="web"><a href="{url}"><div class="title">{title}</div></a><div class="snippet-description">{snippet}</div></div>"#
            ),
            EngineId::Bing => format!(
                r#"<li class="b_algo"><h2><a href="{url}">{title}</a></h2><div class="b_caption"><p>{snippet}</p></div></li>"#
            ),
            EngineId::DuckDuckGo => format!(
                r#"<div class="result__body"><a class="result__a" href="{url}">{title}</a><a class="result__snippet">{snippet}</a></div>"#
            ),
            EngineId::Yahoo => format!(
                r#"<div class="algo-sr"><div class="compTitle"><a href="{url}"><h3>{title}</h3></a></div><div class="compText">{snippet}</div></div>"#
            ),
            EngineId::Wikipedia => unreachable!(),
        }
    };
    if engine == EngineId::Wikipedia {
        let pages: Vec<_> = urls
            .iter()
            .map(|url| {
                let key = url.rsplit('/').next().unwrap();
                serde_json::json!({ "key": key, "title": key, "excerpt": format!("About {key}") })
            })
            .collect();
        return serde_json::json!({ "pages": pages }).to_string();
    }
    let body: String = urls
        .iter()
        .enumerate()
        .map(|(n, url)| entry(n + 1, url))
        .collect();
    format!("<html><body>{body}</body></html>")
}
