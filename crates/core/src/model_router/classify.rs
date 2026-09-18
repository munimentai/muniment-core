//! The optional query classifier that picks a route.
//!
//! Routing is optional. With no classifier every turn takes the fallback
//! route and the balancer still spreads it across the pool. With one, the
//! turn's last user message goes to the classifier as one `choice` question
//! whose options are the user's own routes, and the answer names the route.
//! A confidence under the configured floor takes the fallback instead, so a
//! guess never silently picks the expensive model.
//!
//! The classifier is a network call to a service the user names, so it sends
//! the turn's text off the machine. Settings says so, and the default is off.

use std::time::Duration;

use serde_json::{json, Value};

use super::balance;
use super::config::{Classifier, Route, RouterConfig};
use super::usage::Ledger;
use super::wire::Tokens;

/// TypeSafe's System One endpoint.
pub const TYPESAFE_URL: &str = "https://api.typesafe.ai/v1/systemone";
/// The question name the router asks under.
pub const QUESTION: &str = "route";
/// What the router asks the classifier.
pub const INSTRUCTIONS: &str = "Which of these models should answer this request?";
/// How long a classifier call may take before the turn goes on without it.
pub const TIMEOUT: Duration = Duration::from_secs(8);
/// The longest slice of the turn the classifier sees.
pub const STATE_LIMIT: usize = 8_000;

/// Why a turn took the route it took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No classifier is configured, or there is only one route.
    NotClassified,
    /// The classifier answered above the confidence floor.
    Classified,
    /// The classifier answered below the floor, so the fallback took the turn.
    LowConfidence,
    /// The classifier did not answer, so the fallback took the turn.
    Failed,
}

impl Reason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotClassified => "not-classified",
            Self::Classified => "classified",
            Self::LowConfidence => "low-confidence",
            Self::Failed => "failed",
        }
    }
}

/// The route a turn takes and how it got there.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub route: Route,
    pub confidence: f64,
    pub reason: Reason,
    /// The account a pooled classifier spent, and what it spent. A classifier
    /// on the user's own account costs them, so the ledger counts it.
    pub spent_on: Option<String>,
    pub spent: Tokens,
}

impl Decision {
    fn plain(route: Route, confidence: f64, reason: Reason) -> Self {
        Self {
            route,
            confidence,
            reason,
            spent_on: None,
            spent: Tokens::default(),
        }
    }
}

/// What a pooled classifier is told, so a small model answers in one shape.
pub const POOLED_SYSTEM: &str = "You are a router. Read the request and pick exactly one option. Answer with one JSON object and nothing else: {\"choice\": \"<option name>\", \"confidence\": <0 to 1>}. The confidence is your own probability that the option is right.";

/// The `choice` question for this configuration's routes.
pub fn question(config: &RouterConfig, state: &str) -> Value {
    let mut criteria = serde_json::Map::new();
    for route in &config.routes {
        criteria.insert(route.key.clone(), Value::String(route.description.clone()));
    }
    let model = config.classifier.model().to_owned();
    json!({
        "state": clip(state),
        "model": model,
        "questions": { QUESTION: {
            "type": "choice",
            "instructions": INSTRUCTIONS,
            "criteria": Value::Object(criteria),
        }},
    })
}

/// The chosen option and its confidence, from a System One answer.
pub fn parse(answer: &Value) -> Option<(String, f64)> {
    let choice = answer.get("answers")?.get(QUESTION)?;
    let key = choice.get("choice")?.as_str()?.to_owned();
    // An answer with no confidence is a certain one.
    let confidence = choice
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(1.0);
    Some((key, confidence))
}

/// The classifier's URL and its bearer, when one is configured.
fn endpoint(classifier: &Classifier) -> Option<(String, Option<String>)> {
    match classifier {
        Classifier::None | Classifier::Pooled { .. } => None,
        Classifier::Typesafe {
            api_key, base_url, ..
        } => Some((
            base_url
                .as_deref()
                .filter(|url| !url.trim().is_empty())
                .unwrap_or(TYPESAFE_URL)
                .to_owned(),
            Some(api_key.clone()),
        )),
        Classifier::Endpoint {
            base_url, api_key, ..
        } => Some((
            base_url.clone(),
            api_key.clone().filter(|key| !key.trim().is_empty()),
        )),
    }
}

/// Asks the classifier, and answers with the route the turn takes. A turn
/// always gets a route while the configuration holds one, because every
/// failure lands on the fallback.
pub fn decide(
    config: &RouterConfig,
    ledger: &Ledger,
    state: &str,
    now_ms: i64,
    timeout: Duration,
) -> Option<Decision> {
    let fallback = config.fallback_route()?.clone();
    if !config.classifies() {
        return Some(Decision::plain(fallback, 0.0, Reason::NotClassified));
    }
    let asked = match &config.classifier {
        Classifier::Pooled { family, model } => {
            ask_pool(config, ledger, family, model, state, now_ms, timeout)
        }
        _ => {
            let Some((url, bearer)) = endpoint(&config.classifier) else {
                return Some(Decision::plain(fallback, 0.0, Reason::NotClassified));
            };
            Asked {
                answer: ask(&url, bearer.as_deref(), &question(config, state), timeout)
                    .as_ref()
                    .and_then(parse),
                spent_on: None,
                spent: Tokens::default(),
            }
        }
    };
    let settle = |route: Route, confidence: f64, reason: Reason| Decision {
        route,
        confidence,
        reason,
        spent_on: asked.spent_on.clone(),
        spent: asked.spent,
    };
    let Some((key, confidence)) = asked.answer.clone() else {
        return Some(settle(fallback, 0.0, Reason::Failed));
    };
    let Some(route) = config.route(&key) else {
        return Some(settle(fallback, confidence, Reason::Failed));
    };
    if confidence < config.min_confidence {
        return Some(settle(fallback, confidence, Reason::LowConfidence));
    }
    Some(settle(route.clone(), confidence, Reason::Classified))
}

/// What one classifier call came back with.
struct Asked {
    answer: Option<(String, f64)>,
    spent_on: Option<String>,
    spent: Tokens,
}

/// A pooled classifier: the balancer picks an account of the classifier's
/// family and a small model on it answers the same choice as JSON.
fn ask_pool(
    config: &RouterConfig,
    ledger: &Ledger,
    family: &str,
    model: &str,
    state: &str,
    now_ms: i64,
    timeout: Duration,
) -> Asked {
    let empty = Asked {
        answer: None,
        spent_on: None,
        spent: Tokens::default(),
    };
    let Ok(account) = balance::pick(config, ledger, family, model, now_ms) else {
        return empty;
    };
    let Some(upstream) = account.upstream() else {
        return empty;
    };
    let options = config
        .routes
        .iter()
        .map(|route| format!("- {}: {}", route.key, route.description))
        .collect::<Vec<_>>()
        .join("\n");
    let body = json!({
        "model": model,
        "temperature": 0,
        "messages": [
            { "role": "system", "content": format!("{POOLED_SYSTEM}\n\nThe options:\n{options}") },
            { "role": "user", "content": clip(state) },
        ],
    });
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let answered = agent
        .post(&format!("{upstream}/chat/completions"))
        .set("content-type", "application/json")
        .set(
            "authorization",
            &format!("Bearer {}", account.credential.bearer()),
        )
        .send_json(&body)
        .ok()
        .and_then(|response| response.into_json::<Value>().ok());
    let Some(answered) = answered else {
        return Asked {
            answer: None,
            spent_on: Some(account.id.clone()),
            spent: Tokens::default(),
        };
    };
    Asked {
        answer: answered
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            .and_then(|choice| choice.get("message")?.get("content")?.as_str())
            .and_then(parse_pooled_answer),
        spent_on: Some(account.id.clone()),
        spent: super::wire::tokens(&answered).unwrap_or_default(),
    }
}

/// The choice and confidence a small model wrote, out of the JSON it answered
/// with, fenced or plain.
pub fn parse_pooled_answer(content: &str) -> Option<(String, f64)> {
    let text = content.trim();
    let text = text
        .strip_prefix("```json")
        .or_else(|| text.strip_prefix("```"))
        .map(|rest| rest.trim_start())
        .unwrap_or(text);
    let text = text.strip_suffix("```").map(str::trim_end).unwrap_or(text);
    // A model that wrote a sentence around its JSON still has the object in it.
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    let value: Value = serde_json::from_str(text.get(start..=end)?).ok()?;
    let choice = value.get("choice")?.as_str()?.trim().to_owned();
    if choice.is_empty() {
        return None;
    }
    let confidence = value
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(1.0)
        .clamp(0.0, 1.0);
    Some((choice, confidence))
}

/// One classifier call. Nothing here fails a turn: an unreachable classifier,
/// a refusal and a body that is not JSON all read as no answer.
fn ask(url: &str, bearer: Option<&str>, body: &Value, timeout: Duration) -> Option<Value> {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let mut request = agent.post(url).set("content-type", "application/json");
    if let Some(bearer) = bearer {
        request = request.set("authorization", &format!("Bearer {bearer}"));
    }
    request.send_json(body).ok()?.into_json::<Value>().ok()
}

/// Whether the classifier answers at all, for the Test button in Settings.
pub fn check(classifier: &Classifier, timeout: Duration) -> Result<(), String> {
    let Some((url, bearer)) = endpoint(classifier) else {
        return Err("No classifier is configured.".into());
    };
    let probe = json!({
        "state": "A short question about the weather.",
        "model": classifier.model(),
        "questions": { QUESTION: {
            "type": "choice",
            "instructions": INSTRUCTIONS,
            "criteria": { "fast": "A short question", "deep": "A long reasoning task" },
        }},
    });
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let mut request = agent.post(&url).set("content-type", "application/json");
    if let Some(bearer) = bearer {
        request = request.set("authorization", &format!("Bearer {bearer}"));
    }
    match request.send_json(&probe) {
        Ok(response) => match response.into_json::<Value>() {
            Ok(value) if parse(&value).is_some() => Ok(()),
            Ok(_) => Err("The classifier answered without a choice.".into()),
            Err(_) => Err("The classifier answered with something that is not JSON.".into()),
        },
        Err(ureq::Error::Status(401, _)) | Err(ureq::Error::Status(403, _)) => {
            Err("The classifier refused the key.".into())
        }
        Err(ureq::Error::Status(status, _)) => Err(format!("The classifier answered {status}.")),
        Err(ureq::Error::Transport(_)) => Err("The classifier did not answer.".into()),
    }
}

/// The last `STATE_LIMIT` bytes of the turn, on a character boundary. The tail
/// carries the request; the head is history the classifier does not need.
fn clip(state: &str) -> String {
    if state.len() <= STATE_LIMIT {
        return state.to_owned();
    }
    let mut start = state.len() - STATE_LIMIT;
    while start < state.len() && !state.is_char_boundary(start) {
        start += 1;
    }
    state[start..].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_router::config::{Classifier, Route, RouterConfig};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn routed(classifier: Classifier) -> RouterConfig {
        RouterConfig {
            enabled: true,
            classifier,
            routes: vec![
                Route {
                    key: "fast".into(),
                    description: "A short question".into(),
                    family: "openai".into(),
                    model: "gpt-5.6-mini".into(),
                },
                Route {
                    key: "deep".into(),
                    description: "A long reasoning task".into(),
                    family: "anthropic".into(),
                    model: "claude-opus-5".into(),
                },
            ],
            fallback: Some("fast".into()),
            min_confidence: 0.55,
            ..RouterConfig::default()
        }
    }

    fn typesafe(base_url: Option<String>) -> Classifier {
        Classifier::Typesafe {
            api_key: "apikey_1".into(),
            model: "jev-latest".into(),
            base_url,
        }
    }

    #[test]
    fn the_question_carries_every_route_as_an_option() {
        let config = routed(typesafe(None));
        let question = question(&config, "Why did the build fail?");
        assert_eq!(question["state"], "Why did the build fail?");
        assert_eq!(question["model"], "jev-latest");
        let choice = &question["questions"][QUESTION];
        assert_eq!(choice["type"], "choice");
        assert_eq!(choice["criteria"]["fast"], "A short question");
        assert_eq!(choice["criteria"]["deep"], "A long reasoning task");
    }

    #[test]
    fn a_system_one_answer_reads_as_a_choice_and_a_confidence() {
        let answer = json!({
            "model": "jev-1.13.0",
            "answers": { "route": {
                "type": "choice",
                "choice": "deep",
                "probabilities": { "fast": 0.08, "deep": 0.92 },
                "confidence": 0.82
            }},
            "usage": { "input_tokens": 312, "output_tokens": 48 }
        });
        assert_eq!(parse(&answer), Some(("deep".to_owned(), 0.82)));
        assert_eq!(
            parse(&json!({ "answers": { "route": { "choice": "fast" } } })),
            Some(("fast".to_owned(), 1.0))
        );
        assert_eq!(parse(&json!({ "answers": {} })), None);
        assert_eq!(parse(&json!({})), None);
    }

    #[test]
    fn with_no_classifier_every_turn_takes_the_fallback() {
        let config = routed(Classifier::None);
        let decision = decide(&config, &Ledger::default(), "anything", 1_000, TIMEOUT).unwrap();
        assert_eq!(decision.route.key, "fast");
        assert_eq!(decision.reason, Reason::NotClassified);
        // No route at all means the router has nothing to route to.
        let empty = RouterConfig::default();
        assert_eq!(
            decide(&empty, &Ledger::default(), "anything", 1_000, TIMEOUT),
            None
        );
    }

    #[test]
    fn a_confident_answer_takes_its_route_and_a_weak_one_falls_back() {
        let server = mock(json!({ "answers": { "route": {
            "choice": "deep", "confidence": 0.82
        }}}));
        let decision = decide(
            &routed(typesafe(Some(server.url.clone()))),
            &Ledger::default(),
            "prove it",
            1_000,
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(decision.route.key, "deep");
        assert_eq!(decision.route.model, "claude-opus-5");
        assert_eq!(decision.reason, Reason::Classified);
        assert_eq!(decision.confidence, 0.82);

        let weak = mock(json!({ "answers": { "route": {
            "choice": "deep", "confidence": 0.2
        }}}));
        let decision = decide(
            &routed(typesafe(Some(weak.url))),
            &Ledger::default(),
            "prove it",
            1_000,
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(decision.route.key, "fast");
        assert_eq!(decision.reason, Reason::LowConfidence);
        assert_eq!(decision.confidence, 0.2);
        assert_eq!(server.authorization(), Some("Bearer apikey_1".to_owned()));
    }

    #[test]
    fn a_classifier_that_does_not_answer_never_fails_the_turn() {
        // Nothing listens on port 9, so the call fails at the transport.
        let config = routed(typesafe(Some("http://127.0.0.1:9/v1/systemone".into())));
        let decision = decide(
            &config,
            &Ledger::default(),
            "prove it",
            1_000,
            Duration::from_millis(300),
        )
        .unwrap();
        assert_eq!(decision.route.key, "fast");
        assert_eq!(decision.reason, Reason::Failed);

        // An answer naming a route the configuration lost also falls back.
        let stray = mock(json!({ "answers": { "route": { "choice": "gone", "confidence": 0.99 }}}));
        let decision = decide(
            &routed(typesafe(Some(stray.url))),
            &Ledger::default(),
            "prove it",
            1_000,
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(decision.route.key, "fast");
        assert_eq!(decision.reason, Reason::Failed);
    }

    #[test]
    fn the_test_button_names_what_the_classifier_said() {
        let good = mock(json!({ "answers": { "route": { "choice": "fast", "confidence": 0.9 }}}));
        assert_eq!(check(&typesafe(Some(good.url)), TIMEOUT), Ok(()));
        let shapeless = mock(json!({ "answers": {} }));
        assert!(check(&typesafe(Some(shapeless.url)), TIMEOUT).is_err());
        assert!(check(&Classifier::None, TIMEOUT).is_err());
        let refused = mock_status(401, json!({ "error": "no" }));
        assert_eq!(
            check(&typesafe(Some(refused.url)), TIMEOUT),
            Err("The classifier refused the key.".into())
        );
    }

    #[test]
    fn a_long_turn_is_clipped_to_its_tail_on_a_character_boundary() {
        let state = format!("{}… the real question", "x".repeat(STATE_LIMIT));
        let clipped = clip(&state);
        assert!(clipped.len() <= STATE_LIMIT);
        assert!(clipped.ends_with("the real question"));
        assert_eq!(clip("short"), "short");
    }

    #[test]
    fn a_small_model_answers_the_same_choice_as_json() {
        assert_eq!(
            parse_pooled_answer("{\"choice\": \"deep\", \"confidence\": 0.8}"),
            Some(("deep".to_owned(), 0.8))
        );
        // A model that fenced its JSON, or wrote a sentence around it, still answers.
        assert_eq!(
            parse_pooled_answer("```json\n{\"choice\":\"fast\",\"confidence\":0.9}\n```"),
            Some(("fast".to_owned(), 0.9))
        );
        assert_eq!(
            parse_pooled_answer("Here you go: {\"choice\":\"fast\"} — hope that helps."),
            Some(("fast".to_owned(), 1.0))
        );
        // A confidence outside the range is pulled back into it.
        assert_eq!(
            parse_pooled_answer("{\"choice\":\"fast\",\"confidence\":7}"),
            Some(("fast".to_owned(), 1.0))
        );
        assert_eq!(parse_pooled_answer("no json here"), None);
        assert_eq!(parse_pooled_answer("{\"choice\":\"\"}"), None);
        assert_eq!(parse_pooled_answer("{}"), None);
    }

    #[test]
    fn a_pooled_classifier_spends_the_account_it_classified_on() {
        let answered = mock(json!({
            "choices": [{ "message": { "role": "assistant", "content": "{\"choice\":\"deep\",\"confidence\":0.91}" } }],
            "usage": { "prompt_tokens": 120, "completion_tokens": 9 }
        }));
        let mut config = routed(Classifier::Pooled {
            family: "openai".into(),
            model: "gpt-5.6-nano".into(),
        });
        config.accounts.push(crate::model_router::config::Account {
            id: "a1".into(),
            family: "openai".into(),
            label: "work".into(),
            credential: crate::model_router::config::Credential::ApiKey {
                key: "sk-a1".into(),
            },
            // The mock's URL already ends at the version, so the call lands on
            // its `/chat/completions`.
            base_url: Some(answered.url.trim_end_matches("/systemone").to_owned()),
            models: Vec::new(),
            enabled: true,
            weight: 1,
        });
        let decision = decide(&config, &Ledger::default(), "prove it", 1_000, TIMEOUT).unwrap();
        assert_eq!(decision.route.key, "deep");
        assert_eq!(decision.reason, Reason::Classified);
        assert_eq!(decision.confidence, 0.91);
        assert_eq!(decision.spent_on.as_deref(), Some("a1"));
        assert_eq!(decision.spent.input, 120);
        assert_eq!(decision.spent.output, 9);
        assert_eq!(answered.authorization(), Some("Bearer sk-a1".to_owned()));
    }

    #[test]
    fn a_pooled_classifier_with_no_account_falls_back_and_spends_nothing() {
        let config = routed(Classifier::Pooled {
            family: "openai".into(),
            model: "gpt-5.6-nano".into(),
        });
        let decision = decide(&config, &Ledger::default(), "prove it", 1_000, TIMEOUT).unwrap();
        assert_eq!(decision.route.key, "fast");
        assert_eq!(decision.reason, Reason::Failed);
        assert_eq!(decision.spent_on, None);
        assert_eq!(decision.spent, Tokens::default());
    }

    struct Mock {
        url: String,
        authorization: std::sync::mpsc::Receiver<Option<String>>,
    }

    impl Mock {
        fn authorization(&self) -> Option<String> {
            self.authorization.recv().ok().flatten()
        }
    }

    fn mock(body: Value) -> Mock {
        mock_status(200, body)
    }

    /// The value of one header in a request head, whatever its case.
    fn header(head: &str, name: &str) -> Option<String> {
        head.lines()
            .find(|line| line.to_ascii_lowercase().starts_with(&format!("{name}:")))
            .map(|line| line[name.len() + 1..].trim().to_owned())
    }

    /// One in-process HTTP server that answers one request with `body`. It
    /// drains the request body first: a server that closes on an unread body
    /// resets the connection and the client reads a transport failure.
    fn mock_status(status: u16, body: Value) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, authorization) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut head = Vec::new();
            let mut byte = [0_u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => break,
                }
            }
            let head = String::from_utf8_lossy(&head).to_string();
            let _ = sender.send(header(&head, "authorization"));
            let length: usize = header(&head, "content-length")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let mut request_body = vec![0_u8; length];
            let _ = stream.read_exact(&mut request_body);
            let payload = body.to_string();
            let response = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });
        Mock {
            url: format!("http://127.0.0.1:{port}/v1/systemone"),
            authorization,
        }
    }
}
