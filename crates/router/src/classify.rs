//! The optional query classifier that picks a route.
//!
//! Routing is optional. With no classifier every turn takes the fallback and
//! the balancer still spreads it across the pool. With one, the turn's last
//! user message goes to the classifier as one `choice` question whose options
//! are every model the pools serve, each carrying the statement that says what
//! work it wins. A confidence under the configured floor takes the fallback
//! instead, so a guess never silently picks the expensive model.
//!
//! The classifier is a network call to a service the user names, so it sends
//! the turn's text off the machine. Settings says so, and the default is off.

use std::time::Duration;

use serde_json::{json, Value};

use super::balance;
use super::config::{Classifier, Limits, Route, RouterConfig};
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

/// Thresholds belong to the exact endpoint/model, not to the catalog as a whole.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Profile {
    pub minimum: f64,
    pub score: Score,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            minimum: 0.6,
            score: Score::Native,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Score {
    #[default]
    Native,
    Probability,
}
pub fn profile_key(classifier: &Classifier) -> String {
    let location = match classifier {
        Classifier::Endpoint { base_url, .. } => base_url.as_str(),
        Classifier::Typesafe { base_url, .. } => base_url.as_deref().unwrap_or(TYPESAFE_URL),
        Classifier::Pooled { family, .. } => family.as_str(),
        Classifier::None => "none",
    };
    super::policy::digest(&format!(
        "{}|{}|{}",
        classifier.kind(),
        location,
        classifier.model()
    ))
}
pub fn profile(config: &RouterConfig) -> Profile {
    config
        .policy
        .classifier_profiles
        .get(&profile_key(&config.classifier))
        .cloned()
        .unwrap_or(Profile {
            minimum: config.min_confidence,
            ..Default::default()
        })
}
fn parse_profile(answer: &Value, options: &[Route], profile: &Profile) -> Option<(String, f64)> {
    let row = answer.get("answers")?.get(QUESTION)?;
    if row.get("type").is_some_and(|t| t != "choice")
        || row["abstain"] == true
        || row.get("status").is_some_and(|s| s != "ok")
    {
        return None;
    }
    let key = row["choice"].as_str()?;
    if !options.iter().any(|o| o.key == key) {
        return None;
    }
    let probability = if let Some(values) = row.get("probabilities") {
        let values = values.as_object()?;
        if values.len() != options.len() {
            return None;
        }
        let mut total = 0.0;
        let mut maximum = 0.0_f64;
        for option in options {
            let p = values.get(&option.key)?.as_f64()?;
            if !p.is_finite() || !(0.0..=1.0).contains(&p) {
                return None;
            }
            total += p;
            maximum = maximum.max(p);
        }
        let selected = values.get(key)?.as_f64()?;
        if (total - 1.0).abs() > 0.02 || selected + 0.0001 < maximum {
            return None;
        }
        Some(selected)
    } else {
        None
    };
    let score = match profile.score {
        Score::Native => row["confidence"].as_f64()?,
        Score::Probability => probability?,
    };
    (score.is_finite() && (0.0..=1.0).contains(&score)).then(|| (key.into(), score))
}

/// Why a turn took the route it took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No classifier is configured, or only one model is in the running.
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
    pub classifier: Option<super::wire::ClassifierUsage>,
}

impl Decision {
    fn plain(route: Route, confidence: f64, reason: Reason) -> Self {
        Self {
            route,
            confidence,
            reason,
            spent_on: None,
            spent: Tokens::default(),
            classifier: None,
        }
    }
}

/// What a pooled classifier is told, so a small model answers in one shape.
pub const POOLED_SYSTEM: &str = "You are a router. Read the request and pick exactly one option. Answer with one JSON object and nothing else: {\"choice\": \"<option name>\", \"confidence\": <0 to 1>}. The confidence is your own probability that the option is right.";

/// The `choice` question over every model in the running.
pub fn question(config: &RouterConfig, options: &[Route], state: &str) -> Value {
    let mut criteria = serde_json::Map::new();
    for option in options {
        criteria.insert(
            option.key.clone(),
            Value::String(option.description.clone()),
        );
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
    // Missing or invalid confidence must not authorize a model switch.
    let confidence = choice
        .get("confidence")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))?;
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
    options: &[Route],
    ledger: &Ledger,
    state: &str,
    now_ms: i64,
    timeout: Duration,
) -> Option<Decision> {
    decide_for(
        config,
        options,
        ledger,
        state,
        now_ms,
        timeout,
        INSTRUCTIONS,
    )
}

/// Reuses the classifier connection for capability selection without changing model routes.
#[allow(clippy::too_many_arguments)]
pub fn decide_for(
    config: &RouterConfig,
    options: &[Route],
    ledger: &Ledger,
    state: &str,
    now_ms: i64,
    timeout: Duration,
    instructions: &str,
) -> Option<Decision> {
    let fallback = super::fallback(config, options)?.clone();
    if !super::classifies(config, options) {
        return Some(Decision::plain(fallback, 0.0, Reason::NotClassified));
    }
    let asked = match &config.classifier {
        Classifier::Pooled { family, model } => ask_pool(
            PoolCall {
                config,
                options,
                ledger,
                family,
                model,
            },
            &format!("{instructions}\n\n{state}"),
            now_ms,
            timeout,
        ),
        _ => {
            let mut body = question(config, options, state);
            body["questions"][QUESTION]["instructions"] = json!(instructions);
            let Some(request) = build_request(&config.classifier, &body) else {
                return Some(Decision::plain(fallback, 0.0, Reason::NotClassified));
            };
            let response = ask(&request, timeout);
            Asked {
                answer: response
                    .as_ref()
                    .and_then(|answer| parse_profile(answer, options, &profile(config))),
                spent_on: None,
                spent: response.as_ref().and_then(super::wire::tokens),
            }
        }
    };
    let mut decision = select(config, options, asked.answer)?;
    decision.spent_on = asked.spent_on;
    decision.spent = asked.spent.unwrap_or_default();
    decision.classifier = Some(classifier_usage(&config.classifier, asked.spent));
    Some(decision)
}

/// Apply the desktop confidence and eligibility rules to an external observation.
pub fn select(
    config: &RouterConfig,
    options: &[Route],
    answer: Option<(String, f64)>,
) -> Option<Decision> {
    let fallback = super::fallback(config, options)?.clone();
    let Some((key, confidence)) =
        answer.filter(|(_, confidence)| confidence.is_finite() && (0.0..=1.0).contains(confidence))
    else {
        return Some(Decision::plain(fallback, 0.0, Reason::Failed));
    };
    let Some(route) = options.iter().find(|option| option.key == key) else {
        return Some(Decision::plain(fallback, confidence, Reason::Failed));
    };
    let threshold = profile(config).minimum;
    if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) || confidence < threshold {
        return Some(Decision::plain(fallback, confidence, Reason::LowConfidence));
    }
    Some(Decision::plain(
        route.clone(),
        confidence,
        Reason::Classified,
    ))
}

fn classifier_usage(
    classifier: &Classifier,
    tokens: Option<Tokens>,
) -> super::wire::ClassifierUsage {
    let (model, price) = match classifier {
        Classifier::Pooled { family, model } => (
            format!("{family}/{model}"),
            super::model_catalog::entry(family, model).map(|entry| (entry.price, entry.output)),
        ),
        Classifier::Endpoint {
            model, base_url, ..
        } if matches!(model.as_str(), "jev-latest" | "jev-preview" | "jev-1.13.0")
            && url::Url::parse(base_url)
                .ok()
                .is_some_and(|u| u.host_str() == Some("api.typesafe.ai")) =>
        {
            (format!("typesafe/{model}"), Some((0.042, 0.0)))
        }
        // The Decisions API bills input tokens only.
        Classifier::Endpoint {
            model, base_url, ..
        } if model == "gpt-6-luna" && openai_decisions(base_url) => {
            (format!("openai/{model}"), Some((0.10, 0.0)))
        }
        Classifier::Typesafe { model, .. } => (
            format!("typesafe/{model}"),
            matches!(model.as_str(), "jev-latest" | "jev-preview" | "jev-1.13.0")
                .then_some((0.042, 0.0)),
        ),
        _ => (classifier.model().to_owned(), None),
    };
    let cost = tokens.zip(price).map(|(tokens, (input, output))| {
        (tokens.input as f64 * input + tokens.output as f64 * output) / 1_000_000.0
    });
    super::wire::ClassifierUsage {
        model,
        tokens,
        cost,
    }
}

/// What one classifier call came back with.
struct Asked {
    answer: Option<(String, f64)>,
    spent_on: Option<String>,
    spent: Option<Tokens>,
}

/// The pool one classifier call reaches, and the choice it is given.
struct PoolCall<'a> {
    config: &'a RouterConfig,
    options: &'a [Route],
    ledger: &'a Ledger,
    family: &'a str,
    model: &'a str,
}

/// A pooled classifier: the balancer picks an account of the classifier's
/// family and a small model on it answers the same choice as JSON.
fn ask_pool(call: PoolCall<'_>, state: &str, now_ms: i64, timeout: Duration) -> Asked {
    let PoolCall {
        config,
        options,
        ledger,
        family,
        model,
    } = call;
    let empty = Asked {
        answer: None,
        spent_on: None,
        spent: None,
    };
    let Ok(account) = balance::pick(config, ledger, family, model, now_ms) else {
        return empty;
    };
    let listed = options
        .iter()
        .map(|option| format!("- {}: {}", option.key, option.description))
        .collect::<Vec<_>>()
        .join("\n");
    let body = json!({
        "model": model,
        "temperature": 0,
        "max_tokens": 128,
        "messages": [
            { "role": "system", "content": format!("{POOLED_SYSTEM}\n\nThe options:\n{listed}") },
            { "role": "user", "content": clip(state) },
        ],
    });
    let agent = crate::http::agent_builder()
        .redirects(0)
        .timeout(timeout)
        .build();
    let Ok(prepared) = super::transport::prepare(account, &body, model) else {
        return empty;
    };
    let mut call = agent
        .post(&prepared.url)
        .set("content-type", "application/json");
    for (name, value) in &prepared.headers {
        call = call.set(name, value);
    }
    let answered = call
        .send_json(&prepared.body)
        .ok()
        .and_then(|response| super::transport::collect(response, prepared.protocol, model).ok());
    // A call the upstream refused or never answered spent nothing the ledger
    // can count, and naming the account here would record a served turn on
    // an account that just refused one.
    let Some(answered) = answered else {
        return empty;
    };
    Asked {
        answer: answered
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            .and_then(|choice| choice.get("message")?.get("content")?.as_str())
            .and_then(parse_pooled_answer),
        spent_on: Some(account.id.clone()),
        spent: super::wire::tokens(&answered),
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

/// OpenAI's Decisions API, which only an OpenAI API key reaches.
pub const OPENAI_DECISIONS_URL: &str = "https://api.openai.com/v1/decisions";

fn openai_decisions(url: &str) -> bool {
    url::Url::parse(url).ok().is_some_and(|url| {
        url.host_str() == Some("api.openai.com") && url.path().ends_with("/decisions")
    })
}

// Workers AI wraps the same decision request in its model/input envelope.
// OpenAI's Decisions API takes the state as text and the questions as a list
// of named `choice` questions whose choices carry their descriptions.
fn classifier_body(url: &str, body: &Value) -> Value {
    if openai_decisions(url) {
        let input = match &body["state"] {
            Value::String(text) => text.clone(),
            state => state.to_string(),
        };
        let questions: Vec<Value> = body["questions"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(name, question)| {
                let choices: Vec<Value> = question["criteria"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(|(value, description)| json!({"value": value, "description": description}))
                    .collect();
                json!({"type": "choice", "name": name, "instructions": question["instructions"], "choices": choices})
            })
            .collect();
        return json!({"model": body["model"], "input": input, "questions": questions});
    }
    let cloudflare = url::Url::parse(url).ok().is_some_and(|url| {
        url.host_str() == Some("api.cloudflare.com") && url.path().ends_with("/ai/run")
    });
    if cloudflare {
        let mut input = body.clone();
        if let Some(object) = input.as_object_mut() {
            object.remove("model");
        }
        json!({ "model": body["model"], "input": input })
    } else {
        body.clone()
    }
}

/// The answers out of a Workers AI envelope. Cloudflare's own models, such as
/// Clef, put them under `result`. A third-party model, such as Jev, puts them
/// under a completed run record: `result.state` and `result.result`.
fn classifier_response(value: Value) -> Value {
    if value.get("answers").is_some_and(Value::is_array) {
        return decisions_response(value);
    }
    let Some(result) = value.get("result").filter(|result| result.is_object()) else {
        return value;
    };
    if result.get("answers").is_none() && result.get("state") == Some(&json!("Completed")) {
        if let Some(run) = result.get("result").filter(|run| run.is_object()) {
            return run.clone();
        }
    }
    result.clone()
}

/// OpenAI's Decisions answers, a list of named answers whose probabilities
/// are a list of `{value, probability}`, in System One's answers-by-name
/// shape. A refusal reads as an abstention.
fn decisions_response(mut value: Value) -> Value {
    let mut answers = serde_json::Map::new();
    for answer in value["answers"].as_array().into_iter().flatten() {
        let Some(name) = answer["name"].as_str() else {
            continue;
        };
        let row = if answer["type"] == "choice" {
            let probabilities: serde_json::Map<String, Value> = answer["probabilities"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|entry| {
                    Some((
                        entry["value"].as_str()?.to_owned(),
                        entry["probability"].clone(),
                    ))
                })
                .collect();
            json!({"type": "choice", "choice": answer["choice"], "confidence": answer["confidence"],
                "probabilities": probabilities})
        } else {
            json!({"type": answer["type"], "abstain": true})
        };
        answers.insert(name.to_owned(), row);
    }
    value["answers"] = Value::Object(answers);
    value
}

/// The exact request one classifier call sends: where, under which bearer,
/// and with which JSON body.
#[derive(Clone, PartialEq)]
pub struct Request {
    pub url: String,
    pub bearer: Option<String>,
    pub body: Value,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("url", &self.url)
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .field("body", &self.body)
            .finish()
    }
}

/// The request for a System One body (`state`, `model`, `questions`), shaped
/// for the classifier's endpoint. `None` when the classifier has no endpoint.
pub fn build_request(classifier: &Classifier, body: &Value) -> Option<Request> {
    let (url, bearer) = endpoint(classifier)?;
    let body = classifier_body(&url, body);
    Some(Request { url, bearer, body })
}

/// The request for asking `questions` about `state`.
pub fn request(classifier: &Classifier, state: &Value, questions: &Value) -> Option<Request> {
    build_request(
        classifier,
        &json!({"state": state, "model": classifier.model(), "questions": questions}),
    )
}

/// What one classifier call came back with, and how it went.
#[derive(Debug, Clone, PartialEq)]
pub struct Sent {
    /// The answer in System One's shape, once any envelope is unwrapped.
    pub answer: Option<Value>,
    /// The answers by question name, when the answer carries them.
    pub answers: Option<serde_json::Map<String, Value>>,
    /// The HTTP status, when the classifier replied at all.
    pub status: Option<u16>,
    /// Why the call produced no answers: a non-2xx status, a body that is not
    /// JSON, an answer without answers, or a transport failure.
    pub error: Option<String>,
    pub latency: Duration,
    /// The usage the answer reports.
    pub usage: Option<Tokens>,
}

fn agent(timeout: Duration) -> ureq::Agent {
    crate::http::agent_builder()
        .redirects(0)
        .timeout(timeout)
        .build()
}

/// Sends a request and reports the answers with the status or error text, the
/// latency and the reported usage.
pub fn send(request: &Request, timeout: Duration) -> Sent {
    send_on(&agent(timeout), request)
}

fn send_on(agent: &ureq::Agent, request: &Request) -> Sent {
    let started = std::time::Instant::now();
    let mut call = agent
        .post(&request.url)
        .set("content-type", "application/json");
    if let Some(bearer) = &request.bearer {
        call = call.set("authorization", &format!("Bearer {bearer}"));
    }
    let mut sent = Sent {
        answer: None,
        answers: None,
        status: None,
        error: None,
        latency: Duration::ZERO,
        usage: None,
    };
    match call.send_json(&request.body) {
        Ok(response) => {
            let status = response.status();
            sent.status = Some(status);
            if !(200..300).contains(&status) {
                sent.error = Some(format!("The decision model answered {status}."));
            } else {
                match response.into_json::<Value>() {
                    Ok(value) => {
                        let answer = classifier_response(value);
                        sent.usage = super::wire::tokens(&answer);
                        match answer.get("answers") {
                            Some(Value::Object(answers)) => sent.answers = Some(answers.clone()),
                            _ => sent.error = Some("The decision model sent no answers.".into()),
                        }
                        sent.answer = Some(answer);
                    }
                    Err(_) => {
                        sent.error = Some(
                            "The decision model answered with something that is not JSON.".into(),
                        );
                    }
                }
            }
        }
        Err(ureq::Error::Status(status, _)) => {
            sent.status = Some(status);
            sent.error = Some(format!("The decision model answered {status}."));
        }
        Err(ureq::Error::Transport(error)) => {
            sent.error = Some(format!(
                "The decision model did not answer: {:?} {}",
                error.kind(),
                error.message().unwrap_or_default()
            ));
        }
    }
    sent.latency = started.elapsed();
    sent
}

/// One classifier call. Nothing here fails a turn: an unreachable classifier,
/// a refusal and a body that is not JSON all read as no answer.
fn ask(request: &Request, timeout: Duration) -> Option<Value> {
    send(request, timeout).answer
}

/// Asks a decision model several `choice` questions about one state in one
/// request, and answers System One's answers by question name. Only a System
/// One route, Workers AI or OpenAI's Decisions API answers. A pooled chat
/// model does not.
pub fn ask_choices(
    classifier: &Classifier,
    state: &Value,
    questions: &Value,
    timeout: Duration,
) -> Result<serde_json::Map<String, Value>, String> {
    ask_choices_on(&agent(timeout), classifier, state, questions)
}

fn ask_choices_on(
    agent: &ureq::Agent,
    classifier: &Classifier,
    state: &Value,
    questions: &Value,
) -> Result<serde_json::Map<String, Value>, String> {
    let request =
        request(classifier, state, questions).ok_or("Connect a decision model in Settings.")?;
    let sent = send_on(agent, &request);
    if sent.answer.is_none() {
        return Err("The decision model did not answer.".into());
    }
    sent.answers
        .ok_or_else(|| "The decision model sent no answers.".into())
}

/// Whether the classifier answers at all, for the Test button in Settings.
pub fn check(classifier: &Classifier, timeout: Duration) -> Result<(), String> {
    check_profile(classifier, &Profile::default(), timeout)
}
pub fn check_profile(
    classifier: &Classifier,
    profile: &Profile,
    timeout: Duration,
) -> Result<(), String> {
    let options: Vec<Route> = ["fast", "deep"]
        .into_iter()
        .map(|key| Route {
            key: key.into(),
            family: String::new(),
            model: String::new(),
            description: String::new(),
        })
        .collect();
    let probe = json!({
        "state": "A short question about the weather.",
        "model": classifier.model(),
        "questions": { QUESTION: {
            "type": "choice",
            "instructions": INSTRUCTIONS,
            "criteria": { "fast": "A short question", "deep": "A long reasoning task" },
        }},
    });
    let Some(prepared) = build_request(classifier, &probe) else {
        return Err("No classifier is configured.".into());
    };
    let sent = send(&prepared, timeout);
    match (sent.status, sent.answer) {
        (Some(401 | 403), _) => Err("The classifier refused the key.".into()),
        (Some(status), _) if !(200..300).contains(&status) => {
            Err(format!("The classifier answered {status}."))
        }
        (None, _) => Err("The classifier did not answer.".into()),
        (Some(_), None) => Err("The classifier answered with something that is not JSON.".into()),
        (Some(_), Some(answer)) if parse_profile(&answer, &options, profile).is_some() => Ok(()),
        (Some(_), Some(_)) => Err("The classifier answered without a choice.".into()),
    }
}

/// How many options (and questions) a probe carries. A provider that accepts
/// it has a limit of at least this many.
const PROBE_SIZE: u32 = 256;

/// What a probe request came back with.
enum Probed {
    /// The provider accepted the request.
    Accepted,
    /// The provider refused the request with this body.
    Refused(String),
    /// No answer, or a refusal that carries no body to read.
    Silent,
}

/// Sends one probe body and reports how the provider took it.
fn probe(agent: &ureq::Agent, url: &str, bearer: Option<&str>, body: &Value) -> Probed {
    let mut request = agent.post(url).set("content-type", "application/json");
    if let Some(bearer) = bearer {
        request = request.set("authorization", &format!("Bearer {bearer}"));
    }
    match request.send_json(classifier_body(url, body)) {
        Ok(_) => Probed::Accepted,
        Err(ureq::Error::Status(_, response)) => response
            .into_string()
            .map_or(Probed::Silent, Probed::Refused),
        Err(ureq::Error::Transport(_)) => Probed::Silent,
    }
}

/// The largest count a rejection message allows. It reads a range such as
/// "must contain 2–26 candidates" (en dash or hyphen) and a bound such as
/// "at most 255 choices". A message that names neither gives no limit.
pub fn parse_maximum(message: &str) -> Option<u32> {
    // A JSON body may carry the en dash as an escape.
    let text = message.to_lowercase().replace("\\u2013", "\u{2013}");
    let number = |from: &str| -> Option<(u32, usize)> {
        let from = from.trim_start();
        let digits = from.chars().take_while(char::is_ascii_digit).count();
        Some((from.get(..digits)?.parse().ok()?, from.len() - digits))
    };
    let maximum = if let Some(at) = text.find("at most ") {
        number(&text[at + "at most ".len()..])?.0
    } else {
        let at = text.find("must contain ")?;
        let (_, rest) = number(&text[at + "must contain ".len()..])?;
        let rest = &text[text.len() - rest..];
        let rest = rest.trim_start().strip_prefix(['\u{2013}', '-'])?;
        number(rest)?.0
    };
    (maximum > 0).then_some(maximum)
}

/// The count a probe teaches: the maximum its rejection names, or the probe
/// size when the provider accepted it.
fn learned(probed: Probed) -> Option<u32> {
    match probed {
        Probed::Accepted => Some(PROBE_SIZE),
        Probed::Refused(message) => parse_maximum(&message),
        Probed::Silent => None,
    }
}

/// The largest count a text states as a range from 2, such as "2 to 255
/// options". Text without that range gives no limit.
fn parse_range(text: &str) -> Option<u32> {
    let mut rest = text;
    while let Some(at) = rest.find("2 to ") {
        rest = &rest[at + "2 to ".len()..];
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        if let Some(maximum) = rest[..digits].parse::<u32>().ok().filter(|n| *n > 0) {
            return Some(maximum);
        }
    }
    None
}

/// The first "2 to N" range in any string of a JSON value.
fn range_in(value: &Value) -> Option<u32> {
    match value {
        Value::String(text) => parse_range(text),
        Value::Array(items) => items.iter().find_map(range_in),
        Value::Object(map) => map.values().find_map(range_in),
        _ => None,
    }
}

/// The `questions` property of a published input schema, wherever it nests.
fn questions_schema(value: &Value) -> Option<&Value> {
    match value {
        Value::Object(map) => map
            .get("questions")
            .filter(|node| node.is_object())
            .or_else(|| map.values().find_map(questions_schema)),
        Value::Array(items) => items.iter().find_map(questions_schema),
        _ => None,
    }
}

/// The limits a Workers AI model schema states: `maxProperties` on the
/// questions, and the "2 to N" text that describes the options.
fn schema_limits(schema: &Value) -> Limits {
    Limits {
        options: range_in(questions_schema(schema).unwrap_or(schema)),
        questions: questions_schema(schema)
            .and_then(|node| node.get("maxProperties"))
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .filter(|count| *count > 0),
    }
}

/// The JSON a GET returns, or `None` when the request fails, is refused or
/// answers something that is not JSON.
fn get_json(agent: &ureq::Agent, url: &str, bearer: Option<&str>) -> Option<Value> {
    let mut request = agent.get(url);
    if let Some(bearer) = bearer {
        request = request.set("authorization", &format!("Bearer {bearer}"));
    }
    request.call().ok()?.into_json().ok()
}

/// The Workers AI model schema URL for a run URL, with the model in the query.
fn schema_url(url: &str, model: &str) -> Option<String> {
    let mut parsed = url::Url::parse(url).ok()?;
    if parsed.host_str() != Some("api.cloudflare.com") {
        return None;
    }
    let path = parsed.path().strip_suffix("/ai/run")?.to_owned();
    parsed.set_path(&format!("{path}/ai/models/schema"));
    parsed.set_query(None);
    parsed.query_pairs_mut().append_pair("model", model);
    Some(parsed.into())
}

/// Ollama's `/api/show` URL for an endpoint URL.
fn show_url(url: &str) -> Option<String> {
    let mut parsed = url::Url::parse(url).ok()?;
    parsed.set_path("/api/show");
    parsed.set_query(None);
    Some(parsed.into())
}

/// The limits the provider publishes for the classifier's model. Workers AI
/// states them in the model schema. Ollama's `/api/show` lists the `decision`
/// capability, which states no count unless an entry carries a "2 to N"
/// range. Metadata that is missing or unreadable states nothing.
fn published(
    agent: &ureq::Agent,
    classifier: &Classifier,
    url: &str,
    bearer: Option<&str>,
) -> Limits {
    if let Some(schema) = schema_url(url, classifier.model()) {
        return get_json(agent, &schema, bearer)
            .map(|schema| schema_limits(&schema))
            .unwrap_or_default();
    }
    if !matches!(classifier, Classifier::Endpoint { .. }) || openai_decisions(url) {
        return Limits::default();
    }
    let Some(show) = show_url(url) else {
        return Limits::default();
    };
    let mut request = agent.post(&show);
    if let Some(bearer) = bearer {
        request = request.set("authorization", &format!("Bearer {bearer}"));
    }
    let Some(shown) = request
        .send_json(json!({"model": classifier.model()}))
        .ok()
        .and_then(|response| response.into_json::<Value>().ok())
    else {
        return Limits::default();
    };
    let decision = shown
        .get("capabilities")
        .and_then(Value::as_array)
        .filter(|capabilities| capabilities.iter().any(|name| name == "decision"));
    Limits {
        options: decision.and_then(|capabilities| capabilities.iter().find_map(range_in)),
        questions: None,
    }
}

/// Learns the limits of a decision connection. A question limit that
/// `metadata` states stands and skips its probe. A limit that the provider's
/// published model metadata states also skips its probe. Otherwise one `choice` question with 256 options teaches the options per
/// question, and one request with 256 questions teaches the questions per
/// request. An accepted probe records 256 as a floor, and a refusal that names
/// no maximum teaches nothing.
pub fn learn(classifier: &Classifier, metadata: &Limits, timeout: Duration) -> Limits {
    learn_on(&agent(timeout), classifier, metadata)
}

fn learn_on(agent: &ureq::Agent, classifier: &Classifier, metadata: &Limits) -> Limits {
    let Some((url, bearer)) = endpoint(classifier) else {
        return Limits::default();
    };
    let published = if metadata.questions.is_some() {
        Limits::default()
    } else {
        published(agent, classifier, &url, bearer.as_deref())
    };
    let ask = |questions: Value| {
        probe(
            agent,
            &url,
            bearer.as_deref(),
            &json!({
                "state": "A short question about the weather.",
                "model": classifier.model(),
                "questions": questions,
            }),
        )
    };
    let question = |count: u32| {
        let criteria: serde_json::Map<String, Value> = (0..count)
            .map(|index| (format!("option-{index}"), json!("A candidate")))
            .collect();
        json!({ "type": "choice", "instructions": INSTRUCTIONS, "criteria": criteria })
    };
    let options = published
        .options
        .or_else(|| learned(ask(json!({ QUESTION: question(PROBE_SIZE) }))));
    let questions = metadata.questions.or(published.questions).or_else(|| {
        let many: serde_json::Map<String, Value> = (0..PROBE_SIZE)
            .map(|index| (format!("{QUESTION}-{index}"), question(2)))
            .collect();
        learned(ask(Value::Object(many)))
    });
    Limits { options, questions }
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
    use crate::config::{Classifier, Route, RouterConfig};
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
            max_options: None,
            limits: Default::default(),
        }
    }

    /// One decision over a configuration's own routes as the option set, which
    /// is what `options` builds from a pool that serves exactly those models.
    fn decided(config: &RouterConfig, state: &str, timeout: Duration) -> Option<Decision> {
        decide(
            config,
            &config.routes,
            &Ledger::default(),
            state,
            1_000,
            timeout,
        )
    }

    #[test]
    fn the_question_carries_every_route_as_an_option() {
        let config = routed(typesafe(None));
        let question = question(&config, &config.routes, "Why did the build fail?");
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
            None
        );
        assert_eq!(parse(&json!({ "answers": {} })), None);
        assert_eq!(parse(&json!({})), None);
    }

    #[test]
    fn with_no_classifier_every_turn_takes_the_fallback() {
        let config = routed(Classifier::None);
        let decision = decided(&config, "anything", TIMEOUT).unwrap();
        assert_eq!(decision.route.key, "fast");
        assert_eq!(decision.reason, Reason::NotClassified);
        // No route at all means the router has nothing to route to.
        let empty = RouterConfig::default();
        assert_eq!(decided(&empty, "anything", TIMEOUT), None);
    }

    #[test]
    fn typesafe_usage_survives_fallback_and_uses_input_only_pricing() {
        let server = mock(
            json!({"answers":{"route":{"choice":"deep","confidence":0.2}},
            "usage":{"input_tokens":1000,"output_tokens":12}}),
        );
        let config = routed(typesafe(Some(server.url)));
        let decision = decided(&config, "test", TIMEOUT).unwrap();
        assert_eq!(decision.reason, Reason::LowConfidence);
        let usage = decision.classifier.unwrap();
        assert_eq!(
            usage.tokens,
            Some(Tokens {
                input: 1000,
                output: 12,
                ..Default::default()
            })
        );
        assert_eq!(usage.cost, Some(0.000042));
        assert!(classifier_usage(&config.classifier, None).cost.is_none());
    }

    #[test]
    fn a_confident_answer_takes_its_route_and_a_weak_one_falls_back() {
        let server = mock(json!({ "answers": { "route": {
            "choice": "deep", "confidence": 0.82
        }}}));
        let config = routed(typesafe(Some(server.url.clone())));
        let decision = decided(&config, "prove it", TIMEOUT).unwrap();
        assert_eq!(decision.route.key, "deep");
        assert_eq!(decision.route.model, "claude-opus-5");
        assert_eq!(decision.reason, Reason::Classified);
        assert_eq!(decision.confidence, 0.82);

        let weak = mock(json!({ "answers": { "route": {
            "choice": "deep", "confidence": 0.2
        }}}));
        let weak_config = routed(typesafe(Some(weak.url)));
        let decision = decided(&weak_config, "prove it", TIMEOUT).unwrap();
        assert_eq!(decision.route.key, "fast");
        assert_eq!(decision.reason, Reason::LowConfidence);
        assert_eq!(decision.confidence, 0.2);
        assert_eq!(server.authorization(), Some("Bearer apikey_1".to_owned()));
    }

    #[test]
    fn a_classifier_that_does_not_answer_never_fails_the_turn() {
        // Nothing listens on port 9, so the call fails at the transport.
        let config = routed(typesafe(Some("http://127.0.0.1:9/v1/systemone".into())));
        let decision = decided(&config, "prove it", Duration::from_millis(300)).unwrap();
        assert_eq!(decision.route.key, "fast");
        assert_eq!(decision.reason, Reason::Failed);

        // An answer naming a route the configuration lost also falls back.
        let stray = mock(json!({ "answers": { "route": { "choice": "gone", "confidence": 0.99 }}}));
        let stray_config = routed(typesafe(Some(stray.url)));
        let decision = decided(&stray_config, "prove it", TIMEOUT).unwrap();
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
            parse_pooled_answer("Here you go: {\"choice\":\"fast\"} and I hope that helps."),
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
        config.accounts.push(crate::config::Account {
            id: "a1".into(),
            family: "openai".into(),
            label: "work".into(),
            credential: crate::config::Credential::ApiKey {
                key: "sk-a1".into(),
            },
            // The mock's URL already ends at the version, so the call lands on
            // its `/chat/completions`.
            base_url: Some(answered.url.trim_end_matches("/systemone").to_owned()),
            models: Vec::new(),
            enabled: true,
            weight: 1,
        });
        let decision = decided(&config, "prove it", TIMEOUT).unwrap();
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
        let decision = decided(&config, "prove it", TIMEOUT).unwrap();
        assert_eq!(decision.route.key, "fast");
        assert_eq!(decision.reason, Reason::Failed);
        assert_eq!(decision.spent_on, None);
        assert_eq!(decision.spent, Tokens::default());
    }

    /// A server that answers every request with one status and body, and
    /// counts the requests it served.
    fn serve(status: u16, body: &str) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served = count.clone();
        let body = body.to_owned();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut head = Vec::new();
                let mut byte = [0_u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let length: usize = header(&head, "content-length")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let mut request_body = vec![0_u8; length];
                let _ = stream.read_exact(&mut request_body);
                served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (format!("http://127.0.0.1:{port}/v1/systemone"), count)
    }

    fn learned_from(status: u16, body: &str, metadata: Limits) -> (Limits, usize) {
        let (url, count) = serve(status, body);
        let limits = learn(&typesafe(Some(url)), &metadata, TIMEOUT);
        (limits, count.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[test]
    fn a_rejection_message_names_the_maximum() {
        // Ollama, with an en dash and with a hyphen.
        assert_eq!(
            parse_maximum("criteria must contain 2\u{2013}26 candidates"),
            Some(26)
        );
        assert_eq!(
            parse_maximum("criteria must contain 2-26 candidates"),
            Some(26)
        );
        // TypeSafe and Cloudflare.
        assert_eq!(parse_maximum("Must have at most 255 choices"), Some(255));
        assert_eq!(
            parse_maximum(r#"{"errors":[{"message":"too big: at most 255 items"}]}"#),
            Some(255)
        );
        assert_eq!(parse_maximum("something went wrong"), None);
        assert_eq!(parse_maximum("criteria must contain 2 candidates"), None);
        assert_eq!(parse_maximum(""), None);
    }

    #[test]
    fn each_provider_error_teaches_its_maximum() {
        for (message, expected) in [
            (
                r#"{"error":"criteria must contain 2\u201326 candidates"}"#,
                26,
            ),
            (r#"{"error":"Must have at most 255 choices"}"#, 255),
            (r#"{"errors":[{"message":"at most 255 items"}]}"#, 255),
        ] {
            let limits = learned_from(
                400,
                message,
                Limits {
                    options: None,
                    questions: Some(1),
                },
            )
            .0;
            assert_eq!(limits.options, Some(expected), "{message}");
        }
    }

    #[test]
    fn an_accepted_probe_records_the_floor() {
        let (limits, requests) = learned_from(200, "{}", Limits::default());
        assert_eq!(limits.options, Some(256));
        assert_eq!(limits.questions, Some(256));
        assert_eq!(requests, 2);
    }

    #[test]
    fn a_message_with_no_maximum_yields_no_limit() {
        let (limits, _) = learned_from(400, r#"{"error":"bad request"}"#, Limits::default());
        assert_eq!(limits, Limits::default());
        let (limits, _) = learned_from(401, "", Limits::default());
        assert_eq!(limits, Limits::default());
    }

    #[test]
    fn the_question_probe_is_skipped_when_metadata_states_the_limit() {
        let metadata = Limits {
            options: None,
            questions: Some(8),
        };
        let (limits, requests) = learned_from(400, "at most 255 choices", metadata);
        assert_eq!(limits.options, Some(255));
        assert_eq!(limits.questions, Some(8));
        assert_eq!(requests, 1);
        // Without metadata the second probe runs and reads its own message.
        let (limits, requests) = learned_from(400, "at most 255 items", Limits::default());
        assert_eq!(limits.questions, Some(255));
        assert_eq!(requests, 2);
    }

    /// A server that answers by request path, and records `METHOD path` for
    /// every request. An unknown path answers 404.
    fn route_server(
        routes: Vec<(&'static str, u16, String)>,
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut head = Vec::new();
                let mut byte = [0_u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let length: usize = header(&head, "content-length")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let mut request_body = vec![0_u8; length];
                let _ = stream.read_exact(&mut request_body);
                let mut line = head.lines().next().unwrap_or_default().split_whitespace();
                let method = line.next().unwrap_or_default();
                let target = line.next().unwrap_or_default();
                log.lock().unwrap().push(format!("{method} {target}"));
                let path = target.split('?').next().unwrap_or_default();
                let (status, body) = routes
                    .iter()
                    .find(|(route, ..)| *route == path)
                    .map_or((404, String::new()), |(_, status, body)| {
                        (*status, body.clone())
                    });
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (port, seen)
    }

    fn redirected_agent(port: u16) -> ureq::Agent {
        crate::http::agent_builder()
            .redirects(0)
            .timeout(TIMEOUT)
            .resolver(move |_: &str| Ok(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))]))
            .build()
    }

    fn cloudflare() -> Classifier {
        Classifier::Endpoint {
            base_url: "http://api.cloudflare.com/client/v4/accounts/abc/ai/run".into(),
            api_key: Some("cf-token".into()),
            model: "typesafe/jev".into(),
            max_options: None,
            limits: Limits::default(),
        }
    }

    #[test]
    fn a_published_cloudflare_schema_sets_the_limits_without_a_question_probe() {
        let schema = json!({"result": {"input": {"properties": {"questions": {
            "maxProperties": 64,
            "description": "Each choice question takes 2 to 255 options.",
        }}}}});
        let (port, seen) = route_server(vec![(
            "/client/v4/accounts/abc/ai/models/schema",
            200,
            schema.to_string(),
        )]);
        let limits = learn_on(&redirected_agent(port), &cloudflare(), &Limits::default());
        assert_eq!(limits.questions, Some(64));
        assert_eq!(limits.options, Some(255));
        assert_eq!(
            *seen.lock().unwrap(),
            ["GET /client/v4/accounts/abc/ai/models/schema?model=typesafe%2Fjev"]
        );
    }

    #[test]
    fn a_schema_that_states_only_the_questions_still_probes_the_options() {
        let schema = json!({"questions": {"maxProperties": 64}});
        let (port, seen) = route_server(vec![
            (
                "/client/v4/accounts/abc/ai/models/schema",
                200,
                schema.to_string(),
            ),
            (
                "/client/v4/accounts/abc/ai/run",
                400,
                "at most 200 choices".into(),
            ),
        ]);
        let limits = learn_on(&redirected_agent(port), &cloudflare(), &Limits::default());
        assert_eq!(limits.questions, Some(64));
        assert_eq!(limits.options, Some(200));
        let posts = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.starts_with("POST"))
            .count();
        assert_eq!(posts, 1);
    }

    #[test]
    fn an_unreadable_schema_falls_through_to_the_probe() {
        for (status, body) in [(200, "not json"), (500, ""), (404, "{}"), (200, "{}")] {
            let (port, seen) = route_server(vec![
                (
                    "/client/v4/accounts/abc/ai/models/schema",
                    status,
                    body.into(),
                ),
                (
                    "/client/v4/accounts/abc/ai/run",
                    400,
                    "at most 255 choices".into(),
                ),
            ]);
            let limits = learn_on(&redirected_agent(port), &cloudflare(), &Limits::default());
            assert_eq!(limits.options, Some(255), "{status} {body}");
            assert_eq!(limits.questions, Some(255), "{status} {body}");
            let posts = seen
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request.starts_with("POST"))
                .count();
            assert_eq!(posts, 2, "{status} {body}");
        }
    }

    #[test]
    fn the_decision_capability_alone_still_falls_through_to_the_probe() {
        let shown = json!({"capabilities": ["completion", "decision"]});
        let (port, seen) = route_server(vec![
            ("/api/show", 200, shown.to_string()),
            (
                "/v1/systemone",
                400,
                "criteria must contain 2-26 candidates".into(),
            ),
        ]);
        let classifier = Classifier::Endpoint {
            base_url: format!("http://127.0.0.1:{port}/v1/systemone"),
            api_key: None,
            model: "kev".into(),
            max_options: None,
            limits: Limits::default(),
        };
        let limits = learn(&classifier, &Limits::default(), TIMEOUT);
        assert_eq!(limits.options, Some(26));
        assert_eq!(limits.questions, Some(26));
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0], "POST /api/show");
        let probes = seen
            .iter()
            .filter(|request| *request == "POST /v1/systemone")
            .count();
        assert_eq!(probes, 2);
    }

    #[test]
    fn a_missing_show_endpoint_falls_through_to_the_probe() {
        let (port, _) = route_server(vec![(
            "/v1/systemone",
            400,
            "criteria must contain 2-26 candidates".into(),
        )]);
        let classifier = Classifier::Endpoint {
            base_url: format!("http://127.0.0.1:{port}/v1/systemone"),
            api_key: None,
            model: "kev".into(),
            max_options: None,
            limits: Limits::default(),
        };
        let limits = learn(&classifier, &Limits::default(), TIMEOUT);
        assert_eq!(limits.options, Some(26));
    }

    #[test]
    fn a_classifier_with_no_endpoint_learns_nothing() {
        assert_eq!(
            learn(&Classifier::None, &Limits::default(), TIMEOUT),
            Limits::default()
        );
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

#[cfg(test)]
mod connection_wire_tests {
    use super::*;
    #[test]
    fn cloudflare_answers_read_from_both_envelopes() {
        let answers = json!({ "answers": { "route": { "choice": "fast" } } });
        // Clef answers under `result`.
        assert_eq!(
            classifier_response(json!({ "success": true, "result": answers.clone() })),
            answers
        );
        // Jev answers under a completed run record.
        assert_eq!(
            classifier_response(
                json!({ "success": true, "result": { "state": "Completed", "result": answers.clone() } })
            ),
            answers
        );
        assert_eq!(classifier_response(answers.clone()), answers);
    }

    #[test]
    fn cloudflare_wraps_only_its_own_endpoint() {
        let body = json!({"model":"typesafe/jev", "state":"sample", "questions":{"route":{"type":"choice"}}});
        let wrapped = classifier_body(
            "https://api.cloudflare.com/client/v4/accounts/abc/ai/run",
            &body,
        );
        assert_eq!(wrapped["model"], "typesafe/jev");
        assert_eq!(wrapped["input"]["state"], "sample");
        assert!(wrapped["input"].get("model").is_none());
        assert_eq!(
            classifier_body("https://openrouter.ai/api/v1/systemone", &body),
            body
        );
        assert_eq!(classifier_body("http://127.0.0.1:8000/ai/run", &body), body);
        let answer = json!({"answers":{"route":{"choice":"fast","confidence":0.9}}});
        assert_eq!(
            classifier_response(json!({"success":true,"result":answer})),
            answer
        );
        assert_eq!(classifier_response(answer.clone()), answer);
    }

    #[test]
    fn openai_decisions_take_named_choices_and_answer_as_a_choice() {
        let route = |key: &str| Route {
            key: key.into(),
            description: format!("The {key} model"),
            family: "openai".into(),
            model: key.into(),
        };
        let config = RouterConfig {
            classifier: Classifier::Endpoint {
                model: "gpt-6-luna".into(),
                base_url: OPENAI_DECISIONS_URL.into(),
                api_key: Some("key".into()),
                max_options: None,
                limits: Default::default(),
            },
            routes: vec![route("fast"), route("deep")],
            ..RouterConfig::default()
        };
        let body = classifier_body(
            OPENAI_DECISIONS_URL,
            &question(&config, &config.routes, "Fix the typo."),
        );
        assert_eq!(body["model"], "gpt-6-luna");
        assert_eq!(body["input"], "Fix the typo.");
        assert_eq!(body["questions"][0]["type"], "choice");
        assert_eq!(body["questions"][0]["name"], QUESTION);
        assert_eq!(body["questions"][0]["choices"].as_array().unwrap().len(), 2);
        let answer = classifier_response(json!({
            "answers": [{"name": "route", "type": "choice", "choice": "fast", "confidence": 0.8,
                "probabilities": [{"value": "fast", "probability": 0.9}, {"value": "deep", "probability": 0.1}]}],
            "usage": {"input_tokens": 40, "output_tokens": 0},
        }));
        assert_eq!(
            parse_profile(&answer, &config.routes, &Profile::default()),
            Some(("fast".into(), 0.8))
        );
        let refused =
            classifier_response(json!({"answers": [{"name": "route", "type": "refusal"}]}));
        assert_eq!(
            parse_profile(&refused, &config.routes, &Profile::default()),
            None
        );
        let usage = classifier_usage(
            &config.classifier,
            Some(Tokens {
                input: 1_000_000,
                ..Default::default()
            }),
        );
        assert_eq!(usage.model, "openai/gpt-6-luna");
        assert_eq!(usage.cost, Some(0.10));
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    fn options() -> Vec<Route> {
        ["a", "b"]
            .into_iter()
            .map(|key| Route {
                key: key.into(),
                family: "test".into(),
                model: key.into(),
                description: String::new(),
            })
            .collect()
    }
    #[test]
    fn rejects_abstentions_foreign_options_and_inconsistent_probabilities() {
        let options = options();
        let p = Profile::default();
        for row in [
            json!({"choice":"a","confidence":0.9,"abstain":true}),
            json!({"choice":"foreign","confidence":0.9}),
            json!({"choice":"a","confidence":0.9,"probabilities":{"a":0.2,"b":0.8}}),
            json!({"choice":"a","confidence":0.9,"probabilities":{"a":0.9}}),
        ] {
            assert!(parse_profile(&json!({"answers":{"route":row}}), &options, &p).is_none());
        }
    }
    #[test]
    fn native_confidence_and_option_probability_are_distinct() {
        let a = json!({"answers":{"route":{"choice":"a","confidence":0.4,"probabilities":{"a":0.8,"b":0.2}}}});
        assert_eq!(
            parse_profile(&a, &options(), &Profile::default())
                .unwrap()
                .1,
            0.4
        );
        assert_eq!(
            parse_profile(
                &a,
                &options(),
                &Profile {
                    score: Score::Probability,
                    ..Default::default()
                }
            )
            .unwrap()
            .1,
            0.8
        );
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};

    /// One stub that answers one request, and reports the path and body it got.
    fn stub(
        status: u16,
        payload: &str,
    ) -> (
        u16,
        std::sync::mpsc::Receiver<(String, Option<String>, String)>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = std::sync::mpsc::channel();
        let payload = payload.to_owned();
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
            let value = |name: &str| {
                head.lines()
                    .find(|line| line.to_ascii_lowercase().starts_with(&format!("{name}:")))
                    .map(|line| line[name.len() + 1..].trim().to_owned())
            };
            let length: usize = value("content-length")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let mut body = vec![0_u8; length];
            let _ = stream.read_exact(&mut body);
            let path = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_owned();
            let _ = sender.send((
                path,
                value("authorization"),
                String::from_utf8_lossy(&body).to_string(),
            ));
            let response = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });
        (port, receiver)
    }

    /// An agent that reaches the stub whatever host the URL names, so a URL
    /// with a Cloudflare or OpenAI host still lands on the stub.
    fn redirected(port: u16) -> ureq::Agent {
        crate::http::agent_builder()
            .redirects(0)
            .timeout(TIMEOUT)
            .resolver(move |_: &str| Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]))
            .build()
    }

    fn questions() -> Value {
        json!({ QUESTION: {
            "type": "choice",
            "instructions": INSTRUCTIONS,
            "criteria": { "fast": "A short question", "deep": "A long reasoning task" },
        }})
    }

    fn system_one_reply() -> Value {
        json!({"answers": {"route": {"type": "choice", "choice": "fast", "confidence": 0.9}}})
    }

    #[test]
    fn the_typesafe_request_is_what_the_stub_receives() {
        let state = json!("Fix the typo.");
        let questions = questions();
        let (port, received) = stub(200, &system_one_reply().to_string());
        let classifier = Classifier::Typesafe {
            max_options: None,
            limits: Default::default(),
            api_key: "apikey_1".into(),
            model: "jev-latest".into(),
            base_url: Some(format!("http://127.0.0.1:{port}/v1/systemone")),
        };
        let built = request(&classifier, &state, &questions).unwrap();
        assert_eq!(built.bearer.as_deref(), Some("apikey_1"));
        assert_eq!(
            built.body,
            json!({"state": state, "model": "jev-latest", "questions": questions})
        );
        ask_choices(&classifier, &state, &questions, TIMEOUT).unwrap();
        let (path, authorization, body) = received.recv().unwrap();
        assert_eq!(path, "/v1/systemone");
        assert_eq!(authorization.as_deref(), Some("Bearer apikey_1"));
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), built.body);
    }

    #[test]
    fn the_endpoint_request_is_what_the_stub_receives() {
        let state = json!("Fix the typo.");
        let questions = questions();
        let (port, received) = stub(200, &system_one_reply().to_string());
        let classifier = Classifier::Endpoint {
            max_options: None,
            limits: Default::default(),
            model: "jev-latest".into(),
            base_url: format!("http://127.0.0.1:{port}/custom/decide"),
            api_key: Some("endpoint-key".into()),
        };
        let built = request(&classifier, &state, &questions).unwrap();
        assert_eq!(built.bearer.as_deref(), Some("endpoint-key"));
        ask_choices(&classifier, &state, &questions, TIMEOUT).unwrap();
        let (path, authorization, body) = received.recv().unwrap();
        assert_eq!(path, "/custom/decide");
        assert_eq!(authorization.as_deref(), Some("Bearer endpoint-key"));
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), built.body);
        assert_eq!(built.body["state"], "Fix the typo.");
    }

    #[test]
    fn the_cloudflare_request_is_what_the_stub_receives() {
        // The stub answers under Workers AI's `result` envelope.
        let reply = json!({"success": true, "result": system_one_reply()});
        let state = json!("Fix the typo.");
        let questions = questions();
        let (port, received) = stub(200, &reply.to_string());
        let classifier = Classifier::Endpoint {
            max_options: None,
            limits: Default::default(),
            model: "typesafe/jev".into(),
            base_url: format!("http://api.cloudflare.com:{port}/client/v4/accounts/abc/ai/run"),
            api_key: Some("cf-token".into()),
        };
        let built = request(&classifier, &state, &questions).unwrap();
        assert_eq!(built.body["model"], "typesafe/jev");
        assert_eq!(built.body["input"]["state"], "Fix the typo.");
        assert!(built.body["input"].get("model").is_none());
        let answers = ask_choices_on(&redirected(port), &classifier, &state, &questions).unwrap();
        assert_eq!(answers["route"]["choice"], "fast");
        let (path, authorization, body) = received.recv().unwrap();
        assert_eq!(path, "/client/v4/accounts/abc/ai/run");
        assert_eq!(authorization.as_deref(), Some("Bearer cf-token"));
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), built.body);
    }

    #[test]
    fn the_openai_decisions_request_is_what_the_stub_receives() {
        let reply = json!({"answers": [{"name": "route", "type": "choice", "choice": "fast",
            "confidence": 0.9, "probabilities": [{"value": "fast", "probability": 1.0}]}]});
        let state = json!("Fix the typo.");
        let questions = questions();
        let (port, received) = stub(200, &reply.to_string());
        let classifier = Classifier::Endpoint {
            max_options: None,
            limits: Default::default(),
            model: "gpt-6-luna".into(),
            base_url: format!("http://api.openai.com:{port}/v1/decisions"),
            api_key: Some("sk-test".into()),
        };
        let built = request(&classifier, &state, &questions).unwrap();
        assert_eq!(built.body["input"], "Fix the typo.");
        assert_eq!(built.body["questions"][0]["name"], QUESTION);
        let answers = ask_choices_on(&redirected(port), &classifier, &state, &questions).unwrap();
        assert_eq!(answers["route"]["choice"], "fast");
        let (path, authorization, body) = received.recv().unwrap();
        assert_eq!(path, "/v1/decisions");
        assert_eq!(authorization.as_deref(), Some("Bearer sk-test"));
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), built.body);
    }

    #[test]
    fn a_classifier_with_no_endpoint_builds_no_request() {
        assert!(request(&Classifier::None, &json!("x"), &questions()).is_none());
        assert_eq!(
            ask_choices(&Classifier::None, &json!("x"), &questions(), TIMEOUT),
            Err("Connect a decision model in Settings.".into())
        );
    }

    fn built(url: String) -> Request {
        let classifier = Classifier::Endpoint {
            max_options: None,
            limits: Default::default(),
            model: "jev-latest".into(),
            base_url: url,
            api_key: None,
        };
        request(&classifier, &json!("x"), &questions()).unwrap()
    }

    #[test]
    fn a_send_reports_the_answers_the_status_the_latency_and_the_usage() {
        let (port, _) = stub(
            200,
            &json!({"answers": {"route": {"choice": "fast", "confidence": 0.9}},
                "usage": {"input_tokens": 312, "output_tokens": 48}})
            .to_string(),
        );
        let sent = send(&built(format!("http://127.0.0.1:{port}/v1")), TIMEOUT);
        assert_eq!(sent.status, Some(200));
        assert_eq!(sent.error, None);
        assert_eq!(sent.answers.unwrap()["route"]["choice"], "fast");
        assert_eq!(
            sent.usage,
            Some(Tokens {
                input: 312,
                output: 48,
                ..Default::default()
            })
        );
        assert!(sent.latency > Duration::ZERO);
    }

    #[test]
    fn a_send_names_a_non_2xx_status() {
        let (port, _) = stub(503, "{\"error\":\"busy\"}");
        let sent = send(&built(format!("http://127.0.0.1:{port}/v1")), TIMEOUT);
        assert_eq!(sent.status, Some(503));
        assert_eq!(
            sent.error.as_deref(),
            Some("The decision model answered 503.")
        );
        assert!(sent.answer.is_none() && sent.answers.is_none());
    }

    #[test]
    fn a_send_names_a_body_that_is_not_json() {
        let (port, _) = stub(200, "<html>nope</html>");
        let sent = send(&built(format!("http://127.0.0.1:{port}/v1")), TIMEOUT);
        assert_eq!(sent.status, Some(200));
        assert_eq!(
            sent.error.as_deref(),
            Some("The decision model answered with something that is not JSON.")
        );
        assert!(sent.answer.is_none() && sent.usage.is_none());
    }

    #[test]
    fn a_send_names_an_answer_without_answers_and_keeps_its_usage() {
        let (port, _) = stub(200, &json!({"usage": {"input_tokens": 5}}).to_string());
        let sent = send(&built(format!("http://127.0.0.1:{port}/v1")), TIMEOUT);
        assert_eq!(
            sent.error.as_deref(),
            Some("The decision model sent no answers.")
        );
        assert_eq!(sent.usage.map(|usage| usage.input), Some(5));
    }

    #[test]
    fn a_send_names_a_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accepts the connection and never answers.
        let held = std::thread::spawn(move || {
            let accepted = listener.accept();
            std::thread::sleep(Duration::from_millis(800));
            drop(accepted);
        });
        let sent = send(
            &built(format!("http://127.0.0.1:{port}/v1")),
            Duration::from_millis(200),
        );
        assert_eq!(sent.status, None);
        assert!(
            sent.error
                .as_deref()
                .is_some_and(|error| error.starts_with("The decision model did not answer")),
            "{:?}",
            sent.error
        );
        assert!(sent.answer.is_none());
        held.join().unwrap();
    }
}
