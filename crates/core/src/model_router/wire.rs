//! Reading and writing the OpenAI chat wire the router speaks on both sides.
//!
//! Pi sends the router an OpenAI chat completion request. The router sends the
//! picked account's upstream the same request with the model swapped, and
//! relays the answer back. Everything the router needs to read out of that
//! traffic lives here: the turn's text for the classifier, the model the
//! request names, and the token counts the ledger records.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Pi preserves response IDs but keeps the requested model name (`auto`).
/// Carry the selected route in a unique response ID so concurrent turns and
/// restored receipts use their own evidence, never a global last-model value.
pub fn routed_response_id(family: &str, model: &str) -> String {
    let route = serde_json::to_vec(&(family, model)).expect("strings serialize");
    format!(
        "muniment-route-v1.{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(route),
        uuid::Uuid::new_v4()
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutingEvidence {
    pub account: String,
    pub selected_model: String,
    pub decision: String,
    pub confidence: Option<f64>,
    pub classification_ms: u64,
    pub exclusions: Vec<String>,
    pub fallback_causes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct RoutedResponse {
    family: String,
    model: String,
    classifier: Option<ClassifierUsage>,
    routing: RoutingEvidence,
}

pub fn evidenced_response_id(
    family: &str,
    model: &str,
    classifier: Option<&ClassifierUsage>,
    routing: RoutingEvidence,
) -> String {
    let value = RoutedResponse {
        family: family.into(),
        model: model.into(),
        classifier: classifier.cloned(),
        routing,
    };
    let bytes = serde_json::to_vec(&value).expect("routing evidence serializes");
    format!(
        "muniment-route-v3.{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        uuid::Uuid::new_v4()
    )
}

fn evidenced_response(id: &str) -> Option<RoutedResponse> {
    if id.len() > 65536 {
        return None;
    }
    let (encoded, nonce) = id.strip_prefix("muniment-route-v3.")?.split_once('.')?;
    uuid::Uuid::parse_str(nonce).ok()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    let value: RoutedResponse = serde_json::from_slice(&bytes).ok()?;
    if super::family::family(&value.family).is_none()
        || value.model.is_empty()
        || value.model.len() > 512
        || value.model.chars().any(char::is_control)
        || value
            .routing
            .confidence
            .is_some_and(|v| !v.is_finite() || !(0.0..=1.0).contains(&v))
    {
        return None;
    }
    Some(value)
}

pub fn response_routing(id: &str) -> Option<RoutingEvidence> {
    evidenced_response(id).map(|value| value.routing)
}

pub fn response_model(id: &str) -> Option<(String, String)> {
    if id.starts_with("muniment-route-v3.") {
        return evidenced_response(id).map(|value| (value.family, value.model));
    }
    if id.starts_with("muniment-route-v2.") {
        return classified_response(id).map(|(family, model, _)| (family, model));
    }
    if id.len() > 2048 {
        return None;
    }
    let rest = id.strip_prefix("muniment-route-v1.")?;
    let (route, nonce) = rest.split_once('.')?;
    uuid::Uuid::parse_str(nonce).ok()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(route)
        .ok()?;
    let (family, model): (String, String) = serde_json::from_slice(&bytes).ok()?;
    if super::family::family(&family).is_none()
        || model.is_empty()
        || model.len() > 512
        || model.chars().any(char::is_control)
    {
        return None;
    }
    Some((family, model))
}

/// Usage recorded by one classifier call. Missing values mean unreported, not free.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassifierUsage {
    pub model: String,
    pub tokens: Option<Tokens>,
    pub cost: Option<f64>,
}

pub fn classified_response_id(
    family: &str,
    model: &str,
    classifier: Option<&ClassifierUsage>,
) -> String {
    let Some(classifier) = classifier else {
        return routed_response_id(family, model);
    };
    let route = serde_json::to_vec(&(family, model, classifier)).expect("route serializes");
    format!(
        "muniment-route-v2.{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(route),
        uuid::Uuid::new_v4()
    )
}

fn classified_response(id: &str) -> Option<(String, String, ClassifierUsage)> {
    if id.len() > 4096 {
        return None;
    }
    let (route, nonce) = id.strip_prefix("muniment-route-v2.")?.split_once('.')?;
    uuid::Uuid::parse_str(nonce).ok()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(route)
        .ok()?;
    let value: (String, String, ClassifierUsage) = serde_json::from_slice(&bytes).ok()?;
    if super::family::family(&value.0).is_none()
        || value.1.is_empty()
        || value.1.len() > 512
        || value.1.chars().any(char::is_control)
        || value.2.model.is_empty()
        || value.2.model.len() > 512
        || value.2.model.chars().any(char::is_control)
        || value
            .2
            .cost
            .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
    {
        return None;
    }
    Some(value)
}

pub fn response_classifier(id: &str) -> Option<ClassifierUsage> {
    if id.starts_with("muniment-route-v3.") {
        return evidenced_response(id).and_then(|value| value.classifier);
    }
    classified_response(id).map(|(_, _, usage)| usage)
}

/// The token counts one turn spent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    pub input: u64,
    pub output: u64,
}

/// The model an OpenAI chat request names.
pub fn requested_model(request: &Value) -> Option<&str> {
    request.get("model")?.as_str()
}

/// Whether the request asks for a streamed answer.
pub fn streams(request: &Value) -> bool {
    request
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The turn's text for the classifier: the last user message, flattened out of
/// whichever content shape the client sent.
pub fn classifier_state(request: &Value) -> String {
    let Some(messages) = request.get("messages").and_then(Value::as_array) else {
        return String::new();
    };
    messages
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))
        .map(message_text)
        .unwrap_or_default()
}

/// One message's text, from a string body or from the text parts of a list.
fn message_text(message: &Value) -> String {
    match message.get("content") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Whether the client asked for the usage chunk of a streamed answer itself.
/// Pi does by default, and that chunk is then the client's to keep.
pub fn wants_usage(request: &Value) -> bool {
    request
        .get("stream_options")
        .and_then(|options| options.get("include_usage"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The request the upstream receives: the same request with the model the
/// router resolved, and, on a streamed turn, the usage chunk asked for so the
/// ledger can count a stream. The router drops that chunk before the client
/// sees it unless the client asked for it too.
pub fn upstream_request(request: &Value, model: &str) -> Value {
    let mut upstream = request.clone();
    if let Some(object) = upstream.as_object_mut() {
        object.insert("model".into(), Value::String(model.to_owned()));
        if streams(request) {
            let options = object
                .entry("stream_options")
                .or_insert_with(|| serde_json::json!({}));
            if !options.is_object() {
                *options = serde_json::json!({});
            }
            if let Some(options) = options.as_object_mut() {
                options.insert("include_usage".into(), Value::Bool(true));
            }
        }
    }
    upstream
}

/// The token counts in an answer, from the `usage` object either side sends.
pub fn tokens(value: &Value) -> Option<Tokens> {
    let usage = value.get("usage")?;
    if usage.is_null() {
        return None;
    }
    let count = |names: [&str; 2]| -> u64 {
        names
            .iter()
            .find_map(|name| usage.get(*name).and_then(Value::as_u64))
            .unwrap_or(0)
    };
    Some(Tokens {
        input: count(["prompt_tokens", "input_tokens"]),
        output: count(["completion_tokens", "output_tokens"]),
    })
}

/// Whether a streamed chunk carries only usage, which is the chunk the router
/// asked for itself and keeps off the client's wire.
pub fn usage_only_chunk(chunk: &Value) -> bool {
    let empty_choices = chunk
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| choices.is_empty());
    empty_choices && tokens(chunk).is_some()
}

/// The OpenAI model list the router answers `/v1/models` with.
pub fn model_list(models: &[String]) -> Value {
    serde_json::json!({
        "object": "list",
        "data": models
            .iter()
            .map(|id| serde_json::json!({
                "id": id,
                "object": "model",
                "owned_by": super::config::ROUTER_PROVIDER,
            }))
            .collect::<Vec<_>>(),
    })
}

/// The error body the router answers a failed turn with, in the shape an
/// OpenAI client already reads.
pub fn error_body(message: &str, kind: &str) -> Value {
    serde_json::json!({ "error": { "message": message, "type": kind } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> Value {
        json!({
            "model": "auto",
            "stream": true,
            "messages": [
                { "role": "system", "content": "You are muniment." },
                { "role": "user", "content": "First question" },
                { "role": "assistant", "content": "First answer" },
                { "role": "user", "content": [
                    { "type": "text", "text": "Why did the build fail?" },
                    { "type": "image_url", "image_url": { "url": "data:image/png;base64,AA" } },
                    { "type": "text", "text": "Read the log." }
                ]}
            ]
        })
    }

    #[test]
    fn the_classifier_sees_the_last_user_turn_whatever_shape_it_came_in() {
        assert_eq!(
            classifier_state(&request()),
            "Why did the build fail?\nRead the log."
        );
        assert_eq!(
            classifier_state(&json!({ "messages": [{ "role": "user", "content": "plain" }] })),
            "plain"
        );
        assert_eq!(classifier_state(&json!({})), "");
        assert_eq!(
            classifier_state(&json!({ "messages": [{ "role": "system", "content": "s" }] })),
            ""
        );
    }

    #[test]
    fn the_upstream_request_carries_the_resolved_model_and_asks_a_stream_to_count() {
        let upstream = upstream_request(&request(), "gpt-5.6-mini");
        assert_eq!(upstream["model"], "gpt-5.6-mini");
        assert_eq!(upstream["stream_options"]["include_usage"], true);
        assert_eq!(upstream["messages"], request()["messages"]);

        let once = json!({ "model": "auto", "messages": [] });
        let upstream = upstream_request(&once, "claude-opus-5");
        assert_eq!(upstream["model"], "claude-opus-5");
        assert!(upstream.get("stream_options").is_none());
        assert!(!streams(&once));
        assert!(streams(&request()));
        assert!(!wants_usage(&request()));

        // A client that asked for usage itself keeps its other options, and
        // the router knows to leave the usage chunk on the wire.
        let mut asking = request();
        asking["stream_options"] = json!({ "include_usage": true, "other": 1 });
        let upstream = upstream_request(&asking, "gpt-5.6-mini");
        assert_eq!(upstream["stream_options"]["include_usage"], true);
        assert_eq!(upstream["stream_options"]["other"], 1);
        assert!(wants_usage(&asking));
        assert_eq!(requested_model(&once), Some("auto"));
        assert_eq!(requested_model(&json!({})), None);
    }

    #[test]
    fn both_token_spellings_read_as_the_same_counts() {
        assert_eq!(
            tokens(&json!({ "usage": { "prompt_tokens": 312, "completion_tokens": 48 } })),
            Some(Tokens {
                input: 312,
                output: 48
            })
        );
        assert_eq!(
            tokens(&json!({ "usage": { "input_tokens": 7, "output_tokens": 2 } })),
            Some(Tokens {
                input: 7,
                output: 2
            })
        );
        assert_eq!(tokens(&json!({ "usage": null })), None);
        assert_eq!(tokens(&json!({})), None);
        assert_eq!(tokens(&json!({ "usage": {} })), Some(Tokens::default()));
    }

    #[test]
    fn the_usage_chunk_is_the_one_with_no_choices() {
        assert!(usage_only_chunk(&json!({
            "choices": [],
            "usage": { "prompt_tokens": 10, "completion_tokens": 3 }
        })));
        assert!(!usage_only_chunk(&json!({
            "choices": [{ "delta": { "content": "hi" } }],
            "usage": null
        })));
        assert!(!usage_only_chunk(&json!({ "choices": [] })));
    }

    #[test]
    fn the_model_list_reads_as_an_openai_list() {
        let list = model_list(&["auto".to_owned(), "deep".to_owned()]);
        assert_eq!(list["object"], "list");
        assert_eq!(list["data"][0]["id"], "auto");
        assert_eq!(list["data"][1]["id"], "deep");
        assert_eq!(list["data"][0]["owned_by"], "muniment-router");
        assert_eq!(error_body("no", "router_error")["error"]["message"], "no");
    }
}
