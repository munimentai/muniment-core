//! Provider-specific subscription wires, normalized to the router's chat wire.
//! Account selection stays in the router; this module never retries a turn.

use super::config::{Account, Credential};
use super::wire;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Chat,
    Responses,
    Messages,
}

pub struct Request {
    pub url: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Value,
    pub protocol: Protocol,
}

pub fn prepare(account: &Account, request: &Value, model: &str) -> Result<Request, String> {
    let provider = account.credential.pi_provider();
    let protocol = match provider {
        Some("openai-codex" | "xai" | "meta") => Protocol::Responses,
        Some("anthropic" | "kimi") => Protocol::Messages,
        Some(_) => return Err("This subscription does not support routed turns yet.".into()),
        None if account.family == "anthropic" => Protocol::Messages,
        None => Protocol::Chat,
    };
    let default = match provider {
        Some("openai-codex") => "https://chatgpt.com/backend-api/codex",
        Some("kimi") => "https://api.kimi.com/coding/v1",
        _ => {
            account
                .family()
                .ok_or("The account names no provider.")?
                .base_url
        }
    };
    let base = account
        .base_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .unwrap_or(default)
        .trim_end_matches('/');
    let mut headers = vec![(
        "authorization",
        format!("Bearer {}", account.credential.bearer()),
    )];
    if provider == Some("meta") {
        headers.push(("user-agent", "muse-code/1.0.2".into()));
        headers.push(("x-client-id", "tbh:tui".into()));
    }
    if protocol == Protocol::Messages {
        headers.push(("anthropic-version", "2023-06-01".into()));
        if provider == Some("anthropic") {
            headers.push((
                "anthropic-beta",
                "claude-code-20250219,oauth-2025-04-20".into(),
            ));
            headers.push(("user-agent", "claude-cli/2.1.282".into()));
            headers.push(("x-app", "cli".into()));
        }
        if matches!(account.credential, Credential::ApiKey { .. }) {
            headers.clear();
            headers.push(("x-api-key", account.credential.bearer().to_owned()));
            headers.push(("anthropic-version", "2023-06-01".into()));
        }
    }
    if let Credential::Subscription {
        provider,
        account_id,
        ..
    } = &account.credential
    {
        if provider == "openai-codex" {
            headers.push((
                "chatgpt-account-id",
                account_id
                    .clone()
                    .filter(|id| !id.is_empty())
                    .ok_or("Reconnect this OpenAI account to read its account ID.")?,
            ));
            headers.push(("OpenAI-Beta", "responses=experimental".into()));
        }
    }
    let (path, mut body) = match protocol {
        Protocol::Chat => ("chat/completions", wire::upstream_request(request, model)),
        Protocol::Responses => ("responses", responses_request(request, model)?),
        Protocol::Messages => ("messages", messages_request(request, model)?),
    };
    if account.family == "anthropic" {
        body["cache_control"] = json!({"type":"ephemeral"});
    }
    if provider == Some("anthropic") {
        // Match Pi's OAuth adapter. Anthropic requires this separate identity
        // block for subscription requests; preserve the harness prompt after it.
        let system = body
            .as_object_mut()
            .unwrap()
            .entry("system")
            .or_insert_with(|| json!([]));
        system.as_array_mut().unwrap().insert(0, json!({"type":"text", "text":"You are Claude Code, Anthropic's official CLI for Claude."}));
    }
    Ok(Request {
        url: format!("{base}/{path}"),
        headers,
        body,
        protocol,
    })
}

fn content_parts(content: &Value, responses: bool, assistant: bool) -> Result<Vec<Value>, String> {
    if content.is_null() {
        return Ok(vec![]);
    }
    let text_type = if !responses {
        "text"
    } else if assistant {
        "output_text"
    } else {
        "input_text"
    };
    if let Some(text) = content.as_str() {
        return Ok(vec![json!({"type":text_type,"text":text})]);
    }
    let parts = content.as_array().ok_or("Unsupported message content.")?;
    parts.iter().map(|part| match part["type"].as_str() {
        Some("text") => Ok(json!({"type":text_type,"text":part["text"]})),
        Some("image_url") if !assistant => {
            let url = part["image_url"]["url"].as_str().ok_or("An image has no URL.")?;
            if responses { return Ok(json!({"type":"input_image","image_url":url})); }
            if let Some(data) = url.strip_prefix("data:") {
                let (mime, data) = data.split_once(";base64,").ok_or("Unsupported image encoding.")?;
                Ok(json!({"type":"image","source":{"type":"base64","media_type":mime,"data":data}}))
            } else { Ok(json!({"type":"image","source":{"type":"url","url":url}})) }
        }
        _ => Err("This model cannot receive this content type through routing.".into()),
    }).collect()
}

fn messages(request: &Value) -> Result<&Vec<Value>, String> {
    request["messages"]
        .as_array()
        .ok_or_else(|| "The request has no messages.".into())
}

pub fn responses_request(request: &Value, model: &str) -> Result<Value, String> {
    let mut input = vec![];
    let mut instructions = vec![];
    for message in messages(request)? {
        let role = message["role"].as_str().ok_or("A message has no role.")?;
        if role == "system" || role == "developer" {
            for part in content_parts(&message["content"], true, false)? {
                instructions.push(part["text"].as_str().unwrap_or_default().to_owned());
            }
        } else if role == "tool" {
            input.push(json!({"type":"function_call_output","call_id":message["tool_call_id"],"output":message["content"]}));
        } else if role == "user" || role == "assistant" {
            let content = content_parts(&message["content"], true, role == "assistant")?;
            if !content.is_empty() {
                input.push(json!({"role":role,"content":content}));
            }
            if let Some(calls) = message["tool_calls"].as_array() {
                for call in calls {
                    input.push(json!({"type":"function_call","call_id":call["id"],"name":call["function"]["name"],"arguments":call["function"]["arguments"]}));
                }
            }
        } else {
            return Err("Unsupported message role.".into());
        }
    }
    let mut body = json!({"model":model,"stream":true,"store":false,"instructions":instructions.join("\n"),"input":input});
    if let Some(tools) = request["tools"].as_array() {
        body["tools"] = Value::Array(tools.iter().map(|tool| json!({"type":"function","name":tool["function"]["name"],"description":tool["function"]["description"],"parameters":tool["function"]["parameters"]})).collect());
    }
    if let Some(choice) = request.get("tool_choice") {
        body["tool_choice"] = if choice.is_string() {
            choice.clone()
        } else {
            json!({"type":"function","name":choice["function"]["name"]})
        };
    }
    if let Some(effort) = request.get("reasoning_effort") {
        body["reasoning"] = json!({"effort":effort});
    }
    if let Some(parallel) = request.get("parallel_tool_calls") {
        body["parallel_tool_calls"] = parallel.clone();
    }
    Ok(body)
}

pub fn messages_request(request: &Value, model: &str) -> Result<Value, String> {
    let mut input = vec![];
    let mut system = vec![];
    for message in messages(request)? {
        let role = message["role"].as_str().ok_or("A message has no role.")?;
        if role == "system" || role == "developer" {
            system.extend(content_parts(&message["content"], false, false)?);
        } else if role == "tool" {
            input.push(json!({"role":"user","content":[{"type":"tool_result","tool_use_id":message["tool_call_id"],"content":message["content"]}]}));
        } else if role == "user" || role == "assistant" {
            let mut content = content_parts(&message["content"], false, role == "assistant")?;
            if let Some(calls) = message["tool_calls"].as_array() {
                for call in calls {
                    let args: Value = serde_json::from_str(
                        call["function"]["arguments"].as_str().unwrap_or("{}"),
                    )
                    .map_err(|_| "A tool call has invalid JSON arguments.")?;
                    content.push(json!({"type":"tool_use","id":call["id"],"name":call["function"]["name"],"input":args}));
                }
            }
            input.push(json!({"role":role,"content":content}));
        } else {
            return Err("Unsupported message role.".into());
        }
    }
    let mut body = json!({"model":model,"stream":true,"max_tokens":request.get("max_completion_tokens").or_else(|| request.get("max_tokens")).cloned().unwrap_or(json!(8192)),"messages":input});
    if !system.is_empty() {
        body["system"] = Value::Array(system);
    }
    if let Some(tools) = request["tools"].as_array() {
        body["tools"] = Value::Array(tools.iter().map(|tool| json!({"name":tool["function"]["name"],"description":tool["function"]["description"],"input_schema":tool["function"]["parameters"]})).collect());
    }
    if let Some(choice) = request.get("tool_choice") {
        body["tool_choice"] = match choice.as_str() {
            Some("required") => json!({"type":"any"}),
            Some(value) => json!({"type":value}),
            None => json!({"type":"tool","name":choice["function"]["name"]}),
        };
    }
    for key in ["temperature", "top_p"] {
        if let Some(value) = request.get(key) {
            body[key] = value.clone();
        }
    }
    Ok(body)
}

/// Converts one provider event at a time, preserving tool-call indices and deltas.
pub struct Decoder {
    pub tokens: wire::Tokens,
    pub response_id: String,
    pub finished: bool,
    pub finish_reason: String,
    pub text: String,
    pub tools: Vec<Value>,
    /// The provider's model field, not the route the caller requested.
    pub reported_model: Option<String>,
    pub conflicting_models: bool,
    indices: BTreeMap<String, usize>,
    model: String,
}
impl Decoder {
    pub fn new(model: &str) -> Self {
        Self {
            tokens: wire::Tokens::default(),
            response_id: uuid::Uuid::new_v4().to_string(),
            finished: false,
            finish_reason: "stop".into(),
            text: String::new(),
            tools: vec![],
            reported_model: None,
            conflicting_models: false,
            indices: BTreeMap::new(),
            model: model.into(),
        }
    }
    fn chunk(&self, delta: Value) -> Value {
        json!({"id":self.response_id,"object":"chat.completion.chunk","model":self.model,"choices":[{"index":0,"delta":delta,"finish_reason":null}]})
    }
    fn tool(&mut self, key: String, id: &Value, name: &Value) -> Value {
        let index = self.tools.len();
        self.indices.insert(key, index);
        self.tools
            .push(json!({"id":id,"type":"function","function":{"name":name,"arguments":""}}));
        self.finish_reason = "tool_calls".into();
        self.chunk(json!({"tool_calls":[{"index":index,"id":id,"type":"function","function":{"name":name,"arguments":""}}]}))
    }
    fn arguments(&mut self, key: &str, delta: &str) -> Result<Value, String> {
        let index = *self
            .indices
            .get(key)
            .ok_or("The provider sent arguments before a tool call.")?;
        let text = self.tools[index]["function"]["arguments"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
            + delta;
        self.tools[index]["function"]["arguments"] = json!(text);
        Ok(self.chunk(json!({"tool_calls":[{"index":index,"function":{"arguments":delta}}]})))
    }
    pub fn event(&mut self, event: &Value) -> Result<Option<Value>, String> {
        let kind = event["type"].as_str().unwrap_or_default();
        if let Some(model) = event["response"]["model"]
            .as_str()
            .or_else(|| event["message"]["model"].as_str())
        {
            if self
                .reported_model
                .as_deref()
                .is_some_and(|previous| previous != model)
            {
                self.conflicting_models = true;
            }
            self.reported_model = Some(model.to_owned());
        }
        let value = match kind {
            "response.output_text.delta" => {
                let text = event["delta"].as_str().unwrap_or_default();
                self.text.push_str(text);
                Some(self.chunk(json!({"content":text})))
            }
            "response.output_item.added" if event["item"]["type"] == "function_call" => {
                Some(self.tool(
                    event["item"]["id"].as_str().unwrap_or_default().into(),
                    &event["item"]["call_id"],
                    &event["item"]["name"],
                ))
            }
            "response.function_call_arguments.delta" => Some(self.arguments(
                event["item_id"].as_str().unwrap_or_default(),
                event["delta"].as_str().unwrap_or_default(),
            )?),
            "response.completed" | "response.done" => {
                self.tokens = wire::tokens(&event["response"]).unwrap_or_default();
                self.finished = true;
                None
            }
            "message_start" => {
                self.tokens = wire::tokens(&event["message"]).unwrap_or_default();
                None
            }
            "content_block_start" if event["content_block"]["type"] == "tool_use" => {
                Some(self.tool(
                    event["index"].to_string(),
                    &event["content_block"]["id"],
                    &event["content_block"]["name"],
                ))
            }
            "content_block_delta" => match event["delta"]["type"].as_str() {
                Some("text_delta") => {
                    let text = event["delta"]["text"].as_str().unwrap_or_default();
                    self.text.push_str(text);
                    Some(self.chunk(json!({"content":text})))
                }
                Some("input_json_delta") => Some(self.arguments(
                    &event["index"].to_string(),
                    event["delta"]["partial_json"].as_str().unwrap_or_default(),
                )?),
                _ => None,
            },
            "message_delta" => {
                if let Some(counts) = wire::tokens(event) {
                    self.tokens.output = counts.output;
                    if counts.input > 0 {
                        self.tokens.input = counts.input;
                        self.tokens.cache_read = counts.cache_read;
                        self.tokens.cache_write = counts.cache_write;
                        self.tokens.cache_write_1h = counts.cache_write_1h;
                    }
                }
                if event["delta"]["stop_reason"] == "max_tokens" {
                    self.finish_reason = "length".into();
                }
                None
            }
            "message_stop" => {
                self.finished = true;
                None
            }
            "error" | "response.failed" | "response.incomplete" => {
                return Err(
                    "The provider did not finish the routed response. Retry the request.".into(),
                )
            }
            _ => None,
        };
        Ok(value)
    }
    pub fn final_chunk(&self) -> Value {
        json!({"id":self.response_id,"object":"chat.completion.chunk","model":self.model,"choices":[{"index":0,"delta":{},"finish_reason":self.finish_reason}]})
    }
    pub fn usage_chunk(&self) -> Value {
        json!({"id":self.response_id,"object":"chat.completion.chunk","model":self.model,"choices":[],"usage":{"prompt_tokens":self.tokens.input,"completion_tokens":self.tokens.output,"total_tokens":self.tokens.input+self.tokens.output,"prompt_tokens_details":{"cached_tokens":self.tokens.cache_read},"cache_creation_input_tokens":self.tokens.cache_write,"completion_tokens_details":{"reasoning_tokens":self.tokens.reasoning}}})
    }
    pub fn completion(&self) -> Value {
        let mut message = json!({"role":"assistant","content":self.text});
        if !self.tools.is_empty() {
            message["tool_calls"] = json!(self.tools);
        }
        json!({"id":self.response_id,"object":"chat.completion","model":self.model,"choices":[{"index":0,"message":message,"finish_reason":self.finish_reason}],"usage":{"prompt_tokens":self.tokens.input,"completion_tokens":self.tokens.output,"total_tokens":self.tokens.input+self.tokens.output,"prompt_tokens_details":{"cached_tokens":self.tokens.cache_read},"cache_creation_input_tokens":self.tokens.cache_write,"completion_tokens_details":{"reasoning_tokens":self.tokens.reasoning}}})
    }
}

/// Reads a native response for non-streaming consumers such as the classifier.
pub fn collect(response: ureq::Response, protocol: Protocol, model: &str) -> Result<Value, String> {
    use std::io::{BufRead, Read};
    if protocol == Protocol::Chat {
        return response
            .into_json()
            .map_err(|_| "Invalid provider JSON.".into());
    }
    let mut decoder = Decoder::new(model);
    let reader = std::io::BufReader::new(response.into_reader().take(32 * 1024 * 1024));
    let mut data = String::new();
    for line in reader.lines() {
        let line = line.map_err(|_| "The provider stream failed.")?;
        if let Some(part) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(part.trim_start());
        }
        if !line.is_empty() || data.is_empty() {
            continue;
        }
        if data == "[DONE]" {
            break;
        }
        let event: Value = serde_json::from_str(&data).map_err(|_| "Invalid provider event.")?;
        data.clear();
        decoder.event(&event)?;
        if decoder.finished {
            return Ok(decoder.completion());
        }
    }
    Err("The provider stream ended before completion.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_receipts_use_provider_models_not_requested_models() {
        let mut decoder = Decoder::new("requested");
        assert_eq!(decoder.reported_model, None);
        decoder
            .event(&json!({"type":"response.created","response":{"model":"actual"}}))
            .unwrap();
        assert_eq!(decoder.reported_model.as_deref(), Some("actual"));
        assert!(!decoder.conflicting_models);
        decoder
            .event(&json!({"type":"response.completed","response":{"model":"other"}}))
            .unwrap();
        assert!(decoder.conflicting_models);
    }

    #[test]
    fn subscription_receipts_read_messages_and_do_not_invent_missing_models() {
        let mut decoder = Decoder::new("requested");
        decoder
            .event(&json!({"type":"message_start","message":{"model":"actual"}}))
            .unwrap();
        assert_eq!(decoder.reported_model.as_deref(), Some("actual"));
        decoder.event(&json!({"type":"message_stop"})).unwrap();
        assert!(decoder.finished);
        assert_eq!(decoder.reported_model.as_deref(), Some("actual"));
        let mut absent = Decoder::new("requested");
        absent
            .event(&json!({"type":"response.completed","response":{}}))
            .unwrap();
        assert_eq!(absent.reported_model, None);
        let mut failed = Decoder::new("requested");
        assert!(failed.event(&json!({"type":"response.failed"})).is_err());
        assert!(!failed.finished);
    }

    #[test]
    fn muse_subscription_uses_responses_and_its_minted_key() {
        let account: Account = serde_json::from_value(json!({
            "id":"muse", "family":"meta", "label":"Muse Code", "enabled":true,
            "weight":1, "models":[],
            "credential":{"type":"subscription", "provider":"meta", "access":"minted-fixture"}
        }))
        .unwrap();
        let prepared = prepare(
            &account,
            &json!({"messages":[{"role":"user","content":"Hello"}]}),
            "muse-fixture",
        )
        .unwrap();
        assert_eq!(prepared.protocol, Protocol::Responses);
        assert_eq!(prepared.url, "https://api.meta.ai/v1/responses");
        assert!(prepared
            .headers
            .contains(&("authorization", "Bearer minted-fixture".into())));
        assert!(prepared
            .headers
            .contains(&("x-client-id", "tbh:tui".into())));
        assert_eq!(prepared.body["model"], "muse-fixture");
    }

    #[test]
    fn subscription_identity_is_separate_from_the_harness_prompt_and_api_key_requests() {
        let mut account: Account = serde_json::from_value(json!({
            "id":"claude", "family":"anthropic", "label":"Claude", "enabled":true,
            "weight":1, "models":["claude-opus-5"],
            "credential":{"type":"subscription", "provider":"anthropic", "access":"test-token", "refresh":"test-refresh", "expires_ms":9999999999999_i64}
        })).unwrap();
        let request = json!({"messages":[{"role":"system","content":"Harness instructions"},{"role":"user","content":"Hello"}]});
        let oauth = prepare(&account, &request, "claude-opus-5").unwrap();
        assert_eq!(
            oauth.body["system"][0]["text"],
            "You are Claude Code, Anthropic's official CLI for Claude."
        );
        assert_eq!(oauth.body["system"][1]["text"], "Harness instructions");
        assert!(oauth.headers.iter().any(
            |(name, value)| *name == "anthropic-beta" && value.contains("claude-code-20250219")
        ));
        assert!(oauth
            .headers
            .iter()
            .any(|(name, value)| *name == "user-agent" && value == "claude-cli/2.1.282"));
        account.credential = Credential::ApiKey {
            key: "test-key".into(),
        };
        let api = prepare(&account, &request, "claude-opus-5").unwrap();
        assert_eq!(api.body["system"].as_array().unwrap().len(), 1);
        assert_eq!(api.body["system"][0]["text"], "Harness instructions");
    }

    #[test]
    fn messages_preserve_tools_results_images_and_system_text() {
        let request = json!({"messages":[{"role":"system","content":"Be brief"},
            {"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]},
            {"role":"assistant","content":null,"tool_calls":[{"id":"c1","function":{"name":"read","arguments":"{\"path\":\"a\"}"}}]},
            {"role":"tool","tool_call_id":"c1","content":"found"}],
            "tools":[{"type":"function","function":{"name":"read","description":"Read","parameters":{"type":"object"}}}]});
        let anthropic = messages_request(&request, "claude").unwrap();
        assert_eq!(anthropic["system"][0]["text"], "Be brief");
        assert_eq!(
            anthropic["messages"][0]["content"][1]["source"]["media_type"],
            "image/png"
        );
        assert_eq!(anthropic["messages"][1]["content"][0]["input"]["path"], "a");
        assert_eq!(anthropic["messages"][2]["content"][0]["tool_use_id"], "c1");
        let codex = responses_request(&request, "gpt").unwrap();
        assert_eq!(codex["instructions"], "Be brief");
        assert_eq!(codex["input"][1]["type"], "function_call");
        assert_eq!(codex["input"][2]["call_id"], "c1");
        assert_eq!(codex["tools"][0]["name"], "read");
        assert_eq!(codex["store"], false);
    }
    #[test]
    fn native_tool_deltas_keep_ids_indices_and_usage() {
        let mut d = Decoder::new("gpt");
        let start = d.event(&json!({"type":"response.output_item.added","item":{"type":"function_call","id":"item1","call_id":"call1","name":"read"}})).unwrap().unwrap();
        assert_eq!(start["choices"][0]["delta"]["tool_calls"][0]["id"], "call1");
        d.event(&json!({"type":"response.function_call_arguments.delta","item_id":"item1","delta":"{}"})).unwrap();
        assert!(!d.finished);
        d.event(&json!({"type":"response.completed","response":{"usage":{"input_tokens":12,"output_tokens":3}}})).unwrap();
        assert!(d.finished);
        assert_eq!(d.tokens.input, 12);
        assert_eq!(
            d.completion()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"],
            "{}"
        );
        assert_eq!(d.finish_reason, "tool_calls");
    }
    #[test]
    fn anthropic_usage_combines_start_and_delta_and_requires_stop() {
        let mut d = Decoder::new("claude");
        d.event(&json!({"type":"message_start","message":{"usage":{"input_tokens":42,"output_tokens":1}}})).unwrap();
        d.event(
            &json!({"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}),
        )
        .unwrap();
        d.event(&json!({"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":8}})).unwrap();
        assert!(!d.finished);
        d.event(&json!({"type":"message_stop"})).unwrap();
        assert_eq!(d.tokens.input, 42);
        assert_eq!(d.tokens.output, 8);
        assert_eq!(d.finish_reason, "length");
        assert_eq!(d.text, "hello");
        assert!(d.event(&json!({"type":"error"})).is_err());
    }
}
