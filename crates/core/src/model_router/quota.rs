//! What a subscription has left: the windows the upstream reports, the
//! percent used in each, and when each resets.
//!
//! A subscription meters use by window, not by token. Codex answers
//! `GET https://chatgpt.com/backend-api/wham/usage` with one or two windows,
//! and a window is known by its length, never by its slot: a Pro plan's
//! `primary_window` is the weekly one. Claude answers
//! `GET https://api.anthropic.com/api/oauth/usage` with a five-hour and a
//! seven-day window and a scoped weekly limit per model family.
//!
//! The screen shows what is left, not what is used, because that is the number
//! a subscriber watches. The store carries no token and no prompt.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::config::{Account, Credential};

/// The quota store in the agent directory.
pub const QUOTA_FILE: &str = "muniment-router-quota.json";
pub const CODEX_USAGE_URL: &str = "https://chatgpt.com/backend-api/wham/usage";
pub const CLAUDE_USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
/// The header set Codex's own client sends, which the usage route gates on.
pub const CODEX_USER_AGENT: &str =
    "codex-tui/0.149.1 (Mac OS 26.5.2; arm64) iTerm.app/3.6.11 (codex-tui; 0.149.1)";
pub const CLAUDE_OAUTH_BETA: &str = "oauth-2025-04-20";
/// Kimi meters its coding plan by window and answers here with a bearer.
pub const KIMI_USAGE_URL: &str = "https://api.kimi.com/coding/v1/usages";
/// Antigravity answers its buckets here, a fraction left per model family.
pub const ANTIGRAVITY_QUOTA_URL: &str =
    "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary";
/// Devin's seat service answers a protobuf with a daily and a weekly percent left.
pub const DEVIN_SERVER_URL: &str = "https://server.codeium.com";
pub const DEVIN_STATUS_PATH: &str = "/exa.seat_management_pb.SeatManagementService/GetUserStatus";
pub const TIMEOUT: Duration = Duration::from_secs(12);

const FIVE_HOURS: i64 = 5 * 60 * 60;
const ONE_DAY: i64 = 24 * 60 * 60;
const ONE_WEEK: i64 = 7 * 24 * 60 * 60;
const MONTH_LOW: i64 = 28 * 24 * 60 * 60;
const MONTH_HIGH: i64 = 31 * 24 * 60 * 60;

/// How long a window runs. The upstream says it in seconds, and the label
/// follows the length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowKind {
    FiveHour,
    Daily,
    Weekly,
    Monthly,
    Other,
}

impl WindowKind {
    /// The kind a window of `seconds` is.
    pub fn from_seconds(seconds: i64) -> Self {
        if seconds == FIVE_HOURS {
            Self::FiveHour
        } else if seconds == ONE_DAY {
            Self::Daily
        } else if seconds == ONE_WEEK {
            Self::Weekly
        } else if (MONTH_LOW..=MONTH_HIGH).contains(&seconds) {
            Self::Monthly
        } else {
            Self::Other
        }
    }

    /// The label Settings shows.
    pub fn label(self) -> &'static str {
        match self {
            Self::FiveHour => "5-hour window",
            Self::Daily => "Daily window",
            Self::Weekly => "Weekly window",
            Self::Monthly => "Monthly window",
            Self::Other => "Window",
        }
    }
}

/// One metered window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Window {
    pub kind: WindowKind,
    /// The upstream's own name when it scopes the window, `Fable` or
    /// `GPT-5.3-Codex-Spark`. Empty for the account-wide window.
    #[serde(default)]
    pub scope: String,
    /// Percent of the window spent, 0 to 100.
    pub used_percent: f64,
    /// Unix milliseconds the window resets, when the upstream says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at_ms: Option<i64>,
    /// Whether the upstream has stopped serving on this window.
    #[serde(default)]
    pub limit_reached: bool,
}

impl Window {
    /// Percent of the window left, which is what the screen shows.
    pub fn remaining_percent(&self) -> f64 {
        (100.0 - self.used_percent).clamp(0.0, 100.0)
    }
}

/// Everything one probe learned about an account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Quota {
    /// `pro`, `plus`, `max`, or whatever the upstream calls the plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default)]
    pub windows: Vec<Window>,
    /// Codex's rate-limit reset credits: resets the account can spend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banked_resets: Option<u32>,
    /// Unix milliseconds the probe answered.
    pub observed_at_ms: i64,
}

impl Quota {
    /// The account-wide window that limits most turns: weekly when there is
    /// one, else five-hour, else the first.
    pub fn headline(&self) -> Option<&Window> {
        let unscoped = || self.windows.iter().filter(|window| window.scope.is_empty());
        unscoped()
            .find(|window| window.kind == WindowKind::Weekly)
            .or_else(|| unscoped().find(|window| window.kind == WindowKind::FiveHour))
            .or_else(|| self.windows.first())
    }
}

/// A number the upstream may send as a number or a string.
fn number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// One Codex window object, as `primary_window`, `secondary_window` and each
/// `additional_rate_limits[].rate_limit` carry it.
fn codex_window(value: &Value, scope: &str, limit_reached: bool, now_ms: i64) -> Option<Window> {
    let used_percent = number(value.get("used_percent"))?;
    let seconds = number(value.get("limit_window_seconds")).unwrap_or(0.0) as i64;
    let resets_at_ms = number(value.get("reset_at"))
        .map(|seconds| (seconds * 1000.0) as i64)
        .or_else(|| {
            number(value.get("reset_after_seconds")).map(|after| now_ms + (after * 1000.0) as i64)
        });
    Some(Window {
        kind: WindowKind::from_seconds(seconds),
        scope: scope.to_owned(),
        used_percent: used_percent.clamp(0.0, 100.0),
        resets_at_ms,
        limit_reached,
    })
}

/// The quota in a `wham/usage` answer.
pub fn parse_codex(payload: &Value, now_ms: i64) -> Option<Quota> {
    let rate_limit = payload.get("rate_limit")?;
    let limit_reached = rate_limit
        .get("limit_reached")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || rate_limit.get("allowed").and_then(Value::as_bool) == Some(false);
    let mut windows = Vec::new();
    for slot in ["primary_window", "secondary_window"] {
        if let Some(window) = rate_limit
            .get(slot)
            .filter(|value| value.is_object())
            .and_then(|value| codex_window(value, "", limit_reached, now_ms))
        {
            windows.push(window);
        }
    }
    // Each additional limit is scoped to one model family and named by it.
    if let Some(additional) = payload
        .get("additional_rate_limits")
        .and_then(Value::as_array)
    {
        for entry in additional {
            let name = text(entry.get("limit_name"))
                .or_else(|| text(entry.get("name")))
                .unwrap_or_default();
            let reached = entry
                .get("rate_limit")
                .and_then(|limit| limit.get("limit_reached"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let source = entry.get("rate_limit").unwrap_or(entry);
            for slot in ["primary_window", "secondary_window"] {
                if let Some(window) = source
                    .get(slot)
                    .filter(|value| value.is_object())
                    .and_then(|value| codex_window(value, &name, reached, now_ms))
                {
                    windows.push(window);
                }
            }
        }
    }
    Some(Quota {
        plan: text(payload.get("plan_type")),
        email: text(payload.get("email")),
        windows,
        banked_resets: payload
            .get("rate_limit_reset_credits")
            .and_then(|credits| credits.get("available_count"))
            .and_then(Value::as_u64)
            .map(|count| count as u32),
        observed_at_ms: now_ms,
    })
}

fn rfc3339_ms(value: Option<&Value>) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value?.as_str()?)
        .ok()
        .map(|moment| moment.timestamp_millis())
}

/// The quota in an `api/oauth/usage` answer. The `limits` list is the clean
/// source, one entry per window with its kind and scope. The named windows
/// stand in when the list is absent.
pub fn parse_claude(payload: &Value, now_ms: i64) -> Option<Quota> {
    let mut windows = Vec::new();
    if let Some(limits) = payload.get("limits").and_then(Value::as_array) {
        for limit in limits {
            let Some(used_percent) = number(limit.get("percent")) else {
                continue;
            };
            let kind = match text(limit.get("group")).as_deref() {
                Some("session") => WindowKind::FiveHour,
                Some("weekly") => WindowKind::Weekly,
                _ => WindowKind::Other,
            };
            let scope = limit
                .get("scope")
                .and_then(|scope| scope.get("model"))
                .and_then(|model| text(model.get("display_name")))
                .unwrap_or_default();
            windows.push(Window {
                kind,
                scope,
                used_percent: used_percent.clamp(0.0, 100.0),
                resets_at_ms: rfc3339_ms(limit.get("resets_at")),
                limit_reached: text(limit.get("severity")).as_deref() == Some("blocked"),
            });
        }
    }
    if windows.is_empty() {
        for (name, kind) in [
            ("five_hour", WindowKind::FiveHour),
            ("seven_day", WindowKind::Weekly),
        ] {
            let Some(window) = payload.get(name).filter(|value| value.is_object()) else {
                continue;
            };
            let Some(used_percent) = number(window.get("utilization")) else {
                continue;
            };
            windows.push(Window {
                kind,
                scope: String::new(),
                used_percent: used_percent.clamp(0.0, 100.0),
                resets_at_ms: rfc3339_ms(window.get("resets_at")),
                limit_reached: false,
            });
        }
    }
    if windows.is_empty() {
        return None;
    }
    Some(Quota {
        plan: None,
        email: None,
        windows,
        banked_resets: None,
        observed_at_ms: now_ms,
    })
}

fn fetch(url: &str, headers: &[(&str, &str)], timeout: Duration) -> Option<Value> {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let mut request = agent.get(url);
    for (name, value) in headers {
        request = request.set(name, value);
    }
    request.call().ok()?.into_json::<Value>().ok()
}

/// Asks Codex what this account has left.
pub fn probe_codex(
    access: &str,
    account_id: Option<&str>,
    now_ms: i64,
    timeout: Duration,
) -> Option<Quota> {
    let bearer = format!("Bearer {access}");
    let mut headers = vec![
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/json"),
        ("User-Agent", CODEX_USER_AGENT),
    ];
    if let Some(account_id) = account_id {
        headers.push(("Chatgpt-Account-Id", account_id));
    }
    parse_codex(&fetch(CODEX_USAGE_URL, &headers, timeout)?, now_ms)
}

/// Grok Build's credits endpoint, as used by its billing extension.
pub const XAI_USAGE_URL: &str = "https://cli-chat-proxy.grok.com/v1/billing?format=credits";

pub fn parse_xai(payload: &Value, now_ms: i64) -> Option<Quota> {
    let config = payload.get("config")?;
    let used = number(config.get("creditUsagePercent")).or_else(|| {
        let limit = number(config.pointer("/monthlyLimit/val"))?;
        (limit > 0.0).then(|| number(config.pointer("/used/val")).unwrap_or(0.0) / limit * 100.0)
    })?;
    if !used.is_finite() {
        return None;
    }
    let period = config.get("currentPeriod");
    let kind = match period.and_then(|p| p.get("type")).and_then(Value::as_str) {
        Some("USAGE_PERIOD_TYPE_WEEKLY") => WindowKind::Weekly,
        Some("USAGE_PERIOD_TYPE_MONTHLY") => WindowKind::Monthly,
        _ if config.get("monthlyLimit").is_some() => WindowKind::Monthly,
        _ => WindowKind::Other,
    };
    Some(Quota {
        plan: text(payload.get("subscription_tier")),
        email: None,
        windows: vec![Window {
            kind,
            scope: String::new(),
            used_percent: used.clamp(0.0, 100.0),
            resets_at_ms: rfc3339_ms(period.and_then(|p| p.get("end")))
                .or_else(|| rfc3339_ms(config.get("billingPeriodEnd"))),
            limit_reached: used >= 100.0,
        }],
        banked_resets: None,
        observed_at_ms: now_ms,
    })
}

pub fn probe_xai(
    access: &str,
    account_id: Option<&str>,
    now_ms: i64,
    timeout: Duration,
) -> Option<Quota> {
    let bearer = format!("Bearer {access}");
    let mut headers = vec![
        ("Authorization", bearer.as_str()),
        ("X-XAI-Token-Auth", "xai-grok-cli"),
    ];
    if let Some(id) = account_id {
        headers.push(("x-userid", id));
    }
    let mut quota = parse_xai(&fetch(XAI_USAGE_URL, &headers, timeout)?, now_ms)?;
    if let Some(user) = fetch("https://cli-chat-proxy.grok.com/v1/user", &headers, timeout) {
        quota.email = text(user.get("email"));
    }
    Some(quota)
}

/// Asks Anthropic what this account has left.
pub fn probe_claude(access: &str, now_ms: i64, timeout: Duration) -> Option<Quota> {
    let bearer = format!("Bearer {access}");
    let headers = [
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/json"),
        ("anthropic-beta", CLAUDE_OAUTH_BETA),
    ];
    parse_claude(&fetch(CLAUDE_USAGE_URL, &headers, timeout)?, now_ms)
}

fn post_json(url: &str, headers: &[(&str, &str)], body: Value, timeout: Duration) -> Option<Value> {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let mut request = agent.post(url);
    for (name, value) in headers {
        request = request.set(name, value);
    }
    request.send_json(body).ok()?.into_json::<Value>().ok()
}

fn post_bytes(
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    timeout: Duration,
) -> Option<Vec<u8>> {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let mut request = agent.post(url);
    for (name, value) in headers {
        request = request.set(name, value);
    }
    use std::io::Read;
    let response = request.send_bytes(body).ok()?;
    let mut bytes = Vec::new();
    let mut limited = response.into_reader().take(4 << 20);
    limited.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// A reset instant from an RFC 3339 field, or from seconds left.
fn reset_ms(record: &Value, now_ms: i64) -> Option<i64> {
    for key in ["reset_at", "resetAt", "reset_time", "resetTime"] {
        if let Some(moment) = rfc3339_ms(record.get(key)) {
            return Some(moment);
        }
    }
    for key in ["reset_in", "resetIn", "ttl"] {
        if let Some(seconds) = number(record.get(key)).filter(|seconds| *seconds > 0.0) {
            return Some(now_ms + (seconds * 1000.0) as i64);
        }
    }
    None
}

/// Kimi names a window by a duration and a unit such as `TIME_UNIT_MINUTE`.
fn kimi_window_seconds(window: &Value) -> Option<i64> {
    let duration = number(window.get("duration")).filter(|value| *value > 0.0)?;
    let unit = text(window.get("timeUnit"))
        .or_else(|| text(window.get("time_unit")))
        .unwrap_or_default()
        .to_uppercase();
    let unit = unit.trim_start_matches("TIME_UNIT_").trim_end_matches('S');
    let seconds = match unit {
        "SECOND" => 1.0,
        "" | "MINUTE" => 60.0,
        "HOUR" => 3600.0,
        "DAY" => 86_400.0,
        "WEEK" => 604_800.0,
        _ => return None,
    };
    Some((duration * seconds) as i64)
}

/// One Kimi limit as a window: what is used of what is allowed.
fn kimi_window(item: &Value, now_ms: i64) -> Option<Window> {
    let detail = item
        .get("detail")
        .filter(|value| value.is_object())
        .unwrap_or(item);
    let limit = number(detail.get("limit")).filter(|limit| *limit > 0.0)?;
    let used = number(detail.get("used"))
        .or_else(|| number(detail.get("remaining")).map(|remaining| limit - remaining))?;
    // A limit's name says which window it is. Only a scope names a model.
    let scope = text(item.get("scope"))
        .or_else(|| text(detail.get("scope")))
        .unwrap_or_default();
    let seconds = item
        .get("window")
        .and_then(kimi_window_seconds)
        .or_else(|| kimi_window_seconds(item))
        .or_else(|| kimi_window_seconds(detail))
        .unwrap_or(0);
    Some(Window {
        kind: WindowKind::from_seconds(seconds),
        scope,
        used_percent: (used / limit * 100.0).clamp(0.0, 100.0),
        resets_at_ms: reset_ms(detail, now_ms).or_else(|| reset_ms(item, now_ms)),
        limit_reached: used >= limit,
    })
}

/// The quota in a Kimi `usages` answer: each limit is one window, and the
/// plain `usage` stands in when the list is absent.
pub fn parse_kimi(payload: &Value, now_ms: i64) -> Option<Quota> {
    let mut windows: Vec<Window> = payload
        .get("limits")
        .and_then(Value::as_array)
        .map(|limits| {
            limits
                .iter()
                .filter_map(|item| kimi_window(item, now_ms))
                .collect()
        })
        .unwrap_or_default();
    if windows.is_empty() {
        if let Some(window) = payload
            .get("usage")
            .and_then(|usage| kimi_window(usage, now_ms))
        {
            windows.push(window);
        }
    }
    if windows.is_empty() {
        return None;
    }
    Some(Quota {
        plan: text(payload.get("plan")).or_else(|| text(payload.get("plan_name"))),
        email: text(payload.get("email")),
        windows,
        banked_resets: None,
        observed_at_ms: now_ms,
    })
}

/// Antigravity names a window in words. The rest reads as one of its own.
fn antigravity_window_kind(window: &str) -> WindowKind {
    match window.trim().to_lowercase().as_str() {
        "5h" | "five-hour" | "five_hour" | "five hour" => WindowKind::FiveHour,
        "daily" | "day" | "24h" => WindowKind::Daily,
        "weekly" | "week" => WindowKind::Weekly,
        "monthly" | "month" => WindowKind::Monthly,
        _ => WindowKind::Other,
    }
}

/// The quota in an Antigravity `retrieveUserQuotaSummary` answer: every
/// bucket of every group is one window scoped to the model family it names,
/// and the fraction left becomes the percent used the screen shows.
pub fn parse_antigravity(payload: &Value, now_ms: i64) -> Option<Quota> {
    let mut windows = Vec::new();
    for group in payload.get("groups").and_then(Value::as_array)? {
        for bucket in group
            .get("buckets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(remaining) = number(bucket.get("remainingFraction"))
                .or_else(|| number(bucket.get("remaining_fraction")))
            else {
                continue;
            };
            let remaining = remaining.clamp(0.0, 1.0);
            windows.push(Window {
                kind: antigravity_window_kind(&text(bucket.get("window")).unwrap_or_default()),
                scope: text(bucket.get("displayName"))
                    .or_else(|| text(bucket.get("display_name")))
                    .or_else(|| text(bucket.get("bucketId")))
                    .unwrap_or_default(),
                used_percent: ((1.0 - remaining) * 100.0).clamp(0.0, 100.0),
                resets_at_ms: rfc3339_ms(bucket.get("resetTime"))
                    .or_else(|| rfc3339_ms(bucket.get("reset_time"))),
                limit_reached: remaining <= 0.0,
            });
        }
    }
    if windows.is_empty() {
        return None;
    }
    Some(Quota {
        plan: payload
            .get("currentTier")
            .and_then(|tier| text(tier.get("name")).or_else(|| text(tier.get("id")))),
        email: None,
        windows,
        banked_resets: None,
        observed_at_ms: now_ms,
    })
}

/// Protobuf wire helpers, enough for Devin's one request and one answer.
mod proto {
    pub fn varint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    pub fn bytes_field(field: u32, data: &[u8], out: &mut Vec<u8>) {
        varint(u64::from(field) << 3 | 2, out);
        varint(data.len() as u64, out);
        out.extend_from_slice(data);
    }

    pub fn string_field(field: u32, text: &str, out: &mut Vec<u8>) {
        bytes_field(field, text.as_bytes(), out);
    }

    fn read_varint(data: &[u8], at: &mut usize) -> Option<u64> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *data.get(*at)?;
            *at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }

    /// One field as the wire carries it.
    pub enum Field<'a> {
        Varint(u64),
        Bytes(&'a [u8]),
        Other,
    }

    /// Every top-level field of a message, in order.
    pub fn fields(data: &[u8]) -> Vec<(u32, Field<'_>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < data.len() {
            let Some(key) = read_varint(data, &mut at) else {
                break;
            };
            let number = (key >> 3) as u32;
            match key & 7 {
                0 => match read_varint(data, &mut at) {
                    Some(value) => out.push((number, Field::Varint(value))),
                    None => break,
                },
                1 => {
                    at += 8;
                    out.push((number, Field::Other));
                }
                2 => {
                    let Some(length) = read_varint(data, &mut at) else {
                        break;
                    };
                    let end = at.saturating_add(length as usize);
                    if end > data.len() {
                        break;
                    }
                    out.push((number, Field::Bytes(&data[at..end])));
                    at = end;
                }
                5 => {
                    at += 4;
                    out.push((number, Field::Other));
                }
                _ => break,
            }
        }
        out
    }
}

/// A 732-character hex fingerprint Devin's seat service wants, derived from a
/// seed so one account presents one device.
pub fn devin_fingerprint(seed: &str) -> String {
    use sha2::Digest;
    let mut out = String::new();
    let mut counter = 0;
    while out.len() < 732 {
        let digest = sha2::Sha256::digest(format!("{seed}-{counter}").as_bytes());
        out.push_str(
            &digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        counter += 1;
    }
    out.truncate(732);
    out
}

/// The `GetUserStatus` request as Devin's CLI sends it.
pub fn devin_status_request(session_token: &str, fingerprint: &str) -> Vec<u8> {
    let mut metadata = Vec::new();
    proto::string_field(1, "chisel", &mut metadata);
    proto::string_field(2, "3000.10.21", &mut metadata);
    proto::string_field(3, session_token, &mut metadata);
    proto::string_field(4, "en", &mut metadata);
    proto::string_field(5, std::env::consts::OS, &mut metadata);
    proto::string_field(7, "3000.10.21", &mut metadata);
    proto::string_field(12, "chisel", &mut metadata);
    proto::string_field(31, fingerprint, &mut metadata);
    let mut request = Vec::new();
    proto::bytes_field(1, &metadata, &mut request);
    request
}

/// The quota in a `GetUserStatus` answer: the daily and weekly percent left,
/// their resets, the plan and the email.
pub fn parse_devin_status(bytes: &[u8], now_ms: i64) -> Option<Quota> {
    use proto::Field;
    let mut email = None;
    let mut plan = None;
    let mut daily: Option<(f64, Option<i64>)> = None;
    let mut weekly: Option<(f64, Option<i64>)> = None;
    let status = proto::fields(bytes)
        .into_iter()
        .find_map(|(number, field)| match field {
            Field::Bytes(data) if number == 1 => Some(data),
            _ => None,
        })?;
    for (number, field) in proto::fields(status) {
        match (number, field) {
            (7, Field::Bytes(data)) => email = String::from_utf8(data.to_vec()).ok(),
            (13, Field::Bytes(plan_status)) => {
                let mut daily_left = None;
                let mut weekly_left = None;
                let mut daily_reset = None;
                let mut weekly_reset = None;
                for (inner, value) in proto::fields(plan_status) {
                    match (inner, value) {
                        (1, Field::Bytes(info)) => {
                            for (key, item) in proto::fields(info) {
                                if let (2, Field::Bytes(name)) = (key, item) {
                                    plan = String::from_utf8(name.to_vec()).ok();
                                }
                            }
                        }
                        (14, Field::Varint(value)) => daily_left = Some(value as f64),
                        (15, Field::Varint(value)) => weekly_left = Some(value as f64),
                        (17, Field::Varint(value)) if value > 0 => {
                            daily_reset = Some(value as i64 * 1000)
                        }
                        (18, Field::Varint(value)) if value > 0 => {
                            weekly_reset = Some(value as i64 * 1000)
                        }
                        _ => {}
                    }
                }
                daily = daily_left.map(|left| (left, daily_reset));
                weekly = weekly_left.map(|left| (left, weekly_reset));
            }
            _ => {}
        }
    }
    let mut windows = Vec::new();
    for (kind, value) in [(WindowKind::Daily, daily), (WindowKind::Weekly, weekly)] {
        if let Some((left, resets_at_ms)) = value {
            windows.push(Window {
                kind,
                scope: String::new(),
                used_percent: (100.0 - left).clamp(0.0, 100.0),
                resets_at_ms,
                limit_reached: left <= 0.0,
            });
        }
    }
    if windows.is_empty() {
        return None;
    }
    Some(Quota {
        plan,
        email,
        windows,
        banked_resets: None,
        observed_at_ms: now_ms,
    })
}

/// Asks Kimi what this account has left.
pub fn probe_kimi(access: &str, device_id: &str, now_ms: i64, timeout: Duration) -> Option<Quota> {
    let bearer = format!("Bearer {access}");
    let mut headers = vec![("Authorization", bearer.as_str())];
    let device = super::native_auth::kimi_headers(device_id);
    let device: Vec<(&str, &str)> = device
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    headers.extend(device);
    parse_kimi(&fetch(KIMI_USAGE_URL, &headers, timeout)?, now_ms)
}

/// Asks Antigravity what this account has left in each of its buckets.
pub fn probe_antigravity(
    access: &str,
    project: Option<&str>,
    now_ms: i64,
    timeout: Duration,
) -> Option<Quota> {
    let bearer = format!("Bearer {access}");
    let headers = [
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/json"),
        ("User-Agent", super::native_auth::ANTIGRAVITY_USER_AGENT),
    ];
    let body = match project {
        Some(project) => serde_json::json!({"project": project}),
        None => serde_json::json!({}),
    };
    parse_antigravity(
        &post_json(ANTIGRAVITY_QUOTA_URL, &headers, body, timeout)?,
        now_ms,
    )
}

/// Asks Devin's seat service what this account has left today and this week.
pub fn probe_devin(session_token: &str, now_ms: i64, timeout: Duration) -> Option<Quota> {
    let authorization = format!("Basic {session_token}-{session_token}");
    let headers = [
        ("Authorization", authorization.as_str()),
        ("Connect-Protocol-Version", "1"),
        ("Content-Type", "application/proto"),
        ("Accept", "*/*"),
    ];
    let body = devin_status_request(session_token, &devin_fingerprint(session_token));
    let answer = post_bytes(
        &format!("{DEVIN_SERVER_URL}{DEVIN_STATUS_PATH}"),
        &headers,
        &body,
        timeout,
    )?;
    parse_devin_status(&answer, now_ms)
}

/// Whether the router has a usage route for this sign-in provider. xAI has
/// none, so its card says what the router cannot read.
pub fn has_reader(provider: &str) -> bool {
    matches!(
        provider,
        "openai-codex" | "anthropic" | "kimi" | "antigravity" | "devin" | "xai"
    )
}

/// Asks the account's upstream what it has left. A key has no window to ask
/// about, and a provider with no usage route answers nothing.
pub fn probe(account: &Account, now_ms: i64, timeout: Duration) -> Option<Quota> {
    match &account.credential {
        Credential::ApiKey { .. } => None,
        Credential::Subscription {
            provider,
            access,
            account_id,
            ..
        } => match provider.as_str() {
            "openai-codex" => probe_codex(access, account_id.as_deref(), now_ms, timeout),
            "anthropic" => probe_claude(access, now_ms, timeout),
            "xai" => probe_xai(access, account_id.as_deref(), now_ms, timeout),
            "kimi" => probe_kimi(
                access,
                account_id.as_deref().unwrap_or_default(),
                now_ms,
                timeout,
            ),
            "antigravity" => probe_antigravity(access, account_id.as_deref(), now_ms, timeout),
            "devin" => probe_devin(access, now_ms, timeout),
            _ => None,
        },
    }
}

/// Every account's last probe, keyed by account id.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QuotaStore {
    #[serde(default)]
    pub accounts: BTreeMap<String, Quota>,
}

pub fn quota_path(agent: &Path) -> PathBuf {
    agent.join(QUOTA_FILE)
}

/// Reads the store, or an empty one. A damaged store reads as empty: a lost
/// snapshot is refreshed by the next probe, and it must never stop a turn.
pub fn load(agent: &Path) -> QuotaStore {
    fs::read(quota_path(agent))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save(agent: &Path, store: &QuotaStore) -> io::Result<()> {
    fs::create_dir_all(agent)?;
    super::config::write_private(&quota_path(agent), &serde_json::to_vec_pretty(store)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grok_credits_parse_weekly_monthly_empty_and_exhausted() {
        let value = serde_json::json!({"config": {"creditUsagePercent": 42.5, "currentPeriod": {"type": "USAGE_PERIOD_TYPE_WEEKLY", "end": "2026-10-01T00:00:00Z"}}, "subscription_tier": "SuperGrok"});
        let quota = parse_xai(&value, 123).unwrap();
        assert_eq!(quota.windows[0].kind, WindowKind::Weekly);
        assert_eq!(quota.windows[0].remaining_percent(), 57.5);
        assert!(quota.windows[0].resets_at_ms.is_some());
        assert_eq!(quota.plan.as_deref(), Some("SuperGrok"));
        assert!(parse_xai(&serde_json::json!({"config": {}}), 0).is_none());
        let quota = parse_xai(
            &serde_json::json!({"config": {"monthlyLimit": {"val": 100}, "used": {"val": 150}}}),
            0,
        )
        .unwrap();
        assert_eq!(quota.windows[0].kind, WindowKind::Monthly);
        assert_eq!(quota.windows[0].remaining_percent(), 0.0);
        assert!(quota.windows[0].limit_reached);
    }

    use serde_json::json;

    /// A Pro account's answer, as `wham/usage` gave it.
    fn codex_pro() -> Value {
        json!({
            "account_id": "5ee281cb",
            "email": "mikey@example.com",
            "plan_type": "pro",
            "rate_limit": {
                "allowed": true,
                "limit_reached": false,
                "primary_window": {
                    "used_percent": 81,
                    "limit_window_seconds": 604800,
                    "reset_after_seconds": 104196,
                    "reset_at": 1789805858
                },
                "secondary_window": null
            },
            "additional_rate_limits": null,
            "rate_limit_reset_credits": { "available_count": 3, "applicable_available_count": 0 }
        })
    }

    #[test]
    fn a_window_is_known_by_its_length_not_its_slot() {
        assert_eq!(WindowKind::from_seconds(18_000), WindowKind::FiveHour);
        assert_eq!(WindowKind::from_seconds(604_800), WindowKind::Weekly);
        assert_eq!(WindowKind::from_seconds(30 * 86_400), WindowKind::Monthly);
        assert_eq!(WindowKind::from_seconds(60), WindowKind::Other);
        assert_eq!(WindowKind::from_seconds(86_400), WindowKind::Daily);
        assert_eq!(WindowKind::Daily.label(), "Daily window");
        // A Pro plan's primary window is the weekly one.
        let quota = parse_codex(&codex_pro(), 1_789_700_000_000).unwrap();
        assert_eq!(quota.windows.len(), 1);
        assert_eq!(quota.windows[0].kind, WindowKind::Weekly);
        assert_eq!(quota.windows[0].used_percent, 81.0);
        assert_eq!(quota.windows[0].remaining_percent(), 19.0);
        assert_eq!(quota.windows[0].resets_at_ms, Some(1_789_805_858_000));
        assert!(!quota.windows[0].limit_reached);
        assert_eq!(quota.plan.as_deref(), Some("pro"));
        assert_eq!(quota.email.as_deref(), Some("mikey@example.com"));
        assert_eq!(quota.banked_resets, Some(3));
        assert_eq!(quota.headline().unwrap().kind, WindowKind::Weekly);
    }

    #[test]
    fn a_plus_plan_carries_both_windows_and_a_scoped_extra_limit() {
        let payload = json!({
            "plan_type": "plus",
            "rate_limit": {
                "allowed": false,
                "limit_reached": true,
                "primary_window": { "used_percent": "100", "limit_window_seconds": 18000, "reset_after_seconds": 900 },
                "secondary_window": { "used_percent": 40, "limit_window_seconds": 604800, "reset_at": 1789805858 }
            },
            "additional_rate_limits": [{
                "limit_name": "GPT-5.3-Codex-Spark",
                "rate_limit": {
                    "limit_reached": false,
                    "primary_window": { "used_percent": 12, "limit_window_seconds": 604800 }
                }
            }]
        });
        let quota = parse_codex(&payload, 1_000_000).unwrap();
        assert_eq!(quota.windows.len(), 3);
        assert_eq!(quota.windows[0].kind, WindowKind::FiveHour);
        assert_eq!(quota.windows[0].used_percent, 100.0);
        assert!(quota.windows[0].limit_reached);
        // A reset given as seconds from now lands relative to the probe.
        assert_eq!(quota.windows[0].resets_at_ms, Some(1_000_000 + 900_000));
        assert_eq!(quota.windows[1].kind, WindowKind::Weekly);
        assert_eq!(quota.windows[2].scope, "GPT-5.3-Codex-Spark");
        assert!(!quota.windows[2].limit_reached);
        // The headline is the account-wide weekly, never the scoped one.
        let headline = quota.headline().unwrap();
        assert_eq!(headline.kind, WindowKind::Weekly);
        assert!(headline.scope.is_empty());
        assert_eq!(quota.banked_resets, None);
        assert!(parse_codex(&json!({}), 0).is_none());
    }

    #[test]
    fn a_claude_answer_reads_its_limits_list_with_scope_and_kind() {
        let payload = json!({
            "five_hour": { "utilization": 15.0, "resets_at": "2026-09-18T06:39:59.949775+00:00" },
            "seven_day": { "utilization": 41.0, "resets_at": "2026-09-20T21:59:58.949794+00:00" },
            "limits": [
                { "kind": "session", "group": "session", "percent": 15, "severity": "normal",
                  "resets_at": "2026-09-18T06:39:59.949775+00:00", "scope": null, "is_active": false },
                { "kind": "weekly_all", "group": "weekly", "percent": 41, "severity": "normal",
                  "resets_at": "2026-09-20T21:59:58.949794+00:00", "scope": null, "is_active": false },
                { "kind": "weekly_scoped", "group": "weekly", "percent": 73, "severity": "normal",
                  "resets_at": "2026-09-20T21:59:58.949990+00:00",
                  "scope": { "model": { "id": null, "display_name": "Fable" }, "surface": null }, "is_active": true }
            ]
        });
        let quota = parse_claude(&payload, 1_000).unwrap();
        assert_eq!(quota.windows.len(), 3);
        assert_eq!(quota.windows[0].kind, WindowKind::FiveHour);
        assert_eq!(quota.windows[0].remaining_percent(), 85.0);
        assert_eq!(quota.windows[1].kind, WindowKind::Weekly);
        assert_eq!(quota.windows[1].used_percent, 41.0);
        assert_eq!(quota.windows[2].scope, "Fable");
        assert_eq!(quota.windows[2].used_percent, 73.0);
        assert!(quota.windows[0].resets_at_ms.unwrap() > 1_700_000_000_000);
        assert_eq!(quota.headline().unwrap().used_percent, 41.0);
    }

    #[test]
    fn a_claude_answer_without_the_list_falls_back_to_its_named_windows() {
        let payload = json!({
            "five_hour": { "utilization": 15.0, "resets_at": "2026-09-18T06:39:59+00:00" },
            "seven_day": { "utilization": 41.0, "resets_at": null }
        });
        let quota = parse_claude(&payload, 1_000).unwrap();
        assert_eq!(quota.windows.len(), 2);
        assert_eq!(quota.windows[1].resets_at_ms, None);
        assert!(parse_claude(&json!({ "limits": [] }), 0).is_none());
    }

    #[test]
    fn a_key_has_no_window_to_ask_about() {
        let account = Account {
            id: "a1".into(),
            family: "openai".into(),
            label: "work".into(),
            credential: Credential::ApiKey { key: "sk".into() },
            base_url: None,
            models: Vec::new(),
            enabled: true,
            weight: 1,
        };
        assert_eq!(probe(&account, 0, Duration::from_millis(50)), None);
        // A subscription on a provider with no usage route answers nothing too.
        let xai = Account {
            credential: Credential::Subscription {
                provider: "xai".into(),
                access: "at".into(),
                refresh: None,
                expires_ms: None,
                account_id: None,
                email: None,
                plan: None,
                renews_at_ms: None,
            },
            ..account
        };
        assert!(xai.credential.pi_provider().is_some());
        assert!(has_reader("xai"));
        assert!(has_reader("anthropic") && has_reader("openai-codex"));
    }

    #[test]
    fn a_kimi_answer_reads_each_limit_as_a_window_by_its_duration() {
        let payload = json!({
            "limits": [
                { "name": "Weekly", "window": { "duration": 10080, "timeUnit": "TIME_UNIT_MINUTE" },
                  "detail": { "used": 30, "limit": 100, "reset_at": "2026-09-20T00:00:00Z" } },
                { "window": { "duration": 5, "timeUnit": "TIME_UNIT_HOUR" },
                  "detail": { "remaining": 15, "limit": 60, "reset_in": 900 } }
            ]
        });
        let quota = parse_kimi(&payload, 1_000_000).unwrap();
        assert_eq!(quota.windows.len(), 2);
        assert_eq!(quota.windows[0].kind, WindowKind::Weekly);
        assert_eq!(quota.windows[0].scope, "");
        assert_eq!(quota.windows[0].used_percent, 30.0);
        assert!(quota.windows[0].resets_at_ms.unwrap() > 1_700_000_000_000);
        assert_eq!(quota.windows[1].kind, WindowKind::FiveHour);
        assert_eq!(quota.windows[1].used_percent, 75.0);
        assert_eq!(quota.windows[1].resets_at_ms, Some(1_000_000 + 900_000));
        assert_eq!(quota.headline().unwrap().kind, WindowKind::Weekly);
        // The plain usage stands in when the list is absent.
        let plain = parse_kimi(&json!({ "usage": { "used": 5, "limit": 10 } }), 0).unwrap();
        assert_eq!(plain.windows[0].used_percent, 50.0);
        assert!(parse_kimi(&json!({}), 0).is_none());
    }

    #[test]
    fn an_antigravity_answer_reads_each_bucket_as_a_scoped_window() {
        let payload = json!({
            "groups": [{ "displayName": "Gemini", "buckets": [
                { "displayName": "Gemini 3 Pro", "window": "5h", "remainingFraction": 0.25, "resetTime": "2026-09-18T12:00:00Z" },
                { "displayName": "Gemini 3 Pro", "window": "weekly", "remainingFraction": "0", "resetTime": "2026-09-21T00:00:00Z" }
            ] }],
            "currentTier": { "id": "g1-pro-tier", "name": "Google AI Pro" }
        });
        let quota = parse_antigravity(&payload, 5).unwrap();
        assert_eq!(quota.windows.len(), 2);
        assert_eq!(quota.windows[0].kind, WindowKind::FiveHour);
        assert_eq!(quota.windows[0].scope, "Gemini 3 Pro");
        assert_eq!(quota.windows[0].used_percent, 75.0);
        assert_eq!(quota.windows[1].kind, WindowKind::Weekly);
        assert!(quota.windows[1].limit_reached);
        assert_eq!(quota.plan.as_deref(), Some("Google AI Pro"));
        assert!(parse_antigravity(&json!({ "groups": [] }), 0).is_none());
    }

    #[test]
    fn a_devin_status_round_trips_through_the_wire() {
        // The request names the token and a device of 732 hex characters.
        let fingerprint = devin_fingerprint("token-1");
        assert_eq!(fingerprint.len(), 732);
        assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(fingerprint, devin_fingerprint("token-1"));
        let request = devin_status_request("devin-session-token$eyJ", &fingerprint);
        let outer = proto::fields(&request);
        assert_eq!(outer.len(), 1);
        let metadata = match &outer[0] {
            (1, proto::Field::Bytes(data)) => *data,
            _ => panic!("the request wraps its metadata in field 1"),
        };
        let names: Vec<u32> = proto::fields(metadata)
            .iter()
            .map(|(number, _)| *number)
            .collect();
        assert_eq!(names, [1, 2, 3, 4, 5, 7, 12, 31]);

        // An answer built the way the service builds it reads back.
        let mut plan_info = Vec::new();
        proto::string_field(2, "Devin Core", &mut plan_info);
        let mut plan_status = Vec::new();
        proto::bytes_field(1, &plan_info, &mut plan_status);
        proto::varint(14 << 3, &mut plan_status);
        proto::varint(40, &mut plan_status);
        proto::varint(15 << 3, &mut plan_status);
        proto::varint(90, &mut plan_status);
        proto::varint(17 << 3, &mut plan_status);
        proto::varint(1_789_800_000, &mut plan_status);
        let mut status = Vec::new();
        proto::string_field(3, "mikey", &mut status);
        proto::string_field(7, "mikey@example.com", &mut status);
        proto::bytes_field(13, &plan_status, &mut status);
        let mut answer = Vec::new();
        proto::bytes_field(1, &status, &mut answer);
        let quota = parse_devin_status(&answer, 7).unwrap();
        assert_eq!(quota.email.as_deref(), Some("mikey@example.com"));
        assert_eq!(quota.plan.as_deref(), Some("Devin Core"));
        assert_eq!(quota.windows.len(), 2);
        assert_eq!(quota.windows[0].kind, WindowKind::Daily);
        assert_eq!(quota.windows[0].used_percent, 60.0);
        assert_eq!(quota.windows[0].resets_at_ms, Some(1_789_800_000_000));
        assert_eq!(quota.windows[1].kind, WindowKind::Weekly);
        assert_eq!(quota.windows[1].remaining_percent(), 90.0);
        assert_eq!(quota.headline().unwrap().kind, WindowKind::Weekly);
        assert!(parse_devin_status(&[], 0).is_none());
    }

    #[test]
    fn the_store_reads_back_and_a_damaged_one_reads_as_empty() {
        let agent =
            std::env::temp_dir().join(format!("muniment-router-quota-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&agent).unwrap();
        let mut store = QuotaStore::default();
        store
            .accounts
            .insert("a1".into(), parse_codex(&codex_pro(), 5).unwrap());
        save(&agent, &store).unwrap();
        assert_eq!(load(&agent), store);
        fs::write(quota_path(&agent), b"nope").unwrap();
        assert_eq!(load(&agent), QuotaStore::default());
    }
}
