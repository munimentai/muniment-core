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
pub const TIMEOUT: Duration = Duration::from_secs(12);

const FIVE_HOURS: i64 = 5 * 60 * 60;
const ONE_WEEK: i64 = 7 * 24 * 60 * 60;
const MONTH_LOW: i64 = 28 * 24 * 60 * 60;
const MONTH_HIGH: i64 = 31 * 24 * 60 * 60;

/// How long a window runs. The upstream says it in seconds, and the label
/// follows the length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowKind {
    FiveHour,
    Weekly,
    Monthly,
    Other,
}

impl WindowKind {
    /// The kind a window of `seconds` is.
    pub fn from_seconds(seconds: i64) -> Self {
        if seconds == FIVE_HOURS {
            Self::FiveHour
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
        assert_eq!(probe(&xai, 0, Duration::from_millis(50)), None);
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
