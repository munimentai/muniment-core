//! What each account has served: the counters Settings shows and the cooldown
//! the balancer honors.
//!
//! The ledger carries no prompt and no reply. It counts turns, tokens and
//! failures, and it names the last failure so a user can see why an account
//! stopped taking its share.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The ledger's file in the agent directory.
pub const USAGE_FILE: &str = "muniment-router-usage.json";
/// How many daily buckets the ledger keeps for the usage bar.
pub const DAYS_KEPT: usize = 30;
/// The first cooldown after a refusal, and the ceiling repeated refusals reach.
pub const FIRST_COOLDOWN_MS: i64 = 15_000;
pub const MAX_COOLDOWN_MS: i64 = 15 * 60 * 1000;

/// One day of one account's work.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DayUsage {
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub errors: u64,
}

/// One account's whole record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountUsage {
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub errors: u64,
    /// Unix milliseconds of the last turn this account served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_ms: Option<i64>,
    /// The upstream's own words for the last refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Unix milliseconds until which the balancer skips this account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_until_ms: Option<i64>,
    /// Refusals in a row. It sets the next cooldown and a success clears it.
    #[serde(default)]
    pub strikes: u32,
    /// `YYYY-MM-DD` to that day's work, newest day last, [`DAYS_KEPT`] at most.
    #[serde(default)]
    pub days: BTreeMap<String, DayUsage>,
}

impl AccountUsage {
    /// Whether the balancer may send a turn to this account at `now_ms`.
    pub fn available(&self, now_ms: i64) -> bool {
        self.cooldown_until_ms.is_none_or(|until| now_ms >= until)
    }
}

/// Every account's record, keyed by account id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    #[serde(default)]
    pub accounts: BTreeMap<String, AccountUsage>,
}

impl Ledger {
    pub fn account(&self, id: &str) -> Option<&AccountUsage> {
        self.accounts.get(id)
    }

    /// Whether the balancer may send a turn to `id` at `now_ms`. An account
    /// with no record has served nothing and is available.
    pub fn available(&self, id: &str, now_ms: i64) -> bool {
        self.accounts
            .get(id)
            .is_none_or(|usage| usage.available(now_ms))
    }

    /// Counts one served turn and clears the account's cooldown.
    pub fn record_success(
        &mut self,
        id: &str,
        day: &str,
        now_ms: i64,
        input_tokens: u64,
        output_tokens: u64,
    ) {
        let usage = self.accounts.entry(id.to_owned()).or_default();
        usage.requests += 1;
        usage.input_tokens += input_tokens;
        usage.output_tokens += output_tokens;
        usage.last_used_ms = Some(now_ms);
        usage.last_error = None;
        usage.cooldown_until_ms = None;
        usage.strikes = 0;
        let bucket = usage.days.entry(day.to_owned()).or_default();
        bucket.requests += 1;
        bucket.input_tokens += input_tokens;
        bucket.output_tokens += output_tokens;
        trim(&mut usage.days);
    }

    /// Counts one refusal and puts the account in cooldown when `cools` says
    /// the upstream refused the account itself, not the request.
    pub fn record_error(&mut self, id: &str, day: &str, now_ms: i64, message: &str, cools: bool) {
        let usage = self.accounts.entry(id.to_owned()).or_default();
        usage.errors += 1;
        usage.last_error = Some(clip(message));
        usage.last_used_ms = Some(now_ms);
        if cools {
            usage.strikes = usage.strikes.saturating_add(1);
            usage.cooldown_until_ms = Some(now_ms + cooldown_ms(usage.strikes));
        }
        let bucket = usage.days.entry(day.to_owned()).or_default();
        bucket.errors += 1;
        trim(&mut usage.days);
    }

    /// Drops the record of an account the user removed.
    pub fn forget(&mut self, id: &str) {
        self.accounts.remove(id);
    }
}

/// The cooldown a run of `strikes` refusals earns: 15 seconds doubling to 15
/// minutes, so one refusing account stops taking its share without going away.
pub fn cooldown_ms(strikes: u32) -> i64 {
    let doublings = strikes.saturating_sub(1).min(16);
    FIRST_COOLDOWN_MS
        .saturating_mul(1_i64 << doublings)
        .min(MAX_COOLDOWN_MS)
}

/// Whether an upstream status means the account itself is refused, so the
/// balancer should pass it over: rate limits, auth failures and quota.
pub fn status_cools(status: u16) -> bool {
    matches!(status, 401 | 402 | 403 | 429) || status >= 500
}

fn clip(message: &str) -> String {
    let message = message.trim();
    if message.chars().count() <= 240 {
        return message.to_owned();
    }
    message.chars().take(240).collect()
}

fn trim(days: &mut BTreeMap<String, DayUsage>) {
    while days.len() > DAYS_KEPT {
        let Some(oldest) = days.keys().next().cloned() else {
            break;
        };
        days.remove(&oldest);
    }
}

/// The ledger's file inside an agent directory.
pub fn usage_path(agent: &Path) -> PathBuf {
    agent.join(USAGE_FILE)
}

/// Reads the ledger, or an empty one when nothing has been served yet. A
/// ledger that cannot be parsed reads as empty: counters are not the product,
/// and a lost count must never stop a turn.
pub fn load(agent: &Path) -> Ledger {
    fs::read(usage_path(agent))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Replaces the ledger.
pub fn save(agent: &Path, ledger: &Ledger) -> io::Result<()> {
    fs::create_dir_all(agent)?;
    let bytes = serde_json::to_vec_pretty(ledger)?;
    super::config::write_private(&usage_path(agent), &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_served_turn_counts_once_in_the_total_and_in_its_day() {
        let mut ledger = Ledger::default();
        ledger.record_success("a1", "2026-09-17", 1_000, 300, 40);
        ledger.record_success("a1", "2026-09-17", 2_000, 100, 10);
        let usage = ledger.account("a1").unwrap();
        assert_eq!(usage.requests, 2);
        assert_eq!(usage.input_tokens, 400);
        assert_eq!(usage.output_tokens, 50);
        assert_eq!(usage.last_used_ms, Some(2_000));
        assert_eq!(usage.days["2026-09-17"].requests, 2);
        assert_eq!(usage.days["2026-09-17"].input_tokens, 400);
    }

    #[test]
    fn a_refusal_cools_the_account_and_a_success_clears_it() {
        let mut ledger = Ledger::default();
        ledger.record_error("a1", "2026-09-17", 1_000, "429 rate limit", true);
        let usage = ledger.account("a1").unwrap();
        assert_eq!(usage.errors, 1);
        assert_eq!(usage.strikes, 1);
        assert_eq!(usage.cooldown_until_ms, Some(1_000 + FIRST_COOLDOWN_MS));
        assert!(!ledger.available("a1", 1_000));
        assert!(ledger.available("a1", 1_000 + FIRST_COOLDOWN_MS));
        assert!(ledger.available("a2", 1_000));
        ledger.record_error("a1", "2026-09-17", 2_000, "429 again", true);
        assert_eq!(
            ledger.account("a1").unwrap().cooldown_until_ms,
            Some(2_000 + FIRST_COOLDOWN_MS * 2)
        );
        ledger.record_success("a1", "2026-09-17", 3_000, 10, 2);
        let usage = ledger.account("a1").unwrap();
        assert_eq!(usage.strikes, 0);
        assert_eq!(usage.cooldown_until_ms, None);
        assert_eq!(usage.last_error, None);
        assert_eq!(usage.errors, 2);
        assert_eq!(usage.days["2026-09-17"].errors, 2);
    }

    #[test]
    fn a_bad_request_counts_without_cooling_the_account() {
        let mut ledger = Ledger::default();
        ledger.record_error("a1", "2026-09-17", 1_000, "400 bad model", false);
        let usage = ledger.account("a1").unwrap();
        assert_eq!(usage.errors, 1);
        assert_eq!(usage.strikes, 0);
        assert_eq!(usage.cooldown_until_ms, None);
        assert!(ledger.available("a1", 1_000));
    }

    #[test]
    fn the_cooldown_doubles_to_its_ceiling_and_stops_there() {
        assert_eq!(cooldown_ms(1), FIRST_COOLDOWN_MS);
        assert_eq!(cooldown_ms(2), FIRST_COOLDOWN_MS * 2);
        assert_eq!(cooldown_ms(3), FIRST_COOLDOWN_MS * 4);
        assert_eq!(cooldown_ms(40), MAX_COOLDOWN_MS);
        assert_eq!(cooldown_ms(0), FIRST_COOLDOWN_MS);
    }

    #[test]
    fn only_an_account_refusal_cools_the_account() {
        for status in [401, 402, 403, 429, 500, 503] {
            assert!(status_cools(status), "{status} must cool");
        }
        for status in [400, 404, 422] {
            assert!(!status_cools(status), "{status} must not cool");
        }
    }

    #[test]
    fn the_ledger_keeps_its_last_thirty_days() {
        let mut ledger = Ledger::default();
        for day in 1..=40 {
            ledger.record_success("a1", &format!("2026-09-{day:02}"), 1_000, 1, 1);
        }
        let usage = ledger.account("a1").unwrap();
        assert_eq!(usage.days.len(), DAYS_KEPT);
        assert!(!usage.days.contains_key("2026-09-01"));
        assert!(usage.days.contains_key("2026-09-40"));
        assert_eq!(usage.requests, 40);
    }

    #[test]
    fn a_ledger_reads_back_and_a_damaged_one_reads_as_empty() {
        let agent = std::env::temp_dir().join(format!("muniment-usage-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&agent).unwrap();
        let mut ledger = Ledger::default();
        ledger.record_success("a1", "2026-09-17", 1_000, 5, 1);
        save(&agent, &ledger).unwrap();
        assert_eq!(load(&agent), ledger);
        fs::write(usage_path(&agent), b"not json").unwrap();
        assert_eq!(load(&agent), Ledger::default());
    }

    #[test]
    fn a_removed_account_loses_its_record() {
        let mut ledger = Ledger::default();
        ledger.record_success("a1", "2026-09-17", 1_000, 5, 1);
        ledger.forget("a1");
        assert!(ledger.account("a1").is_none());
    }

    #[test]
    fn a_long_upstream_message_is_clipped() {
        let mut ledger = Ledger::default();
        ledger.record_error("a1", "2026-09-17", 1_000, &"x".repeat(1_000), true);
        assert_eq!(
            ledger
                .account("a1")
                .unwrap()
                .last_error
                .as_ref()
                .unwrap()
                .chars()
                .count(),
            240
        );
    }
}
