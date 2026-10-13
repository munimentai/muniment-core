//! Which account of a pool takes the next turn.
//!
//! The rule is least-loaded weighted round robin: among the accounts that can
//! serve the model and are not cooling, the one whose served share sits
//! furthest below its weight goes next. A pool of equal weights alternates. A
//! pool with one account at weight 3 and one at weight 1 sends three turns to
//! the first for every one to the second.
//!
//! The served share is the decayed recent count, not the lifetime one, so an
//! account added to a long-lived pool takes its share of new turns instead of
//! every turn until its lifetime count draws level.
//!
//! Keys and subscriptions never balance together. While a family has a
//! subscription that serves the model, its subscriptions take the turns, and
//! a key takes one only when it is marked overflow and every subscription is
//! cooling or spent. A family with no such subscription balances its keys.

use super::config::{Account, RouterConfig};
use super::usage::Ledger;

/// Shares closer than this are equal.
const TIE: f64 = 0.01;

/// Why no account could take a turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickError {
    /// The family holds no account at all.
    EmptyPool,
    /// Every account of the family is disabled or at weight zero.
    AllDisabled,
    /// No enabled account lists this model.
    NoneServesModel,
    /// Every candidate is cooling. Carries the earliest moment one returns.
    AllCooling { ready_at_ms: i64 },
    /// Every eligible account has a known exhausted allowance.
    UsageLimit,
}

impl PickError {
    /// The sentence the composer shows.
    pub fn message(&self) -> String {
        match self {
            Self::EmptyPool => "No account is connected for this provider. Add one in Settings → Models.".into(),
            Self::AllDisabled => "Every account for this provider is turned off. Turn one on in Settings → Models.".into(),
            Self::NoneServesModel => "No connected account serves this model. Add the model to an account in Settings → Models.".into(),
            Self::AllCooling { .. } => "Every account for this provider is temporarily unavailable.".into(),
            Self::UsageLimit => "This provider has no remaining allowance. Wait for the reset, add an account, or choose another provider.".into(),
        }
    }
}

/// The account that takes the next turn for `family` and `model`.
pub fn pick<'a>(
    config: &'a RouterConfig,
    ledger: &Ledger,
    family: &str,
    model: &str,
    now_ms: i64,
) -> Result<&'a Account, PickError> {
    pick_with_active(
        config,
        ledger,
        family,
        model,
        now_ms,
        &std::collections::BTreeMap::new(),
    )
}

/// Whether an account can take a turn on `model`: on, weighted, servable, and
/// serving the model. Cooling does not count against it.
pub fn usable(account: &Account, model: &str) -> bool {
    account.enabled && account.weight > 0 && account.credential.servable() && account.serves(model)
}

/// The accounts of `family` that balance together for `model`: its
/// subscriptions while any of them can serve the model, else its keys. A key
/// never balances with a subscription, so a subscription's turn never spills
/// into API billing by rotation.
pub fn balanced<'a>(config: &'a RouterConfig, family: &str, model: &str) -> Vec<&'a Account> {
    let usable: Vec<&Account> = config
        .pool(family)
        .into_iter()
        .filter(|account| usable(account, model))
        .collect();
    if usable.iter().any(|account| !account.is_key()) {
        usable
            .into_iter()
            .filter(|account| !account.is_key())
            .collect()
    } else {
        usable
    }
}

/// The keys that take a turn for `family` and `model` once every subscription
/// that balances for it is cooling or spent. Empty while the family has no
/// subscription for the model, because its keys then balance on their own.
pub fn overflow<'a>(config: &'a RouterConfig, family: &str, model: &str) -> Vec<&'a Account> {
    let usable: Vec<&Account> = config
        .pool(family)
        .into_iter()
        .filter(|account| usable(account, model))
        .collect();
    if !usable.iter().any(|account| !account.is_key()) {
        return Vec::new();
    }
    usable
        .into_iter()
        .filter(|account| account.is_key() && account.overflow)
        .collect()
}

/// Whether `family` has a subscription for `model` and every one is cooling,
/// the one state in which an overflow key may take the turn.
pub fn subscriptions_cooling(
    config: &RouterConfig,
    ledger: &Ledger,
    family: &str,
    model: &str,
    now_ms: i64,
) -> bool {
    let subscriptions: Vec<&Account> = balanced(config, family, model)
        .into_iter()
        .filter(|account| !account.is_key())
        .collect();
    !subscriptions.is_empty()
        && subscriptions
            .iter()
            .all(|account| !ledger.available(&account.id, now_ms))
}

/// Includes reserved turns so concurrent calls share the pool too.
pub fn pick_with_active<'a>(
    config: &'a RouterConfig,
    ledger: &Ledger,
    family: &str,
    model: &str,
    now_ms: i64,
    active: &std::collections::BTreeMap<String, u32>,
) -> Result<&'a Account, PickError> {
    let pool = config.pool(family);
    if pool.is_empty() {
        return Err(PickError::EmptyPool);
    }
    if !pool
        .iter()
        .any(|account| account.enabled && account.weight > 0 && account.credential.servable())
    {
        return Err(PickError::AllDisabled);
    }
    let serving = balanced(config, family, model);
    if serving.is_empty() {
        return Err(PickError::NoneServesModel);
    }
    match least_loaded(&serving, ledger, now_ms, active) {
        Err(PickError::AllCooling { ready_at_ms }) => {
            let spill = overflow(config, family, model);
            if spill.is_empty() {
                return Err(PickError::AllCooling { ready_at_ms });
            }
            least_loaded(&spill, ledger, now_ms, active).map_err(|error| match error {
                PickError::AllCooling { ready_at_ms: keys } => PickError::AllCooling {
                    ready_at_ms: ready_at_ms.min(keys),
                },
                other => other,
            })
        }
        picked => picked,
    }
}

/// The ready account of `serving` whose served share sits furthest below its
/// weight, or the earliest moment one returns when every one is cooling.
fn least_loaded<'a>(
    serving: &[&'a Account],
    ledger: &Ledger,
    now_ms: i64,
    active: &std::collections::BTreeMap<String, u32>,
) -> Result<&'a Account, PickError> {
    let ready: Vec<&Account> = serving
        .iter()
        .copied()
        .filter(|account| ledger.available(&account.id, now_ms))
        .collect();
    if ready.is_empty() {
        let ready_at_ms = serving
            .iter()
            .filter_map(|account| {
                ledger
                    .account(&account.id)
                    .and_then(|usage| usage.cooldown_until_ms)
            })
            .min()
            .unwrap_or(now_ms);
        return Err(PickError::AllCooling { ready_at_ms });
    }
    // The share each account has served against the share its weight claims.
    // The lowest ratio goes next, and configured order breaks a tie, so a
    // fresh pool starts at its first account and then alternates. Shares
    // within a hundredth of a turn tie, so decay between two turns served a
    // moment apart never reorders them.
    let share = |account: &Account| {
        let served = ledger
            .account(&account.id)
            .map(|usage| usage.recent(now_ms))
            .unwrap_or(0.0)
            + f64::from(*active.get(&account.id).unwrap_or(&0));
        served / f64::from(account.weight)
    };
    let mut best = 0;
    let mut lowest = share(ready[0]);
    for (index, account) in ready.iter().enumerate().skip(1) {
        let candidate = share(account);
        if candidate < lowest - TIE {
            best = index;
            lowest = candidate;
        }
    }
    Ok(ready[best])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Credential, RouterConfig};

    fn account(id: &str, family: &str, weight: u32) -> Account {
        Account {
            id: id.to_owned(),
            family: family.to_owned(),
            label: id.to_owned(),
            credential: Credential::ApiKey { key: "sk".into() },
            base_url: None,
            models: Vec::new(),
            enabled: true,
            weight,
            overflow: false,
        }
    }

    fn subscription(id: &str) -> Account {
        let mut account = account(id, "openai", 1);
        account.credential = Credential::Subscription {
            provider: "openai-codex".into(),
            access: "at".into(),
            refresh: None,
            expires_ms: None,
            account_id: Some(id.into()),
            email: None,
            plan: None,
            renews_at_ms: None,
        };
        account
    }

    fn overflow_key(id: &str) -> Account {
        let mut account = account(id, "openai", 1);
        account.overflow = true;
        account
    }

    fn config(accounts: Vec<Account>) -> RouterConfig {
        RouterConfig {
            enabled: true,
            accounts,
            ..RouterConfig::default()
        }
    }

    /// Serves `turns` turns and answers with the account id of each one.
    fn run(config: &RouterConfig, ledger: &mut Ledger, model: &str, turns: usize) -> Vec<String> {
        (0..turns)
            .map(|turn| {
                let picked = pick(config, ledger, "openai", model, 1_000 + turn as i64)
                    .unwrap()
                    .id
                    .clone();
                ledger.record_success(&picked, "2026-09-17", 1_000 + turn as i64, 1, 1);
                picked
            })
            .collect()
    }

    #[test]
    fn an_equal_pool_alternates() {
        let config = config(vec![account("a1", "openai", 1), account("a2", "openai", 1)]);
        let mut ledger = Ledger::default();
        assert_eq!(
            run(&config, &mut ledger, "gpt", 6),
            ["a1", "a2", "a1", "a2", "a1", "a2"]
        );
        assert_eq!(ledger.account("a1").unwrap().requests, 3);
        assert_eq!(ledger.account("a2").unwrap().requests, 3);
    }

    #[test]
    fn a_weighted_pool_serves_each_account_its_share() {
        let config = config(vec![account("a1", "openai", 3), account("a2", "openai", 1)]);
        let mut ledger = Ledger::default();
        run(&config, &mut ledger, "gpt", 8);
        assert_eq!(ledger.account("a1").unwrap().requests, 6);
        assert_eq!(ledger.account("a2").unwrap().requests, 2);
    }

    #[test]
    fn a_cooling_account_is_passed_over_and_comes_back() {
        let config = config(vec![account("a1", "openai", 1), account("a2", "openai", 1)]);
        let mut ledger = Ledger::default();
        ledger.record_error("a1", "2026-09-17", 1_000, "429", true);
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt", 1_100).unwrap().id,
            "a2"
        );
        let back = 1_000 + super::super::usage::FIRST_COOLDOWN_MS;
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt", back).unwrap().id,
            "a1"
        );
    }

    #[test]
    fn a_pool_that_cannot_answer_says_which_way_it_failed() {
        let mut config = config(vec![account("a1", "openai", 1)]);
        let mut ledger = Ledger::default();
        assert_eq!(
            pick(&config, &ledger, "anthropic", "claude", 1_000),
            Err(PickError::EmptyPool)
        );
        config.accounts[0].models = vec!["gpt-5.6-mini".into()];
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt-5.6", 1_000),
            Err(PickError::NoneServesModel)
        );
        assert!(pick(&config, &ledger, "openai", "gpt-5.6-mini", 1_000).is_ok());
        config.accounts[0].enabled = false;
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt-5.6-mini", 1_000),
            Err(PickError::AllDisabled)
        );
        config.accounts[0].enabled = true;
        config.accounts[0].weight = 0;
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt-5.6-mini", 1_000),
            Err(PickError::AllDisabled)
        );
        config.accounts[0].weight = 1;
        ledger.record_error("a1", "2026-09-17", 1_000, "429", true);
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt-5.6-mini", 1_100),
            Err(PickError::AllCooling {
                ready_at_ms: 1_000 + super::super::usage::FIRST_COOLDOWN_MS
            })
        );
        assert!(!PickError::EmptyPool.message().is_empty());
    }

    #[test]
    fn an_unsupported_subscription_is_never_picked() {
        let mut config = config(vec![account("a1", "openai", 1), account("s1", "openai", 1)]);
        config.accounts[1].credential = Credential::Subscription {
            provider: "devin".into(),
            access: "at".into(),
            refresh: None,
            expires_ms: None,
            account_id: None,
            email: None,
            plan: None,
            renews_at_ms: None,
        };
        let mut ledger = Ledger::default();
        // Four turns, and every one lands on the key.
        assert_eq!(
            run(&config, &mut ledger, "gpt", 4),
            ["a1", "a1", "a1", "a1"]
        );
        // A pool of subscriptions alone reads as all disabled, not as empty.
        config.accounts.remove(0);
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt", 1_000),
            Err(PickError::AllDisabled)
        );
    }

    #[test]
    fn a_pool_that_gains_an_account_sends_the_new_one_its_share_first() {
        let mut config = config(vec![account("a1", "openai", 1)]);
        let mut ledger = Ledger::default();
        run(&config, &mut ledger, "gpt", 4);
        config.accounts.push(account("a2", "openai", 1));
        // The new account has served nothing, so it takes turns until it draws level.
        assert_eq!(
            run(&config, &mut ledger, "gpt", 4),
            ["a2", "a2", "a2", "a2"]
        );
        assert_eq!(ledger.account("a1").unwrap().requests, 4);
        assert_eq!(ledger.account("a2").unwrap().requests, 4);
    }

    #[test]
    fn an_account_added_to_a_long_lived_pool_takes_its_share_not_every_turn() {
        use crate::usage::RECENT_HALF_LIFE_MS;
        let mut config = config(vec![account("a1", "openai", 1)]);
        let mut ledger = Ledger::default();
        // A thousand turns over the past day.
        let now = 24 * 60 * 60 * 1000;
        for turn in 0..1000 {
            ledger.record_success("a1", "2026-09-17", turn * 86_400, 1, 1);
        }
        config.accounts.push(account("a2", "openai", 1));
        let mut picked = Vec::new();
        for turn in 0..40 {
            let at = now + turn * 1_000;
            let id = pick(&config, &ledger, "openai", "gpt", at)
                .unwrap()
                .id
                .clone();
            ledger.record_success(&id, "2026-09-18", at, 1, 1);
            picked.push(id);
        }
        let old = picked.iter().filter(|id| *id == "a1").count();
        // Lifetime counts would send all forty to a2. The recent count lets
        // a2 catch up within a few turns and then the pool alternates.
        assert!(old >= 15, "a1 served {old} of 40");
        assert!(picked[..2].iter().all(|id| id == "a2"));
        assert!(ledger.account("a1").unwrap().recent(now) < RECENT_HALF_LIFE_MS as f64);
    }

    #[test]
    fn a_key_never_balances_with_a_subscription_of_its_family() {
        let config = config(vec![
            account("k1", "openai", 5),
            subscription("s1"),
            subscription("s2"),
        ]);
        let mut ledger = Ledger::default();
        assert_eq!(
            run(&config, &mut ledger, "gpt", 4),
            ["s1", "s2", "s1", "s2"]
        );
        // Every subscription cooling leaves the turn unserved, not on the key.
        ledger.record_error("s1", "2026-09-17", 2_000, "429", true);
        ledger.record_error("s2", "2026-09-17", 2_000, "429", true);
        assert!(matches!(
            pick(&config, &ledger, "openai", "gpt", 2_100),
            Err(PickError::AllCooling { .. })
        ));
        assert!(ledger.account("k1").is_none());
    }

    #[test]
    fn an_overflow_key_serves_only_while_every_subscription_cools() {
        let config = config(vec![
            account("k1", "openai", 1),
            overflow_key("k2"),
            subscription("s1"),
            subscription("s2"),
        ]);
        let mut ledger = Ledger::default();
        assert_eq!(run(&config, &mut ledger, "gpt", 2), ["s1", "s2"]);
        // One subscription cooling keeps the turn on the other.
        ledger.record_error("s1", "2026-09-17", 2_000, "429", true);
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt", 2_100).unwrap().id,
            "s2"
        );
        // Both cooling moves the turn to the overflow key, never the plain one.
        ledger.record_error("s2", "2026-09-17", 2_000, "429", true);
        assert!(subscriptions_cooling(
            &config, &ledger, "openai", "gpt", 2_100
        ));
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt", 2_100).unwrap().id,
            "k2"
        );
        // An overflow key cooling too reports the earliest return.
        ledger.record_error("k2", "2026-09-17", 2_050, "429", true);
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt", 2_100),
            Err(PickError::AllCooling {
                ready_at_ms: 2_000 + super::super::usage::FIRST_COOLDOWN_MS
            })
        );
        // A subscription back from cooling takes the next turn again.
        let back = 2_000 + super::super::usage::FIRST_COOLDOWN_MS;
        assert!(!subscriptions_cooling(
            &config, &ledger, "openai", "gpt", back
        ));
        assert_eq!(
            pick(&config, &ledger, "openai", "gpt", back)
                .unwrap()
                .credential
                .source(),
            "account"
        );
    }

    #[test]
    fn keys_serve_as_before_when_no_subscription_can() {
        let mut config = config(vec![
            account("k1", "openai", 1),
            overflow_key("k2"),
            subscription("s1"),
        ]);
        let mut ledger = Ledger::default();
        // A subscription that is off leaves the keys to balance alone.
        config.accounts[2].enabled = false;
        assert_eq!(
            run(&config, &mut ledger, "gpt", 4),
            ["k1", "k2", "k1", "k2"]
        );
        assert!(overflow(&config, "openai", "gpt").is_empty());
        // So does one that does not serve the model.
        config.accounts[2].enabled = true;
        config.accounts[2].models = vec!["gpt-other".into()];
        assert_eq!(
            balanced(&config, "openai", "gpt")
                .iter()
                .map(|account| account.id.as_str())
                .collect::<Vec<_>>(),
            ["k1", "k2"]
        );
        assert_eq!(
            balanced(&config, "openai", "gpt-other")
                .iter()
                .map(|account| account.id.as_str())
                .collect::<Vec<_>>(),
            ["s1"]
        );
        // Another family's subscription never holds a key back.
        config.accounts[2].models.clear();
        config.accounts[2].family = "anthropic".into();
        assert_eq!(balanced(&config, "openai", "gpt").len(), 2);
    }

    #[test]
    fn the_balanced_set_counts_subscriptions_while_any_serves_else_keys() {
        let mut config = config(vec![
            account("k1", "openai", 1),
            overflow_key("k2"),
            subscription("s1"),
            subscription("s2"),
        ]);
        let ids = |config: &RouterConfig| {
            balanced(config, "openai", "gpt")
                .iter()
                .map(|account| account.id.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&config), ["s1", "s2"]);
        assert_eq!(
            overflow(&config, "openai", "gpt")
                .iter()
                .map(|account| account.id.as_str())
                .collect::<Vec<_>>(),
            ["k2"]
        );
        config.accounts[2].weight = 0;
        assert_eq!(ids(&config), ["s2"]);
        config.accounts[3].enabled = false;
        assert_eq!(ids(&config), ["k1", "k2"]);
    }
}
