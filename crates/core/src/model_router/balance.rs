//! Which account of a pool takes the next turn.
//!
//! The rule is least-loaded weighted round robin: among the accounts that can
//! serve the model and are not cooling, the one whose served share sits
//! furthest below its weight goes next. A pool of equal weights alternates. A
//! pool with one account at weight 3 and one at weight 1 sends three turns to
//! the first for every one to the second.

use super::config::{Account, RouterConfig};
use super::usage::Ledger;

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
}

impl PickError {
    /// The sentence the composer shows.
    pub fn message(&self) -> String {
        match self {
            Self::EmptyPool => "No account is connected for this provider. Add one in Settings → Models.".into(),
            Self::AllDisabled => "Every account for this provider is turned off. Turn one on in Settings → Models.".into(),
            Self::NoneServesModel => "No connected account serves this model. Add the model to an account in Settings → Models.".into(),
            Self::AllCooling { .. } => "Every account for this provider is rate limited. Wait, or add another account.".into(),
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
    let pool = config.pool(family);
    if pool.is_empty() {
        return Err(PickError::EmptyPool);
    }
    let live: Vec<&Account> = pool
        .iter()
        .copied()
        .filter(|account| account.enabled && account.weight > 0)
        .collect();
    if live.is_empty() {
        return Err(PickError::AllDisabled);
    }
    let serving: Vec<&Account> = live
        .iter()
        .copied()
        .filter(|account| account.serves(model))
        .collect();
    if serving.is_empty() {
        return Err(PickError::NoneServesModel);
    }
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
    // fresh pool starts at its first account and then alternates.
    let served: Vec<u64> = ready
        .iter()
        .map(|account| {
            ledger
                .account(&account.id)
                .map(|usage| usage.requests)
                .unwrap_or(0)
        })
        .collect();
    let mut best = 0;
    for index in 1..ready.len() {
        // served[i] / weight[i] < served[best] / weight[best], without division.
        let left = served[index] as u128 * ready[best].weight as u128;
        let right = served[best] as u128 * ready[index].weight as u128;
        if left < right {
            best = index;
        }
    }
    Ok(ready[best])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_router::config::{Credential, RouterConfig};

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
        }
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
}
