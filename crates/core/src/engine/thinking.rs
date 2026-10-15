//! Pi's thinking levels: the ladder, the levels one model supports, the
//! nearest supported level to a request, and the level Pi starts a model at.
//! Each rule follows the pinned Pi's own `getSupportedThinkingLevels`,
//! `clampThinkingLevel` and startup level, so a level the runtime picks is
//! the level Pi runs.

use serde_json::{Map, Value};

/// Every thinking level Pi knows, from none to the most.
pub const THINKING_LEVELS: [&str; 7] = ["off", "minimal", "low", "medium", "high", "xhigh", "max"];

/// The level Pi starts at when its settings name none.
pub const DEFAULT_THINKING_LEVEL: &str = "medium";

/// The settings key that holds the startup level of each model, keyed by
/// `provider/model`.
pub const MODEL_THINKING_LEVELS: &str = "modelThinkingLevels";

/// The settings key that holds the startup level of every other model.
pub const DEFAULT_THINKING_LEVEL_SETTING: &str = "defaultThinkingLevel";

/// The ladder entry for a level Pi knows.
pub fn thinking_level(level: &str) -> Option<&'static str> {
    THINKING_LEVELS.into_iter().find(|known| *known == level)
}

/// The levels a model supports, from Pi's model object. A model without
/// reasoning supports only `off`. A reasoning model supports `off` through
/// `high` unless its `thinkingLevelMap` maps a level to null, and `xhigh` and
/// `max` only when the map names them.
pub fn supported_thinking_levels(model: &Value) -> Vec<&'static str> {
    if model.get("reasoning").and_then(Value::as_bool) != Some(true) {
        return vec!["off"];
    }
    let map = model.get("thinkingLevelMap").and_then(Value::as_object);
    THINKING_LEVELS
        .into_iter()
        .filter(|level| {
            let mapped = map.and_then(|map| map.get(*level));
            if mapped.is_some_and(Value::is_null) {
                return false;
            }
            !matches!(*level, "xhigh" | "max") || mapped.is_some()
        })
        .collect()
}

/// The levels a model with no `thinkingLevelMap` supports: none without
/// reasoning, `off` through `high` with it.
pub fn reasoning_thinking_levels(reasoning: bool) -> Vec<&'static str> {
    if reasoning {
        THINKING_LEVELS[..5].to_vec()
    } else {
        Vec::new()
    }
}

/// The supported level nearest to `level`: the level itself, else the next
/// supported level above it, else the next below it. An unknown level answers
/// the first supported level, and no supported level answers `off`.
pub fn clamp_thinking_level(level: &str, available: &[&'static str]) -> &'static str {
    let first = available.first().copied().unwrap_or("off");
    let Some(requested) = THINKING_LEVELS.iter().position(|known| *known == level) else {
        return first;
    };
    THINKING_LEVELS[requested..]
        .iter()
        .chain(THINKING_LEVELS[..requested].iter().rev())
        .find(|candidate| available.contains(candidate))
        .copied()
        .unwrap_or(first)
}

/// The level Pi starts `provider/model` at, before clamping: the model's own
/// entry in `modelThinkingLevels`, else `defaultThinkingLevel`, else medium.
pub fn startup_thinking_level<'a>(
    settings: &'a Map<String, Value>,
    provider: &str,
    model: &str,
) -> &'a str {
    settings
        .get(MODEL_THINKING_LEVELS)
        .and_then(|levels| levels.get(format!("{provider}/{model}")))
        .and_then(Value::as_str)
        .or_else(|| {
            settings
                .get(DEFAULT_THINKING_LEVEL_SETTING)
                .and_then(Value::as_str)
        })
        .unwrap_or(DEFAULT_THINKING_LEVEL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_model_without_reasoning_supports_only_off() {
        assert_eq!(supported_thinking_levels(&json!({"id": "small"})), ["off"]);
        assert_eq!(
            supported_thinking_levels(
                &json!({"reasoning": false, "thinkingLevelMap": {"xhigh": "xhigh"}})
            ),
            ["off"]
        );
    }

    #[test]
    fn a_reasoning_model_supports_off_through_high_and_the_extra_levels_its_map_names() {
        assert_eq!(
            supported_thinking_levels(&json!({"reasoning": true})),
            ["off", "minimal", "low", "medium", "high"]
        );
        assert_eq!(
            supported_thinking_levels(
                &json!({"reasoning": true, "thinkingLevelMap": {"xhigh": "xhigh", "max": "max"}})
            ),
            ["off", "minimal", "low", "medium", "high", "xhigh", "max"]
        );
        assert_eq!(
            supported_thinking_levels(&json!({"reasoning": true, "thinkingLevelMap": {
                "off": null, "minimal": null, "low": "low", "medium": null, "high": "high", "xhigh": null, "max": "max"
            }})),
            ["low", "high", "max"]
        );
    }

    #[test]
    fn a_level_clamps_up_first_then_down() {
        let levels = ["low", "high", "max"];
        assert_eq!(clamp_thinking_level("high", &levels), "high");
        assert_eq!(clamp_thinking_level("medium", &levels), "high");
        assert_eq!(clamp_thinking_level("off", &levels), "low");
        assert_eq!(clamp_thinking_level("xhigh", &levels), "max");
        let ladder = ["off", "minimal", "low", "medium", "high"];
        assert_eq!(clamp_thinking_level("max", &ladder), "high");
        assert_eq!(clamp_thinking_level("unknown", &ladder), "off");
        assert_eq!(clamp_thinking_level("high", &["off"]), "off");
        assert_eq!(clamp_thinking_level("high", &[]), "off");
    }

    #[test]
    fn the_startup_level_prefers_the_model_entry_then_the_default_then_medium() {
        let settings = json!({
            "defaultThinkingLevel": "low",
            "modelThinkingLevels": {"openai/gpt": "xhigh"}
        });
        let settings = settings.as_object().unwrap();
        assert_eq!(startup_thinking_level(settings, "openai", "gpt"), "xhigh");
        assert_eq!(startup_thinking_level(settings, "openai", "other"), "low");
        assert_eq!(
            startup_thinking_level(&Map::new(), "openai", "gpt"),
            "medium"
        );
    }

    #[test]
    fn only_ladder_names_are_levels() {
        assert_eq!(thinking_level("xhigh"), Some("xhigh"));
        assert_eq!(thinking_level("High"), None);
        assert_eq!(reasoning_thinking_levels(false), Vec::<&str>::new());
        assert_eq!(reasoning_thinking_levels(true).last(), Some(&"high"));
    }
}
