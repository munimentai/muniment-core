//! What each model is for, as the classifier reads it.
//!
//! Every model an enabled account can serve is in the running when the
//! classifier picks. A model id means nothing to a classifier, so each entry
//! carries a statement: the work it wins, then the cost or the weakness that
//! should push a query to another one. The statement is the whole reason a
//! route is chosen, so it names a query shape, never a benchmark.
//!
//! Prices are per million tokens as the provider lists them, and they move.
//! An account may name models of its own, and those serve without an entry
//! here, described by their id alone.

/// One model, and the statement that puts it in the running.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelEntry {
    pub family: &'static str,
    pub model: &'static str,
    pub name: &'static str,
    /// `deep`, `balanced` or `fast`.
    pub tier: &'static str,
    /// US dollars per million input tokens.
    pub price: f64,
    /// US dollars per million output tokens.
    pub output: f64,
    pub context: &'static str,
    /// The work this model wins, in query shapes.
    pub strengths: &'static str,
    /// The cost or weakness that sends a query elsewhere.
    pub limits: &'static str,
}

impl ModelEntry {
    /// The statement the classifier reads for this model.
    pub fn statement(&self) -> String {
        format!("{}. {}.", self.strengths, self.limits)
    }
}

/// Every model the catalog describes, by family.
pub const MODELS: &[ModelEntry] = &[
    ModelEntry {
        family: "openai",
        model: "gpt-6-astra",
        name: "GPT-6 Astra",
        tier: "deep",
        price: 10.0,
        output: 50.0,
        context: "1.05M",
        strengths: "Long end-to-end work that runs for many steps without asking: driving tools and software, working across many files, research that has to finish a whole task",
        limits: "The most expensive model here at $10 per million in and $50 out, and on a subscription it burns a five-hour window in around fifteen messages, so short work belongs elsewhere",
    },
    ModelEntry {
        family: "openai",
        model: "gpt-5.6-sol",
        name: "GPT-5.6 Sol",
        tier: "deep",
        price: 4.0,
        output: 20.0,
        context: "400K",
        strengths: "Agentic coding and finding the fault in code: a failing test, a subtle bug, a refactor that has to keep working, terminal work that runs itself",
        limits: "At $4 per million in it costs real money, and a prompt over 272K tokens bills at double, so keep the context tight",
    },
    ModelEntry {
        family: "openai",
        model: "gpt-5.6-terra",
        name: "GPT-5.6 Terra",
        tier: "balanced",
        price: 2.0,
        output: 12.0,
        context: "400K",
        strengths: "Everyday work at a fair price: ordinary coding, drafting, analysis, the turns that are neither trivial nor hard",
        limits: "It is the middle tier, so it gives up ground on the hardest reasoning and on the longest agent runs",
    },
    ModelEntry {
        family: "openai",
        model: "gpt-5.6-luna",
        name: "GPT-5.6 Luna",
        tier: "fast",
        price: 0.2,
        output: 1.2,
        context: "400K",
        strengths: "Short and fast: a lookup, a one-line edit, a rename, a yes or no, classifying or extracting from text",
        limits: "The cheapest and the weakest, so anything that needs a chain of reasoning goes to another route",
    },
    ModelEntry {
        family: "anthropic",
        model: "claude-opus-5",
        name: "Claude Opus 5",
        tier: "deep",
        price: 5.0,
        output: 25.0,
        context: "1M",
        strengths: "The hardest thinking: a subtle bug that resists, architecture to weigh, a full-codebase refactor, a multi-step agent plan where one wrong step compounds, writing that has to be right",
        limits: "At $5 per million in and $25 out it costs about five times Haiku, so it takes only the work that needs it",
    },
    ModelEntry {
        family: "anthropic",
        model: "claude-sonnet-5",
        name: "Claude Sonnet 5",
        tier: "balanced",
        price: 3.0,
        output: 15.0,
        context: "1M",
        strengths: "The daily driver: coding, writing, analysis and research at volume, with the same million-token window as Opus",
        limits: "It gives way to Opus on the hardest reasoning and to the cheap tier on high-volume short turns",
    },
    ModelEntry {
        family: "anthropic",
        model: "claude-haiku-4-5",
        name: "Claude Haiku 4.5",
        tier: "fast",
        price: 1.0,
        output: 5.0,
        context: "200K",
        strengths: "Speed first: classifying intent, pulling fields out of text, triaging a message, any turn where waiting is the cost",
        limits: "A 200K window, the smallest here, and it is not the model for a chain of reasoning",
    },
    ModelEntry {
        family: "google",
        model: "gemini-3.1-pro",
        name: "Gemini 3.1 Pro",
        tier: "deep",
        price: 2.0,
        output: 12.0,
        context: "1M",
        strengths: "A large body of text at once: a long document, a wide codebase, many files in one turn, at a million tokens for $2 per million in",
        limits: "Developers report it as the least reliable of these to build against, and Google reads as under-provisioned, so a turn that must not fail goes elsewhere",
    },
    ModelEntry {
        family: "google",
        model: "gemini-3.5-flash",
        name: "Gemini 3.5 Flash",
        tier: "balanced",
        price: 1.5,
        output: 9.0,
        context: "1M",
        strengths: "Fast work over a long context: reading a lot and answering quickly, including computer use",
        limits: "At $1.50 per million in it is dearer than its own Pro tier, so it earns its place on speed, not price",
    },
    ModelEntry {
        family: "google",
        model: "gemini-3.5-flash-lite",
        name: "Gemini 3.5 Flash-Lite",
        tier: "fast",
        price: 0.15,
        output: 0.6,
        context: "1M",
        strengths: "Cheap work over a long context: skimming, sorting, tagging or extracting across a large input",
        limits: "The weakest Google tier, and it is for volume rather than judgment",
    },
    ModelEntry {
        family: "xai",
        model: "grok-4.6",
        name: "Grok 4.6",
        tier: "deep",
        price: 2.0,
        output: 6.0,
        context: "500K",
        strengths: "What is happening now, and cheap agentic coding: current events, live search, a post or a feed, and multi-step coding at $2 per million in",
        limits: "It writes long and cluttered, and it carries nothing between turns, so anything needing a tidy answer or a memory of earlier work goes elsewhere",
    },
    ModelEntry {
        family: "kimi",
        model: "kimi-k3",
        name: "Kimi K3",
        tier: "deep",
        price: 3.0,
        output: 15.0,
        context: "1M",
        strengths: "Long-horizon coding across a whole repository, on open weights, with a million-token window and few refusals on work other models decline",
        limits: "Weaker at reading images and at spatial questions, and in an ambiguous request it acts rather than asking, so send it work that is already well specified",
    },
];

/// Every catalog model of one family, most capable first.
pub fn family_models(family: &str) -> Vec<&'static ModelEntry> {
    MODELS
        .iter()
        .filter(|entry| entry.family == family)
        .collect()
}

/// The catalog entry for one family and model.
pub fn entry(family: &str, model: &str) -> Option<&'static ModelEntry> {
    MODELS
        .iter()
        .find(|entry| entry.family == family && entry.model == model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_router::family::FAMILIES;

    #[test]
    fn every_catalog_model_belongs_to_a_family_the_router_pools() {
        for entry in MODELS {
            assert!(
                FAMILIES.iter().any(|family| family.id == entry.family),
                "{} names no pooled family",
                entry.model
            );
            assert!(matches!(entry.tier, "deep" | "balanced" | "fast"));
            assert!(entry.price > 0.0 && entry.output > 0.0);
        }
        // Every pooled family offers at least one model to route to. Devin is
        // a subscription the pool shows and probes, and no turn lands on it.
        for family in FAMILIES {
            if matches!(family.id, "devin" | "meta") {
                continue;
            }
            assert!(
                !family_models(family.id).is_empty(),
                "{} offers no model",
                family.id
            );
        }
    }

    #[test]
    fn a_statement_names_the_work_and_then_the_trade_off() {
        let astra = entry("openai", "gpt-6-astra").unwrap();
        let statement = astra.statement();
        assert!(statement.starts_with("Long end-to-end work"));
        assert!(statement.contains("$10 per million"));
        assert!(statement.ends_with('.'));
        // A statement long enough to discriminate, short enough to fit many.
        for model in MODELS {
            let statement = model.statement();
            assert!(statement.len() > 80, "{} says too little", model.model);
            assert!(statement.len() < 400, "{} says too much", model.model);
        }
    }

    #[test]
    fn a_model_is_addressable_by_its_family_and_id() {
        assert_eq!(entry("xai", "grok-4.6").unwrap().name, "Grok 4.6");
        assert_eq!(entry("xai", "grok-9").map(|entry| entry.name), None);
        assert_eq!(entry("nobody", "grok-4.6"), None);
        assert_eq!(family_models("kimi").len(), 1);
        assert_eq!(family_models("openai").len(), 4);
        assert!(family_models("nobody").is_empty());
    }
}
