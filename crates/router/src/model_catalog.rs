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
//!
//! The catalog is data: `catalog.toml` is compiled in as the default, and a
//! host may put another file in force at runtime with [`install`] or a
//! [`Reloader`]. A file that fails the check never replaces a good catalog.

use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};

use serde::Deserialize;
use sha2::{Digest, Sha256};

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

/// The catalog compiled into the binary. A host that names no catalog file
/// routes with this one.
pub const DEFAULT_CATALOG: &str = include_str!("../catalog.toml");

/// The embedded default catalog, parsed once.
pub static MODELS: LazyLock<&'static [ModelEntry]> =
    LazyLock::new(|| leak(parse(DEFAULT_CATALOG).expect("the embedded catalog is valid")));

/// The catalog in force. `None` is the embedded default.
static CURRENT: RwLock<Option<&'static [ModelEntry]>> = RwLock::new(None);

/// Every model the catalog in force describes.
pub fn models() -> &'static [ModelEntry] {
    CURRENT
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .unwrap_or(*MODELS)
}

/// Every catalog model of one family, most capable first.
pub fn family_models(family: &str) -> Vec<&'static ModelEntry> {
    models()
        .iter()
        .filter(|entry| entry.family == family)
        .collect()
}

/// The catalog entry for one family and model.
pub fn entry(family: &str, model: &str) -> Option<&'static ModelEntry> {
    models()
        .iter()
        .find(|entry| entry.family == family && entry.model == model)
}

/// One model as the catalog file writes it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogModel {
    pub family: String,
    pub model: String,
    pub name: String,
    pub tier: String,
    pub price: f64,
    pub output: f64,
    pub context: String,
    pub strengths: String,
    pub limits: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    #[serde(default)]
    model: Vec<CatalogModel>,
}

/// The token count a context string such as `400K` or `1.05M` names.
pub fn context_tokens(text: &str) -> Option<u64> {
    let text = text.trim();
    let scale = if text.ends_with('M') {
        1_000_000.0
    } else if text.ends_with('K') {
        1000.0
    } else {
        1.0
    };
    let value = text.trim_end_matches(['M', 'K']).parse::<f64>().ok()?;
    (value.is_finite() && value > 0.0).then_some((value * scale) as u64)
}

/// Reads and checks a catalog file. Every entry must name a pooled family, a
/// known tier, finite non-negative prices, a context size and both
/// statements, and no family and model pair may appear twice.
pub fn parse(text: &str) -> Result<Vec<CatalogModel>, String> {
    let file: CatalogFile =
        toml::from_str(text).map_err(|error| format!("The catalog is not valid TOML: {error}"))?;
    if file.model.is_empty() {
        return Err("The catalog names no model.".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in &file.model {
        let name = format!("{}/{}", entry.family, entry.model);
        if crate::family::family(&entry.family).is_none() {
            return Err(format!("{name} names no pooled family."));
        }
        if entry.model.trim().is_empty()
            || entry.model.len() > 128
            || entry
                .model
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(format!("{name} has an invalid model id."));
        }
        if !matches!(entry.tier.as_str(), "deep" | "balanced" | "fast") {
            return Err(format!(
                "{name} has tier {}, not deep, balanced or fast.",
                entry.tier
            ));
        }
        if !(entry.price.is_finite() && entry.price >= 0.0)
            || !(entry.output.is_finite() && entry.output >= 0.0)
        {
            return Err(format!("{name} has an invalid price."));
        }
        if context_tokens(&entry.context).is_none() {
            return Err(format!("{name} has an invalid context size."));
        }
        if [&entry.name, &entry.strengths, &entry.limits]
            .iter()
            .any(|text| text.trim().is_empty())
        {
            return Err(format!("{name} needs a name, strengths and limits."));
        }
        if !seen.insert(name.clone()) {
            return Err(format!("{name} appears twice."));
        }
    }
    Ok(file.model)
}

/// Gives a parsed catalog the `'static` lifetime the lookups answer with. A
/// catalog lives until the process ends, so each distinct catalog a host
/// installs stays in memory once.
fn leak(models: Vec<CatalogModel>) -> &'static [ModelEntry] {
    fn text(value: String) -> &'static str {
        Box::leak(value.into_boxed_str())
    }
    let entries: Vec<ModelEntry> = models
        .into_iter()
        .map(|entry| ModelEntry {
            family: text(entry.family),
            model: text(entry.model),
            name: text(entry.name),
            tier: text(entry.tier),
            price: entry.price,
            output: entry.output,
            context: text(entry.context),
            strengths: text(entry.strengths),
            limits: text(entry.limits),
        })
        .collect();
    Box::leak(entries.into_boxed_slice())
}

/// Puts a checked catalog in force for this process. A text that fails the
/// check changes nothing and answers why.
pub fn install(text: &str) -> Result<usize, String> {
    let models = leak(parse(text)?);
    *CURRENT.write().unwrap_or_else(|error| error.into_inner()) = Some(models);
    Ok(models.len())
}

/// Puts the embedded default back in force.
pub fn reset() {
    *CURRENT.write().unwrap_or_else(|error| error.into_inner()) = None;
}

/// What one look at a catalog file did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reload {
    /// The file holds what it held at the last look.
    Unchanged,
    /// The file changed and its catalog is now in force, with this many models.
    Installed(usize),
    /// The file changed and failed the check, so the last good catalog stays.
    Rejected(String),
}

/// Watches one catalog file and installs it whenever its contents change.
pub struct Reloader {
    path: PathBuf,
    seen: Option<[u8; 32]>,
    /// The last read failure, so one missing file is reported once.
    unreadable: Option<String>,
}

impl Reloader {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            seen: None,
            unreadable: None,
        }
    }

    /// Reads the file and installs it when its contents differ from the last
    /// look. A file that cannot be read counts as rejected once, until the
    /// failure changes.
    pub fn poll(&mut self) -> Reload {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) => {
                let message = format!("{}: {error}", self.path.display());
                if self.unreadable.as_ref() == Some(&message) {
                    return Reload::Unchanged;
                }
                self.unreadable = Some(message.clone());
                return Reload::Rejected(message);
            }
        };
        self.unreadable = None;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if self.seen == Some(digest) {
            return Reload::Unchanged;
        }
        self.seen = Some(digest);
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => return Reload::Rejected("The catalog is not UTF-8.".into()),
        };
        match install(&text) {
            Ok(count) => Reload::Installed(count),
            Err(error) => Reload::Rejected(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::family::FAMILIES;

    #[test]
    fn every_catalog_model_belongs_to_a_family_the_router_pools() {
        for entry in MODELS.iter() {
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
        for model in MODELS.iter() {
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

    #[test]
    fn a_catalog_file_must_pass_the_check() {
        assert_eq!(parse(DEFAULT_CATALOG).unwrap().len(), MODELS.len());
        let one = |field: &str, value: &str| {
            let mut entry = toml::Table::new();
            for (name, text) in [
                ("family", "openai"),
                ("model", "gpt-test"),
                ("name", "GPT Test"),
                ("tier", "fast"),
                ("context", "128K"),
                ("strengths", "Short work"),
                ("limits", "Weak at long work"),
            ] {
                entry.insert(name.into(), toml::Value::String(text.into()));
            }
            entry.insert("price".into(), toml::Value::Float(1.0));
            entry.insert("output".into(), toml::Value::Float(2.0));
            if !field.is_empty() {
                entry.insert(field.into(), toml::Value::String(value.into()));
            }
            let mut file = toml::Table::new();
            file.insert(
                "model".into(),
                toml::Value::Array(vec![toml::Value::Table(entry)]),
            );
            toml::to_string(&file).unwrap()
        };
        assert_eq!(parse(&one("", "")).unwrap()[0].model, "gpt-test");
        assert!(parse(&one("family", "nobody"))
            .unwrap_err()
            .contains("family"));
        assert!(parse(&one("tier", "huge")).unwrap_err().contains("tier"));
        assert!(parse(&one("context", "lots"))
            .unwrap_err()
            .contains("context"));
        assert!(parse(&one("limits", " ")).is_err());
        assert!(parse(&one("model", "gpt test")).is_err());
        assert!(parse(&one("extra", "x")).is_err());
        assert!(parse("").unwrap_err().contains("no model"));
        assert!(parse("[[model]]\nfamily = 1").is_err());
        let twice = format!("{}\n{}", one("", ""), one("", ""));
        assert!(parse(&twice).unwrap_err().contains("twice"));
        assert_eq!(context_tokens("1.05M"), Some(1_050_000));
        assert_eq!(context_tokens("400K"), Some(400_000));
        assert_eq!(context_tokens("0"), None);
    }

    #[test]
    fn a_reloaded_catalog_takes_effect_and_a_bad_file_keeps_the_last_good_one() {
        let path =
            std::env::temp_dir().join(format!("muniment-catalog-{}.toml", uuid::Uuid::now_v7()));
        // A superset of the default, so tests that read the catalog at the
        // same time still find every default model.
        let extended = format!(
            "{DEFAULT_CATALOG}\n[[model]]\nfamily = \"openai\"\nmodel = \"gpt-reload-test\"\nname = \"Reload Test\"\ntier = \"fast\"\nprice = 0.1\noutput = 0.2\ncontext = \"64K\"\nstrengths = \"Short work\"\nlimits = \"Weak at long work\"\n"
        );
        let mut reloader = Reloader::new(&path);
        assert!(matches!(reloader.poll(), Reload::Rejected(_)));
        assert_eq!(reloader.poll(), Reload::Unchanged);
        std::fs::write(&path, &extended).unwrap();
        assert_eq!(reloader.poll(), Reload::Installed(MODELS.len() + 1));
        assert_eq!(
            entry("openai", "gpt-reload-test").unwrap().name,
            "Reload Test"
        );
        assert_eq!(reloader.poll(), Reload::Unchanged);
        std::fs::write(&path, "[[model]]\nfamily = \"nobody\"").unwrap();
        assert!(matches!(reloader.poll(), Reload::Rejected(_)));
        assert!(entry("openai", "gpt-reload-test").is_some());
        assert_eq!(reloader.poll(), Reload::Unchanged);
        reset();
        assert!(entry("openai", "gpt-reload-test").is_none());
        assert_eq!(models().len(), MODELS.len());
        std::fs::remove_file(path).unwrap();
    }
}
