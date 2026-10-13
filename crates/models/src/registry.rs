//! The provider registry: every provider Muniment connects, how each signs
//! in, the names the interface shows, and the decision-model connections the
//! router's classifier reaches. [`registry`] serializes all of it for a client.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::family::{native_sign_in, FAMILIES};
use crate::local_servers::{Kind, KINDS};

/// The Ollama provider id, and the model it starts on when its server lists none.
pub const OLLAMA_PROVIDER: &str = "ollama";
pub const OLLAMA_MODEL: &str = "llama3.2:latest";
pub const LM_STUDIO_PROVIDER: &str = "lmstudio";
/// The pi-claude-bridge provider: Anthropic through the Claude Code sign-in.
pub const CLAUDE_BRIDGE_PROVIDER: &str = "claude-bridge";
/// A named OpenAI-compatible endpoint's provider id starts with this.
pub const CUSTOM_PROVIDER_PREFIX: &str = "custom-";
/// The provider id Pi reaches the model router under.
pub const ROUTER_PROVIDER: &str = "muniment-router";
/// The providers the local-mode status reports, in its order.
pub const STATUS_PROVIDERS: [&str; 4] = ["anthropic", "google", "openai", "ollama"];

/// One way to connect a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    /// The Claude Code sign-in through the pi-claude-bridge package.
    ClaudeCode,
    /// An account sign-in.
    Account,
    /// An API key in Pi's `auth.json`.
    Key,
    /// An Ollama server.
    Ollama,
    /// An OpenAI-compatible server URL.
    Endpoint,
}

/// The account a provider signs in with: the sign-in provider id and the
/// label the method shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Account {
    pub provider: &'static str,
    pub label: &'static str,
}

/// One provider Settings connects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    /// Featured first in the connector and offered inline in the Models list.
    #[serde(skip_serializing_if = "is_false")]
    pub popular: bool,
    /// The Pi provider that takes the key, when it is not `id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_provider: Option<&'static str>,
    pub methods: &'static [Method],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<Account>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<&'static str>,
    /// The name a connected key shows, when it is not `name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name: Option<&'static str>,
    /// The settings Pi reads from the key credential's `env` beside the key.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub key_settings: &'static [&'static str],
}

fn is_false(value: &bool) -> bool {
    !value
}

const fn key(id: &'static str, name: &'static str) -> Provider {
    Provider {
        id,
        name,
        popular: false,
        key_provider: None,
        methods: &[Method::Key],
        account: None,
        base_url: None,
        key_name: None,
        key_settings: &[],
    }
}

/// Every provider, in the order the connector lists them. Anthropic's account
/// is the Claude Code sign-in, so it carries no account here.
pub const PROVIDERS: &[Provider] = &[
    Provider {
        id: "anthropic",
        name: "Anthropic",
        popular: true,
        key_provider: None,
        methods: &[Method::ClaudeCode, Method::Key],
        account: None,
        base_url: None,
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "openai",
        name: "OpenAI",
        popular: true,
        key_provider: None,
        methods: &[Method::Account, Method::Key],
        account: Some(Account {
            provider: "openai-codex",
            label: "ChatGPT Plus or Pro account",
        }),
        base_url: None,
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "xai",
        name: "xAI",
        popular: true,
        key_provider: None,
        methods: &[Method::Account, Method::Key],
        account: Some(Account {
            provider: "xai",
            label: "Grok Build account",
        }),
        base_url: None,
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "google",
        name: "Google",
        popular: true,
        key_provider: None,
        methods: &[Method::Account, Method::Key],
        account: Some(Account {
            provider: "antigravity",
            label: "Antigravity account",
        }),
        base_url: None,
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "openrouter",
        name: "OpenRouter",
        popular: true,
        key_provider: None,
        methods: &[Method::Account, Method::Key],
        account: Some(Account {
            provider: "openrouter",
            label: "OpenRouter account",
        }),
        base_url: None,
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "ollama",
        name: "Ollama",
        popular: true,
        key_provider: None,
        methods: &[Method::Ollama],
        account: None,
        base_url: Some("http://localhost:11434/v1"),
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "lmstudio",
        name: "LM Studio",
        popular: true,
        key_provider: None,
        methods: &[Method::Endpoint],
        account: None,
        base_url: Some("http://localhost:1234/v1"),
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "custom",
        name: "Custom OpenAI-compatible endpoint",
        popular: true,
        key_provider: None,
        methods: &[Method::Endpoint],
        account: None,
        base_url: None,
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "github-copilot",
        name: "GitHub Copilot",
        popular: false,
        key_provider: None,
        methods: &[Method::Account],
        account: Some(Account {
            provider: "github-copilot",
            label: "GitHub Copilot account",
        }),
        base_url: None,
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "meta",
        name: "Meta Muse",
        popular: true,
        key_provider: None,
        methods: &[Method::Account],
        account: Some(Account {
            provider: "meta",
            label: "Muse Code account",
        }),
        base_url: None,
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "devin",
        name: "Devin",
        popular: true,
        key_provider: None,
        methods: &[Method::Account],
        account: Some(Account {
            provider: "devin",
            label: "Devin account",
        }),
        base_url: None,
        key_name: None,
        key_settings: &[],
    },
    Provider {
        id: "kimi",
        name: "Kimi",
        popular: true,
        key_provider: Some("kimi-coding"),
        methods: &[Method::Account, Method::Key],
        account: Some(Account {
            provider: "kimi",
            label: "Kimi Code account",
        }),
        base_url: None,
        key_name: Some("Kimi For Coding"),
        key_settings: &[],
    },
    key("deepseek", "DeepSeek"),
    key("mistral", "Mistral"),
    key("groq", "Groq"),
    key("cerebras", "Cerebras"),
    key("nvidia", "NVIDIA NIM"),
    key("amazon-bedrock", "Amazon Bedrock"),
    key("azure-openai-responses", "Azure OpenAI"),
    key("zai", "ZAI Coding Plan"),
    key("opencode", "OpenCode Zen"),
    key("opencode-go", "OpenCode Go"),
    key("huggingface", "Hugging Face"),
    key("fireworks", "Fireworks"),
    key("together", "Together"),
    key("baseten", "Baseten"),
    Provider {
        id: "vllm",
        name: "vLLM",
        popular: true,
        key_provider: None,
        methods: &[Method::Endpoint],
        account: None,
        base_url: Some("http://localhost:8000/v1"),
        key_name: None,
        key_settings: &[],
    },
    key("minimax", "MiniMax"),
    key("qwen-token-plan", "Qwen Token Plan"),
    key("radius", "Radius"),
    key("xiaomi", "Xiaomi"),
    key("moonshotai", "Moonshot AI"),
    key("zai-coding-cn", "ZAI Coding China"),
    key("xiaomi-token-plan-sgp", "Xiaomi Token Plan Singapore"),
    key("qwen-token-plan-individual", "Qwen Token Plan Individual"),
    key("moonshotai-cn", "Moonshot AI China"),
    key("xiaomi-token-plan-cn", "Xiaomi Token Plan China"),
    Provider {
        key_name: Some("Cloudflare Gateway"),
        key_settings: &["CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_GATEWAY_ID"],
        ..key("cloudflare-ai-gateway", "Cloudflare AI Gateway")
    },
    key("xiaomi-token-plan-ams", "Xiaomi Token Plan Amsterdam"),
    key("typesafe", "TypeSafe"),
    key("qwen-token-plan-cn", "Qwen Token Plan China"),
    key("google-vertex", "Google Vertex AI"),
    key("ant-ling", "Ant Ling"),
    Provider {
        key_name: Some("Cloudflare Workers"),
        key_settings: &["CLOUDFLARE_ACCOUNT_ID"],
        ..key("cloudflare-workers-ai", "Cloudflare Workers AI")
    },
    Provider {
        key_name: Some("Vercel Gateway"),
        key_settings: &[],
        ..key("vercel-ai-gateway", "Vercel AI Gateway")
    },
    key("minimax-cn", "MiniMax China"),
];

/// The label each method shows. An account shows its own label first.
pub const METHOD_LABELS: &[(&str, &str)] = &[
    ("claude-code", "Claude Code sign-in"),
    ("account", "Account"),
    ("key", "API key"),
    ("ollama", "Ollama server"),
    ("endpoint", "Server URL"),
];

/// Provider ids that reach the shell under another provider's name: the Codex
/// account is OpenAI, the bridge is Anthropic.
pub const ALIASES: &[(&str, &str)] = &[
    ("openai-codex", "openai"),
    ("claude-bridge", "anthropic"),
    ("antigravity", "google"),
    ("kimi-coding", "kimi"),
];

/// The tag each provider source shows.
pub const SOURCE_TAGS: &[(&str, &str)] = &[
    ("key", "Key"),
    ("account", "Account"),
    ("local", "Local"),
    ("custom", "Custom"),
    ("claude-code", "Claude Code"),
    ("router", "Router"),
];

/// The provider each router family pools from. A family absent here pools
/// from no provider of its own.
pub const FAMILY_PROVIDERS: &[(&str, &str)] = &[
    ("openai", "openai"),
    ("anthropic", "anthropic"),
    ("google", "google"),
    ("xai", "xai"),
    ("kimi", "kimi"),
    ("devin", "devin"),
];

/// One subscription the first run offers. `catalog` is the provider Settings
/// opens, and `logo` is the full-color mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Subscription {
    pub id: &'static str,
    pub name: &'static str,
    pub plan: &'static str,
    pub logo: &'static str,
    pub catalog: &'static str,
}

/// The subscriptions Muniment signs in to, in their default order.
pub const SUBSCRIPTIONS: &[Subscription] = &[
    Subscription {
        id: "anthropic",
        name: "Claude",
        plan: "Pro or Max, through Claude Code",
        logo: "anthropic",
        catalog: "anthropic",
    },
    Subscription {
        id: "openai",
        name: "ChatGPT",
        plan: "Plus or Pro",
        logo: "openai",
        catalog: "openai",
    },
    Subscription {
        id: "xai",
        name: "Grok",
        plan: "Grok Build",
        logo: "xai",
        catalog: "xai",
    },
    Subscription {
        id: "google",
        name: "Google",
        plan: "Antigravity",
        logo: "antigravity-color",
        catalog: "google",
    },
    Subscription {
        id: "github-copilot",
        name: "GitHub Copilot",
        plan: "Copilot plan",
        logo: "github-copilot",
        catalog: "github-copilot",
    },
    Subscription {
        id: "meta",
        name: "Meta Muse",
        plan: "Muse Code",
        logo: "meta",
        catalog: "meta",
    },
    Subscription {
        id: "kimi",
        name: "Kimi",
        plan: "Kimi Code",
        logo: "kimi-coding",
        catalog: "kimi",
    },
    Subscription {
        id: "devin",
        name: "Devin",
        plan: "Devin plan",
        logo: "devin",
        catalog: "devin",
    },
    Subscription {
        id: "openrouter",
        name: "OpenRouter",
        plan: "Credits",
        logo: "openrouter",
        catalog: "openrouter",
    },
];

/// One decision model the router's classifier connects to. A local entry
/// names its repository and runs on the user's own server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Classifier {
    pub id: &'static str,
    pub name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<&'static str>,
    pub model: &'static str,
    pub note: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compatible: Option<bool>,
    pub methods: &'static [&'static str],
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub variants: &'static [Variant],
}

/// One size of a decision model, with the model id each method names it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Variant {
    pub id: &'static str,
    pub name: &'static str,
    #[serde(serialize_with = "pairs")]
    pub models: &'static [(&'static str, &'static str)],
}

const fn local(
    id: &'static str,
    name: &'static str,
    repo: &'static str,
    model: &'static str,
    note: &'static str,
    methods: &'static [&'static str],
) -> Classifier {
    Classifier {
        id,
        name,
        repo: Some(repo),
        model,
        note,
        compatible: Some(true),
        methods,
        variants: &[],
    }
}

const SERVER_DOWNLOAD: &[&str] = &["server", "download"];

/// The decision models, ordered for adoption and ease of setup. Each answers
/// System One's typed choice. Pi's model catalog names the hosted ids, and
/// each project's own server names the local ones.
pub const CLASSIFIERS: &[Classifier] = &[
    Classifier {
        id: "jev",
        name: "Jev",
        repo: None,
        model: "jev-latest",
        note: "Hosted decision model. Choose where your routing requests go.",
        compatible: None,
        methods: &["typesafe", "openrouter", "cloudflare", "server"],
        variants: &[],
    },
    // Cloudflare's decision models, in two sizes. Each way to connect names the
    // model by its own id: Cloudflare Workers AI, an Ollama server, or OpenRouter.
    Classifier {
        id: "clef",
        name: "Clef",
        repo: None,
        model: "clef-flash",
        note: "Cloudflare's decision models. Clef Flash is the fast, inexpensive one. Clef is the larger, more accurate one.",
        compatible: None,
        methods: &["cloudflare", "ollama", "openrouter"],
        variants: &[
            Variant {
                id: "clef-flash",
                name: "Clef Flash",
                models: &[
                    ("cloudflare", "@cf/cloudflare/clef-flash"),
                    ("ollama", "clef-flash"),
                    ("openrouter", "cloudflare/clef-flash"),
                ],
            },
            Variant {
                id: "clef",
                name: "Clef",
                models: &[
                    ("cloudflare", "@cf/cloudflare/clef"),
                    ("ollama", "clef"),
                    ("openrouter", "cloudflare/clef"),
                ],
            },
        ],
    },
    // OpenAI's decision model answers through the Decisions API, which takes an
    // OpenAI API key. A ChatGPT sign-in does not reach it.
    Classifier {
        id: "luna",
        name: "GPT-6 Luna",
        repo: None,
        model: "gpt-6-luna",
        note: "OpenAI's decision model. It needs an OpenAI API key, because a ChatGPT sign-in does not reach the Decisions API.",
        compatible: None,
        methods: &["openai"],
        variants: &[],
    },
    local(
        "kev",
        "Kev",
        "https://github.com/jaredpalmer/kev",
        "kev-latest",
        "Local decision models in several sizes. The server downloads the checkpoint and base model on first use.",
        SERVER_DOWNLOAD,
    ),
    local(
        "nimble",
        "Nimble",
        "https://github.com/bespokelabsai/nimble",
        "nimble",
        "A 9B decision model. Ollama serves it, or run its own System One server.",
        &["ollama", "server", "download"],
    ),
    local(
        "von",
        "Von",
        "https://github.com/wfzyx/von",
        "von-1.3.0",
        "A small English decision model that runs on a CPU.",
        SERVER_DOWNLOAD,
    ),
    local(
        "laya",
        "Laya",
        "https://github.com/NandhaKishorM/laya",
        "english",
        "Very fast on a CPU, and less accurate at picking a model. The server downloads weights on first use.",
        SERVER_DOWNLOAD,
    ),
    local(
        "decider",
        "Decider 4B",
        "https://github.com/Mapika/decider",
        "Mapika/decider-4b",
        "Runs on CPU, Apple Silicon or CUDA. The 4B weights need about 8 GB in bfloat16.",
        SERVER_DOWNLOAD,
    ),
];

/// One way to reach a decision model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ConnectionMethod {
    pub name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<&'static str>,
    #[serde(skip_serializing_if = "is_false")]
    pub key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guide: Option<&'static str>,
    /// A decision model on the connected Ollama server, under Ollama's own System One route.
    #[serde(skip_serializing_if = "is_false")]
    pub ollama: bool,
}

const fn method(name: &'static str) -> ConnectionMethod {
    ConnectionMethod {
        name,
        url: None,
        model: None,
        key: false,
        guide: None,
        ollama: false,
    }
}

/// The ways to reach a decision model, by method id.
pub const CONNECTION_METHODS: &[(&str, ConnectionMethod)] = &[
    (
        "typesafe",
        ConnectionMethod {
            url: Some("https://api.typesafe.ai/v1/systemone"),
            model: Some("jev-latest"),
            key: true,
            ..method("TypeSafe API")
        },
    ),
    (
        "openrouter",
        ConnectionMethod {
            url: Some("https://openrouter.ai/api/v1/systemone"),
            model: Some("typesafe/jev-1.13"),
            key: true,
            ..method("OpenRouter API")
        },
    ),
    (
        "openai",
        ConnectionMethod {
            url: Some("https://api.openai.com/v1/decisions"),
            model: Some("gpt-6-luna"),
            key: true,
            ..method("OpenAI API")
        },
    ),
    (
        "cloudflare",
        ConnectionMethod {
            model: Some("typesafe/jev"),
            key: true,
            guide: Some("https://developers.cloudflare.com/ai/models/typesafe/jev/"),
            ..method("Cloudflare Workers AI")
        },
    ),
    (
        "ollama",
        ConnectionMethod {
            ollama: true,
            ..method("Ollama server")
        },
    ),
    (
        "server",
        ConnectionMethod {
            url: Some("http://127.0.0.1:8000/v1/systemone"),
            ..method("Connect a server")
        },
    ),
    ("download", method("Download and run locally")),
];

/// The commands that start each local decision model's server.
pub const LOCAL_SETUP: &[(&str, &str)] = &[
    ("laya", "pip install \"laya[serve]\"\nLAYA_MODELS=english laya-serve"),
    ("kev", "git clone https://github.com/jaredpalmer/kev.git\ncd kev\nuv sync --extra serve\nuv run --extra serve python -m kev.serve --run jaredpalmer/kev-4b --port 8009"),
    ("decider", "git clone https://github.com/Mapika/decider.git\ncd decider\npip install -e \".[serve]\"\nscripts/serve.sh Mapika/decider-4b 8000"),
    ("von", "pip install von-sdk\nvon serve --host 127.0.0.1 --port 8000"),
];

/// Ollama's decision models, by the name Ollama gives each, with the
/// classifier whose mark each shows and its display name. Ollama's model list
/// does not mark them, so for Ollama the name is the fallback.
pub const OLLAMA_DECISIONS: &[(&str, (&str, &str))] = &[
    ("clef-flash", ("clef", "Clef Flash")),
    ("clef", ("clef", "Clef")),
    ("nimble", ("nimble", "Nimble")),
    ("laya", ("laya", "Laya")),
    ("tev1", ("tev1", "Tev1")),
];

/// One router family: the name it shows and the provider it pools from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FamilyEntry {
    pub id: &'static str,
    pub name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<&'static str>,
}

/// The decision-model catalog and how to reach each one.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Classifiers {
    pub entries: &'static [Classifier],
    #[serde(serialize_with = "pairs")]
    pub methods: &'static [(&'static str, ConnectionMethod)],
    #[serde(serialize_with = "pairs")]
    pub local_setup: &'static [(&'static str, &'static str)],
    #[serde(serialize_with = "pairs")]
    pub ollama_decisions: &'static [(&'static str, (&'static str, &'static str))],
}

/// Everything a client reads about providers, in one value.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Registry {
    pub providers: &'static [Provider],
    #[serde(serialize_with = "pairs")]
    pub method_labels: &'static [(&'static str, &'static str)],
    #[serde(serialize_with = "pairs")]
    pub aliases: &'static [(&'static str, &'static str)],
    #[serde(serialize_with = "pairs")]
    pub source_tags: &'static [(&'static str, &'static str)],
    pub families: Vec<FamilyEntry>,
    pub subscriptions: &'static [Subscription],
    pub classifiers: Classifiers,
    pub local_servers: &'static [Kind],
}

/// Writes ordered pairs as one JSON object in their order.
fn pairs<S: Serializer, T: Serialize>(
    entries: &&'static [(&'static str, T)],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(entries.len()))?;
    for (key, value) in entries.iter() {
        map.serialize_entry(key, value)?;
    }
    map.end()
}

/// The whole registry.
pub fn registry() -> Registry {
    Registry {
        providers: PROVIDERS,
        method_labels: METHOD_LABELS,
        aliases: ALIASES,
        source_tags: SOURCE_TAGS,
        families: FAMILIES
            .iter()
            .map(|family| FamilyEntry {
                id: family.id,
                name: family.name,
                provider: lookup(FAMILY_PROVIDERS, family.id),
            })
            .collect(),
        subscriptions: SUBSCRIPTIONS,
        classifiers: Classifiers {
            entries: CLASSIFIERS,
            methods: CONNECTION_METHODS,
            local_setup: LOCAL_SETUP,
            ollama_decisions: OLLAMA_DECISIONS,
        },
        local_servers: KINDS,
    }
}

fn lookup(pairs: &[(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    pairs
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| *value)
}

/// The registry row with this id.
pub fn provider(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|provider| provider.id == id)
}

/// The registry id a provider id edits under: an alias's target, else itself.
pub fn catalog_id(id: &str) -> &str {
    lookup(ALIASES, id).unwrap_or(id)
}

/// Every Pi provider that takes an API key, with the name its key shows.
pub fn key_providers() -> impl Iterator<Item = (&'static str, &'static str)> {
    PROVIDERS
        .iter()
        .filter(|provider| provider.methods.contains(&Method::Key))
        .map(|provider| {
            (
                provider.key_provider.unwrap_or(provider.id),
                provider.key_name.unwrap_or(provider.name),
            )
        })
}

/// The name a key for this Pi provider shows, when Pi takes a key for it.
pub fn key_provider_name(id: &str) -> Option<&'static str> {
    key_providers()
        .find(|(provider, _)| *provider == id)
        .map(|(_, name)| name)
}

/// The settings a provider needs beside its key, which Pi reads from the
/// credential's `env`.
pub fn key_settings(id: &str) -> &'static [&'static str] {
    PROVIDERS
        .iter()
        .find(|provider| provider.key_provider.unwrap_or(provider.id) == id)
        .map_or(&[], |provider| provider.key_settings)
}

/// The name an account Pi signs into shows. The router's own sign-ins never
/// reach Pi.
pub fn account_provider_name(id: &str) -> Option<&'static str> {
    PROVIDERS
        .iter()
        .find(|provider| {
            provider
                .account
                .is_some_and(|account| account.provider == id && !native_sign_in(id))
        })
        .map(|provider| provider.name)
}

/// The name a connected provider shows: the local servers, the bridge and the
/// router by their own names, then a key's name, then an account's.
pub fn display_name(id: &str) -> Option<&'static str> {
    match id {
        ROUTER_PROVIDER => Some("Model router"),
        OLLAMA_PROVIDER | LM_STUDIO_PROVIDER | CLAUDE_BRIDGE_PROVIDER => {
            provider(catalog_id(id)).map(|provider| provider.name)
        }
        _ => key_provider_name(id).or_else(|| account_provider_name(id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_key_provider_appears_once_under_the_name_its_key_shows() {
        let keys: Vec<_> = key_providers().collect();
        assert_eq!(keys.len(), 39);
        for (id, _) in &keys {
            assert_eq!(keys.iter().filter(|(other, _)| other == id).count(), 1);
        }
        assert_eq!(key_provider_name("kimi-coding"), Some("Kimi For Coding"));
        assert_eq!(key_provider_name("kimi"), None);
        assert_eq!(
            key_provider_name("cloudflare-ai-gateway"),
            Some("Cloudflare Gateway")
        );
        assert_eq!(key_provider_name("ollama"), None);
        assert_eq!(
            key_settings("cloudflare-ai-gateway"),
            ["CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_GATEWAY_ID"]
        );
        assert!(key_settings("openai").is_empty());
    }

    #[test]
    fn a_connected_provider_shows_its_own_name() {
        for (id, name) in [
            ("ollama", Some("Ollama")),
            ("lmstudio", Some("LM Studio")),
            ("claude-bridge", Some("Anthropic")),
            ("muniment-router", Some("Model router")),
            ("anthropic", Some("Anthropic")),
            ("openai-codex", Some("OpenAI")),
            ("github-copilot", Some("GitHub Copilot")),
            ("vercel-ai-gateway", Some("Vercel Gateway")),
            // The router's own sign-ins never reach Pi, so Pi never lists them.
            ("antigravity", None),
            ("nobody", None),
        ] {
            assert_eq!(display_name(id), name, "{id}");
        }
    }

    #[test]
    fn every_reference_names_a_known_entry() {
        for (_, target) in ALIASES {
            assert!(provider(target).is_some(), "{target}");
        }
        for subscription in SUBSCRIPTIONS {
            assert!(provider(subscription.catalog).is_some());
        }
        for (family, target) in FAMILY_PROVIDERS {
            assert!(crate::family::family(family).is_some());
            assert!(provider(target).is_some());
        }
        for classifier in CLASSIFIERS {
            for method in classifier.methods {
                assert!(CONNECTION_METHODS.iter().any(|(id, _)| id == method));
            }
        }
        for row in PROVIDERS {
            assert!(row.methods.iter().all(|method| {
                METHOD_LABELS
                    .iter()
                    .any(|(id, _)| serde_json::to_value(method).unwrap() == json!(id))
            }));
        }
        assert_eq!(catalog_id("openai-codex"), "openai");
        assert_eq!(catalog_id("ollama"), "ollama");
    }

    #[test]
    fn the_registry_serializes_in_the_shape_the_interface_reads() {
        let value = serde_json::to_value(registry()).unwrap();
        assert_eq!(
            value["providers"][1],
            json!({"id": "openai", "name": "OpenAI", "popular": true, "methods": ["account", "key"],
                "account": {"provider": "openai-codex", "label": "ChatGPT Plus or Pro account"}})
        );
        assert_eq!(
            value["providers"][11],
            json!({"id": "kimi", "name": "Kimi", "popular": true, "keyProvider": "kimi-coding",
                "methods": ["account", "key"], "account": {"provider": "kimi", "label": "Kimi Code account"},
                "keyName": "Kimi For Coding"})
        );
        assert_eq!(value["methodLabels"]["claude-code"], "Claude Code sign-in");
        assert_eq!(value["aliases"]["antigravity"], "google");
        assert_eq!(value["sourceTags"]["router"], "Router");
        assert_eq!(value["families"][5], json!({"id": "meta", "name": "Meta"}));
        assert_eq!(value["subscriptions"][3]["logo"], "antigravity-color");
        assert_eq!(
            value["classifiers"]["entries"][1]["variants"][0]["models"]["cloudflare"],
            "@cf/cloudflare/clef-flash"
        );
        assert_eq!(
            value["classifiers"]["methods"]["cloudflare"],
            json!({"name": "Cloudflare Workers AI", "model": "typesafe/jev", "key": true,
                "guide": "https://developers.cloudflare.com/ai/models/typesafe/jev/"})
        );
        assert_eq!(
            value["classifiers"]["ollamaDecisions"]["clef-flash"],
            json!(["clef", "Clef Flash"])
        );
        assert_eq!(value["localServers"][0]["ports"], json!([11434]));
    }
}
