//! The provider families the router balances across, and the wire each speaks.

/// The wire protocol an account's upstream answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// `POST /chat/completions` with the OpenAI request and response shape.
    OpenAiCompatible,
    /// `POST /messages` with the Anthropic request and response shape.
    AnthropicMessages,
}

/// One provider family. A pool holds many accounts of one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Family {
    /// The stable id the config and the ledger store.
    pub id: &'static str,
    /// The name Settings shows.
    pub name: &'static str,
    /// The upstream an account uses when it names no base URL of its own.
    pub base_url: &'static str,
    pub wire: Wire,
}

/// Every family the router balances. Each one takes many accounts.
pub const FAMILIES: [Family; 7] = [
    Family {
        id: "openai",
        name: "OpenAI",
        base_url: "https://api.openai.com/v1",
        wire: Wire::OpenAiCompatible,
    },
    // Anthropic answers the OpenAI request shape on its own compatibility
    // route. The native Messages wire carries thinking blocks the route drops,
    // so an account may name a base URL of its own to reach it.
    Family {
        id: "anthropic",
        name: "Anthropic",
        base_url: "https://api.anthropic.com/v1",
        wire: Wire::OpenAiCompatible,
    },
    Family {
        id: "google",
        name: "Google",
        base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        wire: Wire::OpenAiCompatible,
    },
    Family {
        id: "xai",
        name: "xAI",
        base_url: "https://api.x.ai/v1",
        wire: Wire::OpenAiCompatible,
    },
    Family {
        id: "kimi",
        name: "Kimi",
        base_url: "https://api.moonshot.ai/v1",
        wire: Wire::OpenAiCompatible,
    },
    Family {
        id: "meta",
        name: "Meta",
        base_url: "https://api.meta.ai/v1",
        wire: Wire::OpenAiCompatible,
    },
    // Devin is a subscription alone. The pool holds it and shows what it has
    // left, and no turn lands on it until the router speaks its wire.
    Family {
        id: "devin",
        name: "Devin",
        base_url: "https://api.devin.ai/v1",
        wire: Wire::OpenAiCompatible,
    },
];

/// The subscription sign-ins and the family each one pools into. The first
/// three are Pi's own sign-ins, under Pi's provider ids. Kimi, Antigravity
/// and Devin have no Pi sign-in, so the router runs its own: Kimi by device
/// code, Antigravity and Devin through the browser.
pub const SUBSCRIPTION_PROVIDERS: [(&str, &str, &str); 7] = [
    ("openai-codex", "openai", "ChatGPT Plus or Pro"),
    ("xai", "xai", "Grok Build"),
    ("anthropic", "anthropic", "Claude Pro or Max"),
    ("kimi", "kimi", "Kimi Code"),
    (
        "antigravity",
        "google",
        "Antigravity, with a Google account",
    ),
    ("devin", "devin", "Devin"),
    ("meta", "meta", "Muse Code"),
];

/// The sign-ins the router runs itself rather than through Pi.
pub const NATIVE_SIGN_INS: [&str; 4] = ["kimi", "antigravity", "devin", "meta"];

/// Whether a subscription provider signs in through the router's own flow.
pub fn native_sign_in(provider: &str) -> bool {
    NATIVE_SIGN_INS.contains(&provider)
}

/// The family a Pi sign-in provider pools into.
pub fn family_for_pi_provider(provider: &str) -> Option<Family> {
    SUBSCRIPTION_PROVIDERS
        .iter()
        .find(|(pi, _, _)| *pi == provider)
        .and_then(|(_, id, _)| family(id))
}

/// The family with this id.
pub fn family(id: &str) -> Option<Family> {
    FAMILIES.iter().copied().find(|entry| entry.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_catalog_contains_the_six_providers_and_muse() {
        for provider in [
            "antigravity",
            "openai-codex",
            "anthropic",
            "xai",
            "devin",
            "kimi",
            "meta",
        ] {
            assert_eq!(
                SUBSCRIPTION_PROVIDERS
                    .iter()
                    .filter(|(id, _, _)| *id == provider)
                    .count(),
                1
            );
            assert!(family_for_pi_provider(provider).is_some());
        }
        assert!(native_sign_in("meta"));
    }

    #[test]
    fn every_family_is_addressable_by_its_id() {
        for entry in FAMILIES {
            assert_eq!(family(entry.id), Some(entry));
            assert!(entry.base_url.starts_with("https://"));
        }
        assert_eq!(family("nobody"), None);
        assert_eq!(family_for_pi_provider("openai-codex").unwrap().id, "openai");
        assert_eq!(family_for_pi_provider("xai").unwrap().id, "xai");
        assert_eq!(family_for_pi_provider("github-copilot"), None);
        assert_eq!(family_for_pi_provider("kimi").unwrap().id, "kimi");
        assert_eq!(family_for_pi_provider("antigravity").unwrap().id, "google");
        assert_eq!(family_for_pi_provider("devin").unwrap().id, "devin");
        assert!(native_sign_in("kimi") && !native_sign_in("openai-codex"));
        assert_eq!(family("anthropic").unwrap().wire, Wire::OpenAiCompatible);
        assert_eq!(family("kimi").unwrap().wire, Wire::OpenAiCompatible);
    }
}
