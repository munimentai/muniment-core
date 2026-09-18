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
pub const FAMILIES: [Family; 5] = [
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
];

/// Pi's sign-in providers and the family each one pools into. Pi signs into an
/// account under its own provider id, and the router holds the result as one
/// more account of the family.
pub const SUBSCRIPTION_PROVIDERS: [(&str, &str, &str); 3] = [
    ("openai-codex", "openai", "ChatGPT Plus or Pro"),
    ("xai", "xai", "SuperGrok or X Premium"),
    ("anthropic", "anthropic", "Claude Pro or Max"),
];

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
    fn every_family_is_addressable_by_its_id() {
        for entry in FAMILIES {
            assert_eq!(family(entry.id), Some(entry));
            assert!(entry.base_url.starts_with("https://"));
        }
        assert_eq!(family("nobody"), None);
        assert_eq!(family_for_pi_provider("openai-codex").unwrap().id, "openai");
        assert_eq!(family_for_pi_provider("xai").unwrap().id, "xai");
        assert_eq!(family_for_pi_provider("github-copilot"), None);
        assert_eq!(family("anthropic").unwrap().wire, Wire::OpenAiCompatible);
        assert_eq!(family("kimi").unwrap().wire, Wire::OpenAiCompatible);
    }
}
