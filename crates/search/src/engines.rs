//! The engines: search URLs, result page parsers and block detection.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use percent_encoding::percent_decode_str;
use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};
use url::form_urlencoded::byte_serialize;

/// The most results one engine page yields.
pub const PAGE_RESULTS: usize = 10;

/// One search engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineId {
    Brave,
    Bing,
    DuckDuckGo,
    Yahoo,
    Wikipedia,
}

impl EngineId {
    /// Every engine in the default order.
    pub const ALL: [EngineId; 5] = [
        EngineId::Brave,
        EngineId::Bing,
        EngineId::DuckDuckGo,
        EngineId::Yahoo,
        EngineId::Wikipedia,
    ];

    pub fn name(self) -> &'static str {
        match self {
            EngineId::Brave => "brave",
            EngineId::Bing => "bing",
            EngineId::DuckDuckGo => "duckduckgo",
            EngineId::Yahoo => "yahoo",
            EngineId::Wikipedia => "wikipedia",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|engine| engine.name() == name)
    }

    /// The page a person opens before searching, for its cookies. `None` for
    /// engines that need none.
    pub fn home_url(self) -> Option<&'static str> {
        match self {
            EngineId::Bing => Some("https://www.bing.com/"),
            EngineId::DuckDuckGo => Some("https://html.duckduckgo.com/html/"),
            EngineId::Yahoo => Some("https://search.yahoo.com/"),
            EngineId::Brave | EngineId::Wikipedia => None,
        }
    }

    /// Whether the engine reads `site:` and `-site:` terms in the query.
    pub fn reads_site_terms(self) -> bool {
        self != EngineId::Wikipedia
    }

    /// Whether the engine can limit results to `range`.
    pub fn supports(self, range: TimeRange) -> bool {
        match self {
            EngineId::Brave | EngineId::Bing | EngineId::DuckDuckGo => true,
            EngineId::Yahoo => range != TimeRange::Year,
            EngineId::Wikipedia => false,
        }
    }
}

/// How recent results must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeRange {
    Day,
    Week,
    Month,
    Year,
}

impl TimeRange {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "day" => Some(TimeRange::Day),
            "week" => Some(TimeRange::Week),
            "month" => Some(TimeRange::Month),
            "year" => Some(TimeRange::Year),
            _ => None,
        }
    }
}

/// One result as an engine lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

/// The URL that searches `engine` for `query`, limited to `range` when the
/// engine supports it.
pub fn search_url(engine: EngineId, query: &str, range: Option<TimeRange>) -> String {
    let q = encode(query);
    let range = range.filter(|range| engine.supports(*range));
    match engine {
        EngineId::Brave => {
            let mut url = format!("https://search.brave.com/search?q={q}&source=web");
            if let Some(range) = range {
                let tf = match range {
                    TimeRange::Day => "pd",
                    TimeRange::Week => "pw",
                    TimeRange::Month => "pm",
                    TimeRange::Year => "py",
                };
                url.push_str(&format!("&tf={tf}"));
            }
            url
        }
        EngineId::Bing => {
            let mut url = format!("https://www.bing.com/search?q={q}&form=QBLH");
            if let Some(range) = range {
                let filter = match range {
                    TimeRange::Day => "ex1:\"ez1\"".to_owned(),
                    TimeRange::Week => "ex1:\"ez2\"".to_owned(),
                    TimeRange::Month => "ex1:\"ez3\"".to_owned(),
                    TimeRange::Year => {
                        let today = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|elapsed| elapsed.as_secs() / 86_400)
                            .unwrap_or(0);
                        format!("ex1:\"ez5_{}_{today}\"", today.saturating_sub(365))
                    }
                };
                url.push_str(&format!("&filters={}", encode(&filter)));
            }
            url
        }
        EngineId::DuckDuckGo => {
            let mut url = format!("https://html.duckduckgo.com/html/?q={q}");
            if let Some(range) = range {
                let df = match range {
                    TimeRange::Day => "d",
                    TimeRange::Week => "w",
                    TimeRange::Month => "m",
                    TimeRange::Year => "y",
                };
                url.push_str(&format!("&df={df}"));
            }
            url
        }
        EngineId::Yahoo => {
            let mut url = format!("https://search.yahoo.com/search?p={q}&fr=sfp");
            let age = match range {
                Some(TimeRange::Day) => Some(("1d", "d")),
                Some(TimeRange::Week) => Some(("1w", "w")),
                Some(TimeRange::Month) => Some(("1m", "m")),
                Some(TimeRange::Year) | None => None,
            };
            if let Some((age, btf)) = age {
                url.push_str(&format!("&age={age}&btf={btf}&fr2=time"));
            }
            url
        }
        EngineId::Wikipedia => {
            format!("https://en.wikipedia.org/w/rest.php/v1/search/page?q={q}&limit={PAGE_RESULTS}")
        }
    }
}

/// Why a response is not a usable result page, or `None` when it is.
///
/// Status, final URL and result count decide it. The word "captcha" in a page
/// is no signal: Brave prints "Switch to traditional captcha" on every page.
pub fn blocked(engine: EngineId, status: u16, final_url: &str, results: usize) -> Option<String> {
    if final_url.contains("/sorry/") || final_url.contains("/captcha") {
        return Some(format!("redirected to {final_url}"));
    }
    if status != 200 {
        return Some(format!("HTTP {status}"));
    }
    // An empty Wikipedia answer is a real "no match".
    (results == 0 && engine != EngineId::Wikipedia).then(|| "no results".to_owned())
}

/// The results on one engine page, at most [`PAGE_RESULTS`].
pub fn parse(engine: EngineId, body: &str) -> Vec<SearchResult> {
    let mut results = match engine {
        EngineId::Bing => parse_bing(&Html::parse_document(body)),
        EngineId::DuckDuckGo => parse_duckduckgo(&Html::parse_document(body)),
        EngineId::Wikipedia => parse_wikipedia(body),
        EngineId::Brave => css(body, &BRAVE, str::to_owned),
        EngineId::Yahoo => css(body, &YAHOO, unwrap_yahoo),
    };
    results.truncate(PAGE_RESULTS);
    results
}

fn encode(text: &str) -> String {
    byte_serialize(text.as_bytes()).collect()
}

/// Collapses whitespace runs, including newlines, to single spaces.
fn clean_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The cleaned text of the first element under `element` that `selector` matches.
fn first_text(element: &ElementRef, selector: &Selector) -> String {
    element
        .select(selector)
        .next()
        .map(|found| clean_text(&found.text().collect::<String>()))
        .unwrap_or_default()
}

fn selector(text: &str) -> Selector {
    Selector::parse(text).expect("a valid built-in selector")
}

fn parse_bing(doc: &Html) -> Vec<SearchResult> {
    let block = selector("li.b_algo");
    let anchor = selector("h2 a");
    let snippet = selector(".b_caption p, p");
    let mut results = Vec::new();
    for element in doc.select(&block) {
        let Some(link) = element.select(&anchor).next() else {
            continue;
        };
        let title = clean_text(&link.text().collect::<String>());
        let url = unwrap_bing(link.value().attr("href").unwrap_or_default());
        if !title.is_empty() && !url.is_empty() {
            results.push(SearchResult {
                title,
                url,
                snippet: first_text(&element, &snippet),
            });
        }
    }
    results
}

fn parse_duckduckgo(doc: &Html) -> Vec<SearchResult> {
    let body = selector(".result__body");
    let web = selector(".web-result");
    let anchor = selector("a.result__a");
    let snippet = selector(".result__snippet");
    let mut containers: Vec<_> = doc.select(&body).collect();
    if containers.is_empty() {
        containers = doc.select(&web).collect();
    }
    let mut results = Vec::new();
    for element in containers {
        let Some(link) = element.select(&anchor).next() else {
            continue;
        };
        let title = clean_text(&link.text().collect::<String>());
        let url = resolve_duckduckgo_href(link.value().attr("href").unwrap_or_default());
        // Ads link back to a duckduckgo.com click tracker.
        let tracker = url::Url::parse(&url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_owned))
            .is_some_and(|host| host == "duckduckgo.com" || host.ends_with(".duckduckgo.com"));
        if !title.is_empty() && !url.is_empty() && !tracker {
            results.push(SearchResult {
                title,
                url,
                snippet: first_text(&element, &snippet),
            });
        }
    }
    results
}

/// `//duckduckgo.com/l/?uddg=<target>` → target.
fn resolve_duckduckgo_href(href: &str) -> String {
    if href.is_empty() {
        return String::new();
    }
    let normalized = href
        .strip_prefix("//")
        .map_or_else(|| href.to_owned(), |rest| format!("https://{rest}"));
    match url::Url::parse(&normalized) {
        Ok(parsed) => parsed
            .query_pairs()
            .find(|(key, _)| key == "uddg")
            .map(|(_, value)| value.into_owned())
            .unwrap_or_else(|| parsed.to_string()),
        Err(_) => href.to_owned(),
    }
}

/// One page in a Wikipedia REST search answer.
#[derive(Deserialize)]
struct WikiPage {
    key: Option<String>,
    title: Option<String>,
    excerpt: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct WikiResponse {
    pages: Option<Vec<WikiPage>>,
}

fn parse_wikipedia(body: &str) -> Vec<SearchResult> {
    let Ok(parsed) = serde_json::from_str::<WikiResponse>(body) else {
        return Vec::new();
    };
    parsed
        .pages
        .unwrap_or_default()
        .into_iter()
        .map(|page| {
            let key = page
                .key
                .clone()
                .or_else(|| page.title.clone())
                .unwrap_or_default();
            let title = decode_html(&clean_text(&page.title.or(page.key).unwrap_or_default()));
            let snippet = page.excerpt.or(page.description).unwrap_or_default();
            SearchResult {
                title,
                url: format!("https://en.wikipedia.org/wiki/{}", encode(&key)),
                snippet: decode_html(&clean_text(&strip_tags(&snippet))),
            }
        })
        .collect()
}

fn strip_tags(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for c in input.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Selectors for one result block. The link's href is the URL, and the title
/// falls back to the link text.
struct Css {
    block: &'static str,
    link: &'static str,
    title: &'static str,
    snippet: &'static str,
}

const BRAVE: Css = Css {
    block: "div.snippet[data-type=\"web\"]",
    link: "a[href^=\"http\"]",
    title: ".title",
    snippet:
        ".generic-snippet .content, .inline-qa-question, .inline-qa-answer, .snippet-description",
};

const YAHOO: Css = Css {
    block: "div.algo-sr",
    link: "div.compTitle a",
    title: "div.compTitle h3",
    snippet: "div.compText",
};

fn css(body: &str, rules: &Css, fix_url: fn(&str) -> String) -> Vec<SearchResult> {
    let doc = Html::parse_document(body);
    let (link, title, snippet) = (
        selector(rules.link),
        selector(rules.title),
        selector(rules.snippet),
    );
    let text = |element: ElementRef, wanted: &Selector| {
        element
            .select(wanted)
            .next()
            .map(element_text)
            .unwrap_or_default()
    };
    doc.select(&selector(rules.block))
        .filter_map(|element| {
            let anchor = element.select(&link).next()?;
            let url = fix_url(anchor.value().attr("href")?);
            let title = Some(text(element, &title))
                .filter(|title| !title.is_empty())
                .unwrap_or_else(|| element_text(anchor));
            (!title.is_empty() && url.starts_with("http")).then(|| SearchResult {
                title,
                url,
                snippet: text(element, &snippet),
            })
        })
        .collect()
}

fn element_text(element: ElementRef) -> String {
    clean_text(&element.text().collect::<String>())
}

/// Strips tags and decodes entities in HTML carried inside JSON, such as `Apple&#039;s`.
fn decode_html(text: &str) -> String {
    if !text.contains(['&', '<']) {
        return text.to_owned();
    }
    element_text(Html::parse_fragment(text).root_element())
}

fn query_param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// `bing.com/ck/a?...&u=a1<base64url>` → target.
fn unwrap_bing(href: &str) -> String {
    query_param(href, "u")
        .and_then(|value| value.strip_prefix("a1").map(str::to_owned))
        .and_then(|encoded| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded.trim_end_matches('='))
                .ok()
        })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| href.to_owned())
}

/// `r.search.yahoo.com/.../RU=<encoded target>/RK=...` → target.
fn unwrap_yahoo(href: &str) -> String {
    href.split_once("/RU=")
        .and_then(|(_, rest)| rest.split('/').next())
        .map(|target| percent_decode_str(target).decode_utf8_lossy().into_owned())
        .unwrap_or_else(|| href.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_names_round_trip() {
        for engine in EngineId::ALL {
            assert_eq!(EngineId::from_name(engine.name()), Some(engine));
        }
        assert_eq!(EngineId::from_name("google"), None);
    }

    #[test]
    fn search_urls_encode_the_query_and_time_range() {
        assert_eq!(
            search_url(EngineId::Brave, "a b&c", Some(TimeRange::Week)),
            "https://search.brave.com/search?q=a+b%26c&source=web&tf=pw"
        );
        assert_eq!(
            search_url(EngineId::DuckDuckGo, "rust", Some(TimeRange::Day)),
            "https://html.duckduckgo.com/html/?q=rust&df=d"
        );
        assert_eq!(
            search_url(EngineId::Bing, "rust", Some(TimeRange::Month)),
            "https://www.bing.com/search?q=rust&form=QBLH&filters=ex1%3A%22ez3%22"
        );
        assert!(search_url(EngineId::Bing, "rust", Some(TimeRange::Year))
            .contains("&filters=ex1%3A%22ez5_"));
        assert_eq!(
            search_url(EngineId::Yahoo, "rust", Some(TimeRange::Week)),
            "https://search.yahoo.com/search?p=rust&fr=sfp&age=1w&btf=w&fr2=time"
        );
        assert_eq!(
            search_url(EngineId::Yahoo, "rust", Some(TimeRange::Year)),
            "https://search.yahoo.com/search?p=rust&fr=sfp"
        );
        assert_eq!(
            search_url(EngineId::Wikipedia, "rust", Some(TimeRange::Day)),
            "https://en.wikipedia.org/w/rest.php/v1/search/page?q=rust&limit=10"
        );
    }

    #[test]
    fn block_rules_follow_status_url_and_count() {
        assert_eq!(
            blocked(EngineId::Bing, 200, "https://www.bing.com/search", 10),
            None
        );
        assert!(blocked(EngineId::Brave, 429, "https://search.brave.com/search", 0).is_some());
        assert!(blocked(EngineId::Bing, 200, "https://www.bing.com/captcha?x", 10).is_some());
        assert!(blocked(EngineId::Yahoo, 200, "https://example.com/sorry/index", 10).is_some());
        assert!(blocked(
            EngineId::DuckDuckGo,
            200,
            "https://html.duckduckgo.com/html/",
            0
        )
        .is_some());
        assert_eq!(
            blocked(EngineId::Wikipedia, 200, "https://en.wikipedia.org/", 0),
            None
        );
    }

    #[test]
    fn brave_pages_that_mention_captcha_still_parse() {
        let page = r#"<html><body><a>Switch to traditional captcha</a>
            <div class="snippet" data-type="web"><a href="https://example.com/a">
            <div class="title">Example A</div></a>
            <div class="generic-snippet"><div class="content">About A</div></div></div>
            </body></html>"#;
        let results = parse(EngineId::Brave, page);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/a");
        assert_eq!(results[0].snippet, "About A");
        assert_eq!(
            blocked(EngineId::Brave, 200, "https://search.brave.com/search", 1),
            None
        );
    }

    #[test]
    fn redirect_links_unwrap_to_their_targets() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("https://docs.rs/");
        assert_eq!(
            unwrap_bing(&format!(
                "https://www.bing.com/ck/a?!&&p=1&u=a1{encoded}&ntb=1"
            )),
            "https://docs.rs/"
        );
        assert_eq!(
            unwrap_yahoo("https://r.search.yahoo.com/_ylt=x/RV=2/RE=1/RO=10/RU=https%3a%2f%2ftokio.rs%2f/RK=2/RS=y-"),
            "https://tokio.rs/"
        );
        assert_eq!(
            resolve_duckduckgo_href("//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fx&rut=1"),
            "https://example.com/x"
        );
    }

    #[test]
    fn wikipedia_excerpts_lose_markup_and_entities() {
        let body = r#"{"pages":[{"key":"Apple_silicon","title":"Apple silicon","excerpt":"<span class=\"searchmatch\">Apple</span>&#039;s chips"}]}"#;
        let results = parse(EngineId::Wikipedia, body);
        assert_eq!(
            results,
            vec![SearchResult {
                title: "Apple silicon".into(),
                url: "https://en.wikipedia.org/wiki/Apple_silicon".into(),
                snippet: "Apple's chips".into(),
            }]
        );
    }
}
