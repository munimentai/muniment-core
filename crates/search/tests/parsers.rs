//! Each engine's parser against one saved result page.

use muniment_search::engines::{blocked, parse, EngineId};

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn check(engine: EngineId, file: &str) -> Vec<muniment_search::SearchResult> {
    let results = parse(engine, &fixture(file));
    for result in &results {
        println!("{} | {} | {}", result.title, result.url, result.snippet);
    }
    assert!(!results.is_empty(), "{file} parsed to no results");
    assert!(results.len() <= 10);
    for result in &results {
        assert!(!result.title.is_empty(), "{file}: a result without a title");
        assert!(
            result.url.starts_with("https://") || result.url.starts_with("http://"),
            "{file}: {} is not a target URL",
            result.url
        );
    }
    assert_eq!(
        blocked(engine, 200, "https://example.com/search", results.len()),
        None
    );
    results
}

#[test]
fn bing_links_unwrap_to_their_targets() {
    let results = check(EngineId::Bing, "bing.html");
    assert!(results.len() >= 8);
    assert!(results.iter().all(|r| !r.url.contains("bing.com/ck/")));
    assert!(results.iter().any(|r| !r.snippet.is_empty()));
}

#[test]
fn duckduckgo_links_unwrap_to_their_targets() {
    let results = check(EngineId::DuckDuckGo, "duckduckgo.html");
    assert!(results.len() >= 8);
    assert!(results.iter().all(|r| !r.url.contains("duckduckgo.com")));
    assert!(results.iter().all(|r| !r.snippet.is_empty()));
}

#[test]
fn wikipedia_answers_become_article_links() {
    let results = check(EngineId::Wikipedia, "wikipedia.json");
    assert!(results
        .iter()
        .all(|r| r.url.starts_with("https://en.wikipedia.org/wiki/")));
    assert!(results
        .iter()
        .all(|r| !r.snippet.contains('<') && !r.snippet.contains("&#")));
}

#[test]
fn yahoo_links_unwrap_to_their_targets() {
    let results = check(EngineId::Yahoo, "yahoo.html");
    assert!(results
        .iter()
        .all(|r| !r.url.contains("r.search.yahoo.com")));
    assert!(results.iter().any(|r| !r.snippet.is_empty()));
}

#[test]
fn brave_web_results_parse_despite_the_captcha_link() {
    let page = fixture("brave.html");
    assert!(page.to_lowercase().contains("captcha"));
    let results = check(EngineId::Brave, "brave.html");
    assert!(results.len() >= 8);
    assert!(results.iter().all(|r| !r.snippet.is_empty()));
}
