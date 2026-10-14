//! Metasearch over stand-in engines: merging, filters, blocks and ranges.

mod common;

use common::{Answer, Engines};
use muniment_search::{EngineId, EngineStatus, Query, TimeRange};

fn urls(outcome: &muniment_search::Outcome) -> Vec<&str> {
    outcome
        .results
        .iter()
        .map(|merged| merged.result.url.as_str())
        .collect()
}

fn status(outcome: &muniment_search::Outcome, engine: EngineId) -> EngineStatus {
    outcome
        .engines
        .iter()
        .find(|report| report.engine == engine)
        .map(|report| report.status.clone())
        .unwrap()
}

#[test]
fn results_merge_by_url_and_interleave_by_rank_in_engine_order() {
    let engines = Engines::default()
        .answer(
            EngineId::Brave,
            Answer::Results(vec!["https://a.example/", "https://b.example/"]),
        )
        .answer(
            EngineId::Bing,
            Answer::Results(vec!["https://www.a.example", "https://c.example/"]),
        )
        .answer(
            EngineId::DuckDuckGo,
            Answer::Results(vec!["https://d.example/", "http://b.example/#x"]),
        );
    let search = engines.metasearch(&[EngineId::Brave, EngineId::Bing, EngineId::DuckDuckGo]);
    let outcome = search.search(&Query::new("rust"));
    assert_eq!(
        urls(&outcome),
        [
            "https://a.example/",
            "https://d.example/",
            "https://b.example/",
            "https://c.example/"
        ]
    );
    assert_eq!(
        outcome.results[0].engines,
        [EngineId::Brave, EngineId::Bing]
    );
    assert_eq!(
        outcome.results[2].engines,
        [EngineId::Brave, EngineId::DuckDuckGo]
    );
    assert_eq!(status(&outcome, EngineId::Bing), EngineStatus::Answered(2));
}

#[test]
fn site_terms_filter_results_and_reach_only_engines_that_read_them() {
    let engines = Engines::default()
        .answer(
            EngineId::Bing,
            Answer::Results(vec![
                "https://docs.rs/tokio",
                "https://old.docs.rs/tokio",
                "https://example.com/tokio",
            ]),
        )
        .answer(
            EngineId::Wikipedia,
            Answer::Results(vec!["https://en.wikipedia.org/wiki/Tokio"]),
        );
    let search = engines.metasearch(&[EngineId::Bing, EngineId::Wikipedia]);
    let outcome = search.search(&Query::new("tokio site:docs.rs -site:old.docs.rs"));
    assert_eq!(urls(&outcome), ["https://docs.rs/tokio"]);
    assert_eq!(
        engines.searches(EngineId::Bing),
        ["https://www.bing.com/search?q=tokio+site%3Adocs.rs+-site%3Aold.docs.rs&form=QBLH"]
    );
    assert_eq!(
        engines.searches(EngineId::Wikipedia),
        ["https://en.wikipedia.org/w/rest.php/v1/search/page?q=tokio&limit=10"]
    );
}

#[test]
fn a_blocked_engine_is_dropped_and_then_rests() {
    let engines = Engines::default()
        .answer(EngineId::Brave, Answer::Status(429))
        .answer(EngineId::Yahoo, Answer::Results(vec![]))
        .answer(
            EngineId::DuckDuckGo,
            Answer::Results(vec!["https://a.example/"]),
        );
    let search = engines.metasearch(&[EngineId::Brave, EngineId::Yahoo, EngineId::DuckDuckGo]);
    let outcome = search.search(&Query::new("rust"));
    assert_eq!(urls(&outcome), ["https://a.example/"]);
    assert_eq!(
        status(&outcome, EngineId::Brave),
        EngineStatus::Blocked("HTTP 429".into())
    );
    assert_eq!(
        status(&outcome, EngineId::Yahoo),
        EngineStatus::Blocked("no results".into())
    );
    assert!(outcome.answered());

    let again = search.search(&Query::new("rust"));
    assert!(matches!(
        status(&again, EngineId::Brave),
        EngineStatus::CoolingDown(_)
    ));
    assert_eq!(engines.searches(EngineId::Brave).len(), 1);
    assert_eq!(engines.searches(EngineId::DuckDuckGo).len(), 2);
}

#[test]
fn a_time_range_skips_engines_that_cannot_honor_it() {
    let engines = Engines::default()
        .answer(EngineId::Brave, Answer::Results(vec!["https://a.example/"]))
        .answer(EngineId::Yahoo, Answer::Results(vec!["https://b.example/"]))
        .answer(
            EngineId::Wikipedia,
            Answer::Results(vec!["https://en.wikipedia.org/wiki/A"]),
        );
    let search = engines.metasearch(&[EngineId::Brave, EngineId::Yahoo, EngineId::Wikipedia]);
    let mut query = Query::new("rust");
    query.time_range = Some(TimeRange::Year);
    let outcome = search.search(&query);
    assert_eq!(urls(&outcome), ["https://a.example/"]);
    assert_eq!(status(&outcome, EngineId::Yahoo), EngineStatus::Skipped);
    assert_eq!(status(&outcome, EngineId::Wikipedia), EngineStatus::Skipped);
    assert_eq!(
        engines.searches(EngineId::Brave),
        ["https://search.brave.com/search?q=rust&source=web&tf=py"]
    );

    query.time_range = Some(TimeRange::Week);
    let outcome = search.search(&query);
    assert_eq!(status(&outcome, EngineId::Yahoo), EngineStatus::Answered(1));
}

#[test]
fn the_count_stays_between_one_and_twenty() {
    let many: Vec<&'static str> = (0..10)
        .map(|n| &*Box::leak(format!("https://brave{n}.example/").into_boxed_str()))
        .collect();
    let more: Vec<&'static str> = (0..10)
        .map(|n| &*Box::leak(format!("https://bing{n}.example/").into_boxed_str()))
        .collect();
    let most: Vec<&'static str> = (0..10)
        .map(|n| &*Box::leak(format!("https://ddg{n}.example/").into_boxed_str()))
        .collect();
    let engines = Engines::default()
        .answer(EngineId::Brave, Answer::Results(many))
        .answer(EngineId::Bing, Answer::Results(more))
        .answer(EngineId::DuckDuckGo, Answer::Results(most));
    let search = engines.metasearch(&[EngineId::Brave, EngineId::Bing, EngineId::DuckDuckGo]);
    let mut query = Query::new("rust");
    query.count = 50;
    assert_eq!(search.search(&query).results.len(), 20);
    query.count = 0;
    assert_eq!(search.search(&query).results.len(), 1);
    query.count = 5;
    assert_eq!(search.search(&query).results.len(), 5);
}

#[test]
fn only_enabled_engines_run_in_the_configured_order() {
    let engines = Engines::default()
        .answer(EngineId::Brave, Answer::Results(vec!["https://a.example/"]))
        .answer(EngineId::Bing, Answer::Results(vec!["https://b.example/"]))
        .answer(EngineId::Yahoo, Answer::Results(vec!["https://c.example/"]));
    let search = engines.metasearch(&[EngineId::Yahoo, EngineId::Bing, EngineId::Yahoo]);
    assert_eq!(search.engines(), [EngineId::Yahoo, EngineId::Bing]);
    let outcome = search.search(&Query::new("rust"));
    assert_eq!(urls(&outcome), ["https://c.example/", "https://b.example/"]);
    assert!(engines.searches(EngineId::Brave).is_empty());
}
