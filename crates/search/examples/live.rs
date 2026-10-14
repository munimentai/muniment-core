//! Searches the real engines once and prints what each one did.
//!
//! `cargo run -p muniment-search --example live -- "query" [day|week|month|year]`
//!
//! `ENGINES=brave,bing` limits the search to those engines.

use muniment_search::{Config, EngineId, EngineStatus, Metasearch, Query, TimeRange};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(text) = args.next() else {
        eprintln!("usage: live <query> [day|week|month|year]");
        std::process::exit(2);
    };
    let mut query = Query::new(text);
    query.count = 20;
    query.time_range = args.next().and_then(|range| TimeRange::from_name(&range));
    let mut config = Config::default();
    if let Ok(names) = std::env::var("ENGINES") {
        config.engines = names.split(',').filter_map(EngineId::from_name).collect();
    }
    let search = Metasearch::new(config);
    let started = std::time::Instant::now();
    let outcome = search.search(&query);
    println!("{:.1}s", started.elapsed().as_secs_f64());
    for report in &outcome.engines {
        let status = match &report.status {
            EngineStatus::Answered(count) => format!("{count} results"),
            EngineStatus::Blocked(reason) => format!("blocked: {reason}"),
            EngineStatus::CoolingDown(seconds) => format!("cooling down {seconds}s"),
            EngineStatus::Failed(reason) => format!("failed: {reason}"),
            EngineStatus::Skipped => "skipped".to_owned(),
        };
        let transport = report.transport.unwrap_or("-");
        println!("{:<11} {transport:<6} {status}", report.engine.name());
    }
    println!("merged: {}", outcome.results.len());
    for (rank, merged) in outcome.results.iter().enumerate() {
        let engines: Vec<&str> = merged.engines.iter().map(|engine| engine.name()).collect();
        println!(
            "{:>2}. {} | {} [{}]",
            rank + 1,
            merged.result.title,
            merged.result.url,
            engines.join(",")
        );
    }
}
