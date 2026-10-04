//! Prometheus metrics in the text exposition format.
//!
//! Counters and histograms accumulate in memory for the life of the process.
//! Gauges for cooldowns, quota windows and runs are read from the router's
//! state when Prometheus scrapes.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;

/// Upper bounds of the latency histogram, in seconds.
const BUCKETS: [f64; 12] = [
    0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
];

type Labels = Vec<(&'static str, String)>;

/// One gauge sample: the metric name, its labels and its value.
pub type Gauge = (&'static str, Labels, f64);

struct Histogram {
    counts: [u64; BUCKETS.len()],
    sum: f64,
    count: u64,
}

#[derive(Default)]
pub struct Metrics {
    counters: Mutex<BTreeMap<(&'static str, Labels), f64>>,
    histograms: Mutex<BTreeMap<(&'static str, Labels), Histogram>>,
}

/// What each metric family means, for the `# HELP` and `# TYPE` lines.
const FAMILIES: &[(&str, &str, &str)] = &[
    (
        "muniment_router_http_requests_total",
        "counter",
        "HTTP requests answered, by route and status.",
    ),
    (
        "muniment_router_upstream_requests_total",
        "counter",
        "Upstream attempts, by model, account and outcome.",
    ),
    (
        "muniment_router_tokens_total",
        "counter",
        "Tokens upstream answers reported, by model and kind.",
    ),
    (
        "muniment_router_cost_usd_total",
        "counter",
        "Estimated spend in US dollars, by model.",
    ),
    (
        "muniment_router_upstream_duration_seconds",
        "histogram",
        "Upstream attempt duration, by model.",
    ),
    (
        "muniment_router_routing_decisions_total",
        "counter",
        "Routing decisions, by model, role and reason.",
    ),
    (
        "muniment_router_budget_rejections_total",
        "counter",
        "Requests refused for an exhausted run budget, by role.",
    ),
    (
        "muniment_router_cooldowns_total",
        "counter",
        "Upstream refusals that cooled an account, by account.",
    ),
    (
        "muniment_router_catalog_reloads_total",
        "counter",
        "Catalog file loads, by result.",
    ),
    (
        "muniment_router_account_cooling",
        "gauge",
        "1 while an account is in cooldown.",
    ),
    (
        "muniment_router_account_cooldown_seconds",
        "gauge",
        "Seconds until an account's cooldown ends.",
    ),
    (
        "muniment_router_account_in_flight",
        "gauge",
        "Upstream turns in flight, by account.",
    ),
    (
        "muniment_router_quota_used_percent",
        "gauge",
        "Percent of a subscription window spent, by account, window and scope.",
    ),
    (
        "muniment_router_runs_active",
        "gauge",
        "Runs with a live token known to this process.",
    ),
    (
        "muniment_router_draining",
        "gauge",
        "1 while the router drains before it stops.",
    ),
];

impl Metrics {
    pub fn add(&self, name: &'static str, labels: &[(&'static str, &str)], value: f64) {
        let labels = labels.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
        *self
            .counters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry((name, labels))
            .or_insert(0.0) += value;
    }

    pub fn observe(&self, name: &'static str, labels: &[(&'static str, &str)], seconds: f64) {
        let labels = labels.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
        let mut histograms = self.histograms.lock().unwrap_or_else(|e| e.into_inner());
        let entry = histograms.entry((name, labels)).or_insert(Histogram {
            counts: [0; BUCKETS.len()],
            sum: 0.0,
            count: 0,
        });
        for (index, bound) in BUCKETS.iter().enumerate() {
            if seconds <= *bound {
                entry.counts[index] += 1;
            }
        }
        entry.sum += seconds;
        entry.count += 1;
    }

    /// The exposition text: every accumulated series plus `gauges`.
    pub fn render(&self, gauges: &[Gauge]) -> String {
        let mut series: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for ((name, labels), value) in self
            .counters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            series.entry(name).or_default().push(format!(
                "{name}{} {}",
                render_labels(labels, None),
                number(*value)
            ));
        }
        for ((name, labels), histogram) in self
            .histograms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            let lines = series.entry(name).or_default();
            for (index, bound) in BUCKETS.iter().enumerate() {
                lines.push(format!(
                    "{name}_bucket{} {}",
                    render_labels(labels, Some(&number(*bound))),
                    histogram.counts[index]
                ));
            }
            lines.push(format!(
                "{name}_bucket{} {}",
                render_labels(labels, Some("+Inf")),
                histogram.count
            ));
            lines.push(format!(
                "{name}_sum{} {}",
                render_labels(labels, None),
                number(histogram.sum)
            ));
            lines.push(format!(
                "{name}_count{} {}",
                render_labels(labels, None),
                histogram.count
            ));
        }
        for (name, labels, value) in gauges {
            series.entry(name).or_default().push(format!(
                "{name}{} {}",
                render_labels(labels, None),
                number(*value)
            ));
        }
        let mut text = String::new();
        for (name, kind, help) in FAMILIES {
            let Some(lines) = series.get(name) else {
                continue;
            };
            let _ = writeln!(text, "# HELP {name} {help}");
            let _ = writeln!(text, "# TYPE {name} {kind}");
            for line in lines {
                let _ = writeln!(text, "{line}");
            }
        }
        text
    }
}

fn number(value: f64) -> String {
    if value.is_finite() {
        format!("{value}")
    } else if value.is_nan() {
        "NaN".into()
    } else if value > 0.0 {
        "+Inf".into()
    } else {
        "-Inf".into()
    }
}

fn render_labels(labels: &[(&'static str, String)], bucket: Option<&str>) -> String {
    let mut parts: Vec<String> = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{}\"", escape(value)))
        .collect();
    if let Some(bound) = bucket {
        parts.push(format!("le=\"{bound}\""));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", parts.join(","))
    }
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exposition_carries_help_type_labels_and_buckets() {
        let metrics = Metrics::default();
        metrics.add(
            "muniment_router_cost_usd_total",
            &[("model", "openai/a\"b")],
            0.5,
        );
        metrics.add(
            "muniment_router_cost_usd_total",
            &[("model", "openai/a\"b")],
            0.25,
        );
        metrics.observe(
            "muniment_router_upstream_duration_seconds",
            &[("model", "m")],
            0.3,
        );
        let text = metrics.render(&[(
            "muniment_router_account_cooling",
            vec![("account", "a1".into())],
            1.0,
        )]);
        assert!(text.contains("# TYPE muniment_router_cost_usd_total counter"));
        assert!(text.contains("muniment_router_cost_usd_total{model=\"openai/a\\\"b\"} 0.75"));
        assert!(text.contains(
            "muniment_router_upstream_duration_seconds_bucket{model=\"m\",le=\"0.25\"} 0"
        ));
        assert!(text.contains(
            "muniment_router_upstream_duration_seconds_bucket{model=\"m\",le=\"0.5\"} 1"
        ));
        assert!(text.contains(
            "muniment_router_upstream_duration_seconds_bucket{model=\"m\",le=\"+Inf\"} 1"
        ));
        assert!(text.contains("muniment_router_upstream_duration_seconds_count{model=\"m\"} 1"));
        assert!(text.contains("muniment_router_account_cooling{account=\"a1\"} 1"));
        assert!(!text.contains("muniment_router_runs_active"));
    }
}
