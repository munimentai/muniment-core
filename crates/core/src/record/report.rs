//! The local report: every finding is a query over the resolved graph, run
//! live, and nothing here writes. Each finding is one sentence with a
//! magnitude, a claim and a consequence, and the evidence behind it is a few
//! records, so a person can agree with it, disagree with it, or fix it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{CompanyRecord, RecordError};

/// How far behind its kind's newest row a record is before it counts stale.
const STALE_DAYS: i64 = 365;
/// A dead field holds a value on fewer than one row in this many.
const DEAD_FIELD_PER: i64 = 1_000;
/// A text field with at most this many distinct values is a list in prose.
const LIST_DISTINCT_CAP: i64 = 12;
/// A field needs this many filled rows before its distinct count says anything.
const LIST_FILLED_FLOOR: i64 = 50;
/// How many example lines a finding's evidence carries.
const EXAMPLES: usize = 3;

/// One row of the report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    /// `identity`, `freshness` or `schema`.
    pub category: String,
    pub magnitude: i64,
    /// The noun phrase the magnitude counts, `duplicate people`.
    pub short: String,
    pub claim: String,
    pub consequence: String,
    /// The kind the finding is about, when it is about one kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub evidence: Vec<String>,
}

/// One kind and the live records it holds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KindCount {
    pub name: String,
    pub count: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// Findings with a magnitude above zero, largest first.
    pub findings: Vec<Finding>,
    pub kinds: Vec<KindCount>,
    pub open: usize,
}

/// The legal suffixes a company name carries or drops between systems.
const LEGAL_SUFFIXES: [&str; 18] = [
    "inc",
    "incorporated",
    "llc",
    "ltd",
    "limited",
    "corp",
    "corporation",
    "co",
    "company",
    "gmbh",
    "plc",
    "sa",
    "ag",
    "bv",
    "pty",
    "llp",
    "lp",
    "srl",
];

/// Properties that hold prose or a name, never a list.
const PROSE_PROPERTIES: [&str; 22] = [
    "name",
    "legal_name",
    "full_name",
    "given_name",
    "family_name",
    "title",
    "subject",
    "description",
    "notes",
    "body_text",
    "preview",
    "sender",
    "email",
    "phone",
    "website",
    "domain",
    "url",
    "repo_url",
    "external_key",
    "external_message_id",
    "in_reply_to",
    "key",
];

/// A company name folded for comparison: lowercase, punctuation dropped, the
/// legal suffix dropped.
pub fn fold_org_name(name: &str) -> String {
    let lowered: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    let mut words: Vec<&str> = lowered.split_whitespace().collect();
    while words.len() > 1
        && words
            .last()
            .is_some_and(|word| LEGAL_SUFFIXES.contains(word))
    {
        words.pop();
    }
    words.join(" ")
}

/// A web domain folded for comparison: lowercase, no scheme, no `www.`, no path.
pub fn fold_domain(value: &str) -> String {
    let mut text = value.trim().to_lowercase();
    if let Some(index) = text.find("://") {
        text = text[index + 3..].to_owned();
    }
    if let Some(index) = text.find('/') {
        text.truncate(index);
    }
    text.trim_start_matches("www.")
        .trim_end_matches('.')
        .to_owned()
}

fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn count(value: i64) -> String {
    let digits = value.abs().to_string();
    let mut out = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    if value < 0 {
        format!("-{out}")
    } else {
        out
    }
}

fn plural(value: i64, word: &str) -> String {
    if value == 1 {
        format!("{} {word}", count(value))
    } else {
        format!("{} {word}s", count(value))
    }
}

/// Groups of titled rows that share one key, largest first.
fn duplicate_groups(rows: Vec<(String, String, String)>) -> Vec<(String, Vec<(String, String)>)> {
    let mut groups: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (key, id, title) in rows {
        if key.is_empty() {
            continue;
        }
        groups.entry(key).or_default().push((id, title));
    }
    let mut groups: Vec<(String, Vec<(String, String)>)> = groups
        .into_iter()
        .filter(|(_, members)| members.len() > 1)
        .collect();
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    groups
}

impl CompanyRecord {
    /// The live rows of every kind, most first.
    fn kind_counts(&self) -> Result<Vec<KindCount>, RecordError> {
        let mut statement = self.connection.prepare(
            "select kind, count(*) from entity where deleted_at is null group by kind order by count(*) desc, kind",
        )?;
        let counts = statement
            .query_map([], |row| {
                Ok(KindCount {
                    name: row.get(0)?,
                    count: row.get(1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(counts)
    }

    fn titled_rows(&self, kind: &str) -> Result<Vec<(String, String)>, RecordError> {
        let mut statement = self.connection.prepare(
            "select id, title from entity where kind = ?1 and deleted_at is null and trim(title) <> '' order by title, id",
        )?;
        let rows = statement
            .query_map([kind], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn duplicate_people(&self, rows: i64) -> Result<Option<Finding>, RecordError> {
        let people = self
            .titled_rows("person")?
            .into_iter()
            .map(|(id, title)| (title.trim().to_lowercase(), id, title))
            .collect();
        let groups = duplicate_groups(people);
        let extras: i64 = groups
            .iter()
            .map(|(_, members)| members.len() as i64 - 1)
            .sum();
        if extras == 0 {
            return Ok(None);
        }
        let mut evidence = vec![
            format!(
                "person {} rows, {} resolve onto another person",
                count(rows),
                count(extras)
            ),
            "rule lower(title) equal, no shared identity".to_owned(),
        ];
        for (_, members) in groups.iter().take(EXAMPLES) {
            let ids: Vec<&str> = members.iter().map(|(id, _)| id.as_str()).take(2).collect();
            evidence.push(format!(
                "{} {} rows {}",
                members[0].1,
                members.len(),
                ids.join(" ")
            ));
        }
        Ok(Some(Finding {
            id: "duplicate-person".into(),
            category: "identity".into(),
            magnitude: extras,
            short: "duplicate people".into(),
            claim: "people appear more than once under one name".into(),
            consequence: "every owner report and every campaign count reads them twice".into(),
            kind: Some("person".into()),
            evidence,
        }))
    }

    fn duplicate_organizations(&self, rows: i64) -> Result<Option<Finding>, RecordError> {
        let orgs = self
            .titled_rows("org")?
            .into_iter()
            .map(|(id, title)| (fold_org_name(&title), id, title))
            .collect();
        let groups = duplicate_groups(orgs);
        let extras: i64 = groups
            .iter()
            .map(|(_, members)| members.len() as i64 - 1)
            .sum();
        if extras == 0 {
            return Ok(None);
        }
        let mut evidence = vec![
            format!(
                "org {} rows, {} share a normalized name",
                count(rows),
                count(extras)
            ),
            "rule name lowercased, punctuation and legal suffix dropped".to_owned(),
        ];
        for (_, members) in groups.iter().take(EXAMPLES) {
            let titles: Vec<&str> = members
                .iter()
                .map(|(_, title)| title.as_str())
                .take(2)
                .collect();
            evidence.push(format!("{} {}", titles.join(" and "), members[0].0));
        }
        Ok(Some(Finding {
            id: "duplicate-organization".into(),
            category: "identity".into(),
            magnitude: extras,
            short: "duplicate organizations".into(),
            claim: "organizations carry a name another organization already carries".into(),
            consequence: "pipeline rolls up to two rows for one account".into(),
            kind: Some("org".into()),
            evidence,
        }))
    }

    fn domain_collisions(&self) -> Result<Option<Finding>, RecordError> {
        let mut claims: Vec<(String, String, String)> = Vec::new();
        let mut statement = self.connection.prepare(
            "select id, title, json_extract(data, '$.domain') from entity
             where kind = 'org' and deleted_at is null and json_extract(data, '$.domain') is not null",
        )?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (id, title, domain) = row?;
            claims.push((fold_domain(&domain), id, title));
        }
        let mut statement = self.connection.prepare(
            "select e.id, e.title, i.value from identity i join entity e on e.id = i.entity_id
             where i.kind = 'domain' and e.kind = 'org' and e.deleted_at is null",
        )?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (id, title, domain) = row?;
            claims.push((fold_domain(&domain), id, title));
        }
        // One org claiming one domain twice is one claim.
        claims.sort();
        claims.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
        let groups = duplicate_groups(claims);
        let orgs: i64 = groups.iter().map(|(_, members)| members.len() as i64).sum();
        if orgs == 0 {
            return Ok(None);
        }
        let mut evidence = vec![format!(
            "org {} rows share a domain with another row across {}",
            count(orgs),
            plural(groups.len() as i64, "domain")
        )];
        for (domain, members) in groups.iter().take(EXAMPLES) {
            let titles: Vec<&str> = members
                .iter()
                .map(|(_, title)| title.as_str())
                .take(3)
                .collect();
            evidence.push(format!("{domain} {}", titles.join(", ")));
        }
        Ok(Some(Finding {
            id: "domain-collision".into(),
            category: "identity".into(),
            magnitude: orgs,
            short: "domains claimed twice".into(),
            claim: "organizations claim a web domain another organization already claims".into(),
            consequence: "routing sends one account to two owners".into(),
            kind: Some("org".into()),
            evidence,
        }))
    }

    /// The properties a kind row defines, core then own.
    fn kind_properties(&self, kind: &super::KindRow) -> Vec<(String, serde_json::Value)> {
        let mut properties = Vec::new();
        for schema in std::iter::once(&kind.schema).chain(kind.extension.iter()) {
            if let Some(map) = schema.get("properties").and_then(|value| value.as_object()) {
                for (name, definition) in map {
                    if identifier(name) {
                        properties.push((name.clone(), definition.clone()));
                    }
                }
            }
        }
        properties
    }

    fn dead_fields(&self, kinds: &[super::KindRow]) -> Result<Option<Finding>, RecordError> {
        let mut lines = Vec::new();
        let mut total = 0_i64;
        for kind in kinds {
            if kind.count < DEAD_FIELD_PER {
                continue;
            }
            let known: Vec<String> = self
                .kind_properties(kind)
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            let mut statement = self.connection.prepare(
                "select j.key, count(*) from entity e, json_each(e.data) j
                 where e.kind = ?1 and e.deleted_at is null and j.type <> 'null'
                   and not (j.type = 'text' and trim(j.value) = '')
                 group by j.key",
            )?;
            let filled = statement
                .query_map([&kind.name], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for (property, filled) in filled {
                if !known.contains(&property) {
                    continue;
                }
                if filled > 0 && filled * DEAD_FIELD_PER < kind.count {
                    total += 1;
                    lines.push((
                        filled,
                        format!(
                            "{}.{property} {} of {} rows",
                            kind.name,
                            count(filled),
                            count(kind.count)
                        ),
                    ));
                }
            }
        }
        if total == 0 {
            return Ok(None);
        }
        lines.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let mut evidence: Vec<String> = lines
            .iter()
            .take(EXAMPLES)
            .map(|(_, line)| line.clone())
            .collect();
        if total as usize > EXAMPLES {
            evidence.push(format!(
                "{} more under the same bound",
                count(total - EXAMPLES as i64)
            ));
        }
        Ok(Some(Finding {
            id: "dead-field".into(),
            category: "schema".into(),
            magnitude: total,
            short: "fields nobody reads".into(),
            claim: "fields hold a value on fewer than one record in a thousand".into(),
            consequence: "a form asks for what no report reads".into(),
            kind: None,
            evidence,
        }))
    }

    fn text_that_is_a_list(
        &self,
        kinds: &[super::KindRow],
    ) -> Result<Option<Finding>, RecordError> {
        let mut lines = Vec::new();
        for kind in kinds {
            if kind.count < LIST_FILLED_FLOOR {
                continue;
            }
            let state_property = kind.state_property().map(str::to_owned);
            for (property, definition) in self.kind_properties(kind) {
                if definition.get("type").and_then(|value| value.as_str()) != Some("string")
                    || definition.get("enum").is_some()
                    || state_property.as_deref() == Some(property.as_str())
                    || PROSE_PROPERTIES.contains(&property.trim_start_matches("x_"))
                {
                    continue;
                }
                let (distinct, filled): (i64, i64) = self.connection.query_row(
                    &format!(
                        "select count(distinct v), count(*) from
                         (select trim(json_extract(data, '$.{property}')) as v from entity
                          where kind = ?1 and deleted_at is null)
                         where v is not null and v <> ''"
                    ),
                    [&kind.name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                if filled >= LIST_FILLED_FLOOR && (2..=LIST_DISTINCT_CAP).contains(&distinct) {
                    lines.push((
                        distinct,
                        format!(
                            "{}.{property} {} distinct values over {} rows",
                            kind.name,
                            count(distinct),
                            count(filled)
                        ),
                    ));
                }
            }
        }
        if lines.is_empty() {
            return Ok(None);
        }
        let total = lines.len() as i64;
        lines.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let mut evidence: Vec<String> = lines
            .iter()
            .take(EXAMPLES)
            .map(|(_, line)| line.clone())
            .collect();
        if total as usize > EXAMPLES {
            evidence.push(format!(
                "{} more under the same bound",
                count(total - EXAMPLES as i64)
            ));
        }
        Ok(Some(Finding {
            id: "text-that-is-a-list".into(),
            category: "schema".into(),
            magnitude: total,
            short: "text fields that are lists".into(),
            claim: "free text fields hold fewer than twelve distinct values".into(),
            consequence: "a list is doing its work as a paragraph".into(),
            kind: None,
            evidence,
        }))
    }

    fn stale_values(&self, kinds: &[KindCount]) -> Result<Option<Finding>, RecordError> {
        let mut total = 0_i64;
        let mut lines = Vec::new();
        let mut oldest_days = 0_i64;
        for kind in kinds {
            let newest: Option<String> = self.connection.query_row(
                "select max(updated_at) from entity where kind = ?1 and deleted_at is null",
                [&kind.name],
                |row| row.get(0),
            )?;
            let Some(newest) =
                newest.and_then(|text| chrono::DateTime::parse_from_rfc3339(&text).ok())
            else {
                continue;
            };
            let threshold = (newest - chrono::Duration::days(STALE_DAYS))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let (behind, oldest): (i64, Option<String>) = self.connection.query_row(
                "select count(*), min(updated_at) from entity
                 where kind = ?1 and deleted_at is null and updated_at < ?2",
                [&kind.name, &threshold],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if behind == 0 {
                continue;
            }
            total += behind;
            if let Some(oldest) =
                oldest.and_then(|text| chrono::DateTime::parse_from_rfc3339(&text).ok())
            {
                oldest_days = oldest_days.max((newest - oldest).num_days());
            }
            lines.push((
                behind,
                format!(
                    "{} {} behind {}",
                    kind.name,
                    plural(behind, "row"),
                    &threshold[..10]
                ),
            ));
        }
        if total == 0 {
            return Ok(None);
        }
        lines.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let mut evidence: Vec<String> = lines
            .iter()
            .take(EXAMPLES)
            .map(|(_, line)| line.clone())
            .collect();
        evidence.push(format!("oldest {}", plural(oldest_days, "day")));
        Ok(Some(Finding {
            id: "stale-value".into(),
            category: "freshness".into(),
            magnitude: total,
            short: "stale values".into(),
            claim: "records hold a value nothing has touched in a year while their kind moved on"
                .into(),
            consequence: "the older copy answers first".into(),
            kind: None,
            evidence,
        }))
    }

    /// The report over the live graph: every finding with a magnitude, largest
    /// first, and the kind holdings under it. It reads and writes nothing.
    pub fn report(&self) -> Result<Report, RecordError> {
        let counts = self.kind_counts()?;
        let rows = |name: &str| {
            counts
                .iter()
                .find(|kind| kind.name == name)
                .map(|kind| kind.count)
                .unwrap_or(0)
        };
        let kinds = self.kinds()?;
        let mut findings = Vec::new();
        for finding in [
            self.duplicate_people(rows("person"))?,
            self.duplicate_organizations(rows("org"))?,
            self.domain_collisions()?,
            self.dead_fields(&kinds)?,
            self.text_that_is_a_list(&kinds)?,
            self.stale_values(&counts)?,
        ]
        .into_iter()
        .flatten()
        {
            if finding.magnitude > 0 {
                findings.push(finding);
            }
        }
        findings.sort_by(|a, b| b.magnitude.cmp(&a.magnitude).then_with(|| a.id.cmp(&b.id)));
        let open = findings.len();
        Ok(Report {
            findings,
            kinds: counts,
            open,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn record() -> CompanyRecord {
        let path = std::env::temp_dir().join(format!("muniment-report-{}.sqlite3", Uuid::now_v7()));
        CompanyRecord::open(&path).unwrap()
    }

    fn insert(
        record: &CompanyRecord,
        kind: &str,
        title: &str,
        data: &str,
        updated: &str,
    ) -> String {
        let id = Uuid::now_v7().to_string();
        record
            .connection
            .execute(
                "insert into entity (id, kind, title, data, created_at, updated_at)
                 values (?1, ?2, ?3, ?4, ?5, ?5)",
                rusqlite::params![id, kind, title, data, updated],
            )
            .unwrap();
        id
    }

    #[test]
    fn names_fold_the_way_systems_differ_on_them() {
        assert_eq!(
            fold_org_name("Northwind Traders, Inc."),
            "northwind traders"
        );
        assert_eq!(fold_org_name("NORTHWIND TRADERS"), "northwind traders");
        assert_eq!(fold_org_name("Fabrikam Co Ltd"), "fabrikam");
        assert_eq!(fold_org_name("Inc"), "inc");
        assert_eq!(
            fold_domain("https://www.Northwind.example/about"),
            "northwind.example"
        );
        assert_eq!(fold_domain("northwind.example."), "northwind.example");
    }

    #[test]
    fn an_empty_company_has_no_findings() {
        let record = record();
        let report = record.report().unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.open, 0);
        assert!(report.kinds.is_empty());
    }

    #[test]
    fn duplicates_collisions_and_stale_rows_each_carry_their_magnitude() {
        let record = record();
        let now = "2026-09-18T00:00:00.000Z";
        let old = "2024-01-01T00:00:00.000Z";
        insert(
            &record,
            "person",
            "Ada Chen",
            r#"{"full_name":"Ada Chen"}"#,
            now,
        );
        insert(
            &record,
            "person",
            "ada chen",
            r#"{"full_name":"ada chen"}"#,
            now,
        );
        insert(
            &record,
            "person",
            "Ada Chen",
            r#"{"full_name":"Ada Chen"}"#,
            now,
        );
        insert(&record, "person", "Bo Li", r#"{"full_name":"Bo Li"}"#, old);
        insert(
            &record,
            "org",
            "Northwind Traders",
            r#"{"name":"Northwind Traders","domain":"northwind.example"}"#,
            now,
        );
        insert(
            &record,
            "org",
            "Northwind Traders Inc.",
            r#"{"name":"Northwind Traders Inc.","domain":"https://www.northwind.example"}"#,
            now,
        );
        insert(
            &record,
            "org",
            "Contoso",
            r#"{"name":"Contoso","domain":"contoso.example"}"#,
            now,
        );
        insert(
            &record,
            "org",
            "Fabrikam",
            r#"{"name":"Fabrikam","domain":"contoso.example"}"#,
            now,
        );
        let report = record.report().unwrap();
        let ids: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.id.as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "domain-collision",
                "duplicate-person",
                "duplicate-organization",
                "stale-value"
            ]
        );
        let domains = &report.findings[0];
        assert_eq!(domains.magnitude, 4);
        assert!(
            domains.evidence[1].starts_with("contoso.example Contoso, Fabrikam"),
            "{:?}",
            domains.evidence
        );
        let people = &report.findings[1];
        assert_eq!(people.magnitude, 2);
        assert_eq!(people.kind.as_deref(), Some("person"));
        assert!(people.evidence[0].starts_with("person 4 rows, 2 resolve"));
        let orgs = &report.findings[2];
        assert_eq!(orgs.magnitude, 1);
        let stale = &report.findings[3];
        assert_eq!(stale.magnitude, 1);
        assert_eq!(stale.category, "freshness");
        assert!(
            stale
                .evidence
                .last()
                .unwrap()
                .starts_with("oldest 991 days"),
            "{:?}",
            stale.evidence
        );
        assert_eq!(report.open, 4);
        let people = report
            .kinds
            .iter()
            .find(|kind| kind.name == "person")
            .unwrap();
        assert_eq!(people.count, 4);
        assert_eq!(report.kinds.len(), 2);
    }

    #[test]
    fn a_text_field_with_few_values_is_a_list_and_a_rare_field_is_dead() {
        let record = record();
        let now = "2026-09-18T00:00:00.000Z";
        for index in 0..1_200 {
            let reason = ["price", "timing", "competitor"][index % 3];
            let extra = if index < 1 {
                r#","competitor":"Fabrikam""#
            } else {
                ""
            };
            insert(
                &record,
                "deal",
                &format!("Deal {index}"),
                &format!(
                    r#"{{"name":"Deal {index}","stage":"discovery","lost_reason":"{reason}"{extra}}}"#
                ),
                now,
            );
        }
        let report = record.report().unwrap();
        let list = report
            .findings
            .iter()
            .find(|finding| finding.id == "text-that-is-a-list")
            .unwrap();
        assert_eq!(list.magnitude, 1);
        assert_eq!(
            list.evidence[0],
            "deal.lost_reason 3 distinct values over 1,200 rows"
        );
        let dead = report
            .findings
            .iter()
            .find(|finding| finding.id == "dead-field")
            .unwrap();
        assert_eq!(dead.magnitude, 1);
        assert_eq!(dead.evidence[0], "deal.competitor 1 of 1,200 rows");
        // The stage is the kind's state and never a list finding, and no row is stale.
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.id != "stale-value"));
    }
}
