//! The panel's reads: one kind's rows, paged and sorted, and one entity with
//! everything that touches it. Both read the live graph and write nothing.

use super::{CompanyRecord, EdgeRow, EntityRow, EventRow, IdentityRow, KindRow, RecordError};
use rusqlite::params;
use serde::{Deserialize, Serialize};

/// Rows one page holds at most.
pub const QUERY_LIMIT_CAP: usize = 500;
const QUERY_LIMIT_DEFAULT: usize = 100;
const BASE_SORT_COLUMNS: [&str; 4] = ["title", "state", "created_at", "updated_at"];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryOptions {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: usize,
    /// A base column, `title`, `state`, `created_at` or `updated_at`, or one
    /// property of the kind.
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub descending: bool,
    /// Keeps the rows whose `state` equals this value.
    #[serde(default)]
    pub state: Option<String>,
    /// Full-text search over title and prose.
    #[serde(default)]
    pub search: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryPage {
    pub kind: String,
    pub rows: Vec<EntityRow>,
    pub total: i64,
    pub offset: usize,
    pub limit: usize,
    pub sort: String,
    pub descending: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EdgeDetail {
    #[serde(flatten)]
    pub edge: EdgeRow,
    pub src_kind: String,
    pub src_title: String,
    pub dst_kind: String,
    pub dst_title: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntityDetail {
    pub entity: EntityRow,
    pub kind: KindRow,
    pub identities: Vec<IdentityRow>,
    pub edges: Vec<EdgeDetail>,
    pub events: Vec<EventRow>,
}

fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Each word as a quoted prefix token, so the start of a title finds it.
pub(super) fn search_query(text: &str) -> String {
    text.split_whitespace()
        .map(|word| format!("\"{}\"*", word.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

impl CompanyRecord {
    /// One page of a kind's live rows. An unknown sort column is an error the
    /// caller reads, never SQL the caller wrote.
    pub fn query(&self, kind: &str, options: &QueryOptions) -> Result<QueryPage, RecordError> {
        let kind_row = self.require_kind(kind)?;
        let limit = options
            .limit
            .unwrap_or(QUERY_LIMIT_DEFAULT)
            .clamp(1, QUERY_LIMIT_CAP);
        let sort = options.sort.as_deref().unwrap_or("updated_at");
        let order_expression = if BASE_SORT_COLUMNS.contains(&sort) {
            format!("\"{sort}\"")
        } else {
            let known = kind_row
                .schema
                .get("properties")
                .and_then(|properties| properties.get(sort))
                .is_some()
                || kind_row
                    .extension
                    .as_ref()
                    .and_then(|extension| extension.get("properties"))
                    .and_then(|properties| properties.get(sort))
                    .is_some();
            if !known || !identifier(sort) {
                return Err(RecordError::Validation(
                    super::ValidationError::UnknownProperty(sort.to_owned()),
                ));
            }
            format!("json_extract(data, '$.{sort}')")
        };
        let direction = if options.descending { "desc" } else { "asc" };
        let mut clauses = vec!["kind = ?1".to_owned(), "deleted_at is null".to_owned()];
        let mut values: Vec<rusqlite::types::Value> = vec![kind.to_owned().into()];
        if let Some(state) = options.state.as_deref().filter(|state| !state.is_empty()) {
            values.push(state.to_owned().into());
            clauses.push(format!("state = ?{}", values.len()));
        }
        if let Some(search) = options
            .search
            .as_deref()
            .map(search_query)
            .filter(|query| !query.is_empty())
        {
            values.push(search.into());
            clauses.push(format!(
                "id in (select entity_id from entity_search where entity_search match ?{})",
                values.len()
            ));
        }
        let filter = clauses.join(" and ");
        let total: i64 = self.connection.query_row(
            &format!("select count(*) from entity where {filter}"),
            rusqlite::params_from_iter(values.iter()),
            |row| row.get(0),
        )?;
        let mut statement = self.connection.prepare(&format!(
            "select id from entity where {filter} order by {order_expression} {direction}, id limit {limit} offset {}",
            options.offset
        ))?;
        let ids = statement
            .query_map(rusqlite::params_from_iter(values.iter()), |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let rows = ids
            .iter()
            .filter_map(|id| self.entity(id).transpose())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(QueryPage {
            kind: kind.to_owned(),
            rows,
            total,
            offset: options.offset,
            limit,
            sort: sort.to_owned(),
            descending: options.descending,
        })
    }

    /// One entity with its kind, identities, edges and events.
    pub fn entity_detail(&self, id: &str) -> Result<Option<EntityDetail>, RecordError> {
        let Some(entity) = self.entity(id)? else {
            return Ok(None);
        };
        let kind = self.require_kind(&entity.kind)?;
        let identities = self.identities(id)?;
        let mut edges = Vec::new();
        for edge in self.edges(id)? {
            let (src_kind, src_title) = self.title_of(&edge.src_id)?;
            let (dst_kind, dst_title) = self.title_of(&edge.dst_id)?;
            edges.push(EdgeDetail {
                edge,
                src_kind,
                src_title,
                dst_kind,
                dst_title,
            });
        }
        let events = self.events(id)?;
        Ok(Some(EntityDetail {
            entity,
            kind,
            identities,
            edges,
            events,
        }))
    }

    fn title_of(&self, id: &str) -> Result<(String, String), RecordError> {
        Ok(self
            .connection
            .query_row(
                "select kind, title from entity where id = ?1",
                params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap_or_else(|_| (String::new(), id.to_owned())))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{IdentityInput, LinkInput, Operation, PrincipalType, Reference};
    use super::*;
    use serde_json::json;

    fn fixture(label: &str) -> (std::path::PathBuf, CompanyRecord, String) {
        let directory =
            std::env::temp_dir().join(format!("muniment-query-{label}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&directory).unwrap();
        let mut record = CompanyRecord::open(directory.join("graph.sqlite3")).unwrap();
        let human = record
            .create_principal(PrincipalType::Human, "owner", None)
            .unwrap()
            .id;
        (directory, record, human)
    }

    fn create(
        record: &mut CompanyRecord,
        human: &str,
        kind: &str,
        data: serde_json::Value,
    ) -> String {
        let proposal = record
            .propose(Operation::Create {
                kind: kind.into(),
                data: data.as_object().unwrap().clone(),
                identities: vec![],
                links: vec![],
            })
            .unwrap();
        record.commit(&proposal.id, human).unwrap().entity_ids[0].clone()
    }

    #[test]
    fn pages_sorts_filters_and_searches_one_kind() {
        let (directory, mut record, human) = fixture("pages");
        for (name, stage, amount) in [
            ("Northwind renewal", "won", 96000),
            ("Contoso pilot", "discovery", 12000),
            ("Fabrikam expansion", "negotiation", 50000),
        ] {
            create(
                &mut record,
                &human,
                "deal",
                json!({"name": name, "stage": stage, "expected_close": "2026-12-01", "amount": amount}),
            );
        }
        let page = record.query("deal", &QueryOptions::default()).unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(page.rows.len(), 3);
        assert_eq!(page.sort, "updated_at");
        assert_eq!(page.limit, 100);

        let by_amount = record
            .query(
                "deal",
                &QueryOptions {
                    sort: Some("amount".into()),
                    descending: true,
                    ..QueryOptions::default()
                },
            )
            .unwrap();
        assert_eq!(
            by_amount
                .rows
                .iter()
                .map(|row| row.title.as_str())
                .collect::<Vec<_>>(),
            ["Northwind renewal", "Fabrikam expansion", "Contoso pilot"]
        );

        let paged = record
            .query(
                "deal",
                &QueryOptions {
                    sort: Some("title".into()),
                    limit: Some(2),
                    offset: 1,
                    ..QueryOptions::default()
                },
            )
            .unwrap();
        assert_eq!(paged.total, 3);
        assert_eq!(
            paged
                .rows
                .iter()
                .map(|row| row.title.as_str())
                .collect::<Vec<_>>(),
            ["Fabrikam expansion", "Northwind renewal"]
        );

        let won = record
            .query(
                "deal",
                &QueryOptions {
                    state: Some("won".into()),
                    ..QueryOptions::default()
                },
            )
            .unwrap();
        assert_eq!(won.total, 1);
        assert_eq!(won.rows[0].title, "Northwind renewal");

        let searched = record
            .query(
                "deal",
                &QueryOptions {
                    search: Some("contoso".into()),
                    ..QueryOptions::default()
                },
            )
            .unwrap();
        assert_eq!(searched.rows.len(), 1);
        assert_eq!(searched.rows[0].title, "Contoso pilot");
        let prefixed = record
            .query(
                "deal",
                &QueryOptions {
                    search: Some("cont pil".into()),
                    ..QueryOptions::default()
                },
            )
            .unwrap();
        assert_eq!(prefixed.rows.len(), 1);
        assert_eq!(prefixed.rows[0].title, "Contoso pilot");

        assert!(matches!(
            record.query(
                "deal",
                &QueryOptions {
                    sort: Some("data; drop table entity".into()),
                    ..QueryOptions::default()
                }
            ),
            Err(RecordError::Validation(_))
        ));
        assert!(matches!(
            record.query("widget", &QueryOptions::default()),
            Err(RecordError::UnknownKind(_))
        ));
        assert!(record
            .query("person", &QueryOptions::default())
            .unwrap()
            .rows
            .is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn an_entity_detail_carries_its_kind_identities_edges_and_events() {
        let (directory, mut record, human) = fixture("detail");
        let org = record
            .propose(Operation::Create {
                kind: "org".into(),
                data: json!({"name": "Northwind"}).as_object().unwrap().clone(),
                identities: vec![IdentityInput {
                    kind: "domain".into(),
                    value: "northwind.example".into(),
                }],
                links: vec![],
            })
            .unwrap();
        let org_id = record.commit(&org.id, &human).unwrap().entity_ids[0].clone();
        let person = record
            .propose(Operation::Create {
                kind: "person".into(),
                data: json!({"full_name": "Elena Vasquez"})
                    .as_object()
                    .unwrap()
                    .clone(),
                identities: vec![],
                links: vec![LinkInput {
                    relation: "works_at".into(),
                    target: Reference::Entity(org_id.clone()),
                    props: Default::default(),
                }],
            })
            .unwrap();
        let person_id = record.commit(&person.id, &human).unwrap().entity_ids[0].clone();

        let detail = record.entity_detail(&org_id).unwrap().unwrap();
        assert_eq!(detail.entity.title, "Northwind");
        assert_eq!(detail.kind.name, "org");
        assert_eq!(detail.identities[0].value, "northwind.example");
        assert_eq!(detail.edges.len(), 1);
        assert_eq!(detail.edges[0].edge.relation, "works_at");
        assert_eq!(detail.edges[0].src_title, "Elena Vasquez");
        assert_eq!(detail.edges[0].src_kind, "person");
        assert_eq!(detail.edges[0].dst_title, "Northwind");
        assert_eq!(detail.events.len(), 1);
        assert_eq!(detail.events[0].verb, "created");
        assert_eq!(detail.events[0].actor_label.as_deref(), Some("owner"));
        assert!(record.entity_detail("missing").unwrap().is_none());
        let person_detail = record.entity_detail(&person_id).unwrap().unwrap();
        assert_eq!(person_detail.edges[0].dst_title, "Northwind");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
