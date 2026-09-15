//! The companies a machine holds: one directory each under
//! `<state>/companies/<id>/`, with the graph, a name and the SQL audit file.
//! The runtime holds one current company.

use super::{CompanyRecord, PrincipalType, RecordError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const COMPANIES_DIRECTORY_NAME: &str = "companies";
pub const GRAPH_FILE_NAME: &str = "graph.sqlite3";
pub const COMPANY_FILE_NAME: &str = "company.json";
pub const SQL_AUDIT_FILE_NAME: &str = "sql-audit.sqlite3";
const CURRENT_FILE_NAME: &str = "current";
const MAX_NAME_LENGTH: usize = 120;
/// The label of the one human principal a company starts with.
pub const OWNER_LABEL: &str = "owner";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanySummary {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub owner_principal_id: String,
    pub current: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CompanyFile {
    id: String,
    name: String,
    created_at: String,
    owner_principal_id: String,
}

#[derive(Debug)]
pub enum CompanyError {
    Io(io::Error),
    Json(serde_json::Error),
    Record(RecordError),
    InvalidName(String),
    UnknownCompany(String),
}

impl fmt::Display for CompanyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "company files failed: {error}"),
            Self::Json(error) => write!(formatter, "company record failed to parse: {error}"),
            Self::Record(error) => write!(formatter, "{error}"),
            Self::InvalidName(reason) => write!(formatter, "company name {reason}"),
            Self::UnknownCompany(id) => write!(formatter, "no company has id {id}"),
        }
    }
}

impl std::error::Error for CompanyError {}

impl From<io::Error> for CompanyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for CompanyError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<RecordError> for CompanyError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

/// `<state>/companies`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompaniesRoot {
    directory: PathBuf,
}

impl CompaniesRoot {
    pub fn new(state_directory: impl AsRef<Path>) -> Self {
        Self {
            directory: state_directory.as_ref().join(COMPANIES_DIRECTORY_NAME),
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn company_directory(&self, id: &str) -> PathBuf {
        self.directory.join(id)
    }

    pub fn graph_path(&self, id: &str) -> PathBuf {
        self.company_directory(id).join(GRAPH_FILE_NAME)
    }

    pub fn sql_audit_path(&self, id: &str) -> PathBuf {
        self.company_directory(id).join(SQL_AUDIT_FILE_NAME)
    }

    /// Every company, oldest first, with the current one marked.
    pub fn list(&self) -> Result<Vec<CompanySummary>, CompanyError> {
        let current = self.current()?;
        let mut companies = Vec::new();
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(companies),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Some(file) = self.read_company_file(&entry.path())? else {
                continue;
            };
            companies.push(CompanySummary {
                current: current.as_deref() == Some(file.id.as_str()),
                id: file.id,
                name: file.name,
                created_at: file.created_at,
                owner_principal_id: file.owner_principal_id,
            });
        }
        companies.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(companies)
    }

    /// The current company id, when one is selected and still exists.
    pub fn current(&self) -> Result<Option<String>, CompanyError> {
        match fs::read_to_string(self.directory.join(CURRENT_FILE_NAME)) {
            Ok(text) => {
                let id = text.trim().to_owned();
                if !id.is_empty()
                    && self
                        .company_directory(&id)
                        .join(COMPANY_FILE_NAME)
                        .is_file()
                {
                    Ok(Some(id))
                } else {
                    Ok(None)
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Creates the directory, the graph with its catalogue, the owner's human
    /// principal and the name. The first company becomes current.
    pub fn create(&self, name: &str) -> Result<CompanySummary, CompanyError> {
        let name = validate_name(name)?;
        let id = uuid::Uuid::now_v7().to_string();
        let directory = self.company_directory(&id);
        fs::create_dir_all(&directory)?;
        let owner = {
            let mut record = CompanyRecord::open(self.graph_path(&id))?;
            record.create_principal(PrincipalType::Human, OWNER_LABEL, None)?
        };
        let file = CompanyFile {
            id: id.clone(),
            name,
            created_at: super::now_string(),
            owner_principal_id: owner.id,
        };
        self.write_company_file(&directory, &file)?;
        let current = match self.current()? {
            Some(current) => current == id,
            None => {
                self.write_current(&id)?;
                true
            }
        };
        Ok(CompanySummary {
            id: file.id,
            name: file.name,
            created_at: file.created_at,
            owner_principal_id: file.owner_principal_id,
            current,
        })
    }

    pub fn select(&self, id: &str) -> Result<CompanySummary, CompanyError> {
        let file = self.require_company(id)?;
        self.write_current(id)?;
        Ok(CompanySummary {
            id: file.id,
            name: file.name,
            created_at: file.created_at,
            owner_principal_id: file.owner_principal_id,
            current: true,
        })
    }

    pub fn rename(&self, id: &str, name: &str) -> Result<CompanySummary, CompanyError> {
        let name = validate_name(name)?;
        let mut file = self.require_company(id)?;
        file.name = name;
        self.write_company_file(&self.company_directory(id), &file)?;
        let current = self.current()?.as_deref() == Some(id);
        Ok(CompanySummary {
            id: file.id,
            name: file.name,
            created_at: file.created_at,
            owner_principal_id: file.owner_principal_id,
            current,
        })
    }

    /// Opens one company's graph.
    pub fn open(&self, id: &str) -> Result<CompanyRecord, CompanyError> {
        self.require_company(id)?;
        Ok(CompanyRecord::open(self.graph_path(id))?)
    }

    fn require_company(&self, id: &str) -> Result<CompanyFile, CompanyError> {
        if uuid::Uuid::parse_str(id).is_err() {
            return Err(CompanyError::UnknownCompany(id.to_owned()));
        }
        self.read_company_file(&self.company_directory(id))?
            .filter(|file| file.id == id)
            .ok_or_else(|| CompanyError::UnknownCompany(id.to_owned()))
    }

    fn read_company_file(&self, directory: &Path) -> Result<Option<CompanyFile>, CompanyError> {
        match fs::read_to_string(directory.join(COMPANY_FILE_NAME)) {
            Ok(text) => Ok(Some(serde_json::from_str(&text)?)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn write_company_file(&self, directory: &Path, file: &CompanyFile) -> Result<(), CompanyError> {
        let text = serde_json::to_string_pretty(file)?;
        write_atomically(&directory.join(COMPANY_FILE_NAME), text.as_bytes())?;
        Ok(())
    }

    fn write_current(&self, id: &str) -> Result<(), CompanyError> {
        fs::create_dir_all(&self.directory)?;
        write_atomically(&self.directory.join(CURRENT_FILE_NAME), id.as_bytes())?;
        Ok(())
    }
}

fn write_atomically(destination: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = destination.with_extension(format!("tmp-{}", uuid::Uuid::now_v7()));
    fs::write(&temporary, bytes)?;
    let replaced = crate::atomic_file::replace(&temporary, destination);
    if replaced.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    replaced
}

fn validate_name(name: &str) -> Result<String, CompanyError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CompanyError::InvalidName("is empty".to_owned()));
    }
    if name.chars().count() > MAX_NAME_LENGTH {
        return Err(CompanyError::InvalidName(format!(
            "is over {MAX_NAME_LENGTH} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(CompanyError::InvalidName(
            "carries a control character".to_owned(),
        ));
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_state(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "muniment-companies-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn creates_lists_selects_and_renames_companies() {
        let state = temporary_state("lifecycle");
        let root = CompaniesRoot::new(&state);
        assert!(root.list().unwrap().is_empty());
        assert_eq!(root.current().unwrap(), None);

        let first = root.create("  Northwind Traders ").unwrap();
        assert_eq!(first.name, "Northwind Traders");
        assert!(first.current);
        assert!(root.graph_path(&first.id).is_file());
        assert!(root
            .company_directory(&first.id)
            .join(COMPANY_FILE_NAME)
            .is_file());
        assert_eq!(root.current().unwrap().as_deref(), Some(first.id.as_str()));

        let second = root.create("Surfoff").unwrap();
        assert!(!second.current);
        let listed = root.list().unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|company| company.name.as_str())
                .collect::<Vec<_>>(),
            ["Northwind Traders", "Surfoff"]
        );
        assert_eq!(listed.iter().filter(|company| company.current).count(), 1);

        let selected = root.select(&second.id).unwrap();
        assert!(selected.current);
        assert_eq!(root.current().unwrap().as_deref(), Some(second.id.as_str()));
        assert!(!root.list().unwrap()[0].current);

        let renamed = root.rename(&first.id, "Northwind").unwrap();
        assert_eq!(renamed.name, "Northwind");
        assert!(!renamed.current);
        assert_eq!(root.list().unwrap()[0].name, "Northwind");

        let record = root.open(&first.id).unwrap();
        let owner = record
            .principal(&first.owner_principal_id)
            .unwrap()
            .unwrap();
        assert_eq!(owner.principal_type, PrincipalType::Human);
        assert_eq!(owner.label, OWNER_LABEL);
        assert_eq!(record.kinds().unwrap().len(), 20);
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn refuses_bad_names_and_unknown_ids() {
        let state = temporary_state("invalid");
        let root = CompaniesRoot::new(&state);
        assert!(matches!(
            root.create("   "),
            Err(CompanyError::InvalidName(_))
        ));
        assert!(matches!(
            root.create(&"n".repeat(121)),
            Err(CompanyError::InvalidName(_))
        ));
        assert!(matches!(
            root.create("bad\u{7}name"),
            Err(CompanyError::InvalidName(_))
        ));
        assert!(matches!(
            root.select("not-a-uuid"),
            Err(CompanyError::UnknownCompany(_))
        ));
        let missing = uuid::Uuid::now_v7().to_string();
        assert!(matches!(
            root.rename(&missing, "x"),
            Err(CompanyError::UnknownCompany(_))
        ));
        assert!(matches!(
            root.open(&missing),
            Err(CompanyError::UnknownCompany(_))
        ));
        assert!(root.list().unwrap().is_empty());
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn a_current_pointer_at_a_missing_company_reads_as_none() {
        let state = temporary_state("pointer");
        let root = CompaniesRoot::new(&state);
        fs::create_dir_all(root.directory()).unwrap();
        fs::write(root.directory().join(CURRENT_FILE_NAME), "gone").unwrap();
        assert_eq!(root.current().unwrap(), None);
        let created = root.create("Fresh").unwrap();
        assert!(created.current);
        fs::remove_dir_all(state).unwrap();
    }
}
