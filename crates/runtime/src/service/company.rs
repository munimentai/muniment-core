//! Company service operations over the record's companies root.

use muniment_core::attach::ProtocolError;
use muniment_core::record::{CompaniesRoot, CompanyError, CompanySummary};
use std::path::Path;

fn protocol_error(error: CompanyError) -> ProtocolError {
    match error {
        CompanyError::InvalidName(_) | CompanyError::UnknownCompany(_) => {
            ProtocolError::invalid_request_with_reason(error.to_string())
        }
        other => ProtocolError::persistence_failed_with_reason(other.to_string()),
    }
}

/// Lists every company under the state root, oldest first, current marked.
pub fn list_companies(
    state_directory: impl AsRef<Path>,
) -> Result<Vec<CompanySummary>, ProtocolError> {
    CompaniesRoot::new(state_directory)
        .list()
        .map_err(protocol_error)
}

/// Creates one company with its graph and owner principal.
pub fn create_company(
    state_directory: impl AsRef<Path>,
    name: &str,
) -> Result<CompanySummary, ProtocolError> {
    CompaniesRoot::new(state_directory)
        .create(name)
        .map_err(protocol_error)
}

/// Makes one company current.
pub fn select_company(
    state_directory: impl AsRef<Path>,
    company_id: &str,
) -> Result<CompanySummary, ProtocolError> {
    CompaniesRoot::new(state_directory)
        .select(company_id)
        .map_err(protocol_error)
}

/// Deletes one company with its graph. The caller closes the open record
/// first, so no handle holds the files.
pub fn delete_company(
    state_directory: impl AsRef<Path>,
    company_id: &str,
) -> Result<CompanySummary, ProtocolError> {
    CompaniesRoot::new(state_directory)
        .delete(company_id)
        .map_err(protocol_error)
}

/// Renames one company.
pub fn rename_company(
    state_directory: impl AsRef<Path>,
    company_id: &str,
    name: &str,
) -> Result<CompanySummary, ProtocolError> {
    CompaniesRoot::new(state_directory)
        .rename(company_id, name)
        .map_err(protocol_error)
}
