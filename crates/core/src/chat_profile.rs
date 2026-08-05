use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use crate::cas::{CasError, LocalCas};
use crate::journal::{JournalError, RunJournal};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatProfile {
    directory: PathBuf,
}

impl ChatProfile {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn journal_path(&self) -> PathBuf {
        self.directory.join("runs.sqlite3")
    }

    pub fn cas_directory(&self) -> PathBuf {
        self.directory.join("cas")
    }

    pub fn pi_session_root(&self) -> PathBuf {
        self.directory.join("pi-sessions")
    }

    pub fn create_directories(&self) -> Result<(), ChatProfileError> {
        std::fs::create_dir_all(&self.directory).map_err(ChatProfileError::ProfileDirectory)?;
        std::fs::create_dir_all(self.pi_session_root()).map_err(ChatProfileError::PiSessionRoot)?;
        Ok(())
    }

    pub fn open_storage(&self) -> Result<(RunJournal, LocalCas), ChatProfileError> {
        self.create_directories()?;
        let journal =
            RunJournal::open(self.journal_path()).map_err(ChatProfileError::JournalOpen)?;
        let cas = LocalCas::open(&self.cas_directory()).map_err(ChatProfileError::CasOpen)?;
        Ok((journal, cas))
    }
}

#[derive(Debug)]
pub enum ChatProfileError {
    ProfileDirectory(std::io::Error),
    PiSessionRoot(std::io::Error),
    JournalOpen(JournalError),
    CasOpen(CasError),
}

impl fmt::Display for ChatProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileDirectory(_) => formatter.write_str("could not create the chat profile"),
            Self::PiSessionRoot(_) => formatter.write_str("could not create the Pi session root"),
            Self::JournalOpen(_) => formatter.write_str("could not open the run journal"),
            Self::CasOpen(_) => formatter.write_str("could not open the local CAS"),
        }
    }
}

impl Error for ChatProfileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ProfileDirectory(error) | Self::PiSessionRoot(error) => Some(error),
            Self::JournalOpen(error) => Some(error),
            Self::CasOpen(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_chat_storage_paths() {
        let profile = ChatProfile::new(std::path::Path::new("profile"));

        assert_eq!(
            profile.journal_path(),
            std::path::Path::new("profile/runs.sqlite3")
        );
        assert_eq!(profile.cas_directory(), std::path::Path::new("profile/cas"));
        assert_eq!(
            profile.pi_session_root(),
            std::path::Path::new("profile/pi-sessions")
        );
    }

    #[test]
    fn creates_profile_and_pi_session_directories() {
        let parent =
            std::env::temp_dir().join(format!("muniment-chat-profile-{}", uuid::Uuid::new_v4()));
        let directory = parent.join("profile");
        let profile = ChatProfile::new(&directory);

        profile.create_directories().unwrap();

        assert!(directory.is_dir());
        assert!(profile.pi_session_root().is_dir());
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn identifies_a_pi_session_root_creation_error() {
        let directory = std::env::temp_dir().join(format!(
            "muniment-chat-profile-error-{}",
            uuid::Uuid::new_v4()
        ));
        let profile = ChatProfile::new(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(profile.pi_session_root(), b"not a directory").unwrap();

        assert!(matches!(
            profile.create_directories(),
            Err(ChatProfileError::PiSessionRoot(_))
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn opens_the_journal_and_cas() {
        let directory = std::env::temp_dir().join(format!(
            "muniment-chat-profile-storage-{}",
            uuid::Uuid::new_v4()
        ));
        let profile = ChatProfile::new(&directory);

        let (_journal, _cas) = profile.open_storage().unwrap();

        assert!(profile.journal_path().is_file());
        assert!(profile.cas_directory().join("objects").is_dir());
        assert!(profile.pi_session_root().is_dir());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn identifies_a_journal_open_error() {
        let directory = std::env::temp_dir().join(format!(
            "muniment-chat-profile-journal-error-{}",
            uuid::Uuid::new_v4()
        ));
        let profile = ChatProfile::new(&directory);
        std::fs::create_dir_all(profile.journal_path()).unwrap();

        assert!(matches!(
            profile.open_storage(),
            Err(ChatProfileError::JournalOpen(_))
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn identifies_a_cas_open_error() {
        let directory = std::env::temp_dir().join(format!(
            "muniment-chat-profile-cas-error-{}",
            uuid::Uuid::new_v4()
        ));
        let profile = ChatProfile::new(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(profile.cas_directory(), b"not a directory").unwrap();

        assert!(matches!(
            profile.open_storage(),
            Err(ChatProfileError::CasOpen(_))
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
