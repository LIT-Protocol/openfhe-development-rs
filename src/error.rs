use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Sync Point error: `{0}`")]
    SyncPoisonError(String),
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        Error::SyncPoisonError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
