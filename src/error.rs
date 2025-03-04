//! Error handling by this library

use thiserror::Error;

/// Error type for the library
#[derive(Debug, Error)]
pub enum Error {
    /// Error when the library is unable to obtain a sync lock
    #[error("Sync Point error: `{0}`")]
    SyncPoison(String),
    /// Error when the library is unable to derive a value from a repr
    #[error("Derive More Try From Repr error: `{0}`")]
    DeriveMoreTryFromRepr(String),
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        Error::SyncPoison(e.to_string())
    }
}

impl<T> From<derive_more::TryFromReprError<T>> for Error
where
    T: std::fmt::Debug,
{
    fn from(e: derive_more::TryFromReprError<T>) -> Self {
        Error::DeriveMoreTryFromRepr(e.to_string())
    }
}

/// Results returned by the library
pub type Result<T> = std::result::Result<T, Error>;
