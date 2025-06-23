use std::fmt;
use std::sync::PoisonError;
use serde::de::StdError;
use thiserror::Error;

pub type NyxResult<T, E = NyxError> = Result<T, E>;

#[derive(Debug, Error)]
pub enum NyxError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),

  #[error("SQLite error: {0}")]
  Sql(#[from] rusqlite::Error),

  #[error("tree-sitter error: {0}")]
  TreeSitter(#[from] tree_sitter::LanguageError),

  #[error("connection-pool error: {0}")]
  Pool(#[from] r2d2::Error),

  #[error("time error: {0}")]
  Time(#[from] std::time::SystemTimeError),

  #[error("poisoned lock: {0}")]
  Poison(String),
  
  #[error(transparent)]
  Other(#[from] Box<dyn StdError + Send + Sync + 'static>),
  
  #[error("{0}")]
  Msg(String),
}

impl<T> From<PoisonError<T>> for NyxError
where
  T: fmt::Debug,
{
  fn from(err: PoisonError<T>) -> Self {
    NyxError::Poison(err.to_string())
  }
}

impl From<&str> for NyxError {
  fn from(s: &str) -> Self {
    NyxError::Msg(s.to_owned())
  }
}

impl From<String> for NyxError {
  fn from(s: String) -> Self {
    NyxError::Msg(s)
  }
}

impl From<Box<dyn std::error::Error>> for NyxError {
  fn from(err: Box<dyn std::error::Error>) -> Self {
    NyxError::Msg(err.to_string())
  }
}
