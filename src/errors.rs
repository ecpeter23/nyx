use thiserror::Error;

pub type NyxResult<T, E = NyxError> = core::result::Result<T, E>;

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

  #[error("other: {0}")]
  Other(String),
}