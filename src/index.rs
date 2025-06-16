pub mod index {
  use blake3::Hasher;
  use rusqlite::{params, Connection, OptionalExtension};
  use std::fs;
  use std::path::Path;
  use std::time::{SystemTime, UNIX_EPOCH};

  /// Schema: stores digest, file modification time (secs since epoch) and
  /// last time we *fully* scanned the file.
  const SCHEMA: &str = r#"
        CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            hash BLOB NOT NULL,
            mtime INTEGER NOT NULL,
            scanned_at INTEGER NOT NULL
        );"#;

  pub(crate) struct Indexer {
    conn: Connection,
  }

  impl Indexer {
    pub fn new(database_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
      let conn = Connection::open(database_path)?;
      conn.execute_batch(SCHEMA)?;
      Ok(Self { conn })
    }

    /// Returns `true` if the caller should analyze the file, i.e., we have
    /// never seen it or something changed (mtime or content hash).
    pub fn should_scan(&self, path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
      let meta = fs::metadata(path)?;
      let mtime = meta.modified()?.duration_since(UNIX_EPOCH)?.as_secs() as i64;

      let digest = Self::digest_file(path)?;

      let row: Option<(Vec<u8>, i64)> = self
        .conn
        .query_row(
          "SELECT hash, mtime FROM files WHERE path = ?1",
          params![path.to_string_lossy()],
          |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

      match row {
        Some((stored_hash, stored_mtime)) => {
          Ok(stored_hash != digest || stored_mtime != mtime)
        }
        None => Ok(true),
      }
    }

    /// Persist a fresh scan result.
    pub fn record_scan(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
      let meta = fs::metadata(path)?;
      let mtime = meta.modified()?.duration_since(UNIX_EPOCH)?.as_secs() as i64;
      let scanned_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() as i64;
      let digest = Self::digest_file(path)?;

      self.conn.execute(
        "REPLACE INTO files (path, hash, mtime, scanned_at) VALUES (?1, ?2, ?3, ?4)",
        params![path.to_string_lossy(), digest, mtime, scanned_at],
      )?;
      Ok(())
    }

    fn digest_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
      let mut hasher = Hasher::new();
      let mut file = fs::File::open(path)?;
      std::io::copy(&mut file, &mut hasher)?;
      Ok(hasher.finalize().as_bytes().to_vec())
    }
  }
}