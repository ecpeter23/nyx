pub mod index {
  use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
  use std::fs;
  use std::path::{Path, PathBuf};
  use std::str::FromStr;
  use std::time::{SystemTime, UNIX_EPOCH};
  use crate::commands::scan::Diag;
  use crate::patterns::Severity;
  use r2d2_sqlite::{SqliteConnectionManager};
  use std::ops::Deref;
  use std::sync::Arc;
  use r2d2::{Pool, PooledConnection};

  /// DB schema (foreign‑keys enabled).
  const SCHEMA: &str = r#"
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS files (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            project    TEXT    NOT NULL,
            path       TEXT    NOT NULL,
            hash       BLOB    NOT NULL,
            mtime      INTEGER NOT NULL,
            scanned_at INTEGER NOT NULL,
            UNIQUE(project, path)
        );

        CREATE TABLE IF NOT EXISTS issues (
            file_id    INTEGER NOT NULL
                              REFERENCES files(id)
                              ON DELETE CASCADE,
            rule_id    TEXT    NOT NULL,
            severity   TEXT    NOT NULL,
            line       INTEGER NOT NULL,
            col        INTEGER NOT NULL,
            PRIMARY KEY (file_id, rule_id, line, col)
        );
    "#;

  /// A single issue row, ready for insertion.
  #[derive(Debug, Clone)]
  pub struct IssueRow<'a> {
    pub rule_id: &'a str,
    pub severity: &'a str,
    pub line: i64,
    pub col: i64,
  }

  pub struct Indexer {
    conn: PooledConnection<SqliteConnectionManager>,
    project: String,
  }

  impl Indexer {

    pub fn init(
      database_path: &Path,
    ) -> Result<std::sync::Arc<Pool<SqliteConnectionManager>>, Box<dyn std::error::Error>> {
      let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
      let manager         = SqliteConnectionManager::file(&database_path).with_flags(flags);
      let pool  = Arc::new(Pool::new(manager)?);

      {
        let conn = pool.get()?;
        conn.pragma_update(None, "journal_mode", &"WAL")?;
        conn.execute_batch(SCHEMA)?;
      }
      Ok(pool)
    }

    pub fn from_pool(
      project: &str,
      pool: &Pool<SqliteConnectionManager>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
      let conn = pool.get()?;
      Ok(Self { conn, project: project.to_owned() })
    }

    // helper so code below can treat PooledConnection like &Connection
    fn c(&self) -> &Connection { self.conn.deref() }

    /// Open (or create) the DB at `database_path` for the given project name.
    // pub fn new(project: &str, database_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
    //   let conn = Connection::open(database_path)?;
    //   conn.pragma_update(None, "journal_mode", &"WAL")?;
    //   conn.execute_batch(SCHEMA)?;
    //   Ok(Self { conn, project: project.to_owned() })
    // }

    /// Return true when the file *content* or *mtime* changed since the last scan.
    pub fn should_scan(&self, path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
      let meta = fs::metadata(path)?;
      let mtime = meta.modified()?.duration_since(UNIX_EPOCH)?.as_secs() as i64;
      let digest = Self::digest_file(path)?;

      let row: Option<(Vec<u8>, i64)> = self
          .conn
          .query_row(
            "SELECT hash, mtime FROM files WHERE project = ?1 AND path = ?2",
            params![self.project, path.to_string_lossy()],
            |r| Ok((r.get(0)?, r.get(1)?)),
          )
          .optional()?;

      Ok(match row {
        Some((stored_hash, stored_mtime)) => stored_hash != digest || stored_mtime != mtime,
        None => true,
      })
    }

    /// Insert or update the `files` row and return its id.
    pub fn upsert_file(&self, path: &Path) -> Result<i64, Box<dyn std::error::Error>> {
      let meta = fs::metadata(path)?;
      let mtime = meta.modified()?.duration_since(UNIX_EPOCH)?.as_secs() as i64;
      let scanned_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
      let digest = Self::digest_file(path)?;

      self.c().execute(
        "INSERT INTO files (project, path, hash, mtime, scanned_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(project,path) DO UPDATE
                 SET hash = excluded.hash,
                     mtime = excluded.mtime,
                     scanned_at = excluded.scanned_at",
        params![self.project, path.to_string_lossy(), digest, mtime, scanned_at],
      )?;

      let id: i64 = self.c().query_row(
        "SELECT id FROM files WHERE project = ?1 AND path = ?2",
        params![self.project, path.to_string_lossy()],
        |r| r.get(0),
      )?;
      Ok(id)
    }

    /// Replace all issues for `file_id` with the supplied set.
    pub fn replace_issues<'a>(&mut self, file_id: i64, issues: impl IntoIterator<Item = IssueRow<'a>>)
                              -> Result<(), Box<dyn std::error::Error>> {
      let tx = self.conn.transaction()?;
      tx.execute("DELETE FROM issues WHERE file_id = ?", params![file_id])?;

      {
        let mut stmt = tx.prepare(
          "INSERT INTO issues (file_id, rule_id, severity, line, col)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for iss in issues {
          stmt.execute(params![file_id, iss.rule_id, iss.severity, iss.line, iss.col])?;
        }
      }
      tx.commit()?;
      Ok(())
    }

    /// Gets the issues for a specific file so we don't have to rescan
    pub fn get_issues_from_file(
      &self,
      path: &Path,
    ) -> Result<Vec<Diag>, Box<dyn std::error::Error>> {
      let file_id: i64 = self.c().query_row(
        "SELECT id FROM files WHERE project = ?1 AND path = ?2",
        params![self.project, path.to_string_lossy()],
        |r| r.get(0),
      )?;
      
      let mut stmt = self.c().prepare(
        "SELECT rule_id, severity, line, col
         FROM issues
         WHERE file_id = ?1",
      )?;

      let issue_iter = stmt.query_map([file_id], |row| {
        let sev_str: String = row.get(1)?;
        Ok(Diag {
          path:        path.to_string_lossy().to_string(),                     
          id:          row.get::<_, String>(0)?,                // rule_id
          line:        row.get::<_, i64>(2)? as usize,
          col:         row.get::<_, i64>(3)? as usize,
          severity:    Severity::from_str(&sev_str).unwrap(),
        })
      })?;

      Ok(issue_iter.filter_map(Result::ok).collect())
    }
    
    /// gets files from the database
    pub fn get_files(&self, project: &str) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
      let mut stmt = self.c().prepare(
        "SELECT path
         FROM files
         WHERE project = ?1",
      )?;

      let file_iter = stmt.query_map([project], |row| row.get::<_, String>(0))?;
      
      Ok(file_iter.map(|p| p.map(PathBuf::from)).collect::<Result<_, _>>()?)
    }

    /// Clears the tables to prep for a reindex
    pub fn clear(&self) -> rusqlite::Result<()> {
      self.c().execute_batch(
        r#"
        PRAGMA foreign_keys = OFF;

        DROP TABLE IF EXISTS issues;
        DROP TABLE IF EXISTS files;

        PRAGMA foreign_keys = ON;
        VACUUM;
        "#,
      )?;
      
      self.c().execute_batch(SCHEMA)?;
      Ok(())
    }

    fn digest_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
      let mut hasher = blake3::Hasher::new();
      let mut file = fs::File::open(path)?;
      std::io::copy(&mut file, &mut hasher)?;
      Ok(hasher.finalize().as_bytes().to_vec())
    }
  }
}
