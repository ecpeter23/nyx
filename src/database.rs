pub mod index {
    use crate::commands::scan::Diag;
    use crate::errors::NyxResult;
    use crate::patterns::Severity;
    use r2d2::{Pool, PooledConnection};
    use r2d2_sqlite::SqliteConnectionManager;
    use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
    use std::fs;
    use std::ops::Deref;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

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

        CREATE TABLE IF NOT EXISTS function_summaries (
            hash        TEXT PRIMARY KEY,
            project     TEXT NOT NULL,
            name        TEXT NOT NULL,
            lang        TEXT NOT NULL,
            summary     TEXT NOT NULL,
            updated_at  INTEGER NOT NULL,
        );
    "#;

    // TODO: ADD CLEANS FOR EACH TABLE BASED ON PROJECT WHICH RUNS ON CLEAN
    // TODO: ADD DROP AND GIVE A CLI PARAMETER FOR DROP

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
        pub fn init(database_path: &Path) -> NyxResult<Arc<Pool<SqliteConnectionManager>>> {
            let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
            let manager = SqliteConnectionManager::file(database_path).with_flags(flags);
            let pool = Arc::new(Pool::new(manager)?);

            {
                let conn = pool.get()?;
                conn.pragma_update(None, "journal_mode", "WAL")?;
                conn.execute_batch(SCHEMA)?;
            }
            Ok(pool)
        }

        pub fn from_pool(project: &str, pool: &Pool<SqliteConnectionManager>) -> NyxResult<Self> {
            let conn = pool.get()?;
            Ok(Self {
                conn,
                project: project.to_owned(),
            })
        }

        // helper so code below can treat PooledConnection like &Connection
        fn c(&self) -> &Connection {
            self.conn.deref()
        }

        /// Return true when the file *content* or *mtime* changed since the last scan.
        pub fn should_scan(&self, path: &Path) -> NyxResult<bool> {
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
        pub fn upsert_file(&self, path: &Path) -> NyxResult<i64> {
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
                params![
                    self.project,
                    path.to_string_lossy(),
                    digest,
                    mtime,
                    scanned_at
                ],
            )?;

            let id: i64 = self.c().query_row(
                "SELECT id FROM files WHERE project = ?1 AND path = ?2",
                params![self.project, path.to_string_lossy()],
                |r| r.get(0),
            )?;
            Ok(id)
        }

        /// Replace all issues for `file_id` with the supplied set.
        pub fn replace_issues<'a>(
            &mut self,
            file_id: i64,
            issues: impl IntoIterator<Item = IssueRow<'a>>,
        ) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            tx.execute("DELETE FROM issues WHERE file_id = ?", params![file_id])?;

            {
                let mut stmt = tx.prepare(
                    "INSERT INTO issues (file_id, rule_id, severity, line, col)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )?;
                for iss in issues {
                    stmt.execute(params![
                        file_id,
                        iss.rule_id,
                        iss.severity,
                        iss.line,
                        iss.col
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        }

        /// Gets the issues for a specific file so we don't have to rescan
        pub fn get_issues_from_file(&self, path: &Path) -> NyxResult<Vec<Diag>> {
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
                    path: path.to_string_lossy().to_string(),
                    id: row.get::<_, String>(0)?, // rule_id
                    line: row.get::<_, i64>(2)? as usize,
                    col: row.get::<_, i64>(3)? as usize,
                    severity: Severity::from_str(&sev_str).unwrap(),
                })
            })?;

            Ok(issue_iter.filter_map(Result::ok).collect())
        }

        pub fn upsert_summary(
            &mut self,
            project: &str,
            path: &Path,
            hash: &str,
            s: &crate::summary::FuncSummary,
        ) -> NyxResult<()> {
            let conn = self.c();
            let now  = chrono::Utc::now().timestamp_millis(); // i64

            conn.execute(
                "INSERT INTO function_summaries (hash, project, name, lang, summary, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(hash) DO UPDATE SET summary = excluded.summary,
                                                     updated_at = excluded.updated_at",
                (
                    hash,
                    project,
                    &s.name,
                    path.extension().and_then(|e| e.to_str()).unwrap_or_default(),
                    serde_json::to_string(s).unwrap(), //TODO REPLACE UNWRAP
                    now,
                ),
            )?;
            Ok(())
        }

        pub fn load_all_summaries(&self, project: &str) -> NyxResult<Vec<crate::summary::FuncSummary<'static>>> {
            let mut stmt = self
                .c()
                .prepare("SELECT summary FROM function_summaries WHERE project = ?1")?;

            let iter = stmt.query_map([project], |row| {
                let json: String = row.get(0)?;
                Ok(serde_json::from_str::<crate::summary::FuncSummary>(json.as_str()).unwrap()) // TODO: REPLACE UNWRAP
            })?;
            
            Ok(iter
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|s| unsafe { std::mem::transmute::<_, crate::summary::FuncSummary<'static>>(s) })
                .collect())
        }

        /// gets files from the database
        pub fn get_files(&self, project: &str) -> NyxResult<Vec<PathBuf>> {
            let mut stmt = self.c().prepare(
                "SELECT path
         FROM files
         WHERE project = ?1",
            )?;

            let file_iter = stmt.query_map([project], |row| row.get::<_, String>(0))?;

            Ok(file_iter
                .map(|p| p.map(PathBuf::from))
                .collect::<Result<_, _>>()?)
        }

        // -------------------------------------------------------------------------
        // Maintenance utilities
        // -------------------------------------------------------------------------
        pub fn clear(&self) -> NyxResult<()> {
            self.c().execute_batch(
                r#"
        PRAGMA foreign_keys = OFF;

        DROP TABLE IF EXISTS issues;
        DROP TABLE IF EXISTS files;
        DROP TABLE IF EXISTS function_summaries;

        PRAGMA foreign_keys = ON;
        VACUUM;
        "#,
            )?;

            self.c().execute_batch(SCHEMA)?;
            Ok(())
        }

        pub fn vacuum(&self) -> NyxResult<()> {
            self.c().execute("VACUUM;", [])?;
            Ok(())
        }

        // -------------------------------------------------------------------------
        // Helpers
        // -------------------------------------------------------------------------
        fn digest_file(path: &Path) -> NyxResult<Vec<u8>> {
            let mut hasher = blake3::Hasher::new();
            let mut file = fs::File::open(path)?;
            std::io::copy(&mut file, &mut hasher)?;
            Ok(hasher.finalize().as_bytes().to_vec())
        }
    }
}

#[test]
fn indexer_should_scan_and_upsert_logic() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let file = td.path().join("sample.rs");
    std::fs::write(&file, "fn main() {}").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let idx = index::Indexer::from_pool("proj", &pool).unwrap();

    // first time: nothing in DB → must scan
    assert!(idx.should_scan(&file).unwrap());

    // after upsert: no changes → should *not* scan
    idx.upsert_file(&file).unwrap();
    assert!(!idx.should_scan(&file).unwrap());

    // modify contents
    std::thread::sleep(std::time::Duration::from_millis(25)); // ensure mtime tick
    std::fs::write(&file, "fn main() { /* changed */ }").unwrap();
    assert!(idx.should_scan(&file).unwrap());
}

#[test]
fn replace_issues_and_query_back() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let file = td.path().join("code.go");
    std::fs::write(&file, "package main").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let fid = idx.upsert_file(&file).unwrap();

    let issues = [
        index::IssueRow {
            rule_id: "X1",
            severity: "High",
            line: 3,
            col: 7,
        },
        index::IssueRow {
            rule_id: "X2",
            severity: "Low",
            line: 4,
            col: 1,
        },
    ];
    idx.replace_issues(fid, issues.clone()).unwrap();

    let stored = idx.get_issues_from_file(&file).unwrap();
    assert_eq!(stored.len(), 2);
    assert!(
        stored
            .iter()
            .any(|d| d.id == "X1" && d.severity == crate::patterns::Severity::High)
    );
    assert!(
        stored
            .iter()
            .any(|d| d.id == "X2" && d.severity == crate::patterns::Severity::Low)
    );
}

#[test]
fn clear_and_vacuum_reset_tables() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("f.rs");
    std::fs::write(&f, "//").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let idx = index::Indexer::from_pool("proj", &pool).unwrap();
    idx.upsert_file(&f).unwrap();

    assert!(!idx.get_files("proj").unwrap().is_empty());
    idx.clear().unwrap();
    idx.vacuum().unwrap();
    assert!(idx.get_files("proj").unwrap().is_empty());
}
