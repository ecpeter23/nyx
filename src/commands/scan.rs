use crate::utils::project::get_project_info;
use console::style;
use std::path::Path;
use std::sync::{Arc, Mutex};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use crate::database::index::{IssueRow, Indexer};
use crate::patterns::Severity;
use crate::utils::config::Config;
use crate::utils::query_cache;
use crate::walk::spawn_senders;
use rayon::prelude::*;

use tree_sitter::{Language, Parser, QueryCursor, StreamingIterator};

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub struct Diag {
    pub(crate) path: String,
    pub(crate) line: usize,
    pub(crate) col: usize,
    pub(crate) severity: Severity,
    pub(crate) id: String,
}

/// Entry point called by the CLI.
pub fn handle(
    path: &str,
    no_index: bool,
    rebuild_index: bool,
    format: String,
    high_only: bool,
    database_dir: &Path,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let scan_path = Path::new(path).canonicalize()?;
    let (project_name, db_path) = get_project_info(&scan_path, database_dir)?;
    let diags: Vec<Diag>;
    
    if no_index {
        diags = scan_filesystem(&scan_path, config).unwrap();
    } else {
        if rebuild_index || !db_path.exists() {
            tracing::debug!("Scanning filesystem index filesystem");
            crate::commands::index::build_index(&project_name,&scan_path, &db_path, config)?;
        }

        let pool = Indexer::init(&db_path)?;
        diags = scan_with_index_parallel(&project_name, pool, config)?;
    }

    if format == "console" || format == "" && config.output.default_format == "console" {
        for d in &diags {
            if high_only && d.severity != Severity::High {
                continue;
            }
            let sev_str = match d.severity {
                Severity::High => style("HIGH").red().bold(),
                Severity::Medium => style("MEDIUM").yellow().bold(),
                Severity::Low => style("LOW").cyan().bold(),
            };
            println!(
                "{}:{}:{}  [{}]  {}",
                style(d.path.clone()).blue().underlined(),
                d.line,
                d.col,
                sev_str,
                style(&d.id).bold(),
            );
        }
    }
    Ok(())
}

// --------------------------------------------------------------------------------------------
// Scanning helpers
// --------------------------------------------------------------------------------------------

fn scan_filesystem(
    root: &Path,
    cfg: &Config,
) ->Result<Vec<Diag>, Box<dyn std::error::Error + Send + Sync>> {
    let rx = spawn_senders(root, cfg);
    let acc = Mutex::new(Vec::new());

    rx.into_iter()
      .flatten()
      .par_bridge()                       // rayon hand-off
      .try_for_each(|path| {              // stable API
          let mut local = run_rules_on_file(&path, cfg).unwrap();   // <- same as before
          let mut guard = acc.lock().unwrap();
          guard.append(&mut local);
          Ok::<(), DynError>(())          // explicit error type
      })?;                                // propagate first error, if any

    Ok(acc.into_inner().unwrap())
}

fn scan_with_index_parallel(
    project: &str,
    pool: Arc<Pool<SqliteConnectionManager>>,
    cfg: &Config,
) -> Result<Vec<Diag>, Box<dyn std::error::Error>> {

    // Get the file list once (single connection, no contention)
    let files = {
        let idx = Indexer::from_pool(project, &pool)?;
        idx.get_files(project)?
    };

    let acc = Mutex::new(Vec::new());

    files.into_par_iter()
      .try_for_each(|path| -> Result<(), DynError> {
          let mut idx = Indexer::from_pool(project, &pool).unwrap();

          if idx.should_scan(&path).unwrap() {
              let mut diags = run_rules_on_file(&path, cfg).unwrap();
              let file_id   = idx.upsert_file(&path).unwrap();

              let rows: Vec<IssueRow> = diags.iter().map(|d| IssueRow {
                  rule_id: d.id.as_ref(),
                  severity: match d.severity {
                      Severity::High   => "HIGH",
                      Severity::Medium => "MEDIUM",
                      Severity::Low    => "LOW",
                  },
                  line: d.line as i64,
                  col:  d.col  as i64,
              }).collect();

              idx.replace_issues(file_id, rows).unwrap();
              acc.lock().unwrap().append(&mut diags);
          } else {
              let mut cached = idx.get_issues_from_file(&path).unwrap();
              acc.lock().unwrap().append(&mut cached);
          }
          Ok(())
      }).unwrap();

    {
        let idx = Indexer::from_pool(project, &pool)?;
        idx.vacuum()?;
    }

    Ok(acc.into_inner().unwrap())
}

// --------------------------------------------------------------------------------------------
// Tree‑sitter‑based rule runner – returns a Vec<Diag>
// --------------------------------------------------------------------------------------------
pub(crate) fn run_rules_on_file(
    path: &Path,
    cfg: &Config,
) -> Result<Vec<Diag>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;

    let mut parser = Parser::new();

    let lang_key = match path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "rs" => (Language::from(tree_sitter_rust::LANGUAGE), "rust"),
        "c" => (Language::from(tree_sitter_c::LANGUAGE), "c"),
        "cpp" | "c++" => (Language::from(tree_sitter_cpp::LANGUAGE), "cpp"),
        "java" => (Language::from(tree_sitter_java::LANGUAGE), "java"),
        "go" => (Language::from(tree_sitter_go::LANGUAGE), "go"),
        "php" => (Language::from(tree_sitter_php::LANGUAGE_PHP), "php"),
        "py" => (Language::from(tree_sitter_python::LANGUAGE), "python"),
        "ts" | "tsx" => (Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT), "typescript"),
        "js" => (Language::from(tree_sitter_javascript::LANGUAGE), "javascript"),
        _ => return Ok(Vec::new()),
    };
    let (ts_lang, lang_name) = lang_key;

    parser.set_language(&ts_lang)?;
    let tree = parser.parse(&*bytes, None).ok_or("tree‑sitter failed")?;
    let root = tree.root_node();

    let compiled = query_cache::for_lang(lang_name, ts_lang);
    let mut cursor = QueryCursor::new();
    let mut out = Vec::new();

    for cq in &compiled {
        if cfg.scanner.min_severity > cq.meta.severity {
            continue;
        }
        let mut matches = cursor.matches(&cq.query, root, &*bytes);
        while let Some(m) = matches.next() {
            for cap in m.captures.iter().filter(|c| c.index == 0) {
                let point = cap.node.start_position();
                out.push(Diag {
                    path: path.to_string_lossy().to_string(),
                    line: point.row + 1,
                    col: point.column + 1,
                    severity: cq.meta.severity,
                    id: String::from(cq.meta.id),
                });
            }
        }
    }
    Ok(out)
}