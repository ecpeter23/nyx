pub(crate) use crate::ast::run_rules_on_file;
use crate::database::index::{Indexer, IssueRow};
use crate::errors::NyxResult;
use crate::patterns::Severity;
use crate::utils::config::Config;
use crate::utils::project::get_project_info;
use crate::walk::spawn_senders;
use console::style;
use dashmap::DashMap;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

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
    database_dir: &Path,
    config: &Config,
) -> NyxResult<()> {
    let scan_path = Path::new(path).canonicalize()?;
    let (project_name, db_path) = get_project_info(&scan_path, database_dir)?;

    println!(
        "{} {}...\n",
        style("Checking").green().bold(),
        &project_name
    );

    let diags: Vec<Diag> = if no_index {
        scan_filesystem(&scan_path, config)?
    } else {
        if rebuild_index || !db_path.exists() {
            tracing::debug!("Scanning filesystem index filesystem");
            crate::commands::index::build_index(&project_name, &scan_path, &db_path, config)?;
        }

        let pool = Indexer::init(&db_path)?;
        scan_with_index_parallel(&project_name, pool, config)?
    };

    tracing::debug!("Found {:?} issues.", diags.len());

    if format == "console" || (format.is_empty() && config.output.default_format == "console") {
        tracing::debug!("Printing to console");
        let mut grouped: BTreeMap<&str, Vec<&Diag>> = BTreeMap::new();
        for d in &diags {
            grouped.entry(&d.path).or_default().push(d);
        }

        for (path, issues) in &grouped {
            println!("{}", style(path).blue().underlined());
            for d in issues {
                println!(
                    "  {:>4}:{:<4}  [{}]  {}",
                    d.line,
                    d.col,
                    d.severity,
                    style(&d.id).bold()
                );
            }
            println!();
        }

        println!(
            "{} '{}' generated {} issues.",
            style("warning").yellow().bold(),
            style(project_name).white().bold(),
            style(diags.len()).bold()
        );
        println!("\t"); // TODO: Add individual counts for different warning levels
    }
    Ok(())
}

// --------------------------------------------------------------------------------------------
// Scanning helpers
// --------------------------------------------------------------------------------------------

fn scan_filesystem(root: &Path, cfg: &Config) -> NyxResult<Vec<Diag>> {
    let rx = spawn_senders(root, cfg);
    let acc = Mutex::new(Vec::new());

    rx.into_iter().flatten().par_bridge().try_for_each(|path| {
        let mut local = run_rules_on_file(&path, cfg)?;
        acc.lock().unwrap().append(&mut local);
        Ok::<(), DynError>(())
    })?;

    let mut diags = acc.into_inner()?;
    if let Some(max) = cfg.output.max_results {
        diags.truncate(max as usize);
    }

    Ok(diags)
}

pub fn scan_with_index_parallel(
    project: &str,
    pool: Arc<Pool<SqliteConnectionManager>>,
    cfg: &Config,
) -> NyxResult<Vec<Diag>> {
    let files = {
        let idx = Indexer::from_pool(project, &pool)?;
        idx.get_files(project)?
    };

    let diag_map: DashMap<String, Vec<Diag>> = DashMap::new();

    files.into_par_iter().for_each_init(
        || Indexer::from_pool(project, &pool).expect("db pool"),
        |idx, path| {
            let needs_scan = idx.should_scan(&path).unwrap_or(true);

            let mut diags = if needs_scan {
                let d = run_rules_on_file(&path, cfg).unwrap_or_default();
                let file_id = idx.upsert_file(&path).unwrap_or_default();
                idx.replace_issues(
                    file_id,
                    d.iter().map(|d| IssueRow {
                        rule_id: &d.id,
                        severity: d.severity.as_db_str(),
                        line: d.line as i64,
                        col: d.col as i64,
                    }),
                )
                .ok();
                d
            } else {
                idx.get_issues_from_file(&path).unwrap_or_default()
            };
            if !diags.is_empty() {
                diag_map
                    .entry(path.to_string_lossy().to_string())
                    .or_default()
                    .append(&mut diags);
            }
        },
    );

    // Optional, heavy: only vacuum on --rebuild-index
    // if rebuild { idx.vacuum()?; }

    let mut diags: Vec<Diag> = diag_map.into_iter().flat_map(|(_, v)| v).collect();

    if let Some(max) = cfg.output.max_results {
        diags.truncate(max as usize);
    }

    Ok(diags)
}
