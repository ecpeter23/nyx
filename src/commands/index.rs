use std::fs;
use std::process::exit;
use bytesize::ByteSize;
use chrono::{DateTime, Local};
use console::style;
use crate::cli::IndexAction;
use crate::database::index::{Indexer, IssueRow};
use crate::patterns::Severity;
use crate::utils::Config;
use crate::utils::project::get_project_info;
use crate::walk::spawn_senders;
use rayon::prelude::*;

pub fn handle(
    action: IndexAction,
    database_dir: &std::path::Path,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        IndexAction::Build { path, force } => {
            let build_path = std::path::Path::new(&path).canonicalize()?;
            let (project_name, db_path) = get_project_info(&build_path, database_dir)?;

            if force || !db_path.exists() {
                build_index(&project_name, &build_path, &db_path, config)?;
                println!("✔ {} {}", style("Index built:" ).green(), style(db_path.display()).white().bold());
                exit(0);
            } else {
                println!("{} {}", style("↩ Index already exists").yellow(), style("(use --force to rebuild)").dim());
                exit(0);
            }
        }
        IndexAction::Status { path } => {
            let status_path = std::path::Path::new(&path).canonicalize()?;
            let (project_name, db_path) = get_project_info(&status_path, database_dir)?;

            println!("{}", style("Project status").blue().bold().underlined());
            println!("  {:14} {}", style("Project"),    style(&project_name).white().bold());
            println!("  {:14} {}", style("Index path"), style(db_path.display()).underlined());
            println!("  {:14} {}", style("Exists"),     style(db_path.exists()).bold());

            if db_path.exists() {
                let meta = fs::metadata(&db_path)?;
                let size = ByteSize::b(meta.len());
                let mtime: DateTime<Local> = meta.modified()?.into();
                println!("  {:14} {}", style("Size"),      size);
                println!("  {:14} {}", style("Modified"),  mtime.format("%Y-%m-%d %H:%M:%S"));
            }
            
            exit(0);
        }
    }
}

pub fn build_index(
    project_name: &str,
    project_path: &std::path::Path,
    db_path: &std::path::Path,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::debug!("Building index for: {}", project_name);
    fs::File::create(db_path)?;
    
    let pool = Indexer::init(db_path)?;
    {
        let idx = Indexer::from_pool(project_name, &pool).unwrap();
        idx.clear()?;
    }

    tracing::debug!("Cleaned index for: {}", project_name);
    
    let rx = spawn_senders(project_path, config);
    let paths: Vec<_> = rx.into_iter().flatten().collect();
    
    paths.into_par_iter().try_for_each(|path| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let issues = crate::commands::scan::run_rules_on_file(&path, config).unwrap();
        let mut idx = Indexer::from_pool(project_name, &pool).unwrap();
        let file_id = idx.upsert_file(&path).unwrap();

        let rows: Vec<IssueRow> = issues.iter().map(|d| IssueRow {
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
        Ok(())
    }).unwrap();
    
    {
        let idx = Indexer::from_pool(project_name, &pool)?;
        idx.vacuum()?;
    }
    
    Ok(())
}