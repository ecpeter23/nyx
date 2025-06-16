use crate::cli::OutputFormat;
use crate::utils::project::get_project_info;
use std::path::Path;
use crate::utils::config::Config;
use tree_sitter::{Parser};
use crate::index::index::Indexer;
use crate::walk::spawn_senders;

pub fn handle(
    path: &str,
    no_index: bool,
    rebuild_index: bool,
    format: OutputFormat,
    high_only: bool,
    database_dir: &Path,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let scan_path = Path::new(path).canonicalize()?;
    let (project_name, db_path) = get_project_info(&scan_path, database_dir)?;

    tracing::debug!("Config: {:?}", config);
    tracing::info!("Scanning project: {}", project_name);
    tracing::info!("Scan path: {}", scan_path.display());

    if no_index {
        tracing::info!("Scanning without index...");
        scan_filesystem(&scan_path, config)?;
    } else {
        if rebuild_index || !db_path.exists() {
            tracing::info!("Building/updating index...");
            crate::commands::index::build_index(&scan_path, &db_path)?;
        }

        tracing::info!("Using index: {}", db_path.display());
        scan_with_index(&scan_path, &db_path, config)?;
    }

    tracing::info!("Output format: {:?}", format);
    if high_only {
        tracing::info!("Filtering: High severity only");
    }

    Ok(())
}

fn scan_filesystem(root: &Path, cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let rx = spawn_senders(root, cfg);

    for batch in rx.iter().flatten() {
        tracing::debug!("Scanning file: {}", batch.display());
        scan_single_file(&batch, cfg)?;     // <-- your actual scanner
    }
    Ok(())
}
fn scan_with_index(root: &Path, db_path: &Path, cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let indexer = Indexer::new(db_path)
      .map_err(|e| format!("opening index {}: {e}", db_path.display()))?;

    let rx = spawn_senders(root, cfg);

    for batch in rx.iter().flatten() {
        let scan = indexer.should_scan(&batch)?;
        tracing::debug!("Should scan: {}, file: {}", scan, batch.display());
        if scan {
            tracing::debug!("Scanning file: {}", batch.display());
            scan_single_file(&batch, cfg)?;   // your scanner
            indexer.record_scan(&batch)?;
        }
    }
    Ok(())
}

fn scan_single_file(
    path: &Path,
    _cfg: &Config,
) -> Result<(), Box<dyn std::error::Error>> { 
    if path.extension().and_then(|s| s.to_str()) != Some("rs") { 
        return Ok(()); 
    }

    let source = std::fs::read_to_string(path)?;

    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_rust::LANGUAGE.into())?;

    let tree    = parser.parse(&source, None).ok_or("tree-sitter failed")?;
    let root    = tree.root_node();
    
    let mut fn_count = 0;
    let mut cursor   = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "function_item" {
            fn_count += 1;
         }
    }

    tracing::info!(
        "scanned {} – found {} Rust function(s)",
        path.display(),
        fn_count
    );

    //  TODO: real vulnerability/pattern checks go here
    Ok(())
}