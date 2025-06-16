use crate::cli::OutputFormat;
use crate::utils::project::get_project_info;
use std::path::Path;
use crate::utils::config::Config;
use tree_sitter::{Language, Parser, QueryCursor, StreamingIterator};
use crate::database::index::Indexer;
use crate::utils::query_cache;
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
    cfg: &Config,                       // assume cfg.high_only: bool
) -> Result<(), Box<dyn std::error::Error>> {
    let source = std::fs::read_to_string(path)?;
    let mut parser = Parser::new();

    let ext = path
      .extension()
      .and_then(|s| s.to_str())
      .unwrap_or_default()
      .to_ascii_lowercase();

    // Pick the right tree-sitter language *and* pre-compiled queries
    let (ts_lang, lang_key): (Language, &'static str) = match ext.as_str() {
        "rs" => (Language::from(tree_sitter_rust::LANGUAGE), "rust"),
        "c" => (Language::from(tree_sitter_c::LANGUAGE), "c"),
        "cpp" | "c++" => (Language::from(tree_sitter_cpp::LANGUAGE), "cpp"),
        "java" => (Language::from(tree_sitter_java::LANGUAGE), "java"),
        "go" => (Language::from(tree_sitter_go::LANGUAGE), "go"),
        "php" => (Language::from(tree_sitter_php::LANGUAGE_PHP), "php"),
        "py" => (Language::from(tree_sitter_python::LANGUAGE), "python"),
        "ts" | "tsx" => (Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT), "typescript"),
        "js" => (Language::from(tree_sitter_javascript::LANGUAGE), "javascript"),
        _ => return Ok(()),
    };

    parser.set_language(&ts_lang)?;

    let tree  = parser.parse(&source, None).ok_or("tree-sitter failed")?;
    let root  = tree.root_node();

    // ----- run vulnerability patterns -----
    let compiled = query_cache::for_lang(lang_key, ts_lang);
    let mut cursor = QueryCursor::new();

    for cq in &compiled {
        if cfg.scanner.min_severity > cq.meta.severity {
            continue;       
        }
        
        let mut matches = cursor.matches(&cq.query, root, source.as_bytes());

        while let Some(m) = matches.next() {
            // capture 0 is the one tagged @vuln
            for cap in m.captures.iter().filter(|c| c.index == 0) {
                let point = cap.node.start_position();
                let line = point.row;
                let col = point.column;
                tracing::warn!(
                    file   = %path.display(),
                    line   = line + 1,
                    column = col + 1,
                    id     = cq.meta.id,
                    sev    = ?cq.meta.severity,
                    "pattern matched"
                );
            }
        }
    }

    Ok(())
}