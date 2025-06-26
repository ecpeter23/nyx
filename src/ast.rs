use crate::commands::scan::Diag;
use crate::errors::{NyxError, NyxResult};
use crate::utils::ext::lowercase_ext;
use crate::utils::{Config, query_cache};
use std::cell::RefCell;
use std::path::Path;
use tree_sitter::{Language, QueryCursor, StreamingIterator};
use crate::cfg::{analyse_function, build_cfg};
use crate::patterns::Severity;

thread_local! {
    static PARSER: RefCell<tree_sitter::Parser> = RefCell::new(tree_sitter::Parser::new());
}

/// Convenience alias for node indices.
fn byte_offset_to_point(tree: &tree_sitter::Tree, byte: usize) -> tree_sitter::Point {
  // `descendant_for_byte_range` gives us *some* node that starts at `byte`,
  // `start_position` turns that into rows & columns (both 0-based)
  tree.root_node()
    .descendant_for_byte_range(byte, byte)
    .map(|n| n.start_position())
    .unwrap_or_else(|| tree_sitter::Point { row: 0, column: 0 })
}

pub(crate) fn run_rules_on_file(path: &Path, cfg: &Config) -> NyxResult<Vec<Diag>> {
    tracing::debug!("Running rules on: {}", path.display());
    let bytes = std::fs::read(path)?;

    // Fast binary-file guard (skip if >1% NULs)
    if bytes.iter().filter(|b| **b == 0).count() * 100 / bytes.len().max(1) > 1 {
        return Ok(vec![]);
    }

    let (ts_lang, lang_slug) = match lowercase_ext(path) {
        Some("rs") => (Language::from(tree_sitter_rust::LANGUAGE), "rust"),
        Some("c") => (Language::from(tree_sitter_c::LANGUAGE), "c"),
        Some("cpp") => (Language::from(tree_sitter_cpp::LANGUAGE), "cpp"),
        Some("java") => (Language::from(tree_sitter_java::LANGUAGE), "java"),
        Some("go") => (Language::from(tree_sitter_go::LANGUAGE), "go"),
        Some("php") => (Language::from(tree_sitter_php::LANGUAGE_PHP), "php"),
        Some("py") => (Language::from(tree_sitter_python::LANGUAGE), "python"),
        Some("ts") => (
            Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
            "typescript",
        ),
        Some("js") => (
            Language::from(tree_sitter_javascript::LANGUAGE),
            "javascript",
        ),
        Some("rb") => (Language::from(tree_sitter_ruby::LANGUAGE), "ruby"),
        _ => return Ok(vec![]),
    };

    let _tree = PARSER.with(|cell| {
        let mut parser = cell.borrow_mut();
        parser.set_language(&ts_lang)?;
        parser
            .parse(&*bytes, None)
            .ok_or_else(|| NyxError::Other("tree-sitter failed".into()))
    })?;
  
    let mut out = Vec::new();
    let (cfg_graph, entry) = build_cfg(&_tree, &bytes, lang_slug);

    for p in analyse_function(&cfg_graph, entry) {
      let src_byte = cfg_graph[p.first().copied().unwrap()].span.0;
      let point    = byte_offset_to_point(&_tree, src_byte);
      
      out.push(Diag {
          path:     path.to_string_lossy().into_owned(),
          line:     point.row + 1,     
          col:      point.column + 1,
          severity: Severity::High,              
          id:       "taint-unsanitised-flow".into(),
     });
     }

    let root = _tree.root_node();
    
    let compiled = query_cache::for_lang(lang_slug, ts_lang);
    let mut cursor = QueryCursor::new();
    
    for cq in compiled.iter() {
        if cfg.scanner.min_severity <= cq.meta.severity {
            continue;
        }
        let mut matches = cursor.matches(&cq.query, root, &*bytes);
        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index == 0) {
                let point = cap.node.start_position();
                out.push(Diag {
                    path: path.to_string_lossy().into_owned(),
                    line: point.row + 1,
                    col: point.column + 1,
                    severity: cq.meta.severity,
                    id: cq.meta.id.to_owned(),
                });
            }
        }
    }
  
    out.sort_by(|a, b| (a.line, a.col, &a.id, a.severity)
      .cmp(&(b.line, b.col, &b.id, b.severity)));
    out.dedup_by(|a, b| {
      a.line == b.line &&
        a.col  == b.col  &&
        a.id   == b.id   &&
        a.severity == b.severity
    });
  
    Ok(out)
}

#[test]
fn unknown_extension_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let txt = dir.path().join("notes.txt");
    std::fs::write(&txt, "just some text").unwrap();

    let diags = run_rules_on_file(&txt, &Config::default())
        .expect("function should never error on plain text");

    assert!(diags.is_empty());
}

#[test]
fn binary_file_guard_triggers() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("junk.bin");

    let mut data = vec![0_u8; 2048];
    for i in (0..data.len()).step_by(3) {
        data[i] = 0;
    }
    std::fs::write(&bin, &data).unwrap();

    let diags = run_rules_on_file(&bin, &Config::default()).unwrap();
    assert!(diags.is_empty(), "binary files are skipped");
}
