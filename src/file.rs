use std::cell::RefCell;
use std::path::Path;
use tree_sitter::{Language, QueryCursor, StreamingIterator};
use crate::commands::scan::Diag;
use crate::errors::{NyxResult, NyxError};
use crate::utils::{query_cache, Config};
use crate::utils::ext::lowercase_ext;

thread_local! {
    static PARSER: RefCell<tree_sitter::Parser> = RefCell::new(tree_sitter::Parser::new());
}

pub(crate) fn run_rules_on_file(
  path: &Path,
  cfg: &Config,
) -> NyxResult<Vec<Diag>> {
  let bytes = std::fs::read(path)?;

  // Fast binary-file guard (skip if >1% NULs)
  if bytes.iter().filter(|b| **b == 0).count() * 100 / bytes.len().max(1) > 1 {
    return Ok(vec![]);
  }

  let lang_name = match lowercase_ext(path) {
    Some(l) => l,
    None    => return Ok(vec![]),
  };

  let ts_lang = match lang_name {
    "rs"  => Language::from(tree_sitter_rust::LANGUAGE),
    "c"   => Language::from(tree_sitter_c::LANGUAGE),
    "cpp" => Language::from(tree_sitter_cpp::LANGUAGE),
    "java"=> Language::from(tree_sitter_java::LANGUAGE),
    "go"  => Language::from(tree_sitter_go::LANGUAGE),
    "php" => Language::from(tree_sitter_php::LANGUAGE_PHP),
    "py"  => Language::from(tree_sitter_python::LANGUAGE),
    "ts"  => Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
    "js"  => Language::from(tree_sitter_javascript::LANGUAGE),
    _     => return Ok(vec![]),
  };

  let _tree = PARSER.with(|cell| {
    let mut parser = cell.borrow_mut();
    parser.set_language(&ts_lang)?;
    parser.parse(&*bytes, None)
      .ok_or_else(|| NyxError::Other("tree-sitter failed".into()))
  })?;

  let root = _tree.root_node();

  let compiled = query_cache::for_lang(lang_name, ts_lang);
  let mut cursor = QueryCursor::new();
  let mut out = Vec::new();

  for cq in compiled.iter() {
    if cfg.scanner.min_severity > cq.meta.severity {
      continue;
    }
    let mut matches = cursor.matches(&cq.query, root, &*bytes);
    while let Some(m) = matches.next() {
      if let Some(cap) = m.captures.iter().find(|c| c.index == 0) {
        let point = cap.node.start_position();
        out.push(Diag {
          path: path.to_string_lossy().into_owned(),
          line: point.row + 1,
          col:  point.column + 1,
          severity: cq.meta.severity,
          id: cq.meta.id.to_owned(),
        });
      }
    }
  }
  Ok(out)
}
