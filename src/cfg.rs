use petgraph::algo::dominators::{simple_fast, Dominators};
use petgraph::prelude::*;
use tree_sitter::{Language, Node, Tree};
use tracing::debug;

use std::collections::{HashMap, HashSet};

/// -------------------------------------------------------------------------
///  Public AST‑to‑CFG data structures
/// -------------------------------------------------------------------------
#[derive(Debug, Clone, Copy)]
pub enum StmtKind {
  Entry,
  Exit,
  Seq,
  If,
  Loop,
  Break,
  Continue,
  Return,
  Call,
}

#[derive(Debug, Clone, Copy)]
pub enum EdgeKind {
  Seq,   // ordinary fall‑through
  True,  // `cond == true` branch
  False, // `cond == false` branch
  Back,  // back‑edge that closes a loop
}

/// Optional taint metadata (can sit on any node).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLabel<'a> {
  Source(&'a str),
  Sanitizer(&'a str),
  Sink(&'a str),
}

#[derive(Debug, Clone)]
pub struct NodeInfo<'a> {
  pub kind:  StmtKind,
  pub span:  (usize, usize),      // byte offsets in the original file
  pub label: Option<DataLabel<'a>>, // taint classification if any
}

pub type Cfg<'a> = Graph<NodeInfo<'a>, EdgeKind>;

// -------------------------------------------------------------------------
//                      Utility helpers
// -------------------------------------------------------------------------

/// Return the text of a node.
#[inline]
fn text_of<'a>(n: Node<'a>, code: &'a [u8]) -> Option<String> {
  std::str::from_utf8(&code[n.start_byte()..n.end_byte()])
      .ok()
      .map(|s| s.to_string())
}

/// Return the callee identifier for the first call / method / macro inside `n`.
fn first_call_ident<'a>(n: Node<'a>, code: &'a [u8]) -> Option<String> {
  let mut cursor = n.walk();
  for c in n.children(&mut cursor) {
    match c.kind() {
      "call_expression" | "method_call_expression" | "macro_invocation" => {
        // Re-use the same logic we have in `push_node`
        return match c.kind() {
          "call_expression" => c
              .child_by_field_name("function")
              .and_then(|f| text_of(f, code)),
          "method_call_expression" => {
            let func = c.child_by_field_name("method")
                .or_else(|| c.child_by_field_name("name"))
                .and_then(|f| text_of(f, code));
            let recv = c.child_by_field_name("object")
                .and_then(|f| text_of(f, code));
            match (recv, func) {
              (Some(r), Some(f)) => Some(format!("{r}::{f}")),
              (_,      Some(f))  => Some(f.to_string()),
              _                  => None,
            }
          }
          "macro_invocation" => c
              .child_by_field_name("macro")
              .and_then(|f| text_of(f, code)),
          _ => None,
        };
      }
      _ => {}
    }
  }
  None
}

/// Create a node in one short borrow and optionally attach a taint label.
fn push_node<'a>(
  g:    &mut Cfg<'a>,
  kind: StmtKind,
  ast:  Node<'a>,
  lang: &str,
  code: &'a [u8],
) -> NodeIndex {
  /* ── 1.  IDENTIFIER EXTRACTION ─────────────────────────────────────── */

  // Primary guess (varies by AST kind)
  let mut text = match ast.kind() {
    // plain `foo(bar)` style call
    "call_expression" => ast
        .child_by_field_name("function")
        .and_then(|n| text_of(n, code))
        .unwrap_or_default(),

    // method / UFCS call  `recv.method()`  or  `Type::func()`
    "method_call_expression" => {
      let func = ast.child_by_field_name("method")
          .or_else(|| ast.child_by_field_name("name"))
          .and_then(|n| text_of(n, code));
      let recv = ast.child_by_field_name("object")
          .and_then(|n| text_of(n, code));
      match (recv, func) {
        (Some(r), Some(f)) => format!("{r}::{f}"),
        (_,      Some(f))  => f,
        _                  => String::new(),
      }
    }

    // `my_macro!(…)`
    "macro_invocation" => ast
        .child_by_field_name("macro")
        .and_then(|n| text_of(n, code))
        .unwrap_or_default(),

    // everything else – fallback to raw slice
    _ => text_of(ast, code).unwrap_or_default(),
  };

  // If this is a `let` or `expression_statement` that *contains* a call,
  // prefer the first inner call identifier instead of the whole line.
  if matches!(ast.kind(), "let_declaration" | "expression_statement") {
    if let Some(inner) = first_call_ident(ast, code) {
      text = inner;
    }
  }

  /* ── 2.  LABEL LOOK-UP  ───────────────────────────────────────────── */

  let label = crate::labels::classify(lang, &text);
  let span  = (ast.start_byte(), ast.end_byte());

  /* ── 3.  GRAPH INSERTION + DEBUG ──────────────────────────────────── */

  let idx = g.add_node(NodeInfo { kind, span, label });

  debug!(
        target: "cfg",
        "node {} ← {:?} txt=`{}` span={:?} label={:?}",
        idx.index(),
        kind,
        text,
        span,
        label
    );
  idx
}

/// Add the same edge (of the same kind) from every node in `froms` to `to`.
#[inline]
fn connect_all<'a>(g: &mut Cfg<'a>, froms: &[NodeIndex], to: NodeIndex, kind: EdgeKind) {
  for &f in froms {
    debug!(target: "cfg", "edge {} → {} ({:?})", f.index(), to.index(), kind);
    g.add_edge(f, to, kind);
  }
}

// -------------------------------------------------------------------------
//    The recursive *work‑horse* that converts an AST node into a CFG slice.
//    Returns the set of *exit* nodes that need to be wired further.
// -------------------------------------------------------------------------
fn build_sub<'a>(
  ast:   Node<'a>,
  preds: &[NodeIndex],      // predecessor frontier
  g:     &mut Cfg<'a>,
  lang:  &str,
  code:  &'a [u8],
) -> Vec<NodeIndex> {
  match ast.kind() {
    // ─────────────────────────────────────────────────────────────────
    //  IF‑/ELSE: two branches that re‑merge afterwards
    // ─────────────────────────────────────────────────────────────────
    "if_expression" => {
      // Condition node
      let cond = push_node(g, StmtKind::If, ast, lang, code);
      connect_all(g, preds, cond, EdgeKind::Seq);

      // Locate then & else blocks
      let (then_block, else_block) = {
        let mut cursor = ast.walk();
        let blocks: Vec<_> = ast
            .children(&mut cursor)
            .filter(|n| n.kind() == "block")
            .collect();
        (blocks.get(0).copied(), blocks.get(1).copied())
      };

      // THEN branch
      let then_exits = if let Some(b) = then_block {
        let exits = build_sub(b, &[cond], g, lang, code);
        // True edges leave the condition
        connect_all(g, &[cond], exits[0], EdgeKind::True);
        exits
      } else {
        vec![cond]
      };

      // ELSE branch
      let else_exits = if let Some(b) = else_block {
        let exits = build_sub(b, &[cond], g, lang, code);
        connect_all(g, &[cond], exits[0], EdgeKind::False);
        exits
      } else {
        // No explicit else → non-taken branch flows to the *then* exits
        connect_all(g, &[cond], then_exits[0], EdgeKind::False);
        then_exits.clone()
      };

      // Frontier = union of both branches
      then_exits.into_iter().chain(else_exits).collect()
    }

    // ─────────────────────────────────────────────────────────────────
    //  WHILE / FOR: classic loop with a back edge.
    // ─────────────────────────────────────────────────────────────────
    "while_statement" | "for_statement" => {
      let header = push_node(g, StmtKind::Loop, ast, lang, code);
      connect_all(g, preds, header, EdgeKind::Seq);

      // Body = first (and usually only) block child.
      let body = ast
          .child_by_field_name("body")
          .or_else(|| {
            let mut c = ast.walk();
            ast.children(&mut c).find(|n| n.kind() == "block")
          })
          .expect("loop without body");

      let body_exits = build_sub(body, &[header], g, lang, code);

      // Back‑edge for every linear exit → header.
      for &e in &body_exits {
        connect_all(g, &[e], header, EdgeKind::Back);
      }
      // Falling out of the loop = header’s false branch.
      vec![header]
    }

    // ─────────────────────────────────────────────────────────────────
    //  Control-flow sinks (return / break / continue).
    // ─────────────────────────────────────────────────────────────────
    "return_statement" => {
      let ret = push_node(g, StmtKind::Return, ast, lang, code);
      connect_all(g, preds, ret, EdgeKind::Seq);
      Vec::new() // terminates this path
    }
    "break_expression" | "break_statement" => {
      let brk = push_node(g, StmtKind::Break, ast, lang, code);
      connect_all(g, preds, brk, EdgeKind::Seq);
      Vec::new()
    }
    "continue_expression" | "continue_statement" => {
      let cont = push_node(g, StmtKind::Continue, ast, lang, code);
      connect_all(g, preds, cont, EdgeKind::Seq);
      Vec::new()
    }

    // ─────────────────────────────────────────────────────────────────
    //  BLOCK: statements execute sequentially
    // ─────────────────────────────────────────────────────────────────
    "source_file" | "block" => {
      let mut cursor   = ast.walk();
      let mut frontier = preds.to_vec();
      for child in ast.children(&mut cursor) {
        frontier = build_sub(child, &frontier, g, lang, code);
      }
      frontier
    }

    // Function item – create a header and dive into its body
    "function_item" => {
      let header = push_node(g, StmtKind::Seq, ast, lang, code);
      connect_all(g, preds, header, EdgeKind::Seq);

      if let Some(body) = ast.child_by_field_name("body") {
        build_sub(body, &[header], g, lang, code)
      } else {
        vec![header] // declaration w/o body
      }
    }

    // Statements that **may** contain a call ---------------------------------
    "let_declaration" | "expression_statement" => {
      let mut cursor = ast.walk();
      let has_call = ast.children(&mut cursor).any(|c| {
        matches!(
                    c.kind(),
                    "call_expression" | "method_call_expression" | "macro_invocation"
                )
      });

      let kind = if has_call { StmtKind::Call } else { StmtKind::Seq };
      let node = push_node(g, kind, ast, lang, code);
      connect_all(g, preds, node, EdgeKind::Seq);
      vec![node]
    }

    // Trivia we drop completely ---------------------------------------------
    "line_comment" | "block_comment"
    | ";" | "," | "(" | ")" | "{" | "}" | "\n"
    | "use_declaration"     
    | "attribute_item"          
    | "mod_item" | "type_item" 
    => preds.to_vec(),

    // ─────────────────────────────────────────────────────────────────
    //  Every other node = simple sequential statement
    // ─────────────────────────────────────────────────────────────────
    _ => {
      let n = push_node(g, StmtKind::Seq, ast, lang, code);
      connect_all(g, preds, n, EdgeKind::Seq);
      vec![n]
    }
  }
}

// -------------------------------------------------------------------------
//  === PUBLIC ENTRY POINT =================================================
// -------------------------------------------------------------------------

/// Build an intraprocedural CFG and return (graph, entry_node).
///
/// * Walks the Tree‑Sitter AST.
/// * Creates `StmtKind::*` nodes only for *statement‑level* constructs to keep
///   the graph compact.
/// * Wires a synthetic `Entry` node in front and a synthetic `Exit` node after
///   all real sinks.
pub(crate) fn build_cfg<'a>(tree: &'a Tree, code: &'a [u8], lang: &str) -> (Cfg<'a>, NodeIndex) {
  debug!(target: "cfg", "Building CFG for {:?}", tree.root_node());

  let mut g: Cfg<'a> = Graph::with_capacity(128, 256);
  let entry = g.add_node(NodeInfo {
    kind:  StmtKind::Entry,
    span:  (0, 0),
    label: None,
  });
  let exit = g.add_node(NodeInfo {
    kind:  StmtKind::Exit,
    span:  (code.len(), code.len()),
    label: None,
  });

  // Build the body below the synthetic ENTRY.
  let exits = build_sub(tree.root_node(), &[entry], &mut g, lang, code);

  // Wire every real exit to our synthetic EXIT node.
  for e in exits {
    connect_all(&mut g, &[e], exit, EdgeKind::Seq);
  }

  debug!(target: "cfg", "CFG DONE — nodes: {}, edges: {}", g.node_count(), g.edge_count());

  if cfg!(debug_assertions) {
    // List every node
    for idx in g.node_indices() {
      debug!(target: "cfg", "  node {:>3}: {:?}", idx.index(), g[idx]);
    }
    // List every edge
    for e in g.edge_references() {
      debug!(
                target: "cfg",
                "  edge {:>3} → {:<3} ({:?})",
                e.source().index(),
                e.target().index(),
                e.weight()
            );
    }

    // Reachability check
    let mut reachable: HashSet<NodeIndex> = Default::default();
    let mut bfs = Bfs::new(&g, entry);
    while let Some(nx) = bfs.next(&g) {
      reachable.insert(nx);
    }
    debug!(
            target: "cfg",
            "reachable nodes: {}/{}",
            reachable.len(),
            g.node_count()
        );
    if reachable.len() != g.node_count() {
      let unreachable: Vec<_> =
          g.node_indices().filter(|i| !reachable.contains(i)).collect();
      debug!(target: "cfg", "‼︎ unreachable nodes: {:?}", unreachable);
    }

    // (Optional) Dominator tree sanity check
    let doms: Dominators<_> = simple_fast(&g, entry);
    debug!(target: "cfg", "dominator tree computed (len = {:?})", doms);
  }
  
  (g, entry)
}

/* ---------- TAINT-ANALYSIS PASSES ---------- */

/// Find every unsanitised Source→Sink path (simple forward BFS).
pub fn find_tainted_paths<N, E>(
  g: &Graph<N, E>,
  is_source: impl Fn(NodeIndex) -> bool,
  is_sink: impl Fn(NodeIndex) -> bool,
  is_sanitizer: impl Fn(NodeIndex) -> bool,
) -> Vec<Vec<NodeIndex>>
where
  N: std::fmt::Debug,
{
  use std::collections::VecDeque;

  let mut findings = Vec::new();

  for src in g.node_indices().filter(|&n| is_source(n)) {
    let mut pred: HashMap<NodeIndex, NodeIndex> = HashMap::new();
    let mut q = VecDeque::new();
    q.push_back(src);

    while let Some(nx) = q.pop_front() {
      if is_sanitizer(nx) {
        continue; // taint killed
      }
      if is_sink(nx) {
        // rebuild path
        let mut path = vec![nx];
        let mut cur = nx;
        while let Some(&p) = pred.get(&cur) {
          path.push(p);
          if p == src {
            break;
          }
          cur = p;
        }
        path.reverse();
        findings.push(path);
      }
      for tgt in g.neighbors(nx) {
        if !pred.contains_key(&tgt) {
          pred.insert(tgt, nx);
          q.push_back(tgt);
        }
      }
    }
  }
  findings
}

/// Drop any finding whose sink is dominated by a sanitizer.
pub fn filter_by_dominators<N, E>(
  g: &Graph<N, E>,
  entry: NodeIndex,
  findings: Vec<Vec<NodeIndex>>,
  is_sanitizer: impl Fn(NodeIndex) -> bool,
) -> Vec<Vec<NodeIndex>> {
  let dom: Dominators<NodeIndex> = simple_fast(g, entry);
  findings
    .into_iter()
    .filter(|path| {
      let sink = *path.last().unwrap();
      let mut cur = sink;
      loop {
        if is_sanitizer(cur) {
          return false;
        }
        if let Some(idom) = dom.immediate_dominator(cur) {
          cur = idom;
        } else {
          break;
        }
      }
      true
    })
    .collect()
}

/// Public API: run both passes and return only the genuine problems.
pub fn analyse_function(
  cfg: &Cfg,
  entry: NodeIndex,
) -> Vec<Vec<NodeIndex>> {
  let tainted = find_tainted_paths(
    cfg,
    |n| matches!(cfg[n].label, Some(DataLabel::Source(_))),
    |n| matches!(cfg[n].label, Some(DataLabel::Sink(_))),
    |n| matches!(cfg[n].label, Some(DataLabel::Sanitizer(_))),
  );
  filter_by_dominators(
    cfg,
    entry,
    tainted,
    |n| matches!(cfg[n].label, Some(DataLabel::Sanitizer(_))),
  )
}

#[test]
fn env_to_arg_is_flagged() {
  let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS_ARG").unwrap();
            Command::new("sh").arg(x).status().unwrap();
        }"#;

  let mut parser = tree_sitter::Parser::new();
  parser.set_language(&Language::from(tree_sitter_rust::LANGUAGE)).unwrap();
  let tree = parser.parse(src as &[u8], None).unwrap();

  let (cfg, entry) = build_cfg(&tree, src, "rust");
  let findings = analyse_function(&cfg, entry);

  assert_eq!(findings.len(), 1);  // exactly one unsanitised Source→Sink
}

#[test]
fn taint_through_if_else() {
  let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let safe = html_escape::encode_safe(&x);

            if x.len() > 5 {
                Command::new("sh").arg(&x).status().unwrap();   // UNSAFE
            } else {
                Command::new("sh").arg(&safe).status().unwrap(); // SAFE
            }
        }"#;

  let mut parser = tree_sitter::Parser::new();
  parser.set_language(&Language::from(tree_sitter_rust::LANGUAGE)).unwrap();
  let tree = parser.parse(src as &[u8], None).unwrap();

  let (cfg, entry) = build_cfg(&tree, src, "rust");
  let findings = analyse_function(&cfg, entry);

  // exactly one path (via the True branch) should be flagged
  assert_eq!(findings.len(), 1);
}

#[test]
fn taint_through_while_loop() {
  let src = br#"
        use std::{env, process::Command};
        fn main() {
            let mut x = env::var("DANGEROUS").unwrap();
            while x.len() < 100 {                       // Loop header (Loop)
                x.push_str("a");
            }
            Command::new("sh").arg(x).status().unwrap(); // Should be flagged
        }"#;

  let mut parser = tree_sitter::Parser::new();
  parser.set_language(&Language::from(tree_sitter_rust::LANGUAGE)).unwrap();
  let tree = parser.parse(src as &[u8], None).unwrap();

  let (cfg, entry) = build_cfg(&tree, src, "rust");
  let findings = analyse_function(&cfg, entry);
  assert_eq!(findings.len(), 1);
}

#[test]
fn taint_killed_by_sanitizer() {
  let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = html_escape::encode_safe(&x);    // sanitizer node
            Command::new("sh").arg(clean).status().unwrap();  // SAFE
        }"#;

  let mut parser = tree_sitter::Parser::new();
  parser.set_language(&Language::from(tree_sitter_rust::LANGUAGE)).unwrap();
  let tree = parser.parse(src as &[u8], None).unwrap();

  let (cfg, entry) = build_cfg(&tree, src, "rust");
  let findings = analyse_function(&cfg, entry);
  assert!(findings.is_empty());
}

#[test]
fn taint_breaks_out_of_loop() {
  let src = br#"
        use std::{env, process::Command};
        fn main() {
            loop {
                let x = env::var("DANGEROUS").unwrap();
                Command::new("sh").arg(&x).status().unwrap(); // vulnerable
                break;
            }
        }"#;

  let mut parser = tree_sitter::Parser::new();
  parser.set_language(&Language::from(tree_sitter_rust::LANGUAGE)).unwrap();
  let tree = parser.parse(src as &[u8], None).unwrap();

  let (cfg, entry) = build_cfg(&tree, src, "rust");
  let findings = analyse_function(&cfg, entry);
  assert_eq!(findings.len(), 1);
}
