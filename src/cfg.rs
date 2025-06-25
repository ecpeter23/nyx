use std::collections::{HashMap, VecDeque};
use petgraph::algo::dominators::{simple_fast, Dominators};
use petgraph::prelude::*;
use tree_sitter::{Language, Node, Tree};

/// Kinds of statements we care about.
#[derive(Debug, Clone, Copy)]
pub enum StmtKind {
  Entry, Exit, Seq, If, Loop, Break, Continue, Return, Call,
}

#[derive(Debug, Clone, Copy)]
pub enum EdgeKind {
  Seq, True, False, Back,
}

/// Taint metadata (optional on every node).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLabel<'a> {
  Source(&'a str),
  Sanitizer(&'a str),
  Sink(&'a str),
}

/// Full per-node info used by the analyser.
#[derive(Debug, Clone)]
pub struct NodeInfo<'a> {
  pub kind: StmtKind,
  pub span: (usize, usize),          // byte offsets in the file
  pub label: Option<DataLabel<'a>>,  // None for ordinary statements
}

/// Convenience alias.
pub type Cfg<'a> = Graph<NodeInfo<'a>, EdgeKind>;

/// --- helper: create a node in one short borrow --------------------------
pub fn push_node<'a>(
  g:     &mut Cfg<'a>,
  kind:  StmtKind,
  ast:   Node<'a>,
  lang:  &str,
  code:  &'a [u8],
) -> NodeIndex {
  let text = match ast.kind() {
    "call_expression" => {
      ast.child_by_field_name("function")
        .and_then(|n| Some(&code[n.start_byte()..n.end_byte()]))
        .and_then(|s| std::str::from_utf8(s).ok())
        .unwrap_or_default()
    }
    "method_call_expression" => {
      ast.child_by_field_name("method") 
        .or_else(|| ast.child_by_field_name("name"))
        .and_then(|n| Some(&code[n.start_byte()..n.end_byte()]))
        .and_then(|s| std::str::from_utf8(s).ok())
        .unwrap_or_default()
    }
    _ => {
      let span = (ast.start_byte(), ast.end_byte());
      std::str::from_utf8(&code[span.0..span.1]).unwrap_or_default()
    }
  };

  let span  = (ast.start_byte(), ast.end_byte());
  let label = crate::labels::classify(lang, text);
  
  if !matches!(ast.kind(), "call_expression" | "method_call_expression") {
    return g.add_node(NodeInfo { kind, span, label: None });
  }
  g.add_node(NodeInfo { kind, span, label })
}


/// Build an intraprocedural CFG and return (graph, entry_node).
pub(crate) fn build_cfg<'a>(tree: &'a Tree, code: &'a [u8], lang: &str) -> (Cfg<'a>, NodeIndex) {
  tracing::debug!("Building CFG for {}", &tree.root_node() );
  
  let mut g: Cfg<'a> = Graph::with_capacity(128, 256);
  let entry = g.add_node(NodeInfo { kind: StmtKind::Entry,  span: (0, 0),             label: None });
  let exit  = g.add_node(NodeInfo { kind: StmtKind::Exit,   span: (code.len(), code.len()), label: None });

  // ---------- iterative DFS ----------
  let mut stack = vec![(tree.root_node(), entry)];
  while let Some((ts_node, prev)) = stack.pop() {
    match ts_node.kind() {
      "if_expression" => { // TODO: MAKE SURE THIS WORKS
        let node = push_node(&mut g, StmtKind::If, ts_node, lang, code);
        g.add_edge(prev, node, EdgeKind::Seq); 
        g.add_edge(node, prev, EdgeKind::Seq);
        
        let mut cursor = ts_node.walk();
        let children: Vec<_> = ts_node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
          stack.push((child, node));
        }
      }
      "while_statement" | "for_statement" => {  // TODO: MAKE SURE THIS WORKS
        let node = push_node(&mut g, StmtKind::Loop, ts_node, lang, code);
        g.add_edge(prev, node, EdgeKind::Seq); 
        g.add_edge(node, prev, EdgeKind::Seq);
        
        let mut cursor = ts_node.walk();
        let children: Vec<_> = ts_node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
          stack.push((child, node));
        }
      }
      _ => {
        let node = push_node(&mut g, StmtKind::Seq, ts_node, lang, code);
        g.add_edge(prev, node, EdgeKind::Seq); 
        g.add_edge(node, prev, EdgeKind::Seq);
        
        let mut cursor = ts_node.walk();
        let children: Vec<_> = ts_node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
          stack.push((child, node));
        }
      }
    }
  }
  g.add_edge(entry, exit, EdgeKind::Seq);
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
