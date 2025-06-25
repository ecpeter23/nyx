use std::collections::HashMap;
use petgraph::algo::dominators::{simple_fast, Dominators};
use petgraph::prelude::*;
use petgraph::visit::NodeIndexable;
use tree_sitter::{Node, Tree};

/// What kind of statement or block a node represents.
/// Keep it small; attach extra data in a side-table if needed.
#[derive(Debug, Clone, Copy)]
pub enum StmtKind {
    Entry, Exit, Seq, If, Loop, Break, Continue, Return, Call,
}

#[derive(Debug, Clone, Copy)]
pub enum EdgeKind {
    Seq,        // fall-through
    True,       // taken branch
    False,      // not taken
    Back,       // loop back-edge
}

#[derive(Debug, Clone)]
pub enum DataLabel<'a> {
    Source(&'a str),     
    Sanitizer(&'a str), 
    Sink(&'a str),     
}

#[derive(Debug, Clone)]
pub struct NodeInfo<'a> {
    pub kind: StmtKind,
    pub span: (usize, usize),       
    pub label: Option<DataLabel<'a>>, 
}

/// Build an intraprocedural CFG for a single translation unit.
pub fn build_cfg(tree: &Tree, code: &[u8]) -> Graph<StmtKind, EdgeKind> {
    let mut g: Graph<StmtKind, EdgeKind> = Graph::with_capacity(128, 256);
    let entry = g.add_node(StmtKind::Entry);
    let exit  = g.add_node(StmtKind::Exit);

    // A very small recursive descent; real code should use an explicit
    // stack or QueryCursor to avoid recursion limits.
    fn walk(
        ts_node: Node,
        g: &mut Graph<StmtKind, EdgeKind>,
        prev: NodeIndex<u32>,
        code: &[u8],
    ) -> NodeIndex<u32> {
        match ts_node.kind() {
            "if_expression" => {
                let cond = g.add_node(StmtKind::If);
                g.add_edge(prev, cond, EdgeKind::Seq);

                let then_block   = ts_node.child_by_field_name("consequence").unwrap();
                let else_block   = ts_node.child_by_field_name("alternative");
                let tail_after_if;

                // True branch
                let tail_then = walk(then_block, g, cond, code);
                g.add_edge(cond, g.from_index(tail_then.index()), EdgeKind::True);

                // False branch
                if let Some(else_node) = else_block {
                    let tail_else = walk(else_node, g, cond, code);
                    g.add_edge(cond, g.from_index(tail_else.index()), EdgeKind::False);
                    tail_after_if = g.add_node(StmtKind::Seq);
                    g.add_edge(tail_then, tail_after_if, EdgeKind::Seq);
                    g.add_edge(tail_else, tail_after_if, EdgeKind::Seq);
                } else {
                    tail_after_if = tail_then;
                }
                tail_after_if
            }
            "while_statement" | "for_statement" => {
                let header = g.add_node(StmtKind::Loop);
                g.add_edge(prev, header, EdgeKind::Seq);

                let body = ts_node.child_by_field_name("body").unwrap();
                let tail = walk(body, g, header, code);

                // back-edge
                g.add_edge(tail, header, EdgeKind::Back);

                // fall-through after loop
                let after_loop = g.add_node(StmtKind::Seq);
                g.add_edge(header, after_loop, EdgeKind::False);
                after_loop
            }
            // …handle return, break, continue, call expression, etc.
            _ => {
                let node = g.add_node(StmtKind::Seq);
                g.add_edge(prev, node, EdgeKind::Seq);
                node
            }
        }
    }

    let root = tree.root_node();
    let tail = walk(root, &mut g, entry, code);
    g.add_edge(tail, exit, EdgeKind::Seq);
    g
}

/// Return every unsanitised Source→Sink path.
/// Each path is a Vec<NodeIndex>; caller can map back to spans for nice diagnostics.
pub fn find_tainted_paths<N, E>(
    g: &Graph<N, E>,
    is_source: impl Fn(NodeIndex) -> bool,
    is_sink: impl Fn(NodeIndex) -> bool,
    is_sanitizer: impl Fn(NodeIndex) -> bool,
) -> Vec<Vec<NodeIndex>>
where
    N: std::fmt::Debug,
{
    let mut findings = Vec::new();

    // iterate all sources once; graphs are tiny so O(S * (V+E)) is fine
    for src in g.node_indices().filter(|&n| is_source(n)) {
        // ordinary BFS but we track predecessors so we can rebuild the path
        let mut bfs = Bfs::new(g, src);
        let mut pred: HashMap<NodeIndex, NodeIndex> = HashMap::new();

        while let Some(nx) = bfs.next(g) {
            if is_sanitizer(nx) {
                // do *not* push its outgoing edges -> taint is killed
                continue;
            }
            if is_sink(nx) {
                // reconstruct Source-Sink path
                let mut path = vec![nx];
                let mut cur = nx;
                while let Some(&p) = pred.get(&cur) {
                    path.push(p);
                    if p == src { break; }
                    cur = p;
                }
                path.reverse();
                findings.push(path);
                // keep searching – there may be more sinks downstream
            }
            // enqueue neighbours
            for e in g.edges(nx) {
                let tgt = e.target();
                if !pred.contains_key(&tgt) {
                    pred.insert(tgt, nx);
                    bfs.queue().push_back(tgt);
                }
            }
        }
    }
    findings
}


pub fn filter_by_dominators<N, E>(
    g: &Graph<N, E>,
    entry: NodeIndex,
    findings: Vec<Vec<NodeIndex>>,
    is_sanitizer: impl Fn(NodeIndex) -> bool,
) -> Vec<Vec<NodeIndex>> {
    let dom: Dominators<NodeIndex> = simple_fast(g, entry); // O(V * E) but tiny here
    findings
        .into_iter()
        .filter(|path| {
            let sink = *path.last().unwrap();
            // walk up the dom tree; if we hit a sanitizer -> safe
            let mut cur = sink;
            loop {
                if is_sanitizer(cur) { return false; }
                if let Some(idom) = dom.immediate_dominator(cur) {
                    cur = idom;
                } else { break; }
            }
            true
        })
        .collect()
}

pub fn analyse_function(
    cfg: &Graph<NodeInfo, EdgeKind>,
    entry: NodeIndex,
) -> Vec<Vec<NodeIndex>> {
    // simple closures capture your label enum
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
