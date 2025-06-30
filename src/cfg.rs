use petgraph::algo::dominators::{Dominators, simple_fast};
use petgraph::prelude::*;
use tracing::debug;
use tree_sitter::{Node, Tree};

use crate::labels::{Cap, DataLabel, Kind, classify, lookup};
use std::collections::{HashMap, HashSet};
// WHAT WE STILL NEED TO DO:
// todo: add the cap labels and remove the bit flags after each sanitizer, checking the bit flags with the sink
//
//
// 1.
// We need to analyze the CFG and add function details to the nodes.
// And upload each functions status to a cache with the specific status of the function, for example what source it has, what sink it has, what sanitizer it has, and what taint it has.
//
// 2.
// For each taint from a function we will see if it gets tainted in a function if not, we will add it to a list of potentially tainted functions
// then, after we analyze all the functions, we will see if any of the potentially tainted functions are actually tainted
//
// 3.

// Questions: Do we want to analyze taint on a per function basis as we are building the CFG, or do we want to analyze the whole CFG at once?

/// -------------------------------------------------------------------------
///  Public AST‑to‑CFG data structures
/// -------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq)]
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

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub kind: StmtKind,
    pub span: (usize, usize),     // byte offsets in the original file
    pub label: Option<DataLabel>, // taint classification if any
    pub defines: Option<String>,  // variable written by this stmt
    pub uses: Vec<String>,        // variables read
    pub callee: Option<String>,
}

pub type Cfg = Graph<NodeInfo, EdgeKind>;
pub type FuncSummaries = HashMap<String, (NodeIndex, NodeIndex, Option<DataLabel>)>;

// -------------------------------------------------------------------------
//                      Utility helpers
// -------------------------------------------------------------------------

/// Return the text of a node.
#[inline]
pub(crate) fn text_of<'a>(n: Node<'a>, code: &'a [u8]) -> Option<String> {
    std::str::from_utf8(&code[n.start_byte()..n.end_byte()])
        .ok()
        .map(|s| s.to_string())
}

/// Return the callee identifier for the first call / method / macro inside `n`.
fn first_call_ident<'a>(n: Node<'a>, lang: &str, code: &'a [u8]) -> Option<String> {
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        match lookup(lang, c.kind()) {
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro => {
                // Re-use the same logic we have in `push_node`
                return match lookup(lang, c.kind()) {
                    Kind::CallFn => c
                        .child_by_field_name("function")
                        .and_then(|f| text_of(f, code)),
                    Kind::CallMethod => {
                        let func = c
                            .child_by_field_name("method")
                            .or_else(|| c.child_by_field_name("name"))
                            .and_then(|f| text_of(f, code));
                        let recv = c
                            .child_by_field_name("object")
                            .and_then(|f| text_of(f, code));
                        match (recv, func) {
                            (Some(r), Some(f)) => Some(format!("{r}::{f}")),
                            (_, Some(f)) => Some(f.to_string()),
                            _ => None,
                        }
                    }
                    Kind::CallMacro => c
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

/// Recursively collect every identifier that occurs inside `n`.
fn collect_idents(n: Node, code: &[u8], out: &mut Vec<String>) {
    if n.kind() == "identifier" {
        if let Some(txt) = text_of(n, code) {
            out.push(txt);
        }
    } else {
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            collect_idents(ch, code, out);
        }
    }
}

/// Return `(defines, uses)` for the AST fragment `ast`.
fn def_use(ast: Node, lang: &str, code: &[u8]) -> (Option<String>, Vec<String>) {
    match ast.kind() {
        // `let <pat> = <val>;`
        "let_declaration" => {
            let mut defs = None;
            let mut uses = Vec::new();

            if let Some(pat) = ast.child_by_field_name("pattern") {
                // first identifier inside the pattern = variable name
                let mut tmp = Vec::<String>::new();
                collect_idents(pat, code, &mut tmp);
                defs = tmp.into_iter().next();
            }
            if let Some(val) = ast.child_by_field_name("value") {
                collect_idents(val, code, &mut uses);
            }
            (defs, uses)
        }

        // Plain assignment `x = y  z`
        "assignment_expression" => {
            let mut defs = None;
            let mut uses = Vec::new();
            if let Some(lhs) = ast.child_by_field_name("left") {
                let mut tmp = Vec::<String>::new();
                collect_idents(lhs, code, &mut tmp);
                defs = tmp.pop();
            }
            if let Some(rhs) = ast.child_by_field_name("right") {
                collect_idents(rhs, code, &mut uses);
            }
            (defs, uses)
        }

        // everything else – no definition, but may read vars
        _ => {
            let mut uses = Vec::new();
            collect_idents(ast, code, &mut uses);
            (None, uses)
        }
    }
}

/// Create a node in one short borrow and optionally attach a taint label.
fn push_node<'a>(
    g: &mut Cfg,
    kind: StmtKind,
    ast: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> NodeIndex {
    /* ── 1.  IDENTIFIER EXTRACTION ─────────────────────────────────────── */

    // Primary guess (varies by AST kind)
    let mut text = match lookup(lang, ast.kind()) {
        // plain `foo(bar)` style call
        Kind::CallFn => ast
            .child_by_field_name("function")
            .and_then(|n| text_of(n, code))
            .unwrap_or_default(),

        // method / UFCS call  `recv.method()`  or  `Type::func()`
        Kind::CallMethod => {
            let func = ast
                .child_by_field_name("method")
                .or_else(|| ast.child_by_field_name("name"))
                .and_then(|n| text_of(n, code));
            let recv = ast
                .child_by_field_name("object")
                .and_then(|n| text_of(n, code));
            match (recv, func) {
                (Some(r), Some(f)) => format!("{r}::{f}"),
                (_, Some(f)) => f,
                _ => String::new(),
            }
        }

        // `my_macro!(…)`
        Kind::CallMacro => ast
            .child_by_field_name("macro")
            .and_then(|n| text_of(n, code))
            .unwrap_or_default(),

        // everything else – fallback to raw slice
        _ => text_of(ast, code).unwrap_or_default(),
    };

    // If this is a `let` or `expression_statement` that *contains* a call,
    // prefer the first inner call identifier instead of the whole line.
    if matches!(lookup(lang, ast.kind()), Kind::CallWrapper) {
        if let Some(inner) = first_call_ident(ast, lang, code) {
            text = inner;
        }
    }

    /* ── 2.  LABEL LOOK-UP  ───────────────────────────────────────────── */

    let label = classify(lang, &text);
    let span = (ast.start_byte(), ast.end_byte());

    /* ── 3.  GRAPH INSERTION + DEBUG ──────────────────────────────────── */

    let (defines, uses) = def_use(ast, lang, code);

    let callee = if kind == StmtKind::Call {
        Some(text.clone())
    } else {
        None
    };

    let idx = g.add_node(NodeInfo {
        kind,
        span,
        label,
        defines,
        uses,
        callee,
    });

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
fn connect_all(g: &mut Cfg, froms: &[NodeIndex], to: NodeIndex, kind: EdgeKind) {
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
    ast: Node<'a>,
    preds: &[NodeIndex], // predecessor frontier
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    summaries: &mut FuncSummaries,
) -> Vec<NodeIndex> {
    match lookup(lang, ast.kind()) {
        // ─────────────────────────────────────────────────────────────────
        //  IF‑/ELSE: two branches that re‑merge afterwards
        // ─────────────────────────────────────────────────────────────────
        // todo fix
        Kind::If => {
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
                (blocks.first().copied(), blocks.get(1).copied())
            };

            // THEN branch
            let then_exits = if let Some(b) = then_block {
                let exits = build_sub(b, &[cond], g, lang, code, summaries);
                // True edges leave the condition
                if let Some(&first) = exits.first() {
                    connect_all(g, &[cond], first, EdgeKind::True);
                }
                exits
            } else {
                vec![cond]
            };

            // ELSE branch
            let else_exits = if let Some(b) = else_block {
                let exits = build_sub(b, &[cond], g, lang, code, summaries);
                if let Some(&first) = exits.first() {
                    connect_all(g, &[cond], first, EdgeKind::False);
                }
                exits
            } else {
                // No explicit else → non-taken branch flows to the *then* exits
                if let Some(&first) = then_exits.first() {
                    connect_all(g, &[cond], first, EdgeKind::False);
                }
                then_exits.clone()
            };

            // Frontier = union of both branches
            then_exits.into_iter().chain(else_exits).collect()
        }

        Kind::InfiniteLoop => {
            // Synthetic header node
            let header = push_node(g, StmtKind::Loop, ast, lang, code);
            connect_all(g, preds, header, EdgeKind::Seq);

            // The body is the single `block` child
            let body = ast.child_by_field_name("body").expect("loop without body");
            let body_exits = build_sub(body, &[header], g, lang, code, summaries);

            // Back-edge from every linear exit to header
            for &e in &body_exits {
                connect_all(g, &[e], header, EdgeKind::Back);
            }
            // `loop` may break → those exits are frontiers too
            body_exits.into_iter().chain([header]).collect()
        }

        // ─────────────────────────────────────────────────────────────────
        //  WHILE / FOR: classic loop with a back edge.
        // ─────────────────────────────────────────────────────────────────
        Kind::While | Kind::For => {
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

            let body_exits = build_sub(body, &[header], g, lang, code, summaries);

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
        Kind::Return => {
            let ret = push_node(g, StmtKind::Return, ast, lang, code);
            connect_all(g, preds, ret, EdgeKind::Seq);
            Vec::new() // terminates this path
        }
        Kind::Break => {
            let brk = push_node(g, StmtKind::Break, ast, lang, code);
            connect_all(g, preds, brk, EdgeKind::Seq);
            Vec::new()
        }
        Kind::Continue => {
            let cont = push_node(g, StmtKind::Continue, ast, lang, code);
            connect_all(g, preds, cont, EdgeKind::Seq);
            Vec::new()
        }

        // ─────────────────────────────────────────────────────────────────
        //  BLOCK: statements execute sequentially
        // ─────────────────────────────────────────────────────────────────
        Kind::SourceFile | Kind::Block => {
            let mut cursor = ast.walk();
            let mut frontier = preds.to_vec();
            for child in ast.children(&mut cursor) {
                frontier = build_sub(child, &frontier, g, lang, code, summaries);
            }
            frontier
        }

        // Function item – create a header and dive into its body
        Kind::Function => {
            // 1) create a header node for this fn
            let fn_name = ast
                .child_by_field_name("name")
                .and_then(|n| text_of(n, code))
                .unwrap_or_else(|| "<anon>".to_string());
            let entry_idx = push_node(g, StmtKind::Seq, ast, lang, code);
            connect_all(g, preds, entry_idx, EdgeKind::Seq);

            // 2) build its body
            let body = ast.child_by_field_name("body").expect("fn w/o body");
            let body_exits = build_sub(body, &[entry_idx], g, lang, code, summaries);

            // ───── 3) light-weight dataflow + capture both explicit & implicit returns ─
            let mut var_taint = HashMap::<String, Cap>::new();
            let mut node_bits = HashMap::<NodeIndex, Cap>::new();
            let mut fn_src_bits = Cap::empty();
            let mut fn_sani_bits = Cap::empty();
            let mut fn_sink_bits = Cap::empty();

            // first, sweep *all* nodes in this function and record their out_bits
            for idx in g.node_indices() {
                let info = &g[idx];
                if info.span.0 < ast.start_byte() || info.span.1 > ast.end_byte() {
                    continue;
                }

                // record any explicit sanitizer caps
                if let Some(DataLabel::Sanitizer(bits)) = info.label {
                        fn_sani_bits |= bits;
                    }
                // record any explicit sink caps
                if let Some(DataLabel::Sink(bits)) = info.label {
                        fn_sink_bits |= bits;
                    }
                // record any explicit source caps
                if let Some(DataLabel::Source(bits)) = info.label {
                        fn_src_bits |= bits;
                    }

                //  a) incoming taint from any vars we read
                let mut in_bits = Cap::empty();
                for u in &info.uses {
                    if let Some(b) = var_taint.get(u) {
                        in_bits |= *b;
                    }
                }

                //  b) apply this node’s own label
                let mut out_bits = in_bits;
                if let Some(lab) = &info.label {
                    match *lab {
                        DataLabel::Source(bits) => out_bits |= bits,
                        DataLabel::Sanitizer(bits) => out_bits &= !bits,
                        DataLabel::Sink(_) => { /* no-op */ }
                    }
                }

                //  c) write it back to the var we define (if any)
                if let Some(def) = &info.defines {
                    if out_bits.is_empty() {
                        var_taint.remove(def);
                    } else {
                        var_taint.insert(def.clone(), out_bits);
                    }
                }

                //  d) stash it for later
                node_bits.insert(idx, out_bits);
            }

            // now fold in any *explicit* returns
            for (&idx, &bits) in &node_bits {
                if g[idx].kind == StmtKind::Return {
                    fn_src_bits |= bits;
                }
            }

            // …and *implicit* returns via fall-through from each exit predecessor
            for &pred in &body_exits {
                if let Some(&bits) = node_bits.get(&pred) {
                    fn_src_bits |= bits;
                }
            }

            let fn_label = fn_src_bits
                .is_empty()
                .then(|| None)
                .unwrap_or(Some(DataLabel::Source(fn_src_bits)));

            let fn_summary_label = if !fn_sink_bits.is_empty() {
                Some(DataLabel::Sink(fn_sink_bits))
            } else if !fn_sani_bits.is_empty() {
            Some(DataLabel::Sanitizer(fn_sani_bits))
        } else if !fn_src_bits.is_empty() {
            Some(DataLabel::Source(fn_src_bits))
        } else {
            None
        };

            /* ───── 4) synthesise an explicit exit-node and wire it up ──────────── */
            let exit_idx = g.add_node(NodeInfo {
                kind: StmtKind::Return,
                span: (ast.start_byte(), ast.end_byte()),
                label: None,
                defines: None,
                uses: Vec::new(),
                callee: None,
            });
            for &b in &body_exits {
                connect_all(g, &[b], exit_idx, EdgeKind::Seq);
            }

            /* ───── 5) store the summary – *don’t* overwrite it later! ──────────── */
            summaries.insert(fn_name.clone(), (entry_idx, exit_idx, fn_summary_label));

            vec![exit_idx]
        }

        // Statements that **may** contain a call ---------------------------------
        Kind::CallWrapper => {
            let mut cursor = ast.walk();

            if let Some(inner) = ast.children(&mut cursor).find(|c| {
                matches!(
                    lookup(lang, c.kind()),
                    Kind::InfiniteLoop | Kind::While | Kind::For | Kind::If
                )
            }) {
                return build_sub(inner, preds, g, lang, code, summaries);
            }

            let has_call = ast.children(&mut cursor).any(|c| {
                matches!(
                    lookup(lang, c.kind()),
                    Kind::CallFn | Kind::CallMethod | Kind::CallMacro
                )
            });

            let kind = if has_call {
                StmtKind::Call
            } else {
                StmtKind::Seq
            };
            let node = push_node(g, kind, ast, lang, code);
            connect_all(g, preds, node, EdgeKind::Seq);
            vec![node]
        }

        // Trivia we drop completely ---------------------------------------------
        Kind::Trivia => preds.to_vec(),

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
pub(crate) fn build_cfg<'a>(
    tree: &'a Tree,
    code: &'a [u8],
    lang: &str,
) -> (Cfg, NodeIndex, FuncSummaries) {
    debug!(target: "cfg", "Building CFG for {:?}", tree.root_node());

    let mut g: Cfg = Graph::with_capacity(128, 256);
    let mut summaries = FuncSummaries::new();
    let entry = g.add_node(NodeInfo {
        kind: StmtKind::Entry,
        span: (0, 0),
        label: None,
        defines: None,
        uses: Vec::new(),
        callee: None,
    });
    let exit = g.add_node(NodeInfo {
        kind: StmtKind::Exit,
        span: (code.len(), code.len()),
        label: None,
        defines: None,
        uses: Vec::new(),
        callee: None,
    });

    // Build the body below the synthetic ENTRY.
    let exits = build_sub(
        tree.root_node(),
        &[entry],
        &mut g,
        lang,
        code,
        &mut summaries,
    );
    debug!(target: "cfg", "exits: {:?}", exits);
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
            let unreachable: Vec<_> = g
                .node_indices()
                .filter(|i| !reachable.contains(i))
                .collect();
            debug!(target: "cfg", "‼︎ unreachable nodes: {:?}", unreachable);
        }

        // (Optional) Dominator tree sanity check
        let doms: Dominators<_> = simple_fast(&g, entry);
        debug!(target: "cfg", "dominator tree computed (len = {:?})", doms);
    }

    (g, entry, summaries)
}

pub(crate) fn dump_cfg(g: &Cfg) {
    debug!(target: "taint", "CFG DUMP: nodes = {}, edges = {}", g.node_count(), g.edge_count());
    for idx in g.node_indices() {
        debug!(target: "taint", "  node {:>3}: {:?}", idx.index(), g[idx]);
    }
    for e in g.edge_references() {
        debug!(
            target: "taint",
            "  edge {:>3} → {:<3} ({:?})",
            e.source().index(),
            e.target().index(),
            e.weight()
        );
    }
}
