use petgraph::algo::dominators::{Dominators, simple_fast};
use petgraph::prelude::*;
use tracing::debug;
use tree_sitter::{Node, Tree};

use crate::labels::{DataLabel, Kind, classify, lookup};
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};

/// WHAT WE STILL NEED TO DO:
/// todo: add the cap labels and remove the bit flags after each sanitizer, checking the bit flags with the sink
///
///
/// 1.
/// We need to analyze the CFG and add function details to the nodes.
/// And upload each functions status to a cache with the specific status of the function, for example what source it has, what sink it has, what sanitizer it has, and what taint it has.
///
/// 2.
/// For each taint from a function we will see if it gets tainted in a function if not, we will add it to a list of potentially tainted functions
/// then, after we analyze all the functions, we will see if any of the potentially tainted functions are actually tainted
///
/// 3.
///

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
}

pub type Cfg = Graph<NodeInfo, EdgeKind>;

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
        if let Some(inner) = first_call_ident(ast, &lang, code) {
            text = inner;
        }
    }

    /* ── 2.  LABEL LOOK-UP  ───────────────────────────────────────────── */

    let label = classify(lang, &text);
    let span = (ast.start_byte(), ast.end_byte());

    /* ── 3.  GRAPH INSERTION + DEBUG ──────────────────────────────────── */

    let (defines, uses) = def_use(ast, code);

    let idx = g.add_node(NodeInfo {
        kind,
        span,
        label,
        defines,
        uses,
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
fn connect_all<'a>(g: &mut Cfg, froms: &[NodeIndex], to: NodeIndex, kind: EdgeKind) {
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
) -> Vec<NodeIndex> {
    match lookup(lang, ast.kind()) {
        // ─────────────────────────────────────────────────────────────────
        //  IF‑/ELSE: two branches that re‑merge afterwards
        // ─────────────────────────────────────────────────────────────────
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
                (blocks.get(0).copied(), blocks.get(1).copied())
            };

            // THEN branch
            let then_exits = if let Some(b) = then_block {
                let exits = build_sub(b, &[cond], g, lang, code);
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
                let exits = build_sub(b, &[cond], g, lang, code);
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
            let body_exits = build_sub(body, &[header], g, lang, code);

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
                frontier = build_sub(child, &frontier, g, lang, code);
            }
            frontier
        }

        // Function item – create a header and dive into its body
        Kind::Function => {
            let header = push_node(g, StmtKind::Seq, ast, lang, code);
            connect_all(g, preds, header, EdgeKind::Seq);

            if let Some(body) = ast.child_by_field_name("body") {
                build_sub(body, &[header], g, lang, code)
            } else {
                vec![header] // declaration w/o body
            }
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
                return build_sub(inner, preds, g, lang, code);
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
        // "line_comment" | "block_comment"
        // | ";" | "," | "(" | ")" | "{" | "}" | "\n"
        // | "use_declaration"
        // | "attribute_item"
        // | "mod_item" | "type_item"
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
pub(crate) fn build_cfg<'a>(tree: &'a Tree, code: &'a [u8], lang: &str) -> (Cfg, NodeIndex) {
    debug!(target: "cfg", "Building CFG for {:?}", tree.root_node());

    let mut g: Cfg = Graph::with_capacity(128, 256);
    let entry = g.add_node(NodeInfo {
        kind: StmtKind::Entry,
        span: (0, 0),
        label: None,
        defines: None,
        uses: Vec::new(),
    });
    let exit = g.add_node(NodeInfo {
        kind: StmtKind::Exit,
        span: (code.len(), code.len()),
        label: None,
        defines: None,
        uses: Vec::new(),
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

    (g, entry)
}

/* ---------- TAINT-ANALYSIS PASSES ---------- */
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
fn def_use(ast: Node, code: &[u8]) -> (Option<String>, Vec<String>) {
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

        // Plain assignment `x = y + z`
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

fn set_hash(s: &HashSet<String>) -> u64 {
    let mut v: Vec<_> = s.iter().collect();
    v.sort(); // deterministic
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

fn apply_taint<'a>(node: &NodeInfo, taint: &HashSet<String>) -> HashSet<String> {
    let mut out = taint.clone();

    match node.label {
        // A new untrusted value enters the program
        Some(DataLabel::Source(_)) => {
            if let Some(d) = &node.defines {
                out.insert(d.clone());
            }
        }
        // Anything written by a sanitizer becomes clean – whatever its
        // arguments were is irrelevant here.
        Some(DataLabel::Sanitizer(_)) => {
            if let Some(d) = &node.defines {
                out.remove(d);
            }
        }

        // A function call *returning* tainted/clean data ----------------------
        // (`let v = source_*()` or `let v = sanitize_*(x)`)
        _ if node.kind == StmtKind::Call => {
            if let Some(d) = &node.defines {
                match node.label {
                    Some(DataLabel::Source(_)) => {
                        out.insert(d.clone());
                    } // gen
                    Some(DataLabel::Sanitizer(_)) => {
                        out.remove(d);
                    } // kill
                    _ => { /* normal flow handled below */ }
                }
            }
        }

        // All other statements: classic gen/kill for assignments
        _ => {
            if let Some(d) = &node.defines {
                let rhs_tainted = node.uses.iter().any(|u| out.contains(u));
                if rhs_tainted {
                    out.insert(d.clone());
                } else {
                    out.remove(d);
                }
            }
        }
    }

    out
}

pub fn analyse_function(cfg: &Cfg, entry: NodeIndex) -> Vec<Vec<NodeIndex>> {
    use std::collections::{HashMap, HashSet, VecDeque};

    /// Queue item: current CFG node + taint map that holds here
    #[derive(Clone)]
    struct Item {
        node: NodeIndex,
        taint: HashSet<String>,
    }

    // (node, taint_hash)  →  predecessor key   (for path rebuild)
    type Key = (NodeIndex, u64);
    let mut pred: HashMap<Key, Key> = HashMap::new();

    // Seen states so we do not revisit them infinitely
    let mut seen: HashSet<Key> = HashSet::new();

    // Resulting Source→Sink paths
    let mut findings: Vec<Vec<NodeIndex>> = Vec::new();

    let mut q = VecDeque::new();
    q.push_back(Item {
        node: entry,
        taint: HashSet::new(),
    });
    seen.insert((entry, 0));

    while let Some(Item { node, taint }) = q.pop_front() {
        let updated = apply_taint(&cfg[node], &taint); // step effect

        /* ----------     SINK CHECK     ---------- */
        if let Some(DataLabel::Sink(_)) = cfg[node].label {
            if cfg[node].uses.iter().any(|u| updated.contains(u)) {
                // reconstruct path back to *any* Source
                let mut p: Vec<NodeIndex> = vec![node];
                let mut k = (node, set_hash(&taint)); // predecessor key

                while let Some(&(prev, _)) = pred.get(&k) {
                    p.push(prev);
                    if matches!(cfg[prev].label, Some(DataLabel::Source(_))) {
                        break;
                    }
                    // climb further
                    let prev_hash = pred.get(&k).map(|(_, h)| *h).unwrap_or(0);
                    k = (prev, prev_hash);
                }
                p.reverse();
                findings.push(p);
            }
        }

        /* ----------   BFS successor step   ---------- */
        for succ in cfg.neighbors(node) {
            let key = (succ, set_hash(&updated));
            if !seen.contains(&key) {
                seen.insert(key);
                pred.insert(key, (node, set_hash(&taint)));
                q.push_back(Item {
                    node: succ,
                    taint: updated.clone(),
                });
            }
        }
    }

    findings
}

#[test]
fn env_to_arg_is_flagged() {
    use tree_sitter::Language;
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS_ARG").unwrap();
            Command::new("sh").arg(x).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry) = build_cfg(&tree, src, "rust");
    let findings = analyse_function(&cfg, entry);

    assert_eq!(findings.len(), 1); // exactly one unsanitised Source→Sink
}

#[test]
fn taint_through_if_else() {
    use tree_sitter::Language;
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
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry) = build_cfg(&tree, src, "rust");
    let findings = analyse_function(&cfg, entry);

    // exactly one path (via the True branch) should be flagged
    assert_eq!(findings.len(), 1);
}

#[test]
fn taint_through_while_loop() {
    use tree_sitter::Language;
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
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry) = build_cfg(&tree, src, "rust");
    let findings = analyse_function(&cfg, entry);
    assert_eq!(findings.len(), 1);
}

#[test]
fn taint_killed_by_sanitizer() {
    use tree_sitter::Language;
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = html_escape::encode_safe(&x);    // sanitizer node
            Command::new("sh").arg(clean).status().unwrap();  // SAFE
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry) = build_cfg(&tree, src, "rust");
    let findings = analyse_function(&cfg, entry);
    assert!(findings.is_empty());
}

#[test]
fn taint_breaks_out_of_loop() {
    use tree_sitter::Language;
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
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry) = build_cfg(&tree, src, "rust");
    let findings = analyse_function(&cfg, entry);
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_two_sources() {
    use tree_sitter::Language;
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let y = env::var("SAFE").unwrap();
            let clean = html_escape::encode_safe(&y);
            Command::new("sh").arg(x).status().unwrap();
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry) = build_cfg(&tree, src, "rust");
    let findings = analyse_function(&cfg, entry);
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_should_not_panic_on_empty_function() {
    use tree_sitter::Language;
    let src = br#"
        use std::{env, process::Command};
        fn f() {
            if cond() {
                return;
            }
            do_something();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let (cfg, entry) = build_cfg(&tree, src, "rust");
    let findings = analyse_function(&cfg, entry);
    assert!(findings.is_empty());
}
