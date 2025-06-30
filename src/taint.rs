use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use petgraph::graph::NodeIndex;
use tracing::debug;
use tree_sitter::Node;
use crate::cfg::{build_cfg, Cfg, NodeInfo, StmtKind};
use crate::labels::DataLabel;

fn set_hash(s: &HashSet<String>) -> u64 {
    let mut v: Vec<_> = s.iter().collect();
    v.sort(); // deterministic
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

fn apply_taint(node: &NodeInfo, taint: &HashSet<String>) -> HashSet<String> {
    debug!(target: "taint", "Applying taint to node: {:?}", node);
    debug!(target: "taint", "Taint: {:?}", taint);
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

pub fn analyse_file(cfg: &Cfg, entry: NodeIndex) -> Vec<Vec<NodeIndex>> {
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry);

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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry);

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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry);
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry);
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry);
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry);
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

    let (cfg, entry, summaries) = build_cfg(&tree, src, "rust");
    let findings = analyse_file(&cfg, entry);
    assert!(findings.is_empty());
}