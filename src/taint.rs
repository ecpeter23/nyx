use crate::cfg::{Cfg, FuncSummaries, NodeInfo, StmtKind, build_cfg};
use crate::labels::{Cap, DataLabel};
use petgraph::graph::NodeIndex;
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use tracing::debug;

fn set_hash(s: &HashSet<String>) -> u64 {
    let mut v: Vec<_> = s.iter().collect();
    v.sort(); // deterministic
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}
fn taint_hash(taint: &HashMap<String, Cap>) -> u64 {
    let mut v: Vec<_> = taint.iter().collect();
    v.sort_by_key(|(k,_)| k.clone());
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for (k, bits) in v {
        k.hash(&mut h);
        bits.bits().hash(&mut h);
    }
    h.finish()
}

fn apply_taint(
    node: &NodeInfo,
    taint: &HashMap<String, Cap>,
    summaries: &FuncSummaries,
) -> HashMap<String, Cap> {
    debug!(target: "taint", "Applying taint to node: {:?}", node);
    debug!(target: "taint", "Taint: {:?}", taint);
    let mut out = taint.clone();

    match node.label {
        // A new untrusted value enters the program
        Some(DataLabel::Source(bits)) => {
            if let Some(v) = &node.defines {
                out.insert(v.clone(), bits);
            }
        }
        // Anything written by a sanitizer becomes clean – whatever its
        // arguments were is irrelevant here.
        Some(DataLabel::Sanitizer(bits)) => {
            if let Some(v) = &node.defines {
                if let Some(existing) = out.get(v) {
                    let new = *existing & !bits;
                    if new.is_empty() { out.remove(v); }
                    else             { out.insert(v.clone(), new); }
                }
            }
        }

        // A function call *returning* tainted/clean data ----------------------
        // (`let v = source_*()` or `let v = sanitize_*(x)`)
        _ if node.kind == StmtKind::Call => {
            if let Some(callee) = &node.callee {
                if let Some((_, _, Some(label))) = summaries.get(callee) {
                    match *label {
                        DataLabel::Source(bits) => {
                            if let Some(v) = &node.defines {
                                out.insert(v.clone(), bits);
                            }
                        }
                        DataLabel::Sanitizer(bits) => {
                            if let Some(v) = &node.defines {
                                if let Some(existing) = out.get(v) {
                                    let new = *existing & !bits;
                                    if new.is_empty() { out.remove(v); }
                                    else             { out.insert(v.clone(), new); }
                                }
                            }
                        }
                        DataLabel::Sink(_) => {
                            // calling this function is itself a sink
                            // if any of its args were tainted, report
                            // todo
                        }
                    }
                    return out;
                }
            }
        }

        // All other statements: classic gen/kill for assignments
        _ => {
            if let Some(d) = &node.defines {
                let mut combined = Cap::empty();
                for u in &node.uses {
                    if let Some(bits) = out.get(u) {
                        combined |= *bits;
                    }
                }
                if combined.is_empty() {
                    out.remove(d);
                } else {
                    out.insert(d.clone(), combined);
                }
            }
        }
    }

    out
}

pub fn analyse_file(cfg: &Cfg, entry: NodeIndex, summaries: &FuncSummaries) -> Vec<Vec<NodeIndex>> {
    use std::collections::{HashMap, HashSet, VecDeque};

    /// Queue item: current CFG node + taint map that holds here
    #[derive(Clone)]
    struct Item {
        node: NodeIndex,
        taint: HashMap<String, Cap>,
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
        taint: HashMap::new(),
    });
    seen.insert((entry, 0));

    while let Some(Item{node, taint}) = q.pop_front() {
        let out = apply_taint(&cfg[node], &taint, summaries);

        // if this node *is* a sink‐call, check it:
        if let Some(DataLabel::Sink(sink_caps)) = cfg[node].label {
            // did any arg still carry any sink bit?
            let bad = cfg[node].uses.iter()
                .any(|u| out.get(u).map_or(false, |b| (*b & sink_caps) != Cap::empty()));
            if bad {
                // reconstruct path back to some prior Source
                let mut path = vec![node];
                let mut key = (node, taint_hash(&taint));
                while let Some(&(prev, prev_hash)) = pred.get(&key) {
                    path.push(prev);
                    if matches!(cfg[prev].label, Some(DataLabel::Source(_))) {
                        break;
                    }
                    key = (prev, prev_hash);
                }
                path.reverse();
                findings.push(path);
            }
        }

        // enqueue successors
        for succ in cfg.neighbors(node) {
            let h = taint_hash(&out);
            let key = (succ, h);
            if !seen.contains(&key) {
                seen.insert(key);
                pred.insert(key, (node, taint_hash(&taint)));
                let item = Item {
                    node: succ,
                    taint: out.clone(),
                };
                q.push_back(item);
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
    let findings = analyse_file(&cfg, entry, &summaries);

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
    let findings = analyse_file(&cfg, entry, &summaries);

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
    let findings = analyse_file(&cfg, entry, &summaries);
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
    let findings = analyse_file(&cfg, entry, &summaries);
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
    let findings = analyse_file(&cfg, entry, &summaries);
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
    let findings = analyse_file(&cfg, entry, &summaries);
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
    let findings = analyse_file(&cfg, entry, &summaries);
    assert!(findings.is_empty());
}
