mod javascript;
mod rust;

use bitflags::bitflags;
use once_cell::sync::Lazy;
use phf::Map;
use std::collections::HashMap;

/// A single rule: if the AST text equals (or ends with) one of the `matchers`,
/// the node gets `label`.
#[derive(Debug, Clone, Copy)]
pub struct LabelRule {
    pub matchers: &'static [&'static str],
    pub label: DataLabel,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Cap: u8 {
        const ENV_VAR      = 0b0000_0001;
        const HTML_ESCAPE  = 0b0000_0010;
        const SHELL_ESCAPE = 0b0000_0100;
        const URL_ENCODE   = 0b0000_1000;
        const JSON_PARSE   = 0b0001_0000;
        const FILE_IO      = 0b0010_0000;
        // todo: add more if needed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    If,
    InfiniteLoop,
    While,
    For,
    LoopBody,
    CallFn,
    CallMethod,
    CallMacro,
    Break,
    Continue,
    Return,
    Block,
    SourceFile,
    Function,
    Assignment,
    CallWrapper,
    Trivia,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLabel {
    Source(Cap),
    Sanitizer(Cap),
    Sink(Cap),
}

static REGISTRY: Lazy<HashMap<&'static str, &'static [LabelRule]>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("rust", rust::RULES);
    m.insert("rs", rust::RULES);

    m.insert("javascript", javascript::RULES);
    m.insert("js", javascript::RULES);

    // add more languages in one line:
    // m.insert("go", go::RULES);

    m
});

type FastMap = &'static Map<&'static str, Kind>;

pub(crate) static CLASSIFIERS: Lazy<HashMap<&'static str, FastMap>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("rust", &rust::KINDS);
    m.insert("rs", &rust::KINDS);

    // m.insert("javascript",  &javascript::KINDS);
    // m.insert("js",          &javascript::KINDS);

    // todo: add more languages
    m
});

#[inline(always)]
pub fn lookup(lang: &str, raw: &str) -> Kind {
    CLASSIFIERS
        .get(lang)
        .and_then(|m| m.get(raw).copied())
        .unwrap_or(Kind::Other)
}

/// Try to classify a piece of syntax text.
/// `lang` is the canonicalised language key (“rust”, “javascript”, …).
pub fn classify(lang: &str, text: &str) -> Option<DataLabel> {
    let key = lang.to_ascii_lowercase();
    let rules = REGISTRY.get(key.as_str())?;
    let head = text.split(['(', '<']).next().unwrap_or("");

    let text_lc = head.trim().to_ascii_lowercase();

    for rule in *rules {
        for raw in rule.matchers {
            let m = raw.to_ascii_lowercase();

            if m.ends_with('_') {
                if text_lc.starts_with(&m) {
                    return Some(rule.label);
                }
            } else if text_lc.ends_with(&m) {
                let start = text_lc.len() - m.len();
                let ok = start == 0 || matches!(text_lc.as_bytes()[start - 1], b'.' | b':');
                if ok {
                    return Some(rule.label);
                }
            }
        }
    }
    None
}
