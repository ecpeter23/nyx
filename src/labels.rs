use once_cell::sync::Lazy;
use std::collections::HashMap;

use crate::cfg::DataLabel;

/// A single rule: if the AST text equals (or ends with) one of the `matchers`,
/// the node gets `label`.
#[derive(Debug, Clone, Copy)]
pub struct LabelRule {
  pub matchers: &'static [&'static str],
  pub label:    DataLabel<'static>,
}

/* ----------  per-language rule tables  ---------- */

pub mod rust {
  use super::*;

  ///   • `Source`  = untrusted data entering the program
  ///   • `Sink`    = potentially dangerous APIs that consume that data
  ///   • `Sanitizer` = escapes / validators that make data safe
  pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
      matchers: &["std::env::var", "env::var"],
      label:    DataLabel::Source("env-var"),
    },

    // ───────── Sanitizers ──────────
    LabelRule {
      matchers: &["html_escape::encode_safe"],
      label:    DataLabel::Sanitizer("html-escape"),
    },

    // ─────────── Sinks ─────────────
    //  All the key points where untrusted strings reach the OS shell.
    LabelRule {
      matchers: &[
        "command::new",
        "std::process::command::new",
        "command::arg",
        "command::args",
        "command::status",
        "command::output",
      ],
      label:    DataLabel::Sink("process-spawn"),
    },
  ];
}

pub mod javascript {
  use super::*;
  pub static RULES: &[LabelRule] = &[
    LabelRule { matchers: &["document.location", "window.location"], label: DataLabel::Source("url-param") },
    LabelRule { matchers: &["JSON.parse"],       label: DataLabel::Sanitizer("json-parse") },
    LabelRule { matchers: &["eval"],             label: DataLabel::Sink("eval-call") },
  ];
}

/* ----------  global registry identical to the pattern registry ---------- */

static REGISTRY: Lazy<HashMap<&'static str, &'static [LabelRule]>> = Lazy::new(|| {
  let mut m = HashMap::new();
  m.insert("rust", rust::RULES);
  m.insert("rs",   rust::RULES);

  m.insert("javascript", javascript::RULES);
  m.insert("js",         javascript::RULES);

  // add more languages in one line:
  // m.insert("go", go::RULES);

  m
});

/// Try to classify a piece of syntax text.
/// `lang` is the canonicalised language key (“rust”, “javascript”, …).
pub fn classify<'a>(lang: &str, text: &str) -> Option<DataLabel<'a>> {
  let key     = lang.to_ascii_lowercase();
  let rules   = REGISTRY.get(key.as_str())?;
  let head    = text.split(|c| c == '(' || c == '<')
    .next().unwrap_or("");

  let text_lc = head.trim().to_ascii_lowercase();

  for rule in *rules {
    for raw in rule.matchers {
      let m = raw.to_ascii_lowercase();

      if text_lc.ends_with(&m) {
        let start = text_lc.len() - m.len();     
        let ok = start == 0              
          || matches!(text_lc.as_bytes()[start - 1], b'.' | b':');

        if ok {
          return Some(rule.label);     
        }
      }
    }
}
  None
}

