use crate::labels::{Cap, DataLabel, LabelRule};

pub static RULES: &[LabelRule] = &[
  // ─────────── Sources ───────────
  LabelRule {
    matchers: &["std::env::var", "env::var"],
    label:    DataLabel::Source(Cap::all()),
  },

  // ───────── Sanitizers ──────────
  // `fn sanitize_*(&str) -> String`
  LabelRule {
    matchers: &["html_escape::encode_safe", "sanitize_", "sanitize_html"],
    label:    DataLabel::Sanitizer(Cap::HTML_ESCAPE),
  },
  LabelRule {
    matchers: &["shell_escape::unix::escape"],
    label:    DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
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
    label:    DataLabel::Sink(Cap::SHELL_ESCAPE),
  },
];