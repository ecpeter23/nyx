use crate::labels::{Cap, DataLabel, LabelRule};
use crate::labels::syntax::{Kind};
use phf::{phf_map, Map};

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

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_expression"        => Kind::If,
    "loop_expression"      => Kind::InfiniteLoop,
    "loop_statement"       => Kind::LoopBody,
    "while_statement"      => Kind::While,
    "for_statement"        => Kind::For,

    "return_statement"     => Kind::Return,
    "break_expression"     => Kind::Break,
    "break_statement"      => Kind::Break,
    "continue_expression"  => Kind::Continue,
    "continue_statement"   => Kind::Continue,

    // structure
    "source_file"          => Kind::SourceFile,
    "block"                => Kind::Block,
    "function_item"        => Kind::Function,

    // data-flow
    "call_expression"        => Kind::CallFn,
    "method_call_expression" => Kind::CallMethod,
    "macro_invocation"       => Kind::CallMacro,
    "let_declaration"        => Kind::CallWrapper,
    "expression_statement"   => Kind::CallWrapper,
    "assignment_expression"  => Kind::Assignment,

    // trivia
    "line_comment"     => Kind::Trivia,
    "block_comment"    => Kind::Trivia,
    ";" => Kind::Trivia, "," => Kind::Trivia,
    "(" => Kind::Trivia, ")" => Kind::Trivia,
    "{" => Kind::Trivia, "}" => Kind::Trivia, "\n" => Kind::Trivia,
    "use_declaration"  => Kind::Trivia,
    "attribute_item"   => Kind::Trivia,
    "mod_item"         => Kind::Trivia,
    "type_item"        => Kind::Trivia,
};
