use crate::patterns::{Pattern, Severity};

/// The full catalogue.
///
/// *Feel free to prune, extend, or tweak severities to suit your own threat
/// model.*
pub const PATTERNS: &[Pattern] = &[
  Pattern {
    id: "unsafe_block",
    description: "Use of an `unsafe` block",
    query: "(unsafe_block) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "unsafe_fn",
    description: "`unsafe fn` declaration",
    query: "(function_item (modifier) @kw (#eq? @kw \"unsafe\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "unwrap_call",
    description: "`.unwrap()` call (may panic)",
    query: "(call_expression function: (field_expression field: (field_identifier) @name (#eq? @name \"unwrap\"))) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "expect_call",
    description: "`.expect()` call (may panic)",
    query: "(call_expression function: (field_expression field: (field_identifier) @name (#eq? @name \"expect\"))) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "panic_macro",
    description: "`panic!` macro invocation",
    query: "(macro_invocation (identifier) @id (#eq? @id \"panic\")) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "todo_or_unimplemented",
    description: "`todo!()` / `unimplemented!()` placeholder",
    query: "(macro_invocation (identifier) @id (#match? @id \"todo|unimplemented\")) @vuln",
    severity: Severity::Low,
  },
  Pattern {
    id: "transmute_call",
    description: "`std::mem::transmute` call",
    query: "(call_expression function: (scoped_identifier path: (identifier) @p (#eq? @p \"mem\") name: (identifier) @f (#eq? @f \"transmute\"))) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "get_unchecked",
    description: "`get_unchecked` or `get_unchecked_mut` slice access",
    query: "(call_expression function: (field_expression field: (field_identifier) @m (#match? @m \"get_unchecked(_mut)?\"))) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "copy_nonoverlapping",
    description: "Raw pointer `copy_nonoverlapping`",
    query: "(call_expression function: (scoped_identifier path: (identifier) @p (#eq? @p \"ptr\") name: (identifier) @f (#eq? @f \"copy_nonoverlapping\"))) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "narrow_cast_with_as",
    description: "`as` cast to an 8-/16-bit integer (possible truncation)",
    query: "(as_expression left: (_) right: (primitive_type) @to (#match? @to \"u8|i8|u16|i16\")) @vuln",
    severity: Severity::Low,
  },
];
