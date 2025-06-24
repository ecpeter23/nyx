use crate::patterns::{Pattern, Severity};

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
        query: "(function_item
               (function_modifiers) @mods
               (#match? @mods \"^unsafe\\b\")) @vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "transmute_call",
        description: "`std::mem::transmute` call",
        query: "(call_expression
                  function: (scoped_identifier
                              path: (identifier) @p (#eq? @p \"mem\")
                              name: (identifier) @f (#eq? @f \"transmute\")))
                @vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "copy_nonoverlapping",
        description: "Raw pointer `copy_nonoverlapping`",
        query: "(call_expression
                  function: (scoped_identifier
                              path: (identifier) @p (#eq? @p \"ptr\")
                              name: (identifier) @f (#eq? @f \"copy_nonoverlapping\")))
                @vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "get_unchecked",
        description: "`get_unchecked` / `get_unchecked_mut` slice access",
        query: "(call_expression
                  function: (field_expression
                              field: (field_identifier) @m
                              (#match? @m \"get_unchecked(_mut)?\"))) @vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "unwrap_call",
        description: "`.unwrap()` call (may panic)",
        query: "(call_expression
              function: (field_expression
                          field: (field_identifier) @name
                          (#eq? @name \"unwrap\")))   ; exact match
            @vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "expect_call",
        description: "`.expect()` call (may panic)",
        query: "(call_expression
                  function: (field_expression
                              field: (field_identifier) @name
                              (#eq? @name \"expect\"))) @vuln",
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
        query: "(macro_invocation
                  (identifier) @id
                  (#match? @id \"todo|unimplemented\")) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "narrow_cast_with_as",
        description: "`as` cast to an 8-/16-bit integer (possible truncation)",
        query: "(type_cast_expression
                  type: (primitive_type) @to
                  (#match? @to \"^u?i(8|16)$\")) @vuln",
        severity: Severity::Low,
    },
    Pattern {
        id: "mem_zeroed",
        description: "`std::mem::zeroed()`",
        query: "(call_expression function:(scoped_identifier path:(identifier)@p (#eq? @p \"mem\") name:(identifier)@n (#eq? @n \"zeroed\")))@vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "mem_forget",
        description: "`std::mem::forget()`",
        query: "(call_expression function:(scoped_identifier path:(identifier)@p (#eq? @p \"mem\") name:(identifier)@n (#eq? @n \"forget\")))@vuln",
        severity: Severity::Medium,
    },
    Pattern {
        id: "ptr_read",
        description: "`ptr::read_*` raw-ptr read",
        query: "(call_expression function:(scoped_identifier path:(identifier)@p (#eq? @p \"ptr\") name:(identifier)@n (#match? @n \"read(_volatile)?\")))@vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "arc_unwrap",
        description: "`Arc::unwrap_or_else_unchecked`",
        query: "(call_expression function:(scoped_identifier name:(identifier)@n (#eq? @n \"unwrap_or_else_unchecked\")))@vuln",
        severity: Severity::High,
    },
    Pattern {
        id: "dbg_macro",
        description: "`dbg!()` left in code",
        query: "(macro_invocation (identifier)@id (#eq? @id \"dbg\"))@vuln",
        severity: Severity::Low,
    },
];
