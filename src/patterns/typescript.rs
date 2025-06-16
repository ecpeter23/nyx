use crate::patterns::{Pattern, Severity};

pub const PATTERNS: &[Pattern] = &[
  Pattern {
    id: "eval_call",
    description: "Use of eval()",
    query: "(call_expression function: (identifier) @id (#eq? @id \"eval\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "new_function",
    description: "new Function() constructor",
    query: "(new_expression constructor: (identifier) @id (#eq? @id \"Function\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "document_write",
    description: "document.write() call",
    query: "(call_expression function: (member_expression object: (identifier) @obj (#eq? @obj \"document\") property: (property_identifier) @prop (#eq? @prop \"write\"))) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "inner_html_assignment",
    description: "Assignment to element.innerHTML",
    query: "(assignment_expression left: (member_expression property: (property_identifier) @prop (#eq? @prop \"innerHTML\"))) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "settimeout_string",
    description: "setTimeout / setInterval with a string argument",
    query: "(call_expression function: (identifier) @id (#match? @id \"setTimeout|setInterval\") arguments: (arguments (string) @code . _)) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "any_type",
    description: "Type annotation of `any`",
    query: "(type_annotation (predefined_type) @t (#eq? @t \"any\")) @vuln",
    severity: Severity::Low,
  },
  Pattern {
    id: "json_parse",
    description: "JSON.parse on dynamic string",
    query: "(call_expression function: (member_expression object: (identifier) @obj (#eq? @obj \"JSON\") property: (property_identifier) @prop (#eq? @prop \"parse\"))) @vuln",
    severity: Severity::Low,
  },
];