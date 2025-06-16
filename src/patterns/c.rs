use crate::patterns::{Pattern, Severity};

pub const PATTERNS: &[Pattern] = &[
  Pattern {
    id: "strcpy_call",
    description: "strcpy() usage",
    query: "(call_expression function: (identifier) @id (#eq? @id \"strcpy\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "strcat_call",
    description: "strcat() usage",
    query: "(call_expression function: (identifier) @id (#eq? @id \"strcat\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "sprintf_call",
    description: "sprintf() (no length limit)",
    query: "(call_expression function: (identifier) @id (#eq? @id \"sprintf\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "gets_call",
    description: "gets() usage",
    query: "(call_expression function: (identifier) @id (#eq? @id \"gets\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "scanf_with_percent_s",
    description: "scanf(\"%s\") without length specifier",
    query: "(call_expression function: (identifier) @id (#eq? @id \"scanf\") arguments: (argument_list (string_literal) @fmt (#match? @fmt \".*%s.*\"))) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "system_call",
    description: "system() shell execution",
    query: "(call_expression function: (identifier) @id (#eq? @id \"system\")) @vuln",
    severity: Severity::Medium,
  },
];
