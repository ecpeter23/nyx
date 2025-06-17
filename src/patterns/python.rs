use crate::patterns::{Pattern, Severity};

pub const PATTERNS: &[Pattern] = &[
  Pattern {
    id: "eval_call",
    description: "eval() on dynamic input",
    query: "(call function: (identifier) @id (#eq? @id \"eval\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "exec_call",
    description: "exec(...) execution of dynamic code",
    query: "(call function: (identifier) @id (#eq? @id \"exec\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "subprocess_shell_true",
    description: "subprocess.* with shell=True",
    query: "(call function: (attribute object: (identifier) @pkg (#eq? @pkg \"subprocess\")) arguments: (argument_list . (keyword_argument name: (identifier) @k (#eq? @k \"shell\")) (true) @val)) @vuln",
    severity: Severity::Medium,
  }
];
