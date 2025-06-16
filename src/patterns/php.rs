use crate::patterns::{Pattern, Severity};

pub const PATTERNS: &[Pattern] = &[
  Pattern {
    id: "eval_call",
    description: "eval($code) execution",
    query: "(function_call_expression function: (name) @n (#eq? @n \"eval\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "preg_replace_e",
    description: "preg_replace with deprecated /e modifier",
    query: "(function_call_expression function: (name) @n (#eq? @n \"preg_replace\") arguments: (arguments (string) @pat (#match? @pat \"/.*e.*$/\"))) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "create_function",
    description: "create_function(...) anonymous eval-like",
    query: "(function_call_expression function: (name) @n (#eq? @n \"create_function\")) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "unserialize_call",
    description: "unserialize(...) on user input",
    query: "(function_call_expression function: (name) @n (#eq? @n \"unserialize\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "mysql_query_concat",
    description: "mysql_query with concatenated SQL",
    query: "(function_call_expression function: (name) @n (#eq? @n \"mysql_query\") arguments: (arguments (binary_expression) @concat)) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "system_call",
    description: "system()/shell_exec()/exec() command execution",
    query: "(function_call_expression function: (name) @n (#match? @n \"system|shell_exec|exec|passthru\")) @vuln",
    severity: Severity::Medium,
  },
];
