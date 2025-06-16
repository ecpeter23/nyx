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
    id: "pickle_load",
    description: "pickle.load / loads – unsafe deserialization",
    query: "(call function: (attribute attribute: (identifier) @attr (#match? @attr \"load(s)?\") object: (identifier) @pkg (#eq? @pkg \"pickle\"))) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "subprocess_shell_true",
    description: "subprocess.* with shell=True",
    query: "(call function: (attribute object: (identifier) @pkg (#eq? @pkg \"subprocess\")) arguments: (argument_list . (keyword_argument name: (identifier) @k (#eq? @k \"shell\")) (true) @val)) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "random_random",
    description: "random.random() for security-sensitive randomness",
    query: "(call function: (attribute attribute: (identifier) @attr (#eq? @attr \"random\") object: (identifier) @pkg (#eq? @pkg \"random\"))) @vuln",
    severity: Severity::Low,
  },
  Pattern {
    id: "sql_concat",
    description: "SQL query built via f-string or +-concat",
    query: "(call function: (attribute attribute: (identifier) @m (#match? @m \"execute|executemany\")) arguments: (argument_list (f_string) @fstr)) @vuln",
    severity: Severity::Medium,
  },
];
