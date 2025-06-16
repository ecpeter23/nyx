use crate::patterns::{Pattern, Severity};

pub const PATTERNS: &[Pattern] = &[
  Pattern {
    id: "runtime_exec",
    description: "Runtime.getRuntime().exec(...) – arbitrary-command execution",
    query: "(method_invocation object: (method_invocation name: (identifier) @n (#eq? @n \"getRuntime\")) name: (identifier) @id (#eq? @id \"exec\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "class_for_name",
    description: "Dynamic reflection via Class.forName(...)",
    query: "(method_invocation object: (identifier) @c (#eq? @c \"Class\") name: (identifier) @id (#eq? @id \"forName\")) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "object_deserialization",
    description: "java.io.ObjectInputStream#readObject() deserialization",
    query: "(method_invocation object: (identifier) @o (#eq? @o \"ObjectInputStream\") name: (identifier) @id (#eq? @id \"readObject\")) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "insecure_random",
    description: "java.util.Random used where SecureRandom is expected",
    query: "(object_creation_expression type: (identifier) @t (#eq? @t \"Random\")) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "thread_stop",
    description: "Deprecated Thread.stop() invocation",
    query: "(method_invocation name: (identifier) @id (#eq? @id \"stop\") object: (identifier) @obj (#eq? @obj \"Thread\")) @vuln",
    severity: Severity::Low,
  },
  Pattern {
    id: "sql_concat",
    description: "SQL built with string concatenation",
    query: "(method_invocation name: (identifier) @id (#match? @id \"execute(Query|Update)?\") arguments: (argument_list (binary_expression) @concat)) @vuln",
    severity: Severity::Medium,
  },
];
