use crate::patterns::{Pattern, Severity};

pub const PATTERNS: &[Pattern] = &[
  Pattern {
    id: "exec_command",
    description: "os/exec Command construction",
    query: "(call_expression function: (selector_expression field: (field_identifier) @f (#eq? @f \"Command\"))) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "http_insecure_tls",
    description: "&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}",
    query: "(composite_literal type: (selector_expression field: (field_identifier) @t (#eq? @t \"Transport\")) body: (literal_value (keyed_element key: (identifier) @k (#eq? @k \"TLSClientConfig\") value: (composite_literal body: (literal_value (keyed_element key: (identifier) @ik (#eq? @ik \"InsecureSkipVerify\") value: (true)))))) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "unsafe_pointer",
    description: "Use of unsafe.Pointer",
    query: "(qualified_type type: (selector_expression field: (field_identifier) @f (#eq? @f \"Pointer\"))) @vuln",
    severity: Severity::High,
  },
  Pattern {
    id: "md5_sha1",
    description: "crypto/md5 or crypto/sha1 usage",
    query: "(call_expression function: (selector_expression object: (identifier) @pkg (#match? @pkg \"md5|sha1\"))) @vuln",
    severity: Severity::Medium,
  },
  Pattern {
    id: "hardcoded_secret",
    description: "Hard-coded string that looks like an API key/token",
    query: "(interpreted_string_literal) @s (#match? @s \"(?i)(api|secret|token|password)[=:]?[ \\t]*[A-Za-z0-9_\\-]{8,}\")",
    severity: Severity::Low,
  },
];
