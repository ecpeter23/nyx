use crate::patterns::{Pattern, Severity};
pub const PATTERNS: &[Pattern] = &[
    // ---------- Runtime code-execution primitives ----------
    Pattern {
        id: "eval_call",
        description: "Kernel#eval usage",
        query: r#"
          (call
            (identifier) @id
            (#eq? @id "eval")
          ) @vuln
        "#,
        severity: Severity::High,
    },
    Pattern {
        id: "instance_eval_call",
        description: "Object#instance_eval usage",
        query: r#"
          (call
            (identifier) @id
            (#eq? @id "instance_eval")
          ) @vuln
        "#,
        severity: Severity::High,
    },
    Pattern {
        id: "class_eval_call",
        description: "Module#class_eval / module_eval usage",
        query: r#"
          (call
            (identifier) @id
            (#match? @id "^(class_eval|module_eval)$")
          ) @vuln
        "#,
        severity: Severity::High,
    },
    // ---------- Shell execution ----------
    Pattern {
        id: "system_exec_interp",
        description: "system/exec with string interpolation",
        query: r#"
          (call
            method: (identifier) @m
            (#match? @m "^(system|exec)$")
            arguments: (argument_list
              (string
                (interpolation)+ @vuln
              )
            )
          )
        "#,
        severity: Severity::High,
    },
    Pattern {
        id: "backtick_command",
        description: "Back-tick shell execution",
        // `uname -a`
        query: r#"(shell_command) @vuln"#,
        severity: Severity::High,
    },
    // ---------- Dangerous deserialisation ----------
    Pattern {
        id: "yaml_load",
        description: "YAML.load / Psych.load (arbitrary object deserialisation)",
        query: r#"
          (call
            receiver: (constant) @recv
            (#match? @recv "^(YAML|Psych)$")
            method: (identifier) @m
            (#eq? @m "load")
          ) @vuln
        "#,
        severity: Severity::High,
    },
    Pattern {
        id: "marshal_load",
        description: "Marshal.load usage",
        query: r#"
          (call
            receiver: (constant) @recv
            (#eq? @recv "Marshal")
            method: (identifier) @m
            (#eq? @m "load")
          ) @vuln
        "#,
        severity: Severity::High,
    },
    // ---------- Reflection / meta-programming ----------
    Pattern {
        id: "send_dynamic",
        description: "send() with dynamic first argument (not a literal symbol)",
        query: r#"
          (call
            method: (identifier) @m
            (#eq? @m "send")
            arguments: (argument_list
              [
                (identifier)                ; send(method_name_var, …)
                (string (interpolation)+)   ; send("user_#{role}", …)
              ] @vuln
            )
          )
        "#,
        severity: Severity::Medium,
    },
    Pattern {
        id: "constantize_call",
        description: "ActiveSupport constantize / safe_constantize on tainted data",
        query: r#"
          (call
            method: (identifier) @m
            (#match? @m "^(constantize|safe_constantize)$")
          ) @vuln
        "#,
        severity: Severity::Medium,
    },
    // ---------- Insecure resource access ----------
    Pattern {
        id: "open_uri_http",
        description: "Kernel#open with HTTP(S) URL (open-uri auto-follow)",
        query: r#"
          (call
            method: (identifier) @m
            (#eq? @m "open")
            arguments: (argument_list
              (string) @url
              (#match? @url "^\"https?://")
            )
          ) @vuln
        "#,
        severity: Severity::Medium,
    },
];
