//! demo.rs  —  realistic taint-tracking playground
//! `cargo add html-escape shell-escape` before compiling.

use std::{env, process::Command, fs};

#[derive(Default)]
struct UserCtx {
    query: String,          // potentially tainted
    sanitized: String,      // should remain clean
}

/// ----------   helper wrappers so we get nice Source / Sink labels   ----------
fn source_env(var: &str) -> String {
    env::var(var).unwrap_or_default()                          // Source(env-var)
}

fn source_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()               // Source(file-io)
}

fn sink_shell(arg: &str) {
    Command::new("sh").arg(arg).status().unwrap();             // Sink(process-spawn)
}

fn sink_html(out: &str) {
    println!("{out}");                                         // Sink(html-out)
}

fn sanitize_html(s: &str) -> String {
    html_escape::encode_safe(s)                                // Sanitizer(html-escape)
}

fn sanitize_shell(s: &str) -> String {
    shell_escape::unix::escape(s.into()).into_owned()          // Sanitizer(shell-escape)
}

/// ----------   1. Main demo fuction   ----------
fn main() {
    // FLOW A ────────────────────────────────────────────────────────────────
    // env → sanitized → safe shell
    let raw = source_env("USER_CMD");
    let clean = sanitize_shell(&raw);
    sink_shell(&clean);                       // EXPECT: SAFE

    // FLOW B ────────────────────────────────────────────────────────────────
    // env → if-else, only one branch escapes
    let arg = source_env("ANOTHER");
    if arg.len() > 5 {
        sink_shell(&arg);                     // EXPECT: UNSAFE  (branch tainted)
    } else {
        let escaped = sanitize_shell(&arg);
        sink_shell(&escaped);                 // safe
    }

    // FLOW C ────────────────────────────────────────────────────────────────
    // file → while loop → HTML sanitizer cleared
    let mut data = source_file("/tmp/input.txt");
    while data.len() < 32 {
        data.push('x');
    }
    let html_ok = sanitize_html(&data);
    sink_html(&html_ok);                      // safe

    // FLOW D ────────────────────────────────────────────────────────────────
    // file → struct field → match → unsanitised HTML
    let mut ctx = UserCtx::default();
    ctx.query = source_file("/tmp/q.txt");
    // overwrite the clean field; `ctx.sanitized` is *not* tainted
    ctx.sanitized = sanitize_html("constant");
    match ctx {
        UserCtx { query, sanitized } if query.contains("DROP") => {
            sink_html(&query);                // EXPECT: UNSAFE
        }
        _ => {
            sink_html(&ctx.sanitized);        // safe
        }
    }

    // FLOW E ────────────────────────────────────────────────────────────────
    // source → function call → reassignment clears taint
    let mut name = source_env("USER");        // tainted
    greet(&name);                            // just prints
    name = "anonymous".into();               // kills taint
    greet(&name);                            // safe

    // FLOW F ────────────────────────────────────────────────────────────────
    // Multiple sanitizers, only the *right* one matters
    let cmd = source_env("MIXED");
    let partly = sanitize_html(&cmd);        // wrong sanitizer
    sink_shell(&partly);                     // EXPECT: UNSAFE
}

/// helper (non-sink) function
fn greet(who: &str) {
    println!("Hello, {who}");
}