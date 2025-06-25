// src/main.rs
use std::env;
use std::process::Command;

fn main() {
  // ── Source ───────────────────────────────────────────────────────────────
  // Anything read from the environment is considered untrusted.
  let user_input = env::var("DANGEROUS_ARG").unwrap_or_default();

  // (Optional) print it so the compiler can’t optimise it away.
  println!("Received from env: {user_input}");

  // ── Sink ─────────────────────────────────────────────────────────────────
  // The untrusted value is injected into a command line without sanitisation.
  // Your CFG + taint engine should flag this as a vulnerability.
  let _status = Command::new("sh")
    .arg("-c")
    .arg(user_input)   // <-- SINK: unsanitised
    .status()
    .expect("failed to spawn shell");
}



/*
To verify:

$ DANGEROUS_ARG='echo pwnd' cargo run
Received from env: echo pwnd
*/