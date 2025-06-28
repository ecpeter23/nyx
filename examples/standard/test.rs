use std::{env, process::Command};
fn main() {
  let y = env::var("SAFE").unwrap();

  let x = env::var("DANGEROUS").unwrap();
  let clean = html_escape::encode_safe(&y);
  Command::new("sh").arg(x).status().unwrap();
  Command::new("sh").arg(clean).status().unwrap();
}