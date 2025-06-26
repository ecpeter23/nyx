use std::{env, process::Command};
fn main() {
    let x = env::var("DANGEROUS").unwrap();
    let clean = html_escape::encode_safe(&x);    // sanitizer node
    Command::new("sh").arg(clean).status().unwrap();  // SAFE
}