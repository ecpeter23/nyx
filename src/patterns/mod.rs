pub mod rust;
pub mod typescript;
pub mod javascript;
pub mod cpp;
pub mod c;
mod java;
mod go;
mod php;
mod python;

use std::collections::HashMap;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;

/// How bad / noisy a pattern is considered.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
  Low,
  Medium,
  High,
}

/// One AST pattern with a tree-sitter query and meta-data.
#[derive(Debug, Clone, Serialize)]
pub struct Pattern {
  /// Unique identifier (snake-case preferred).
  pub id: &'static str,
  /// Human-readable explanation.
  pub description: &'static str,
  /// tree-sitter query string.
  pub query: &'static str,
  /// Rough severity bucket.
  pub severity: Severity,
}

impl FromStr for Severity { // TODO: FIX
  type Err = ();

  fn from_str(input: &str) -> Result<Self, Self::Err> {
    match input.to_lowercase().as_str() {
      "medium" => Ok(Severity::Medium),
      "high"   => Ok(Severity::High),
      _        => Ok(Severity::Low),
    }
  }
}


/// Global, lazily-initialised registry: lang-name → pattern slice
static REGISTRY: Lazy<HashMap<&'static str, &'static [Pattern]>> = Lazy::new(|| {
  let mut m = HashMap::new();

  // ---- Rust ----
  m.insert("rust", rust::PATTERNS);

  // ---- TypeScript ----
  m.insert("typescript", typescript::PATTERNS);
  m.insert("ts", typescript::PATTERNS);
  m.insert("tsx", typescript::PATTERNS);

  // ---- JavaScript ----
  m.insert("javascript", javascript::PATTERNS);
  m.insert("js", javascript::PATTERNS);

  // ---- C & C++ ----
  m.insert("c", c::PATTERNS);
  m.insert("cpp", cpp::PATTERNS);
  m.insert("c++", cpp::PATTERNS);

  // ---- Other languages in the folder ----
  m.insert("java", java::PATTERNS);
  m.insert("go", go::PATTERNS);
  m.insert("php", php::PATTERNS);
  m.insert("python", python::PATTERNS);
  m.insert("py", python::PATTERNS);

  tracing::debug!("AST-pattern registry initialised ({} languages)", m.len());
  
  m
});

/// Return all patterns for the requested language (case-insensitive).
///
/// Unknown languages yield an **empty** `Vec`.
pub fn load(lang: &str) -> Vec<Pattern> {
  let key = lang.to_ascii_lowercase();
  REGISTRY
    .get(key.as_str())
    .copied()            // `&'static [Pattern]` → *copy* the slice pointer
    .unwrap_or(&[])      // unknown lang ⇒ empty slice
    .to_vec()            // caller owns the `Vec`
}