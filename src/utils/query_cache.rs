use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use once_cell::sync::Lazy;
use tree_sitter::{Language, Query};

use crate::patterns::{self, Pattern};

#[derive(Clone)]
pub struct CompiledQuery {
  pub meta: Pattern,
  pub query: Arc<Query>,         
}

static CACHE: Lazy<RwLock<HashMap<&'static str, Vec<CompiledQuery>>>> =
  Lazy::new(|| RwLock::new(HashMap::new()));

pub fn for_lang(lang: &'static str, ts_lang: Language) -> Vec<CompiledQuery> {
  // fast-path read
  if let Some(v) = CACHE.read().unwrap().get(lang) {
    return v.clone();
  }

  // compile under write-lock exactly once
  let patterns = patterns::load(lang);
  let mut vec = Vec::with_capacity(patterns.len());

  for p in patterns {
    match Query::new(&ts_lang, p.query) {
      Ok(q) => vec.push(CompiledQuery { meta: p, query: Arc::new(q) }),
      Err(e) => tracing::warn!(lang, id = p.id, "query compile error: {e}"),
    }
  }

  CACHE.write().unwrap().insert(lang, vec.clone());
  vec
}