use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use tree_sitter::{Language, Query};

use crate::patterns::{self, Pattern};

#[derive(Clone)]
pub struct CompiledQuery {
    pub meta: Pattern,
    pub query: Arc<Query>,
}

type QuerySet = Arc<Vec<CompiledQuery>>;
static CACHE: LazyLock<RwLock<HashMap<&'static str, QuerySet>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Return **one shared Arc** to the per-language query set.
/// Cloning the `Arc` is O(1) and the underlying Vec lives for the
/// lifetime of the process.
pub fn for_lang(lang: &'static str, ts_lang: Language) -> std::sync::Arc<Vec<CompiledQuery>> {
    // fast path
    if let Some(v) = CACHE.read().unwrap().get(lang) {
        return v.clone();
    }

    // slow path — compile
    let patterns = patterns::load(lang);
    let compiled: Vec<_> = patterns
        .into_iter()
        .filter_map(|p| match Query::new(&ts_lang, p.query) {
            Ok(q) => Some(CompiledQuery {
                meta: p,
                query: std::sync::Arc::new(q),
            }),
            Err(e) => {
                tracing::warn!(lang, id = p.id, "query compile error: {e}");
                None
            }
        })
        .collect();

    let compiled = std::sync::Arc::new(compiled);

    let mut w = CACHE.write().unwrap();
    w.entry(lang).or_insert_with(|| compiled.clone()).clone()
}
