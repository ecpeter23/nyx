use crossbeam_channel::{Receiver, Sender, bounded};
use ignore::{WalkBuilder, WalkState, overrides::OverrideBuilder};
use std::{
    mem,
    path::{Path, PathBuf},
    thread,
};

use crate::utils::Config;

// ---------------------------------------------------------------------------
// Internal constants / helpers
// ---------------------------------------------------------------------------

type Batch = Vec<PathBuf>;

struct Batcher {
    tx: Sender<Batch>,
    batch: Batch,
}
impl Batcher {
    fn push(&mut self, p: PathBuf, batch_size: usize) {
        self.batch.push(p);
        if self.batch.len() == batch_size {
            self.flush();
        }
    }
    fn flush(&mut self) {
        if !self.batch.is_empty() {
            let _ = self.tx.send(mem::take(&mut self.batch));
        }
    }
}
impl Drop for Batcher {
    fn drop(&mut self) {
        self.flush();
    }
}

// ---------------------------------------------------------------------------
/// Walk `root` and send *batches* of paths through the returned channel.
pub fn spawn_senders(root: &Path, cfg: &Config) -> Receiver<Batch> {
    // ----- 1  build ignore/override rules ----------------------------------
    let mut ob = OverrideBuilder::new(root);
    for ext in &cfg.scanner.excluded_extensions {
        if let Err(e) = ob.add(&format!("!*.{ext}")) {
            tracing::warn!("cannot add ignore pattern ‘{ext}’: {e}");
        }
    }
    for dir in &cfg.scanner.excluded_directories {
        if let Err(e) = ob.add(&format!("!**/{dir}/**")) {
            tracing::warn!("cannot add ignore pattern ‘{dir}’: {e}");
        }
    }
    let overrides = ob.build().unwrap();

    // ----- 2  channel & thread pool parameters -----------------------------
    let workers = cfg.performance.worker_threads.unwrap_or(num_cpus::get());
    let (tx, rx) = bounded::<Batch>(workers * cfg.performance.channel_multiplier);

    let root = root.to_path_buf();
    let scan_hidden = cfg.scanner.scan_hidden_files;
    let follow = cfg.scanner.follow_symlinks;
    let max_bytes = cfg.scanner.max_file_size_mb.unwrap_or(0) * 1_048_576;
    let batch_size = cfg.performance.batch_size;

    // ----- 3  the background walker thread ---------------------------------
    thread::spawn(move || {
        WalkBuilder::new(root)
            .hidden(!scan_hidden)
            .follow_links(follow)
            .threads(workers)
            .overrides(overrides)
            .build_parallel()
            .run(move || {
                let mut b = Batcher {
                    tx: tx.clone(),
                    batch: Vec::with_capacity(batch_size),
                };

                Box::new(move |entry| {
                    tracing::debug!("walking {:?}", entry);
                    let entry = match entry {
                        Ok(e) if e.file_type().map(|ft| ft.is_file()).unwrap_or(false) => e,
                        _ => return WalkState::Continue,
                    };

                    if max_bytes != 0 {
                        match entry.metadata() {
                            Ok(m) if m.len() > max_bytes => return WalkState::Continue,
                            Err(e) => {
                                tracing::debug!("metadata failed for {:?}: {e}", entry.path());
                                return WalkState::Continue;
                            }
                            _ => {}
                        }
                    }

                    tracing::debug!("sending {:?}", entry);
                    b.push(entry.into_path(), batch_size);
                    WalkState::Continue
                })
            });
    });

    rx
}

#[test]
fn walker_respects_excluded_extensions() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("keep.rs"), "fn main(){}").unwrap();
    std::fs::write(tmp.path().join("skip.txt"), "ignored").unwrap();

    let mut cfg = Config::default();
    cfg.scanner.excluded_extensions = vec!["txt".into()];
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let rx = spawn_senders(tmp.path(), &cfg);

    let all: Vec<_> = rx.into_iter().flatten().collect();

    assert!(all.iter().any(|p| p.ends_with("keep.rs")));
    assert!(all.iter().all(|p| !p.ends_with("skip.txt")));
}
