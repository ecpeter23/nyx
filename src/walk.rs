use crossbeam_channel::{bounded, Receiver, Sender};
use ignore::{overrides::OverrideBuilder, WalkBuilder, WalkState};
use std::{
    mem,
    path::{Path, PathBuf},
    thread,
};

use crate::utils::Config;

// ---------------------------------------------------------------------------
// Internal constants / helpers
// ---------------------------------------------------------------------------
const DEFAULT_BATCH:     usize = 8;   // a tad larger for fewer sends
const CHANNEL_MULTIPLIER:usize = 4;   // capacity = threads × this

type Batch = Vec<PathBuf>;

struct Batcher {
    tx:    Sender<Batch>,
    batch: Batch,
}
impl Batcher {
    fn push(&mut self, p: PathBuf) {
        self.batch.push(p);
        if self.batch.len() == DEFAULT_BATCH {
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
    fn drop(&mut self) { self.flush(); }
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
    let overrides   = ob.build().unwrap();

    // ----- 2  channel & thread pool parameters -----------------------------
    let workers     = cfg.performance.worker_threads.unwrap_or(num_cpus::get());
    let (tx, rx)    = bounded::<Batch>(workers * CHANNEL_MULTIPLIER);

    let root        = root.to_path_buf();
    let scan_hidden = cfg.scanner.scan_hidden_files;
    let follow      = cfg.scanner.follow_symlinks;
    let max_bytes   = cfg.scanner.max_file_size_mb.unwrap_or(0) * 1_048_576;

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
                  tx:    tx.clone(),
                  batch: Vec::with_capacity(DEFAULT_BATCH),
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
                  b.push(entry.into_path());
                  WalkState::Continue
              })
          });
    });

    rx
}
