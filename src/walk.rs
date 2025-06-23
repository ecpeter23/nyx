use crossbeam_channel::{bounded, Receiver};
use ignore::{WalkBuilder, WalkState};
use std::{path::{Path, PathBuf}, thread};
use ignore::overrides::OverrideBuilder;
use crate::utils::Config;

const BATCH_SIZE: usize = 5;

type Batch = Vec<PathBuf>;

#[derive(Debug)]
struct Batcher {
    tx: crossbeam_channel::Sender<Batch>,
    batch: Batch,
}

impl Batcher {
    fn push(&mut self, p: PathBuf) {
        self.batch.push(p);
        if self.batch.len() == BATCH_SIZE {
            self.flush();
        }
    }
    fn flush(&mut self) {
        if !self.batch.is_empty() {
            let _ = self.tx.send(std::mem::take(&mut self.batch));
        }
    }
}

impl Drop for Batcher {
    fn drop(&mut self) {
        // guarantees the remainder is sent when the worker is dropped
        self.flush();
    }
}


/// Walk `root`, send file paths to the returned receiver.
pub fn spawn_senders(
    root: &Path, 
    cfg: &Config
) -> Receiver<Batch> {
    let mut ob = OverrideBuilder::new(root);

    for ext in &cfg.scanner.excluded_extensions {
        if let Err(e) = ob.add(&format!("!*.{ext}")) {
            tracing::warn!("could not add ignore pattern: {e}");
        }
    }

    for dir in &cfg.scanner.excluded_directories {
        if let Err(e) = ob.add(&format!("!**/{dir}/**")) {
            tracing::warn!("could not add ignore pattern: {e}");
        }
    }
    
    let overrides = ob.build().unwrap();
    let worker_thrs  = cfg.performance.worker_threads.unwrap_or(num_cpus::get());
    
    let (tx, rx) = bounded::<Batch>(worker_thrs * 2usize);
    
    let root       = root.to_path_buf();
    let scan_hidden   = cfg.scanner.scan_hidden_files;
    let follow_links  = cfg.scanner.follow_symlinks;
    let max_bytes: u64      = (cfg.scanner.max_file_size_mb.unwrap_or(0)) * 1_048_576;

    thread::spawn(move || {
        let walker = WalkBuilder::new(root)
          .hidden(!scan_hidden)
          .follow_links(follow_links)
          .threads(worker_thrs)
          .overrides(overrides)
          .build_parallel();

        walker.run(move || {
            let mut batcher = Batcher {
                tx: tx.clone(),
                batch: Vec::with_capacity(BATCH_SIZE),
            };

            Box::new(move |entry| {
                tracing::debug!("walking: {:?}", entry);
                let e = match entry {
                    Ok(e) if e.file_type().map(|ft| ft.is_file()).unwrap_or(false) => e,
                    _ => return WalkState::Continue,
                };
                if max_bytes != 0 {
                    match e.metadata() {
                        Ok(m) if m.len() <= max_bytes => {},
                        _ => return WalkState::Continue,
                    }
                }
                tracing::debug!("scanning file: {:?}", e);
                batcher.push(e.into_path());
                if batcher.batch.len() == BATCH_SIZE {
                    let _ = batcher.tx.send(std::mem::take(&mut batcher.batch));
                }
                WalkState::Continue
            })
        });

    });
    
    rx
}
