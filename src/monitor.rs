//! The monitoring loop: waits for notifications or the reconciliation
//! deadline, then polls dirty files.
//!
//! Everything here runs on one thread. Readers are polled sequentially, each
//! with a bounded read budget, so a busy file cannot starve the others and a
//! blocking line consumer (output backpressure) simply pauses the loop.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::config::Config;
use crate::metrics::Metrics;
use crate::reader::{Line, READ_BUF_BYTES, ReaderOptions, TailedFile};
use crate::watcher::{Waker, Watcher, wake_channel};

/// Bytes read from one file per poll before moving on to the next file.
pub const READ_BUDGET_BYTES: usize = 1024 * 1024;

pub struct Monitor {
    files: Vec<TailedFile>,
    watcher: Watcher,
    wake_rx: Receiver<()>,
    waker: Waker,
    reconcile: Duration,
    metrics: Arc<Metrics>,
    buf: Vec<u8>,
}

impl Monitor {
    /// `notifications = false` disables inotify entirely, leaving only
    /// periodic reconciliation (used to test the fallback path).
    pub fn new(cfg: &Config, metrics: Arc<Metrics>, notifications: bool) -> Self {
        let opts = ReaderOptions {
            max_line_bytes: cfg.general.max_line_bytes,
            read_budget: READ_BUDGET_BYTES,
            drain_grace: Duration::from_millis(cfg.general.rotation_drain_ms),
        };
        let (waker, wake_rx) = wake_channel();
        let paths: &[PathBuf] = &cfg.files;
        let files = paths
            .iter()
            .map(|p| TailedFile::new(p.clone(), cfg.general.startup_mode, opts))
            .collect();
        let watcher = Watcher::new(paths, notifications, waker.clone(), Arc::clone(&metrics));
        if watcher.is_active() {
            info!(
                files = paths.len(),
                dirs = watcher.watched_dirs(),
                "filesystem notifications active"
            );
        }
        Monitor {
            files,
            watcher,
            wake_rx,
            waker,
            reconcile: Duration::from_millis(cfg.general.reconcile_interval_ms),
            metrics,
            buf: vec![0; READ_BUF_BYTES],
        }
    }

    /// A handle that interrupts the loop's wait, e.g. after setting the
    /// shutdown flag.
    pub fn waker(&self) -> Waker {
        self.waker.clone()
    }

    /// Runs until `shutdown` is set (and the loop is woken). Every line is
    /// passed to `on_line` together with the index of its configured file.
    ///
    /// `on_line` may block (output backpressure); the loop then pauses.
    /// Unread data stays in the files, so pausing loses nothing unless a
    /// file is rotated away and fully removed meanwhile.
    pub fn run(&mut self, shutdown: &AtomicBool, on_line: &mut dyn FnMut(usize, Line<'_>)) {
        let mut next_reconcile = Instant::now();
        let mut busy = false;
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            if !busy {
                let timeout = next_reconcile.saturating_duration_since(Instant::now());
                match self.wake_rx.recv_timeout(timeout) {
                    Ok(()) | Err(RecvTimeoutError::Timeout) => {}
                    // We hold a Waker ourselves, so this cannot happen;
                    // degrade to timed polling rather than spin.
                    Err(RecvTimeoutError::Disconnected) => {
                        warn!("wake channel closed unexpectedly");
                        std::thread::sleep(timeout);
                    }
                }
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
            }

            let now = Instant::now();
            if now >= next_reconcile {
                self.watcher.reconcile_watches();
                self.watcher.mark_all_dirty();
                next_reconcile = now + self.reconcile;
            } else {
                self.watcher.handle_rescan();
            }

            busy = false;
            for (i, file) in self.files.iter_mut().enumerate() {
                if !self.watcher.take_dirty(i) {
                    continue;
                }
                let more = file.poll(now, &mut self.buf, &self.metrics, &mut |line| {
                    on_line(i, line)
                });
                if more {
                    self.watcher.mark_dirty(i);
                    busy = true;
                }
            }
        }
    }
}
