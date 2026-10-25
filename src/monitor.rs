//! The monitoring loop: waits for notifications or the reconciliation
//! deadline, then polls dirty files.
//!
//! Everything here runs on one thread. Readers are polled sequentially, each
//! with a bounded read budget, so a busy file cannot starve the others and a
//! blocking line consumer (output backpressure) simply pauses the loop.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::config::{Config, StartupMode};
use crate::metrics::Metrics;
use crate::reader::{FileId, Line, READ_BUF_BYTES, ReaderOptions, TailedFile};
use crate::state::FileState;
use crate::watcher::{Waker, Watcher, wake_channel};

/// Bytes read from one file per poll before moving on to the next file.
pub const READ_BUDGET_BYTES: usize = 1024 * 1024;

/// Receives the result of [`Monitor::checkpoint`] in [`Monitor::run_with`].
pub type OnCheckpoint<'a> = dyn FnMut(Vec<Option<FileState>>) + 'a;

/// Why [`Monitor::run_with`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    Shutdown,
    /// A reload was requested; apply it and call `run_with` again.
    Reload,
}

pub struct Monitor {
    files: Vec<TailedFile>,
    /// Identity each file had after its last poll.
    ids: Vec<Option<FileId>>,
    watcher: Watcher,
    wake_rx: Receiver<()>,
    waker: Waker,
    reconcile: Duration,
    opts: ReaderOptions,
    notifications: bool,
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
        let files: Vec<TailedFile> = paths
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
            ids: vec![None; files.len()],
            files,
            watcher,
            wake_rx,
            waker,
            reconcile: Duration::from_millis(cfg.general.reconcile_interval_ms),
            opts,
            notifications,
            metrics,
            buf: vec![0; READ_BUF_BYTES],
        }
    }

    /// Saved positions from a previous run; call before [`Monitor::run`].
    /// Entries for paths that are no longer configured are ignored.
    pub fn resume(&mut self, mut saved: HashMap<PathBuf, FileState>) {
        for f in &mut self.files {
            if let Some(st) = saved.remove(f.path()) {
                f.set_resume(st);
            }
        }
    }

    /// The position to save for each file, by configured index.
    pub fn checkpoint(&mut self) -> Vec<Option<FileState>> {
        self.files.iter_mut().map(TailedFile::checkpoint).collect()
    }

    /// A handle that interrupts the loop's wait, e.g. after setting the
    /// shutdown flag.
    pub fn waker(&self) -> Waker {
        self.waker.clone()
    }

    /// Applies a reloaded configuration's files and timing; call between
    /// [`Monitor::run_with`] calls.
    ///
    /// A file still configured keeps its reader, including its offset,
    /// any incomplete line and a rotated file being drained. A removed file
    /// is closed after its incomplete trailing lines are passed to
    /// `on_line` under its old index. An added file is read from the
    /// beginning, since all of its content is new to this process.
    /// `max_line_bytes` is not changed (it needs a restart).
    pub fn reconfigure(&mut self, cfg: &Config, on_line: &mut dyn FnMut(usize, Line<'_>)) {
        self.opts.drain_grace = Duration::from_millis(cfg.general.rotation_drain_ms);
        self.reconcile = Duration::from_millis(cfg.general.reconcile_interval_ms);
        let mut old: HashMap<PathBuf, TailedFile> = HashMap::new();
        for (i, mut f) in std::mem::take(&mut self.files).into_iter().enumerate() {
            if cfg.files.iter().any(|p| p == f.path()) {
                old.insert(f.path().to_path_buf(), f);
            } else {
                f.close(&self.metrics, &mut |line| on_line(i, line));
                info!(path = %f.path().display(), "file no longer configured; closed");
            }
        }
        let opts = self.opts;
        self.files = cfg
            .files
            .iter()
            .map(|p| match old.remove(p) {
                Some(mut f) => {
                    f.set_drain_grace(opts.drain_grace);
                    f
                }
                None => {
                    info!(path = %p.display(), "file added to configuration");
                    TailedFile::new(p.clone(), StartupMode::Beginning, opts)
                }
            })
            .collect();
        self.ids = self.files.iter().map(TailedFile::current_id).collect();
        // Recreated rather than patched: the next run_with call starts with
        // a reconciliation pass that polls every file, which covers any
        // event missed in between.
        self.watcher = Watcher::new(
            &cfg.files,
            self.notifications,
            self.waker.clone(),
            Arc::clone(&self.metrics),
        );
    }

    /// Runs until `shutdown` is set (and the loop is woken). Every line is
    /// passed to `on_line` together with the index of its configured file.
    ///
    /// `on_line` may block (output backpressure); the loop then pauses.
    /// Unread data stays in the files, so pausing loses nothing unless a
    /// file is rotated away and fully removed meanwhile.
    pub fn run(&mut self, shutdown: &AtomicBool, on_line: &mut dyn FnMut(usize, Line<'_>)) {
        self.run_with(shutdown, None, on_line, None);
    }

    /// Like [`Monitor::run`], additionally passing [`Monitor::checkpoint`]
    /// to `on_checkpoint` every `interval` (between polls, so every line
    /// before a checkpoint has been passed to `on_line`), and returning
    /// [`Stopped::Reload`] between polls once `reload` is set (the flag is
    /// cleared).
    pub fn run_with(
        &mut self,
        shutdown: &AtomicBool,
        reload: Option<&AtomicBool>,
        on_line: &mut dyn FnMut(usize, Line<'_>),
        mut checkpoints: Option<(Duration, &mut OnCheckpoint<'_>)>,
    ) -> Stopped {
        let reload_requested = || reload.is_some_and(|r| r.swap(false, Ordering::Relaxed));
        let mut next_reconcile = Instant::now();
        let mut next_checkpoint = Instant::now();
        let mut busy = false;
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return Stopped::Shutdown;
            }
            if reload_requested() {
                return Stopped::Reload;
            }
            if let Some((interval, f)) = &mut checkpoints {
                let now = Instant::now();
                if now >= next_checkpoint {
                    f(self.checkpoint());
                    next_checkpoint = now + *interval;
                }
            }
            if !busy {
                let deadline = match checkpoints {
                    Some(_) => next_reconcile.min(next_checkpoint),
                    None => next_reconcile,
                };
                let timeout = deadline.saturating_duration_since(Instant::now());
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
                    return Stopped::Shutdown;
                }
                if reload_requested() {
                    return Stopped::Reload;
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
            let mut changed = false;
            for (i, file) in self.files.iter_mut().enumerate() {
                // A pass can read up to READ_BUDGET_BYTES from every file;
                // do not make shutdown wait for all of them.
                if shutdown.load(Ordering::Relaxed) {
                    return Stopped::Shutdown;
                }
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
                let id = file.current_id();
                if id != self.ids[i] {
                    self.ids[i] = id;
                    changed = true;
                }
            }
            if changed {
                // A rotation may have retargeted a symlink: move its watch
                // now rather than at the next reconciliation.
                self.watcher.refresh_targets();
            }
        }
    }
}
