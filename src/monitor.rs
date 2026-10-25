//! The monitoring loop: waits for notifications or the reconciliation
//! deadline, then polls dirty files.
//!
//! Everything here runs on one thread. Readers are polled sequentially, each
//! with a bounded read budget, so a busy file cannot starve the others and a
//! blocking line consumer (output backpressure) simply pauses the loop.
//!
//! The directory of each `[[files]] glob` is listed at startup, on every
//! reconciliation tick and whenever a matching name is created, removed or
//! renamed. A new match is followed from offset 0, up to
//! `general.max_glob_files` per glob. A match that disappears gets the normal
//! rotation and deletion handling; its slot is released once the file is
//! gone from the path and nothing is left to read.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::config::{self, Config, Glob, StartupMode};
use crate::journal::{Journal, Start};
use crate::metrics::{self, Metrics};
use crate::reader::{FileId, Line, READ_BUF_BYTES, ReaderOptions, TailedFile};
use crate::state::FileState;
use crate::watcher::{Waker, Watcher, wake_channel};

/// Bytes read from one file per poll before moving on to the next file.
pub const READ_BUDGET_BYTES: usize = 1024 * 1024;
/// Minimum time between warnings about matches refused for one glob.
const REFUSED_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Receives the result of [`Monitor::checkpoint`] in [`Monitor::run_with`].
/// The second argument is the journal cursor, if the journal is read.
pub type OnCheckpoint<'a> = dyn FnMut(Vec<(Arc<Path>, FileState)>, Option<Arc<str>>) + 'a;

/// Receives every line, together with the path of the file it came from.
pub type OnLine<'a> = dyn FnMut(&Arc<Path>, Line<'_>) + 'a;

/// A followed file.
struct Slot {
    path: Arc<Path>,
    file: TailedFile,
    /// Identity the file had after its last poll.
    id: Option<FileId>,
    /// The glob that found the file; `None` for a configured path.
    glob: Option<usize>,
}

impl Slot {
    /// A file found by a glob that can be forgotten: nothing is open or
    /// draining, and nothing is at the path. A file renamed away or deleted
    /// keeps its slot while it is still read (normal rotation and deletion
    /// handling).
    fn is_gone(&self) -> bool {
        self.glob.is_some()
            && !self.file.is_open()
            && !self.file.is_draining()
            && fs::symlink_metadata(&self.path).is_err_and(|e| e.kind() == ErrorKind::NotFound)
    }
}

/// A `[[files]] glob` entry and the files it currently has.
struct GlobState {
    glob: Glob,
    /// Number of slots held for this glob.
    followed: usize,
    /// Matches refused at the last listing because of `max_glob_files`, so
    /// each is counted once. At most `max_glob_files` are remembered.
    refused: HashSet<PathBuf>,
    last_warning: Option<Instant>,
    /// The last listing failed with this error; reported once.
    list_error: Option<ErrorKind>,
}

impl GlobState {
    fn new(glob: &Glob) -> Self {
        GlobState {
            glob: glob.clone(),
            followed: 0,
            refused: HashSet::new(),
            last_warning: None,
            list_error: None,
        }
    }
}

/// Why [`Monitor::run_with`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    Shutdown,
    /// A reload was requested; apply it and call `run_with` again.
    Reload,
}

pub struct Monitor {
    /// Indexed by watcher slot; `None` for a free slot.
    slots: Vec<Option<Slot>>,
    globs: Vec<GlobState>,
    max_glob_files: usize,
    opts: ReaderOptions,
    watcher: Watcher,
    wake_rx: Receiver<()>,
    waker: Waker,
    reconcile: Duration,
    notifications: bool,
    /// Readers kept from before a reload, until a glob claims them.
    carried: HashMap<PathBuf, (Arc<Path>, TailedFile)>,
    metrics: Arc<Metrics>,
    buf: Vec<u8>,
    /// Read after the files; see [`Monitor::start_journal`].
    journal: Option<(Arc<Path>, Journal)>,
}

impl Monitor {
    /// `notifications = false` disables inotify entirely, leaving only
    /// periodic reconciliation (used to test the fallback path).
    ///
    /// Globs are matched here for the first time; files they match now are
    /// treated like configured paths and follow `startup_mode`.
    pub fn new(cfg: &Config, metrics: Arc<Metrics>, notifications: bool) -> Self {
        let opts = ReaderOptions {
            max_line_bytes: cfg.general.max_line_bytes,
            read_budget: READ_BUDGET_BYTES,
            drain_grace: Duration::from_millis(cfg.general.rotation_drain_ms),
        };
        let (waker, wake_rx) = wake_channel();
        let paths: &[PathBuf] = &cfg.files;
        let slots = paths
            .iter()
            .map(|p| {
                Some(Slot {
                    path: p.as_path().into(),
                    file: TailedFile::new(p.clone(), cfg.general.startup_mode, opts),
                    id: None,
                    glob: None,
                })
            })
            .collect();
        let watcher = Watcher::new(
            paths,
            &cfg.globs,
            notifications,
            waker.clone(),
            Arc::clone(&metrics),
        );
        let globs = cfg.globs.iter().map(GlobState::new).collect();
        let mut monitor = Monitor {
            slots,
            globs,
            max_glob_files: cfg.general.max_glob_files,
            opts,
            watcher,
            wake_rx,
            waker,
            reconcile: Duration::from_millis(cfg.general.reconcile_interval_ms),
            notifications,
            carried: HashMap::new(),
            metrics,
            buf: vec![0; READ_BUF_BYTES],
            journal: None,
        };
        for g in 0..monitor.globs.len() {
            monitor.scan_glob(g, Some(cfg.general.startup_mode));
        }
        if monitor.watcher.is_active() {
            info!(
                files = monitor.files(),
                dirs = monitor.watcher.watched_dirs(),
                "filesystem notifications active"
            );
        }
        monitor
    }

    /// Number of files currently followed.
    pub fn files(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Starts reading the journal if the configuration asks for it, after
    /// `cursor` (saved by a previous run) or else per `startup_mode`.
    pub fn start_journal(&mut self, cfg: &Config, cursor: Option<String>) -> std::io::Result<()> {
        let Some(j) = &cfg.journal else {
            return Ok(());
        };
        let journal = Journal::spawn(
            j.matches.clone(),
            Start::new(cursor, cfg.general.startup_mode),
            cfg.general.max_line_bytes,
            self.waker.clone(),
            Arc::clone(&self.metrics),
        )?;
        self.journal = Some((Path::new(config::JOURNAL_SOURCE).into(), journal));
        Ok(())
    }

    /// Cursor of the last journal entry passed to `on_line`.
    pub fn journal_cursor(&self) -> Option<Arc<str>> {
        self.journal.as_ref().and_then(|(_, j)| j.cursor())
    }

    /// Saved positions from a previous run; call before [`Monitor::run`].
    /// Entries for paths that are not followed are ignored.
    pub fn resume(&mut self, mut saved: HashMap<PathBuf, FileState>) {
        for s in self.slots.iter_mut().flatten() {
            if let Some(st) = saved.remove(s.file.path()) {
                s.file.set_resume(st);
            }
        }
    }

    /// The position to save for each open file.
    pub fn checkpoint(&mut self) -> Vec<(Arc<Path>, FileState)> {
        self.slots
            .iter_mut()
            .flatten()
            .filter_map(|s| s.file.checkpoint().map(|st| (Arc::clone(&s.path), st)))
            .collect()
    }

    /// Lists the directory of glob `g`: follows new matches (up to
    /// `max_glob_files`) and releases the slots of files that are gone and
    /// fully read. `startup` is the start mode for new matches; `None`
    /// reads them from the beginning. Returns `true` if any slot changed.
    fn scan_glob(&mut self, g: usize, startup: Option<StartupMode>) -> bool {
        let Monitor {
            slots,
            globs,
            watcher,
            metrics,
            max_glob_files,
            opts,
            carried,
            ..
        } = self;
        let st = &mut globs[g];
        let mut changed = false;

        for (i, slot) in slots.iter_mut().enumerate() {
            if slot
                .as_ref()
                .is_some_and(|s| s.glob == Some(g) && s.is_gone())
            {
                *slot = None;
                watcher.remove(i);
                st.followed -= 1;
                changed = true;
            }
        }

        let entries = match fs::read_dir(&st.glob.dir) {
            Ok(entries) => {
                if st.list_error.take().is_some() {
                    info!(glob = st.glob.text, "glob directory can be listed again");
                }
                entries
            }
            Err(e) => {
                if st.list_error != Some(e.kind()) {
                    if e.kind() == ErrorKind::NotFound {
                        warn!(
                            glob = st.glob.text,
                            "glob directory not found; waiting for it to appear"
                        );
                    } else {
                        metrics::inc(&metrics.read_errors);
                        warn!(glob = st.glob.text, error = %e, "cannot list glob directory; will retry");
                    }
                    st.list_error = Some(e.kind());
                }
                return changed;
            }
        };
        let mut refused = HashSet::new();
        let (mut refused_now, mut newly_refused) = (0, 0);
        for entry in entries.flatten() {
            let name = entry.file_name();
            if !st.glob.matches(name.as_bytes()) {
                continue;
            }
            // Not followable, and not worth a warning on every listing.
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let path = st.glob.dir.join(&name);
            // Followed already, as a configured path or for some glob.
            if watcher.slot_of(&path).is_some() {
                continue;
            }
            if st.followed >= *max_glob_files {
                refused_now += 1;
                if !st.refused.contains(&path) {
                    newly_refused += 1;
                }
                if refused.len() < *max_glob_files {
                    refused.insert(path);
                }
                continue;
            }
            let (shared, file) = match (carried.remove(&path), startup) {
                (Some((shared, mut f)), _) => {
                    // Followed before a reload.
                    f.set_drain_grace(opts.drain_grace);
                    (shared, f)
                }
                (None, Some(mode)) => (
                    path.as_path().into(),
                    TailedFile::new(path.clone(), mode, *opts),
                ),
                (None, None) => {
                    info!(glob = st.glob.text, path = %path.display(), "new file matches glob");
                    (
                        path.as_path().into(),
                        TailedFile::appeared(path.clone(), *opts),
                    )
                }
            };
            let i = watcher.add(path);
            if i == slots.len() {
                slots.push(None);
            }
            slots[i] = Some(Slot {
                path: shared,
                id: file.current_id(),
                file,
                glob: Some(g),
            });
            st.followed += 1;
            changed = true;
        }
        st.refused = refused;
        if newly_refused > 0 {
            metrics::add(&metrics.glob_matches_refused, newly_refused);
            let now = Instant::now();
            if st
                .last_warning
                .is_none_or(|t| now.duration_since(t) >= REFUSED_WARN_INTERVAL)
            {
                warn!(
                    glob = st.glob.text,
                    limit = *max_glob_files,
                    refused = refused_now,
                    "glob matches more files than general.max_glob_files; not following the rest"
                );
                st.last_warning = Some(now);
            }
        }
        if changed {
            debug!(
                glob = st.glob.text,
                files = st.followed,
                "glob matches updated"
            );
        }
        changed
    }

    /// A handle that interrupts the loop's wait, e.g. after setting the
    /// shutdown flag.
    pub fn waker(&self) -> Waker {
        self.waker.clone()
    }

    /// Applies a reloaded configuration's files, globs and timing; call
    /// between [`Monitor::run_with`] calls.
    ///
    /// A file still followed, as a configured path or as a match of a glob,
    /// keeps its reader, including its offset, any incomplete line and a
    /// rotated file being drained. A file no longer followed is closed after
    /// its incomplete trailing lines are passed to `on_line`. A newly
    /// followed file is read from the beginning, since all of its content is
    /// new to this process. `max_line_bytes` is not changed (it needs a
    /// restart).
    pub fn reconfigure(&mut self, cfg: &Config, on_line: &mut OnLine<'_>) {
        self.opts.drain_grace = Duration::from_millis(cfg.general.rotation_drain_ms);
        self.reconcile = Duration::from_millis(cfg.general.reconcile_interval_ms);
        self.max_glob_files = cfg.general.max_glob_files;
        let mut old: HashMap<PathBuf, (Arc<Path>, TailedFile)> = std::mem::take(&mut self.slots)
            .into_iter()
            .flatten()
            .map(|s| (s.file.path().to_path_buf(), (s.path, s.file)))
            .collect();
        let opts = self.opts;
        self.slots = cfg
            .files
            .iter()
            .map(|p| {
                let (path, file) = match old.remove(p) {
                    Some((path, mut f)) => {
                        f.set_drain_grace(opts.drain_grace);
                        (path, f)
                    }
                    None => {
                        info!(path = %p.display(), "file added to configuration");
                        let f = TailedFile::new(p.clone(), StartupMode::Beginning, opts);
                        (p.as_path().into(), f)
                    }
                };
                Some(Slot {
                    path,
                    id: file.current_id(),
                    file,
                    glob: None,
                })
            })
            .collect();
        // Recreated rather than patched: the next run_with call starts with
        // a reconciliation pass that polls every file, which covers any
        // event missed in between.
        self.watcher = Watcher::new(
            &cfg.files,
            &cfg.globs,
            self.notifications,
            self.waker.clone(),
            Arc::clone(&self.metrics),
        );
        self.globs = cfg.globs.iter().map(GlobState::new).collect();
        self.carried = old;
        for g in 0..self.globs.len() {
            self.scan_glob(g, None);
        }
        for (_, (path, mut f)) in std::mem::take(&mut self.carried) {
            f.close(&self.metrics, &mut |line| on_line(&path, line));
            info!(path = %path.display(), "file no longer followed; closed");
        }
    }

    /// Runs until `shutdown` is set (and the loop is woken). Every line is
    /// passed to `on_line` together with the path of its file.
    ///
    /// `on_line` may block (output backpressure); the loop then pauses.
    /// Unread data stays in the files, so pausing loses nothing unless a
    /// file is rotated away and fully removed meanwhile.
    pub fn run(&mut self, shutdown: &AtomicBool, on_line: &mut OnLine<'_>) {
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
        on_line: &mut OnLine<'_>,
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
                    let files = self.checkpoint();
                    f(files, self.journal_cursor());
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
                // Also marks every glob dirty.
                self.watcher.reconcile_watches();
                self.watcher.mark_all_dirty();
                next_reconcile = now + self.reconcile;
            } else {
                self.watcher.handle_rescan();
            }

            let mut changed = false;
            for g in 0..self.globs.len() {
                if self.watcher.take_glob_dirty(g) {
                    changed |= self.scan_glob(g, None);
                }
            }

            busy = false;
            let mut gone = Vec::new();
            for (i, slot) in self.slots.iter_mut().enumerate() {
                // A pass can read up to READ_BUDGET_BYTES from every file;
                // do not make shutdown wait for all of them.
                if shutdown.load(Ordering::Relaxed) {
                    return Stopped::Shutdown;
                }
                let Some(slot) = slot else { continue };
                if !self.watcher.take_dirty(i) {
                    continue;
                }
                let more = slot
                    .file
                    .poll(now, &mut self.buf, &self.metrics, &mut |line| {
                        on_line(&slot.path, line)
                    });
                if more {
                    self.watcher.mark_dirty(i);
                    busy = true;
                }
                let id = slot.file.current_id();
                if id != slot.id {
                    slot.id = id;
                    changed = true;
                }
                if id.is_none() && slot.is_gone() {
                    gone.push(i);
                }
            }
            for i in gone {
                // Release the slot now, so that a match refused because of
                // the limit can take it without waiting for reconciliation.
                if let Some(g) = self.slots[i].take().and_then(|s| s.glob) {
                    self.watcher.remove(i);
                    self.globs[g].followed -= 1;
                    if !self.globs[g].refused.is_empty() {
                        self.watcher.mark_glob_dirty(g);
                        busy = true;
                    }
                    changed = true;
                }
            }
            if let Some((path, journal)) = &mut self.journal {
                if journal.poll(&self.metrics, &mut |line| on_line(path, line)) {
                    busy = true;
                }
            }
            if changed {
                // A rotation may have retargeted a symlink, or a glob found
                // a symlink: move or add its watch now rather than at the
                // next reconciliation.
                self.watcher.refresh_targets();
            }
        }
    }
}
