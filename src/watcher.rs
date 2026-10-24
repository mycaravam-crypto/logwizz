//! Filesystem notifications.
//!
//! Notifications are treated as *hints*: they say "look at file N soon".
//! The truth is always established by the reader's own `stat`/`read`, and
//! every file is re-checked on each reconciliation tick, so missed events,
//! queue overflows and filesystems without inotify support (NFS, many FUSE
//! filesystems) only cost latency, never correctness.
//!
//! We watch the *parent directory* of every configured file (non-recursive)
//! rather than the file itself, so creation, rename and deletion are seen
//! even while the file does not exist.
//!
//! Memory use is bounded: the notify thread only sets per-file dirty flags
//! and performs a coalescing `try_send` on a capacity-1 wake channel. There
//! is no event queue that can grow without limit.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use notify::event::AccessKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use tracing::{debug, warn};

use crate::metrics::{self, Metrics};
use crate::reader::FileId;

/// Wakes the monitor loop. Cheap to clone; never blocks.
#[derive(Debug, Clone)]
pub struct Waker(SyncSender<()>);

impl Waker {
    pub fn wake(&self) {
        // Full means a wakeup is already pending; disconnected means the
        // loop has exited. Neither needs handling.
        let _ = self.0.try_send(());
    }
}

/// Creates the wake channel used by the monitor loop.
pub fn wake_channel() -> (Waker, Receiver<()>) {
    let (tx, rx) = sync_channel(1);
    (Waker(tx), rx)
}

/// State shared with the notify thread.
#[derive(Debug)]
struct Shared {
    dirty: Vec<AtomicBool>,
    /// Configured file path -> file index.
    by_path: HashMap<PathBuf, usize>,
    /// Watched directory -> indices of files in it.
    by_dir: HashMap<PathBuf, Vec<usize>>,
    /// Set when the kernel dropped events or a watch broke; makes every
    /// file dirty and triggers re-registration of directory watches.
    rescan: AtomicBool,
    waker: Waker,
    metrics: Arc<Metrics>,
}

impl Shared {
    fn mark_all(&self) {
        for d in &self.dirty {
            d.store(true, Ordering::Relaxed);
        }
    }

    fn handle(&self, res: notify::Result<Event>) {
        let event = match res {
            Ok(event) => event,
            Err(e) => {
                warn!(error = %e, "filesystem notification error; rescanning");
                self.rescan.store(true, Ordering::Relaxed);
                self.mark_all();
                self.waker.wake();
                return;
            }
        };
        if event.need_rescan() {
            metrics::inc(&self.metrics.notify_overflows);
            warn!("filesystem notification queue overflowed; rescanning all files");
            self.rescan.store(true, Ordering::Relaxed);
            self.mark_all();
            self.waker.wake();
            return;
        }
        // Opens (including our own) carry no information about content.
        if matches!(event.kind, EventKind::Access(AccessKind::Open(_))) {
            return;
        }
        let mut hit = false;
        for path in &event.paths {
            if let Some(&i) = self.by_path.get(path) {
                self.dirty[i].store(true, Ordering::Relaxed);
                hit = true;
            } else if let Some(files) = self.by_dir.get(path) {
                // An event on the watched directory itself (removed, moved):
                // its watch is likely gone and must be re-established.
                for &i in files {
                    self.dirty[i].store(true, Ordering::Relaxed);
                }
                self.rescan.store(true, Ordering::Relaxed);
                hit = true;
            }
        }
        if hit {
            self.waker.wake();
        }
    }
}

#[derive(Debug)]
struct DirWatch {
    path: PathBuf,
    /// Identity of the directory when the watch was registered; `None`
    /// if registration failed or has not happened yet.
    watched: Option<FileId>,
    /// A registration failure has been reported and not yet recovered.
    failed: bool,
}

/// Owns the inotify watcher and the per-file dirty flags.
pub struct Watcher {
    inner: Option<RecommendedWatcher>,
    shared: Arc<Shared>,
    dirs: Vec<DirWatch>,
}

impl Watcher {
    /// Sets up notifications for `files`. With `notifications = false`, or
    /// if inotify is unavailable (e.g. `fs.inotify.max_user_instances`
    /// exhausted), only periodic reconciliation detects changes.
    pub fn new(
        files: &[PathBuf],
        notifications: bool,
        waker: Waker,
        metrics: Arc<Metrics>,
    ) -> Self {
        let mut by_path = HashMap::new();
        let mut by_dir: HashMap<PathBuf, Vec<usize>> = HashMap::new();
        for (i, path) in files.iter().enumerate() {
            by_path.insert(path.clone(), i);
            // Config validation guarantees an absolute path with a parent.
            let dir = path.parent().unwrap_or(Path::new("/")).to_path_buf();
            by_dir.entry(dir).or_default().push(i);
        }
        let mut dirs: Vec<DirWatch> = by_dir
            .keys()
            .map(|p| DirWatch {
                path: p.clone(),
                watched: None,
                failed: false,
            })
            .collect();
        dirs.sort_by(|a, b| a.path.cmp(&b.path));

        let shared = Arc::new(Shared {
            dirty: files.iter().map(|_| AtomicBool::new(true)).collect(),
            by_path,
            by_dir,
            rescan: AtomicBool::new(false),
            waker,
            metrics,
        });
        let inner = if notifications {
            let handler_shared = Arc::clone(&shared);
            match notify::recommended_watcher(move |res| handler_shared.handle(res)) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!(
                        error = %e,
                        "filesystem notifications unavailable; relying on periodic reconciliation only"
                    );
                    None
                }
            }
        } else {
            None
        };
        let mut watcher = Watcher {
            inner,
            shared,
            dirs,
        };
        watcher.reconcile_watches();
        watcher
    }

    pub fn is_active(&self) -> bool {
        self.inner.is_some()
    }

    /// Clears and returns the dirty flag of file `i`.
    pub fn take_dirty(&self, i: usize) -> bool {
        self.shared.dirty[i].swap(false, Ordering::Relaxed)
    }

    pub fn mark_dirty(&self, i: usize) {
        self.shared.dirty[i].store(true, Ordering::Relaxed);
    }

    pub fn mark_all_dirty(&self) {
        self.shared.mark_all();
    }

    /// Re-registers directory watches if a rescan was requested.
    pub fn handle_rescan(&mut self) {
        if self.shared.rescan.swap(false, Ordering::Relaxed) {
            self.reconcile_watches();
        }
    }

    /// Ensures every directory is watched, re-registering watches for
    /// directories that appeared or were replaced. Failures are reported
    /// once per transition and retried on the next call.
    pub fn reconcile_watches(&mut self) {
        let Some(inner) = self.inner.as_mut() else {
            return;
        };
        for dir in &mut self.dirs {
            let current = fs::metadata(&dir.path)
                .ok()
                .filter(|m| m.is_dir())
                .map(|m| FileId::of(&m));
            if current.is_some() && current == dir.watched {
                continue;
            }
            if dir.watched.is_some() {
                // Directory replaced or gone: drop the stale watch. An error
                // here just means the kernel already removed it.
                let _ = inner.unwatch(&dir.path);
            }
            let Some(id) = current else {
                if dir.watched.take().is_some() {
                    warn!(dir = %dir.path.display(), "watched directory disappeared");
                }
                continue;
            };
            match inner.watch(&dir.path, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    debug!(dir = %dir.path.display(), "watching directory");
                    dir.watched = Some(id);
                    dir.failed = false;
                    // Anything may have happened while unwatched.
                    if let Some(files) = self.shared.by_dir.get(&dir.path) {
                        for &i in files {
                            self.shared.dirty[i].store(true, Ordering::Relaxed);
                        }
                    }
                }
                Err(e) => {
                    if !dir.failed {
                        warn!(
                            dir = %dir.path.display(),
                            error = %e,
                            "cannot watch directory; relying on periodic reconciliation for it"
                        );
                    }
                    dir.watched = None;
                    dir.failed = true;
                }
            }
        }
    }

    /// Number of directories with an active watch.
    pub fn watched_dirs(&self) -> usize {
        self.dirs.iter().filter(|d| d.watched.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{Flag, ModifyKind};

    fn setup() -> (Watcher, Receiver<()>, Arc<Metrics>) {
        let files = [
            PathBuf::from("/logs/a.log"),
            PathBuf::from("/logs/b.log"),
            PathBuf::from("/other/c.log"),
        ];
        let (waker, rx) = wake_channel();
        let metrics = Arc::new(Metrics::default());
        let w = Watcher::new(&files, false, waker, Arc::clone(&metrics));
        for i in 0..files.len() {
            w.take_dirty(i);
        }
        (w, rx, metrics)
    }

    #[test]
    fn event_marks_only_matching_file() {
        let (w, rx, _) = setup();
        let ev = Event::new(EventKind::Modify(ModifyKind::Any)).add_path("/logs/b.log".into());
        w.shared.handle(Ok(ev));
        assert!(!w.take_dirty(0));
        assert!(w.take_dirty(1));
        assert!(!w.take_dirty(2));
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn unrelated_and_open_events_do_not_wake() {
        let (w, rx, _) = setup();
        w.shared.handle(Ok(
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path("/logs/zzz.log".into())
        ));
        w.shared
            .handle(Ok(Event::new(EventKind::Access(AccessKind::Open(
                notify::event::AccessMode::Read,
            )))
            .add_path("/logs/a.log".into())));
        assert!((0..3).all(|i| !w.take_dirty(i)));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn overflow_marks_everything_and_counts() {
        let (w, rx, metrics) = setup();
        w.shared
            .handle(Ok(Event::new(EventKind::Other).set_flag(Flag::Rescan)));
        assert!((0..3).all(|i| w.take_dirty(i)));
        assert_eq!(metrics.snapshot().notify_overflows, 1);
        assert!(w.shared.rescan.load(Ordering::Relaxed));
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn directory_event_marks_its_files_and_requests_rewatch() {
        let (w, _rx, _) = setup();
        w.shared.handle(Ok(Event::new(EventKind::Remove(
            notify::event::RemoveKind::Folder,
        ))
        .add_path("/logs".into())));
        assert!(w.take_dirty(0) && w.take_dirty(1) && !w.take_dirty(2));
        assert!(w.shared.rescan.load(Ordering::Relaxed));
    }

    #[test]
    fn wakeups_coalesce() {
        let (w, rx, _) = setup();
        for _ in 0..100 {
            w.shared.handle(Ok(
                Event::new(EventKind::Modify(ModifyKind::Any)).add_path("/logs/a.log".into())
            ));
        }
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }
}
