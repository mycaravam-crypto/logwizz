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
//! If a configured path is a symlink, writes to its target only produce
//! events in the target's directory, so that directory is watched too (at
//! most one extra directory per configured file). Targets are re-resolved on
//! every reconciliation and whenever a file's identity changes, so a
//! retargeted symlink moves the extra watch; unused extra watches are
//! removed.
//!
//! For a `[[files]] glob`, its directory is watched, and every creation,
//! removal or rename of a matching name marks the glob dirty, so the monitor
//! lists the directory again. Files found that way get a slot like any other
//! file; slots are reused when the files stop being followed.
//!
//! Memory use is bounded: the notify thread only sets per-file dirty flags
//! and performs a coalescing `try_send` on a capacity-1 wake channel. There
//! is no event queue that can grow without limit.

use std::collections::HashMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard};

use notify::event::{AccessKind, ModifyKind};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use tracing::{debug, warn};

use crate::config::Glob;
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

/// Followed files by slot. The slots of files that are no longer followed
/// are reused, so these only grow to the largest number of files followed
/// at once.
#[derive(Debug, Default)]
struct Files {
    dirty: Vec<AtomicBool>,
    /// Followed path -> slot.
    by_path: HashMap<PathBuf, usize>,
    /// Watched directory -> slots of the followed files in it.
    by_dir: HashMap<PathBuf, Vec<usize>>,
}

impl Files {
    fn mark(&self, slots: &[usize]) {
        for &i in slots {
            self.dirty[i].store(true, Ordering::Relaxed);
        }
    }
}

/// State shared with the notify thread.
#[derive(Debug)]
struct Shared {
    /// Changed only by the monitor thread.
    files: RwLock<Files>,
    globs: Vec<Glob>,
    /// Per glob: a matching name may have appeared or disappeared, so its
    /// directory should be listed again.
    glob_dirty: Vec<AtomicBool>,
    /// Directory searched by a glob -> indices of the globs.
    glob_dirs: HashMap<PathBuf, Vec<usize>>,
    /// Set when the kernel dropped events or a watch broke; makes every
    /// file dirty and triggers re-registration of directory watches.
    rescan: AtomicBool,
    /// Symlink targets; changed only by the monitor thread.
    targets: RwLock<Targets>,
    waker: Waker,
    metrics: Arc<Metrics>,
}

/// Where events for symlink targets arrive.
#[derive(Debug, Default)]
struct Targets {
    /// Event path of a target -> slots of the files that point at it.
    files: HashMap<PathBuf, Vec<usize>>,
    /// Extra watched directory -> slots of files with a target in it.
    dirs: HashMap<PathBuf, Vec<usize>>,
}

/// The resolved target of a symlinked file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    /// The path events for the target arrive with: the target's name in
    /// the watched directory that contains it.
    event_path: PathBuf,
    /// The extra directory to watch, if the target is not in a directory
    /// that is already watched.
    extra_dir: Option<PathBuf>,
}

impl Shared {
    fn files(&self) -> RwLockReadGuard<'_, Files> {
        self.files.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn mark_all(&self) {
        for d in &self.files().dirty {
            d.store(true, Ordering::Relaxed);
        }
        for d in &self.glob_dirty {
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
        // Only these can change which names exist in a directory.
        let names_changed = matches!(
            event.kind,
            EventKind::Create(_)
                | EventKind::Remove(_)
                | EventKind::Modify(ModifyKind::Name(_))
                | EventKind::Any
                | EventKind::Other
        );
        let files = self.files();
        let targets = self.targets.read().unwrap_or_else(PoisonError::into_inner);
        let mut hit = false;
        for path in &event.paths {
            if let Some(&i) = files.by_path.get(path) {
                files.dirty[i].store(true, Ordering::Relaxed);
                hit = true;
            }
            if let Some(slots) = targets.files.get(path) {
                files.mark(slots);
                hit = true;
            }
            if names_changed {
                let globs = path.parent().and_then(|d| self.glob_dirs.get(d));
                if let (Some(globs), Some(name)) = (globs, path.file_name()) {
                    for &g in globs {
                        if self.globs[g].matches(name.as_bytes()) {
                            self.glob_dirty[g].store(true, Ordering::Relaxed);
                            hit = true;
                        }
                    }
                }
            }
            // An event on a watched directory itself (removed, moved): its
            // watch is likely gone and must be re-established.
            let dir_files = files.by_dir.get(path).or_else(|| targets.dirs.get(path));
            if let Some(slots) = dir_files {
                files.mark(slots);
                self.rescan.store(true, Ordering::Relaxed);
                hit = true;
            }
            if let Some(globs) = self.glob_dirs.get(path) {
                for &g in globs {
                    self.glob_dirty[g].store(true, Ordering::Relaxed);
                }
                self.rescan.store(true, Ordering::Relaxed);
                hit = true;
            }
        }
        drop(targets);
        drop(files);
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
    /// Watched only because a symlink target is in it.
    extra: bool,
}

/// Owns the inotify watcher and the per-file dirty flags.
///
/// Files are identified by *slot*. Configured paths have the fixed slots
/// `0..files.len()`; files found by globs are added and removed while
/// running, and their slots are reused.
pub struct Watcher {
    inner: Option<RecommendedWatcher>,
    shared: Arc<Shared>,
    dirs: Vec<DirWatch>,
    /// Followed path of each slot; `None` for a free slot.
    files: Vec<Option<PathBuf>>,
    free: Vec<usize>,
    /// Resolved symlink target of each slot (`None` if not a symlink).
    targets: Vec<Option<Target>>,
}

impl Watcher {
    /// Sets up notifications for `files` and for the directories of
    /// `globs`. With `notifications = false`, or if inotify is unavailable
    /// (e.g. `fs.inotify.max_user_instances` exhausted), only periodic
    /// reconciliation detects changes.
    pub fn new(
        files: &[PathBuf],
        globs: &[Glob],
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
        let mut glob_dirs: HashMap<PathBuf, Vec<usize>> = HashMap::new();
        for (g, glob) in globs.iter().enumerate() {
            glob_dirs.entry(glob.dir.clone()).or_default().push(g);
        }
        let mut dirs: Vec<DirWatch> = by_dir
            .keys()
            .chain(glob_dirs.keys().filter(|d| !by_dir.contains_key(*d)))
            .map(|p| DirWatch {
                path: p.clone(),
                watched: None,
                failed: false,
                extra: false,
            })
            .collect();
        dirs.sort_by(|a, b| a.path.cmp(&b.path));

        let shared = Arc::new(Shared {
            files: RwLock::new(Files {
                dirty: files.iter().map(|_| AtomicBool::new(true)).collect(),
                by_path,
                by_dir,
            }),
            globs: globs.to_vec(),
            glob_dirty: globs.iter().map(|_| AtomicBool::new(true)).collect(),
            glob_dirs,
            rescan: AtomicBool::new(false),
            targets: RwLock::default(),
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
            targets: vec![None; files.len()],
            files: files.iter().cloned().map(Some).collect(),
            free: Vec::new(),
        };
        watcher.reconcile_watches();
        watcher
    }

    pub fn is_active(&self) -> bool {
        self.inner.is_some()
    }

    /// Number of slots, free ones included.
    pub fn slots(&self) -> usize {
        self.files.len()
    }

    /// Starts following `path`, which must be in the directory of a glob,
    /// and returns its slot. The new slot is dirty.
    pub fn add(&mut self, path: PathBuf) -> usize {
        let dir = path.parent().unwrap_or(Path::new("/")).to_path_buf();
        let mut files = self
            .shared
            .files
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let i = match self.free.pop() {
            Some(i) => i,
            None => {
                files.dirty.push(AtomicBool::new(false));
                self.files.push(None);
                self.targets.push(None);
                self.files.len() - 1
            }
        };
        files.dirty[i].store(true, Ordering::Relaxed);
        files.by_path.insert(path.clone(), i);
        files.by_dir.entry(dir).or_default().push(i);
        self.files[i] = Some(path);
        i
    }

    /// Stops following the file in slot `i`; the slot may be reused.
    pub fn remove(&mut self, i: usize) {
        let Some(path) = self.files[i].take() else {
            return;
        };
        let mut files = self
            .shared
            .files
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        files.by_path.remove(&path);
        if let Some(slots) = path.parent().and_then(|d| files.by_dir.get_mut(d)) {
            slots.retain(|&s| s != i);
        }
        files.dirty[i].store(false, Ordering::Relaxed);
        self.free.push(i);
        // Its symlink target, if any, is dropped by the next
        // `refresh_targets`.
    }

    /// The slot of `path` if it is followed.
    pub fn slot_of(&self, path: &Path) -> Option<usize> {
        self.shared.files().by_path.get(path).copied()
    }

    /// Clears and returns the dirty flag of slot `i`.
    pub fn take_dirty(&self, i: usize) -> bool {
        self.shared.files().dirty[i].swap(false, Ordering::Relaxed)
    }

    pub fn mark_dirty(&self, i: usize) {
        self.shared.files().dirty[i].store(true, Ordering::Relaxed);
    }

    pub fn mark_all_dirty(&self) {
        self.shared.mark_all();
    }

    /// Clears and returns the dirty flag of glob `g`.
    pub fn take_glob_dirty(&self, g: usize) -> bool {
        self.shared.glob_dirty[g].swap(false, Ordering::Relaxed)
    }

    pub fn mark_glob_dirty(&self, g: usize) {
        self.shared.glob_dirty[g].store(true, Ordering::Relaxed);
    }

    /// Re-registers directory watches if a rescan was requested.
    pub fn handle_rescan(&mut self) {
        if self.shared.rescan.swap(false, Ordering::Relaxed) {
            self.reconcile_watches();
        }
    }

    /// Ensures every directory is watched, re-registering watches for
    /// directories that appeared or were replaced, and re-resolves symlink
    /// targets. Failures are reported once per transition and retried on
    /// the next call.
    pub fn reconcile_watches(&mut self) {
        self.register_dirs();
        self.refresh_targets();
    }

    /// Re-resolves the targets of symlinked files and moves the extra
    /// directory watches accordingly. Cheap when nothing changed: one
    /// `lstat` per file, plus a resolution for each symlink.
    pub fn refresh_targets(&mut self) {
        if self.inner.is_none() {
            return;
        }
        let targets: Vec<Option<Target>> = self
            .files
            .iter()
            .map(|p| p.as_deref().and_then(|p| self.resolve(p)))
            .collect();
        if targets == self.targets {
            return;
        }
        self.targets = targets;

        let mut map = Targets::default();
        for (i, t) in self.targets.iter().enumerate() {
            let Some(t) = t else { continue };
            map.files.entry(t.event_path.clone()).or_default().push(i);
            if let Some(dir) = &t.extra_dir {
                map.dirs.entry(dir.clone()).or_default().push(i);
            }
        }
        // Drop extra watches nobody needs any more, then add new ones.
        let mut removed = Vec::new();
        if let Some(inner) = self.inner.as_mut() {
            self.dirs.retain(|d| {
                if !d.extra || map.dirs.contains_key(&d.path) {
                    return true;
                }
                if let Some(id) = d.watched {
                    let _ = inner.unwatch(&d.path);
                    removed.push(id);
                }
                debug!(dir = %d.path.display(), "stopped watching symlink target directory");
                false
            });
        }
        // The kernel shares one watch per directory inode, so the removal
        // also ended any other watch on the same directory: re-register it.
        for d in &mut self.dirs {
            if d.watched.is_some_and(|id| removed.contains(&id)) {
                d.watched = None;
            }
        }
        for dir in map.dirs.keys() {
            if !self.dirs.iter().any(|d| &d.path == dir) {
                self.dirs.push(DirWatch {
                    path: dir.clone(),
                    watched: None,
                    failed: false,
                    extra: true,
                });
            }
        }
        *self
            .shared
            .targets
            .write()
            .unwrap_or_else(PoisonError::into_inner) = map;
        self.register_dirs();
    }

    /// The target of `path` if it is a symlink whose target can be resolved.
    fn resolve(&self, path: &Path) -> Option<Target> {
        let link = fs::symlink_metadata(path).ok()?;
        if !link.file_type().is_symlink() {
            return None;
        }
        let target = fs::canonicalize(path).ok()?;
        let (dir, name) = (target.parent()?, target.file_name()?);
        let dir_id = FileId::of(&fs::metadata(dir).ok()?);
        // inotify keeps one watch per directory inode: if the directory is
        // already watched (possibly under another path), events arrive with
        // that path, and a second watch must not be added.
        let watched = self
            .dirs
            .iter()
            .find(|d| d.watched == Some(dir_id) && !(d.extra && d.path != dir));
        Some(match watched {
            Some(d) => Target {
                event_path: d.path.join(name),
                extra_dir: d.extra.then(|| d.path.clone()),
            },
            None => Target {
                event_path: target.clone(),
                extra_dir: Some(dir.to_path_buf()),
            },
        })
    }

    fn register_dirs(&mut self) {
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
                    let files = self.shared.files();
                    let targets = self
                        .shared
                        .targets
                        .read()
                        .unwrap_or_else(PoisonError::into_inner);
                    let slots = if dir.extra {
                        targets.dirs.get(&dir.path)
                    } else {
                        files.by_dir.get(&dir.path)
                    };
                    files.mark(slots.map_or(&[], Vec::as_slice));
                    if !dir.extra {
                        for &g in self.shared.glob_dirs.get(&dir.path).into_iter().flatten() {
                            self.shared.glob_dirty[g].store(true, Ordering::Relaxed);
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
    use notify::event::{CreateKind, Flag};

    fn setup() -> (Watcher, Receiver<()>, Arc<Metrics>) {
        let files = [
            PathBuf::from("/logs/a.log"),
            PathBuf::from("/logs/b.log"),
            PathBuf::from("/other/c.log"),
        ];
        let (waker, rx) = wake_channel();
        let metrics = Arc::new(Metrics::default());
        let w = Watcher::new(&files, &[], false, waker, Arc::clone(&metrics));
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
    fn event_on_symlink_target_marks_file() {
        let (w, rx, _) = setup();
        w.shared
            .targets
            .write()
            .unwrap()
            .files
            .insert("/data/2026.log".into(), vec![0, 2]);
        w.shared.handle(Ok(
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path("/data/2026.log".into())
        ));
        assert!(w.take_dirty(0) && !w.take_dirty(1) && w.take_dirty(2));
        assert!(rx.try_recv().is_ok());
    }

    fn glob(text: &str, exclude: Option<&str>) -> Glob {
        let exclude = exclude.map_or(String::new(), |e| format!("exclude = {e:?}\n"));
        let toml = format!(
            "[[files]]\nglob = {text:?}\n{exclude}\
             [[rules]]\nid = \"r\"\nmatch_type = \"literal\"\npattern = \"x\"\nseverity = \"info\"\n"
        );
        crate::config::parse(&toml, Path::new("t"))
            .unwrap()
            .globs
            .remove(0)
    }

    #[test]
    fn added_slots_receive_events_and_are_reused() {
        let (waker, rx) = wake_channel();
        let globs = [glob("/logs/*.log", None)];
        let mut w = Watcher::new(
            &[PathBuf::from("/logs/a.log")],
            &globs,
            false,
            waker,
            Arc::new(Metrics::default()),
        );
        assert!(w.take_dirty(0) && w.take_glob_dirty(0), "all start dirty");
        let b = w.add("/logs/b.log".into());
        assert_eq!(b, 1);
        assert!(w.take_dirty(b), "new slot is dirty");
        assert_eq!(w.slot_of(Path::new("/logs/b.log")), Some(b));

        w.shared.handle(Ok(
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path("/logs/b.log".into())
        ));
        assert!(w.take_dirty(b) && !w.take_dirty(0));
        assert!(!w.take_glob_dirty(0), "content changes need no listing");
        assert!(rx.try_recv().is_ok());

        w.remove(b);
        assert_eq!(w.slot_of(Path::new("/logs/b.log")), None);
        w.shared.handle(Ok(
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path("/logs/b.log".into())
        ));
        assert!(!w.take_dirty(b));
        assert_eq!(w.add("/logs/c.log".into()), b, "slot reused");
        assert_eq!(w.slots(), 2);
    }

    #[test]
    fn matching_name_changes_mark_the_glob() {
        let (waker, rx) = wake_channel();
        let globs = [glob("/logs/*.log", Some("old*"))];
        let w = Watcher::new(&[], &globs, false, waker, Arc::new(Metrics::default()));
        w.take_glob_dirty(0);
        let create = |p: &str| Event::new(EventKind::Create(CreateKind::File)).add_path(p.into());

        for p in ["/logs/x.txt", "/logs/old.log", "/other/new.log"] {
            w.shared.handle(Ok(create(p)));
            assert!(!w.take_glob_dirty(0), "{p}");
        }
        assert!(rx.try_recv().is_err());
        w.shared.handle(Ok(
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path("/logs/new.log".into())
        ));
        assert!(
            !w.take_glob_dirty(0),
            "writes to unfollowed files are ignored"
        );

        w.shared.handle(Ok(create("/logs/new.log")));
        assert!(w.take_glob_dirty(0));
        assert!(rx.try_recv().is_ok());
        w.shared.handle(Ok(Event::new(EventKind::Remove(
            notify::event::RemoveKind::Folder,
        ))
        .add_path("/logs".into())));
        assert!(w.take_glob_dirty(0), "directory replaced");
        assert!(w.shared.rescan.load(Ordering::Relaxed));
    }

    fn real_watcher(files: &[PathBuf]) -> Watcher {
        let (waker, _rx) = wake_channel();
        let w = Watcher::new(files, &[], true, waker, Arc::new(Metrics::default()));
        assert!(w.is_active());
        w
    }

    #[test]
    fn symlink_target_directory_watch_follows_retarget() {
        let base = tempfile::tempdir().unwrap();
        let (links, d1, d2) = (
            base.path().join("l"),
            base.path().join("d1"),
            base.path().join("d2"),
        );
        for d in [&links, &d1, &d2] {
            fs::create_dir(d).unwrap();
        }
        let (t1, t2) = (d1.join("a.log"), d2.join("b.log"));
        fs::write(&t1, "").unwrap();
        fs::write(&t2, "").unwrap();
        let link = links.join("current.log");
        std::os::unix::fs::symlink(&t1, &link).unwrap();

        let mut w = real_watcher(std::slice::from_ref(&link));
        assert_eq!(w.watched_dirs(), 2, "configured dir + target dir");
        let canon1 = fs::canonicalize(&t1).unwrap();
        assert_eq!(w.targets[0].as_ref().unwrap().event_path, canon1);

        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&t2, &link).unwrap();
        w.refresh_targets();
        assert_eq!(
            w.watched_dirs(),
            2,
            "old target dir unwatched, new one watched"
        );
        let extra: Vec<_> = w.dirs.iter().filter(|d| d.extra).map(|d| &d.path).collect();
        assert_eq!(extra, [&fs::canonicalize(&d2).unwrap()]);

        // No longer a symlink: the extra watch goes away.
        fs::remove_file(&link).unwrap();
        fs::write(&link, "").unwrap();
        w.refresh_targets();
        assert_eq!(w.watched_dirs(), 1);
        assert!(w.shared.targets.read().unwrap().files.is_empty());
    }

    #[test]
    fn symlink_target_in_watched_directory_needs_no_extra_watch() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("2026.log");
        fs::write(&target, "").unwrap();
        let link = dir.path().join("current.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let w = real_watcher(std::slice::from_ref(&link));
        assert_eq!(w.watched_dirs(), 1);
        // Events arrive with the configured directory's path.
        let t = w.targets[0].as_ref().unwrap();
        assert_eq!(t.event_path, target);
        assert_eq!(t.extra_dir, None);
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
