//! Persistent read offsets (`general.state_file`).
//!
//! With a state file, delivery across restarts is *at-least-once*: an
//! offset is saved only after every event produced from the lines before it
//! has been written and flushed to the output, so a crash can repeat events
//! but never skip lines.
//!
//! The monitor records [`Checkpoint`]s: the offsets of all files (just past
//! the last complete line read) together with the number of events queued
//! so far. The state thread saves the newest checkpoint whose events have
//! all been flushed. Lines that matched no rule are covered too, because
//! their offsets only advance together with the events before them.
//!
//! Each entry stores the file's identity and a fingerprint of its first
//! bytes. On startup, an entry is used only if the file at the path is the
//! same file (identity), still starts with the same bytes (so the inode was
//! not reused) and is at least as long as the saved offset (not truncated).
//! Otherwise the file is read from the beginning, since it changed while
//! logwizz was stopped.
//!
//! Writes are atomic: a temporary file next to the state file is written,
//! synced and renamed over it, and the directory is synced.

use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::dispatcher::Progress;
use crate::metrics::{self, Metrics};
use crate::reader::FileId;

/// State file format version.
const STATE_VERSION: u32 = 1;
/// Number of leading bytes covered by the fingerprint.
pub const FINGERPRINT_BYTES: u64 = 256;
/// A state file larger than this is not read.
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
/// Checkpoints waiting for their events to be flushed. When full, the
/// newest one is replaced, so a stalled output costs progress, not memory.
const MAX_PENDING: usize = 8;
/// Minimum time between "state file not written" warnings.
const SAVE_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// The saved position in one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileState {
    pub id: FileId,
    /// Just past the last complete line read.
    pub offset: u64,
    pub fingerprint: Fingerprint,
}

/// A hash of the first `len` bytes of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    pub len: u64,
    pub hash: u64,
}

impl Fingerprint {
    /// Fingerprints the first `min(limit, FINGERPRINT_BYTES)` bytes of `file`.
    pub fn of(file: &File, limit: u64) -> io::Result<Self> {
        let len = limit.min(FINGERPRINT_BYTES);
        let mut buf = [0u8; FINGERPRINT_BYTES as usize];
        let buf = &mut buf[..len as usize];
        let mut done = 0;
        while done < buf.len() {
            match file.read_at(&mut buf[done..], done as u64) {
                Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
                Ok(n) => done += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(Fingerprint {
            len,
            hash: fnv1a(buf),
        })
    }
}

/// FNV-1a: stable across Rust versions and platforms, unlike `std`'s hasher.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Why a saved entry was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mismatch {
    /// A different file is at the path (rotated while stopped).
    Replaced,
    /// The file is shorter than the saved offset.
    Truncated,
    /// Same inode, different content (truncated and rewritten, or reused).
    Changed,
}

impl Mismatch {
    pub fn as_str(self) -> &'static str {
        match self {
            Mismatch::Replaced => "file was replaced while stopped",
            Mismatch::Truncated => "file was truncated while stopped",
            Mismatch::Changed => "file content changed while stopped",
        }
    }
}

impl FileState {
    /// Checks this saved state against the open `file`; returns the offset
    /// to resume from.
    pub fn resume_offset(&self, file: &File, id: FileId, size: u64) -> Result<u64, Mismatch> {
        if id != self.id {
            return Err(Mismatch::Replaced);
        }
        if size < self.offset || size < self.fingerprint.len {
            return Err(Mismatch::Truncated);
        }
        match Fingerprint::of(file, self.fingerprint.len) {
            Ok(fp) if fp == self.fingerprint => Ok(self.offset),
            _ => Err(Mismatch::Changed),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    v: u32,
    files: Vec<Entry>,
    /// Cursor of the last journal entry handled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    journal_cursor: Option<String>,
}

/// What a state file holds.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Saved {
    pub files: HashMap<PathBuf, FileState>,
    pub journal_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: PathBuf,
    dev: u64,
    ino: u64,
    offset: u64,
    fp_len: u64,
    fp: u64,
}

/// Reads the state file. A missing file yields an empty map; an unreadable
/// or invalid one is reported and also yields an empty map, so a bad state
/// file never prevents startup.
pub fn load(path: &Path) -> Saved {
    match try_load(path) {
        Ok(saved) => {
            info!(
                path = %path.display(),
                files = saved.files.len(),
                journal = saved.journal_cursor.is_some(),
                "loaded saved offsets"
            );
            saved
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            info!(path = %path.display(), "no saved offsets yet");
            Saved::default()
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "cannot use state file; starting according to startup_mode"
            );
            Saved::default()
        }
    }
}

fn try_load(path: &Path) -> io::Result<Saved> {
    let mut text = Vec::new();
    File::open(path)?
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut text)?;
    if text.len() as u64 > MAX_STATE_BYTES {
        return Err(io::Error::other(format!(
            "larger than {MAX_STATE_BYTES} bytes"
        )));
    }
    let state: StateFile = serde_json::from_slice(&text).map_err(io::Error::other)?;
    if state.v != STATE_VERSION {
        return Err(io::Error::other(format!(
            "unsupported version {} (expected {STATE_VERSION})",
            state.v
        )));
    }
    let files = state
        .files
        .into_iter()
        .map(|e| {
            let st = FileState {
                id: FileId {
                    dev: e.dev,
                    ino: e.ino,
                },
                offset: e.offset,
                fingerprint: Fingerprint {
                    len: e.fp_len,
                    hash: e.fp,
                },
            };
            (e.path, st)
        })
        .collect();
    Ok(Saved {
        files,
        journal_cursor: state.journal_cursor,
    })
}

/// Atomically replaces the state file with `files`.
pub fn save(
    path: &Path,
    files: &[(&Path, FileState)],
    journal_cursor: Option<&str>,
) -> io::Result<()> {
    let state = StateFile {
        v: STATE_VERSION,
        files: files
            .iter()
            .map(|(p, st)| Entry {
                path: p.to_path_buf(),
                dev: st.id.dev,
                ino: st.id.ino,
                offset: st.offset,
                fp_len: st.fingerprint.len,
                fp: st.fingerprint.hash,
            })
            .collect(),
        journal_cursor: journal_cursor.map(String::from),
    };
    let mut bytes = serde_json::to_vec(&state).map_err(io::Error::other)?;
    bytes.push(b'\n');

    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    // Make the rename itself durable.
    let dir = path.parent().unwrap_or(Path::new("/"));
    File::open(dir)?.sync_all()
}

/// The offsets of all open files at one moment, and how many events had
/// been queued by then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub events: u64,
    pub files: Vec<(Arc<Path>, FileState)>,
    /// Cursor of the last journal entry passed to the rules.
    pub journal: Option<Arc<str>>,
}

/// Checkpoints recorded by the monitor and not yet saved.
#[derive(Debug, Default)]
pub struct Pending {
    queue: VecDeque<Checkpoint>,
}

impl Pending {
    pub fn push(&mut self, cp: Checkpoint) {
        if self
            .queue
            .back()
            .is_some_and(|b| b.files == cp.files && b.journal == cp.journal)
        {
            // Nothing moved; keep the older (more easily flushed) one.
            return;
        }
        if self.queue.len() >= MAX_PENDING {
            self.queue.pop_back();
        }
        self.queue.push_back(cp);
    }

    /// Removes and returns the newest checkpoint whose events have all
    /// been flushed, if any.
    pub fn take_flushed(&mut self, flushed: u64) -> Option<Checkpoint> {
        let mut newest = None;
        while self.queue.front().is_some_and(|c| c.events <= flushed) {
            newest = self.queue.pop_front();
        }
        newest
    }
}

/// Saves flushed checkpoints in the background.
pub struct StateWriter {
    pending: Arc<Mutex<Pending>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl StateWriter {
    pub fn spawn(
        path: PathBuf,
        interval: Duration,
        progress: Arc<Progress>,
        metrics: Arc<Metrics>,
    ) -> io::Result<Self> {
        let pending = Arc::new(Mutex::new(Pending::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut saver = Saver {
            path,
            last: None,
            last_warning: None,
            metrics,
        };
        let (p, s) = (Arc::clone(&pending), Arc::clone(&stop));
        let handle = thread::Builder::new().name("state".into()).spawn(move || {
            loop {
                let stopping = s.load(Ordering::Acquire);
                let flushed = progress.flushed();
                let cp = p
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take_flushed(flushed);
                if let Some(cp) = cp {
                    saver.save(cp);
                }
                if stopping {
                    break;
                }
                thread::park_timeout(interval);
            }
        })?;
        Ok(StateWriter {
            pending,
            stop,
            handle: Some(handle),
        })
    }

    pub fn record(&self, cp: Checkpoint) {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(cp);
    }

    /// Makes a final save attempt and stops the thread. Call after the
    /// output has been flushed.
    pub fn finish(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            h.thread().unpark();
            let _ = h.join();
        }
    }
}

struct Saver {
    path: PathBuf,
    last: Option<Checkpoint>,
    last_warning: Option<Instant>,
    metrics: Arc<Metrics>,
}

impl Saver {
    fn save(&mut self, cp: Checkpoint) {
        if self
            .last
            .as_ref()
            .is_some_and(|l| l.files == cp.files && l.journal == cp.journal)
        {
            return;
        }
        let entries: Vec<(&Path, FileState)> = cp.files.iter().map(|(p, st)| (&**p, *st)).collect();
        match save(&self.path, &entries, cp.journal.as_deref()) {
            Ok(()) => {
                metrics::inc(&self.metrics.state_saves);
                if self.last_warning.take().is_some() {
                    info!(path = %self.path.display(), "state file written again");
                }
                debug!(files = entries.len(), "offsets saved");
                self.last = Some(cp);
            }
            Err(e) => {
                metrics::inc(&self.metrics.state_save_errors);
                let now = Instant::now();
                if self
                    .last_warning
                    .is_none_or(|t| now.duration_since(t) >= SAVE_WARN_INTERVAL)
                {
                    warn!(
                        path = %self.path.display(),
                        error = %e,
                        "cannot write state file; will retry"
                    );
                    self.last_warning = Some(now);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn st(offset: u64) -> FileState {
        FileState {
            id: FileId { dev: 1, ino: 2 },
            offset,
            fingerprint: Fingerprint { len: 0, hash: 0 },
        }
    }

    fn cp(events: u64, offset: u64) -> Checkpoint {
        Checkpoint {
            events,
            files: vec![(Path::new("/a.log").into(), st(offset))],
            journal: None,
        }
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("offsets.json");
        let a = dir.path().join("a.log");
        save(&path, &[(&a, st(42))], None).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!dir.path().join("offsets.json.tmp").exists());
        let map = load(&path);
        assert_eq!(map.files.len(), 1);
        assert_eq!(map.files[&a], st(42));
        assert_eq!(map.journal_cursor, None);
        assert!(!fs::read_to_string(&path).unwrap().contains("journal"));
        save(&path, &[], Some("s=abc;i=1f")).unwrap();
        assert_eq!(load(&path).journal_cursor.as_deref(), Some("s=abc;i=1f"));
    }

    #[test]
    fn missing_corrupt_or_wrong_version_yields_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("offsets.json");
        assert_eq!(load(&path), Saved::default());
        fs::write(&path, "{not json").unwrap();
        assert_eq!(load(&path), Saved::default());
        fs::write(&path, r#"{"v":99,"files":[]}"#).unwrap();
        assert_eq!(load(&path), Saved::default());
    }

    #[test]
    fn fingerprint_detects_changed_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        fs::write(&p, "hello world\n").unwrap();
        let f = File::open(&p).unwrap();
        let fp = Fingerprint::of(&f, 12).unwrap();
        assert_eq!(fp.len, 12);
        let saved = FileState {
            id: FileId { dev: 1, ino: 2 },
            offset: 12,
            fingerprint: fp,
        };
        let id = saved.id;
        assert_eq!(saved.resume_offset(&f, id, 12), Ok(12));
        assert_eq!(
            saved.resume_offset(&f, FileId { dev: 1, ino: 3 }, 12),
            Err(Mismatch::Replaced)
        );
        assert_eq!(saved.resume_offset(&f, id, 5), Err(Mismatch::Truncated));
        fs::write(&p, "HELLO world\n").unwrap();
        assert_eq!(saved.resume_offset(&f, id, 12), Err(Mismatch::Changed));
    }

    #[test]
    fn fingerprint_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        fs::write(&p, vec![b'x'; 1000]).unwrap();
        let fp = Fingerprint::of(&File::open(&p).unwrap(), 1000).unwrap();
        assert_eq!(fp.len, FINGERPRINT_BYTES);
    }

    #[test]
    fn only_flushed_checkpoints_are_taken() {
        let mut p = Pending::default();
        p.push(cp(0, 10));
        p.push(cp(5, 20));
        p.push(cp(9, 30));
        assert_eq!(p.take_flushed(4), Some(cp(0, 10)));
        assert_eq!(p.take_flushed(4), None);
        assert_eq!(p.take_flushed(9), Some(cp(9, 30)));
        assert_eq!(p.take_flushed(100), None);
    }

    #[test]
    fn checkpoints_with_other_files_are_not_merged() {
        let mut p = Pending::default();
        p.push(cp(1, 1));
        let mut reloaded = cp(2, 1);
        reloaded.files = vec![(Path::new("/c.log").into(), st(1))];
        p.push(reloaded.clone());
        assert_eq!(p.queue.len(), 2, "same offsets, other files");
        assert_eq!(p.take_flushed(2), Some(reloaded));
    }

    #[test]
    fn saved_entries_follow_the_checkpoint_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("offsets.json");
        let mut saver = Saver {
            path: path.clone(),
            last: None,
            last_warning: None,
            metrics: Arc::new(Metrics::default()),
        };
        saver.save(cp(0, 5));
        assert_eq!(load(&path).files[Path::new("/a.log")], st(5));
        let mut reloaded = cp(1, 5);
        reloaded.files = vec![(Path::new("/a.log").into(), st(7))];
        saver.save(reloaded);
        let map = load(&path);
        assert_eq!(map.files.len(), 1);
        assert_eq!(map.files[Path::new("/a.log")], st(7));
    }

    #[test]
    fn pending_is_bounded_and_skips_unchanged() {
        let mut p = Pending::default();
        p.push(cp(1, 1));
        p.push(cp(2, 1));
        assert_eq!(p.queue.len(), 1, "unchanged offsets are not queued twice");
        for i in 0..100 {
            p.push(cp(i + 10, i + 10));
        }
        assert_eq!(p.queue.len(), MAX_PENDING);
        assert_eq!(p.queue.back(), Some(&cp(109, 109)), "newest kept");
        assert_eq!(p.queue.front(), Some(&cp(1, 1)), "oldest kept");
    }
}
