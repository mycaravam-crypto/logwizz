//! Incremental reading of log files.
//!
//! # Model
//!
//! A [`TailedFile`] is bound to a configured *path*. At any time it holds at
//! most two open *sources* (file descriptors):
//!
//! * `current`: the file that the path referred to when it was last checked.
//! * `draining`: a file that used to be at the path but was replaced (rename
//!   and create, or a retargeted symlink). It is read until it has produced
//!   no new data for the drain grace period, so lines a writer appends just
//!   after rotation are not lost. Its data is always emitted before data from
//!   `current`.
//!
//! A file's identity is its `(st_dev, st_ino)` pair. Because we keep the
//! descriptor open, the kernel cannot reuse that inode while we compare
//! against it, so an identity match really is the same file.
//!
//! # Semantics
//!
//! * Offsets are kept in memory only; nothing is persisted across restarts.
//! * Truncation (size below our offset, e.g. `copytruncate`) restarts reading
//!   at offset 0. Data written after the truncation but before we notice it,
//!   beyond our old offset, is indistinguishable from old data and may be
//!   missed. This is an inherent limitation of copytruncate.
//! * A deleted file (link count 0) is drained to EOF and closed.
//! * A file renamed away without replacement keeps being read, since its
//!   writer usually keeps appending until it reopens its log.
//! * Lines longer than `max_line_bytes` (not counting a `\r\n` or `\n`
//!   terminator) are cut to that length, flagged as truncated and counted;
//!   the excess is counted in `bytes_skipped`.
//! * An unterminated trailing line is held until its newline arrives. If the
//!   source ends first (truncation, rotation, deletion) it is emitted as is
//!   and counted in `partial_lines_flushed`.
//! * Symlinks are followed: the identity is that of the target, and a
//!   retargeted symlink is treated as a rotation.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use memchr::{memchr, memrchr};
use tracing::{debug, info, warn};

use crate::config::StartupMode;
use crate::metrics::{self, Metrics};
use crate::state::{FINGERPRINT_BYTES, FileState, Fingerprint};

/// Default size of the shared read buffer.
pub const READ_BUF_BYTES: usize = 64 * 1024;

/// Identity of an open file, independent of its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
}

impl FileId {
    pub fn of(meta: &Metadata) -> Self {
        FileId {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

/// One line handed to the consumer. `bytes` excludes the line terminator.
#[derive(Debug, Clone, Copy)]
pub struct Line<'a> {
    pub bytes: &'a [u8],
    /// The line was longer than `max_line_bytes` and has been cut.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ReaderOptions {
    pub max_line_bytes: usize,
    /// Maximum bytes read from one file per [`TailedFile::poll`] call, so a
    /// single busy file cannot starve the others.
    pub read_budget: usize,
    /// How long a rotated-away file must stay idle before it is closed.
    pub drain_grace: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Skip {
    None,
    /// Discarding the rest of an over-long line (counted).
    Oversize,
    /// Discarding the rest of a line that began before startup in tail mode
    /// (expected, not counted).
    StartupPartial,
}

/// Splits a byte stream into lines, holding at most `max` bytes of an
/// incomplete line, plus one trailing `\r` that may turn out to be part of a
/// CRLF terminator (so at most `max + 1` bytes per file).
///
/// Lengths are measured without the line terminator: a CRLF line with exactly
/// `max` bytes of content is not truncated, and a `\r` that ends a cut line
/// is not counted in `bytes_skipped`.
#[derive(Debug)]
struct LineSplitter {
    pending: Vec<u8>,
    skip: Skip,
    /// While skipping: the last skipped byte was a `\r` that has not been
    /// counted yet, because it may belong to the CRLF terminator.
    held_cr: bool,
    max: usize,
}

impl LineSplitter {
    fn new(max: usize) -> Self {
        LineSplitter {
            pending: Vec::new(),
            skip: Skip::None,
            held_cr: false,
            max,
        }
    }

    fn feed(&mut self, mut data: &[u8], m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) {
        while let Some(i) = memchr(b'\n', data) {
            self.complete(&data[..i], m, on_line);
            data = &data[i + 1..];
        }
        if !data.is_empty() {
            self.partial(data, m, on_line);
        }
    }

    /// `seg` ends at a newline (exclusive).
    fn complete(&mut self, seg: &[u8], m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) {
        match self.skip {
            Skip::None => {}
            Skip::Oversize => {
                self.count_skipped(seg, true, m);
                self.skip = Skip::None;
                return;
            }
            Skip::StartupPartial => {
                self.skip = Skip::None;
                return;
            }
        }
        if self.pending.is_empty() {
            emit(seg, self.max, m, on_line);
            return;
        }
        if self.pending.len() + seg.len() <= self.max + 1 {
            // At most `max` bytes of content plus a possible `\r`.
            self.pending.extend_from_slice(seg);
            emit(&self.pending, self.max, m, on_line);
        } else {
            // More than `max + 1` bytes, so more than `max` bytes of content.
            let fill = self.cut_pending(seg);
            self.count_skipped(&seg[fill..], true, m);
            emit_truncated(&self.pending, m, on_line);
        }
        self.reset_pending();
    }

    /// `seg` is a non-empty tail with no newline yet.
    fn partial(&mut self, seg: &[u8], m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) {
        match self.skip {
            Skip::None => {}
            Skip::Oversize => {
                self.count_skipped(seg, false, m);
                return;
            }
            Skip::StartupPartial => return,
        }
        let total = self.pending.len() + seg.len();
        if total <= self.max || (total == self.max + 1 && seg.ends_with(b"\r")) {
            self.pending.extend_from_slice(seg);
            return;
        }
        // The line is already longer than allowed: emit what fits now and
        // discard the remainder up to the next newline.
        let fill = self.cut_pending(seg);
        self.count_skipped(&seg[fill..], false, m);
        emit_truncated(&self.pending, m, on_line);
        self.reset_pending();
        self.skip = Skip::Oversize;
    }

    /// Cuts `pending` + `seg` to `max` bytes in `pending`, counting a held
    /// `\r` that is now known to be content. Returns how many bytes of `seg`
    /// were used.
    fn cut_pending(&mut self, seg: &[u8]) -> usize {
        if self.pending.len() > self.max {
            // The held trailing `\r` was not followed by a newline: it is
            // content beyond `max`, skipped together with the rest.
            self.pending.truncate(self.max);
            self.held_cr = true;
        }
        let fill = self.max - self.pending.len();
        self.pending.extend_from_slice(&seg[..fill]);
        fill
    }

    /// Counts the skipped bytes `seg` of an over-long line, not counting a
    /// trailing `\r` that is (or may still turn out to be) the terminator.
    fn count_skipped(&mut self, seg: &[u8], ends_line: bool, m: &Metrics) {
        let mut n = seg.len() + usize::from(self.held_cr);
        self.held_cr = false;
        let last_is_cr = match seg.last() {
            Some(&b) => b == b'\r',
            None => n > 0,
        };
        if last_is_cr {
            n -= 1;
            self.held_cr = !ends_line;
        }
        metrics::add(&m.bytes_skipped, n as u64);
    }

    /// Emits any held partial line; called when its source ends.
    fn flush(&mut self, m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) {
        if !self.pending.is_empty() {
            metrics::inc(&m.partial_lines_flushed);
            emit(&self.pending, self.max, m, on_line);
        }
        self.reset_pending();
        if self.held_cr {
            metrics::inc(&m.bytes_skipped);
            self.held_cr = false;
        }
        self.skip = Skip::None;
    }

    fn reset_pending(&mut self) {
        self.pending.clear();
        // Do not keep a large allocation around after a single long line.
        if self.pending.capacity() > READ_BUF_BYTES {
            self.pending = Vec::new();
        }
    }
}

/// Emits one line, without its terminator (`\n`, already removed, and a
/// trailing `\r`), cut to `max` bytes if longer.
fn emit(line: &[u8], max: usize, m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) {
    let bytes = line.strip_suffix(b"\r").unwrap_or(line);
    if bytes.len() > max {
        metrics::add(&m.bytes_skipped, (bytes.len() - max) as u64);
        emit_truncated(&bytes[..max], m, on_line);
        return;
    }
    metrics::inc(&m.lines_processed);
    on_line(Line {
        bytes,
        truncated: false,
    });
}

fn emit_truncated(line: &[u8], m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) {
    metrics::inc(&m.lines_processed);
    metrics::inc(&m.lines_truncated);
    on_line(Line {
        bytes: line,
        truncated: true,
    });
}

/// An open descriptor with its read state.
#[derive(Debug)]
struct Source {
    file: File,
    id: FileId,
    offset: u64,
    /// Just past the last newline read: where reading would restart after
    /// a restart, so that no partially read line is lost.
    line_end: u64,
    /// Cached fingerprint for checkpoints; final once it covers
    /// `FINGERPRINT_BYTES`.
    fingerprint: Option<Fingerprint>,
    splitter: LineSplitter,
    /// Last read error kind, to report each distinct failure once.
    error: Option<ErrorKind>,
}

/// Result of reading a source as far as the budget allows.
enum ReadEnd {
    Eof,
    BudgetExhausted,
}

impl Source {
    /// Reads appended data until EOF or until `budget` is used up.
    fn read(
        &mut self,
        path: &Path,
        budget: &mut usize,
        buf: &mut [u8],
        m: &Metrics,
        on_line: &mut dyn FnMut(Line<'_>),
    ) -> io::Result<ReadEnd> {
        let size = self.file.metadata()?.len();
        if size < self.offset {
            warn!(
                path = %path.display(),
                old_offset = self.offset,
                new_size = size,
                "file truncated; reading from the beginning"
            );
            metrics::inc(&m.truncations);
            self.splitter.flush(m, on_line);
            self.offset = 0;
            self.line_end = 0;
            self.fingerprint = None;
        }
        loop {
            if *budget == 0 {
                return Ok(ReadEnd::BudgetExhausted);
            }
            let want = buf.len().min(*budget);
            match self.file.read_at(&mut buf[..want], self.offset) {
                Ok(0) => return Ok(ReadEnd::Eof),
                Ok(n) => {
                    let start = self.offset;
                    self.offset += n as u64;
                    *budget -= n;
                    metrics::add(&m.bytes_read, n as u64);
                    self.splitter.feed(&buf[..n], m, on_line);
                    if let Some(i) = memrchr(b'\n', &buf[..n]) {
                        self.line_end = start + i as u64 + 1;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Reads and records (rather than propagates) errors, counting each
    /// distinct failure once. Returns `Ok(true)` if the budget ran out
    /// before EOF.
    fn read_logged(
        &mut self,
        path: &Path,
        budget: &mut usize,
        buf: &mut [u8],
        m: &Metrics,
        on_line: &mut dyn FnMut(Line<'_>),
    ) -> Result<bool, ()> {
        match self.read(path, budget, buf, m, on_line) {
            Ok(end) => {
                if self.error.take().is_some() {
                    info!(path = %path.display(), "reading recovered");
                }
                Ok(matches!(end, ReadEnd::BudgetExhausted))
            }
            Err(e) => {
                if self.error != Some(e.kind()) {
                    metrics::inc(&m.read_errors);
                    warn!(path = %path.display(), error = %e, "read failed; will retry");
                    self.error = Some(e.kind());
                }
                Err(())
            }
        }
    }
}

/// Why the path currently has no open source, so each condition is
/// reported once rather than on every poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathState {
    Ok,
    Missing,
    Error(ErrorKind),
    NotRegular,
}

/// A monitored path and its open sources.
#[derive(Debug)]
pub struct TailedFile {
    path: PathBuf,
    opts: ReaderOptions,
    /// Start position for the very first open; later opens always start at 0
    /// because a file that appears while we run consists entirely of new data.
    startup: Option<StartupMode>,
    /// Saved position from a previous run, used (if still valid) instead of
    /// `startup` for the very first open.
    resume: Option<FileState>,
    current: Option<Source>,
    draining: Option<(Source, Instant)>,
    state: PathState,
    /// The file whose open was last refused with `EACCES` without being
    /// reported; see `open`.
    access_retried: Option<FileId>,
}

impl TailedFile {
    pub fn new(path: PathBuf, startup: StartupMode, opts: ReaderOptions) -> Self {
        TailedFile {
            path,
            opts,
            startup: Some(startup),
            resume: None,
            current: None,
            draining: None,
            state: PathState::Ok,
            access_retried: None,
        }
    }

    /// A file that appeared while running (found by a glob): it consists
    /// entirely of new data, so it is read from offset 0.
    pub fn appeared(path: PathBuf, opts: ReaderOptions) -> Self {
        TailedFile {
            startup: None,
            ..TailedFile::new(path, StartupMode::Beginning, opts)
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_open(&self) -> bool {
        self.current.is_some()
    }

    /// Uses `saved` for the first open if it still matches the file.
    pub fn set_resume(&mut self, saved: FileState) {
        self.resume = Some(saved);
    }

    /// The position to save for this file: the current source's offset just
    /// past its last complete line. A file being drained after rotation is
    /// not included, so a restart does not return to it.
    pub fn checkpoint(&mut self) -> Option<FileState> {
        let cur = self.current.as_mut()?;
        let limit = cur.line_end.min(FINGERPRINT_BYTES);
        let fingerprint = match cur.fingerprint {
            Some(fp) if fp.len == limit => fp,
            _ => {
                let fp = Fingerprint::of(&cur.file, limit).ok()?;
                cur.fingerprint = Some(fp);
                fp
            }
        };
        Some(FileState {
            id: cur.id,
            offset: cur.line_end,
            fingerprint,
        })
    }

    /// Identity of the file currently read at the path, if any.
    pub fn current_id(&self) -> Option<FileId> {
        self.current.as_ref().map(|s| s.id)
    }

    pub fn is_draining(&self) -> bool {
        self.draining.is_some()
    }

    /// Checks the path, handles rotation and truncation, and passes every
    /// newly completed line to `on_line`.
    ///
    /// Returns `true` if the read budget was exhausted and more data is
    /// probably available; the caller should poll again soon.
    pub fn poll(
        &mut self,
        now: Instant,
        buf: &mut [u8],
        m: &Metrics,
        on_line: &mut dyn FnMut(Line<'_>),
    ) -> bool {
        let mut budget = self.opts.read_budget;

        if self.drain(now, &mut budget, buf, m, on_line) {
            return true;
        }

        match fs::metadata(&self.path) {
            Ok(meta) => {
                let id = FileId::of(&meta);
                match &self.current {
                    Some(cur) if cur.id == id => self.set_state(PathState::Ok, m),
                    Some(_) => {
                        self.rotate(now, m, on_line);
                        if self.drain(now, &mut budget, buf, m, on_line) {
                            return true;
                        }
                        self.open(&meta, m);
                    }
                    None => self.open(&meta, m),
                }
            }
            Err(e) => self.path_unavailable(e, m),
        }

        let Some(cur) = &mut self.current else {
            return false;
        };
        let more = matches!(
            cur.read_logged(&self.path, &mut budget, buf, m, on_line),
            Ok(true)
        );
        if !more && self.state != PathState::Ok {
            self.close_if_deleted(m, on_line);
        }
        more
    }

    /// Reads the draining source and closes it once it has been idle past
    /// its deadline. Returns `true` if the budget ran out.
    fn drain(
        &mut self,
        now: Instant,
        budget: &mut usize,
        buf: &mut [u8],
        m: &Metrics,
        on_line: &mut dyn FnMut(Line<'_>),
    ) -> bool {
        let Some((src, deadline)) = &mut self.draining else {
            return false;
        };
        let before = src.offset;
        let result = src.read_logged(&self.path, budget, buf, m, on_line);
        if result == Ok(true) {
            *deadline = now + self.opts.drain_grace;
            return true;
        }
        if src.offset != before {
            *deadline = now + self.opts.drain_grace;
        } else if now >= *deadline {
            self.finish_draining(m, on_line);
        }
        false
    }

    /// Applies a new rotation grace period (configuration reload); a file
    /// already draining keeps its deadline.
    pub fn set_drain_grace(&mut self, grace: Duration) {
        self.opts.drain_grace = grace;
    }

    /// Stops reading: emits any incomplete trailing lines of the current
    /// and the draining file and closes both. Used when a configuration
    /// reload removes the file.
    pub fn close(&mut self, m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) {
        self.finish_draining(m, on_line);
        if let Some(mut cur) = self.current.take() {
            cur.splitter.flush(m, on_line);
            metrics::dec(&m.files_monitored);
        }
    }

    fn finish_draining(&mut self, m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) {
        if let Some((mut src, _)) = self.draining.take() {
            src.splitter.flush(m, on_line);
            debug!(path = %self.path.display(), offset = src.offset, "closed rotated file");
        }
    }

    /// The path now refers to a different file: move `current` to draining.
    fn rotate(&mut self, now: Instant, m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) {
        let Some(old) = self.current.take() else {
            return;
        };
        metrics::dec(&m.files_monitored);
        metrics::inc(&m.rotations);
        info!(path = %self.path.display(), "file replaced (rotation); draining old file");
        // Only one rotated file is drained at a time; a second rotation within
        // the grace period finishes the older one now.
        self.finish_draining(m, on_line);
        self.draining = Some((old, now + self.opts.drain_grace));
    }

    fn open(&mut self, path_meta: &Metadata, m: &Metrics) {
        if !path_meta.is_file() {
            self.set_state(PathState::NotRegular, m);
            return;
        }
        // O_NONBLOCK keeps a FIFO swapped in at the path from blocking open().
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                self.set_state(PathState::Missing, m);
                return;
            }
            // Tools such as `install -o -g` and logrotate's `create` make a new
            // file root-only before they chown or chmod it. Opening it in
            // that window is not a real permission problem, so a file that
            // appeared or was rotated in while we run gets one silent retry;
            // the next poll (its chmod or chown wakes us) reports the error if
            // it is still there. A file present at startup is reported at once.
            Err(e)
                if e.kind() == ErrorKind::PermissionDenied
                    && self.startup.is_none()
                    && self.access_retried != Some(FileId::of(path_meta)) =>
            {
                self.access_retried = Some(FileId::of(path_meta));
                debug!(path = %self.path.display(), "new file not readable yet; will retry");
                return;
            }
            Err(e) => {
                self.report_open_error(&e, m);
                return;
            }
        };
        // Identity comes from the descriptor, not the earlier stat, in case
        // the path changed in between.
        let meta = match file.metadata() {
            Ok(meta) => meta,
            Err(e) => {
                self.report_open_error(&e, m);
                return;
            }
        };
        if !meta.is_file() {
            self.set_state(PathState::NotRegular, m);
            return;
        }
        let mut splitter = LineSplitter::new(self.opts.max_line_bytes);
        let id = FileId::of(&meta);
        let size = meta.len();
        let resume = self.resume.take();
        let offset = match self.startup.take() {
            None => 0,
            Some(mode) => match resume.map(|r| r.resume_offset(&file, id, size)) {
                Some(Ok(offset)) => {
                    info!(path = %self.path.display(), offset, "resuming from saved offset");
                    offset
                }
                Some(Err(why)) => {
                    warn!(
                        path = %self.path.display(),
                        reason = why.as_str(),
                        "saved offset not usable; reading from the beginning"
                    );
                    0
                }
                None if mode == StartupMode::Tail => size,
                None => 0,
            },
        };
        // Starting in the middle of a line (tail mode, or a saved offset
        // that was itself a tail-mode start position): skip to the next
        // line start. Saved offsets are otherwise always line starts.
        if offset > 0 && !ends_with_newline(&file, offset) {
            splitter.skip = Skip::StartupPartial;
        }
        debug!(path = %self.path.display(), offset, "opened");
        // Inode numbers are reused, so a later file with this identity gets
        // its own retry.
        self.access_retried = None;
        self.current = Some(Source {
            file,
            id,
            offset,
            line_end: offset,
            fingerprint: None,
            splitter,
            error: None,
        });
        metrics::inc(&m.files_monitored);
        self.set_state(PathState::Ok, m);
    }

    /// Counts and reports an error once per distinct failure episode;
    /// identical failures on later retries are not recounted.
    fn report_open_error(&mut self, e: &io::Error, m: &Metrics) {
        // Whatever failed, the first open attempt is over: a file that
        // appears later is read from the beginning.
        self.startup = None;
        self.resume = None;
        if self.state != PathState::Error(e.kind()) {
            metrics::inc(&m.read_errors);
            warn!(path = %self.path.display(), error = %e, "cannot access file; will retry");
        }
        self.state = PathState::Error(e.kind());
    }

    fn path_unavailable(&mut self, e: io::Error, m: &Metrics) {
        if e.kind() == ErrorKind::NotFound {
            self.set_state(PathState::Missing, m);
        } else {
            self.report_open_error(&e, m);
        }
    }

    /// Closes `current` if its file has been unlinked (it has been read to
    /// EOF by the caller). A file merely renamed away stays open.
    fn close_if_deleted(&mut self, m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) {
        let deleted = match &self.current {
            Some(cur) => matches!(cur.file.metadata(), Ok(meta) if meta.nlink() == 0),
            None => false,
        };
        if !deleted {
            return;
        }
        if let Some(mut cur) = self.current.take() {
            cur.splitter.flush(m, on_line);
            metrics::dec(&m.files_monitored);
            info!(path = %self.path.display(), "file deleted; closed after reading to the end");
        }
    }

    fn set_state(&mut self, state: PathState, m: &Metrics) {
        self.startup = None;
        self.resume = None;
        if self.state == state {
            return;
        }
        match state {
            PathState::Ok if self.state != PathState::Ok => {
                info!(path = %self.path.display(), "file available")
            }
            PathState::Missing => {
                if self.current.is_some() {
                    info!(path = %self.path.display(), "file removed from path; still reading open file")
                } else {
                    warn!(path = %self.path.display(), "file not found; waiting for it to appear")
                }
            }
            PathState::NotRegular => {
                metrics::inc(&m.read_errors);
                warn!(path = %self.path.display(), "not a regular file; ignoring until it is replaced")
            }
            _ => {}
        }
        self.state = state;
    }
}

fn ends_with_newline(file: &File, size: u64) -> bool {
    let mut byte = [0u8];
    loop {
        match file.read_at(&mut byte, size - 1) {
            Ok(1) => return byte[0] == b'\n',
            // Shrunk under us: the truncation check on the next read handles it.
            Ok(_) => return true,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            // Unknown: emit the possible fragment rather than drop a line.
            Err(_) => return true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(max: usize, chunks: &[&[u8]]) -> (Vec<(Vec<u8>, bool)>, Metrics) {
        let m = Metrics::default();
        let mut s = LineSplitter::new(max);
        let mut out = Vec::new();
        for c in chunks {
            s.feed(c, &m, &mut |l| out.push((l.bytes.to_vec(), l.truncated)));
        }
        (out, m)
    }

    fn lines(v: &[(Vec<u8>, bool)]) -> Vec<String> {
        v.iter()
            .map(|(b, t)| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(b),
                    if *t { "~" } else { "" }
                )
            })
            .collect()
    }

    #[test]
    fn splits_complete_lines() {
        let (out, m) = split(100, &[b"a\nbb\n\nccc\n"]);
        assert_eq!(lines(&out), ["a", "bb", "", "ccc"]);
        assert_eq!(m.snapshot().lines_processed, 4);
    }

    #[test]
    fn joins_partial_lines_across_chunks() {
        let (out, _) = split(100, &[b"he", b"llo", b" world\nnext", b"\n", b"tail"]);
        assert_eq!(lines(&out), ["hello world", "next"]);
    }

    #[test]
    fn strips_carriage_return() {
        let (out, _) = split(100, &[b"dos\r\n", b"split\r", b"\n"]);
        assert_eq!(lines(&out), ["dos", "split"]);
    }

    #[test]
    fn exact_max_is_not_truncated() {
        let (out, m) = split(4, &[b"abcd\n", b"ab", b"cd\n"]);
        assert_eq!(lines(&out), ["abcd", "abcd"]);
        assert_eq!(m.snapshot().lines_truncated, 0);
    }

    #[test]
    fn oversized_complete_line_is_cut_and_counted() {
        let (out, m) = split(4, &[b"abcdefg\nok\n"]);
        assert_eq!(lines(&out), ["abcd~", "ok"]);
        let s = m.snapshot();
        assert_eq!(s.lines_truncated, 1);
        assert_eq!(s.bytes_skipped, 3);
    }

    #[test]
    fn oversized_partial_line_is_cut_and_rest_skipped() {
        let (out, m) = split(4, &[b"ab", b"cdef", b"ghi", b"j\nok\n"]);
        assert_eq!(lines(&out), ["abcd~", "ok"]);
        let s = m.snapshot();
        assert_eq!(s.lines_truncated, 1);
        assert_eq!(s.bytes_skipped, 6);
        assert_eq!(s.lines_processed, 2);
    }

    #[test]
    fn pending_plus_complete_overflow() {
        let (out, m) = split(4, &[b"abc", b"def\n"]);
        assert_eq!(lines(&out), ["abcd~"]);
        assert_eq!(m.snapshot().bytes_skipped, 2);
    }

    #[test]
    fn flush_emits_pending_and_counts() {
        let m = Metrics::default();
        let mut s = LineSplitter::new(100);
        let mut out = Vec::new();
        s.feed(b"no newline", &m, &mut |l| out.push(l.bytes.to_vec()));
        assert!(out.is_empty());
        s.flush(&m, &mut |l| out.push(l.bytes.to_vec()));
        assert_eq!(out, [b"no newline".to_vec()]);
        assert_eq!(m.snapshot().partial_lines_flushed, 1);
    }

    /// Feeds `input` in every possible split into three chunks.
    fn every_split(max: usize, input: &[u8], check: impl Fn(&[(Vec<u8>, bool)], &Metrics, &str)) {
        for i in 0..=input.len() {
            for j in i..=input.len() {
                let (a, rest) = input.split_at(i);
                let (b, c) = rest.split_at(j - i);
                let (out, m) = split(max, &[a, b, c]);
                check(&out, &m, &format!("{a:?} + {b:?} + {c:?}"));
            }
        }
    }

    #[test]
    fn crlf_line_at_exact_max_is_not_truncated() {
        every_split(4, b"abcd\r\nok\n", |out, m, how| {
            assert_eq!(lines(out), ["abcd", "ok"], "{how}");
            let s = m.snapshot();
            assert_eq!(s.lines_truncated, 0, "{how}");
            assert_eq!(s.bytes_skipped, 0, "{how}");
        });
    }

    #[test]
    fn crlf_terminator_is_not_counted_as_skipped() {
        every_split(4, b"abcde\r\nok\n", |out, m, how| {
            assert_eq!(lines(out), ["abcd~", "ok"], "{how}");
            let s = m.snapshot();
            assert_eq!(s.lines_truncated, 1, "{how}");
            assert_eq!(s.bytes_skipped, 1, "{how}");
        });
    }

    #[test]
    fn inner_carriage_return_beyond_max_is_content() {
        // A `\r` not followed by the newline is content, skipped and counted.
        every_split(4, b"abcd\rx\r\nok\n", |out, m, how| {
            assert_eq!(lines(out), ["abcd~", "ok"], "{how}");
            assert_eq!(m.snapshot().bytes_skipped, 2, "{how}");
        });
        every_split(4, b"abcde\r\rz\n", |out, m, how| {
            assert_eq!(lines(out), ["abcd~"], "{how}");
            assert_eq!(m.snapshot().bytes_skipped, 4, "{how}");
        });
    }

    #[test]
    fn held_carriage_return_is_flushed_without_truncation() {
        let m = Metrics::default();
        let mut s = LineSplitter::new(4);
        let mut out = Vec::new();
        s.feed(b"abcd\r", &m, &mut |l| {
            out.push((l.bytes.to_vec(), l.truncated))
        });
        assert!(out.is_empty());
        assert_eq!(s.pending.len(), 5, "bounded by max + 1");
        s.flush(&m, &mut |l| out.push((l.bytes.to_vec(), l.truncated)));
        assert_eq!(lines(&out), ["abcd"]);
        let snap = m.snapshot();
        assert_eq!(snap.lines_truncated, 0);
        assert_eq!(snap.bytes_skipped, 0);
    }

    #[test]
    fn skipped_trailing_carriage_return_is_counted_on_flush() {
        let m = Metrics::default();
        let mut s = LineSplitter::new(4);
        let mut out = Vec::new();
        s.feed(b"abcdef\r", &m, &mut |l| out.push(l.bytes.to_vec()));
        s.flush(&m, &mut |l| out.push(l.bytes.to_vec()));
        assert_eq!(out, [b"abcd".to_vec()]);
        assert_eq!(m.snapshot().bytes_skipped, 3);
    }

    #[test]
    fn long_line_buffer_is_released() {
        let m = Metrics::default();
        let max = 4 * READ_BUF_BYTES;
        let mut s = LineSplitter::new(max);
        let long = vec![b'x'; max - 1];
        s.feed(&long, &m, &mut |_| {});
        assert!(s.pending.capacity() >= long.len());
        s.feed(b"\n", &m, &mut |_| {});
        assert!(s.pending.capacity() <= READ_BUF_BYTES);
    }

    /// Whole-stream reference: split on `\n`, strip one `\r`, cut at `max`.
    /// An unterminated tail is treated as a line, as `flush` does; if it is
    /// cut, a trailing `\r` is content and counted as skipped.
    fn reference(max: usize, data: &[u8]) -> (Vec<(Vec<u8>, bool)>, u64) {
        let mut out = Vec::new();
        let mut skipped = 0;
        let terminated = data.ends_with(b"\n");
        let mut parts: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
        if parts.last().is_some_and(|p| p.is_empty()) {
            parts.pop();
        }
        let n = parts.len();
        for (i, p) in parts.into_iter().enumerate() {
            let c = strip_cr(p);
            if c.len() > max {
                let tail = i + 1 == n && !terminated;
                let len = if tail { p.len() } else { c.len() };
                skipped += (len - max) as u64;
                out.push((c[..max].to_vec(), true));
            } else {
                out.push((c.to_vec(), false));
            }
        }
        (out, skipped)
    }

    fn strip_cr(line: &[u8]) -> &[u8] {
        line.strip_suffix(b"\r").unwrap_or(line)
    }

    #[test]
    fn matches_reference_under_arbitrary_chunking() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut rand = move |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        for case in 0..20_000 {
            let max = 1 + rand(6);
            let len = rand(40);
            let data: Vec<u8> = (0..len).map(|_| b"aab\r\n"[rand(5)]).collect();
            let m = Metrics::default();
            let mut s = LineSplitter::new(max);
            let mut out = Vec::new();
            let mut rest = &data[..];
            while !rest.is_empty() {
                let n = 1 + rand(rest.len().min(8));
                s.feed(&rest[..n], &m, &mut |l| {
                    out.push((l.bytes.to_vec(), l.truncated))
                });
                rest = &rest[n..];
                assert!(s.pending.len() <= max + 1);
            }
            s.flush(&m, &mut |l| out.push((l.bytes.to_vec(), l.truncated)));
            let (want, skipped) = reference(max, &data);
            let ctx = format!(
                "case {case}: max={max} data={:?}",
                String::from_utf8_lossy(&data)
            );
            assert_eq!(out, want, "{ctx}");
            let snap = m.snapshot();
            assert_eq!(snap.bytes_skipped, skipped, "{ctx}");
            assert_eq!(snap.lines_processed, want.len() as u64, "{ctx}");
            let truncated = want.iter().filter(|l| l.1).count() as u64;
            assert_eq!(snap.lines_truncated, truncated, "{ctx}");
        }
    }

    #[test]
    fn non_utf8_is_passed_through() {
        let (out, _) = split(100, &[b"\xff\xfe\n"]);
        assert_eq!(out[0].0, b"\xff\xfe");
    }
}
