//! Journal input: follows the systemd journal through a `journalctl -f -o
//! json` child process.
//!
//! A reader thread runs journalctl, parses each entry's `MESSAGE` and
//! `__CURSOR`, and passes the entries to the monitor thread through a
//! bounded channel, waking it. When the channel is full the thread stops
//! reading, so journalctl blocks on its pipe and nothing is lost: the
//! entries stay in the journal. If journalctl exits it is restarted after
//! the last cursor seen, with a growing delay.
//!
//! Linking libsystemd instead would break the static binary. The program
//! run is always `journalctl` from `PATH`, never anything from the
//! configuration; the configured matches are passed as arguments.

use std::io::{self, BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use tracing::{info, warn};

use crate::config::StartupMode;
use crate::metrics::{self, Metrics};
use crate::reader::Line;
use crate::watcher::Waker;

/// Entries buffered between the reader thread and the monitor.
const CHANNEL_ENTRIES: usize = 1024;
/// Entries passed to the rules per monitor pass, so files are not starved.
const POLL_BUDGET: usize = 1024;
const MAX_RESTART_DELAY: Duration = Duration::from_secs(30);

/// Where reading starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    /// Right after this saved cursor.
    After(String),
    /// Only entries from now on.
    Tail,
    /// From the start of the current boot.
    Boot,
}

impl Start {
    pub fn new(cursor: Option<String>, mode: StartupMode) -> Self {
        match (cursor, mode) {
            (Some(c), _) => Start::After(c),
            (None, StartupMode::Tail) => Start::Tail,
            (None, StartupMode::Beginning) => Start::Boot,
        }
    }

    fn arg(&self) -> String {
        match self {
            Start::After(c) => format!("--after-cursor={c}"),
            Start::Tail => "--lines=0".into(),
            Start::Boot => "--boot".into(),
        }
    }
}

/// One journal entry. `message` is `None` for entries without a message,
/// which only advance the cursor.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    cursor: Arc<str>,
    message: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct RawEntry {
    #[serde(rename = "__CURSOR")]
    cursor: String,
    #[serde(rename = "MESSAGE", default)]
    message: Option<Message>,
}

/// journalctl writes `MESSAGE` as a string, or as an array of bytes when
/// it is not valid UTF-8.
#[derive(Deserialize)]
#[serde(untagged)]
enum Message {
    Text(String),
    Bytes(Vec<u8>),
}

fn parse(json: &[u8]) -> Option<Entry> {
    let raw: RawEntry = serde_json::from_slice(json).ok()?;
    let mut message = raw.message.map(|m| match m {
        Message::Text(s) => s.into_bytes(),
        Message::Bytes(b) => b,
    });
    if let Some(m) = &mut message {
        while m.last() == Some(&b'\n') {
            m.pop();
        }
    }
    Some(Entry {
        cursor: raw.cursor.into(),
        message,
    })
}

/// Reads one line, without its `\n`, into `buf`. `Ok(None)` at end of
/// input. A line longer than `cap` is skipped up to its newline and
/// reported as `Ok(Some(false))`.
fn read_line(r: &mut impl BufRead, cap: usize, buf: &mut Vec<u8>) -> io::Result<Option<bool>> {
    buf.clear();
    let n = io::Read::take(&mut *r, cap as u64 + 1).read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        return Ok(Some(true));
    }
    if buf.len() > cap {
        r.skip_until(b'\n')?;
        return Ok(Some(false));
    }
    Ok(None) // the writer exited mid-line
}

pub struct Journal {
    rx: Receiver<Entry>,
    cursor: Option<Arc<str>>,
    max_line_bytes: usize,
}

impl Journal {
    /// Starts the reader thread. `matches` are journalctl match arguments
    /// (`FIELD=value` or `+`), already validated.
    pub fn spawn(
        matches: Vec<String>,
        start: Start,
        max_line_bytes: usize,
        waker: Waker,
        metrics: Arc<Metrics>,
    ) -> io::Result<Self> {
        let (tx, rx) = sync_channel(CHANNEL_ENTRIES);
        // Escaping can make a JSON entry several times longer than its
        // message (`\u0001`, or `255,` per byte for byte arrays).
        let cap = max_line_bytes * 6 + 64 * 1024;
        thread::Builder::new()
            .name("journal".into())
            .spawn(move || follow(&matches, start, cap, &tx, &waker, &metrics))?;
        Ok(Journal {
            rx,
            cursor: None,
            max_line_bytes,
        })
    }

    /// Passes buffered entries to `on_line`, at most a budget per call.
    /// Returns `true` if more may be waiting.
    pub fn poll(&mut self, m: &Metrics, on_line: &mut dyn FnMut(Line<'_>)) -> bool {
        for _ in 0..POLL_BUDGET {
            let entry = match self.rx.try_recv() {
                Ok(e) => e,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return false,
            };
            if let Some(msg) = &entry.message {
                metrics::add(&m.bytes_read, msg.len() as u64);
                metrics::inc(&m.lines_processed);
                let truncated = msg.len() > self.max_line_bytes;
                if truncated {
                    metrics::inc(&m.lines_truncated);
                    metrics::add(&m.bytes_skipped, (msg.len() - self.max_line_bytes) as u64);
                }
                on_line(Line {
                    bytes: &msg[..msg.len().min(self.max_line_bytes)],
                    truncated,
                });
            }
            self.cursor = Some(entry.cursor);
        }
        true
    }

    /// Cursor of the last entry passed on by [`Journal::poll`].
    pub fn cursor(&self) -> Option<Arc<str>> {
        self.cursor.clone()
    }
}

/// The reader thread: runs journalctl until the monitor goes away.
fn follow(
    matches: &[String],
    mut start: Start,
    cap: usize,
    tx: &SyncSender<Entry>,
    waker: &Waker,
    m: &Metrics,
) {
    let mut delay = Duration::from_secs(1);
    let mut buf = Vec::new();
    loop {
        let mut cmd = Command::new("journalctl");
        cmd.args(["--follow", "--output=json", "--no-pager", "--quiet"])
            .arg(start.arg())
            .args(matches)
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        // SAFETY: prctl is async-signal-safe and touches no memory of the
        // parent. The child is told to exit when this thread ends.
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        match cmd.spawn() {
            Err(e) => warn!(error = %e, "cannot start journalctl; will retry"),
            Ok(mut child) => {
                info!("following the journal");
                let mut out = BufReader::with_capacity(64 * 1024, child.stdout.take().unwrap());
                loop {
                    match read_line(&mut out, cap, &mut buf) {
                        Ok(Some(true)) => match parse(&buf) {
                            Some(entry) => {
                                start = Start::After(entry.cursor.to_string());
                                if tx.send(entry).is_err() {
                                    let _ = child.kill();
                                    return; // the monitor is gone
                                }
                                waker.wake();
                                delay = Duration::from_secs(1);
                            }
                            None => metrics::inc(&m.journal_entries_skipped),
                        },
                        Ok(Some(false)) => {
                            metrics::inc(&m.journal_entries_skipped);
                            warn!(max_bytes = cap, "journal entry too long; skipped");
                        }
                        Ok(None) => break,
                        Err(e) => {
                            warn!(error = %e, "reading from journalctl failed");
                            break;
                        }
                    }
                }
                let _ = child.kill();
                let status = child.wait();
                warn!(status = ?status, "journalctl exited; restarting");
            }
        }
        metrics::inc(&m.journal_restarts);
        thread::sleep(delay);
        delay = (delay * 2).min(MAX_RESTART_DELAY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_bytes_and_missing_messages() {
        let e = parse(br#"{"__CURSOR":"s=1","MESSAGE":"Failed password\n","PRIORITY":"6"}"#);
        assert_eq!(
            e,
            Some(Entry {
                cursor: "s=1".into(),
                message: Some(b"Failed password".to_vec())
            })
        );
        let e = parse(br#"{"__CURSOR":"s=2","MESSAGE":[255,104,105]}"#).unwrap();
        assert_eq!(e.message.as_deref(), Some(&b"\xffhi"[..]));
        let e = parse(br#"{"__CURSOR":"s=3","MESSAGE":null}"#).unwrap();
        assert_eq!(e.message, None);
        assert_eq!(parse(br#"{"__CURSOR":"s=4"}"#).unwrap().message, None);
        assert_eq!(parse(br#"{"MESSAGE":"no cursor"}"#), None);
        assert_eq!(parse(b"not json"), None);
    }

    #[test]
    fn read_line_bounds_line_length() {
        let mut r = io::Cursor::new(b"short\nmuch too long line\nok\nend".to_vec());
        let mut buf = Vec::new();
        assert_eq!(read_line(&mut r, 8, &mut buf).unwrap(), Some(true));
        assert_eq!(buf, b"short");
        assert_eq!(read_line(&mut r, 8, &mut buf).unwrap(), Some(false));
        assert_eq!(read_line(&mut r, 8, &mut buf).unwrap(), Some(true));
        assert_eq!(buf, b"ok");
        assert_eq!(read_line(&mut r, 8, &mut buf).unwrap(), None);
    }

    #[test]
    fn start_arguments() {
        assert_eq!(Start::new(None, StartupMode::Tail).arg(), "--lines=0");
        assert_eq!(Start::new(None, StartupMode::Beginning).arg(), "--boot");
        assert_eq!(
            Start::new(Some("s=1;i=2".into()), StartupMode::Tail).arg(),
            "--after-cursor=s=1;i=2"
        );
    }
}
