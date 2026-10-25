//! logwizz-notify: aggregates detections from the journal and sends
//! summaries.
//!
//! logwizz itself never touches the network. This separate process reads
//! its JSON events back from the `logwizz` journal namespace, groups them by
//! rule and event-time window ([`aggregate`]) and delivers one summary per
//! group through curl ([`transport`]). Raw log lines never leave the host.
//!
//! The journal cursor and the pending summaries are saved together in one
//! state file, so after a crash reading resumes exactly where the saved
//! summaries end: no event is counted twice, and a summary sent but not yet
//! removed from the saved state is sent again (at-least-once delivery).

pub mod aggregate;
pub mod transport;

use std::fs;
use std::io::{self, BufReader};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::event::Severity;
use crate::journal::read_line;
use aggregate::{Aggregator, Detection, Key, NotAnEvent, Recorded, Summary};
use transport::{Curl, Deliver, Kind};

const STATE_VERSION: u32 = 1;
const STATE_FILE: &str = "state.json";
/// Journal entries buffered between the reader thread and the main loop.
const CHANNEL_ENTRIES: usize = 1024;
/// Longest journal entry read; longer ones are skipped.
const MAX_ENTRY_BYTES: usize = 4 << 20;
/// How often the main loop checks for due windows when no entry arrives.
const TICK: Duration = Duration::from_millis(500);
/// Minimum time between state saves while entries keep arriving.
const SAVE_INTERVAL: Duration = Duration::from_secs(1);
/// Time allowed for delivering pending summaries at shutdown; systemd's
/// TimeoutStopSec must be longer.
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(30);

/// Settings, from the environment (`/etc/logwizz/notify.env`).
#[derive(Debug)]
pub struct Settings {
    pub transport: Curl,
    pub window_secs: u64,
    pub max_pending: usize,
    pub min_priority: Severity,
    pub state_dir: PathBuf,
}

impl Settings {
    /// Reads and validates the settings through `get` (normally
    /// `std::env::var`). Errors never contain secret values.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let var = |name: &str| get(name).filter(|v| !v.is_empty());
        let required = |name: &str| var(name).ok_or_else(|| format!("{name} is not set"));
        let number = |name: &str, default: u64, min: u64, max: u64| match var(name) {
            None => Ok(default),
            Some(v) => match v.parse::<u64>() {
                Ok(n) if (min..=max).contains(&n) => Ok(n),
                _ => Err(format!("{name} must be an integer in {min}..={max}")),
            },
        };
        let no_controls = |name: &str, v: String| {
            if v.chars().any(char::is_control) {
                Err(format!("{name} must not contain control characters"))
            } else {
                Ok(v)
            }
        };
        let https_url = || {
            let url = no_controls("NOTIFY_URL", required("NOTIFY_URL")?)?;
            if !url.starts_with("https://") {
                return Err("NOTIFY_URL must use HTTPS".to_string());
            }
            Ok(url)
        };
        let kind = match var("NOTIFY_KIND").as_deref().unwrap_or("telegram") {
            "telegram" => {
                let token = required("TELEGRAM_BOT_TOKEN")?;
                let valid = token.split_once(':').is_some_and(|(id, secret)| {
                    !id.is_empty()
                        && id.bytes().all(|b| b.is_ascii_digit())
                        && !secret.is_empty()
                        && secret
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                });
                if !valid {
                    return Err("TELEGRAM_BOT_TOKEN has invalid format".into());
                }
                let chat_id = no_controls("TELEGRAM_CHAT_ID", required("TELEGRAM_CHAT_ID")?)?;
                Kind::Telegram { token, chat_id }
            }
            "ntfy" => Kind::Ntfy { url: https_url()? },
            "webhook" => Kind::Webhook { url: https_url()? },
            _ => return Err("NOTIFY_KIND must be telegram, ntfy or webhook".into()),
        };
        let auth = var("NOTIFY_AUTH")
            .map(|a| no_controls("NOTIFY_AUTH", a))
            .transpose()?;
        let min_priority = match var("NOTIFY_MIN_PRIORITY") {
            None => Severity::Warning,
            Some(p) => p.parse().map_err(|()| {
                "NOTIFY_MIN_PRIORITY must be debug, info, notice, warning, error or critical"
                    .to_string()
            })?,
        };
        // systemd may pass several directories, separated by ':'.
        let state_dir = var("STATE_DIRECTORY")
            .map(|d| PathBuf::from(d.split(':').next().unwrap_or_default()))
            .unwrap_or_else(|| PathBuf::from("/var/lib/logwizz-notify"));
        Ok(Settings {
            transport: Curl { kind, auth },
            window_secs: number("NOTIFY_WINDOW_SECS", 60, 10, 3600)?,
            max_pending: number("NOTIFY_MAX_PENDING", 4096, 1, 65536)? as usize,
            min_priority,
            state_dir,
        })
    }
}

/// The state file: the cursor of the last consumed journal entry and the
/// summaries that include everything up to it.
#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    v: u32,
    cursor: Option<String>,
    summaries: Vec<Summary>,
}

fn load_state(dir: &Path, window_secs: u64) -> io::Result<State> {
    let path = dir.join(STATE_FILE);
    match fs::read(&path) {
        Ok(bytes) => {
            let state: State = serde_json::from_slice(&bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("state file {} is invalid: {e}", path.display()),
                )
            })?;
            if state.v != STATE_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "state file {} uses unsupported version {} (expected {})",
                        path.display(),
                        state.v,
                        STATE_VERSION
                    ),
                ));
            }
            Ok(state)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(load_legacy(dir, window_secs)),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("cannot read state file {}: {e}", path.display()),
        )),
    }
}

/// State written by the earlier shell notifier: a `cursor` file and one
/// `agg-*.json` file per pending summary. Removed after the first save.
#[derive(Deserialize)]
struct LegacySummary {
    bucket: u64,
    #[serde(default)]
    window_start: String,
    #[serde(default)]
    window_end: String,
    rule: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    source: String,
    count: u64,
    #[serde(default)]
    retry_count: u32,
    #[serde(default)]
    retry_after: u64,
}

fn legacy_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "cursor" || (n.starts_with("agg-") && n.ends_with(".json")))
        })
        .collect()
}

fn load_legacy(dir: &Path, window_secs: u64) -> State {
    let mut state = State {
        v: STATE_VERSION,
        ..State::default()
    };
    for path in legacy_files(dir) {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if path.ends_with("cursor") {
            state.cursor = Some(text.trim().to_string()).filter(|c| !c.is_empty());
            continue;
        }
        let Ok(old) = serde_json::from_str::<LegacySummary>(&text) else {
            warn!(file = %path.display(), "skipping an invalid summary of the shell notifier");
            continue;
        };
        let span = crate::event::parse_rfc3339(&old.window_end)
            .zip(crate::event::parse_rfc3339(&old.window_start))
            .and_then(|(end, start)| end.checked_sub(start))
            .filter(|&s| s > 0)
            .unwrap_or(window_secs);
        let (sources, overflowed) = match old.source.as_str() {
            "" => (Vec::new(), false),
            "multiple" => (Vec::new(), true),
            s => (
                vec![aggregate::SourceCount {
                    source: s.to_string(),
                    count: old.count,
                }],
                false,
            ),
        };
        state.summaries.push(Summary {
            bucket: old.bucket,
            window_secs: span,
            rule: old.rule,
            host: old.host,
            severity: old.severity.parse().unwrap_or(Severity::Notice),
            description: old.description,
            count: old.count,
            unsourced: if old.source.is_empty() { old.count } else { 0 },
            sources,
            sources_overflowed: overflowed,
            retry_count: old.retry_count,
            retry_after: old.retry_after,
        });
    }
    if state.cursor.is_some() || !state.summaries.is_empty() {
        info!(
            summaries = state.summaries.len(),
            "imported the state of the shell notifier"
        );
    }
    state
}

fn save_state(dir: &Path, cursor: Option<&str>, agg: &Aggregator) -> io::Result<()> {
    let state = State {
        v: STATE_VERSION,
        cursor: cursor.map(String::from),
        summaries: agg.summaries().cloned().collect(),
    };
    let mut bytes = serde_json::to_vec(&state).map_err(io::Error::other)?;
    bytes.push(b'\n');
    crate::state::write_atomic(&dir.join(STATE_FILE), &bytes)
}

/// One journal entry.
struct Entry {
    cursor: String,
    /// `None` if the entry has no text message.
    message: Option<String>,
    /// `__REALTIME_TIMESTAMP`, in seconds.
    time: Option<u64>,
}

#[derive(Deserialize)]
struct RawEntry {
    #[serde(rename = "__CURSOR")]
    cursor: String,
    #[serde(rename = "MESSAGE", default)]
    message: Option<serde_json::Value>,
    #[serde(rename = "__REALTIME_TIMESTAMP", default)]
    realtime: Option<String>,
}

fn parse_entry(json: &[u8]) -> Option<Entry> {
    let raw: RawEntry = serde_json::from_slice(json).ok()?;
    Some(Entry {
        cursor: raw.cursor,
        // Messages that are not valid UTF-8 come as byte arrays; logwizz
        // events are always text.
        message: match raw.message {
            Some(serde_json::Value::String(s)) => Some(s),
            _ => None,
        },
        time: raw
            .realtime
            .and_then(|t| t.parse::<u64>().ok())
            .map(|us| us / 1_000_000),
    })
}

/// Runs journalctl and passes its entries on until it exits; then the
/// channel closes.
fn spawn_journal(cursor: Option<&str>, min: Severity) -> io::Result<Receiver<Entry>> {
    let mut cmd = Command::new("journalctl");
    cmd.args([
        "--namespace=logwizz",
        "--unit=logwizz",
        "--follow",
        "--output=json",
        "--no-pager",
    ])
    .arg(format!("--priority={}", min.syslog_priority()))
    .arg(match cursor {
        Some(c) => format!("--after-cursor={c}"),
        None => "--lines=0".into(),
    })
    .stdin(Stdio::null())
    .stdout(Stdio::piped());
    // SAFETY: prctl is async-signal-safe and touches no memory of the
    // parent. journalctl exits with the reader thread, i.e. with us.
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let (tx, rx) = sync_channel(CHANNEL_ENTRIES);
    let (started_tx, started_rx) = sync_channel(1);
    thread::Builder::new()
        .name("journal".into())
        .spawn(move || match cmd.spawn() {
            Err(e) => {
                let _ = started_tx.send(Err(e));
            }
            Ok(mut child) => {
                let _ = started_tx.send(Ok(()));
                let out = child.stdout.take().expect("stdout is piped");
                read_entries(BufReader::with_capacity(64 * 1024, out), &tx);
                let _ = child.kill();
                let status = child.wait();
                warn!(status = ?status, "journalctl exited");
            }
        })?;
    started_rx
        .recv()
        .map_err(|_| io::Error::other("journal thread died"))??;
    Ok(rx)
}

fn read_entries(mut out: impl io::BufRead, tx: &SyncSender<Entry>) {
    let mut buf = Vec::new();
    loop {
        match read_line(&mut out, MAX_ENTRY_BYTES, &mut buf) {
            Ok(Some(true)) => match parse_entry(&buf) {
                Some(entry) => {
                    if tx.send(entry).is_err() {
                        return;
                    }
                }
                None => warn!("skipping a journal entry that could not be parsed"),
            },
            Ok(Some(false)) => warn!(
                max_bytes = MAX_ENTRY_BYTES,
                "journal entry too long; skipped"
            ),
            Ok(None) => return,
            Err(e) => {
                warn!(error = %e, "reading from journalctl failed");
                return;
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Waits for SIGTERM or SIGINT on its own thread and raises `stop`.
fn spawn_signal_thread(stop: Arc<AtomicBool>) -> io::Result<()> {
    let set = crate::daemon::block_signals(&[libc::SIGTERM, libc::SIGINT])?;
    thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            loop {
                match set.wait() {
                    Ok(sig) => {
                        info!(signal = sig, "termination requested");
                        stop.store(true, Ordering::Relaxed);
                    }
                    Err(e) => {
                        warn!(error = %e, "sigwait failed");
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
        })?;
    Ok(())
}

/// The main loop's state.
struct Notifier<D> {
    agg: Aggregator,
    deliver: D,
    state_dir: PathBuf,
    cursor: Option<String>,
    dirty: bool,
    last_save: Instant,
    /// Legacy state files to remove after the first successful save.
    legacy: Vec<PathBuf>,
}

impl<D: Deliver> Notifier<D> {
    fn save(&mut self, force: bool) {
        if !self.dirty || (!force && self.last_save.elapsed() < SAVE_INTERVAL) {
            return;
        }
        match save_state(&self.state_dir, self.cursor.as_deref(), &self.agg) {
            Ok(()) => {
                self.dirty = false;
                self.last_save = Instant::now();
                for path in self.legacy.drain(..) {
                    let _ = fs::remove_file(path);
                }
            }
            Err(e) => warn!(error = %e, "cannot save the state file; will retry"),
        }
    }

    /// Delivers `keys`; failures stay pending with a backoff. Returns
    /// whether every delivery succeeded.
    fn send(
        &mut self,
        keys: &[Key],
        now: u64,
        partial_after: Option<u64>,
        deadline: Option<Instant>,
    ) -> bool {
        let mut ok = true;
        for key in keys {
            if deadline.is_some_and(|d| Instant::now() >= d) {
                warn!(
                    pending = self.agg.len(),
                    "shutdown time is up; summaries stay pending"
                );
                return false;
            }
            let Some(s) = self.agg.get(key) else { continue };
            let partial = partial_after.is_some_and(|t| s.window_end() > t);
            match self.deliver.deliver(s, partial) {
                Ok(()) => self.agg.remove(key),
                Err(e) => {
                    ok = false;
                    let delay = self.agg.failed(key, now);
                    warn!(error = %e, retry_in_secs = delay, "delivery failed; summary kept for retry");
                }
            }
            self.dirty = true;
        }
        // A delivered summary must leave the saved state promptly, to keep
        // the duplicates after a crash to a minimum.
        self.save(true);
        ok
    }

    fn consume(&mut self, entry: &Entry) -> Recorded {
        if let Some(message) = &entry.message {
            match Detection::parse(message, entry.time) {
                Ok((d, fallback)) => {
                    if fallback {
                        warn!(rule = %d.rule, "event has no valid timestamp; using the journal's");
                    }
                    if self.agg.record(&d) == Recorded::Full {
                        return Recorded::Full;
                    }
                }
                Err(NotAnEvent::NoTime) => {
                    warn!("skipping an event without a valid timestamp");
                }
                Err(NotAnEvent::Other) => {}
            }
        }
        self.cursor = Some(entry.cursor.clone());
        self.dirty = true;
        Recorded::Yes
    }
}

/// How [`run`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    /// Stopped by a signal with everything delivered.
    Clean,
    /// Stopped by a signal with summaries still pending (kept on disk).
    Pending,
    /// journalctl exited; systemd restarts the service.
    JournalEnded,
}

/// Runs until SIGTERM/SIGINT or until journalctl exits.
pub fn run(settings: Settings) -> io::Result<Exit> {
    let stop = Arc::new(AtomicBool::new(false));
    spawn_signal_thread(Arc::clone(&stop))?;
    fs::create_dir_all(&settings.state_dir)?;

    let state = load_state(&settings.state_dir, settings.window_secs)?;
    let legacy = legacy_files(&settings.state_dir);
    let mut n = Notifier {
        agg: Aggregator::new(settings.window_secs, settings.max_pending, state.summaries),
        deliver: settings.transport,
        state_dir: settings.state_dir,
        cursor: state.cursor,
        dirty: !legacy.is_empty(),
        last_save: Instant::now(),
        legacy,
    };
    info!(
        transport = ?n.deliver.kind,
        window_secs = settings.window_secs,
        min_priority = %settings.min_priority,
        pending = n.agg.len(),
        "logwizz-notify started"
    );
    let rx = spawn_journal(n.cursor.as_deref(), settings.min_priority)?;
    Ok(main_loop(&mut n, &rx, &stop))
}

fn main_loop<D: Deliver>(n: &mut Notifier<D>, rx: &Receiver<Entry>, stop: &AtomicBool) -> Exit {
    let mut held: Option<Entry> = None;
    let mut last_check = 0;
    let mut journal_open = true;
    while !stop.load(Ordering::Relaxed) {
        let mut quiet = false;
        let entry = match held.take() {
            Some(e) => Some(e),
            None => match rx.recv_timeout(TICK) {
                Ok(e) => Some(e),
                Err(RecvTimeoutError::Timeout) => {
                    quiet = true;
                    None
                }
                Err(RecvTimeoutError::Disconnected) => {
                    journal_open = false;
                    break;
                }
            },
        };
        let mut paused = false;
        if let Some(e) = entry {
            if n.consume(&e) == Recorded::Full {
                if held.is_none() {
                    warn!(
                        pending = n.agg.len(),
                        "pending summary limit reached; pausing until summaries are delivered"
                    );
                }
                held = Some(e);
                paused = true;
            }
        }
        // Windows closed by the clock go out once the journal is quiet (or
        // consumption is paused); superseded windows at most once a second
        // even while a backlog is being read.
        let now = now_secs();
        if quiet || paused || now != last_check {
            last_check = now;
            let due = n.agg.due(now, quiet || paused);
            if !due.is_empty() {
                n.send(&due, now, None, None);
            }
        }
        n.save(false);
        if paused && !stop.load(Ordering::Relaxed) {
            thread::sleep(TICK);
        }
    }

    if !journal_open {
        // Keep open windows for the restart: they continue where they
        // left off. Closed ones are sent now.
        let now = now_secs();
        let due = n.agg.due(now, true);
        n.send(&due, now, None, Some(Instant::now() + SHUTDOWN_BUDGET));
        n.save(true);
        return Exit::JournalEnded;
    }
    // Stopping: send everything, open windows as partial summaries.
    let now = now_secs();
    let keys = n.agg.keys();
    let ok = n.send(
        &keys,
        now,
        Some(now),
        Some(Instant::now() + SHUTDOWN_BUDGET),
    );
    n.save(true);
    if ok && n.agg.is_empty() {
        info!("logwizz-notify stopped");
        Exit::Clean
    } else {
        warn!(
            pending = n.agg.len(),
            "logwizz-notify stopped with summaries pending"
        );
        Exit::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn settings_defaults_and_validation() {
        let s = Settings::from_env(env(&[
            ("TELEGRAM_BOT_TOKEN", "123456:ABC_def-123"),
            ("TELEGRAM_CHAT_ID", "-100123"),
        ]))
        .unwrap();
        assert_eq!((s.window_secs, s.max_pending), (60, 4096));
        assert_eq!(s.min_priority, Severity::Warning);
        assert_eq!(s.state_dir, Path::new("/var/lib/logwizz-notify"));

        let err = |pairs: &[(&str, &str)]| Settings::from_env(env(pairs)).unwrap_err();
        assert!(err(&[]).contains("TELEGRAM_BOT_TOKEN is not set"));
        let e = err(&[
            ("TELEGRAM_BOT_TOKEN", "secret-no-colon"),
            ("TELEGRAM_CHAT_ID", "1"),
        ]);
        assert!(e.contains("invalid format") && !e.contains("secret"), "{e}");
        let hook = |url: &str| err(&[("NOTIFY_KIND", "webhook"), ("NOTIFY_URL", url)]);
        assert!(hook("http://x").contains("HTTPS"));
        assert!(hook("https://x\nheader = evil").contains("control characters"));
        let ok = [("NOTIFY_KIND", "ntfy"), ("NOTIFY_URL", "https://ntfy.sh/t")];
        let with = |extra: (&str, &str)| {
            let mut v = ok.to_vec();
            v.push(extra);
            Settings::from_env(env(&v))
        };
        assert!(with(("NOTIFY_WINDOW_SECS", "9")).is_err());
        assert!(with(("NOTIFY_WINDOW_SECS", "3601")).is_err());
        assert!(with(("NOTIFY_MAX_PENDING", "0")).is_err());
        assert!(with(("NOTIFY_MIN_PRIORITY", "loud")).is_err());
        assert!(with(("NOTIFY_AUTH", "Bearer a\r\nX: y")).is_err());
        assert_eq!(
            with(("NOTIFY_MIN_PRIORITY", "crit")).unwrap().min_priority,
            Severity::Critical
        );
        assert_eq!(
            with(("STATE_DIRECTORY", "/a:/b")).unwrap().state_dir,
            Path::new("/a")
        );
        assert!(err(&[("NOTIFY_KIND", "email")]).contains("NOTIFY_KIND"));
    }

    #[test]
    fn journal_entries() {
        let e = parse_entry(
            br#"{"__CURSOR":"s=1","MESSAGE":"{\"v\":1}","__REALTIME_TIMESTAMP":"1792932007123456"}"#,
        )
        .unwrap();
        assert_eq!(
            (e.cursor.as_str(), e.message.as_deref()),
            ("s=1", Some("{\"v\":1}"))
        );
        assert_eq!(e.time, Some(1_792_932_007));
        let e = parse_entry(br#"{"__CURSOR":"s=2","MESSAGE":[255,1]}"#).unwrap();
        assert_eq!((e.message, e.time), (None, None));
        assert!(parse_entry(b"{}").is_none());
    }

    #[test]
    fn invalid_or_unsupported_state_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE);

        fs::write(&path, b"{").unwrap();
        let err = load_state(dir.path(), 60).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("state file"));
        assert!(!err.to_string().contains("starting empty"));

        fs::write(
            &path,
            serde_json::to_vec(&State {
                v: STATE_VERSION + 1,
                cursor: Some("saved-cursor".into()),
                summaries: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();
        let err = load_state(dir.path(), 60).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("unsupported version"));
    }

    #[test]
    fn imports_shell_notifier_state() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cursor"), "s=abc;i=9\n").unwrap();
        fs::write(
            dir.path().join("agg-1792932000-0123456789abcdef.json"),
            r#"{"bucket":1792932000,"window_start":"2026-10-25T12:40:00Z","window_end":"2026-10-25T12:45:00Z",
               "host":"web1","rule":"ssh","severity":"warning","description":"d","source":"multiple",
               "source_seen":true,"count":4,"last_cursor":"s=abc;i=9","retry_count":2,"retry_after":5}"#,
        )
        .unwrap();
        fs::write(dir.path().join("agg-bad.json"), "{").unwrap();
        let st = load_state(dir.path(), 60).unwrap();
        assert_eq!(st.cursor.as_deref(), Some("s=abc;i=9"));
        assert_eq!(st.summaries.len(), 1);
        let s = &st.summaries[0];
        assert_eq!((s.window_secs, s.count, s.retry_count), (300, 4, 2));
        assert_eq!(s.source_field(), "multiple");
        assert_eq!(legacy_files(dir.path()).len(), 3);
    }

    /// Records deliveries; fails while `fail` is set.
    #[derive(Default)]
    struct Fake {
        sent: Vec<(String, u64, bool)>,
        fail: bool,
    }

    impl Deliver for Fake {
        fn deliver(&mut self, s: &Summary, partial: bool) -> Result<(), String> {
            if self.fail {
                return Err("down".into());
            }
            self.sent.push((s.rule.clone(), s.count, partial));
            Ok(())
        }
    }

    fn event_entry(cursor: &str, ts: u64, rule: &str) -> Entry {
        Entry {
            cursor: cursor.into(),
            message: Some(format!(
                r#"{{"v":1,"ts":"{}","rule":"{rule}","severity":"warning","line":"RAW"}}"#,
                crate::event::format_rfc3339_secs(ts)
            )),
            time: None,
        }
    }

    fn notifier(dir: &Path, max_pending: usize, fail: bool) -> Notifier<Fake> {
        Notifier {
            agg: Aggregator::new(60, max_pending, Vec::new()),
            deliver: Fake {
                fail,
                ..Fake::default()
            },
            state_dir: dir.to_path_buf(),
            cursor: None,
            dirty: false,
            last_save: Instant::now(),
            legacy: Vec::new(),
        }
    }

    #[test]
    fn stop_flushes_open_windows_as_partial_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = notifier(dir.path(), 10, false);
        let now = now_secs();
        let (tx, rx) = sync_channel(16);
        for i in 0..3 {
            tx.send(event_entry(&format!("c{i}"), now, "ssh")).unwrap();
        }
        tx.send(Entry {
            cursor: "c3".into(),
            message: Some("logwizz started".into()),
            time: None,
        })
        .unwrap();
        // Stop once the queued entries have been consumed.
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = Arc::clone(&stop);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(700));
            stopper.store(true, Ordering::Relaxed);
        });
        let exit = main_loop(&mut n, &rx, &stop);
        drop(tx);
        assert_eq!(exit, Exit::Clean);
        assert_eq!(n.deliver.sent, [("ssh".to_string(), 3, true)]);
        let saved: State =
            serde_json::from_slice(&fs::read(dir.path().join(STATE_FILE)).unwrap()).unwrap();
        assert_eq!(saved.cursor.as_deref(), Some("c3"));
        assert!(saved.summaries.is_empty());
    }

    #[test]
    fn journal_end_keeps_open_windows_and_failures() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = notifier(dir.path(), 10, true);
        let now = now_secs();
        let (tx, rx) = sync_channel(16);
        tx.send(event_entry("old", now - 600, "old_rule")).unwrap();
        tx.send(event_entry("new", now, "new_rule")).unwrap();
        drop(tx);
        let exit = main_loop(&mut n, &rx, &AtomicBool::new(false));
        assert_eq!(exit, Exit::JournalEnded);
        assert!(n.deliver.sent.is_empty());
        let saved: State =
            serde_json::from_slice(&fs::read(dir.path().join(STATE_FILE)).unwrap()).unwrap();
        assert_eq!(saved.cursor.as_deref(), Some("new"));
        let rules: Vec<_> = saved
            .summaries
            .iter()
            .map(|s| (s.rule.as_str(), s.retry_count))
            .collect();
        // The closed window was tried and backs off; the open one waits.
        assert_eq!(rules, [("old_rule", 1), ("new_rule", 0)]);

        // A restart with delivery working sends the closed window and keeps
        // counting into the open one.
        let st = load_state(dir.path(), 60);
        let mut n = notifier(dir.path(), 10, false);
        n.agg = Aggregator::new(60, 10, st.summaries);
        n.cursor = st.cursor;
        let (tx, rx) = sync_channel(16);
        tx.send(event_entry("newer", now, "new_rule")).unwrap();
        drop(tx);
        n.agg.failed(&n.agg.keys()[0], 0); // retry_after in the past
        main_loop(&mut n, &rx, &AtomicBool::new(false));
        assert!(
            n.deliver
                .sent
                .iter()
                .any(|(r, c, _)| r == "old_rule" && *c == 1)
        );
        let new: Vec<_> = n
            .agg
            .summaries()
            .map(|s| (s.rule.as_str(), s.count))
            .collect();
        assert_eq!(new, [("new_rule", 2)]);
    }

    #[test]
    fn full_pending_table_holds_the_entry_without_advancing() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = notifier(dir.path(), 1, true);
        let now = now_secs();
        assert_eq!(n.consume(&event_entry("a", now, "one")), Recorded::Yes);
        assert_eq!(n.consume(&event_entry("b", now, "two")), Recorded::Full);
        assert_eq!(n.cursor.as_deref(), Some("a"));
        // Non-event entries still advance.
        let other = Entry {
            cursor: "c".into(),
            message: None,
            time: None,
        };
        assert_eq!(n.consume(&other), Recorded::Yes);
        assert_eq!(n.cursor.as_deref(), Some("c"));
    }
}
