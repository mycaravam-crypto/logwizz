//! Event output: formatting, bounded queueing, rate limiting and
//! deduplication.
//!
//! The monitor thread produces [`Event`]s and hands them to a single output
//! thread through a bounded channel of `output.queue_capacity` events. When
//! the queue is full, `output.on_full` decides:
//!
//! * `block`: the monitor waits (re-checking the shutdown flag every few
//!   milliseconds). Unread data stays in the log files, so nothing is lost
//!   while the process keeps running, at the cost of detection latency.
//! * `drop`: the event is discarded and counted in `events_dropped`, with a
//!   rate-limited warning.
//!
//! A failed write to the output (including a closed pipe) is counted and
//! shuts the daemon down: there is no point in matching lines nobody can
//! receive, and silently continuing would hide the loss.

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;
use tracing::{error, info, warn};

use crate::config::{Config, Limits, OnFull, OutputFormat, Rule};
use crate::event::{Event, SCHEMA_VERSION, format_rfc3339};
use crate::metrics::{self, Metrics};
use crate::watcher::Waker;

/// Minimum time between "events dropped" warnings.
const DROP_WARN_INTERVAL: Duration = Duration::from_secs(10);
/// Backoff while waiting for queue space in `block` mode.
const BLOCK_RETRY: Duration = Duration::from_millis(2);

/// Process-wide values included in every event.
#[derive(Debug, Clone)]
pub struct Meta {
    pub host: String,
    pub pid: u32,
}

impl Meta {
    pub fn current() -> Self {
        Meta {
            host: hostname(),
            pid: std::process::id(),
        }
    }
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the pointer and length describe a valid, writable buffer.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Static data the formatter needs to render an event.
#[derive(Debug)]
pub struct Tables {
    pub files: Vec<PathBuf>,
    pub rules: Vec<Rule>,
    pub meta: Meta,
}

#[derive(Serialize)]
struct JsonEvent<'a> {
    v: u32,
    ts: &'a str,
    host: &'a str,
    pid: u32,
    file: Cow<'a, str>,
    rule: &'a str,
    description: &'a str,
    severity: &'static str,
    match_type: &'static str,
    line: Cow<'a, str>,
    truncated: bool,
}

/// Formats one event, including the trailing newline, into `out`.
///
/// Line content that is not valid UTF-8 is converted lossily (invalid
/// sequences become U+FFFD). In the human format, control characters are
/// escaped so log content cannot inject terminal escape sequences.
pub fn format_event(
    format: OutputFormat,
    t: &Tables,
    ev: &Event,
    ts: &mut String,
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let rule = &t.rules[ev.rule];
    ts.clear();
    format_rfc3339(ev.time, ts);
    let line = String::from_utf8_lossy(&ev.line);
    let file = t.files[ev.file].to_string_lossy();
    match format {
        OutputFormat::Json => {
            let je = JsonEvent {
                v: SCHEMA_VERSION,
                ts,
                host: &t.meta.host,
                pid: t.meta.pid,
                file,
                rule: &rule.id,
                description: &rule.description,
                severity: rule.severity.as_str(),
                match_type: rule.match_type.as_str(),
                line,
                truncated: ev.truncated,
            };
            serde_json::to_writer(&mut *out, &je)?;
        }
        OutputFormat::Human => {
            write!(
                out,
                "{ts} {:<8} [{}] {}: ",
                rule.severity.as_str().to_ascii_uppercase(),
                rule.id,
                escape(&file)
            )?;
            out.extend_from_slice(escape(&line).as_bytes());
            if ev.truncated {
                out.extend_from_slice(b" [truncated]");
            }
        }
    }
    out.push(b'\n');
    Ok(())
}

fn escape(s: &str) -> Cow<'_, str> {
    if !s.chars().any(char::is_control) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Producer side of the output queue.
pub struct Dispatcher {
    tx: Option<SyncSender<Event>>,
    on_full: OnFull,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    last_drop_warning: Option<Instant>,
    drops_since_warning: u64,
    handle: Option<JoinHandle<io::Result<()>>>,
}

impl Dispatcher {
    /// Starts the output thread writing to `writer`. If writing fails, the
    /// thread sets `shutdown`, wakes the monitor and exits.
    pub fn spawn(
        cfg: &Config,
        tables: Arc<Tables>,
        writer: Box<dyn Write + Send>,
        metrics: Arc<Metrics>,
        shutdown: Arc<AtomicBool>,
        waker: Waker,
    ) -> io::Result<Self> {
        let (tx, rx) = sync_channel(cfg.output.queue_capacity);
        let format = cfg.output.format;
        let m = Arc::clone(&metrics);
        let flag = Arc::clone(&shutdown);
        let handle = thread::Builder::new()
            .name("output".into())
            .spawn(move || {
                let result = write_loop(rx, format, &tables, writer);
                if let Err(e) = &result {
                    metrics::inc(&m.output_errors);
                    error!(error = %e, "writing events failed; shutting down");
                    flag.store(true, Ordering::Relaxed);
                    waker.wake();
                }
                result
            })?;
        Ok(Dispatcher {
            tx: Some(tx),
            on_full: cfg.output.on_full,
            metrics,
            shutdown,
            last_drop_warning: None,
            drops_since_warning: 0,
            handle: Some(handle),
        })
    }

    /// Queues an event according to the `on_full` policy.
    pub fn send(&mut self, ev: Event) {
        let Some(tx) = &self.tx else {
            self.dropped(1);
            return;
        };
        let mut ev = match tx.try_send(ev) {
            Ok(()) => {
                metrics::inc(&self.metrics.events_emitted);
                return;
            }
            Err(TrySendError::Disconnected(_)) => {
                // Output thread has exited; its error is already reported.
                self.dropped(1);
                return;
            }
            Err(TrySendError::Full(ev)) => ev,
        };
        if self.on_full == OnFull::Drop {
            self.dropped(1);
            return;
        }
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                self.dropped(1);
                return;
            }
            thread::sleep(BLOCK_RETRY);
            ev = match tx.try_send(ev) {
                Ok(()) => {
                    metrics::inc(&self.metrics.events_emitted);
                    return;
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.dropped(1);
                    return;
                }
                Err(TrySendError::Full(ev)) => ev,
            };
        }
    }

    fn dropped(&mut self, n: u64) {
        metrics::add(&self.metrics.events_dropped, n);
        self.drops_since_warning += n;
        let now = Instant::now();
        let due = self
            .last_drop_warning
            .is_none_or(|t| now.duration_since(t) >= DROP_WARN_INTERVAL);
        if due {
            warn!(
                dropped = self.drops_since_warning,
                "events dropped: output queue full or output unavailable"
            );
            self.last_drop_warning = Some(now);
            self.drops_since_warning = 0;
        }
    }

    /// Closes the queue, waits for queued events to be written and flushed,
    /// and returns the output thread's result.
    pub fn finish(mut self) -> io::Result<()> {
        self.tx = None;
        match self.handle.take().map(JoinHandle::join) {
            Some(Ok(result)) => result,
            Some(Err(_)) => Err(io::Error::other("output thread panicked")),
            None => Ok(()),
        }
    }
}

fn write_loop(
    rx: Receiver<Event>,
    format: OutputFormat,
    tables: &Tables,
    writer: Box<dyn Write + Send>,
) -> io::Result<()> {
    let mut w = BufWriter::with_capacity(64 * 1024, writer);
    let mut line = Vec::with_capacity(1024);
    let mut ts = String::with_capacity(32);
    // Block for the next event; flush whenever the queue runs empty so that
    // output is batched under load but prompt when idle.
    while let Ok(mut ev) = rx.recv() {
        loop {
            line.clear();
            format_event(format, tables, &ev, &mut ts, &mut line)?;
            w.write_all(&line)?;
            match rx.try_recv() {
                Ok(next) => ev = next,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return w.flush(),
            }
        }
        w.flush()?;
    }
    w.flush()
}

/// Outcome of [`Limiter::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Yes,
    RateLimited,
    Duplicate,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    count: u32,
    suppressed: u64,
}

/// Per-rule rate limiting (fixed windows) and (rule, line) deduplication.
///
/// Memory is bounded by the number of rules plus `dedup_max_entries`. When
/// the dedup table is full and nothing in it has expired, new lines are
/// *not* remembered, so they pass through: the limiter errs towards
/// emitting events, never towards wrongly suppressing them.
#[derive(Debug)]
pub struct Limiter {
    rate_limit: u32,
    rate_window: Duration,
    windows: Vec<Option<Window>>,
    dedup_window: Option<Duration>,
    dedup_max: usize,
    // Keyed with per-process random keys so that log content cannot be
    // crafted to collide with, and thereby suppress, another line.
    hasher: RandomState,
    seen: HashMap<(usize, u64), Instant>,
}

impl Limiter {
    pub fn new(limits: &Limits, rules: usize) -> Self {
        Limiter {
            rate_limit: limits.rate_limit_events,
            rate_window: Duration::from_secs(limits.rate_limit_window_secs),
            windows: vec![None; rules],
            dedup_window: (limits.dedup_window_secs > 0)
                .then(|| Duration::from_secs(limits.dedup_window_secs)),
            dedup_max: limits.dedup_max_entries,
            hasher: RandomState::new(),
            seen: HashMap::new(),
        }
    }

    /// Decides whether an event for `rule` on `line` should be emitted.
    /// `rule_id` is only used in diagnostics.
    pub fn admit(&mut self, rule: usize, rule_id: &str, line: &[u8], now: Instant) -> Admit {
        if let Some(window) = self.dedup_window {
            let key = (rule, self.hasher.hash_one(line));
            match self.seen.get(&key) {
                Some(&t) if now.duration_since(t) < window => return Admit::Duplicate,
                _ => {
                    if self.seen.len() >= self.dedup_max && !self.seen.contains_key(&key) {
                        self.seen.retain(|_, t| now.duration_since(*t) < window);
                    }
                    if self.seen.len() < self.dedup_max || self.seen.contains_key(&key) {
                        self.seen.insert(key, now);
                    }
                }
            }
        }
        if self.rate_limit > 0 {
            let w = self.windows[rule].get_or_insert(Window {
                start: now,
                count: 0,
                suppressed: 0,
            });
            if now.duration_since(w.start) >= self.rate_window {
                if w.suppressed > 0 {
                    info!(
                        rule = rule_id,
                        suppressed = w.suppressed,
                        "rate limit window ended"
                    );
                }
                *w = Window {
                    start: now,
                    count: 0,
                    suppressed: 0,
                };
            }
            if w.count >= self.rate_limit {
                if w.suppressed == 0 {
                    warn!(
                        rule = rule_id,
                        limit = self.rate_limit,
                        window_secs = self.rate_window.as_secs(),
                        "rate limit reached; suppressing further events for this rule"
                    );
                }
                w.suppressed += 1;
                return Admit::RateLimited;
            }
            w.count += 1;
        }
        Admit::Yes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::path::Path;
    use std::time::UNIX_EPOCH;

    fn tables() -> Tables {
        let cfg = config::parse(
            r#"
            [[files]]
            path = "/var/log/auth.log"
            [[rules]]
            id = "ssh"
            description = "Failed SSH \"login\""
            match_type = "literal"
            pattern = "Failed"
            severity = "warning"
            "#,
            Path::new("t"),
        )
        .unwrap();
        Tables {
            files: cfg.files,
            rules: cfg.rules,
            meta: Meta {
                host: "box".into(),
                pid: 42,
            },
        }
    }

    fn event(line: &[u8], truncated: bool) -> Event {
        Event {
            time: UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
            file: 0,
            rule: 0,
            line: line.into(),
            truncated,
        }
    }

    fn render(format: OutputFormat, ev: &Event) -> String {
        let mut out = Vec::new();
        format_event(format, &tables(), ev, &mut String::new(), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn json_event_schema() {
        let s = render(OutputFormat::Json, &event(b"Failed \"x\"\t\x01\xff", false));
        assert!(s.ends_with('\n') && s.matches('\n').count() == 1);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["ts"], "2023-11-14T22:13:20.123000Z");
        assert_eq!(v["host"], "box");
        assert_eq!(v["pid"], 42);
        assert_eq!(v["file"], "/var/log/auth.log");
        assert_eq!(v["rule"], "ssh");
        assert_eq!(v["description"], "Failed SSH \"login\"");
        assert_eq!(v["severity"], "warning");
        assert_eq!(v["match_type"], "literal");
        assert_eq!(v["line"], "Failed \"x\"\t\u{1}\u{FFFD}");
        assert_eq!(v["truncated"], false);
    }

    #[test]
    fn human_format_escapes_control_characters() {
        let s = render(
            OutputFormat::Human,
            &event(b"Failed \x1b[31mred\x1b[0m", true),
        );
        assert_eq!(
            s,
            "2023-11-14T22:13:20.123000Z WARNING  [ssh] /var/log/auth.log: \
             Failed \\u{1b}[31mred\\u{1b}[0m [truncated]\n"
        );
    }

    fn limits(rate: u32, dedup_secs: u64, max: usize) -> Limits {
        Limits {
            rate_limit_events: rate,
            rate_limit_window_secs: 10,
            dedup_window_secs: dedup_secs,
            dedup_max_entries: max,
        }
    }

    #[test]
    fn unlimited_by_default() {
        let mut l = Limiter::new(&Limits::default(), 1);
        let now = Instant::now();
        for _ in 0..1000 {
            assert_eq!(l.admit(0, "r", b"same", now), Admit::Yes);
        }
    }

    #[test]
    fn rate_limit_per_rule_and_window() {
        let mut l = Limiter::new(&limits(2, 0, 1), 2);
        let t0 = Instant::now();
        assert_eq!(l.admit(0, "a", b"1", t0), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"2", t0), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"3", t0), Admit::RateLimited);
        // Other rules have their own budget.
        assert_eq!(l.admit(1, "b", b"1", t0), Admit::Yes);
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(l.admit(0, "a", b"4", t1), Admit::Yes);
    }

    #[test]
    fn dedup_suppresses_within_window() {
        let mut l = Limiter::new(&limits(0, 5, 100), 2);
        let t0 = Instant::now();
        assert_eq!(l.admit(0, "a", b"x", t0), Admit::Yes);
        assert_eq!(
            l.admit(0, "a", b"x", t0 + Duration::from_secs(4)),
            Admit::Duplicate
        );
        assert_eq!(l.admit(1, "b", b"x", t0), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"y", t0), Admit::Yes);
        // The window is measured from first sight, not refreshed by repeats.
        assert_eq!(
            l.admit(0, "a", b"x", t0 + Duration::from_secs(5)),
            Admit::Yes
        );
    }

    #[test]
    fn full_dedup_table_lets_events_through() {
        let mut l = Limiter::new(&limits(0, 60, 2), 1);
        let t0 = Instant::now();
        assert_eq!(l.admit(0, "a", b"1", t0), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"2", t0), Admit::Yes);
        // Table full, nothing expired: "3" is emitted but not remembered.
        assert_eq!(l.admit(0, "a", b"3", t0), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"3", t0), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"1", t0), Admit::Duplicate);
        assert!(l.seen.len() <= 2);
        // After expiry, space is reclaimed.
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(l.admit(0, "a", b"3", t1), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"3", t1), Admit::Duplicate);
    }

    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn test_cfg(extra: &str) -> Config {
        config::parse(
            &format!(
                "[[files]]\npath = \"/x\"\n[[rules]]\nid = \"r\"\nmatch_type = \"literal\"\n\
                 pattern = \"p\"\nseverity = \"info\"\n{extra}"
            ),
            Path::new("t"),
        )
        .unwrap()
    }

    #[test]
    fn output_failure_triggers_shutdown() {
        let cfg = test_cfg("");
        let m = Arc::new(Metrics::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (waker, _rx) = crate::watcher::wake_channel();
        let mut d = Dispatcher::spawn(
            &cfg,
            Arc::new(tables()),
            Box::new(FailingWriter),
            Arc::clone(&m),
            Arc::clone(&shutdown),
            waker,
        )
        .unwrap();
        d.send(event(b"Failed", false));
        let err = d.finish().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(shutdown.load(Ordering::Relaxed));
        assert_eq!(m.snapshot().output_errors, 1);
    }

    /// A writer that blocks until released, to simulate a stalled consumer.
    struct Gate(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
    impl Write for Gate {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            let (lock, cv) = &*self.0;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn stalled(on_full: &str) -> (Dispatcher, Arc<Metrics>, Arc<AtomicBool>, Gate) {
        let cfg = test_cfg(&format!(
            "[output]\nqueue_capacity = 2\non_full = \"{on_full}\"\n"
        ));
        let m = Arc::new(Metrics::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let (waker, _rx) = crate::watcher::wake_channel();
        let d = Dispatcher::spawn(
            &cfg,
            Arc::new(tables()),
            Box::new(Gate(Arc::clone(&gate))),
            Arc::clone(&m),
            Arc::clone(&shutdown),
            waker,
        )
        .unwrap();
        (d, m, shutdown, Gate(gate))
    }

    fn release(g: &Gate) {
        *g.0.0.lock().unwrap() = true;
        g.0.1.notify_all();
    }

    /// Enough events to overflow the output thread's 64 KiB BufWriter, so
    /// that the stalled inner writer is reached and the queue fills.
    const MANY: usize = 2000;

    #[test]
    fn drop_policy_counts_dropped_events() {
        let (mut d, m, _shutdown, gate) = stalled("drop");
        let line = [b'x'; 100];
        for _ in 0..MANY {
            d.send(event(&line, false));
        }
        let s = m.snapshot();
        assert!(s.events_dropped >= 1, "{s}");
        assert_eq!(s.events_emitted + s.events_dropped, MANY as u64);
        release(&gate);
        d.finish().unwrap();
    }

    #[test]
    fn block_policy_waits_and_honours_shutdown() {
        let (mut d, m, shutdown, gate) = stalled("block");
        // The writer stalls, so sends start blocking; a blocked send must
        // give up once shutdown is requested.
        let flag = Arc::clone(&shutdown);
        let t = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            flag.store(true, Ordering::Relaxed);
        });
        let start = Instant::now();
        let line = [b'x'; 100];
        for _ in 0..MANY {
            d.send(event(&line, false));
        }
        assert!(start.elapsed() >= Duration::from_millis(40));
        t.join().unwrap();
        let s = m.snapshot();
        assert!(s.events_dropped >= 1, "{s}");
        assert_eq!(s.events_emitted + s.events_dropped, MANY as u64);
        release(&gate);
        d.finish().unwrap();
    }
}
