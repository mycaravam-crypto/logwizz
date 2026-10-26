//! Event output: formatting, bounded queueing, rate limiting and
//! deduplication.
//!
//! The monitor thread produces [`Event`]s and hands them to a single output
//! thread through a bounded channel of `output.queue_capacity` events, which
//! together may hold at most `output.max_queue_bytes` (see [`event_cost`]).
//! The byte limit keeps memory bounded when lines are long: without it, the
//! default 4096 events of up to 64 KiB each could hold 256 MiB. An event is
//! always accepted into an empty queue, so a single event larger than the
//! limit cannot stall the daemon. When either limit is reached, the queue is
//! full and `output.on_full` decides:
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
//!
//! [`Progress`] counts events queued and events written and flushed, so
//! that saved offsets (see `state`) never run ahead of the output.

use std::borrow::Cow;
use std::collections::hash_map::RandomState;
use std::collections::{HashSet, VecDeque};
use std::hash::BuildHasher;
use std::io::{self, BufWriter, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;
use tracing::{error, info, warn};

use crate::config::{Config, Limits, OnFull, Output, OutputFormat, Rule};
use crate::event::{Event, SCHEMA_VERSION, format_rfc3339};
use crate::metrics::{self, Metrics};
use crate::watcher::Waker;

/// Minimum time between "events dropped" warnings.
const DROP_WARN_INTERVAL: Duration = Duration::from_secs(10);
/// Backoff while waiting for queue space in `block` mode.
const BLOCK_RETRY: Duration = Duration::from_millis(2);
/// Under sustained load the queue never runs empty; flush at least this
/// often anyway so that `Progress::flushed` keeps advancing.
const MAX_FLUSH_DELAY: Duration = Duration::from_millis(200);

/// Events queued and events written and flushed, in queue order.
#[derive(Debug, Default)]
pub struct Progress {
    sent: AtomicU64,
    flushed: AtomicU64,
}

impl Progress {
    /// Events queued so far (only the monitor thread queues events),
    /// including events lost because the output failed or shutdown
    /// interrupted a blocked send: those are never flushed, so no offset
    /// past them is saved. Events dropped by `on_full = "drop"` are not
    /// counted; that loss is by configuration.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Events written and flushed to the output so far. Since the queue is
    /// FIFO, these are exactly the first `flushed()` events queued.
    pub fn flushed(&self) -> u64 {
        self.flushed.load(Ordering::Acquire)
    }
}

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
    #[serde(skip_serializing_if = "Fields::is_empty")]
    fields: Fields<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold: Option<JsonThreshold<'a>>,
}

#[derive(Serialize)]
struct JsonThreshold<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<Cow<'a, str>>,
    count: u32,
    window_secs: u64,
    /// The capture counted by `distinct`, and the first of its values.
    #[serde(skip_serializing_if = "Option::is_none")]
    distinct: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    values: Vec<Cow<'a, str>>,
}

/// Named capture values, serialised as a JSON object in group order.
struct Fields<'a>(Vec<(&'a str, Cow<'a, str>)>);

impl Fields<'_> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for Fields<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(self.0.iter().map(|(k, v)| (k, v)))
    }
}

/// Formats one event, including the trailing newline, into `out`.
///
/// Line content that is not valid UTF-8 is converted lossily (invalid
/// sequences become U+FFFD). In the human format, control characters are
/// escaped so log content cannot inject terminal escape sequences. With
/// `syslog_prefix`, the line starts with `<N>`, N being the severity's
/// syslog priority.
pub fn format_event(
    format: OutputFormat,
    syslog_prefix: bool,
    t: &Tables,
    ev: &Event,
    ts: &mut String,
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let rule = &t.rules[ev.rule];
    ts.clear();
    format_rfc3339(ev.time, ts);
    let line = String::from_utf8_lossy(&ev.line);
    let file = ev.file.to_string_lossy();
    let fields = Fields(
        ev.fields
            .iter()
            .filter_map(|(i, v)| Some((rule.matcher.group_name(*i)?, String::from_utf8_lossy(v))))
            .collect(),
    );
    let threshold = ev.threshold.as_ref().map(|f| JsonThreshold {
        group: f.group.as_deref().map(String::from_utf8_lossy),
        count: f.count,
        window_secs: rule.threshold.as_ref().map_or(0, |t| t.window.as_secs()),
        distinct: rule
            .threshold
            .as_ref()
            .and_then(|t| t.distinct)
            .and_then(|i| rule.matcher.group_name(i)),
        values: f
            .sample
            .iter()
            .map(|v| String::from_utf8_lossy(v))
            .collect(),
    });
    if syslog_prefix {
        write!(out, "<{}>", rule.severity.syslog_priority())?;
    }
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
                fields,
                threshold,
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
            for (name, value) in &fields.0 {
                write!(out, " {name}=")?;
                out.extend_from_slice(escape(value).as_bytes());
            }
            if let Some(t) = &threshold {
                write!(
                    out,
                    " [threshold count={} window={}s",
                    t.count, t.window_secs
                )?;
                if let Some(group) = &t.group {
                    out.extend_from_slice(b" group=");
                    out.extend_from_slice(escape(group).as_bytes());
                }
                if let (Some(name), false) = (t.distinct, t.values.is_empty()) {
                    write!(out, " {name}=")?;
                    out.extend_from_slice(escape(&t.values.join(",")).as_bytes());
                }
                out.push(b']');
            }
        }
    }
    out.push(b'\n');
    Ok(())
}

/// Characters escaped in human output: controls, plus invisible characters
/// that can reorder or hide text (bidi controls, zero-width characters,
/// BOM) and Unicode line separators that some viewers render as a newline.
fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn escape(s: &str) -> Cow<'_, str> {
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if needs_escape(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Bytes an event is charged against `max_queue_bytes`: its line and
/// captured values plus the fixed part of the struct.
pub fn event_cost(ev: &Event) -> usize {
    let fields: usize = ev
        .fields
        .iter()
        .map(|(_, v)| FIELD_OVERHEAD + v.len())
        .sum();
    let threshold = ev.threshold.as_ref().map_or(0, |t| {
        let sample: usize = t.sample.iter().map(|v| FIELD_OVERHEAD + v.len()).sum();
        t.group.as_ref().map_or(0, |g| g.len()) + sample
    });
    std::mem::size_of::<Event>() + ev.line.len() + fields + threshold
}

/// Fixed bytes per captured field: its index and the boxed slice.
const FIELD_OVERHEAD: usize = std::mem::size_of::<(usize, Box<[u8]>)>();

/// What the output queue carries.
enum Msg {
    Event(Event),
    /// Tables for the events queued after this message (configuration
    /// reload). Sent through the queue so that every event is formatted
    /// with the file and rule lists its indices refer to.
    Tables(Arc<Tables>),
}

/// The event inside a message handed back by a failed send; only events
/// are sent with `try_enqueue`.
fn into_event(msg: Msg) -> Event {
    match msg {
        Msg::Event(ev) => ev,
        Msg::Tables(_) => unreachable!("table updates are not sent with try_enqueue"),
    }
}

/// Producer side of the output queue.
pub struct Dispatcher {
    tx: Option<SyncSender<Msg>>,
    /// Sum of [`event_cost`] over events queued or being written. Only the
    /// monitor thread adds to it and only the output thread subtracts.
    queued_bytes: Arc<AtomicUsize>,
    max_queue_bytes: usize,
    on_full: OnFull,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    last_drop_warning: Option<Instant>,
    drops_since_warning: u64,
    progress: Arc<Progress>,
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
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let format = cfg.output.format;
        let prefix = cfg.output.syslog_prefix;
        let m = Arc::clone(&metrics);
        let flag = Arc::clone(&shutdown);
        let in_flight = Arc::clone(&queued_bytes);
        let progress = Arc::new(Progress::default());
        let flushed = Arc::clone(&progress);
        let handle = thread::Builder::new()
            .name("output".into())
            .spawn(move || {
                let result = write_loop(rx, &in_flight, format, prefix, tables, writer, &flushed);
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
            queued_bytes,
            max_queue_bytes: cfg.output.max_queue_bytes,
            on_full: cfg.output.on_full,
            metrics,
            shutdown,
            last_drop_warning: None,
            drops_since_warning: 0,
            progress,
            handle: Some(handle),
        })
    }

    pub fn progress(&self) -> Arc<Progress> {
        Arc::clone(&self.progress)
    }

    fn queued(&self) {
        metrics::inc(&self.metrics.events_emitted);
        self.progress.sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Applies a reloaded configuration's queue byte limit and full-queue
    /// policy. The event capacity, format and destination need a restart.
    pub fn set_policy(&mut self, output: &Output) {
        self.max_queue_bytes = output.max_queue_bytes;
        self.on_full = output.on_full;
    }

    /// Makes events queued from now on refer to `tables`. Waits for queue
    /// space whatever the `on_full` policy, since the update must not be
    /// lost; gives up only on shutdown or when the output thread has
    /// exited.
    pub fn set_tables(&mut self, tables: Arc<Tables>) {
        let Some(tx) = &self.tx else {
            return;
        };
        let mut msg = Msg::Tables(tables);
        loop {
            match tx.try_send(msg) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => return,
                Err(TrySendError::Full(m)) => msg = m,
            }
            if self.shutdown.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(BLOCK_RETRY);
        }
    }

    /// Queues an event according to the `on_full` policy.
    pub fn send(&mut self, ev: Event) {
        let Some(tx) = &self.tx else {
            self.lost();
            return;
        };
        let mut ev = match self.try_enqueue(tx, ev) {
            Ok(()) => {
                self.queued();
                return;
            }
            Err(TrySendError::Disconnected(_)) => {
                // Output thread has exited; its error is already reported.
                self.lost();
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
                self.lost();
                return;
            }
            thread::sleep(BLOCK_RETRY);
            ev = match self.try_enqueue(tx, ev) {
                Ok(()) => {
                    self.queued();
                    return;
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.lost();
                    return;
                }
                Err(TrySendError::Full(ev)) => ev,
            };
        }
    }

    /// Dropped although the policy is to deliver: counts as sent but will
    /// never be flushed, which holds back saved offsets.
    fn lost(&mut self) {
        self.progress.sent.fetch_add(1, Ordering::Relaxed);
        self.dropped(1);
    }

    /// Queues `ev` if both the event count and the byte budget allow it.
    fn try_enqueue(&self, tx: &SyncSender<Msg>, ev: Event) -> Result<(), TrySendError<Event>> {
        let cost = event_cost(&ev);
        let before = self.queued_bytes.fetch_add(cost, Ordering::Relaxed);
        if before > 0 && before + cost > self.max_queue_bytes {
            self.queued_bytes.fetch_sub(cost, Ordering::Relaxed);
            return Err(TrySendError::Full(ev));
        }
        tx.try_send(Msg::Event(ev)).map_err(|e| {
            self.queued_bytes.fetch_sub(cost, Ordering::Relaxed);
            match e {
                TrySendError::Full(m) => TrySendError::Full(into_event(m)),
                TrySendError::Disconnected(m) => TrySendError::Disconnected(into_event(m)),
            }
        })
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
    rx: Receiver<Msg>,
    queued_bytes: &AtomicUsize,
    format: OutputFormat,
    syslog_prefix: bool,
    mut tables: Arc<Tables>,
    writer: Box<dyn Write + Send>,
    progress: &Progress,
) -> io::Result<()> {
    let mut w = BufWriter::with_capacity(64 * 1024, writer);
    let mut line = Vec::with_capacity(1024);
    let mut ts = String::with_capacity(32);
    let mut written = 0u64;
    let flush = |w: &mut BufWriter<_>, written: u64| -> io::Result<Instant> {
        w.flush()?;
        progress.flushed.store(written, Ordering::Release);
        Ok(Instant::now())
    };
    // Block for the next event; flush whenever the queue runs empty so that
    // output is batched under load but prompt when idle.
    while let Ok(mut msg) = rx.recv() {
        let mut last_flush = Instant::now();
        loop {
            match msg {
                Msg::Tables(t) => tables = t,
                Msg::Event(ev) => {
                    line.clear();
                    format_event(format, syslog_prefix, &tables, &ev, &mut ts, &mut line)?;
                    w.write_all(&line)?;
                    queued_bytes.fetch_sub(event_cost(&ev), Ordering::Relaxed);
                    written += 1;
                    if last_flush.elapsed() >= MAX_FLUSH_DELAY {
                        last_flush = flush(&mut w, written)?;
                    }
                }
            }
            match rx.try_recv() {
                Ok(next) => msg = next,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return flush(&mut w, written).map(drop),
            }
        }
        flush(&mut w, written)?;
    }
    flush(&mut w, written).map(drop)
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
/// Only emitted events are remembered for deduplication: a line suppressed
/// by the rate limit has not been reported, so a repeat of it is not a
/// duplicate.
///
/// Memory is bounded by the number of rules plus `dedup_max_entries`. When
/// the dedup table is full and nothing in it has expired, new lines are
/// *not* remembered, so they pass through: the limiter errs towards
/// emitting events, never towards wrongly suppressing them.
///
/// Entries expire in insertion order, because every entry lives for the
/// same window and `now` never goes backwards. Expiry pops them from the
/// front of a queue, so the cost per event is constant however large the
/// table is.
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
    seen: HashSet<DedupKey>,
    /// The entries of `seen` with their insertion times, oldest first.
    expiry: VecDeque<(DedupKey, Instant)>,
}

/// (rule index, keyed hash of the line).
type DedupKey = (usize, u64);

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
            seen: HashSet::new(),
            expiry: VecDeque::new(),
        }
    }

    /// Applies reloaded limits and rule list. `kept[new] = Some(old)` for
    /// each rule that is unchanged (same id and definition) at a possibly
    /// different index; its rate-limit window and dedup entries carry
    /// over. All state of changed and removed rules is dropped.
    pub fn reconfigure(&mut self, limits: &Limits, kept: &[Option<usize>]) {
        self.rate_limit = limits.rate_limit_events;
        self.rate_window = Duration::from_secs(limits.rate_limit_window_secs);
        self.dedup_window =
            (limits.dedup_window_secs > 0).then(|| Duration::from_secs(limits.dedup_window_secs));
        self.dedup_max = limits.dedup_max_entries;
        self.windows = kept
            .iter()
            .map(|old| old.and_then(|i| self.windows.get(i).copied().flatten()))
            .collect();
        // Old rule index -> new index, for the dedup keys.
        let mut renumber = vec![None; kept.iter().flatten().max().map_or(0, |&i| i + 1)];
        for (new, old) in kept.iter().enumerate() {
            if let Some(old) = *old {
                renumber[old] = Some(new);
            }
        }
        let expiry = std::mem::take(&mut self.expiry);
        self.seen.clear();
        if self.dedup_window.is_none() {
            return;
        }
        for ((rule, hash), t) in expiry {
            if let Some(Some(new)) = renumber.get(rule) {
                self.expiry.push_back(((*new, hash), t));
            }
        }
        // A smaller table keeps the newest entries.
        while self.expiry.len() > self.dedup_max {
            self.expiry.pop_front();
        }
        self.seen.extend(self.expiry.iter().map(|&(key, _)| key));
    }

    /// Decides whether an event for `rule` on `line` should be emitted.
    /// `rule_id` is only used in diagnostics.
    pub fn admit(&mut self, rule: usize, rule_id: &str, line: &[u8], now: Instant) -> Admit {
        let key = match self.dedup_window {
            Some(window) => {
                while let Some(&(old, t)) = self.expiry.front() {
                    if now.saturating_duration_since(t) < window {
                        break;
                    }
                    self.seen.remove(&old);
                    self.expiry.pop_front();
                }
                let key = (rule, self.hasher.hash_one(line));
                if self.seen.contains(&key) {
                    return Admit::Duplicate;
                }
                Some(key)
            }
            None => None,
        };
        if self.rate_limit > 0 && !self.within_rate(rule, rule_id, now) {
            return Admit::RateLimited;
        }
        if let Some(key) = key {
            if self.seen.len() < self.dedup_max {
                self.seen.insert(key);
                self.expiry.push_back((key, now));
            }
        }
        Admit::Yes
    }

    /// Counts an event against `rule`'s current window; `false` if the
    /// window's budget is already used up.
    fn within_rate(&mut self, rule: usize, rule_id: &str, now: Instant) -> bool {
        let w = self.windows[rule].get_or_insert(Window {
            start: now,
            count: 0,
            suppressed: 0,
        });
        if now.saturating_duration_since(w.start) >= self.rate_window {
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
            return false;
        }
        w.count += 1;
        true
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
            file: Path::new("/var/log/auth.log").into(),
            rule: 0,
            line: line.into(),
            truncated,
            fields: Vec::new(),
            threshold: None,
        }
    }

    fn render(format: OutputFormat, ev: &Event) -> String {
        render_with(format, false, ev)
    }

    fn render_with(format: OutputFormat, prefix: bool, ev: &Event) -> String {
        let mut out = Vec::new();
        format_event(format, prefix, &tables(), ev, &mut String::new(), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn captured_fields_in_both_formats() {
        let cfg = config::parse(
            r#"
            [[files]]
            path = "/var/log/kern.log"
            [[rules]]
            id = "fw"
            match_type = "regex"
            pattern = 'SRC=(?P<src>\S+) DPT=(?P<dpt>\d+)(?P<rest>.*)'
            severity = "notice"
            "#,
            Path::new("t"),
        )
        .unwrap();
        let line = b"SRC=192.0.2.7 DPT=22 \x1b[31m";
        let ev = Event {
            fields: cfg.rules[0].matcher.fields(line),
            ..event(line, false)
        };
        let t = Tables {
            rules: cfg.rules,
            meta: Meta {
                host: "box".into(),
                pid: 42,
            },
        };
        let render = |format| {
            let mut out = Vec::new();
            format_event(format, false, &t, &ev, &mut String::new(), &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        let v: serde_json::Value = serde_json::from_str(&render(OutputFormat::Json)).unwrap();
        assert_eq!(
            v["fields"],
            serde_json::json!({"src": "192.0.2.7", "dpt": "22", "rest": " \u{1b}[31m"})
        );
        let human = render(OutputFormat::Human);
        assert!(
            human.ends_with(" src=192.0.2.7 dpt=22 rest= \\u{1b}[31m\n"),
            "{human}"
        );
        assert!(event_cost(&ev) > event_cost(&event(line, false)));
        // No named groups: no "fields" key at all.
        let plain = render_with(OutputFormat::Json, false, &event(b"Failed", false));
        assert!(!plain.contains("fields"), "{plain}");
    }

    #[test]
    fn threshold_events_report_group_count_and_window() {
        let cfg = config::parse(
            r#"
            [[files]]
            path = "/var/log/kern.log"
            [[rules]]
            id = "scan"
            match_type = "regex"
            pattern = 'SRC=(?P<src>\S+) DPT=(?P<dpt>\d+)'
            severity = "critical"
            [rules.threshold]
            group_by = "src"
            distinct = "dpt"
            count = 20
            window_secs = 10
            "#,
            Path::new("t"),
        )
        .unwrap();
        let line = b"SRC=192.0.2.7 DPT=22";
        let ev = Event {
            fields: cfg.rules[0].matcher.fields(line),
            threshold: Some(Box::new(crate::threshold::Fired {
                group: Some(b"192.0.2.7"[..].into()),
                count: 20,
                sample: vec![b"22"[..].into(), b"23"[..].into()],
            })),
            ..event(line, false)
        };
        let t = Tables {
            rules: cfg.rules,
            meta: Meta {
                host: "box".into(),
                pid: 42,
            },
        };
        let render = |format| {
            let mut out = Vec::new();
            format_event(format, false, &t, &ev, &mut String::new(), &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        let v: serde_json::Value = serde_json::from_str(&render(OutputFormat::Json)).unwrap();
        assert_eq!(
            v["threshold"],
            serde_json::json!({"group": "192.0.2.7", "count": 20, "window_secs": 10,
                "distinct": "dpt", "values": ["22", "23"]})
        );
        let human = render(OutputFormat::Human);
        assert!(
            human.ends_with(" [threshold count=20 window=10s group=192.0.2.7 dpt=22,23]\n"),
            "{human}"
        );
        assert!(
            event_cost(&ev)
                > event_cost(&Event {
                    threshold: None,
                    ..ev.clone()
                })
        );
        let plain = render_with(OutputFormat::Json, false, &event(b"Failed", false));
        assert!(!plain.contains("threshold"), "{plain}");
    }

    #[test]
    fn syslog_prefix_carries_severity() {
        let ev = event(b"Failed", false);
        let json = render_with(OutputFormat::Json, true, &ev);
        assert!(json.starts_with("<4>{\"v\":1,"), "{json}");
        let human = render_with(OutputFormat::Human, true, &ev);
        assert!(
            human.starts_with("<4>2023-11-14T22:13:20.123000Z WARNING "),
            "{human}"
        );
        assert!(!render(OutputFormat::Json, &ev).starts_with('<'));
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

    #[test]
    fn human_format_escapes_bidi_and_line_separators() {
        let s = render(
            OutputFormat::Human,
            &event("Failed \u{202E}gpj.exe\u{2028}x\u{200B}".as_bytes(), false),
        );
        assert!(
            s.ends_with("Failed \\u{202e}gpj.exe\\u{2028}x\\u{200b}\n"),
            "{s}"
        );
        // Ordinary non-ASCII text is left alone.
        let s = render(
            OutputFormat::Human,
            &event("Failed für €".as_bytes(), false),
        );
        assert!(s.ends_with("Failed für €\n"), "{s}");
    }

    fn limits(rate: u32, dedup_secs: u64, max: usize) -> Limits {
        Limits {
            rate_limit_events: rate,
            rate_limit_window_secs: 10,
            dedup_window_secs: dedup_secs,
            dedup_max_entries: max,
            ..Limits::default()
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
    fn reconfigure_keeps_state_of_unchanged_rules_only() {
        let mut l = Limiter::new(&limits(1, 60, 100), 3);
        let t0 = Instant::now();
        for (rule, id) in [(0, "a"), (1, "b"), (2, "c")] {
            assert_eq!(l.admit(rule, id, b"x", t0), Admit::Yes);
            assert_eq!(l.admit(rule, id, b"y", t0), Admit::RateLimited);
        }
        // New order: c (unchanged, was 2), a new rule, a (unchanged, was 0).
        // b was removed or changed.
        l.reconfigure(&limits(1, 60, 100), &[Some(2), None, Some(0)]);
        assert_eq!(l.admit(0, "c", b"x", t0), Admit::Duplicate);
        assert_eq!(l.admit(0, "c", b"z", t0), Admit::RateLimited);
        assert_eq!(l.admit(1, "new", b"x", t0), Admit::Yes, "fresh state");
        assert_eq!(l.admit(2, "a", b"x", t0), Admit::Duplicate);
        assert_eq!(l.admit(2, "a", b"z", t0), Admit::RateLimited);
    }

    #[test]
    fn reconfigure_applies_new_limits() {
        let mut l = Limiter::new(&limits(1, 60, 100), 1);
        let t0 = Instant::now();
        assert_eq!(l.admit(0, "a", b"x", t0), Admit::Yes);
        // Dedup off and a higher rate limit.
        l.reconfigure(&limits(5, 0, 100), &[Some(0)]);
        assert_eq!(l.admit(0, "a", b"x", t0), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"x", t0), Admit::Yes);
        // A smaller dedup table keeps the newest entries.
        let mut l = Limiter::new(&limits(0, 60, 100), 1);
        for line in [b"1", b"2", b"3"] {
            assert_eq!(l.admit(0, "a", line, t0), Admit::Yes);
        }
        l.reconfigure(&limits(0, 60, 2), &[Some(0)]);
        assert_eq!(l.admit(0, "a", b"1", t0), Admit::Yes, "oldest dropped");
        assert_eq!(l.admit(0, "a", b"3", t0), Admit::Duplicate);
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
        assert!(l.seen.len() <= 2 && l.expiry.len() == l.seen.len());
        // After expiry, space is reclaimed.
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(l.admit(0, "a", b"3", t1), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"3", t1), Admit::Duplicate);
    }

    #[test]
    fn rate_limited_line_is_not_remembered_as_duplicate() {
        let mut l = Limiter::new(&limits(1, 300, 100), 1);
        let t0 = Instant::now();
        assert_eq!(l.admit(0, "a", b"A", t0), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"B", t0), Admit::RateLimited);
        // B was never reported, so after the rate window it must be.
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(l.admit(0, "a", b"B", t1), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"B", t1), Admit::Duplicate);
        // A is still a duplicate of the event emitted at t0.
        assert_eq!(l.admit(0, "a", b"A", t1), Admit::Duplicate);
    }

    #[test]
    fn dedup_entries_expire_oldest_first() {
        let mut l = Limiter::new(&limits(0, 10, 100), 1);
        let t0 = Instant::now();
        for (i, line) in [b"1", b"2", b"3"].iter().enumerate() {
            l.admit(0, "a", *line, t0 + Duration::from_secs(i as u64 * 4));
        }
        // At t0+10 only "1" (seen at t0) has expired.
        let t = t0 + Duration::from_secs(10);
        assert_eq!(l.admit(0, "a", b"1", t), Admit::Yes);
        assert_eq!(l.admit(0, "a", b"2", t), Admit::Duplicate);
        assert_eq!(l.admit(0, "a", b"3", t), Admit::Duplicate);
        assert_eq!(l.seen.len(), 3);
        assert_eq!(l.expiry.len(), 3);
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
        stalled_with(&format!(
            "[output]\nqueue_capacity = 2\non_full = \"{on_full}\"\n"
        ))
    }

    fn stalled_with(extra: &str) -> (Dispatcher, Arc<Metrics>, Arc<AtomicBool>, Gate) {
        let cfg = test_cfg(extra);
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
    fn byte_budget_bounds_queued_memory() {
        // The count limit alone would admit all events; the byte budget must
        // make the queue full long before that.
        let (mut d, m, _shutdown, gate) = stalled_with(
            "[output]\nqueue_capacity = 100000\nmax_queue_bytes = 65536\non_full = \"drop\"\n",
        );
        let line = [b'x'; 1000];
        for _ in 0..MANY {
            d.send(event(&line, false));
        }
        assert!(d.queued_bytes.load(Ordering::Relaxed) <= 65536);
        let s = m.snapshot();
        // Queued events plus those absorbed by the writer's 64 KiB buffer.
        assert!(s.events_emitted < 200, "{s}");
        assert_eq!(s.events_emitted + s.events_dropped, MANY as u64);
        release(&gate);
        let queued = Arc::clone(&d.queued_bytes);
        d.finish().unwrap();
        assert_eq!(queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn event_larger_than_budget_is_accepted_into_empty_queue() {
        let (mut d, m, _shutdown, gate) =
            stalled_with("[output]\nmax_queue_bytes = 65536\non_full = \"drop\"\n");
        release(&gate);
        d.send(event(&[b'x'; 200_000], false));
        let queued = Arc::clone(&d.queued_bytes);
        d.finish().unwrap();
        assert_eq!(m.snapshot().events_emitted, 1);
        assert_eq!(m.snapshot().events_dropped, 0);
        assert_eq!(queued.load(Ordering::Relaxed), 0);
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
