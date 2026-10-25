//! Aggregation of detection events into one summary per rule and window.
//!
//! Everything here is pure: no I/O and no clock. The caller passes event
//! times and the current time, which keeps window and retry behaviour
//! testable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::event::{Severity, format_rfc3339_secs, parse_rfc3339};

/// Sources tracked per summary. Beyond this, the least frequent tracked
/// source is replaced (the space-saving algorithm): every source with more
/// than `count / MAX_TRACKED_SOURCES` matches is still listed, but counts
/// may be overestimated.
pub const MAX_TRACKED_SOURCES: usize = 32;
/// Sources listed in a notification.
pub const TOP_SOURCES: usize = 5;
/// Longest delay between delivery attempts of one summary.
pub const MAX_RETRY_DELAY_SECS: u64 = 300;

const MAX_RULE_BYTES: usize = 64;
const MAX_HOST_BYTES: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 160;
const MAX_SOURCE_BYTES: usize = 128;

/// One detection event, reduced to what a summary may contain. Never holds
/// the log line or any capture other than the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Event time, seconds since the epoch.
    pub time: u64,
    pub rule: String,
    pub host: String,
    pub severity: Severity,
    pub description: String,
    pub source: Option<String>,
}

/// Why a journal message was not turned into a [`Detection`].
#[derive(Debug, PartialEq, Eq)]
pub enum NotAnEvent {
    /// Not a logwizz JSON event (for example a diagnostic line).
    Other,
    /// A logwizz event with neither a valid `ts` nor a journal timestamp.
    NoTime,
}

#[derive(Deserialize)]
struct WireEvent {
    v: u32,
    #[serde(default)]
    ts: Option<String>,
    rule: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    fields: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    threshold: Option<WireThreshold>,
}

#[derive(Deserialize)]
struct WireThreshold {
    #[serde(default)]
    group: Option<String>,
}

impl Detection {
    /// Parses a logwizz JSON event. `journal_time` (the entry's
    /// `__REALTIME_TIMESTAMP`, in seconds) is used when `ts` is missing or
    /// invalid; the second value is then `true`.
    pub fn parse(message: &str, journal_time: Option<u64>) -> Result<(Self, bool), NotAnEvent> {
        if !message.starts_with('{') {
            return Err(NotAnEvent::Other);
        }
        let ev: WireEvent = serde_json::from_str(message).map_err(|_| NotAnEvent::Other)?;
        let rule = clean(&ev.rule, MAX_RULE_BYTES);
        if ev.v != 1 || rule.trim().is_empty() {
            return Err(NotAnEvent::Other);
        }
        let (time, fallback) = match ev.ts.as_deref().and_then(parse_rfc3339) {
            Some(t) => (t, false),
            None => (journal_time.ok_or(NotAnEvent::NoTime)?, true),
        };
        let field = |name: &str| {
            ev.fields
                .as_ref()
                .and_then(|f| f.get(name))
                .and_then(Value::as_str)
        };
        let source = field("src")
            .or_else(|| field("source"))
            .or(ev.threshold.as_ref().and_then(|t| t.group.as_deref()))
            .map(|s| clean(s, MAX_SOURCE_BYTES))
            .filter(|s| !s.is_empty());
        Ok((
            Detection {
                time,
                rule,
                host: clean(ev.host.as_deref().unwrap_or("unknown"), MAX_HOST_BYTES),
                severity: ev
                    .severity
                    .as_deref()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(Severity::Notice),
                description: clean(
                    ev.description.as_deref().unwrap_or(""),
                    MAX_DESCRIPTION_BYTES,
                ),
                source,
            },
            fallback,
        ))
    }
}

/// Replaces control characters with spaces and cuts `s` to at most `max`
/// bytes on a character boundary, so values are safe in headers and
/// single-line message fields.
pub fn clean(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    for c in s.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCount {
    pub source: String,
    pub count: u64,
}

/// Matches of one rule within one window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// Window start, seconds since the epoch; a multiple of `window_secs`.
    pub bucket: u64,
    pub window_secs: u64,
    pub rule: String,
    /// The host of every match, or `multiple`.
    pub host: String,
    pub severity: Severity,
    pub description: String,
    pub count: u64,
    /// Matches that had no source.
    #[serde(default)]
    pub unsourced: u64,
    /// The most frequent sources (see [`MAX_TRACKED_SOURCES`]).
    #[serde(default)]
    pub sources: Vec<SourceCount>,
    /// More distinct sources were seen than could be tracked.
    #[serde(default)]
    pub sources_overflowed: bool,
    #[serde(default)]
    pub retry_count: u32,
    /// No delivery attempt before this time (seconds since the epoch).
    #[serde(default)]
    pub retry_after: u64,
}

impl Summary {
    fn new(d: &Detection, bucket: u64, window_secs: u64) -> Self {
        Summary {
            bucket,
            window_secs,
            rule: d.rule.clone(),
            host: d.host.clone(),
            severity: d.severity,
            description: d.description.clone(),
            count: 0,
            unsourced: 0,
            sources: Vec::new(),
            sources_overflowed: false,
            retry_count: 0,
            retry_after: 0,
        }
    }

    fn add(&mut self, d: &Detection) {
        self.count += 1;
        if self.host != d.host {
            self.host = "multiple".into();
        }
        let Some(src) = &d.source else {
            self.unsourced += 1;
            return;
        };
        if let Some(s) = self.sources.iter_mut().find(|s| &s.source == src) {
            s.count += 1;
        } else if self.sources.len() < MAX_TRACKED_SOURCES {
            self.sources.push(SourceCount {
                source: src.clone(),
                count: 1,
            });
        } else {
            self.sources_overflowed = true;
            let min = self
                .sources
                .iter_mut()
                .min_by_key(|s| s.count)
                .expect("sources is full, so not empty");
            min.source = src.clone();
            min.count += 1;
        }
    }

    pub fn window_end(&self) -> u64 {
        self.bucket + self.window_secs
    }

    /// The source of every match, if they all had the same one.
    pub fn single_source(&self) -> Option<&str> {
        match self.sources.as_slice() {
            [only] if self.unsourced == 0 && !self.sources_overflowed => Some(&only.source),
            _ => None,
        }
    }

    /// `source` as in the v1 payload: the single source, `multiple`, or
    /// empty if no match had a source.
    pub fn source_field(&self) -> &str {
        match self.single_source() {
            Some(s) => s,
            None if self.sources.is_empty() && !self.sources_overflowed => "",
            None => "multiple",
        }
    }

    /// The most frequent sources, most frequent first.
    pub fn top_sources(&self) -> Vec<&SourceCount> {
        let mut top: Vec<_> = self.sources.iter().collect();
        top.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.source.cmp(&b.source)));
        top.truncate(TOP_SOURCES);
        top
    }

    /// The webhook payload, schema `logwizz.notification/v1`.
    pub fn to_json(&self, partial: bool) -> Value {
        json!({
            "schema": "logwizz.notification/v1",
            "host": self.host,
            "rule": self.rule,
            "description": self.description,
            "severity": self.severity,
            "count": self.count,
            "window_start": format_rfc3339_secs(self.bucket),
            "window_end": format_rfc3339_secs(self.window_end()),
            "source": self.source_field(),
            "sources": self.top_sources(),
            "distinct_sources": self.sources.len(),
            "sources_approximate": self.sources_overflowed,
            "partial": partial,
        })
    }

    /// The plain-text message for Telegram and ntfy.
    pub fn to_text(&self, partial: bool) -> String {
        let mut s = format!("logwizz alert - {}\nRule: {}", self.host, self.rule);
        if !self.description.is_empty() {
            s.push_str("\nDescription: ");
            s.push_str(&self.description);
        }
        s.push_str(&format!(
            "\nSeverity: {}\nMatches: {}\nWindow: {} - {}",
            self.severity,
            self.count,
            format_rfc3339_secs(self.bucket),
            format_rfc3339_secs(self.window_end()),
        ));
        if let Some(src) = self.single_source() {
            s.push_str("\nSource: ");
            s.push_str(src);
        } else if !self.sources.is_empty() {
            let top = self.top_sources();
            let listed: Vec<String> = top
                .iter()
                .map(|t| format!("{} ({})", t.source, t.count))
                .collect();
            s.push_str("\nSources: ");
            s.push_str(&listed.join(", "));
            if self.sources_overflowed {
                s.push_str(" and more (approximate counts)");
            } else if self.sources.len() > top.len() {
                s.push_str(&format!(" and {} more", self.sources.len() - top.len()));
            }
        }
        if partial {
            s.push_str("\nPartial window (shutdown or delayed delivery)");
        }
        s
    }
}

/// Identifies a summary: window start, window length, rule.
pub type Key = (u64, u64, String);

/// Whether [`Aggregator::record`] took the detection.
#[derive(Debug, PartialEq, Eq)]
pub enum Recorded {
    Yes,
    /// It needs a new summary and `max_pending` are pending already.
    Full,
}

/// The pending summaries.
#[derive(Debug)]
pub struct Aggregator {
    window_secs: u64,
    max_pending: usize,
    summaries: BTreeMap<Key, Summary>,
    /// Newest window an event has been seen in. Older windows are complete
    /// even if the clock says otherwise (a backlog being read, or skew).
    latest_bucket: u64,
}

impl Aggregator {
    /// `saved` are summaries restored from the state file.
    pub fn new(window_secs: u64, max_pending: usize, saved: Vec<Summary>) -> Self {
        let mut a = Aggregator {
            window_secs,
            max_pending,
            summaries: BTreeMap::new(),
            latest_bucket: 0,
        };
        for s in saved {
            a.latest_bucket = a.latest_bucket.max(s.bucket);
            a.summaries
                .insert((s.bucket, s.window_secs, s.rule.clone()), s);
        }
        a
    }

    pub fn record(&mut self, d: &Detection) -> Recorded {
        let bucket = d.time / self.window_secs * self.window_secs;
        let key = (bucket, self.window_secs, d.rule.clone());
        if !self.summaries.contains_key(&key) && self.summaries.len() >= self.max_pending {
            return Recorded::Full;
        }
        self.latest_bucket = self.latest_bucket.max(bucket);
        self.summaries
            .entry(key)
            .or_insert_with(|| Summary::new(d, bucket, self.window_secs))
            .add(d);
        Recorded::Yes
    }

    /// Summaries to send now: a later window has started, or, with
    /// `by_clock`, the window is over by the clock. Either way only once
    /// their retry delay is over.
    ///
    /// `by_clock` is for when the journal has gone quiet: while a backlog
    /// is being read, the clock says nothing about whether a window's
    /// events have all been seen.
    pub fn due(&self, now: u64, by_clock: bool) -> Vec<Key> {
        self.summaries
            .iter()
            .filter(|(_, s)| {
                (s.bucket < self.latest_bucket || (by_clock && s.window_end() <= now))
                    && s.retry_after <= now
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn keys(&self) -> Vec<Key> {
        self.summaries.keys().cloned().collect()
    }

    pub fn get(&self, key: &Key) -> Option<&Summary> {
        self.summaries.get(key)
    }

    /// A summary was delivered.
    pub fn remove(&mut self, key: &Key) {
        self.summaries.remove(key);
    }

    /// A delivery attempt failed: back off exponentially, from 2 seconds up
    /// to [`MAX_RETRY_DELAY_SECS`]. Returns the delay.
    pub fn failed(&mut self, key: &Key, now: u64) -> u64 {
        let Some(s) = self.summaries.get_mut(key) else {
            return 0;
        };
        let delay = 2u64
            .checked_shl(s.retry_count.min(16))
            .unwrap_or(u64::MAX)
            .min(MAX_RETRY_DELAY_SECS);
        s.retry_count = s.retry_count.saturating_add(1);
        s.retry_after = now + delay;
        delay
    }

    pub fn len(&self) -> usize {
        self.summaries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.summaries.is_empty()
    }

    pub fn summaries(&self) -> impl Iterator<Item = &Summary> {
        self.summaries.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(time: u64, rule: &str, source: Option<&str>) -> Detection {
        Detection {
            time,
            rule: rule.into(),
            host: "web1".into(),
            severity: Severity::Warning,
            description: "Failed SSH authentication".into(),
            source: source.map(String::from),
        }
    }

    #[test]
    fn parses_events_without_the_log_line() {
        let msg = r#"{"v":1,"ts":"2026-10-25T12:40:07.5Z","host":"web1","rule":"ssh",
            "description":"d\nx","severity":"warning","line":"RAW SECRET",
            "fields":{"src":"203.0.113.8","user":"root"}}"#;
        let (d, fallback) = Detection::parse(msg, None).unwrap();
        assert!(!fallback);
        assert_eq!(d.time, 1_792_932_007);
        assert_eq!(d.source.as_deref(), Some("203.0.113.8"));
        assert_eq!(d.description, "d x");
        assert_eq!(d.severity, Severity::Warning);
        assert!(!format!("{d:?}").contains("RAW SECRET"));

        // Threshold group as source; unknown severity and missing host defaulted.
        let msg = r#"{"v":1,"ts":"2026-10-25T12:40:07Z","rule":"scan","severity":"bogus",
            "threshold":{"group":"192.0.2.7","count":20,"window_secs":10}}"#;
        let (d, _) = Detection::parse(msg, None).unwrap();
        assert_eq!(
            (d.source.as_deref(), d.severity, d.host.as_str()),
            (Some("192.0.2.7"), Severity::Notice, "unknown")
        );

        // A bad timestamp falls back to the journal's time, or is refused.
        let msg = r#"{"v":1,"ts":"not-a-timestamp","rule":"r"}"#;
        assert_eq!(Detection::parse(msg, Some(42)).unwrap().0.time, 42);
        assert!(Detection::parse(msg, Some(42)).unwrap().1);
        assert_eq!(Detection::parse(msg, None), Err(NotAnEvent::NoTime));

        for other in [
            "logwizz started",
            "{not json",
            r#"{"v":2,"ts":"2026-10-25T12:40:07Z","rule":"r"}"#,
            r#"{"v":1,"ts":"2026-10-25T12:40:07Z","rule":" "}"#,
            r#"{"v":1,"ts":"2026-10-25T12:40:07Z"}"#,
        ] {
            assert_eq!(
                Detection::parse(other, Some(1)),
                Err(NotAnEvent::Other),
                "{other}"
            );
        }
    }

    #[test]
    fn clean_bounds_and_strips_controls() {
        assert_eq!(clean("a\r\nb\u{1b}[31m", 64), "a  b [31m");
        assert_eq!(clean("ééé", 5), "éé");
    }

    #[test]
    fn groups_by_rule_and_window() {
        let mut a = Aggregator::new(60, 100, Vec::new());
        for (t, rule) in [(120, "a"), (179, "a"), (130, "b"), (180, "a")] {
            assert_eq!(a.record(&det(t, rule, None)), Recorded::Yes);
        }
        assert_eq!(a.len(), 3);
        let counts: Vec<_> = a
            .summaries()
            .map(|s| (s.bucket, s.rule.as_str(), s.count))
            .collect();
        assert_eq!(counts, [(120, "a", 2), (120, "b", 1), (180, "a", 1)]);
    }

    #[test]
    fn windows_are_due_when_over_or_superseded() {
        let mut a = Aggregator::new(60, 100, Vec::new());
        a.record(&det(130, "a", None));
        assert!(a.due(150, true).is_empty(), "window still open");
        assert_eq!(a.due(180, true).len(), 1, "closed by the clock");
        assert!(a.due(180, false).is_empty(), "the clock is not consulted");
        // A later event closes earlier windows even if the clock lags.
        a.record(&det(200, "b", None));
        assert_eq!(a.due(150, false), [(120, 60, "a".to_string())]);
    }

    #[test]
    fn failed_delivery_backs_off_and_is_capped() {
        let mut a = Aggregator::new(60, 100, Vec::new());
        a.record(&det(0, "a", None));
        let k = a.keys().remove(0);
        let delays: Vec<_> = (0..12).map(|_| a.failed(&k, 1000)).collect();
        assert_eq!(&delays[..5], [2, 4, 8, 16, 32]);
        assert!(delays.iter().all(|&d| d <= MAX_RETRY_DELAY_SECS));
        assert_eq!(*delays.last().unwrap(), MAX_RETRY_DELAY_SECS);
        assert!(a.due(1299, true).is_empty());
        assert_eq!(a.due(1300, true).len(), 1);
    }

    #[test]
    fn pending_summaries_are_bounded() {
        let mut a = Aggregator::new(60, 2, Vec::new());
        assert_eq!(a.record(&det(0, "a", None)), Recorded::Yes);
        assert_eq!(a.record(&det(0, "b", None)), Recorded::Yes);
        assert_eq!(a.record(&det(0, "c", None)), Recorded::Full);
        // Existing summaries still count.
        assert_eq!(a.record(&det(1, "a", None)), Recorded::Yes);
        a.remove(&(0, 60, "b".to_string()));
        assert_eq!(a.record(&det(0, "c", None)), Recorded::Yes);
    }

    #[test]
    fn single_and_multiple_sources() {
        let mut s = Summary::new(&det(0, "a", None), 0, 60);
        s.add(&det(0, "a", Some("192.0.2.1")));
        s.add(&det(0, "a", Some("192.0.2.1")));
        assert_eq!(s.single_source(), Some("192.0.2.1"));
        assert_eq!(s.source_field(), "192.0.2.1");
        assert!(s.to_text(false).contains("\nSource: 192.0.2.1"));

        s.add(&det(0, "a", None));
        assert_eq!(s.source_field(), "multiple", "a match without a source");

        let mut none = Summary::new(&det(0, "a", None), 0, 60);
        none.add(&det(0, "a", None));
        assert_eq!(none.source_field(), "");
        assert!(!none.to_text(false).contains("Source"));
    }

    #[test]
    fn top_sources_are_listed_by_count() {
        let mut s = Summary::new(&det(0, "a", None), 0, 60);
        for (src, n) in [
            ("a", 1),
            ("b", 30),
            ("c", 7),
            ("d", 2),
            ("e", 2),
            ("f", 1),
            ("g", 5),
        ] {
            for _ in 0..n {
                s.add(&det(0, "a", Some(src)));
            }
        }
        let top: Vec<_> = s
            .top_sources()
            .iter()
            .map(|t| (t.source.as_str(), t.count))
            .collect();
        assert_eq!(top, [("b", 30), ("c", 7), ("g", 5), ("d", 2), ("e", 2)]);
        let text = s.to_text(false);
        assert!(
            text.contains("\nSources: b (30), c (7), g (5), d (2), e (2) and 2 more"),
            "{text}"
        );
        let v = s.to_json(false);
        assert_eq!(v["source"], "multiple");
        assert_eq!(v["distinct_sources"], 7);
        assert_eq!(v["sources"][0], json!({"source": "b", "count": 30}));
        assert_eq!(v["sources"].as_array().unwrap().len(), TOP_SOURCES);
        assert_eq!(v["sources_approximate"], false);
    }

    #[test]
    fn heavy_source_survives_many_one_off_sources() {
        let mut s = Summary::new(&det(0, "a", None), 0, 60);
        for i in 0..1000 {
            s.add(&det(0, "a", Some(&format!("10.0.{}.{}", i / 256, i % 256))));
            if i % 4 == 0 {
                s.add(&det(0, "a", Some("203.0.113.66")));
            }
        }
        assert_eq!(s.sources.len(), MAX_TRACKED_SOURCES);
        assert!(s.sources_overflowed);
        assert_eq!(s.top_sources()[0].source, "203.0.113.66");
        assert!(s.to_text(false).contains("and more (approximate counts)"));
        assert_eq!(s.to_json(false)["sources_approximate"], true);
    }

    #[test]
    fn payload_shape() {
        let mut s = Summary::new(&det(0, "ssh", None), 1_792_932_000, 60);
        s.add(&det(1_792_932_007, "ssh", Some("203.0.113.8")));
        let v = s.to_json(true);
        assert_eq!(
            v,
            json!({
                "schema": "logwizz.notification/v1",
                "host": "web1",
                "rule": "ssh",
                "description": "Failed SSH authentication",
                "severity": "warning",
                "count": 1,
                "window_start": "2026-10-25T12:40:00Z",
                "window_end": "2026-10-25T12:41:00Z",
                "source": "203.0.113.8",
                "sources": [{"source": "203.0.113.8", "count": 1}],
                "distinct_sources": 1,
                "sources_approximate": false,
                "partial": true,
            })
        );
        assert_eq!(
            s.to_text(true),
            "logwizz alert - web1\nRule: ssh\nDescription: Failed SSH authentication\n\
             Severity: warning\nMatches: 1\nWindow: 2026-10-25T12:40:00Z - 2026-10-25T12:41:00Z\n\
             Source: 203.0.113.8\nPartial window (shutdown or delayed delivery)"
        );
    }

    #[test]
    fn restored_summaries_keep_counting() {
        let mut a = Aggregator::new(60, 10, Vec::new());
        a.record(&det(0, "a", Some("x")));
        let saved: Vec<Summary> = a.summaries().cloned().collect();
        let json = serde_json::to_string(&saved).unwrap();
        let mut b = Aggregator::new(60, 10, serde_json::from_str(&json).unwrap());
        b.record(&det(5, "a", Some("x")));
        assert_eq!(b.len(), 1);
        assert_eq!(b.summaries().next().unwrap().count, 2);
    }
}
