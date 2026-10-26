//! Threshold rules: one event when a group of matches reaches a count
//! within a window, instead of one event per matching line.
//!
//! Each threshold rule has a table of groups (keyed by a captured value, the
//! file, or nothing), bounded by `limits.threshold_max_groups`. A group
//! counts matches, or distinct values of a capture, in a fixed window that
//! starts at its first match. Reaching the count fires one event, resets
//! the group and silences it for the rule's cooldown.
//!
//! A sliding window keeps the previous fixed window's count too and adds
//! the share of it that still lies within `window` of now, assuming its
//! matches were spread evenly (the usual two-bucket rate estimate). A burst
//! that straddles two fixed windows is then counted as one.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::warn;

use crate::config::{GroupBy, Threshold, WindowType};
use crate::event::excerpt;
use crate::metrics::{self, Metrics};

/// Minimum time between eviction warnings.
const WARN_INTERVAL: Duration = Duration::from_secs(10);
/// Distinct values a group keeps as a sample for its event.
pub const SAMPLE_VALUES: usize = 8;
/// Sampled values are cut to this many bytes.
pub const SAMPLE_VALUE_BYTES: usize = 32;

/// A threshold that was reached: what the event reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    /// The captured value the matches were grouped by; `None` for
    /// `group_by = "file"` (the event names the file) or no grouping.
    pub group: Option<Box<[u8]>>,
    pub count: u32,
    /// `distinct` rules: the first distinct values seen, at most
    /// [`SAMPLE_VALUES`], each cut to [`SAMPLE_VALUE_BYTES`].
    pub sample: Vec<Box<[u8]>>,
}

#[derive(Debug)]
struct Group {
    start: Instant,
    last_seen: Instant,
    count: u32,
    /// Keyed hashes of the distinct values seen in this window. A collision
    /// can only undercount; the per-process keys make one impractical to
    /// craft.
    distinct: HashSet<u64>,
    /// Sliding windows: matches (or distinct values not seen again since)
    /// in the window before `start`, and those values.
    prev_count: u32,
    prev_distinct: HashSet<u64>,
    /// See [`Fired::sample`].
    sample: Vec<Box<[u8]>>,
    silent_until: Option<Instant>,
}

/// Group table of one threshold rule.
#[derive(Debug, Default)]
struct Table {
    groups: HashMap<Box<[u8]>, Group>,
}

#[derive(Debug)]
pub struct Thresholds {
    tables: Vec<Table>,
    max_groups: usize,
    hasher: RandomState,
    evictions_since_warning: u64,
    last_warning: Option<Instant>,
    metrics: Arc<Metrics>,
}

impl Thresholds {
    pub fn new(rules: usize, max_groups: usize, metrics: Arc<Metrics>) -> Self {
        Thresholds {
            tables: (0..rules).map(|_| Table::default()).collect(),
            max_groups,
            hasher: RandomState::new(),
            evictions_since_warning: 0,
            last_warning: None,
            metrics,
        }
    }

    /// Applies a reloaded rule list; `kept[new] = Some(old)` for unchanged
    /// rules, whose groups carry over. Groups of changed rules are dropped.
    pub fn reconfigure(&mut self, max_groups: usize, kept: &[Option<usize>]) {
        let mut old: Vec<Option<Table>> = std::mem::take(&mut self.tables)
            .into_iter()
            .map(Some)
            .collect();
        self.tables = kept
            .iter()
            .map(|k| k.and_then(|i| old.get_mut(i)?.take()).unwrap_or_default())
            .collect();
        self.max_groups = max_groups;
    }

    /// Counts one match of `rule`. `fields` are the match's captured values
    /// as (group index, value). Returns what to report if this match makes
    /// the group reach its threshold, `None` if it is absorbed.
    pub fn observe(
        &mut self,
        rule: usize,
        rule_id: &str,
        t: &Threshold,
        file: &Path,
        fields: &[(usize, Box<[u8]>)],
        now: Instant,
    ) -> Option<Fired> {
        let field = |i: usize| fields.iter().find(|(g, _)| *g == i).map(|(_, v)| &**v);
        let net;
        let (key, reported): (&[u8], bool) = match t.group_by {
            GroupBy::All => (b"", false),
            GroupBy::File => (file.as_os_str().as_bytes(), false),
            // A match where the group did not participate is not counted.
            GroupBy::Capture(i) => {
                let value = field(i)?;
                // A value that is not an address is its own group.
                net = t.group_prefix.and_then(|p| p.network(value));
                (net.as_deref().map_or(value, str::as_bytes), true)
            }
        };
        let distinct = match t.distinct {
            Some(i) => {
                let value = field(i)?;
                Some((self.hasher.hash_one(value), value))
            }
            None => None,
        };
        let table = &mut self.tables[rule];
        if !table.groups.contains_key(key) && table.groups.len() >= self.max_groups {
            let evicted = evict(table, t, now);
            metrics::add(&self.metrics.threshold_evictions, evicted);
            self.evictions_since_warning += evicted;
            if self
                .last_warning
                .is_none_or(|w| now.saturating_duration_since(w) >= WARN_INTERVAL)
            {
                warn!(
                    rule = rule_id,
                    evicted = self.evictions_since_warning,
                    max_groups = self.max_groups,
                    "threshold group table full; evicted the least recently seen groups"
                );
                self.evictions_since_warning = 0;
                self.last_warning = Some(now);
            }
        }
        let g = table.groups.entry(key.into()).or_insert_with(|| Group {
            start: now,
            last_seen: now,
            count: 0,
            distinct: HashSet::new(),
            prev_count: 0,
            prev_distinct: HashSet::new(),
            sample: Vec::new(),
            silent_until: None,
        });
        g.last_seen = now;
        if g.silent_until.is_some_and(|until| now < until) {
            return None;
        }
        let elapsed = now.saturating_duration_since(g.start);
        if elapsed >= span(t) {
            g.start = now;
            g.count = 0;
            g.distinct.clear();
            g.prev_count = 0;
            g.prev_distinct.clear();
            g.sample.clear();
        } else if elapsed >= t.window {
            // Sliding only: the current window becomes the previous one.
            g.start += t.window;
            g.prev_count = std::mem::take(&mut g.count);
            g.prev_distinct = std::mem::take(&mut g.distinct);
        }
        match distinct {
            Some((hash, value)) => {
                if g.distinct.insert(hash) {
                    if g.prev_distinct.contains(&hash) {
                        // Already counted in the previous window's share.
                        g.prev_count -= 1;
                    } else if g.sample.len() < SAMPLE_VALUES {
                        g.sample
                            .push(excerpt(value, Some(SAMPLE_VALUE_BYTES)).0.into());
                    }
                }
                g.count = g.distinct.len() as u32;
            }
            None => g.count += 1,
        }
        // The part of the previous window still within `window` of now.
        let left = t
            .window
            .saturating_sub(now.saturating_duration_since(g.start));
        // Round up conservatively: integer truncation here can undercount a threshold at the boundary.
        let share = (u128::from(g.prev_count) * left.as_nanos()).div_ceil(t.window.as_nanos());
        let count = g.count + share as u32;
        if count < t.count {
            return None;
        }
        g.count = 0;
        g.distinct = HashSet::new();
        g.prev_count = 0;
        g.prev_distinct = HashSet::new();
        let sample = std::mem::take(&mut g.sample);
        g.start = now;
        g.silent_until = Some(now + t.cooldown);
        Some(Fired {
            group: reported.then(|| key.into()),
            count,
            sample,
        })
    }
}

/// How long after its `start` a group's counts still matter.
fn span(t: &Threshold) -> Duration {
    match t.window_type {
        WindowType::Fixed => t.window,
        WindowType::Sliding => t.window * 2,
    }
}

/// Makes room in a full table: drops every group whose window and cooldown
/// are over, or else the least recently seen eighth, so that a flood of new
/// keys costs amortised O(1) per key. Returns the number dropped.
fn evict(table: &mut Table, t: &Threshold, now: Instant) -> u64 {
    let before = table.groups.len();
    if before == 0 {
        return 0;
    }
    let idle = |g: &Group| {
        now.saturating_duration_since(g.start) >= span(t)
            && g.silent_until.is_none_or(|until| now >= until)
    };
    table.groups.retain(|_, g| !idle(g));
    if table.groups.len() == before {
        let mut seen: Vec<Instant> = table.groups.values().map(|g| g.last_seen).collect();
        let n = (seen.len() / 8).max(1);
        let (_, &mut cutoff, _) = seen.select_nth_unstable(n - 1);
        let mut left = n;
        table.groups.retain(|_, g| {
            if left > 0 && g.last_seen <= cutoff {
                left -= 1;
                false
            } else {
                true
            }
        });
    }
    (before - table.groups.len()) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn threshold(group_by: GroupBy, distinct: Option<usize>, count: u32) -> Threshold {
        Threshold {
            group_by,
            group_prefix: None,
            distinct,
            count,
            window: Duration::from_secs(10),
            window_type: WindowType::Fixed,
            cooldown: Duration::from_secs(60),
        }
    }

    fn sliding(distinct: Option<usize>, count: u32) -> Threshold {
        Threshold {
            window: Duration::from_secs(60),
            window_type: WindowType::Sliding,
            ..threshold(GroupBy::All, distinct, count)
        }
    }

    #[test]
    fn sliding_window_counts_a_burst_across_the_boundary() {
        let m = Arc::new(Metrics::default());
        let t0 = Instant::now();
        // 1 match at 0 s, 8 at 55–59 s, 8 at 60–63 s: 16 in under 10 s.
        let times: Vec<u64> = std::iter::once(0)
            .chain(55..59)
            .chain(55..59)
            .chain(60..64)
            .chain(60..64)
            .collect();
        let run = |t: &Threshold| {
            let mut th = Thresholds::new(1, 100, Arc::clone(&m));
            times.iter().position(|&s| {
                th.observe(0, "r", t, Path::new("a"), &[], secs(t0, s))
                    .is_some()
            })
        };
        let mut fixed = sliding(None, 10);
        fixed.window_type = WindowType::Fixed;
        assert_eq!(run(&fixed), None, "each fixed window holds fewer than 10");
        // At 60 s, 9 previous matches weigh in almost fully.
        assert_eq!(run(&sliding(None, 10)), Some(9));
    }

    #[test]
    fn sliding_window_rounds_previous_bucket_weight_up_at_threshold_boundary() {
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(1, 100, m), Instant::now());
        let mut t = sliding(None, 11);
        t.window = Duration::from_secs(10);
        for _ in 0..9 {
            assert_eq!(th.observe(0, "r", &t, Path::new("a"), &[], t0), None);
        }
        // At 10 s, 9 previous + 1 current remain below 11.
        assert_eq!(
            th.observe(0, "r", &t, Path::new("a"), &[], secs(t0, 10)),
            None
        );
        // At 11 s the previous bucket contributes 8.1 by the estimate.
        // Rounding down would miss 11; conservative rounding reaches it.
        assert_eq!(
            th.observe(0, "r", &t, Path::new("a"), &[], secs(t0, 11))
                .map(|f| f.count),
            Some(11)
        );
    }

    #[test]
    fn sliding_window_forgets_the_previous_window_gradually() {
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(1, 100, m), Instant::now());
        let t = sliding(None, 10);
        let mut obs = |s| th.observe(0, "r", &t, Path::new("a"), &[], secs(t0, s));
        for _ in 0..8 {
            assert_eq!(obs(0), None);
        }
        // At 90 s half of the previous window (4 of 8) still counts: 4 + 5.
        for _ in 0..5 {
            assert_eq!(obs(90), None);
        }
        assert_eq!(obs(90).map(|f| f.count), Some(10));
        // Two windows after the last start, nothing is left.
        for _ in 0..9 {
            assert_eq!(obs(300), None);
        }
    }

    #[test]
    fn sliding_distinct_counts_a_value_once_across_windows() {
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(1, 100, m), Instant::now());
        let t = sliding(Some(2), 4);
        let mut obs = |s, dpt| th.observe(0, "r", &t, Path::new("a"), &f("a", dpt), secs(t0, s));
        assert_eq!(obs(0, "1"), None);
        assert_eq!(obs(0, "2"), None);
        assert_eq!(obs(0, "3"), None);
        // Ports seen in the previous window again: still 3 distinct.
        assert_eq!(obs(60, "1"), None);
        assert_eq!(obs(60, "2"), None);
        assert_eq!(obs(60, "3"), None);
        let fired = obs(60, "4").unwrap();
        assert_eq!(fired.count, 4);
        // Values from the previous window stay in the sample, each once.
        let sample: Vec<&[u8]> = fired.sample.iter().map(|v| &**v).collect();
        assert_eq!(sample, [&b"1"[..], b"2", b"3", b"4"]);
    }

    fn f(src: &str, dpt: &str) -> Vec<(usize, Box<[u8]>)> {
        vec![(1, src.as_bytes().into()), (2, dpt.as_bytes().into())]
    }

    fn secs(t0: Instant, s: u64) -> Instant {
        t0 + Duration::from_secs(s)
    }

    #[test]
    fn fires_once_at_count_then_cools_down() {
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(1, 100, Arc::clone(&m)), Instant::now());
        let t = threshold(GroupBy::Capture(1), None, 3);
        let mut obs = |s, src| th.observe(0, "r", &t, Path::new("a"), &f(src, "22"), secs(t0, s));
        assert_eq!(obs(0, "a"), None);
        assert_eq!(obs(1, "a"), None);
        assert_eq!(obs(1, "b"), None, "other group");
        let fired = obs(2, "a").unwrap();
        assert_eq!((fired.group.as_deref(), fired.count), (Some(&b"a"[..]), 3));
        for s in 3..6 {
            assert_eq!(obs(s, "a"), None, "cooldown");
        }
        // After the cooldown, counting starts over.
        assert_eq!(obs(62, "a"), None);
        assert_eq!(obs(62, "a"), None);
        assert!(obs(63, "a").is_some());
    }

    #[test]
    fn group_prefix_counts_one_network_together() {
        use crate::config::GroupPrefix;
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(1, 100, m), Instant::now());
        let t = Threshold {
            group_prefix: Some(GroupPrefix { v4: 24, v6: 64 }),
            ..threshold(GroupBy::Capture(1), Some(2), 4)
        };
        let mut obs = |src, dpt| th.observe(0, "r", &t, Path::new("a"), &f(src, dpt), t0);
        // Four addresses of one /24, one port each.
        assert_eq!(obs("194.180.49.53", "22"), None);
        assert_eq!(obs("194.180.49.121", "23"), None);
        assert_eq!(obs("194.180.50.1", "24"), None, "another /24");
        assert_eq!(obs("194.180.49.123", "25"), None);
        let fired = obs("::ffff:194.180.49.127", "26").unwrap();
        assert_eq!(fired.group.as_deref(), Some(&b"194.180.49.0/24"[..]));
        assert_eq!(fired.count, 4);
        // IPv6 by /64; a value that is no address is its own group.
        for dpt in ["1", "2", "3"] {
            assert_eq!(obs("2001:db8:1:2::5", dpt), None);
        }
        let fired = obs("2001:db8:1:2:ffff::1", "4").unwrap();
        assert_eq!(fired.group.as_deref(), Some(&b"2001:db8:1:2::/64"[..]));
        for dpt in ["1", "2", "3"] {
            assert_eq!(obs("scanner.example", dpt), None);
        }
        let fired = obs("scanner.example", "4").unwrap();
        assert_eq!(fired.group.as_deref(), Some(&b"scanner.example"[..]));
    }

    #[test]
    fn distinct_counts_values_not_matches() {
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(1, 100, Arc::clone(&m)), Instant::now());
        let t = threshold(GroupBy::Capture(1), Some(2), 3);
        let mut obs = |dpt| th.observe(0, "r", &t, Path::new("a"), &f("a", dpt), t0);
        for _ in 0..100 {
            assert_eq!(obs("22"), None, "same port again and again");
        }
        assert_eq!(obs("23"), None);
        let fired = obs("24").unwrap();
        assert_eq!(fired.count, 3);
        let sample: Vec<&[u8]> = fired.sample.iter().map(|v| &**v).collect();
        assert_eq!(sample, [&b"22"[..], b"23", b"24"], "in order first seen");
        // The sample is capped in values and bytes.
        let long = "9".repeat(100);
        let mut th2 = Thresholds::new(1, 100, Arc::new(Metrics::default()));
        let t2 = threshold(GroupBy::Capture(1), Some(2), 20);
        let mut fired = None;
        for p in 0..20 {
            fired = th2.observe(
                0,
                "r",
                &t2,
                Path::new("a"),
                &f("a", &format!("{p}{long}")),
                t0,
            );
        }
        let sample = fired.unwrap().sample;
        assert_eq!(sample.len(), SAMPLE_VALUES);
        assert!(sample.iter().all(|v| v.len() == SAMPLE_VALUE_BYTES));
    }

    #[test]
    fn window_expiry_resets_the_count() {
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(1, 100, Arc::clone(&m)), Instant::now());
        let t = threshold(GroupBy::All, None, 2);
        let mut obs = |s| th.observe(0, "r", &t, Path::new("a"), &[], secs(t0, s));
        assert_eq!(obs(0), None);
        assert_eq!(obs(10), None, "first match of a new window");
        assert_eq!(obs(11).map(|f| (f.group, f.count)), Some((None, 2)));
    }

    #[test]
    fn file_grouping_and_missing_captures() {
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(1, 100, Arc::clone(&m)), Instant::now());
        let t = threshold(GroupBy::File, None, 2);
        assert_eq!(th.observe(0, "r", &t, Path::new("a"), &[], t0), None);
        assert_eq!(
            th.observe(0, "r", &t, Path::new("b"), &[], t0),
            None,
            "other file"
        );
        assert!(th.observe(0, "r", &t, Path::new("a"), &[], t0).is_some());
        // A match without the grouping capture is not counted.
        let t = threshold(GroupBy::Capture(5), None, 1);
        assert_eq!(
            th.observe(0, "r", &t, Path::new("a"), &f("a", "1"), t0),
            None
        );
    }

    #[test]
    fn full_table_evicts_and_keeps_tracking() {
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(1, 16, Arc::clone(&m)), Instant::now());
        let t = threshold(GroupBy::Capture(1), None, 2);
        let ms = |n: u64| t0 + Duration::from_millis(n);
        for i in 0..16 {
            th.observe(0, "r", &t, Path::new("a"), &f(&i.to_string(), "1"), ms(i));
        }
        // Full, nothing idle: the least recently seen eighth (2 groups) goes.
        assert_eq!(
            th.observe(0, "r", &t, Path::new("a"), &f("new", "1"), ms(16)),
            None
        );
        assert_eq!(m.snapshot().threshold_evictions, 2);
        assert_eq!(th.tables[0].groups.len(), 15);
        assert!(!th.tables[0].groups.contains_key(&b"0"[..]));
        assert!(!th.tables[0].groups.contains_key(&b"1"[..]));
        assert!(
            th.observe(0, "r", &t, Path::new("a"), &f("new", "1"), ms(17))
                .is_some()
        );
        th.observe(0, "r", &t, Path::new("a"), &f("x", "1"), ms(18));
        // Once their windows are over, all idle groups are dropped at once;
        // "new" is in its cooldown and stays.
        th.observe(0, "r", &t, Path::new("a"), &f("late", "1"), secs(t0, 30));
        assert_eq!(m.snapshot().threshold_evictions, 2 + 15);
        assert_eq!(th.tables[0].groups.len(), 2);
    }

    #[test]
    fn evicting_an_empty_table_is_a_no_op() {
        let t = threshold(GroupBy::All, None, 1);
        assert_eq!(evict(&mut Table::default(), &t, Instant::now()), 0);
    }

    #[test]
    fn reconfigure_keeps_unchanged_rules() {
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(2, 100, Arc::clone(&m)), Instant::now());
        let t = threshold(GroupBy::All, None, 2);
        th.observe(1, "r", &t, Path::new("a"), &[], t0);
        // Rule 1 moves to index 0, a new rule takes index 1.
        th.reconfigure(100, &[Some(1), None]);
        assert!(th.observe(0, "r", &t, Path::new("a"), &[], t0).is_some());
        assert_eq!(th.observe(1, "r", &t, Path::new("a"), &[], t0), None);
    }
}
