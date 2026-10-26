//! Threshold rules: one event when a group of matches reaches a count
//! within a window, instead of one event per matching line.
//!
//! Each threshold rule has a table of groups (keyed by a captured value, the
//! file, or nothing), bounded by `limits.threshold_max_groups`. A group
//! counts matches, or distinct values of a capture, in a fixed window that
//! starts at its first match. Reaching the count fires one event, resets
//! the group and silences it for the rule's cooldown.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::warn;

use crate::config::{GroupBy, Threshold, ThresholdWindow};
use crate::metrics::{self, Metrics};

/// Minimum time between eviction warnings.
const WARN_INTERVAL: Duration = Duration::from_secs(10);

/// A threshold that was reached: what the event reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    /// The captured value the matches were grouped by; `None` for
    /// `group_by = "file"` (the event names the file) or no grouping.
    pub group: Option<Box<[u8]>>,
    pub count: u32,
}

#[derive(Debug)]
struct Group {
    start: Instant,
    last_seen: Instant,
    count: u32,
    previous_count: u32,
    previous_distinct: HashSet<u64>,
    /// Keyed hashes of the distinct values seen in this window. A collision
    /// can only undercount; the per-process keys make one impractical to
    /// craft.
    distinct: HashSet<u64>,
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
        let (key, reported): (&[u8], bool) = match t.group_by {
            GroupBy::All => (b"", false),
            GroupBy::File => (file.as_os_str().as_bytes(), false),
            // A match where the group did not participate is not counted.
            GroupBy::Capture(i) => (field(i)?, true),
        };
        let distinct = match t.distinct {
            Some(i) => Some(self.hasher.hash_one(field(i)?)),
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
            previous_count: 0,
            previous_distinct: HashSet::new(),
            distinct: HashSet::new(),
            silent_until: None,
        });
        g.last_seen = now;
        if g.silent_until.is_some_and(|until| now < until) {
            return None;
        }
        let elapsed = now.saturating_duration_since(g.start);
        if elapsed >= t.window {
            if t.window_mode == ThresholdWindow::Sliding && elapsed < t.window * 2 {
                g.previous_count = g.count;
                g.previous_distinct = std::mem::take(&mut g.distinct);
            } else {
                g.previous_count = 0;
                g.previous_distinct.clear();
                g.distinct.clear();
            }
            g.start = now;
            g.count = 0;
        }
        match distinct {
            Some(hash) => {
                g.distinct.insert(hash);
                g.count = g.distinct.len() as u32;
            }
            None => g.count += 1,
        }
        let count = if t.window_mode == ThresholdWindow::Sliding {
            if t.distinct.is_some() {
                g.distinct.union(&g.previous_distinct).count() as u32
            } else {
                // Two-bucket approximation. Use integer math and round up to
                // avoid losing a marginal match at a bucket boundary.
                let remaining = t.window.saturating_sub(
                    now.saturating_duration_since(g.start)
                ).as_nanos();
                let total = t.window.as_nanos();
                let weighted = u128::from(g.previous_count) * remaining;
                g.count.saturating_add(weighted.div_ceil(total) as u32)
            }
        } else {
            g.count
        };
        if count < t.count {
            return None;
        }
        g.count = 0;
        g.previous_count = 0;
        g.distinct.clear();
        g.previous_distinct.clear();
        g.start = now;
        g.silent_until = Some(now + t.cooldown);
        Some(Fired {
            group: reported.then(|| key.into()),
            count,
        })
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
        now.saturating_duration_since(g.start) >= t.window
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
            distinct,
            count,
            window: Duration::from_secs(10),
            window_mode: ThresholdWindow::Fixed,
            cooldown: Duration::from_secs(60),
        }
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
    fn distinct_counts_values_not_matches() {
        let m = Arc::new(Metrics::default());
        let (mut th, t0) = (Thresholds::new(1, 100, Arc::clone(&m)), Instant::now());
        let t = threshold(GroupBy::Capture(1), Some(2), 3);
        let mut obs = |dpt| th.observe(0, "r", &t, Path::new("a"), &f("a", dpt), t0);
        for _ in 0..100 {
            assert_eq!(obs("22"), None, "same port again and again");
        }
        assert_eq!(obs("23"), None);
        assert_eq!(obs("24").map(|f| f.count), Some(3));
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
    fn sliding_counts_across_bucket_boundary() {
        let m = Arc::new(Metrics::default());
        let (mut fixed, mut sliding) = (
            Thresholds::new(1, 100, Arc::clone(&m)),
            Thresholds::new(1, 100, m),
        );
        let t0 = Instant::now();
        let mut config = threshold(GroupBy::All, None, 10);
        // A fixed window started at zero discards the nine early matches.
        for _ in 0..9 {
            assert!(fixed.observe(0, "r", &config, Path::new("a"), &[], secs(t0, 0)).is_none());
        }
        assert!(fixed.observe(0, "r", &config, Path::new("a"), &[], secs(t0, 10)).is_none());
        config.window_mode = ThresholdWindow::Sliding;
        for _ in 0..9 {
            assert!(sliding.observe(0, "r", &config, Path::new("a"), &[], secs(t0, 0)).is_none());
        }
        assert!(sliding.observe(0, "r", &config, Path::new("a"), &[], secs(t0, 10)).is_some());
    }

    #[test]
    fn sliding_distinct_counts_union_of_adjacent_buckets() {
        let m = Arc::new(Metrics::default());
        let mut th = Thresholds::new(1, 100, m);
        let t0 = Instant::now();
        let mut config = threshold(GroupBy::Capture(1), Some(2), 3);
        config.window_mode = ThresholdWindow::Sliding;
        assert!(th.observe(0, "r", &config, Path::new("a"), &f("a", "22"), t0).is_none());
        assert!(th.observe(0, "r", &config, Path::new("a"), &f("a", "23"), t0).is_none());
        assert!(th.observe(0, "r", &config, Path::new("a"), &f("a", "22"), secs(t0, 10)).is_none());
        assert!(th.observe(0, "r", &config, Path::new("a"), &f("a", "24"), secs(t0, 10)).is_some());
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
