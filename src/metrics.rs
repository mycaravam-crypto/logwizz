//! Low-overhead operational counters.
//!
//! All counters are monotonic `AtomicU64`s updated with relaxed ordering;
//! they are diagnostics, not synchronisation. `files_monitored` is a gauge.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use crate::config::{Action, Rule};

macro_rules! counters {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        #[derive(Debug, Default)]
        pub struct Metrics {
            $($(#[$doc])* pub $name: AtomicU64,)*
        }

        /// A point-in-time copy of all counters.
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct Snapshot {
            $(pub $name: u64,)*
        }

        impl Metrics {
            pub fn snapshot(&self) -> Snapshot {
                Snapshot {
                    $($name: self.$name.load(Ordering::Relaxed),)*
                }
            }
        }

        impl fmt::Display for Snapshot {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut first = true;
                $(
                    if !first {
                        f.write_str(" ")?;
                    }
                    first = false;
                    write!(f, concat!(stringify!($name), "={}"), self.$name)?;
                )*
                let _ = first;
                Ok(())
            }
        }
    };
}

counters! {
    /// Gauge: files currently open for reading (excluding draining ones).
    files_monitored,
    bytes_read,
    lines_processed,
    /// Lines longer than `max_line_bytes`, emitted cut to that length.
    lines_truncated,
    /// Bytes beyond `max_line_bytes` that were not passed to the rules.
    bytes_skipped,
    /// Incomplete trailing lines emitted because their file was truncated,
    /// rotated or deleted before a newline arrived.
    partial_lines_flushed,
    /// Lines that matched an `ignore` rule.
    lines_ignored,
    rule_matches,
    /// Matches discarded by a rule's `exclude` values.
    matches_excluded,
    /// Matches discarded by a rule's `types`: a capture was not of its type.
    matches_mistyped,
    /// Matches of silence rules: the expected line appeared.
    silence_matches,
    /// Silences reported (each one is an event that no match produced).
    silences_reported,
    /// Matches of `after` rules with no recent event of a named rule for
    /// the same value.
    after_unmatched,
    /// Remembered values dropped because an `after` memory was full.
    after_evictions,
    /// Matches of threshold rules that did not reach their threshold, or
    /// fell into its cooldown.
    threshold_absorbed,
    /// Events produced by reached thresholds.
    threshold_fired,
    /// Threshold groups dropped because a rule's group table was full.
    threshold_evictions,
    events_emitted,
    /// Events dropped because the output queue was full (`on_full = "drop"`).
    events_dropped,
    events_rate_limited,
    events_deduplicated,
    output_errors,
    read_errors,
    notify_overflows,
    rotations,
    truncations,
    /// Successful writes of the offset state file.
    state_saves,
    /// Failed writes of the offset state file (retried later).
    state_save_errors,
    /// Files matching a glob that were not followed because the glob had
    /// reached `general.max_glob_files`. Each file is counted once while it
    /// stays refused (beyond `max_glob_files` refused files, on every
    /// directory listing).
    glob_matches_refused,
    /// Journal entries that could not be parsed or were too long.
    journal_entries_skipped,
    /// Times journalctl was started again after it exited or failed to start.
    journal_restarts,
    /// Configuration reloads applied (SIGHUP).
    config_reloads,
    /// Configuration reloads rejected; the running configuration was kept.
    config_reload_failures,
}

#[inline]
pub fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

#[inline]
pub fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn dec(counter: &AtomicU64) {
    counter.fetch_sub(1, Ordering::Relaxed);
}

/// The counters of one rule.
#[derive(Debug)]
pub struct RuleCounters {
    id: String,
    emits: bool,
    /// Lines the rule matched. For an `ignore` rule: lines it ended.
    pub matches: AtomicU64,
    /// Events before `[limits]`: matches that passed the rule's exclusions,
    /// sequence and threshold.
    pub events: AtomicU64,
}

/// Per-rule counters, in rule order: which rule is noisy, and which never
/// matches (a pattern that no longer fits the log format).
///
/// The monitor thread counts through its own handle on the current table
/// ([`RuleStats::table`]) without locking; the lock is only taken to log
/// the table and to replace it on a configuration reload.
#[derive(Debug)]
pub struct RuleStats(RwLock<Arc<[RuleCounters]>>);

impl RuleStats {
    pub fn new(rules: &[Rule]) -> Self {
        RuleStats(RwLock::new(Self::build(rules, &[], &[])))
    }

    fn build(rules: &[Rule], kept: &[Option<usize>], old: &[RuleCounters]) -> Arc<[RuleCounters]> {
        let carried = |i: usize, counter: fn(&RuleCounters) -> &AtomicU64| {
            let old = kept.get(i).copied().flatten().and_then(|k| old.get(k));
            AtomicU64::new(old.map_or(0, |c| counter(c).load(Ordering::Relaxed)))
        };
        rules
            .iter()
            .enumerate()
            .map(|(i, r)| RuleCounters {
                id: r.id.clone(),
                emits: r.action == Action::Emit,
                matches: carried(i, |c| &c.matches),
                events: carried(i, |c| &c.events),
            })
            .collect()
    }

    /// The current table, indexed like the rules it was built from.
    pub fn table(&self) -> Arc<[RuleCounters]> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Replaces the table after a reload and returns the new one. `kept[i]`
    /// is the old index of new rule `i` if its definition is unchanged;
    /// such rules keep their counts, the others start at zero.
    pub fn replace(&self, rules: &[Rule], kept: &[Option<usize>]) -> Arc<[RuleCounters]> {
        let mut table = self.0.write().unwrap_or_else(PoisonError::into_inner);
        *table = Self::build(rules, kept, &table);
        Arc::clone(&table)
    }
}

/// `id=matches/events` per rule; `id=matches/-` for an `ignore` rule.
impl fmt::Display for RuleStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.table().iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{}={}/", c.id, c.matches.load(Ordering::Relaxed))?;
            match c.emits {
                true => write!(f, "{}", c.events.load(Ordering::Relaxed))?,
                false => f.write_str("-")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_stats_display_and_reload() {
        let rule = |id: &str, extra: &str| {
            format!(
                "[[rules]]\nid = \"{id}\"\nmatch_type = \"literal\"\npattern = \"x\"\n{extra}\n"
            )
        };
        let parse = |rules: &str| {
            let text = format!("[[files]]\npath = \"/x\"\n{rules}");
            crate::config::parse(&text, std::path::Path::new("t"))
                .unwrap()
                .rules
        };
        let emit = "severity = \"info\"";
        let old = parse(&format!(
            "{}{}{}",
            rule("a", emit),
            rule("noise", "action = \"ignore\""),
            rule("b", emit)
        ));
        let stats = RuleStats::new(&old);
        let table = stats.table();
        add(&table[0].matches, 5);
        add(&table[0].events, 2);
        add(&table[1].matches, 7);
        add(&table[2].matches, 1);
        assert_eq!(stats.to_string(), "a=5/2 noise=7/- b=1/0");

        // `b` changed (new rule), `a` moved: counts follow the definition.
        let new = parse(&format!(
            "{}{}",
            rule("b", "severity = \"error\""),
            rule("a", emit)
        ));
        let table = stats.replace(&new, &[None, Some(0)]);
        assert_eq!(stats.to_string(), "b=0/0 a=5/2");
        inc(&table[0].matches);
        assert_eq!(stats.to_string(), "b=1/0 a=5/2");
    }

    #[test]
    fn snapshot_and_display() {
        let m = Metrics::default();
        add(&m.bytes_read, 10);
        inc(&m.lines_processed);
        inc(&m.files_monitored);
        dec(&m.files_monitored);
        let s = m.snapshot();
        assert_eq!(s.bytes_read, 10);
        assert_eq!(s.lines_processed, 1);
        assert_eq!(s.files_monitored, 0);
        let text = s.to_string();
        assert!(text.starts_with("files_monitored=0 bytes_read=10 lines_processed=1 "));
    }
}
