//! Sequence rules: a rule with `[rules.after]` counts a match only if one
//! of the rules it names emitted an event with the same capture value
//! shortly before.
//!
//! [`Recent`] remembers, for each (named rule, capture) pair that some
//! `after` refers to, when each value last appeared in an event of that
//! rule. Rules nobody refers to are not remembered. Each table holds at
//! most `limits.threshold_max_groups` values. Tables are keyed by rule id,
//! so they survive a reload for as long as some `after` still names them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{After, Rule};
use crate::metrics::{self, Metrics};

/// Values remembered for one capture of one rule.
#[derive(Debug, Default)]
struct Memory {
    field: String,
    /// Index of `field` in the remembered rule's pattern.
    group: usize,
    /// The longest `within` of the rules asking; older values are useless.
    keep: Duration,
    seen: HashMap<Box<[u8]>, Instant>,
}

#[derive(Debug)]
pub struct Recent {
    /// Remembered rule id -> one memory per field asked about.
    memories: HashMap<String, Vec<Memory>>,
    max_entries: usize,
    metrics: Arc<Metrics>,
}

impl Recent {
    pub fn new(rules: &[Rule], max_entries: usize, metrics: Arc<Metrics>) -> Self {
        let mut recent = Recent {
            memories: HashMap::new(),
            max_entries,
            metrics,
        };
        recent.reconfigure(rules, max_entries);
        recent
    }

    /// Remembers what the `after` tables of `rules` refer to, keeping the
    /// values already seen for (rule id, field) pairs that are still used.
    pub fn reconfigure(&mut self, rules: &[Rule], max_entries: usize) {
        let mut old = std::mem::take(&mut self.memories);
        for after in rules.iter().filter_map(|r| r.after.as_ref()) {
            for id in &after.rules {
                // Validation guarantees the rule exists and has the field.
                let Some(group) = rules
                    .iter()
                    .find(|r| &r.id == id)
                    .and_then(|r| r.matcher.group_index(&after.field))
                else {
                    continue;
                };
                let list = self.memories.entry(id.clone()).or_default();
                let m = match list.iter_mut().position(|m| m.field == after.field) {
                    Some(i) => &mut list[i],
                    None => {
                        let seen = old
                            .get_mut(id)
                            .and_then(|l| l.iter_mut().find(|m| m.field == after.field))
                            .map(|m| std::mem::take(&mut m.seen))
                            .unwrap_or_default();
                        list.push(Memory {
                            field: after.field.clone(),
                            seen,
                            ..Memory::default()
                        });
                        list.last_mut().unwrap()
                    }
                };
                m.group = group;
                m.keep = m.keep.max(after.within);
            }
        }
        self.max_entries = max_entries;
    }

    /// Notes that `rule` emitted an event with these captured values.
    pub fn record(&mut self, rule: &Rule, fields: &[(usize, Box<[u8]>)], now: Instant) {
        let Some(list) = self.memories.get_mut(&rule.id) else {
            return;
        };
        for m in list {
            let Some((_, value)) = fields.iter().find(|(g, _)| *g == m.group) else {
                continue;
            };
            if !m.seen.contains_key(value) && m.seen.len() >= self.max_entries {
                let evicted = evict(m, now);
                metrics::add(&self.metrics.after_evictions, evicted);
            }
            // Journal replay can deliver older entries after newer ones.
            // Keep the most recent event time for each source.
            let saved = m.seen.entry(value.clone()).or_insert(now);
            if now > *saved {
                *saved = now;
            }
        }
    }

    /// Whether one of `after.rules` emitted an event with `value` as its
    /// `after.field` within `after.within` before `now`.
    pub fn follows(&self, after: &After, value: &[u8], now: Instant) -> bool {
        after.rules.iter().any(|id| {
            self.memories
                .get(id)
                .and_then(|l| l.iter().find(|m| m.field == after.field))
                .and_then(|m| m.seen.get(value))
                .is_some_and(|&t| now >= t && now.duration_since(t) <= after.within)
        })
    }
}

/// Makes room in a full memory: drops every value older than `keep`, or
/// else the oldest eighth. Returns the number dropped.
fn evict(m: &mut Memory, now: Instant) -> u64 {
    let before = m.seen.len();
    let keep = m.keep;
    m.seen
        .retain(|_, t| now.saturating_duration_since(*t) <= keep);
    if m.seen.len() == before && before > 0 {
        let mut times: Vec<Instant> = m.seen.values().copied().collect();
        let n = (times.len() / 8).max(1);
        let (_, &mut cutoff, _) = times.select_nth_unstable(n - 1);
        let mut left = n;
        m.seen.retain(|_, t| {
            if left > 0 && *t <= cutoff {
                left -= 1;
                false
            } else {
                true
            }
        });
    }
    (before - m.seen.len()) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::path::Path;

    const RULES: &str = r#"
        [[files]]
        path = "/var/log/auth.log"

        [[rules]]
        id = "scan"
        match_type = "regex"
        pattern = 'scan (?P<src>\S+)'
        severity = "warning"

        [[rules]]
        id = "login"
        match_type = "regex"
        pattern = 'login (?P<src>\S+)'
        severity = "critical"
        [rules.after]
        rules = ["scan"]
        field = "src"
        within_secs = 60
    "#;

    fn rules(text: &str) -> Vec<Rule> {
        config::parse(text, Path::new("t.toml")).unwrap().rules
    }

    fn src(v: &str) -> Vec<(usize, Box<[u8]>)> {
        vec![(1, v.as_bytes().into())]
    }

    #[test]
    fn follows_only_the_same_value_within_the_window() {
        let rules = rules(RULES);
        let after = rules[1].after.as_ref().unwrap();
        let mut r = Recent::new(&rules, 100, Arc::new(Metrics::default()));
        let t0 = Instant::now();
        assert!(!r.follows(after, b"a", t0), "nothing seen yet");
        r.record(&rules[0], &src("a"), t0);
        assert!(r.follows(after, b"a", t0 + Duration::from_secs(60)));
        assert!(!r.follows(after, b"a", t0 + Duration::from_secs(61)));
        assert!(!r.follows(after, b"b", t0), "other value");
        // Events of rules nobody refers to are not remembered.
        r.record(&rules[1], &src("c"), t0);
        assert!(!r.memories.contains_key("login"));
    }

    #[test]
    fn out_of_order_journal_events_do_not_reverse_sequence_time() {
        let rules = rules(RULES);
        let after = rules[1].after.as_ref().unwrap();
        let mut recent = Recent::new(&rules, 100, Arc::new(Metrics::default()));
        let t0 = Instant::now();
        let future = t0 + Duration::from_secs(120);
        recent.record(&rules[0], &src("a"), future);
        assert!(
            !recent.follows(after, b"a", t0),
            "a later scan cannot precede an earlier login"
        );
        recent.record(&rules[0], &src("a"), t0);
        assert!(
            !recent.follows(after, b"a", t0 + Duration::from_secs(61)),
            "an older replay must not replace the latest scan time"
        );
        assert!(recent.follows(after, b"a", future));
    }

    #[test]
    fn full_memory_drops_old_values_first() {
        let rules = rules(RULES);
        let m = Arc::new(Metrics::default());
        let mut r = Recent::new(&rules, 16, Arc::clone(&m));
        let t0 = Instant::now();
        for i in 0..16u64 {
            r.record(
                &rules[0],
                &src(&i.to_string()),
                t0 + Duration::from_millis(i),
            );
        }
        r.record(&rules[0], &src("new"), t0 + Duration::from_millis(16));
        assert_eq!(m.snapshot().after_evictions, 2, "the oldest eighth");
        let after = rules[1].after.as_ref().unwrap();
        let t1 = t0 + Duration::from_millis(17);
        assert!(!r.follows(after, b"0", t1));
        assert!(r.follows(after, b"2", t1));
        r.record(&rules[0], &src("x"), t1);
        // Full again and past `within`: every old value goes at once.
        r.record(&rules[0], &src("late"), t0 + Duration::from_secs(120));
        assert_eq!(m.snapshot().after_evictions, 2 + 16);
        assert_eq!(r.memories["scan"][0].seen.len(), 1);
    }

    #[test]
    fn reload_keeps_values_still_asked_for() {
        let old = rules(RULES);
        let mut r = Recent::new(&old, 100, Arc::new(Metrics::default()));
        let t0 = Instant::now();
        r.record(&old[0], &src("a"), t0);
        let new = rules(&RULES.replace("within_secs = 60", "within_secs = 600"));
        r.reconfigure(&new, 100);
        let after = new[1].after.as_ref().unwrap();
        assert!(r.follows(after, b"a", t0 + Duration::from_secs(300)));
        let gone = rules(RULES.split("[rules.after]").next().unwrap());
        r.reconfigure(&gone, 100);
        assert!(r.memories.is_empty());
    }
}
