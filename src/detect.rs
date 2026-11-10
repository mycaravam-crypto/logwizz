//! What becomes of a rule match: exclusions, sequences and thresholds.
//!
//! Shared by the daemon and `--test`, so a test run decides exactly as the
//! daemon would.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::config::{Config, Rule};
use crate::metrics::Metrics;
use crate::sequence::Recent;
use crate::threshold::{Fired, Thresholds};

/// The outcome of one match of an emitting rule.
#[derive(Debug)]
pub enum Verdict {
    /// Discarded by the rule's `types`: a capture is not what it must be.
    Mistyped,
    /// Discarded by the rule's `exclude`.
    Excluded,
    /// An `after` rule without a recent event of a named rule.
    Unsequenced,
    /// Counted by a threshold that was not reached, or is cooling down.
    Absorbed,
    /// A match of a silence rule: the expected line is still appearing.
    Seen,
    /// An event, before rate limiting and deduplication. Set for a
    /// threshold rule: what was reached.
    Event(Option<Box<Fired>>),
}

/// The detection state between lines.
#[derive(Debug)]
pub struct Detector {
    thresholds: Thresholds,
    recent: Recent,
    /// Per rule; set for silence rules.
    quiet: Vec<Option<Quiet>>,
}

/// The state of one silence rule.
#[derive(Debug, Clone, Copy)]
struct Quiet {
    /// The latest match, or when the rule started waiting for one.
    last_seen: Instant,
    /// The current silence was reported; nothing more until a match.
    reported: bool,
}

impl Quiet {
    fn starting(rule: &Rule, now: Instant) -> Option<Quiet> {
        rule.silence.map(|_| Quiet {
            last_seen: now,
            reported: false,
        })
    }
}

impl Detector {
    pub fn new(cfg: &Config, metrics: Arc<Metrics>) -> Self {
        let max = cfg.limits.threshold_max_groups;
        Detector {
            thresholds: Thresholds::new(cfg.rules.len(), max, Arc::clone(&metrics)),
            recent: Recent::new(&cfg.rules, max, metrics),
            quiet: Self::quiet(&cfg.rules, &[], &[], Instant::now()),
        }
    }

    /// Applies a reloaded configuration. `kept[i]` is the old index of new
    /// rule `i` if its definition is unchanged.
    pub fn reconfigure(&mut self, new: &Config, kept: &[Option<usize>]) {
        let max = new.limits.threshold_max_groups;
        self.thresholds.reconfigure(max, kept);
        self.recent.reconfigure(&new.rules, max);
        self.quiet = Self::quiet(&new.rules, kept, &self.quiet, Instant::now());
    }

    /// Silence state for `rules`: unchanged rules keep theirs, the others
    /// start waiting at `now`.
    fn quiet(
        rules: &[Rule],
        kept: &[Option<usize>],
        old: &[Option<Quiet>],
        now: Instant,
    ) -> Vec<Option<Quiet>> {
        rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let carried = kept.get(i).copied().flatten().and_then(|k| old.get(k));
                carried
                    .copied()
                    .flatten()
                    .or_else(|| Quiet::starting(r, now))
            })
            .collect()
    }

    /// Whether any rule waits for a silence, so [`Detector::silent`] needs
    /// calling regularly.
    pub fn watches_silence(&self) -> bool {
        self.quiet.iter().any(Option::is_some)
    }

    /// The silence rules (by index) that have matched nothing for their
    /// `after_secs` at `now` and were not reported for it yet. Each is
    /// returned once per silence: a match arms it again.
    pub fn silent(&mut self, rules: &[Rule], now: Instant) -> Vec<usize> {
        let mut due = Vec::new();
        for (i, (rule, quiet)) in rules.iter().zip(&mut self.quiet).enumerate() {
            let (Some(after), Some(q)) = (rule.silence, quiet) else {
                continue;
            };
            if !q.reported && now.saturating_duration_since(q.last_seen) >= after {
                q.reported = true;
                due.push(i);
            }
        }
        due
    }

    /// Decides one match of rule `r` (index `rule`) on a line read from
    /// `file` at `now`, with the match's captured values.
    pub fn judge(
        &mut self,
        rule: usize,
        r: &Rule,
        file: &Path,
        fields: &[(usize, Box<[u8]>)],
        now: Instant,
    ) -> Verdict {
        if r.mistyped(fields) {
            return Verdict::Mistyped;
        }
        if r.excludes(fields) {
            return Verdict::Excluded;
        }
        if let Some(q) = self.quiet.get_mut(rule).and_then(Option::as_mut) {
            // Counted from when the line was read, not from its log time:
            // an old entry read late (journal catch-up) still shows that
            // lines arrive, and must not report a silence again.
            q.last_seen = q.last_seen.max(now).max(Instant::now());
            q.reported = false;
            return Verdict::Seen;
        }
        if let Some(after) = &r.after {
            let follows = fields
                .iter()
                .find(|(g, _)| *g == after.group)
                .is_some_and(|(_, v)| self.recent.follows(after, v, now));
            if !follows {
                return Verdict::Unsequenced;
            }
        }
        let threshold = match &r.threshold {
            None => None,
            Some(t) => match self.thresholds.observe(rule, &r.id, t, file, fields, now) {
                Some(fired) => Some(Box::new(fired)),
                None => return Verdict::Absorbed,
            },
        };
        // Before limiting: a rate-limited event still happened.
        self.recent.record(r, fields, now);
        Verdict::Event(threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::time::Duration;

    const RULES: &str = r#"
[[files]]
path = "/var/log/audit.log"

[[rules]]
id = "other"
match_type = "literal"
pattern = "x"
severity = "info"

[[rules]]
id = "quiet"
match_type = "literal"
pattern = "type=SYSCALL"
severity = "critical"
[rules.silence]
after_secs = 60
"#;

    #[test]
    fn silence_is_reported_once_until_the_next_match() {
        let cfg = config::parse(RULES, Path::new("t")).unwrap();
        let mut d = Detector::new(&cfg, Arc::new(Metrics::default()));
        assert!(d.watches_silence());
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let file = Path::new("/var/log/audit.log");
        let quiet = &cfg.rules[1];
        let seen = |d: &mut Detector, secs: u64| {
            assert!(matches!(
                d.judge(1, quiet, file, &[], at(secs)),
                Verdict::Seen
            ));
        };

        // Waiting starts with the detector, not with the first match.
        assert!(d.silent(&cfg.rules, at(59)).is_empty());
        assert_eq!(d.silent(&cfg.rules, at(61)), [1]);
        assert!(d.silent(&cfg.rules, at(500)).is_empty(), "reported once");

        // A match arms it again, counting from that match. (Times in the
        // future stand in for the read time the daemon counts from.)
        seen(&mut d, 600);
        assert!(d.silent(&cfg.rules, at(659)).is_empty());
        seen(&mut d, 650);
        assert!(d.silent(&cfg.rules, at(700)).is_empty());
        assert_eq!(d.silent(&cfg.rules, at(711)), [1]);
    }

    #[test]
    fn reload_keeps_the_state_of_unchanged_silence_rules() {
        let cfg = config::parse(RULES, Path::new("t")).unwrap();
        let mut d = Detector::new(&cfg, Arc::new(Metrics::default()));
        let later = Instant::now() + Duration::from_secs(61);
        assert_eq!(d.silent(&cfg.rules, later), [1]);
        // Unchanged: still reported. Changed: waits again from the reload.
        d.reconfigure(&cfg, &[Some(0), Some(1)]);
        assert!(d.silent(&cfg.rules, later).is_empty());
        d.reconfigure(&cfg, &[Some(0), None]);
        let reloaded = Instant::now();
        assert!(
            d.silent(&cfg.rules, reloaded + Duration::from_secs(59))
                .is_empty()
        );
        assert_eq!(
            d.silent(&cfg.rules, reloaded + Duration::from_secs(61)),
            [1]
        );

        let none = config::parse(
            &RULES[..RULES.find("[[rules]]\nid = \"quiet\"").unwrap()],
            Path::new("t"),
        )
        .unwrap();
        d.reconfigure(&none, &[Some(0)]);
        assert!(!d.watches_silence());
    }
}
