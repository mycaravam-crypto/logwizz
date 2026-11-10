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
    /// An event, before rate limiting and deduplication. Set for a
    /// threshold rule: what was reached.
    Event(Option<Box<Fired>>),
}

/// The detection state between lines.
#[derive(Debug)]
pub struct Detector {
    thresholds: Thresholds,
    recent: Recent,
}

impl Detector {
    pub fn new(cfg: &Config, metrics: Arc<Metrics>) -> Self {
        let max = cfg.limits.threshold_max_groups;
        Detector {
            thresholds: Thresholds::new(cfg.rules.len(), max, Arc::clone(&metrics)),
            recent: Recent::new(&cfg.rules, max, metrics),
        }
    }

    /// Applies a reloaded configuration. `kept[i]` is the old index of new
    /// rule `i` if its definition is unchanged.
    pub fn reconfigure(&mut self, new: &Config, kept: &[Option<usize>]) {
        let max = new.limits.threshold_max_groups;
        self.thresholds.reconfigure(max, kept);
        self.recent.reconfigure(&new.rules, max);
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
