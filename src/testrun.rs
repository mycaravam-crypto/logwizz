//! `--test`: run a sample log through the rules once and report, per rule,
//! what matched and what would have become an event.
//!
//! Nothing is watched, written to the output or saved. Every line counts as
//! read at the same moment, so windows and cooldowns do not elapse (see
//! [`Report::write`]).

use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::config::{Action, Config, Rule};
use crate::detect::{Detector, Verdict};
use crate::dispatcher::escape;
use crate::engine::Engine;
use crate::metrics::Metrics;

/// Threshold reports listed per rule; further ones are only counted.
const MAX_REPORTS: usize = 5;

/// What one rule did with the sample.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuleReport {
    /// Lines the rule matched. For an `ignore` rule: lines it ended.
    pub matches: u64,
    pub excluded: u64,
    /// Matches discarded by `types`.
    pub mistyped: u64,
    /// `after` rules: matches without an earlier event of a named rule.
    pub unsequenced: u64,
    /// Threshold rules: matches counted without reaching the threshold.
    pub absorbed: u64,
    /// Events, before rate limiting and deduplication.
    pub events: u64,
    /// Line number and captured values (name, value) of the first match.
    pub first: Option<(u64, Vec<(String, String)>)>,
    /// Line number, group and count of the first thresholds reached.
    pub reports: Vec<(u64, Option<String>, u32)>,
}

/// The result of a test run. `rules` is parallel to the configuration's.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub lines: u64,
    pub truncated: u64,
    pub ignored: u64,
    /// Lines no rule matched.
    pub unmatched: u64,
    pub rules: Vec<RuleReport>,
}

/// Evaluates every line of `sample` as if it had been read from the input
/// `input` (the path `files` scopes and `group_by = "file"` see).
pub fn run(cfg: &Config, sample: &mut dyn BufRead, input: &Path) -> io::Result<Report> {
    let engine = Engine::new(cfg.rules.clone());
    let mut detector = Detector::new(cfg, Arc::new(Metrics::default()));
    let mut report = Report {
        rules: vec![RuleReport::default(); cfg.rules.len()],
        ..Report::default()
    };
    let max = cfg.general.max_line_bytes;
    let now = Instant::now();
    let mut line = Vec::new();
    while let Some(truncated) = read_line(sample, max, &mut line)? {
        report.lines += 1;
        report.truncated += u64::from(truncated);
        let number = report.lines;
        let mut matched = false;
        let ignored_by = engine.for_each_match(input, &line, |i| {
            matched = true;
            let r = &engine.rules()[i];
            let stats = &mut report.rules[i];
            stats.matches += 1;
            let fields = r.matcher.fields(&line);
            if stats.first.is_none() {
                let named = fields
                    .iter()
                    .filter_map(|(g, v)| Some((r.matcher.group_name(*g)?.to_string(), text(v))))
                    .collect();
                stats.first = Some((number, named));
            }
            match detector.judge(i, r, input, &fields, now) {
                Verdict::Excluded => stats.excluded += 1,
                Verdict::Mistyped => stats.mistyped += 1,
                // Time is not replayed, so no silence is ever reported.
                Verdict::Seen => {}
                Verdict::Unsequenced => stats.unsequenced += 1,
                Verdict::Absorbed => stats.absorbed += 1,
                Verdict::Event(fired) => {
                    stats.events += 1;
                    if let Some(f) = fired.filter(|_| stats.reports.len() < MAX_REPORTS) {
                        let group = f.group.as_deref().map(text);
                        stats.reports.push((number, group, f.count));
                    }
                }
            }
        });
        match ignored_by {
            Some(i) => {
                report.ignored += 1;
                report.rules[i].matches += 1;
            }
            None if !matched => report.unmatched += 1,
            None => {}
        }
    }
    Ok(report)
}

/// Reads the next line into `line`, without its terminator and cut to
/// `max` bytes. `Some(true)`: it was cut. `None`: end of input.
fn read_line(r: &mut dyn BufRead, max: usize, line: &mut Vec<u8>) -> io::Result<Option<bool>> {
    line.clear();
    // One byte more than `max`: room for the newline of a line of `max`.
    if r.take(max as u64 + 1).read_until(b'\n', line)? == 0 {
        return Ok(None);
    }
    let complete = line.last() == Some(&b'\n');
    if complete {
        line.pop();
    }
    let truncated = line.len() > max;
    if truncated {
        line.truncate(max);
        if !complete {
            r.skip_until(b'\n')?;
        }
    }
    if !truncated && line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Some(truncated))
}

/// A captured value for display: the other side controls it, so control
/// and direction characters are escaped as in the human output format.
fn text(value: &[u8]) -> String {
    escape(&String::from_utf8_lossy(value)).into_owned()
}

impl Report {
    /// Writes the report as text. `rules` and `input` are those given to
    /// [`run`]; `sample` names what was read.
    pub fn write(
        &self,
        out: &mut dyn Write,
        rules: &[Rule],
        sample: &str,
        input: &Path,
    ) -> io::Result<()> {
        writeln!(out, "sample: {sample}, read as {}", input.display())?;
        writeln!(
            out,
            "lines: {} read, {} truncated, {} ignored, {} matched no rule",
            self.lines, self.truncated, self.ignored, self.unmatched
        )?;
        let width = rules.iter().map(|r| r.id.len()).max().unwrap_or(0).max(4);
        writeln!(
            out,
            "\n{:width$}  {:>9}  {:>9}  {:>9}  {:>9}  {:>9}  {:>9}",
            "rule", "matches", "mistyped", "excluded", "no_prior", "absorbed", "events"
        )?;
        let cell = |applies: bool, n: u64| match applies {
            true => n.to_string(),
            false => "-".to_string(),
        };
        let mut skipped = 0;
        for (r, s) in rules.iter().zip(&self.rules) {
            if !r.applies_to(input) {
                skipped += 1;
                continue;
            }
            let emits = r.action == Action::Emit;
            writeln!(
                out,
                "{:width$}  {:>9}  {:>9}  {:>9}  {:>9}  {:>9}  {:>9}{}",
                r.id,
                s.matches,
                cell(!r.types.is_empty(), s.mistyped),
                cell(emits && !r.exclude.is_empty(), s.excluded),
                cell(r.after.is_some(), s.unsequenced),
                cell(r.threshold.is_some(), s.absorbed),
                cell(emits && r.silence.is_none(), s.events),
                match (emits, r.silence) {
                    (false, _) => "  (ignore)",
                    (true, Some(_)) => "  (silence)",
                    (true, None) => "",
                },
            )?;
        }
        let mut heading = "\nfirst match:";
        for (r, s) in rules.iter().zip(&self.rules) {
            let Some((line, fields)) = &s.first else {
                continue;
            };
            if fields.is_empty() {
                continue;
            }
            if !heading.is_empty() {
                writeln!(out, "{heading}")?;
                heading = "";
            }
            let fields: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
            writeln!(out, "{:width$}  line {line}: {}", r.id, fields.join(" "))?;
        }
        let mut heading = "\nthresholds reached:";
        for (r, s) in rules.iter().zip(&self.rules) {
            for (i, (line, group, count)) in s.reports.iter().enumerate() {
                if !heading.is_empty() {
                    writeln!(out, "{heading}")?;
                    heading = "";
                }
                let group = group
                    .as_deref()
                    .map(|g| format!("{g}, "))
                    .unwrap_or_default();
                let more = s.events - s.reports.len() as u64;
                let rest = match more > 0 && i + 1 == s.reports.len() {
                    true => format!(" (and {more} more)"),
                    false => String::new(),
                };
                writeln!(
                    out,
                    "{:width$}  line {line}: {group}count {count}{rest}",
                    r.id
                )?;
            }
        }
        writeln!(out)?;
        if skipped > 0 {
            writeln!(
                out,
                "note: {skipped} rule(s) are limited to other inputs (files = [...]) and were not \
                 evaluated; name the input the sample stands for with --as"
            )?;
        }
        writeln!(
            out,
            "note: every line counts as read at the same moment, so windows (window_secs, \
             within_secs) always hold and cooldowns never end; rate limits and deduplication \
             are not applied"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(input: &[u8], max: usize) -> Vec<(String, bool)> {
        let mut r = io::BufReader::with_capacity(4, input);
        let mut line = Vec::new();
        let mut out = Vec::new();
        while let Some(cut) = read_line(&mut r, max, &mut line).unwrap() {
            out.push((String::from_utf8_lossy(&line).into_owned(), cut));
        }
        out
    }

    #[test]
    fn lines_are_split_and_cut() {
        let got = lines(b"one\r\ntwo\n\nabcdefgh\nabcd\nlast", 4);
        let want = [
            ("one", false),
            ("two", false),
            ("", false),
            ("abcd", true),
            ("abcd", false),
            ("last", false),
        ];
        let want: Vec<(String, bool)> = want.iter().map(|(s, c)| (s.to_string(), *c)).collect();
        assert_eq!(got, want);
        assert!(lines(b"", 4).is_empty());
        // An over-long last line without a newline ends the input.
        assert_eq!(lines(b"abcdefgh", 4), [("abcd".to_string(), true)]);
    }
}
