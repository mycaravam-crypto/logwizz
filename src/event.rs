//! Event and severity types.

use std::fmt::{self, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::threshold::Fired;

/// Severity attached to a rule and to every event the rule produces.
///
/// Ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Debug => "debug",
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        }
    }

    /// syslog(3) priority with the same name, as used by the sd-daemon
    /// `<N>` line prefix.
    pub fn syslog_priority(self) -> u8 {
        match self {
            Severity::Debug => 7,
            Severity::Info => 6,
            Severity::Notice => 5,
            Severity::Warning => 4,
            Severity::Error => 3,
            Severity::Critical => 2,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Version of the JSON event schema. Bump on incompatible changes.
pub const SCHEMA_VERSION: u32 = 1;

/// A rule match, owned so that it can cross to the output thread.
#[derive(Debug, Clone)]
pub struct Event {
    pub time: SystemTime,
    /// Index into the configured file list.
    pub file: usize,
    /// Index into the engine's rule list.
    pub rule: usize,
    /// The matching line, or its excerpt.
    pub line: Box<[u8]>,
    /// `line` is incomplete: cut at `max_line_bytes` or `max_excerpt_bytes`.
    pub truncated: bool,
    /// Named capture groups of the rule's regex, as (group index, value).
    pub fields: Vec<(usize, Box<[u8]>)>,
    /// Set for an event of a threshold rule.
    pub threshold: Option<Fired>,
}

/// Returns at most `max` bytes of `line`, backing off to a UTF-8 character
/// boundary so that an excerpt of valid text stays valid. The second value
/// is `true` if anything was cut.
pub fn excerpt(line: &[u8], max: Option<usize>) -> (&[u8], bool) {
    let Some(max) = max else {
        return (line, false);
    };
    if line.len() <= max {
        return (line, false);
    }
    let mut end = max;
    // Back off over at most three continuation bytes.
    for _ in 0..3 {
        if end > 0 && (line[end] & 0xC0) == 0x80 {
            end -= 1;
        } else {
            break;
        }
    }
    if (line[end] & 0xC0) == 0x80 {
        // Not UTF-8 anyway; cut at the byte limit.
        end = max;
    }
    (&line[..end], true)
}

/// Formats `t` as RFC 3339 UTC with microsecond precision, e.g.
/// `2026-10-24T08:15:30.123456Z`. Times before the epoch are clamped to it.
pub fn format_rfc3339(t: SystemTime, out: &mut String) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, day) = civil_from_days(days);
    let _ = write!(
        out,
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:06}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60,
        d.subsec_micros()
    );
}

/// Days since 1970-01-01 to a proleptic Gregorian (year, month, day).
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn syslog_priority_matches_severity_names() {
        let all = [
            Severity::Debug,
            Severity::Info,
            Severity::Notice,
            Severity::Warning,
            Severity::Error,
            Severity::Critical,
        ];
        assert_eq!(all.map(Severity::syslog_priority), [7, 6, 5, 4, 3, 2]);
    }

    fn fmt(secs: u64, micros: u32) -> String {
        let mut s = String::new();
        format_rfc3339(UNIX_EPOCH + Duration::new(secs, micros * 1000), &mut s);
        s
    }

    #[test]
    fn rfc3339_known_dates() {
        assert_eq!(fmt(0, 0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(fmt(951_782_400, 0), "2000-02-29T00:00:00.000000Z");
        assert_eq!(fmt(1_709_164_799, 999_999), "2024-02-28T23:59:59.999999Z");
        assert_eq!(fmt(1_709_251_200, 1), "2024-03-01T00:00:00.000001Z");
        assert_eq!(fmt(1_798_761_599, 0), "2026-12-31T23:59:59.000000Z");
        assert_eq!(fmt(4_102_444_800, 0), "2100-01-01T00:00:00.000000Z");
    }

    #[test]
    fn rfc3339_matches_day_count_for_every_day() {
        // Round-trip check over ~400 years against a naive day counter.
        let (mut y, mut m, mut d) = (1970i64, 1u32, 1u32);
        for day in 0..146_097i64 {
            assert_eq!(civil_from_days(day), (y, m, d), "day {day}");
            let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
            let len = [
                31,
                if leap { 29 } else { 28 },
                31,
                30,
                31,
                30,
                31,
                31,
                30,
                31,
                30,
                31,
            ][(m - 1) as usize];
            d += 1;
            if d > len {
                d = 1;
                m += 1;
                if m > 12 {
                    m = 1;
                    y += 1;
                }
            }
        }
    }

    #[test]
    fn excerpt_limits() {
        assert_eq!(excerpt(b"hello", None), (&b"hello"[..], false));
        assert_eq!(excerpt(b"hello", Some(5)), (&b"hello"[..], false));
        assert_eq!(excerpt(b"hello", Some(3)), (&b"hel"[..], true));
        // "é" is 2 bytes: never split it.
        let s = "aé".as_bytes();
        assert_eq!(excerpt(s, Some(2)), (&b"a"[..], true));
        let s = "€€".as_bytes(); // 3-byte chars
        assert_eq!(excerpt(s, Some(4)), (&s[..3], true));
        assert_eq!(excerpt(s, Some(5)), (&s[..3], true));
        // Garbage continuation bytes: cut at the limit.
        assert_eq!(excerpt(b"\x80\x80\x80\x80\x80", Some(4)).0.len(), 4);
    }
}
