//! Rule matching.

use std::fmt;

use memchr::memmem;
use regex::bytes::Regex;
use serde::Deserialize;

use crate::config::Rule;
use crate::event::excerpt;

/// Maximum named capture groups per rule.
pub const MAX_FIELDS: usize = 16;
/// Captured values are cut to this many bytes, on a UTF-8 boundary.
pub const MAX_FIELD_BYTES: usize = 256;

/// How a rule's pattern is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    /// Case-sensitive substring search.
    Literal,
    /// Regular expression (Rust `regex` syntax, linear-time matching).
    Regex,
}

impl MatchType {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchType::Literal => "literal",
            MatchType::Regex => "regex",
        }
    }
}

impl fmt::Display for MatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A compiled pattern. Built once at configuration load time.
///
/// Matching works on raw bytes so that lines which are not valid UTF-8 are
/// still evaluated rather than skipped.
#[derive(Debug, Clone)]
pub enum Matcher {
    Literal(Box<memmem::Finder<'static>>),
    Regex(Regex),
}

impl Matcher {
    #[inline]
    pub fn is_match(&self, line: &[u8]) -> bool {
        match self {
            Matcher::Literal(finder) => finder.find(line).is_some(),
            Matcher::Regex(re) => re.is_match(line),
        }
    }

    /// The values of the named capture groups in `line`, as (group index,
    /// value). Groups that did not participate are left out. Empty, without
    /// allocating, for literals and regexes without named groups.
    pub fn fields(&self, line: &[u8]) -> Vec<(usize, Box<[u8]>)> {
        let Matcher::Regex(re) = self else {
            return Vec::new();
        };
        if re.capture_names().flatten().next().is_none() {
            return Vec::new();
        }
        // ponytail: allocates a Captures per match; reuse CaptureLocations per
        // rule if threshold rules on busy logs make this show up in benchmarks.
        let Some(caps) = re.captures(line) else {
            return Vec::new();
        };
        re.capture_names()
            .enumerate()
            .filter_map(|(i, name)| {
                name?;
                let value = caps.get(i)?.as_bytes();
                Some((i, excerpt(value, Some(MAX_FIELD_BYTES)).0.into()))
            })
            .collect()
    }

    /// Name of capture group `index`, if it is a named group.
    pub fn group_name(&self, index: usize) -> Option<&str> {
        match self {
            Matcher::Literal(_) => None,
            Matcher::Regex(re) => re.capture_names().nth(index).flatten(),
        }
    }
}

/// Evaluates every enabled rule against a line.
///
/// Rules are evaluated in configuration order and every matching rule
/// produces its own event. Matching allocates nothing.
#[derive(Debug, Clone)]
pub struct Engine {
    rules: Vec<Rule>,
}

impl Engine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Engine { rules }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Calls `f` with the index of each rule matching `line`.
    #[inline]
    pub fn for_each_match(&self, line: &[u8], mut f: impl FnMut(usize)) {
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.matcher.is_match(line) {
                f(i);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::path::Path;

    fn engine(rules: &str) -> Engine {
        let text = format!("[[files]]\npath = \"/x\"\n{rules}");
        Engine::new(config::parse(&text, Path::new("t")).unwrap().rules)
    }

    fn rule(id: &str, kind: &str, pattern: &str) -> String {
        format!(
            "[[rules]]\nid = \"{id}\"\nmatch_type = \"{kind}\"\npattern = '{pattern}'\nseverity = \"info\"\n"
        )
    }

    fn matches<'a>(e: &'a Engine, line: &[u8]) -> Vec<&'a str> {
        let mut out = Vec::new();
        e.for_each_match(line, |i| out.push(e.rules()[i].id.as_str()));
        out
    }

    #[test]
    fn literal_is_case_sensitive_substring() {
        let e = engine(&rule("a", "literal", "Failed password"));
        assert_eq!(matches(&e, b"sshd: Failed password for root"), ["a"]);
        assert!(matches(&e, b"failed password").is_empty());
        assert!(matches(&e, b"Failed passwor").is_empty());
    }

    #[test]
    fn literal_metacharacters_are_literal() {
        let e = engine(&rule("a", "literal", "a.b(c)*"));
        assert_eq!(matches(&e, b"xx a.b(c)* yy"), ["a"]);
        assert!(matches(&e, b"axbc").is_empty());
    }

    #[test]
    fn regex_features() {
        let e = engine(&format!(
            "{}{}",
            rule("ci", "regex", "(?i)kernel panic"),
            rule("anch", "regex", r"^\d{4}-\d{2}-\d{2} ERROR\b"),
        ));
        assert_eq!(matches(&e, b"Kernel PANIC!"), ["ci"]);
        assert_eq!(matches(&e, b"2026-10-24 ERROR disk"), ["anch"]);
        assert!(matches(&e, b" 2026-10-24 ERROR").is_empty());
        assert!(matches(&e, b"2026-10-24 ERRORS").is_empty());
    }

    #[test]
    fn every_matching_rule_fires_in_order() {
        let e = engine(&format!(
            "{}{}{}",
            rule("one", "literal", "disk"),
            rule("two", "regex", "full$"),
            rule("three", "literal", "network"),
        ));
        assert_eq!(matches(&e, b"disk full"), ["one", "two"]);
    }

    #[test]
    fn disabled_rules_never_match() {
        let e = engine(&format!(
            "{}{}enabled = false\n",
            rule("on", "literal", "x"),
            rule("off", "literal", "x"),
        ));
        assert_eq!(matches(&e, b"x"), ["on"]);
    }

    #[test]
    fn named_groups_become_fields() {
        let e = engine(&format!(
            "{}{}",
            rule(
                "re",
                "regex",
                r"SRC=(?P<src>\S+) (x)? ?(?:DPT=(?P<dpt>\d+))?"
            ),
            rule("lit", "literal", "SRC="),
        ));
        let m = &e.rules()[0].matcher;
        let named = |line: &[u8]| -> Vec<(String, Vec<u8>)> {
            m.fields(line)
                .into_iter()
                .map(|(i, v)| (m.group_name(i).unwrap().to_string(), v.into_vec()))
                .collect()
        };
        assert_eq!(
            named(b"SRC=192.0.2.7 DPT=22"),
            [
                ("src".into(), b"192.0.2.7".to_vec()),
                ("dpt".into(), b"22".to_vec())
            ]
        );
        // A group that did not participate is left out; unnamed groups never appear.
        assert_eq!(
            named(b"SRC=192.0.2.7 x "),
            [("src".into(), b"192.0.2.7".to_vec())]
        );
        assert!(e.rules()[1].matcher.fields(b"SRC=1").is_empty());
        let long = format!("SRC={}é ", "a".repeat(MAX_FIELD_BYTES - 1));
        let v = &m.fields(long.as_bytes())[0].1;
        assert_eq!(
            v.len(),
            MAX_FIELD_BYTES - 1,
            "cut before the two-byte character"
        );
    }

    #[test]
    fn non_utf8_lines_are_matched() {
        let e = engine(&format!(
            "{}{}",
            rule("lit", "literal", "error"),
            rule("re", "regex", "err(or)?"),
        ));
        assert_eq!(matches(&e, b"\xff\xfe error \xc3"), ["lit", "re"]);
    }
}
