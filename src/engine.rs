//! Rule matching.

use std::fmt;

use memchr::memmem;
use regex::bytes::Regex;
use serde::Deserialize;

use crate::config::Rule;

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
    fn non_utf8_lines_are_matched() {
        let e = engine(&format!(
            "{}{}",
            rule("lit", "literal", "error"),
            rule("re", "regex", "err(or)?"),
        ));
        assert_eq!(matches(&e, b"\xff\xfe error \xc3"), ["lit", "re"]);
    }
}
