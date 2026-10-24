//! Rule matching.

use std::fmt;

use memchr::memmem;
use regex::bytes::Regex;
use serde::Deserialize;

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
