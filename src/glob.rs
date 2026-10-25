//! Wildcard patterns for a single path component (`[[files]] glob`).
//!
//! Only `*` (any run of bytes, possibly empty) and `?` (exactly one byte)
//! are supported, and only in the final component of a glob, so matching
//! one directory listing is enough. As in the shell, a wildcard never
//! matches a leading `.`: `*.log` does not match `.hidden.log`.
//!
//! Matching works on raw bytes, so names that are not valid UTF-8 can be
//! matched too; `?` matches one byte, not one character.

/// A validated single-component pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    text: Box<[u8]>,
}

impl Pattern {
    /// Validates `text` as the pattern for one path component.
    pub fn new(text: &str) -> Result<Self, String> {
        if text.is_empty() {
            return Err("pattern must not be empty".to_string());
        }
        if text.contains('/') {
            return Err("pattern must not contain '/'".to_string());
        }
        if text.contains("**") {
            return Err("recursive '**' is not supported".to_string());
        }
        if let Some(c) = text
            .chars()
            .find(|c| matches!(c, '[' | ']' | '{' | '}' | '\\'))
        {
            return Err(format!(
                "'{c}' is not supported; only the '*' and '?' wildcards are"
            ));
        }
        Ok(Pattern {
            text: text.as_bytes().into(),
        })
    }

    pub fn has_wildcard(&self) -> bool {
        self.text.iter().any(|&b| b == b'*' || b == b'?')
    }

    /// Whether the file name `name` matches.
    pub fn matches(&self, name: &[u8]) -> bool {
        if name.first() == Some(&b'.') && self.text.first() != Some(&b'.') {
            return false;
        }
        let p = &self.text;
        let (mut pi, mut ni) = (0, 0);
        // Position after the last `*` seen, and the name position it is
        // currently assumed to have consumed up to.
        let mut star: Option<(usize, usize)> = None;
        while ni < name.len() {
            match p.get(pi) {
                Some(b'*') => {
                    pi += 1;
                    star = Some((pi, ni));
                }
                Some(&c) if c == b'?' || c == name[ni] => {
                    pi += 1;
                    ni += 1;
                }
                _ => match star {
                    // Let the last `*` absorb one more byte and retry. With
                    // only one active backtrack point this is O(p * n).
                    Some((sp, sn)) => {
                        pi = sp;
                        ni = sn + 1;
                        star = Some((sp, sn + 1));
                    }
                    None => return false,
                },
            }
        }
        p[pi..].iter().all(|&b| b == b'*')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, name: &str) -> bool {
        Pattern::new(p).unwrap().matches(name.as_bytes())
    }

    #[test]
    fn star_and_question_mark() {
        assert!(m("*.log", "app.log"));
        assert!(!m("*.log", ".log.log"));
        assert!(m("*.log", "x.log"));
        assert!(!m("*.log", "app.log.1"));
        assert!(m("*.log*", "app.log.1"));
        assert!(m("app-????.log", "app-2026.log"));
        assert!(!m("app-????.log", "app-26.log"));
        assert!(m("a*b*c", "abc"));
        assert!(m("a*b*c", "aXbYbZc"));
        assert!(!m("a*b*c", "aXbYbZ"));
        assert!(m("*", "anything"));
        assert!(m("exact.log", "exact.log"));
        assert!(!m("exact.log", "exact.logs"));
    }

    #[test]
    fn leading_dot_needs_literal_dot() {
        assert!(!m("*", ".hidden"));
        assert!(!m("?hidden", ".hidden"));
        assert!(m(".*", ".hidden"));
    }

    #[test]
    fn matches_raw_bytes() {
        let p = Pattern::new("*.log").unwrap();
        assert!(p.matches(b"\xff\xfe.log"));
        assert!(Pattern::new("?.log").unwrap().matches(b"\xff.log"));
    }

    #[test]
    fn many_stars_stay_linear_enough() {
        let p = Pattern::new("*a*a*a*a*a*a*a*a*b").unwrap();
        let name = vec![b'a'; 4096];
        assert!(!p.matches(&name));
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        assert!(Pattern::new("").is_err());
        assert!(Pattern::new("a/b").is_err());
        assert!(Pattern::new("**.log").unwrap_err().contains("'**'"));
        assert!(Pattern::new("[ab].log").unwrap_err().contains("'['"));
        assert!(Pattern::new("{a,b}.log").is_err());
        assert!(!Pattern::new("plain").unwrap().has_wildcard());
    }
}
