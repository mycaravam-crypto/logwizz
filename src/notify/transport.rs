//! Delivery of summaries through `curl`.
//!
//! curl is run once per summary, never per event. Everything secret (the
//! endpoint URL, the Telegram bot token, the Authorization header) and the
//! message itself go to curl's standard input as a config file (`--config
//! -`), so they never appear in process arguments or on disk.

use std::io::Write;
use std::process::{Command, Stdio};

use super::aggregate::Summary;

/// Where summaries go.
#[derive(Clone, PartialEq, Eq)]
pub enum Kind {
    Telegram { token: String, chat_id: String },
    Ntfy { url: String },
    Webhook { url: String },
}

impl std::fmt::Debug for Kind {
    /// Never prints the token or URL.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Kind::Telegram { .. } => "telegram",
            Kind::Ntfy { .. } => "ntfy",
            Kind::Webhook { .. } => "webhook",
        })
    }
}

/// Sends one summary. Implemented by [`Curl`]; tests use fakes.
pub trait Deliver {
    fn deliver(&mut self, summary: &Summary, partial: bool) -> Result<(), String>;
}

/// Telegram's reply is small; anything bigger is not a Telegram reply.
const MAX_RESPONSE_BYTES: &str = "65536";

#[derive(Debug)]
pub struct Curl {
    pub kind: Kind,
    /// Value of an `Authorization` header.
    pub auth: Option<String>,
}

impl Curl {
    /// curl's config for one summary: the request, including secrets.
    pub fn request(&self, s: &Summary, partial: bool) -> String {
        let mut c = String::new();
        let mut opt = |name: &str, value: &str| {
            c.push_str(name);
            c.push_str(" = \"");
            c.push_str(&quote(value));
            c.push_str("\"\n");
        };
        match &self.kind {
            Kind::Telegram { token, chat_id } => {
                opt(
                    "url",
                    &format!("https://api.telegram.org/bot{token}/sendMessage"),
                );
                opt("data-urlencode", &format!("chat_id={chat_id}"));
                opt(
                    "data-urlencode",
                    &format!("text={}", s.to_telegram_html(partial)),
                );
                opt("data-urlencode", "parse_mode=HTML");
                opt("data-urlencode", "disable_web_page_preview=true");
                opt("max-filesize", MAX_RESPONSE_BYTES);
            }
            Kind::Ntfy { url } => {
                let priority = match s.severity.syslog_priority() {
                    0..=2 => "5",
                    3 | 4 => "4",
                    5 => "3",
                    6 => "2",
                    _ => "1",
                };
                opt("url", url);
                opt("header", &format!("Title: logwizz {}: {}", s.host, s.rule));
                opt("header", &format!("Priority: {priority}"));
                opt("header", &format!("Tags: {}", s.severity));
                opt("data-binary", &s.to_text(partial));
                opt("output", "/dev/null");
            }
            Kind::Webhook { url } => {
                opt("url", url);
                opt("header", "Content-Type: application/json");
                opt("data-binary", &s.to_json(partial).to_string());
                opt("output", "/dev/null");
            }
        }
        if let Some(auth) = &self.auth {
            opt("header", &format!("Authorization: {auth}"));
        }
        c
    }
}

/// Escapes a value for a double-quoted curl config string.
fn quote(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for ch in v.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

impl Deliver for Curl {
    fn deliver(&mut self, s: &Summary, partial: bool) -> Result<(), String> {
        let mut child = Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "10",
                "--retry",
                "3",
                "--retry-all-errors",
                "--retry-delay",
                "1",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--config",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run curl: {e}"))?;
        let config = self.request(s, partial);
        let written = child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(config.as_bytes());
        let out = child
            .wait_with_output()
            .map_err(|e| format!("waiting for curl failed: {e}"))?;
        written.map_err(|e| format!("writing to curl failed: {e}"))?;
        if !out.status.success() {
            // curl's message names the failure (and at most the host); keep
            // the first line, bounded.
            let err = String::from_utf8_lossy(&out.stderr);
            let first = err.lines().next().unwrap_or("").trim();
            return Err(format!(
                "curl failed ({}): {}",
                out.status,
                super::aggregate::clean(first, 200)
            ));
        }
        if matches!(self.kind, Kind::Telegram { .. }) {
            let ok = serde_json::from_slice::<serde_json::Value>(&out.stdout)
                .ok()
                .and_then(|v| v.get("ok").and_then(serde_json::Value::as_bool));
            if ok != Some(true) {
                return Err("Telegram did not accept the message".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;

    fn summary() -> Summary {
        serde_json::from_value(serde_json::json!({
            "bucket": 1_792_932_000u64, "window_secs": 60, "rule": "ssh", "host": "web1",
            "severity": "critical", "description": "say \"hi\"\\", "count": 3,
            "sources": [{"source": "203.0.113.8", "count": 3}]
        }))
        .unwrap()
    }

    #[test]
    fn quoting_round_trips_special_characters() {
        assert_eq!(quote("a\"b\\c\nd\u{7}"), "a\\\"b\\\\c\\nd ");
    }

    #[test]
    fn webhook_request() {
        let c = Curl {
            kind: Kind::Webhook {
                url: "https://example.invalid/hook".into(),
            },
            auth: Some("Bearer tok".into()),
        };
        let r = c.request(&summary(), false);
        assert!(
            r.starts_with("url = \"https://example.invalid/hook\"\n"),
            "{r}"
        );
        assert!(r.contains("header = \"Content-Type: application/json\"\n"));
        assert!(r.contains("header = \"Authorization: Bearer tok\"\n"));
        assert!(
            r.contains(r#"\"description\":\"say \\\"hi\\\"\\\\\""#),
            "{r}"
        );
        // One line per option: the body cannot inject options.
        assert_eq!(r.lines().count(), 5, "{r}");
    }

    #[test]
    fn ntfy_and_telegram_requests() {
        let mut s = summary();
        let ntfy = Curl {
            kind: Kind::Ntfy {
                url: "https://ntfy.sh/topic".into(),
            },
            auth: None,
        };
        let r = ntfy.request(&s, true);
        assert!(r.contains("header = \"Title: logwizz web1: ssh\"\n"));
        assert!(r.contains("header = \"Priority: 5\"\n"));
        assert!(r.contains("header = \"Tags: critical\"\n"));
        assert!(r.contains("\\nPartial window"));
        s.severity = Severity::Notice;
        assert!(ntfy.request(&s, false).contains("Priority: 3"));

        let tg = Curl {
            kind: Kind::Telegram {
                token: "123:ABC".into(),
                chat_id: "-100123".into(),
            },
            auth: None,
        };
        let r = tg.request(&s, false);
        assert!(r.contains("url = \"https://api.telegram.org/bot123:ABC/sendMessage\"\n"));
        assert!(r.contains("data-urlencode = \"chat_id=-100123\"\n"));
        assert!(
            r.contains("data-urlencode = \"text=🔵 <b>say \\\"hi\\\"\\\\</b>\\n"),
            "{r}"
        );
        assert!(r.contains("data-urlencode = \"parse_mode=HTML\"\n"));
        assert_eq!(
            format!("{:?}", tg.kind),
            "telegram",
            "Debug hides the token"
        );
    }
}
