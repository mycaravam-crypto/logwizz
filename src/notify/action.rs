//! A Fail2ban actionban report, independent of detection summaries.
//!
//! Only the dedicated, root-authenticated journal record is accepted. A
//! reported callback is not independent verification of firewall enforcement.
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::aggregate::clean;

pub const IDENTIFIER: &str = "logwizz-ban";
pub const PREFIX: &str = "LOGWIZZ_BAN_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanReport {
    pub host: String,
    pub jail: String,
    pub ip: String,
    pub bantime_secs: i64,
    pub time: u64,
    #[serde(default)]
    pub retry_count: u32,
    #[serde(default)]
    pub retry_after: u64,
}

impl BanReport {
    pub fn parse(message: &str, host: &str, time: u64) -> Option<Self> {
        let mut words = message.split_ascii_whitespace();
        if words.next()? != PREFIX {
            return None;
        }
        let jail = words.next()?.strip_prefix("jail=")?;
        let ip = words.next()?.strip_prefix("ip=")?;
        let bantime = words.next()?.strip_prefix("bantime=")?;
        if words.next().is_some()
            || jail.is_empty()
            || jail.len() > 64
            || !jail
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return None;
        }
        let ip: IpAddr = ip.parse().ok()?;
        let bantime_secs: i64 = bantime.parse().ok()?;
        if bantime_secs < -1 {
            return None;
        }
        Some(Self {
            host: clean(host, 128),
            jail: jail.to_owned(),
            ip: ip.to_string(),
            bantime_secs,
            time,
            retry_count: 0,
            retry_after: 0,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": "logwizz.action/v1",
            "action": "ban",
            "status": "actionban_reported",
            "backend": "fail2ban",
            "host": self.host,
            "jail": self.jail,
            "ip": self.ip,
            "bantime_secs": self.bantime_secs,
            "reported_at": crate::event::format_rfc3339_secs(self.time),
        })
    }

    pub fn to_text(&self) -> String {
        let time = if self.bantime_secs == -1 {
            "permanent".to_owned()
        } else {
            format!("{} s", self.bantime_secs)
        };
        format!(
            "Fail2ban actionban reported · {}\nJail: {}\nIP: {}\nBan duration: {}\nFirewall enforcement not independently verified",
            self.host, self.jail, self.ip, time
        )
    }

    pub fn to_telegram_html(&self) -> String {
        let time = if self.bantime_secs == -1 {
            "permanent".to_owned()
        } else {
            format!("{} s", self.bantime_secs)
        };
        format!(
            "🛡 <b>Fail2ban actionban reported</b>\n{} · {}\n<code>{}</code> · {}\n<i>Firewall enforcement not independently verified</i>",
            escape(&self.jail),
            escape(&self.host),
            escape(&self.ip),
            time
        )
    }

    pub fn failed(&mut self, now: u64) -> u64 {
        let delay = 2u64
            .checked_shl(self.retry_count.min(16))
            .unwrap_or(u64::MAX)
            .min(super::aggregate::MAX_RETRY_DELAY_SECS);
        self.retry_count = self.retry_count.saturating_add(1);
        self.retry_after = now.saturating_add(delay);
        delay
    }
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_action_record_validation() {
        let report = BanReport::parse(
            "LOGWIZZ_BAN_V1 jail=logwizz ip=198.51.100.24 bantime=3600",
            "web1",
            42,
        )
        .unwrap();
        assert_eq!(report.jail, "logwizz");
        assert_eq!(report.bantime_secs, 3600);
        assert_eq!(report.to_json()["schema"], "logwizz.action/v1");
        assert_eq!(report.to_json()["status"], "actionban_reported");
        for bad in [
            "LOGWIZZ_BAN_V1 jail=logwizz ip=not-an-ip bantime=1",
            "LOGWIZZ_BAN_V1 jail=x;evil ip=198.51.100.24 bantime=1",
            "LOGWIZZ_BAN_V1 jail=x ip=198.51.100.24 bantime=-2",
            "LOGWIZZ_BAN_V1 jail=x ip=198.51.100.24 bantime=1 extra",
            "LOGWIZZ_BAN_V1 jail=x ip=198.51.100.24",
            "logwizz rule=ssh_bruteforce src=198.51.100.24",
        ] {
            assert!(BanReport::parse(bad, "web1", 42).is_none(), "{bad}");
        }
    }

    #[test]
    fn retry_backoff_is_bounded() {
        let mut report = BanReport::parse(
            "LOGWIZZ_BAN_V1 jail=logwizz ip=198.51.100.24 bantime=-1",
            "web1",
            42,
        )
        .unwrap();
        assert_eq!(report.failed(10), 2);
        assert_eq!(report.failed(10), 4);
        for _ in 0..20 {
            report.failed(10);
        }
        assert_eq!(report.retry_after, 310);
        assert!(report.to_text().contains("permanent"));
    }
}
