//! A Fail2ban actionban report, independent of detection summaries.
//!
//! Only the dedicated, root-authenticated journal record is accepted. A
//! V1 reports only actionban execution. V2 asserts an observed nftables
//! set entry plus active input-chain block rule at reporting time.
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::aggregate::clean;

pub const IDENTIFIER: &str = "logwizz-ban";
pub const PREFIX: &str = "LOGWIZZ_BAN_V1";
pub const VERIFIED_PREFIX: &str = "LOGWIZZ_BAN_V2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanReport {
    pub host: String,
    pub jail: String,
    pub ip: String,
    pub bantime_secs: i64,
    pub time: u64,
    /// V2 only: nftables set membership and input drop/reject rule verified.
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub retry_count: u32,
    #[serde(default)]
    pub retry_after: u64,
}

impl BanReport {
    pub fn parse(message: &str, host: &str, time: u64) -> Option<Self> {
        let mut words = message.split_ascii_whitespace();
        let verified = match words.next()? {
            PREFIX => false,
            VERIFIED_PREFIX => true,
            _ => return None,
        };
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
            verified,
            retry_count: 0,
            retry_after: 0,
        })
    }

    pub fn to_json(&self) -> Value {
        let mut payload = json!({
            "schema": "logwizz.action/v1",
            "action": "ban",
            "status": if self.verified { "firewall_rule_verified" } else { "actionban_reported" },
            "backend": "fail2ban",
            "host": self.host,
            "jail": self.jail,
            "ip": self.ip,
            "bantime_secs": self.bantime_secs,
            "reported_at": crate::event::format_rfc3339_secs(self.time),
        });
        if self.verified {
            payload["verification"] = json!("nftables-set-and-input-drop-rule");
        }
        payload
    }

    pub fn to_text(&self) -> String {
        let time = if self.bantime_secs == -1 {
            "permanent".to_owned()
        } else {
            format!("{} s", self.bantime_secs)
        };
        let (headline, evidence) = if self.verified {
            (
                "Fail2ban nftables ban verified",
                "nftables set entry and input drop/reject rule observed at report time",
            )
        } else {
            (
                "Fail2ban actionban reported",
                "Firewall enforcement not independently verified",
            )
        };
        format!(
            "{headline} · {}\nJail: {}\nIP: {}\nBan duration: {}\n{evidence}",
            self.host, self.jail, self.ip, time
        )
    }

    /// Uses the same English, labelled Telegram layout as detection summaries.
    pub fn to_telegram_html(&self) -> String {
        let duration = if self.bantime_secs == -1 {
            "permanent".to_owned()
        } else {
            format!("{} s", self.bantime_secs)
        };
        let (status, evidence) = if self.verified {
            (
                "Firewall rule verified",
                "nftables set and input drop/reject rule present at report time",
            )
        } else {
            (
                "Ban reported (not verified)",
                "Firewall enforcement not independently verified",
            )
        };
        format!(
            "🟡 <b>Logwizz security alert</b>\n\
             <b>Event:</b> <code>fail2ban_action</code>\n\
             <b>Severity:</b> warning\n\
             <b>Host:</b> {} <code>{}</code>\n\
             <b>Events:</b> 1\n\
             <b>Jail:</b> <code>{}</code>\n\
             <b>Source:</b> <code>{}</code>\n\
             <b>Ban duration:</b> {}\n\
             <b>Status:</b> {status}\n\
             <b>Reported at (UTC):</b> {}\n\
             <i>{evidence}</i>",
            super::host_badge(&self.host),
            escape(&self.host),
            escape(&self.jail),
            escape(&self.ip),
            duration,
            crate::event::format_rfc3339_secs(self.time),
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
        assert!(!report.verified);
        for bad in [
            "LOGWIZZ_BAN_V1 jail=logwizz ip=not-an-ip bantime=1",
            "LOGWIZZ_BAN_V1 jail=x;evil ip=198.51.100.24 bantime=1",
            "LOGWIZZ_BAN_V1 jail=x ip=198.51.100.24 bantime=-2",
            "LOGWIZZ_BAN_V1 jail=x ip=198.51.100.24 bantime=1 extra",
            "LOGWIZZ_BAN_V1 jail=x ip=198.51.100.24",
            "LOGWIZZ_BAN_V2 jail=logwizz ip=invalid bantime=3600",
            "LOGWIZZ_BAN_V2 jail=bad;jail ip=198.51.100.24 bantime=3600",
            "LOGWIZZ_BAN_V2 jail=logwizz ip=198.51.100.24",
            "LOGWIZZ_BAN_V2 jail=logwizz ip=198.51.100.24 bantime=-2",
            "LOGWIZZ_BAN_V2 jail=logwizz ip=198.51.100.24 bantime=1 trailing",
            "LOGWIZZ_BAN_V3 jail=logwizz ip=198.51.100.24 bantime=3600",
            "logwizz rule=ssh_bruteforce src=198.51.100.24",
        ] {
            assert!(BanReport::parse(bad, "web1", 42).is_none(), "{bad}");
        }
    }

    #[test]
    fn v2_report_claims_only_observed_nftables_rule_and_preserves_v1() {
        let report = BanReport::parse(
            "LOGWIZZ_BAN_V2 jail=logwizz ip=198.51.100.24 bantime=3600",
            "web1\r\nbad",
            42,
        )
        .unwrap();
        assert!(report.verified);
        assert_eq!(report.host, "web1  bad");
        assert_eq!(report.to_json()["status"], "firewall_rule_verified");
        assert_eq!(
            report.to_json()["verification"],
            "nftables-set-and-input-drop-rule"
        );
        assert!(report.to_text().contains("nftables ban verified"));
        assert!(report.to_telegram_html().contains("input drop/reject rule"));
        assert!(
            report
                .to_telegram_html()
                .contains("<b>Event:</b> <code>fail2ban_action</code>")
        );
        assert!(
            report
                .to_telegram_html()
                .contains("<b>Host:</b> 🟪 <code>web1</code>")
        );
        assert!(
            report
                .to_telegram_html()
                .contains("<b>Status:</b> Firewall rule verified")
        );
        let saved = serde_json::to_value(&report).unwrap();
        let restored: BanReport = serde_json::from_value(saved).unwrap();
        assert_eq!(restored, report);

        // Older persisted reports carry no V2 flag, preserving their semantics.
        let mut legacy = serde_json::to_value(&report).unwrap();
        legacy.as_object_mut().unwrap().remove("verified");
        let old: BanReport = serde_json::from_value(legacy).unwrap();
        assert!(!old.verified);
        assert_eq!(old.to_json()["status"], "actionban_reported");
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
