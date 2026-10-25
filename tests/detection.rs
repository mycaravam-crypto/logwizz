//! The rules in config/detection.toml against real log lines, and through
//! their thresholds.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use logwizz::config::{self, Config};
use logwizz::metrics::Metrics;
use logwizz::threshold::Thresholds;

fn detection() -> Config {
    config::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("config/detection.toml")).unwrap()
}

/// Rule ids matching `line`, with their captured fields as name=value.
fn hits(cfg: &Config, line: &str) -> Vec<String> {
    cfg.rules
        .iter()
        .filter(|r| r.id != "log_flood" && r.matcher.is_match(line.as_bytes()))
        .map(|r| {
            let fields: Vec<String> = r
                .matcher
                .fields(line.as_bytes())
                .iter()
                .map(|(i, v)| {
                    let name = r.matcher.group_name(*i).unwrap();
                    format!("{name}={}", String::from_utf8_lossy(v))
                })
                .collect();
            format!("{} {}", r.id, fields.join(" "))
        })
        .collect()
}

#[test]
fn rules_match_real_log_lines() {
    let cfg = detection();
    let fw = "Oct 25 10:00:00 web1 kernel: [ 812.123456] logwizz-drop: IN=eth0 OUT= \
              MAC=52:54:00:12:34:56:52:55:0a:00:02:02:08:00 SRC=203.0.113.66 DST=198.51.100.1 \
              LEN=44 TOS=0x00 PREC=0x00 TTL=41 ID=54321 PROTO=TCP SPT=61000 DPT=8080 \
              WINDOW=1024 RES=0x00 SYN URGP=0";
    assert_eq!(
        hits(&cfg, fw),
        [
            "port_scan src=203.0.113.66 dpt=8080",
            "fast_scan src=203.0.113.66 dpt=8080"
        ]
    );
    let fw6 = "Oct 25 10:00:00 web1 kernel: logwizz-drop: IN=eth0 OUT= SRC=2001:0db8:0000:0000:0000:0000:0000:0042 \
               DST=2001:0db8:0000:0000:0000:0000:0000:0001 LEN=60 PROTO=UDP SPT=53000 DPT=161 LEN=20";
    assert_eq!(
        hits(&cfg, fw6)[0],
        "port_scan src=2001:0db8:0000:0000:0000:0000:0000:0042 dpt=161"
    );
    let null = "Oct 25 10:00:01 web1 kernel: logwizz-badflags: IN=eth0 OUT= SRC=203.0.113.66 \
                DST=198.51.100.1 LEN=40 PROTO=TCP SPT=61000 DPT=22 WINDOW=1024 RES=0x00 URGP=0";
    assert_eq!(hits(&cfg, null), ["tcp_flag_scan src=203.0.113.66"]);
    for line in [
        "Oct 25 10:00:02 web1 sshd[1240]: Failed password for invalid user admin from 192.0.2.7 port 52144 ssh2",
        "Oct 25 10:00:02 web1 sshd-session[1240]: Failed password for root from 192.0.2.7 port 52144 ssh2",
        "Oct 25 10:00:02 web1 sshd[1240]: Invalid user oracle from 192.0.2.7 port 52144",
        "2026-10-25T10:00:02.123+00:00 web1 sshd[1240]: Failed publickey for git from 192.0.2.7 port 52144 ssh2: ED25519 SHA256:x",
    ] {
        assert_eq!(hits(&cfg, line), ["ssh_bruteforce src=192.0.2.7"], "{line}");
    }
    for line in [
        "Oct 25 10:00:03 web1 sshd[1250]: banner exchange: Connection from 192.0.2.8 port 40000: invalid format",
        "Oct 25 10:00:03 web1 sshd[1250]: Did not receive identification string from 192.0.2.8 port 40000",
    ] {
        assert_eq!(hits(&cfg, line), ["ssh_probe src=192.0.2.8"], "{line}");
    }
    let nse = r#"192.0.2.9 - - [25/Oct/2026:10:00:04 +0000] "GET /nmaplowercheck1729 HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)""#;
    assert_eq!(hits(&cfg, nse), ["scanner_user_agent src=192.0.2.9"]);
    // Normal traffic matches nothing.
    for line in [
        "Oct 25 10:00:05 web1 sshd[1260]: Accepted publickey for deploy from 10.0.0.5 port 52144 ssh2",
        r#"10.0.0.9 - - [25/Oct/2026:10:00:05 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8.5.0""#,
        "Oct 25 10:00:05 web1 kernel: eth0: link up, 1000Mbps, full-duplex",
    ] {
        assert!(hits(&cfg, line).is_empty(), "{line}");
    }
}

#[test]
fn port_scan_fires_once_per_source() {
    let cfg = detection();
    let i = cfg.rules.iter().position(|r| r.id == "port_scan").unwrap();
    let rule = &cfg.rules[i];
    let t = rule.threshold.as_ref().unwrap();
    let m = Arc::new(Metrics::default());
    let mut th = Thresholds::new(cfg.rules.len(), cfg.limits.threshold_max_groups, m);
    let now = Instant::now();
    let mut fired = Vec::new();
    for port in 1..=1000 {
        for src in ["203.0.113.66", "192.0.2.10"] {
            // 192.0.2.10 only ever talks to one closed port.
            let dpt = if src == "192.0.2.10" { 9 } else { port };
            let line = format!(
                "kernel: logwizz-drop: IN=eth0 SRC={src} DST=198.51.100.1 PROTO=TCP DPT={dpt} SYN"
            );
            let fields = rule.matcher.fields(line.as_bytes());
            if let Some(f) = th.observe(i, &rule.id, t, 0, &fields, now) {
                fired.push((
                    String::from_utf8_lossy(&f.group.unwrap()).into_owned(),
                    port,
                ));
            }
        }
    }
    assert_eq!(fired, [("203.0.113.66".to_string(), 20)]);
}
