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
        // PasswordAuthentication no: a real user's attempt only logs how it ended.
        "2026-10-25T14:14:25.245120+01:00 web1 sshd-session[55948]: Connection closed by authenticating user root 192.0.2.7 port 34280 [preauth]",
        "2026-10-25T14:14:25.245120+01:00 web1 sshd-session[55948]: Disconnected from authenticating user root 192.0.2.7 port 34280 [preauth]",
        "2026-10-25T14:14:25.245120+01:00 web1 sshd-session[55948]: Connection reset by authenticating user root 192.0.2.7 port 34280 [preauth]",
    ] {
        assert_eq!(hits(&cfg, line), ["ssh_bruteforce src=192.0.2.7"], "{line}");
    }
    for line in [
        "Oct 25 10:00:03 web1 sshd[1250]: banner exchange: Connection from 192.0.2.8 port 40000: invalid format",
        "Oct 25 10:00:03 web1 sshd[1250]: Did not receive identification string from 192.0.2.8 port 40000",
    ] {
        assert_eq!(hits(&cfg, line), ["ssh_probe src=192.0.2.8"], "{line}");
    }
    for line in [
        "Oct 25 10:00:03 web1 sudo: pam_unix(sudo:auth): authentication failure; logname=deploy uid=1000 euid=0 tty=/dev/pts/0 ruser=deploy rhost=  user=deploy",
        "Oct 25 10:00:03 web1 sudo:   deploy : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/sh",
        "Oct 25 10:00:03 web1 sudo:   guest : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/guest ; USER=root ; COMMAND=/bin/sh",
    ] {
        assert_eq!(hits(&cfg, line), ["sudo_auth_failure "], "{line}");
    }
    for line in [
        "2026-10-25T14:19:50.1+01:00 web1 usermod[56460]: add 'deploy' to group 'adm'",
        "Oct 25 10:00:04 web1 useradd[2001]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0",
        "Oct 25 10:00:04 web1 passwd[2002]: pam_unix(passwd:chauthtok): password changed for root",
    ] {
        assert_eq!(hits(&cfg, line), ["account_change "], "{line}");
    }
    let nse = r#"192.0.2.9 - - [25/Oct/2026:10:00:04 +0000] "GET /nmaplowercheck1729 HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)""#;
    assert_eq!(hits(&cfg, nse), ["scanner_user_agent src=192.0.2.9"]);
    let caddy = r#"{"level":"info","ts":1761398404.5,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"192.0.2.9","remote_port":"51000","client_ip":"192.0.2.9","proto":"HTTP/1.1","method":"GET","host":"example.org","uri":"/?id=1","headers":{"User-Agent":["sqlmap/1.8.4#stable (https://sqlmap.org)"]}},"status":404}"#;
    assert_eq!(hits(&cfg, caddy), ["scanner_user_agent src=192.0.2.9"]);
    assert_eq!(
        hits(
            &cfg,
            "2026-10-25T14:20:12.5+01:00 web1 sshd-session[56533]: Accepted publickey for deploy from 10.0.0.5 port 34092 ssh2: ED25519 SHA256:x"
        ),
        ["ssh_login login=deploy src=10.0.0.5"]
    );
    assert_eq!(
        hits(
            &cfg,
            "2026-10-25 01:08:51,101 fail2ban.actions        [46533]: NOTICE  [sshd] Ban 192.0.2.10"
        ),
        ["fail2ban_ban src=192.0.2.10"]
    );
    // Normal traffic matches nothing.
    for line in [
        "2026-10-25 01:08:51,105 fail2ban.observer       [46533]: NOTICE  [sshd] Increase Ban 192.0.2.10 (2 # 2h -> 2026-10-25 02:08:50)",
        "2026-10-25 00:49:38,450 fail2ban.actions        [46533]: NOTICE  [sshd] Unban 192.0.2.10",
        r#"{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"10.0.0.9","headers":{"User-Agent":["Mozilla/5.0"]}},"status":200}"#,
        // Invalid users are counted by their "Invalid user" line only.
        "Oct 25 10:00:05 web1 sshd-session[1260]: Connection closed by invalid user admin 192.0.2.7 port 52144 [preauth]",
        "Oct 25 10:00:05 web1 sshd-session[1260]: Received disconnect from 192.0.2.7 port 52144:11: Bye Bye [preauth]",
        "Oct 25 10:00:05 web1 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt update",
        "Oct 25 10:00:05 web1 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1000)",
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
            if let Some(f) =
                th.observe(i, &rule.id, t, Path::new("/var/log/kern.log"), &fields, now)
            {
                fired.push((
                    String::from_utf8_lossy(&f.group.unwrap()).into_owned(),
                    port,
                ));
            }
        }
    }
    assert_eq!(fired, [("203.0.113.66".to_string(), 20)]);
}

#[test]
fn every_detector_fires_at_its_count_and_then_cools_down() {
    let cfg = detection();
    let m = Arc::new(Metrics::default());
    let mut th = Thresholds::new(cfg.rules.len(), cfg.limits.threshold_max_groups, m);
    let file = Path::new("/var/log/test.log");
    // A line for each rule; `{n}` makes distinct values where the rule counts them.
    let lines = [
        (
            "port_scan",
            "kernel: logwizz-drop: IN=eth0 SRC=203.0.113.1 DST=198.51.100.1 PROTO=TCP DPT={n} SYN",
        ),
        (
            "fast_scan",
            "kernel: logwizz-drop: IN=eth0 SRC=203.0.113.2 DST=198.51.100.1 PROTO=TCP DPT={n} SYN",
        ),
        (
            "tcp_flag_scan",
            "kernel: logwizz-badflags: IN=eth0 SRC=203.0.113.3 DST=198.51.100.1 PROTO=TCP DPT={n}",
        ),
        (
            "ssh_bruteforce",
            "sshd[1]: Failed password for root from 192.0.2.4 port {n} ssh2",
        ),
        (
            "ssh_probe",
            "sshd[1]: banner exchange: Connection from 192.0.2.5 port {n}: invalid format",
        ),
        (
            "scanner_user_agent",
            "192.0.2.6 - - \"GET /{n} HTTP/1.1\" 404 1 \"-\" \"sqlmap/1.8\"",
        ),
        ("log_flood", "anything {n}"),
    ];
    let t0 = Instant::now();
    for (id, template) in lines {
        let i = cfg.rules.iter().position(|r| r.id == id).unwrap();
        let rule = &cfg.rules[i];
        let t = rule.threshold.as_ref().unwrap();
        let mut observe = |n: u32, at: Instant| {
            let line = template.replace("{n}", &n.to_string());
            assert!(rule.matcher.is_match(line.as_bytes()), "{id}: {line}");
            let fields = rule.matcher.fields(line.as_bytes());
            th.observe(i, id, t, file, &fields, at)
        };
        for n in 1..t.count {
            assert!(observe(n, t0).is_none(), "{id} fired early at {n}");
        }
        let fired = observe(t.count, t0).unwrap_or_else(|| panic!("{id} did not fire"));
        assert_eq!(fired.count, t.count, "{id}");
        // Silent for the cooldown, however many more matches arrive.
        let during = t0 + t.cooldown - std::time::Duration::from_millis(1);
        for n in 0..t.count * 2 {
            assert!(
                observe(10_000 + n, during).is_none(),
                "{id} fired in its cooldown"
            );
        }
    }
}
