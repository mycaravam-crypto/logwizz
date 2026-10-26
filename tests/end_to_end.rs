//! Runs the `logwizz` binary against temporary files and checks its output,
//! signal handling and exit codes.

mod common;

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::{Duration, Instant};

use common::{append, write_new};

const RULES: &str = r#"
[[rules]]
id = "ssh_failed_login"
description = "Failed SSH authentication"
match_type = "literal"
pattern = "Failed password"
severity = "warning"

[[rules]]
id = "kernel_error"
description = "Kernel error messages"
match_type = "regex"
pattern = "(?i)(kernel panic|out of memory)"
severity = "critical"
"#;

struct Daemon {
    child: Child,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
}

fn lines_of(r: impl std::io::Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        for line in BufReader::new(r).lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

impl Daemon {
    fn start(dir: &Path, config: &str) -> Self {
        let cfg = dir.join("logwizz.toml");
        fs::write(&cfg, config).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_logwizz"))
            .arg("--config")
            .arg(&cfg)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = lines_of(child.stdout.take().unwrap());
        let stderr = lines_of(child.stderr.take().unwrap());
        let d = Daemon {
            child,
            stdout,
            stderr,
        };
        d.wait_stderr("logwizz started");
        d
    }

    fn wait_stderr(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.stderr.recv_timeout(left) {
                Ok(l) if l.contains(needle) => return l,
                Ok(_) => {}
                Err(_) => panic!("{needle:?} not seen on stderr"),
            }
        }
    }

    fn event(&self) -> serde_json::Value {
        let line = self
            .stdout
            .recv_timeout(Duration::from_secs(3))
            .expect("no event on stdout");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("invalid JSON {line:?}: {e}"))
    }

    fn signal(&self, sig: libc::c_int) {
        // SAFETY: plain syscall on our own child's pid.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, sig) },
            0
        );
    }

    fn wait(&mut self, within: Duration) -> ExitStatus {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("daemon did not exit within {within:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(&mut self) -> ExitStatus {
        self.signal(libc::SIGTERM);
        self.wait(Duration::from_secs(5))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn config(general: &str, files: &[&Path], extra: &str) -> String {
    let mut s = format!("[general]\ndiagnostics = \"info\"\n{general}\n{extra}\n{RULES}");
    for f in files {
        s.push_str(&format!(
            "[[files]]\npath = {:?}\n",
            f.display().to_string()
        ));
    }
    s
}

#[test]
fn emits_json_events_and_stops_on_sigterm() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    let kern = dir.path().join("kern.log");
    write_new(&auth, "Failed password for root from 10.0.0.1\nunrelated\n");
    write_new(&kern, "");
    let mut d = Daemon::start(
        dir.path(),
        &config("startup_mode = \"beginning\"", &[&auth, &kern], ""),
    );

    let ev = d.event();
    assert_eq!(ev["v"], 1);
    assert_eq!(ev["rule"], "ssh_failed_login");
    assert_eq!(ev["severity"], "warning");
    assert_eq!(ev["match_type"], "literal");
    assert_eq!(ev["file"], auth.display().to_string());
    assert_eq!(ev["line"], "Failed password for root from 10.0.0.1");
    assert_eq!(ev["truncated"], false);
    assert_eq!(ev["pid"], d.child.id());
    assert!(ev["ts"].as_str().unwrap().ends_with('Z'));

    append(&kern, "Kernel panic - not syncing\n");
    let ev = d.event();
    assert_eq!(ev["rule"], "kernel_error");
    assert_eq!(ev["severity"], "critical");
    assert_eq!(ev["file"], kern.display().to_string());

    // One line matching both rules yields two events.
    append(&kern, "Failed password; Out Of Memory\n");
    let mut rules = [d.event()["rule"].clone(), d.event()["rule"].clone()];
    rules.sort_by_key(|v| v.to_string());
    assert_eq!(rules, ["kernel_error", "ssh_failed_login"]);

    let status = d.stop();
    assert!(status.success(), "{status:?}");
    let stopped = d.wait_stderr("logwizz stopped");
    assert!(stopped.contains("events_emitted=4"), "{stopped}");
}

#[test]
fn tail_mode_ignores_existing_lines() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "Failed password old\n");
    let mut d = Daemon::start(dir.path(), &config("", &[&auth], ""));
    thread::sleep(Duration::from_millis(300));
    append(&auth, "Failed password new\n");
    assert_eq!(d.event()["line"], "Failed password new");
    assert!(d.stdout.recv_timeout(Duration::from_millis(200)).is_err());
    assert!(d.stop().success());
}

#[test]
fn human_output_format() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "Failed password \x1b[2J\n");
    let mut d = Daemon::start(
        dir.path(),
        &config(
            "startup_mode = \"beginning\"",
            &[&auth],
            "[output]\nformat = \"human\"\n",
        ),
    );
    let line = d.stdout.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(
        line.ends_with(&format!(
            " WARNING  [ssh_failed_login] {}: Failed password \\u{{1b}}[2J",
            auth.display()
        )),
        "{line}"
    );
    assert!(d.stop().success());
}

#[test]
fn follows_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "");
    let mut d = Daemon::start(dir.path(), &config("", &[&auth], ""));
    thread::sleep(Duration::from_millis(300));
    append(&auth, "Failed password 1\n");
    assert_eq!(d.event()["line"], "Failed password 1");
    fs::rename(&auth, dir.path().join("auth.log.1")).unwrap();
    write_new(&auth, "Failed password 2\n");
    assert_eq!(d.event()["line"], "Failed password 2");
    assert!(d.stop().success());
}

#[test]
fn closed_stdout_exits_with_failure() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "");
    let cfg_path = dir.path().join("logwizz.toml");
    fs::write(&cfg_path, config("", &[&auth], "")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_logwizz"))
        .arg("--config")
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Close the read end of the pipe: writes will fail with EPIPE.
    drop(child.stdout.take());
    let stderr = lines_of(child.stderr.take().unwrap());
    thread::sleep(Duration::from_millis(300));
    append(&auth, "Failed password\n");
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "daemon kept running");
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(1));
    let err: Vec<String> = stderr.try_iter().collect();
    assert!(
        err.iter().any(|l| l.contains("writing events failed")),
        "{err:?}"
    );
}

#[test]
fn sigusr1_logs_statistics_and_limits_are_counted() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "");
    let mut d = Daemon::start(
        dir.path(),
        &config(
            "",
            &[&auth],
            "[limits]\nrate_limit_events = 2\nrate_limit_window_secs = 3600\n\
             dedup_window_secs = 3600\n",
        ),
    );
    thread::sleep(Duration::from_millis(300));
    append(
        &auth,
        "Failed password a\nFailed password a\nFailed password b\nFailed password c\n",
    );
    assert_eq!(d.event()["line"], "Failed password a");
    assert_eq!(d.event()["line"], "Failed password b");
    assert!(d.stdout.recv_timeout(Duration::from_millis(300)).is_err());
    d.signal(libc::SIGUSR1);
    let stats = d.wait_stderr("statistics");
    for expected in [
        "files_monitored=1",
        "lines_processed=4",
        "rule_matches=4",
        "events_emitted=2",
        "events_deduplicated=1",
        "events_rate_limited=1",
    ] {
        assert!(stats.contains(expected), "{expected} missing: {stats}");
    }
    assert!(d.stop().success());
}

#[test]
fn excluded_sources_are_not_reported() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "");
    let rule = r#"
[[rules]]
id = "ssh_from"
match_type = "regex"
pattern = 'Accepted password .* from (?P<src>\S+)'
severity = "notice"
[rules.exclude]
src = ["192.0.2.0/24"]
"#;
    let mut d = Daemon::start(dir.path(), &config("", &[&auth], rule));
    thread::sleep(Duration::from_millis(300));
    append(
        &auth,
        "Accepted password for a from 192.0.2.7
Accepted password for b from 198.51.100.7
",
    );
    assert_eq!(d.event()["fields"]["src"], "198.51.100.7");
    assert!(d.stdout.recv_timeout(Duration::from_millis(300)).is_err());
    d.signal(libc::SIGUSR1);
    let stats = d.wait_stderr("statistics");
    assert!(stats.contains("rule_matches=2"), "{stats}");
    assert!(stats.contains("matches_excluded=1"), "{stats}");
    assert!(d.stop().success());
}

#[test]
fn after_rule_reports_only_logins_from_earlier_scanners() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "");
    let rules = r#"
[[rules]]
id = "probe"
match_type = "regex"
pattern = 'Did not receive identification string from (?P<src>\S+)'
severity = "warning"

[[rules]]
id = "login_after_probe"
match_type = "regex"
pattern = 'Accepted publickey for \S+ from (?P<src>\S+)'
severity = "critical"
[rules.after]
rules = ["probe"]
field = "src"
within_secs = 3600
"#;
    let mut d = Daemon::start(dir.path(), &config("", &[&auth], rules));
    thread::sleep(Duration::from_millis(300));
    append(
        &auth,
        "Accepted publickey for a from 203.0.113.9 port 1
Did not receive identification string from 203.0.113.9 port 2
Accepted publickey for a from 198.51.100.7 port 3
Accepted publickey for a from 203.0.113.9 port 4
",
    );
    assert_eq!(d.event()["rule"], "probe");
    let ev = d.event();
    assert_eq!(ev["rule"], "login_after_probe");
    assert_eq!(ev["fields"]["src"], "203.0.113.9");
    assert!(ev["line"].as_str().unwrap().ends_with("port 4"), "{ev}");
    assert!(d.stdout.recv_timeout(Duration::from_millis(300)).is_err());
    d.signal(libc::SIGUSR1);
    let stats = d.wait_stderr("statistics");
    for expected in ["rule_matches=4", "after_unmatched=2", "events_emitted=2"] {
        assert!(stats.contains(expected), "{expected} missing: {stats}");
    }
    assert!(d.stop().success());
}

const NEW_RULE: &str = r#"
[[rules]]
id = "new_rule"
description = "Added on reload"
match_type = "literal"
pattern = "NEWMARK"
severity = "notice"
"#;

impl Daemon {
    /// Replaces the configuration file and sends SIGHUP; waits for the
    /// diagnostic containing `outcome`.
    fn reload(&self, dir: &Path, config: &str, outcome: &str) {
        fs::write(dir.join("logwizz.toml"), config).unwrap();
        self.signal(libc::SIGHUP);
        self.wait_stderr(outcome);
    }

    fn stats(&self) -> String {
        self.signal(libc::SIGUSR1);
        self.wait_stderr("statistics")
    }

    fn no_event(&self) {
        if let Ok(line) = self.stdout.recv_timeout(Duration::from_millis(500)) {
            panic!("unexpected event {line}");
        }
    }
}

#[test]
fn reload_adds_rules_and_keeps_offsets() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "");
    let mut d = Daemon::start(dir.path(), &config("", &[&auth], ""));
    thread::sleep(Duration::from_millis(300));
    append(&auth, "Failed password before\nNEWMARK before\n");
    assert_eq!(d.event()["rule"], "ssh_failed_login");
    d.no_event();

    // The new rule comes first, so every existing rule changes its index.
    d.reload(
        dir.path(),
        &config("", &[&auth], NEW_RULE),
        "configuration reloaded",
    );
    append(&auth, "NEWMARK after\nFailed password after\n");
    let ev = d.event();
    assert_eq!(ev["rule"], "new_rule");
    assert_eq!(ev["line"], "NEWMARK after");
    let ev = d.event();
    assert_eq!(ev["rule"], "ssh_failed_login");
    assert_eq!(ev["line"], "Failed password after");
    d.no_event();
    assert!(d.stats().contains("config_reloads=1"));
    assert!(d.stop().success());
}

#[test]
fn invalid_reload_keeps_running_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "");
    let mut d = Daemon::start(dir.path(), &config("", &[&auth], ""));
    let bad = config("", &[&auth], NEW_RULE).replace("pattern = \"NEWMARK\"", "pattern = 7");
    d.reload(dir.path(), &bad, "configuration reload failed");
    thread::sleep(Duration::from_millis(300));
    append(&auth, "NEWMARK\nFailed password\n");
    assert_eq!(d.event()["rule"], "ssh_failed_login");
    d.no_event();
    let stats = d.stats();
    assert!(stats.contains("config_reloads=0"), "{stats}");
    assert!(stats.contains("config_reload_failures=1"), "{stats}");
    assert!(d.stop().success());
}

#[test]
fn reload_removes_and_adds_files() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.log");
    let b = dir.path().join("b.log");
    let c = dir.path().join("c.log");
    write_new(&a, "");
    write_new(&b, "");
    write_new(&c, "Failed password already in c\n");
    let mut d = Daemon::start(dir.path(), &config("", &[&a, &b], ""));
    thread::sleep(Duration::from_millis(300));
    append(&a, "Failed password incomplete in a");
    thread::sleep(Duration::from_millis(300));

    // a is removed, c added before b, so b moves to another index.
    d.reload(
        dir.path(),
        &config("", &[&c, &b], ""),
        "configuration reloaded",
    );
    // a's incomplete last line is still emitted, under its own name.
    let ev = d.event();
    assert_eq!(ev["file"], a.display().to_string());
    assert_eq!(ev["line"], "Failed password incomplete in a");
    // c is new to this process: read from the beginning.
    let ev = d.event();
    assert_eq!(ev["file"], c.display().to_string());
    assert_eq!(ev["line"], "Failed password already in c");

    append(&a, "\nFailed password a is no longer read\n");
    d.no_event();
    append(&b, "Failed password in b\n");
    let ev = d.event();
    assert_eq!(ev["file"], b.display().to_string());
    assert_eq!(ev["line"], "Failed password in b");
    assert!(d.stop().success());
}

#[test]
fn reload_keeps_settings_that_need_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "");
    let mut d = Daemon::start(dir.path(), &config("", &[&auth], ""));
    let changed = config("", &[&auth], "[output]\nformat = \"human\"\n");
    let warning = {
        fs::write(dir.path().join("logwizz.toml"), &changed).unwrap();
        d.signal(libc::SIGHUP);
        d.wait_stderr("only after a restart")
    };
    assert!(warning.contains("output.format"), "{warning}");
    d.wait_stderr("configuration reloaded");
    thread::sleep(Duration::from_millis(300));
    append(&auth, "Failed password\n");
    assert_eq!(d.event()["rule"], "ssh_failed_login", "still JSON");
    assert!(d.stop().success());
}

#[test]
fn diagnostics_do_not_contain_log_content() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.log");
    write_new(&auth, "");
    let cfg = config("", &[&auth], "").replace("diagnostics = \"info\"", "diagnostics = \"trace\"");
    let mut d = Daemon::start(dir.path(), &cfg);
    thread::sleep(Duration::from_millis(300));
    append(&auth, "Failed password SECRET-TOKEN-123\n");
    assert!(
        d.event()["line"]
            .as_str()
            .unwrap()
            .contains("SECRET-TOKEN-123")
    );
    d.stop();
    let err: Vec<String> = d.stderr.try_iter().collect();
    assert!(!err.iter().any(|l| l.contains("SECRET-TOKEN")), "{err:?}");
}

#[test]
fn glob_events_name_the_matched_file() {
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("app");
    fs::create_dir(&logs).unwrap();
    let a = logs.join("a.log");
    write_new(&a, "Failed password at startup\n");
    let glob = format!(
        "[[files]]\nglob = {:?}\n",
        logs.join("*.log").display().to_string()
    );
    let mut d = Daemon::start(
        dir.path(),
        &config("startup_mode = \"beginning\"", &[], &glob),
    );
    let ev = d.event();
    assert_eq!(ev["file"], a.display().to_string());
    assert_eq!(ev["line"], "Failed password at startup");

    let b = logs.join("b.log");
    write_new(&b, "Failed password in a new file\n");
    let ev = d.event();
    assert_eq!(ev["file"], b.display().to_string());
    assert_eq!(ev["line"], "Failed password in a new file");
    assert!(d.stop().success());
}

#[test]
fn ignore_rules_and_catch_all_report_unknown_lines() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("app.log");
    write_new(&log, "");
    let rules = "[[rules]]\nid = \"noise\"\nmatch_type = \"literal\"\npattern = \"heartbeat\"\n\
                 action = \"ignore\"\n\n[[rules]]\nid = \"unknown\"\nmatch_type = \"regex\"\n\
                 pattern = \"^\"\nseverity = \"notice\"\n";
    let mut d = Daemon::start(dir.path(), &config("", &[&log], rules));
    thread::sleep(Duration::from_millis(300));
    append(
        &log,
        "heartbeat ok\nsomething new\nheartbeat Failed password\n",
    );
    let ev = d.event();
    assert_eq!(
        (ev["rule"].as_str(), ev["line"].as_str()),
        (Some("unknown"), Some("something new"))
    );
    // "heartbeat Failed password" is ignored before ssh_failed_login sees it.
    assert!(d.stdout.recv_timeout(Duration::from_millis(300)).is_err());
    d.signal(libc::SIGUSR1);
    let stats = d.wait_stderr("statistics");
    assert!(stats.contains("lines_ignored=2 rule_matches=1"), "{stats}");
    assert!(d.stop().success());
}

#[test]
fn threshold_rule_reports_a_port_scan_once() {
    let dir = tempfile::tempdir().unwrap();
    let kern = dir.path().join("kern.log");
    write_new(&kern, "");
    let rules = r#"
[[rules]]
id = "port_scan"
match_type = "regex"
pattern = 'logwizz-drop: .*SRC=(?P<src>\S+) .*DPT=(?P<dpt>\d+)'
severity = "critical"
[rules.threshold]
group_by = "src"
distinct = "dpt"
count = 20
window_secs = 10
cooldown_secs = 300
"#;
    let mut d = Daemon::start(dir.path(), &config("", &[&kern], rules));
    thread::sleep(Duration::from_millis(300));
    let fw = |src: &str, dpt: u32| {
        format!(
            "Oct 25 10:00:00 web1 kernel: logwizz-drop: IN=eth0 OUT= SRC={src} DST=198.51.100.1 \
             LEN=44 PROTO=TCP SPT=40000 DPT={dpt} WINDOW=1024 RES=0x00 SYN URGP=0\n"
        )
    };
    let mut lines = String::new();
    // A busy client hitting one port many times is not a scan.
    for _ in 0..50 {
        lines.push_str(&fw("192.0.2.10", 443));
    }
    // A scanner: 100 distinct ports, reported once (then the cooldown).
    for port in 1..=100 {
        lines.push_str(&fw("203.0.113.66", port));
    }
    append(&kern, &lines);
    let ev = d.event();
    assert_eq!(ev["rule"], "port_scan");
    assert_eq!(ev["severity"], "critical");
    assert_eq!(ev["fields"]["src"], "203.0.113.66");
    assert_eq!(ev["fields"]["dpt"], "20");
    assert_eq!(
        ev["threshold"],
        serde_json::json!({"group": "203.0.113.66", "count": 20, "window_secs": 10,
            "distinct": "dpt", "values": ["1", "2", "3", "4", "5", "6", "7", "8"]})
    );
    assert!(d.stdout.recv_timeout(Duration::from_millis(300)).is_err());
    d.signal(libc::SIGUSR1);
    let stats = d.wait_stderr("statistics");
    for expected in [
        "rule_matches=150",
        "threshold_absorbed=149",
        "threshold_fired=1",
        "events_emitted=1",
    ] {
        assert!(stats.contains(expected), "{expected} missing: {stats}");
    }
    assert!(d.stop().success());
}

#[test]
fn reload_keeps_glob_offsets_and_switches_globs() {
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("app");
    fs::create_dir(&logs).unwrap();
    let (a, b) = (logs.join("a.log"), logs.join("b.txt"));
    write_new(&a, "");
    write_new(&b, "Failed password already in b\n");
    let glob = |pattern: &str| {
        format!(
            "[[files]]\nglob = {:?}\n",
            logs.join(pattern).display().to_string()
        )
    };
    let mut d = Daemon::start(dir.path(), &config("", &[], &glob("*.log")));
    thread::sleep(Duration::from_millis(300));
    append(&a, "Failed password before\n");
    assert_eq!(d.event()["line"], "Failed password before");

    // a.log stays matched and keeps its offset; b.txt is new to this
    // process and is read from the beginning.
    d.reload(
        dir.path(),
        &config("", &[], &format!("{}{}", glob("*.log"), glob("*.txt"))),
        "configuration reloaded",
    );
    let ev = d.event();
    assert_eq!(ev["file"], b.display().to_string());
    assert_eq!(ev["line"], "Failed password already in b");
    d.no_event();

    // Dropping the *.log glob stops reading a.log.
    d.reload(
        dir.path(),
        &config("", &[], &glob("*.txt")),
        "configuration reloaded",
    );
    append(&a, "Failed password ignored\n");
    append(&b, "Failed password after\n");
    assert_eq!(d.event()["line"], "Failed password after");
    d.no_event();
    assert!(d.stop().success());
}
