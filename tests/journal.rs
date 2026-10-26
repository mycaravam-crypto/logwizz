//! Journal input end to end, with a fake `journalctl` first on `PATH` that
//! records its arguments and prints a prepared feed.

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::{Duration, Instant};

const RULES: &str = r#"
[[rules]]
id = "ssh"
match_type = "regex"
pattern = 'Failed password for \S+ from (?P<src>\S+)'
severity = "warning"
"#;

/// `follow`: keep running after the feed like `journalctl -f`; otherwise
/// exit, so that logwizz has to restart it.
fn fake_journalctl(dir: &Path, feed: &str, follow: bool) {
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(dir.join("feed"), feed).unwrap();
    let tail = if follow { "exec sleep 1000" } else { "exit 0" };
    let script = format!(
        "#!/bin/sh\necho \"$@\" >> '{d}/args'\ncat '{d}/feed'\n{tail}\n",
        d = dir.display()
    );
    let path = bin.join("journalctl");
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct Daemon {
    child: Child,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
}

fn lines_of(r: impl std::io::Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        for line in BufReader::new(r).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

impl Daemon {
    fn start(dir: &Path, config: &str) -> Self {
        let cfg = dir.join("logwizz.toml");
        fs::write(&cfg, config).unwrap();
        let path = format!(
            "{}:{}",
            dir.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_logwizz"))
            .arg("--config")
            .arg(&cfg)
            .env("PATH", path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = lines_of(child.stdout.take().unwrap());
        let stderr = lines_of(child.stderr.take().unwrap());
        Daemon {
            child,
            stdout,
            stderr,
        }
    }

    fn event(&self) -> serde_json::Value {
        let line = self
            .stdout
            .recv_timeout(Duration::from_secs(5))
            .expect("no event on stdout");
        serde_json::from_str(&line).unwrap()
    }

    fn wait_stderr(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.stderr.recv_timeout(left) {
                Ok(l) if l.contains(needle) => return l,
                Ok(_) => {}
                Err(_) => panic!("{needle:?} not seen on stderr"),
            }
        }
    }

    fn stop(mut self) {
        // SAFETY: plain kill(2) on our own child's pid.
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        assert!(self.child.wait().unwrap().success());
    }
}

fn entry(cursor: &str, message: &str) -> String {
    format!(
        "{{\"__CURSOR\":\"{cursor}\",\"MESSAGE\":{},\"_TRANSPORT\":\"syslog\"}}\n",
        serde_json::to_string(message).unwrap()
    )
}

#[test]
fn journal_entries_are_matched_and_the_cursor_is_saved() {
    let dir = tempfile::tempdir().unwrap();
    let mut feed = entry("c1", "Failed password for root from 192.0.2.7 port 22 ssh2");
    feed.push_str("{\"__CURSOR\":\"c2\"}\n"); // no MESSAGE
    feed.push_str("not json\n");
    // Not valid UTF-8: journalctl writes a byte array. "Failed password for x from y\xff"
    let mut bytes: Vec<u8> = b"Failed password for x from 192.0.2.8".to_vec();
    bytes.push(0xff);
    feed.push_str(&format!(
        "{{\"__CURSOR\":\"c3\",\"MESSAGE\":{}}}\n",
        serde_json::to_string(&bytes).unwrap()
    ));
    fake_journalctl(dir.path(), &feed, true);
    let state = dir.path().join("offsets.json");
    let config = format!(
        "[general]\ndiagnostics = \"info\"\nstate_file = {:?}\nstate_flush_ms = 100\n\n[journal]\nmatches = [\"SYSLOG_IDENTIFIER=sshd\"]\n{RULES}",
        state.display().to_string()
    );

    let d = Daemon::start(dir.path(), &config);
    let ev = d.event();
    assert_eq!(ev["file"], "journal");
    assert_eq!(ev["rule"], "ssh");
    assert_eq!(ev["fields"]["src"], "192.0.2.7");
    let ev = d.event();
    assert_eq!(ev["line"], "Failed password for x from 192.0.2.8\u{fffd}");
    // SAFETY: plain kill(2) on our own child's pid.
    unsafe { libc::kill(d.child.id() as i32, libc::SIGUSR1) };
    let stats = d.wait_stderr("statistics");
    assert!(stats.contains("journal_entries_skipped=1"), "{stats}");
    assert!(stats.contains("lines_processed=2"), "{stats}");
    d.stop();

    let args = fs::read_to_string(dir.path().join("args")).unwrap();
    assert_eq!(
        args.lines().next().unwrap(),
        "--follow --output=json --no-pager --lines=0 SYSLOG_IDENTIFIER=sshd"
    );
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    assert_eq!(saved["journal_cursor"], "c3");

    // A restart continues after the saved cursor.
    fs::write(dir.path().join("feed"), "").unwrap();
    let d = Daemon::start(dir.path(), &config);
    d.wait_stderr("following the journal");
    thread::sleep(Duration::from_millis(300));
    d.stop();
    let args = fs::read_to_string(dir.path().join("args")).unwrap();
    assert!(
        args.lines().nth(1).unwrap().contains("--after-cursor=c3"),
        "{args}"
    );
}

#[test]
fn journalctl_is_restarted_after_the_last_cursor() {
    let dir = tempfile::tempdir().unwrap();
    fake_journalctl(
        dir.path(),
        &entry("k7", "Failed password for root from 192.0.2.9 port 22 ssh2"),
        false,
    );
    let config = format!("[general]\ndiagnostics = \"info\"\n\n[journal]\n{RULES}");
    let d = Daemon::start(dir.path(), &config);
    assert_eq!(d.event()["fields"]["src"], "192.0.2.9");
    d.wait_stderr("journalctl exited; restarting");
    // The restart (after a 1 s delay) asks for entries after k7 only, so
    // the entry the fake prints again is a duplicate the real journalctl
    // would not send; it is enough to check the arguments.
    let deadline = Instant::now() + Duration::from_secs(5);
    let args = loop {
        let args = fs::read_to_string(dir.path().join("args")).unwrap_or_default();
        if args.lines().count() >= 2 || Instant::now() > deadline {
            break args;
        }
        thread::sleep(Duration::from_millis(50));
    };
    assert!(
        args.lines()
            .nth(1)
            .is_some_and(|l| l.contains("--after-cursor=k7")),
        "{args}"
    );
    d.stop();
}

#[test]
fn thresholds_count_in_journal_time_when_catching_up() {
    let dir = tempfile::tempdir().unwrap();
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros();
    let at = |cursor: &str, ago_secs: u128, src: &str| {
        format!(
            "{{\"__CURSOR\":\"{cursor}\",\"__REALTIME_TIMESTAMP\":\"{}\",\
             \"MESSAGE\":\"Failed password for root from {src} port 22 ssh2\"}}\n",
            now_us - ago_secs * 1_000_000
        )
    };
    // Read all at once, but logged 30 s apart: no 3 within a minute.
    let mut feed = String::new();
    for (i, ago) in [93, 62, 31, 0].into_iter().enumerate() {
        feed.push_str(&at(&format!("a{i}"), ago, "192.0.2.1"));
    }
    // A real burst, logged within the same second.
    for i in 0..3 {
        feed.push_str(&at(&format!("b{i}"), 0, "192.0.2.2"));
    }
    fake_journalctl(dir.path(), &feed, true);
    let config = format!(
        "[general]\ndiagnostics = \"info\"\n\n[journal]\n{RULES}\
         [rules.threshold]\ngroup_by = \"src\"\ncount = 3\nwindow_secs = 60\n"
    );
    let d = Daemon::start(dir.path(), &config);
    let ev = d.event();
    assert_eq!(ev["fields"]["src"], "192.0.2.2");
    assert!(d.stdout.recv_timeout(Duration::from_millis(300)).is_err());
    d.stop();
}

#[test]
fn journal_replay_sliding_threshold_triggers_followup_only_for_matching_source() {
    let dir = tempfile::tempdir().unwrap();
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros();
    let at = |cursor: &str, ago: u128, message: &str| {
        format!(
            "{{\"__CURSOR\":\"{cursor}\",\"__REALTIME_TIMESTAMP\":\"{}\",\"MESSAGE\":{}}}\n",
            now_us - ago * 1_000_000,
            serde_json::to_string(message).unwrap()
        )
    };
    let source = "192.0.2.10";
    let mut feed = String::new();
    // Four probes cross the 60-second bucket boundary. The 3 initial
    // probes never fire a fixed count=4 threshold, but sliding does.
    for (cursor, ago) in [("p0", 120), ("p1", 65), ("p2", 65), ("p3", 59)] {
        feed.push_str(&at(cursor, ago, &format!("probe {source}")));
    }
    // The correlation uses journal time, not the moment these lines replay.
    feed.push_str(&at("l0", 58, &format!("login {source}")));
    feed.push_str(&at("l1", 57, "login 192.0.2.11"));
    fake_journalctl(dir.path(), &feed, true);
    let config = r#"
[general]
diagnostics = "info"
[journal]

[[rules]]
id = "probe"
match_type = "regex"
pattern = 'probe (?P<src>\S+)'
severity = "warning"
[rules.threshold]
group_by = "src"
count = 4
window_secs = 60
window = "sliding"

[[rules]]
id = "login_after_probe"
match_type = "regex"
pattern = 'login (?P<src>\S+)'
severity = "critical"
[rules.after]
rules = ["probe"]
field = "src"
within_secs = 60
"#;
    let d = Daemon::start(dir.path(), config);
    let first = d.event();
    let second = d.event();
    assert_eq!(first["rule"], "probe");
    assert_eq!(first["fields"]["src"], source);
    assert_eq!(second["rule"], "login_after_probe");
    assert_eq!(second["fields"]["src"], source);
    assert!(d.stdout.recv_timeout(Duration::from_millis(300)).is_err());
    d.stop();
}
