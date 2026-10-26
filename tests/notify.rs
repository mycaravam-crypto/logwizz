//! End-to-end tests of the logwizz-notify binary, with journalctl and curl
//! replaced by scripts on PATH.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const RAW: &str = "RAW-SECRET-SHOULD-NOT-LEAVE-HOST";
const TOKEN: &str = "123456:ABC_def-123";
const URL: &str = "https://example.invalid/logwizz";

/// Prints the fixture after the line holding the `--after-cursor` cursor,
/// then follows forever (like `journalctl -f`) unless JOURNAL_EXIT is set.
const JOURNALCTL: &str = r#"#!/bin/sh
if [ "$1" = "--help" ]; then
  echo "  --namespace=NAME  Show logs from the specified journal namespace"
  exit 0
fi
printf '%s\n' "$@" > "$WORK/journalctl.args"
cursor=
for arg do case "$arg" in --after-cursor=*) cursor=${arg#--after-cursor=} ;; esac; done
if [ -n "$cursor" ]; then
  awk -v c="\"__CURSOR\":\"$cursor\"" 'found { print } index($0, c) { found = 1 }' "$WORK/journal.jsonl"
else
  cat "$WORK/journal.jsonl"
fi
[ -n "$JOURNAL_EXIT" ] && exit 0
exec sleep 1000
"#;

/// Saves its arguments and its stdin (the config with the request) per call.
const CURL: &str = r#"#!/bin/sh
n=$(find "$WORK/requests" -name '*.conf' | wc -l)
printf '%s\n' "$@" > "$WORK/requests/$n.args"
cat > "$WORK/requests/$n.conf"
[ -f "$WORK/curl-fail" ] && { echo "curl: (22) The requested URL returned error: 503" >&2; exit 22; }
printf '{"ok":true}\n'
"#;

struct Work {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl Work {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        fs::create_dir_all(path.join("bin")).unwrap();
        fs::create_dir_all(path.join("requests")).unwrap();
        fs::create_dir_all(path.join("state")).unwrap();
        for (name, body) in [("journalctl", JOURNALCTL), ("curl", CURL)] {
            let p = path.join("bin").join(name);
            fs::write(&p, body).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(path.join("journal.jsonl"), "").unwrap();
        Work { _dir: dir, path }
    }

    fn journal(&self, entries: &[Value]) {
        let text: String = entries.iter().map(|e| format!("{e}\n")).collect();
        fs::write(self.path.join("journal.jsonl"), text).unwrap();
    }

    fn start(&self, env: &[(&str, &str)]) -> Child {
        let path = format!(
            "{}:{}",
            self.path.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_logwizz-notify"));
        cmd.env_clear()
            .env("PATH", path)
            .env("WORK", &self.path)
            .env("STATE_DIRECTORY", self.path.join("state"))
            .envs(env.iter().copied())
            .stdout(Stdio::null())
            .stderr(fs::File::create(self.path.join("stderr")).unwrap());
        cmd.spawn().unwrap()
    }

    fn state(&self) -> Value {
        fs::read(self.path.join("state/state.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null)
    }

    /// Waits until the saved state has consumed up to `cursor`.
    fn wait_cursor(&self, cursor: &str) {
        let start = Instant::now();
        while self.state()["cursor"] != cursor {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "cursor {cursor} not reached; state {} stderr {}",
                self.state(),
                self.stderr()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stderr(&self) -> String {
        fs::read_to_string(self.path.join("stderr")).unwrap_or_default()
    }

    /// The curl configs passed so far, each as (option, value) pairs.
    fn requests(&self) -> Vec<Vec<(String, String)>> {
        let mut out = Vec::new();
        for n in 0.. {
            let Ok(text) = fs::read_to_string(self.path.join(format!("requests/{n}.conf"))) else {
                break;
            };
            out.push(text.lines().map(parse_option).collect());
        }
        out
    }

    fn all_args(&self) -> String {
        let mut s = String::new();
        for e in fs::read_dir(self.path.join("requests")).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "args") {
                s.push_str(&fs::read_to_string(p).unwrap());
            }
        }
        s
    }
}

/// `name = "value"` with curl's escapes.
fn parse_option(line: &str) -> (String, String) {
    let (name, rest) = line.split_once(" = \"").expect(line);
    let rest = rest.strip_suffix('"').expect(line);
    let mut v = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next().unwrap() {
                'n' => v.push('\n'),
                'r' => v.push('\r'),
                't' => v.push('\t'),
                c => v.push(c),
            }
        } else {
            v.push(c);
        }
    }
    (name.to_string(), v)
}

fn value<'a>(req: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    req.iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
        .collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn ts(secs: u64) -> String {
    logwizz::event::format_rfc3339_secs(secs)
}

fn event(cursor: &str, rule: &str, ts: &str, src: Option<&str>) -> Value {
    let mut ev = json!({
        "v": 1, "ts": ts, "host": "test-host", "rule": rule,
        "description": "Failed SSH authentication", "severity": "warning", "line": RAW,
    });
    if let Some(src) = src {
        ev["fields"] = json!({"src": src, "user": RAW});
    }
    json!({"__CURSOR": cursor, "MESSAGE": ev.to_string(), "__REALTIME_TIMESTAMP": format!("{}000000", now())})
}

fn stop(child: &mut Child) -> ExitStatus {
    // SAFETY: plain kill(2) on our own child.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "did not stop");
        thread::sleep(Duration::from_millis(20));
    }
}

/// With hour-long windows, [`open_ts`] stays in an open window for the
/// whole test whatever the clock does.
const WEBHOOK: [(&str, &str); 4] = [
    ("NOTIFY_KIND", "webhook"),
    ("NOTIFY_URL", URL),
    ("NOTIFY_AUTH", "Bearer tk_LWZ"),
    ("NOTIFY_WINDOW_SECS", "3600"),
];

/// Seconds half an hour ahead: its 3600-second window ends at least half
/// an hour from now.
fn open_secs() -> u64 {
    now() + 1800
}

fn open_ts() -> String {
    ts(open_secs())
}

#[test]
fn webhook_summary_on_stop_and_resume_after_cursor() {
    let w = Work::new();
    let t = open_ts();
    w.journal(&[
        event("c1", "ssh_failed_login", &t, Some("203.0.113.7")),
        event("c2", "ssh_failed_login", &t, Some("203.0.113.7")),
        event("c3", "ssh_failed_login", &t, Some("203.0.113.8")),
        json!({"__CURSOR": "c4", "MESSAGE": "logwizz started"}),
    ]);
    let mut child = w.start(&WEBHOOK);
    w.wait_cursor("c4");
    assert!(w.requests().is_empty(), "the window is still open");
    assert!(stop(&mut child).success(), "{}", w.stderr());

    let reqs = w.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(value(&reqs[0], "url"), [URL]);
    assert!(value(&reqs[0], "header").contains(&"Authorization: Bearer tk_LWZ"));
    let body: Value = serde_json::from_str(value(&reqs[0], "data-binary")[0]).unwrap();
    assert_eq!(body["schema"], "logwizz.notification/v1");
    assert_eq!(body["count"], 3);
    assert_eq!(body["source"], "multiple");
    assert_eq!(
        body["sources"],
        json!([{"source": "203.0.113.7", "count": 2}, {"source": "203.0.113.8", "count": 1}])
    );
    assert_eq!(body["partial"], true);
    assert!(body.get("line").is_none());
    let all = fs::read_to_string(w.path.join("requests/0.conf")).unwrap();
    assert!(!all.contains(RAW), "raw log content leaked: {all}");
    let args = w.all_args();
    assert!(!args.contains(URL) && !args.contains("tk_LWZ"), "{args}");
    assert!(args.contains("--config\n-\n"), "{args}");

    let jargs = fs::read_to_string(w.path.join("journalctl.args")).unwrap();
    assert!(jargs.contains("--namespace=logwizz\n") && jargs.contains("--priority=4\n"));
    assert!(jargs.contains("--lines=0\n"), "{jargs}");

    // A restart continues after the saved cursor: nothing is counted again.
    let mut child = w.start(&WEBHOOK);
    thread::sleep(Duration::from_millis(500));
    assert!(stop(&mut child).success());
    let jargs = fs::read_to_string(w.path.join("journalctl.args")).unwrap();
    assert!(jargs.contains("--after-cursor=c4\n"), "{jargs}");
    assert_eq!(w.requests().len(), 1);
}

#[test]
fn failed_delivery_is_kept_and_retried_after_restart() {
    let w = Work::new();
    let t = open_ts();
    w.journal(&[
        event("c1", "ssh", &t, None),
        event("c2", "ssh", &t, None),
        event("c3", "ssh", &t, None),
    ]);
    fs::write(w.path.join("curl-fail"), "").unwrap();
    let mut child = w.start(&WEBHOOK);
    w.wait_cursor("c3");
    let status = stop(&mut child);
    assert_eq!(status.code(), Some(1), "pending summaries: nonzero exit");
    assert!(w.stderr().contains("delivery failed"), "{}", w.stderr());
    assert!(!w.stderr().contains(URL), "{}", w.stderr());
    let state = w.state();
    assert_eq!(state["cursor"], "c3");
    assert_eq!(state["summaries"][0]["count"], 3);
    assert_eq!(state["summaries"][0]["retry_count"], 1);

    fs::remove_file(w.path.join("curl-fail")).unwrap();
    let mut child = w.start(&WEBHOOK);
    thread::sleep(Duration::from_millis(500));
    assert!(stop(&mut child).success(), "{}", w.stderr());
    let reqs = w.requests();
    let body: Value = serde_json::from_str(value(reqs.last().unwrap(), "data-binary")[0]).unwrap();
    assert_eq!(body["count"], 3, "retried once, not recounted");
    assert_eq!(w.state()["summaries"], json!([]));
}

#[test]
fn closed_windows_are_sent_without_stopping() {
    let w = Work::new();
    // Ten minutes ago: long closed.
    let t = ts(now() - 600);
    w.journal(&[
        event("c1", "ssh", &t, Some("192.0.2.1")),
        event("c2", "ssh", &t, Some("192.0.2.1")),
    ]);
    let mut child = w.start(&[
        ("NOTIFY_KIND", "telegram"),
        ("TELEGRAM_BOT_TOKEN", TOKEN),
        ("TELEGRAM_CHAT_ID", "-100123"),
    ]);
    let start = Instant::now();
    while w.requests().is_empty() {
        assert!(start.elapsed() < Duration::from_secs(10), "{}", w.stderr());
        thread::sleep(Duration::from_millis(20));
    }
    assert!(stop(&mut child).success());
    let reqs = w.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        value(&reqs[0], "url"),
        [format!("https://api.telegram.org/bot{TOKEN}/sendMessage").as_str()]
    );
    let form = value(&reqs[0], "data-urlencode");
    assert!(form.contains(&"chat_id=-100123"));
    let text = form.iter().find_map(|f| f.strip_prefix("text=")).unwrap();
    assert!(form.contains(&"parse_mode=HTML"));
    assert!(
        text.contains("\n<code>ssh</code> · warning · test-host\n\n"),
        "{text}"
    );
    assert!(
        text.contains("\n<b>2×</b> from <code>192.0.2.1</code>\n"),
        "{text}"
    );
    assert!(!text.contains("Partial"), "{text}");
    assert!(!w.all_args().contains(TOKEN));
}

#[test]
fn journal_end_keeps_open_windows_for_the_restart() {
    let w = Work::new();
    let t = open_ts();
    // An invalid ts falls back to the journal's receive time.
    let mut bad = event("c2", "ssh", "not-a-timestamp", None);
    bad["__REALTIME_TIMESTAMP"] = json!(format!("{}000000", open_secs()));
    w.journal(&[event("c1", "ssh", &t, None), bad]);
    let mut child = w.start(&[("JOURNAL_EXIT", "1"), WEBHOOK[0], WEBHOOK[1], WEBHOOK[3]]);
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(start.elapsed() < Duration::from_secs(10));
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(1), "systemd restarts it");
    assert!(
        w.requests().is_empty(),
        "no partial summary on a journal restart"
    );
    assert!(w.stderr().contains("using the journal's"), "{}", w.stderr());
    let state = w.state();
    assert_eq!(state["cursor"], "c2");
    assert_eq!(state["summaries"][0]["count"], 2);
}

#[test]
fn imports_the_shell_notifier_state() {
    let w = Work::new();
    let bucket = open_secs() / 3600 * 3600;
    fs::write(w.path.join("state/cursor"), "c1\n").unwrap();
    fs::write(
        w.path
            .join(format!("state/agg-{bucket}-0123456789abcdef.json")),
        json!({"bucket": bucket, "window_start": ts(bucket), "window_end": ts(bucket + 3600),
               "host": "h", "rule": "ssh", "severity": "warning", "description": "", "source": "",
               "source_seen": true, "count": 5, "last_cursor": "c1"})
        .to_string(),
    )
    .unwrap();
    w.journal(&[
        event("c1", "ssh", &ts(bucket), None),
        event("c2", "ssh", &ts(bucket), None),
    ]);
    let mut child = w.start(&WEBHOOK);
    w.wait_cursor("c2");
    assert!(stop(&mut child).success(), "{}", w.stderr());
    let body: Value = serde_json::from_str(value(&w.requests()[0], "data-binary")[0]).unwrap();
    assert_eq!(body["count"], 6, "5 imported + 1 after the imported cursor");
    let left: Vec<_> = fs::read_dir(w.path.join("state"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(left, ["state.json"]);
}

#[test]
fn configuration_errors_exit_2_without_secrets() {
    let w = Work::new();
    let mut child = w.start(&[("TELEGRAM_BOT_TOKEN", "not-a-valid-token")]);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(2));
    let err = w.stderr();
    assert!(
        err.contains("TELEGRAM_BOT_TOKEN has invalid format"),
        "{err}"
    );
    assert!(!err.contains("not-a-valid-token"));
}

#[test]
fn keeps_up_with_a_burst_of_events() {
    let w = Work::new();
    let t = open_ts();
    const N: usize = 20_000;
    let entries: Vec<Value> = (0..N)
        .map(|i| {
            let src = format!("10.0.{}.{}", (i / 256) % 256, i % 256);
            event(&format!("c{i}"), &format!("rule{}", i % 50), &t, Some(&src))
        })
        .collect();
    w.journal(&entries);
    let start = Instant::now();
    let mut child = w.start(&WEBHOOK);
    w.wait_cursor(&format!("c{}", N - 1));
    let elapsed = start.elapsed();
    let total: u64 = w.state()["summaries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["count"].as_u64().unwrap())
        .sum();
    assert_eq!(total, N as u64);
    assert!(stop(&mut child).success());
    assert_eq!(w.requests().len(), 50, "one summary per rule");
    // The shell notifier needed several processes per event (minutes for
    // this burst); this is one parse per event, even in a debug build.
    assert!(elapsed < Duration::from_secs(20), "{elapsed:?}");
    eprintln!("{N} events consumed in {elapsed:?}");
}
