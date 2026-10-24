//! Persistent offsets (`general.state_file`) across restarts of the real
//! binary: no loss, and no repeats after a clean shutdown.

mod common;

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::{Duration, Instant};

use common::{append, write_new};

struct Daemon {
    child: Child,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
    /// Diagnostics logged up to "logwizz started".
    startup: Vec<String>,
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
    fn start(cfg: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_logwizz"))
            .arg("--config")
            .arg(cfg)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut d = Daemon {
            stdout: lines_of(child.stdout.take().unwrap()),
            stderr: lines_of(child.stderr.take().unwrap()),
            child,
            startup: Vec::new(),
        };
        loop {
            let line = d
                .stderr
                .recv_timeout(Duration::from_secs(5))
                .expect("daemon did not start");
            let started = line.contains("logwizz started");
            d.startup.push(line);
            if started {
                return d;
            }
        }
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

    /// The `line` field of every event until none arrives for `quiet`.
    fn events(&self, quiet: Duration) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(l) = self.stdout.recv_timeout(quiet) {
            let v: serde_json::Value = serde_json::from_str(&l).unwrap();
            out.push(v["line"].as_str().unwrap().to_string());
        }
        out
    }

    fn signal(&mut self, sig: libc::c_int) {
        // SAFETY: plain syscall on our own child's pid.
        unsafe { libc::kill(self.child.id() as libc::pid_t, sig) };
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "daemon did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(mut self) -> Vec<String> {
        self.signal(libc::SIGTERM);
        assert!(self.child.wait().unwrap().success());
        self.stderr.try_iter().collect()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Setup {
    dir: tempfile::TempDir,
    log: PathBuf,
    state: PathBuf,
    cfg: PathBuf,
}

/// `startup_mode = "beginning"`: without a usable saved offset a restart
/// would repeat everything, so the absence of repeats shows the offset was
/// used. (It also means no line is missed if it is appended before the
/// first poll has opened the file.)
fn setup(initial: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("app.log");
    let state = dir.path().join("offsets.json");
    let cfg = dir.path().join("logwizz.toml");
    write_new(&log, initial);
    fs::write(
        &cfg,
        format!(
            "[general]\ndiagnostics = \"info\"\nstartup_mode = \"beginning\"\n\
             state_file = {:?}\nstate_flush_ms = 100\n\
             [[files]]\npath = {:?}\n\
             [[rules]]\nid = \"err\"\nmatch_type = \"literal\"\npattern = \"ERR\"\nseverity = \"error\"\n",
            state.display().to_string(),
            log.display().to_string()
        ),
    )
    .unwrap();
    Setup {
        dir,
        log,
        state,
        cfg,
    }
}

const QUIET: Duration = Duration::from_millis(500);

#[test]
fn clean_restart_resumes_without_loss_or_repeats() {
    let s = setup("ERR before first start\n");
    let d = Daemon::start(&s.cfg);
    append(&s.log, "ERR 1\nok\nERR 2\n");
    assert_eq!(
        d.events(QUIET),
        ["ERR before first start", "ERR 1", "ERR 2"]
    );
    d.stop();
    let mode = fs::metadata(&s.state).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // Written while stopped, including a partial line completed later.
    append(&s.log, "ERR 3 while stopped\nno match\nERR 4 par");
    let d = Daemon::start(&s.cfg);
    d.wait_stderr("resuming from saved offset");
    append(&s.log, "tial\n");
    assert_eq!(d.events(QUIET), ["ERR 3 while stopped", "ERR 4 partial"]);
    d.stop();
}

#[test]
fn kill_then_restart_loses_nothing() {
    let s = setup("");
    let mut d = Daemon::start(&s.cfg);
    let all: Vec<String> = (0..200).map(|i| format!("ERR {i}")).collect();
    for chunk in all.chunks(20) {
        append(&s.log, &(chunk.join("\n") + "\n"));
    }
    let first = d.events(QUIET);
    assert_eq!(first, all);
    d.signal(libc::SIGKILL);

    append(&s.log, "ERR after kill\n");
    let d = Daemon::start(&s.cfg);
    let second = d.events(QUIET);
    d.stop();
    // At-least-once: everything after the saved offset is repeated, but
    // the line written while down is never missed.
    assert_eq!(second.last().map(String::as_str), Some("ERR after kill"));
    let repeated = &second[..second.len() - 1];
    assert!(
        all.ends_with(repeated),
        "repeats must be a suffix: {repeated:?}"
    );
}

#[test]
fn truncated_or_replaced_while_stopped_reads_from_start() {
    let s = setup("");
    let d = Daemon::start(&s.cfg);
    append(&s.log, "ERR long first line to make the file longer\n");
    assert_eq!(d.events(QUIET).len(), 1);
    d.stop();

    // copytruncate while stopped, with shorter new content.
    OpenOptions::new()
        .write(true)
        .open(&s.log)
        .unwrap()
        .set_len(0)
        .unwrap();
    append(&s.log, "ERR new\n");
    let d = Daemon::start(&s.cfg);
    d.wait_stderr("file was truncated while stopped");
    assert_eq!(d.events(QUIET), ["ERR new"]);
    d.stop();

    // Rotation (rename + create) while stopped.
    fs::rename(&s.log, s.dir.path().join("app.log.1")).unwrap();
    write_new(&s.log, "ERR rotated\n");
    let d = Daemon::start(&s.cfg);
    d.wait_stderr("file was replaced while stopped");
    assert_eq!(d.events(QUIET), ["ERR rotated"]);
    d.stop();
}

#[test]
fn reused_inode_is_detected_by_fingerprint() {
    let s = setup("ERR original content\n");
    let meta = fs::metadata(&s.log).unwrap();
    // Same identity and long enough, but different first bytes: what an
    // inode reused for a new file looks like.
    fs::write(
        &s.state,
        format!(
            r#"{{"v":1,"files":[{{"path":{:?},"dev":{},"ino":{},"offset":5,"fp_len":5,"fp":1}}]}}"#,
            s.log.display().to_string(),
            meta.dev(),
            meta.ino()
        ),
    )
    .unwrap();
    let d = Daemon::start(&s.cfg);
    d.wait_stderr("file content changed while stopped");
    assert_eq!(d.events(QUIET), ["ERR original content"]);
    d.stop();
}

#[test]
fn corrupt_state_falls_back_and_stale_tmp_is_ignored() {
    let s = setup("ERR old\n");
    fs::write(&s.state, "{ definitely not json").unwrap();
    let d = Daemon::start(&s.cfg);
    assert!(
        d.startup
            .iter()
            .any(|l| l.contains("cannot use state file")),
        "{:?}",
        d.startup
    );
    // Falls back to startup_mode = beginning.
    append(&s.log, "ERR new\n");
    assert_eq!(d.events(QUIET), ["ERR old", "ERR new"]);
    d.stop();

    // A crash during a write leaves a stale temporary file: the real state
    // file is still used, and the next save replaces the temporary file.
    let tmp = s.dir.path().join("offsets.json.tmp");
    fs::write(&tmp, "garbage").unwrap();
    append(&s.log, "ERR while stopped\n");
    let d = Daemon::start(&s.cfg);
    d.wait_stderr("resuming from saved offset");
    assert_eq!(d.events(QUIET), ["ERR while stopped"]);
    d.stop();
    assert!(!tmp.exists());
}

#[test]
fn kill_with_stalled_output_loses_nothing() {
    let s = setup("");
    // Run 1: nobody reads stdout, so the pipe fills, the output thread
    // stalls and events back up behind it. Saved offsets must not run
    // ahead of what actually reached the pipe.
    let mut child = Command::new(env!("CARGO_BIN_EXE_logwizz"))
        .arg("--config")
        .arg(&s.cfg)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(300));
    // Fewer lines than `queue_capacity` (4096): all are read and queued, and
    // a checkpoint is recorded, while most events are stuck behind the pipe.
    let all: Vec<String> = (0..3000)
        .map(|i| format!("ERR {i:05} {}", "x".repeat(80)))
        .collect();
    for chunk in all.chunks(300) {
        append(&s.log, &(chunk.join("\n") + "\n"));
    }
    thread::sleep(Duration::from_millis(1000));
    // SAFETY: plain syscall on our own child's pid.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGKILL) };
    child.wait().unwrap();
    let first: Vec<String> = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
        .map(|v| v["line"].as_str().unwrap().to_string())
        .collect();
    assert!(first.len() < all.len(), "output should have stalled");
    assert!(s.state.exists(), "offsets saved while stalled");

    let d = Daemon::start(&s.cfg);
    let second = d.events(QUIET);
    d.stop();
    let seen: std::collections::HashSet<&String> = first.iter().chain(&second).collect();
    let missing: Vec<&String> = all.iter().filter(|l| !seen.contains(l)).collect();
    assert!(
        missing.is_empty(),
        "{} lines lost, e.g. {:?}",
        missing.len(),
        &missing[..1]
    );
    assert!(
        all.ends_with(&second),
        "run 2 resumes, in order, from a saved offset"
    );
}
