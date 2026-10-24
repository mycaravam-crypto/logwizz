//! Load test: end-to-end throughput, detection latency, memory and idle CPU
//! of the real binary. Ignored by default because it is slow and its numbers
//! are only meaningful on an otherwise idle machine with an optimised build:
//!
//!     cargo test --release --test load -- --ignored --nocapture --test-threads=1
//!
//! Every measurement is end to end: a writer appends to a log file, the
//! daemon detects, reads, matches and formats JSON, and the test reads the
//! events back from the daemon's stdout pipe.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::{Duration, Instant};

const MATCH: &str = "Oct 24 08:15:35 host sshd[1240]: Failed password for invalid user admin from 192.0.2.7 port 22";
const NOISE: [&str; 7] = [
    "Oct 24 08:15:30 host sshd[1234]: Accepted publickey for deploy from 10.0.0.5 port 52144 ssh2",
    "Oct 24 08:15:31 host systemd[1]: Started Session 42 of user deploy.",
    "Oct 24 08:15:32 host CRON[5678]: (root) CMD (/usr/local/bin/backup --incremental)",
    "Oct 24 08:15:33 host kernel: [12345.678901] eth0: link up, 1000Mbps, full-duplex",
    "Oct 24 08:15:34 host nginx[910]: 10.0.0.9 - - \"GET /healthz HTTP/1.1\" 200 2 \"-\" \"probe\"",
    "Oct 24 08:15:36 host postfix/smtpd[2222]: connect from mail.example.org[198.51.100.3]",
    "Oct 24 08:15:37 host dbus-daemon[700]: [system] Successfully activated service 'org.x'",
];

fn rules(n_regex: usize) -> String {
    let mut s = String::from(
        "[[rules]]\nid = \"ssh\"\nmatch_type = \"literal\"\npattern = \"Failed password\"\nseverity = \"warning\"\n",
    );
    for i in 0..n_regex {
        s.push_str(&format!(
            "[[rules]]\nid = \"re{i}\"\nmatch_type = \"regex\"\npattern = '(?i)error code \\d+ in module{i}\\b'\nseverity = \"error\"\n"
        ));
    }
    s
}

struct Daemon {
    child: Child,
    events: Receiver<Instant>,
}

impl Daemon {
    fn start(dir: &Path, log: &Path, n_regex: usize) -> Self {
        let cfg = dir.join("logwizz.toml");
        fs::write(
            &cfg,
            format!(
                "[general]\ndiagnostics = \"info\"\n[[files]]\npath = {:?}\n{}",
                log.display().to_string(),
                rules(n_regex)
            ),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_logwizz"))
            .arg("--config")
            .arg(&cfg)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, events) = channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.is_err() || tx.send(Instant::now()).is_err() {
                    break;
                }
            }
        });
        // Wait until the file is open (tail mode), so no line is missed.
        let stderr = child.stderr.take().unwrap();
        let (ready_tx, ready) = channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if line.contains("logwizz started") {
                    let _ = ready_tx.send(());
                }
            }
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        thread::sleep(Duration::from_millis(200));
        Daemon { child, events }
    }

    fn proc_status(&self, key: &str) -> u64 {
        let text = fs::read_to_string(format!("/proc/{}/status", self.child.id())).unwrap();
        text.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap()
    }

    /// utime + stime in clock ticks.
    fn cpu_ticks(&self) -> u64 {
        let text = fs::read_to_string(format!("/proc/{}/stat", self.child.id())).unwrap();
        // Fields after the ")" of the command name; utime/stime are 14/15.
        let rest = &text[text.rfind(')').unwrap() + 2..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // SAFETY: plain syscall on our own child's pid.
        unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        let _ = self.child.wait();
    }
}

fn throughput(n_regex: usize) {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("load.log");
    File::create(&log).unwrap();
    let d = Daemon::start(dir.path(), &log, n_regex);

    const LINES: usize = 2_000_000;
    let mut chunk = Vec::new();
    for l in std::iter::once(MATCH).chain(NOISE) {
        chunk.extend_from_slice(l.as_bytes());
        chunk.push(b'\n');
    }
    let per_chunk = 1 + NOISE.len();
    let reps = LINES / per_chunk;
    let mut batch = Vec::new();
    for _ in 0..64 {
        batch.extend_from_slice(&chunk);
    }
    let bytes = (reps * chunk.len()) as f64;
    let mut f = OpenOptions::new().append(true).open(&log).unwrap();
    let start = Instant::now();
    let mut written = 0;
    while written < reps {
        let n = (reps - written).min(64);
        f.write_all(&batch[..n * chunk.len()]).unwrap();
        written += n;
    }
    let write_done = start.elapsed();
    let mut last = start;
    for i in 0..reps {
        last = d
            .events
            .recv_timeout(Duration::from_secs(30))
            .unwrap_or_else(|_| panic!("only {i} of {reps} events"));
    }
    let elapsed = last.duration_since(start).as_secs_f64();
    let lines = (reps * per_chunk) as f64;
    println!(
        "throughput  rules=1 literal + {n_regex} regex  lines={} events={reps}  \
         writer={:.2}s  end-to-end={:.2}s  {:.0} lines/s  {:.1} MiB/s  peak RSS={} KiB",
        reps * per_chunk,
        write_done.as_secs_f64(),
        elapsed,
        lines / elapsed,
        bytes / elapsed / (1024.0 * 1024.0),
        d.proc_status("VmHWM:")
    );
}

#[test]
#[ignore]
fn load_throughput_one_literal_rule() {
    throughput(0);
}

#[test]
#[ignore]
fn load_throughput_eleven_rules() {
    throughput(10);
}

#[test]
#[ignore]
fn load_latency_memory_idle_cpu() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("lat.log");
    File::create(&log).unwrap();
    let d = Daemon::start(dir.path(), &log, 10);

    let rss_start = d.proc_status("VmRSS:");

    // Idle CPU over 10 s with the default 1 s reconcile interval.
    let t0 = d.cpu_ticks();
    thread::sleep(Duration::from_secs(10));
    let ticks = d.cpu_ticks() - t0;
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    let idle_pct = ticks as f64 / hz / 10.0 * 100.0;

    // Detection latency: one matching line every 10 ms, written with a
    // single write() each, as a typical logger would.
    let mut f = OpenOptions::new().append(true).open(&log).unwrap();
    let mut samples = Vec::new();
    let line = format!("{MATCH}\n");
    for _ in 0..1000 {
        let t = Instant::now();
        f.write_all(line.as_bytes()).unwrap();
        let got = d.events.recv_timeout(Duration::from_secs(5)).unwrap();
        samples.push(got.duration_since(t));
        thread::sleep(Duration::from_millis(10));
    }
    samples.sort();
    let pct = |p: f64| samples[((samples.len() as f64 * p) as usize).min(samples.len() - 1)];

    println!(
        "idle        cpu={idle_pct:.3}% of one core over 10 s ({ticks} ticks)  RSS={rss_start} KiB"
    );
    println!(
        "latency     n={}  p50={:?}  p95={:?}  p99={:?}  max={:?}  RSS after={} KiB  peak={} KiB",
        samples.len(),
        pct(0.50),
        pct(0.95),
        pct(0.99),
        samples[samples.len() - 1],
        d.proc_status("VmRSS:"),
        d.proc_status("VmHWM:")
    );
    assert!(idle_pct < 1.0, "idle CPU {idle_pct}%");
    assert!(
        pct(0.95) < Duration::from_millis(100),
        "p95 {:?}",
        pct(0.95)
    );
}
