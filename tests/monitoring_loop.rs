//! The monitor loop against real files: notification-driven detection,
//! reconciliation fallback and rotation while running.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, LazyLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::{append, write_new};
use logwizz::config::{self, Config};
use logwizz::metrics::Metrics;
use logwizz::monitor::Monitor;
use logwizz::watcher::Waker;

struct Running {
    lines: Receiver<(PathBuf, String)>,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    waker: Waker,
    handle: Option<JoinHandle<()>>,
}

impl Running {
    fn start(cfg: Config, notifications: bool) -> Self {
        let metrics = Arc::new(Metrics::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut monitor = Monitor::new(&cfg, Arc::clone(&metrics), notifications);
        let paths = cfg.files.clone();
        let waker = monitor.waker();
        let (tx, lines) = channel();
        let flag = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            monitor.run(&flag, &mut |file, line| {
                let text = String::from_utf8_lossy(line.bytes).into_owned();
                let _ = tx.send((paths[file].clone(), text));
            });
        });
        Running {
            lines,
            metrics,
            shutdown,
            waker,
            handle: Some(handle),
        }
    }

    fn wait_open(&self, n: u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.metrics.snapshot().files_monitored < n {
            assert!(Instant::now() < deadline, "files were not opened");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn next(&self, within: Duration) -> Option<(PathBuf, String)> {
        self.lines.recv_timeout(within).ok()
    }

    fn expect(&self, text: &str, within: Duration) -> Duration {
        let start = Instant::now();
        match self.next(within) {
            Some((_, got)) => {
                assert_eq!(got, text);
                start.elapsed()
            }
            None => panic!("no line {text:?} within {within:?}"),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.waker.wake();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn cfg(files: &[&Path], reconcile_ms: u64) -> Config {
    let mut text = format!(
        "[general]\nreconcile_interval_ms = {reconcile_ms}\nrotation_drain_ms = 200\n\
         [[rules]]\nid = \"any\"\nmatch_type = \"literal\"\npattern = \"x\"\nseverity = \"info\"\n"
    );
    for f in files {
        text.push_str(&format!(
            "[[files]]\npath = {:?}\n",
            f.display().to_string()
        ));
    }
    config::parse(&text, Path::new("test")).unwrap()
}

// inotify is shared per-user; serialise timing-sensitive tests so they do
// not compete with each other for CPU on small CI machines.
static SERIAL: LazyLock<std::sync::Mutex<()>> = LazyLock::new(|| std::sync::Mutex::new(()));

#[test]
fn notification_detects_append_quickly() {
    let _g = SERIAL.lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "");
    // Long reconcile interval: only inotify can explain fast detection.
    let r = Running::start(cfg(&[&path], 60_000), true);
    r.wait_open(1);
    let mut worst = Duration::ZERO;
    for i in 0..20 {
        append(&path, &format!("line {i}\n"));
        worst = worst.max(r.expect(&format!("line {i}"), Duration::from_secs(2)));
    }
    assert!(
        worst < Duration::from_millis(500),
        "worst latency {worst:?}"
    );
}

#[test]
fn reconciliation_alone_detects_changes() {
    let _g = SERIAL.lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "");
    let r = Running::start(cfg(&[&path], 100), false);
    r.wait_open(1);
    append(&path, "polled\n");
    r.expect("polled", Duration::from_secs(2));
    // Rotation is also handled by polling alone.
    fs::rename(&path, dir.path().join("app.log.1")).unwrap();
    write_new(&path, "after rotation\n");
    r.expect("after rotation", Duration::from_secs(2));
}

#[test]
fn rotation_and_truncation_while_running() {
    let _g = SERIAL.lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    let rotated = dir.path().join("app.log.1");
    write_new(&path, "");
    let r = Running::start(cfg(&[&path], 60_000), true);
    r.wait_open(1);

    append(&path, "a\n");
    r.expect("a", Duration::from_secs(2));
    fs::rename(&path, &rotated).unwrap();
    write_new(&path, "b\n");
    r.expect("b", Duration::from_secs(2));

    // copytruncate on the new file.
    append(&path, "c\n");
    r.expect("c", Duration::from_secs(2));
    fs::write(&path, "").unwrap();
    append(&path, "d\n");
    r.expect("d", Duration::from_secs(2));

    // delete and recreate.
    fs::remove_file(&path).unwrap();
    write_new(&path, "e\n");
    r.expect("e", Duration::from_secs(2));
    assert!(r.next(Duration::from_millis(100)).is_none());
}

#[test]
fn missing_directory_appears_later() {
    let _g = SERIAL.lock();
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("later");
    let path = sub.join("app.log");
    let r = Running::start(cfg(&[&path], 100), true);
    thread::sleep(Duration::from_millis(150));
    fs::create_dir(&sub).unwrap();
    write_new(&path, "hello\n");
    r.expect("hello", Duration::from_secs(2));
    // Once the directory is watched, appends are notification-driven.
    thread::sleep(Duration::from_millis(250));
    append(&path, "again\n");
    r.expect("again", Duration::from_secs(2));
}

#[test]
fn replaced_directory_is_rewatched() {
    let _g = SERIAL.lock();
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("logs");
    fs::create_dir(&sub).unwrap();
    let path = sub.join("app.log");
    write_new(&path, "");
    let r = Running::start(cfg(&[&path], 300), true);
    r.wait_open(1);
    fs::remove_file(&path).unwrap();
    fs::remove_dir(&sub).unwrap();
    fs::create_dir(&sub).unwrap();
    write_new(&path, "new dir\n");
    r.expect("new dir", Duration::from_secs(3));
    thread::sleep(Duration::from_millis(400));
    // After the reconcile tick the new directory is watched again, so this
    // arrives well before the next tick would find it.
    append(&path, "watched\n");
    let lat = r.expect("watched", Duration::from_secs(3));
    assert!(lat < Duration::from_millis(250), "latency {lat:?}");
}

#[test]
fn multiple_files_are_attributed() {
    let _g = SERIAL.lock();
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.log");
    let b = dir.path().join("b.log");
    write_new(&a, "");
    write_new(&b, "");
    let r = Running::start(cfg(&[&a, &b], 60_000), true);
    r.wait_open(2);
    append(&a, "from a\n");
    append(&b, "from b\n");
    let mut got = vec![
        r.next(Duration::from_secs(2)).unwrap(),
        r.next(Duration::from_secs(2)).unwrap(),
    ];
    got.sort();
    assert_eq!(got, [(a, "from a".into()), (b, "from b".into())]);
}
