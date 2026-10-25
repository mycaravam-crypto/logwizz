//! Incremental reading behaviour of a single monitored file.

mod common;

use std::fs;
use std::time::Duration;

use common::{Harness, append, write_new};
use logwizz::config::StartupMode;
use logwizz::reader::ReaderOptions;

#[test]
fn reads_only_appended_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "old 1\nold 2\n");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);

    assert!(h.poll().is_empty());
    assert!(h.file.is_open());
    append(&path, "new 1\n");
    assert_eq!(h.poll(), ["new 1"]);
    assert!(h.poll().is_empty());
    append(&path, "new 2\nnew 3\n");
    assert_eq!(h.poll(), ["new 2", "new 3"]);
    // Only appended bytes were read: 6 + 12, not the 12 pre-existing ones.
    assert_eq!(h.metrics.snapshot().bytes_read, 18);
}

#[test]
fn beginning_mode_reads_existing_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "old 1\nold 2\n");
    let mut h = Harness::new(path.clone(), StartupMode::Beginning);
    assert_eq!(h.poll(), ["old 1", "old 2"]);
}

#[test]
fn tail_mode_skips_line_in_progress_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "complete\nhalf a li");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    assert!(h.poll().is_empty());
    append(&path, "ne\nfresh\n");
    assert_eq!(h.poll(), ["fresh"]);
}

#[test]
fn partial_line_completed_across_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    append(&path, "Failed pass");
    assert!(h.poll().is_empty());
    append(&path, "word for root");
    assert!(h.poll().is_empty());
    append(&path, "\n");
    assert_eq!(h.poll(), ["Failed password for root"]);
}

#[test]
fn oversized_line_is_cut_not_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    let long = "x".repeat(3000);
    append(&path, &format!("{long}\nafter\n"));
    let lines = h.poll();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], format!("{}~", "x".repeat(1024)));
    assert_eq!(lines[1], "after");
    let s = h.metrics.snapshot();
    assert_eq!(s.lines_truncated, 1);
    assert_eq!(s.bytes_skipped, 3000 - 1024);
}

#[test]
fn read_budget_limits_each_poll() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, &"0123456789\n".repeat(100));
    let mut h = Harness::with_opts(
        path.clone(),
        StartupMode::Beginning,
        ReaderOptions {
            max_line_bytes: 1024,
            read_budget: 110,
            drain_grace: Duration::from_secs(1),
        },
    );
    // `Harness::poll` loops; drive a single poll by hand here.
    let mut buf = vec![0; 4096];
    let mut n = 0;
    let more = h.file.poll(h.now, &mut buf, &h.metrics, &mut |_| n += 1);
    assert!(more);
    assert_eq!(n, 10);
    assert_eq!(h.poll().len(), 90);
}

#[test]
fn missing_file_is_picked_up_when_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("late.log");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    assert!(h.poll().is_empty());
    assert!(!h.file.is_open());
    // A file that appears after startup is new data and is read from 0,
    // even in tail mode.
    write_new(&path, "first\n");
    assert_eq!(h.poll(), ["first"]);
    assert_eq!(h.metrics.snapshot().files_monitored, 1);
}

#[test]
fn unreadable_path_is_reported_once_and_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dir.log");
    fs::create_dir(&path).unwrap();
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    h.poll();
    assert_eq!(h.metrics.snapshot().read_errors, 1);
    fs::remove_dir(&path).unwrap();
    write_new(&path, "ok\n");
    assert_eq!(h.poll(), ["ok"]);
}

/// Root bypasses file permission checks, so the EACCES tests need a normal user (as on CI runners).
fn permissions_enforced() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    if root {
        eprintln!("running as root: permission checks do not apply, nothing to test");
    }
    !root
}

fn chmod(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn new_file_unreadable_until_chmod_is_not_an_error() {
    if !permissions_enforced() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    // Like `install -o root -g adm`: created without access, chmod follows.
    write_new(&path, "first\n");
    chmod(&path, 0o000);
    assert!(h.poll().is_empty());
    assert_eq!(h.metrics.snapshot().read_errors, 0);
    chmod(&path, 0o640);
    assert_eq!(h.poll(), ["first"]);

    // Same for the file a rotation puts in place.
    fs::rename(&path, dir.path().join("app.log.1")).unwrap();
    write_new(&path, "second\n");
    chmod(&path, 0o000);
    assert!(h.poll().is_empty());
    chmod(&path, 0o640);
    assert_eq!(h.poll(), ["second"]);
    assert_eq!(h.metrics.snapshot().read_errors, 0);
}

#[test]
fn new_file_that_stays_unreadable_is_reported_once() {
    if !permissions_enforced() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    write_new(&path, "secret\n");
    chmod(&path, 0o000);
    h.poll();
    assert_eq!(h.metrics.snapshot().read_errors, 0);
    h.poll();
    h.poll();
    assert_eq!(h.metrics.snapshot().read_errors, 1);
    chmod(&path, 0o640);
    assert_eq!(h.poll(), ["secret"]);
}

#[test]
fn unreadable_file_at_startup_is_reported_at_once() {
    if !permissions_enforced() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "x\n");
    chmod(&path, 0o000);
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    assert_eq!(h.metrics.snapshot().read_errors, 1);
}

#[test]
fn fifo_does_not_block() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fifo.log");
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path string.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    assert!(h.poll().is_empty());
    assert!(!h.file.is_open());
}
