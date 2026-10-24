//! Rotation, truncation, deletion and recreation of a monitored file.

mod common;

use std::fs;
use std::time::Duration;

use common::{Harness, append, write_new};
use logwizz::config::StartupMode;

#[test]
fn rename_and_create_drains_old_then_reads_new() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    let rotated = dir.path().join("app.log.1");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    append(&path, "before\n");
    // Rotate without logwizz seeing the "before" line yet, then let the
    // writer, which still holds the old file, append once more.
    fs::rename(&path, &rotated).unwrap();
    write_new(&path, "new 1\n");
    append(&rotated, "late old\n");

    assert_eq!(h.poll(), ["before", "late old", "new 1"]);
    assert!(h.file.is_draining());
    assert_eq!(h.metrics.snapshot().rotations, 1);

    // Writes to the old file within the grace period are still read.
    h.advance(Duration::from_secs(3));
    append(&rotated, "later old\n");
    append(&path, "new 2\n");
    assert_eq!(h.poll(), ["later old", "new 2"]);

    // Idle past the grace period: the old file is closed.
    h.advance(Duration::from_secs(6));
    h.poll();
    assert!(!h.file.is_draining());
    append(&rotated, "ignored\n");
    assert!(h.poll().is_empty());
    assert_eq!(h.metrics.snapshot().files_monitored, 1);
}

#[test]
fn partial_line_in_rotated_file_is_flushed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    append(&path, "unterminated");
    assert!(h.poll().is_empty());
    fs::rename(&path, dir.path().join("app.log.1")).unwrap();
    write_new(&path, "");
    h.poll();
    h.advance(Duration::from_secs(10));
    assert_eq!(h.poll(), ["unterminated"]);
    assert_eq!(h.metrics.snapshot().partial_lines_flushed, 1);
}

#[test]
fn renamed_away_without_replacement_keeps_reading() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    let rotated = dir.path().join("app.log.1");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    fs::rename(&path, &rotated).unwrap();
    append(&rotated, "still writing\n");
    assert_eq!(h.poll(), ["still writing"]);
    assert!(h.file.is_open());
    // Then the new file shows up.
    write_new(&path, "fresh\n");
    assert_eq!(h.poll(), ["fresh"]);
}

#[test]
fn copytruncate_restarts_at_zero() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    append(&path, "one\ntwo\nthree\n");
    assert_eq!(h.poll().len(), 3);
    // copytruncate: copy elsewhere, then truncate in place.
    fs::copy(&path, dir.path().join("app.log.1")).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(0)
        .unwrap();
    append(&path, "after\n");
    assert_eq!(h.poll(), ["after"]);
    let s = h.metrics.snapshot();
    assert_eq!(s.truncations, 1);
    assert_eq!(s.rotations, 0);
}

#[test]
fn truncation_flushes_pending_partial_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    append(&path, "partial");
    h.poll();
    fs::write(&path, "").unwrap();
    assert_eq!(h.poll(), ["partial"]);
}

#[test]
fn delete_then_recreate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    append(&path, "last words\n");
    fs::remove_file(&path).unwrap();
    // Data written before deletion is still read; then the file is closed.
    assert_eq!(h.poll(), ["last words"]);
    assert!(!h.file.is_open());
    assert_eq!(h.metrics.snapshot().files_monitored, 0);
    assert!(h.poll().is_empty());

    write_new(&path, "reborn\n");
    assert_eq!(h.poll(), ["reborn"]);
    assert_eq!(h.metrics.snapshot().files_monitored, 1);
}

#[test]
fn replaced_by_rename_over_path() {
    // e.g. `mv new.log app.log`: same path, different inode.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    let staged = dir.path().join("staged");
    write_new(&staged, "replacement\n");
    fs::rename(&staged, &path).unwrap();
    assert_eq!(h.poll(), ["replacement"]);
    assert_eq!(h.metrics.snapshot().rotations, 1);
}

#[test]
fn symlink_retarget_is_a_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.log");
    let b = dir.path().join("b.log");
    let link = dir.path().join("current.log");
    write_new(&a, "");
    write_new(&b, "");
    std::os::unix::fs::symlink(&a, &link).unwrap();
    let mut h = Harness::new(link.clone(), StartupMode::Tail);
    h.poll();
    append(&a, "from a\n");
    assert_eq!(h.poll(), ["from a"]);
    let tmp = dir.path().join("tmp.lnk");
    std::os::unix::fs::symlink(&b, &tmp).unwrap();
    fs::rename(&tmp, &link).unwrap();
    append(&b, "from b\n");
    assert_eq!(h.poll(), ["from b"]);
}

#[test]
fn two_rotations_within_grace_period() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    append(&path, "gen0\n");
    fs::rename(&path, dir.path().join("app.log.1")).unwrap();
    write_new(&path, "gen1\n");
    assert_eq!(h.poll(), ["gen0", "gen1"]);
    fs::rename(&path, dir.path().join("app.log.2")).unwrap();
    write_new(&path, "gen2\n");
    assert_eq!(h.poll(), ["gen2"]);
    assert_eq!(h.metrics.snapshot().rotations, 2);
}

#[test]
fn renamed_away_and_back_is_the_same_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    let aside = dir.path().join("aside");
    write_new(&path, "");
    let mut h = Harness::new(path.clone(), StartupMode::Tail);
    h.poll();
    fs::rename(&path, &aside).unwrap();
    h.poll();
    fs::rename(&aside, &path).unwrap();
    append(&path, "same file\n");
    assert_eq!(h.poll(), ["same file"]);
    assert_eq!(h.metrics.snapshot().rotations, 0);
    // Deleting it now must still be detected as a deletion.
    fs::remove_file(&path).unwrap();
    h.poll();
    assert!(!h.file.is_open());
}
