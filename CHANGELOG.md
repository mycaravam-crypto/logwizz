# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

<!-- Set the date when v0.1.0 is tagged. -->

First release: a single-binary Linux daemon that tails configured log files
and emits an event for every line matching a rule.

### Added

- **Configuration:** TOML with unknown fields rejected, explicit bounds and a
  1 MiB file size limit. Every validation problem is reported at once.
  `--check-config` validates without starting, and configuration errors exit
  with code 2. World-writable configuration files are refused.
- **File reading:** incremental reads with per-file offsets, `(dev, ino)`
  identity and a bounded partial-line buffer (`max_line_bytes`). Oversized
  lines are cut, flagged `truncated` and counted. Invalid UTF-8 is converted
  lossily and counted.
- **Rotation:** rename+create and replacement are detected by identity
  change. The old file is drained before the new one is read from offset 0.
  copytruncate restarts at offset 0, and deleted files are drained and
  closed. Files that appear after startup are read from the beginning.
- **Monitoring:** inotify watches on each file's parent directory, plus
  periodic reconciliation (`reconcile_interval_ms`). Reconciliation recovers
  missed or overflowed events and covers filesystems without inotify.
- **Rules:** literal (`memchr`) and linear-time regex (`regex`) rules,
  compiled at load time and evaluated without per-line allocation. Severities
  range from `debug` to `critical`.
- **Output:** JSON Lines (schema `v: 1`) or a human format with control
  characters escaped, written to stdout or stderr by a dedicated thread
  behind a bounded queue. When the queue is full, `on_full = "block"` waits
  and `on_full = "drop"` discards and counts. Output write errors, including
  `EPIPE`, shut the daemon down with exit code 1.
- **Limits:** an optional per-rule rate limit and a bounded deduplication
  window. Suppressed events are counted.
- **Operations:** SIGTERM and SIGINT shut down gracefully and flush queued
  events. SIGUSR1 and `general.stats_interval_secs` log a statistics
  snapshot.
- **Packaging:** a hardened systemd unit (`packaging/logwizz.service`):
  `DynamicUser`, no capabilities, read-only filesystem, no network, the
  `@system-service` syscall filter, and memory and task limits.
- **Documentation:** README (configuration reference, event schema,
  delivery guarantees, rotation semantics, limitations) and
  `docs/BENCHMARKS.md`.
- **CI:** fmt, clippy with `-D warnings`, tests, locked release build,
  systemd unit verification, `cargo audit`, and a release build on the MSRV.

### Notes

- Minimum supported Rust version: 1.85. Tests and benchmarks need 1.86.
- Delivery is best-effort and at-most-once. Offsets are not persisted, so
  `startup_mode` decides what happens after a restart.
- Not included: glob patterns, persistent offsets, runtime configuration
  reload. These are planned for 0.2.0 (#9).

[0.1.0]: https://github.com/mycaravam-crypto/logwizz/releases/tag/v0.1.0
