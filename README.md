# logwizz

A small, high-performance Linux log monitoring daemon written in Rust.

logwizz follows a set of local log files, matches every new line against
literal or regular-expression rules, and writes one structured event per
match to stdout or stderr: either JSON Lines or human-readable text. It
survives log rotation, truncation, deletion and recreation, and stays within
explicit memory and queue limits.

It is deliberately small. It is not a SIEM, a log shipper or an alerting
system: pipe its output into whatever does that job for you (journald,
a collector, a script).

```
$ logwizz --config /etc/logwizz/logwizz.toml
{"v":1,"ts":"2026-10-24T08:15:35.120318Z","host":"web1","pid":812,"file":"/var/log/auth.log","rule":"ssh_failed_login","description":"Failed SSH authentication","severity":"warning","match_type":"literal","line":"Oct 24 08:15:35 web1 sshd[1240]: Failed password for invalid user admin from 192.0.2.7 port 22 ssh2","truncated":false}
```

## Contents

- [Building](#building)
- [Usage](#usage)
- [Configuration](#configuration)
- [Event format](#event-format)
- [Behaviour and guarantees](#behaviour-and-guarantees)
- [Operations](#operations)
- [Deployment with systemd](#deployment-with-systemd)
- [Security](#security)
- [Compatibility and limitations](#compatibility-and-limitations)
- [Development](#development)

## Building

Requires Rust 1.85 or newer (the minimum supported Rust version, MSRV) on
Linux. Running the tests and benchmarks needs 1.86, because of the
`criterion` dev-dependency. Development and the full CI gates use the latest
stable release.

```sh
cargo build --release --locked
install -m 0755 target/release/logwizz /usr/bin/logwizz
```

## Usage

```
logwizz [--config <PATH>] [--check-config]
logwizz --version | --help
```

| Option | Meaning |
|---|---|
| `-c, --config <PATH>` | Configuration file. Default `/etc/logwizz/logwizz.toml`. |
| `--check-config` | Load, validate and compile the configuration, print a summary and exit. Does not start monitoring. |
| `-V, --version` / `-h, --help` | Print version or help. |

Exit codes: `0` for a clean shutdown or a valid configuration, `1` for a
runtime failure (for example, the output became unwritable), and `2` for an
invalid configuration. Every configuration problem is listed, not only the
first one.

```
$ logwizz --check-config -c bad.toml
logwizz: invalid configuration in bad.toml:
  - files[0] (var/log/syslog): path must be absolute
  - rules[1] (kernel_error): invalid regex: regex parse error: ...
```

## Configuration

TOML. Unknown keys are rejected, so typos fail loudly. A commented example
with every option is in [`config/logwizz.example.toml`](config/logwizz.example.toml).
Only `[[files]]` and `[[rules]]` are required.

### `[general]`

| Key | Default | Range | Meaning |
|---|---|---|---|
| `startup_mode` | `"tail"` | `tail`, `beginning` | Where reading starts for files that exist at startup. `tail` skips existing content, including the remainder of a line still being written. Files that appear later are always read from the beginning. |
| `max_line_bytes` | `65536` | 256 – 16 MiB | Longer lines are cut to this length, flagged `truncated`, and counted. This is also the cap on buffered incomplete-line data per file (plus one byte for a trailing `\r`). |
| `reconcile_interval_ms` | `1000` | 50 – 600000 | Every file is re-checked at this interval regardless of notifications. |
| `rotation_drain_ms` | `5000` | 0 – 600000 | After rotation, keep reading the old file until it has been idle this long. |
| `diagnostics` | `"warn"` | `error` … `trace` | Verbosity of logwizz's own messages on stderr. |
| `stats_interval_secs` | `0` | 0 – 86400 | Log a statistics line at `info` level at this interval. `0` disables it. |

### `[output]`

| Key | Default | Meaning |
|---|---|---|
| `format` | `"json"` | `json` (JSON Lines) or `human`. |
| `destination` | `"stdout"` | `stdout` or `stderr`. |
| `queue_capacity` | `4096` | Maximum events buffered between the reader and the output writer (1 – 1048576). |
| `on_full` | `"block"` | Full queue: `block` pauses reading, `drop` discards the event and counts it. See [Backpressure](#backpressure). |
| `max_excerpt_bytes` | unset | If set (16 – 16 MiB), events include at most this many bytes of the line, cut on a UTF-8 boundary, with `truncated: true`. |

### `[limits]`

| Key | Default | Meaning |
|---|---|---|
| `rate_limit_events` | `0` | Maximum events per rule per window. `0` means unlimited. |
| `rate_limit_window_secs` | `60` | Length of the fixed rate-limit window. |
| `dedup_window_secs` | `0` | Suppress an identical (rule, line) pair seen within this many seconds of its first occurrence. `0` disables it. |
| `dedup_max_entries` | `4096` | Maximum remembered pairs. When the table is full and nothing has expired, new lines are emitted but not remembered: deduplication never suppresses an event wrongly. |

Suppressed events are counted (`events_rate_limited`, `events_deduplicated`).
logwizz warns when a rule hits its limit and logs the suppressed count when
the window ends.

### `[[files]]`

| Key | Default | Meaning |
|---|---|---|
| `path` | required | Absolute path without `.`, `..` or `//` components. Up to 1024 entries, no duplicates. |
| `enabled` | `true` | Disabled entries are validated but not monitored. |

Globs are not supported in 0.1.0. List each file explicitly.

### `[[rules]]`

| Key | Default | Meaning |
|---|---|---|
| `id` | required | Unique; ASCII letters, digits, `_ - . :`; at most 64 bytes. |
| `description` | `""` | Free text included in events. |
| `enabled` | `true` | Disabled rules are still compiled, so mistakes surface immediately. |
| `match_type` | required | `literal`: case-sensitive substring. `regex`: [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax). Use `(?i)` for case-insensitive matching. |
| `pattern` | required | Non-empty, at most 4096 bytes. Regexes are limited to 2 MiB compiled size. |
| `severity` | required | `debug`, `info`, `notice`, `warning`, `error`, `critical`. |

Rules are compiled once at startup. Every enabled rule is evaluated against
every line in configuration order, and each matching rule produces its own
event. Matching works on raw bytes, so lines that are not valid UTF-8 are
still matched.

Limits: the configuration file may be at most 1 MiB and must not be
world-writable.

## Event format

### JSON Lines (`format = "json"`)

One JSON object per line. Schema version `1`:

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | Schema version, currently `1`. Incompatible changes increment it. |
| `ts` | string | Detection time, RFC 3339 UTC with microseconds, e.g. `2026-10-24T08:15:35.120318Z`. |
| `host` | string | Hostname. |
| `pid` | integer | logwizz process ID. |
| `file` | string | Configured path the line came from. If the file was rotated away, this is still the configured path. |
| `rule` | string | Rule `id`. |
| `description` | string | Rule description. |
| `severity` | string | Rule severity. |
| `match_type` | string | `literal` or `regex`. |
| `line` | string | The matching line without its terminator (`\n` or `\r\n`), or its excerpt. Invalid UTF-8 sequences are replaced with U+FFFD. |
| `truncated` | boolean | `true` if `line` is incomplete (cut at `max_line_bytes` or `max_excerpt_bytes`). |

Consumers should ignore unknown fields; new fields may be added without a
version bump.

### Human (`format = "human"`)

```
2026-10-24T08:15:35.120318Z WARNING  [ssh_failed_login] /var/log/auth.log: Failed password for root ...
```

Control characters in the line are escaped (`\u{1b}`), so log content cannot
inject terminal escape sequences. A truncated line ends with ` [truncated]`.

## Behaviour and guarantees

### Detection

logwizz watches the **parent directory** of each configured file with
inotify (non-recursive). This means creation, renames and deletion are seen
even while the file does not exist. Notifications are only hints: on every
wakeup, and on every reconciliation tick, logwizz checks the file itself
(`stat`, identity and size). As a result:

- missed or overflowed notifications (`IN_Q_OVERFLOW`) cost latency, not
  data. They are counted in `notify_overflows`, and every file is rescanned.
- filesystems without inotify support (NFS, many FUSE filesystems) still
  work through reconciliation alone, with latency of up to
  `reconcile_interval_ms`.
- a directory that is missing at startup, or deleted and recreated, is
  watched again within one reconciliation interval.
- if inotify is unavailable altogether (for example,
  `fs.inotify.max_user_instances` is exhausted), logwizz warns and
  continues with reconciliation only.

Only newly appended bytes are read (`pread` from a per-file offset), with a
1 MiB read budget per file per pass so one busy file cannot starve the
others.

### File identity and rotation

A file is identified by `(device, inode)`. Because logwizz keeps the file
open, the kernel cannot reuse that inode while it is being compared, so a
matching identity really is the same file.

| Situation | Behaviour |
|---|---|
| Rename + create (logrotate `create`) | The path now has a new identity. The old file is moved to a *draining* slot and read until it has been idle for `rotation_drain_ms`, so lines the writer appends after the rename are not lost. The new file is read from offset 0. Old data is always emitted before new data. |
| Replace at the same path (`mv new app.log`), or a retargeted symlink | Treated the same as rename + create. |
| Truncation (`copytruncate`, `: > file`) | Size below offset: reading restarts at 0, and `truncations` is incremented. |
| Deletion | The file is read to EOF and then closed. If the path reappears, the new file is read from 0. |
| Renamed away, no replacement yet | logwizz keeps reading the open file, since its writer usually still appends to it, until a new file appears at the path. |
| Missing at startup or temporarily | Logged once. Picked up and read from offset 0 when it appears. |
| Permission denied or not a regular file | Logged and counted once per episode, retried on every reconcile tick, never fatal. Opening uses `O_NONBLOCK`, so a FIFO cannot hang the daemon. |

Writes to a rotated file whose new name is in the same watched directory do
not map to a configured path. They are picked up on the next reconciliation
tick, within the drain window.

### Lines

- Lines end at `\n`. A trailing `\r` is stripped, and does not count towards
  `max_line_bytes`.
- An incomplete trailing line is held, up to `max_line_bytes` (plus one byte
  for a possible `\r` terminator), until its newline arrives. If its file is
  truncated, rotated or deleted first, it is emitted as is and counted in
  `partial_lines_flushed`.
- A line longer than `max_line_bytes` is emitted cut to that length with
  `truncated: true`. The excess bytes, not counting the terminator, are counted
  in `bytes_skipped`. Lines are never silently dropped.

### Backpressure

Events pass from the monitor thread to a single output thread through a
bounded queue (`queue_capacity`). Output is buffered and flushed whenever the
queue runs empty.

- `on_full = "block"` (default): the monitor waits for queue space. Unread
  data stays in the log files, so nothing is lost while the process runs,
  but detection latency grows with the backlog. If a file is rotated *and
  deleted* during a long stall, its unread tail is lost.
- `on_full = "drop"`: the event is discarded, counted in `events_dropped`,
  and reported with a warning at most every 10 seconds.

If writing to the output fails (for example, the reading end of a pipe
closes), logwizz counts the failure in `output_errors`, logs an error, and
exits with status 1. Continuing would only hide the loss.

### Delivery guarantees

logwizz provides **best-effort, at-most-once delivery within one process
lifetime**. It does **not** provide durable or exactly-once processing:

- Offsets are kept in memory only. After a restart, `startup_mode` decides
  where reading resumes: `tail` skips anything written while logwizz was
  down, and `beginning` re-emits events for existing content.
- Events still queued when the process is killed with SIGKILL, or crashes,
  are lost. On SIGTERM/SIGINT the queue is flushed before exit.
- `copytruncate` is inherently racy. Lines written between the copy and the
  truncation are lost for every reader. Lines written after the truncation
  but before logwizz notices it, beyond the old offset, cannot be told apart
  from old data and may be missed. Prefer rename-based rotation.
- With `on_full = "drop"`, rate limiting or deduplication, events are
  intentionally discarded. Every discarded event is counted.

## Operations

### Signals

| Signal | Effect |
|---|---|
| `SIGTERM`, `SIGINT` | Stop reading, flush queued events, log final statistics, exit 0. |
| `SIGUSR1` | Log a statistics line at `info` level. |
| `SIGHUP` | Logs that reload is not supported. Runtime reload is not implemented in 0.1.0: restart to apply configuration changes. |

### Statistics

Logged on `SIGUSR1`, every `stats_interval_secs`, and at shutdown, as one
line on stderr:

```
INFO statistics stats=files_monitored=2 bytes_read=10512 lines_processed=97 lines_truncated=0 bytes_skipped=0 partial_lines_flushed=0 rule_matches=4 events_emitted=4 events_dropped=0 events_rate_limited=0 events_deduplicated=0 output_errors=0 read_errors=0 notify_overflows=0 rotations=1 truncations=0
```

`files_monitored` is a gauge: files currently open, excluding rotated files
being drained. All other values are counters since startup. Error counters
count episodes: a file that stays unreadable is counted once, not once per
retry.

### Diagnostics

Diagnostics go to stderr, at the level set by `diagnostics`. They contain
paths, error messages and counts, but never log line content, at any level.
If `destination = "stderr"`, events and diagnostics are interleaved on the
same stream.

## Deployment with systemd

[`packaging/logwizz.service`](packaging/logwizz.service) runs logwizz as a
transient unprivileged user (`DynamicUser=yes`) with read-only access to the
filesystem, no capabilities, no network, and a `@system-service` system call
filter. Events go to the journal through stdout.

```sh
install -D -m 0640 config/logwizz.example.toml /etc/logwizz/logwizz.toml
install -m 0644 packaging/logwizz.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now logwizz
journalctl -u logwizz -o cat -f
```

Read access to logs comes from `SupplementaryGroups=adm`, which is right for
Debian and Ubuntu. On other distributions, grant read access with a group or
an ACL. For example, `/var/log/secure` on RHEL-family systems is root-only:

```sh
groupadd -r logwizz
setfacl -m g:logwizz:r /var/log/secure
# Then set SupplementaryGroups=logwizz in a drop-in (systemctl edit logwizz).
```

The unit passes `systemd-analyze verify`, and `systemd-analyze security`
rates it **0.4 SAFE**. The remaining findings are deliberate:
`SupplementaryGroups` provides log access, and `PrivateUsers=yes` would unmap
that group and break it. The hardening has been verified statically only. It
has not yet been exercised on a booted systemd host, so check it against
your own log locations before relying on it.

## Security

- Runs unprivileged. Needs read access to the configured files and search
  access to their directories, nothing else.
- Never executes anything from the configuration. Patterns are data.
- Regexes use the Rust `regex` crate, which guarantees linear-time matching
  (no catastrophic backtracking), with a compiled-size limit per pattern.
- Bounded resources: configuration size (1 MiB), line length, per-file
  partial-line buffer, event queue, dedup table, rule and file counts.
- Configured paths are followed if they are symlinks. The identity tracked is
  the target's, and retargeting the link counts as a rotation. Paths are
  validated to be absolute and normalised.
- A world-writable configuration file is refused.
- Human output escapes control characters. JSON output is escaped by
  `serde_json`.
- Diagnostics never contain log line content.

## Compatibility and limitations

- **Platform:** Linux only (inotify, `sigwait`, `pread`). Developed and
  tested on Ubuntu 24.04 with kernel 6.18 on ext4. Rust's standard library
  requires Linux 3.2 or newer, and other distributions and kernels are
  expected to work, but only the configuration above has been tested.
- **inotify limits:** logwizz uses one inotify instance and one watch per
  distinct parent directory. Overflows of `fs.inotify.max_queued_events` are
  recovered by rescanning.
- **Network and FUSE filesystems:** changes made on other hosts generate no
  inotify events. Detection relies on reconciliation (`reconcile_interval_ms`).
- Not supported in 0.1.0: glob patterns, persistent offsets, runtime
  configuration reload, compressed or rotated-file catch-up, multi-line
  records.
- Rule evaluation is sequential per line. Throughput falls roughly linearly
  with the number of regex rules. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Development

Quality gates (also run in CI):

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release --locked
```

CI also builds the release binary with the MSRV toolchain
(`cargo +1.85 build --release --locked`). Raising the MSRV is a deliberate
change: update `rust-version` in `Cargo.toml`, the CI job and this README
together.

Benchmarks and load tests are run separately:

```sh
cargo bench --bench rule_engine
cargo test --release --test load -- --ignored --nocapture --test-threads=1
```

Layout:

| Path | Purpose |
|---|---|
| `src/config.rs` | TOML schema, defaults, validation, rule compilation |
| `src/reader.rs` | Per-file offsets, identity, line splitting, rotation and truncation |
| `src/watcher.rs` | inotify directory watches, dirty flags, overflow handling |
| `src/monitor.rs` | Single-threaded wait/poll loop with reconciliation |
| `src/engine.rs` | Literal and regex matching |
| `src/event.rs` | Event and severity types, timestamps, excerpts |
| `src/dispatcher.rs` | Output thread, bounded queue, formats, rate limiting, dedup |
| `src/daemon.rs` | Signals, statistics, wiring |
| `src/metrics.rs` | Atomic counters |
| `tests/` | Config, reader, rotation, monitoring loop, end-to-end and load tests |
| `benches/` | Criterion benchmarks |

## License

Apache-2.0. See [LICENSE](LICENSE).
