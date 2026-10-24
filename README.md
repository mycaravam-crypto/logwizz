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

- [Installing](#installing)
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
- [CI and releases](#ci-and-releases)

## Installing

Each [GitHub release](https://github.com/mycaravam-crypto/logwizz/releases)
has a static Linux x64 binary (musl, no runtime dependencies, any
distribution), the systemd unit, the example configuration and
`SHA256SUMS.txt`:

```sh
v=X.Y.Z   # the release to install
base=https://github.com/mycaravam-crypto/logwizz/releases/download/v$v
curl -fL -O "$base/logwizz-v$v-linux-x64" -O "$base/SHA256SUMS.txt"
sha256sum --ignore-missing -c SHA256SUMS.txt
install -m 0755 "logwizz-v$v-linux-x64" /usr/bin/logwizz
logwizz --version
```

Then continue with [Deployment with systemd](#deployment-with-systemd).

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
| `state_file` | unset | absolute path | Persist read offsets here, so a restart resumes where it stopped (at-least-once delivery). Unset keeps offsets in memory only. See [Delivery guarantees](#delivery-guarantees). |
| `state_flush_ms` | `1000` | 100 – 600000 | Minimum time between writes of `state_file`. |

### `[output]`

| Key | Default | Meaning |
|---|---|---|
| `format` | `"json"` | `json` (JSON Lines) or `human`. |
| `destination` | `"stdout"` | `stdout` or `stderr`. |
| `queue_capacity` | `4096` | Maximum events buffered between the reader and the output writer (1 – 1048576). |
| `max_queue_bytes` | `8388608` | Maximum memory held by buffered events, in bytes (64 KiB – 1 GiB): each event counts its line plus a small fixed overhead. The queue is full when either limit is reached. An event larger than this is still accepted into an empty queue. |
| `on_full` | `"block"` | Full queue: `block` pauses reading, `drop` discards the event and counts it. See [Backpressure](#backpressure). |
| `max_excerpt_bytes` | unset | If set (16 – 16 MiB), events include at most this many bytes of the line, cut on a UTF-8 boundary, with `truncated: true`. |

### `[limits]`

| Key | Default | Meaning |
|---|---|---|
| `rate_limit_events` | `0` | Maximum events per rule per window. `0` means unlimited. |
| `rate_limit_window_secs` | `60` | Length of the fixed rate-limit window. |
| `dedup_window_secs` | `0` | Suppress an identical (rule, line) pair within this many seconds of the event first emitted for it. `0` disables it. Lines suppressed by the rate limit are not remembered, so a line that was never reported is never treated as a duplicate. |
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
- if a configured path is a symlink whose target is in another directory,
  that directory is watched too, so writes to the target are detected just
  as quickly. When the link is retargeted, the watch moves with it, right
  after the rotation is detected. Intermediate links in a chain are only
  re-checked on reconciliation.
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
bounded queue (`queue_capacity` events, `max_queue_bytes` bytes). Output is
buffered and flushed whenever the queue runs empty.

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

Without `state_file`, logwizz provides **best-effort, at-most-once delivery
within one process lifetime**:

- Offsets are kept in memory only. After a restart, `startup_mode` decides
  where reading resumes: `tail` skips anything written while logwizz was
  down, and `beginning` re-emits events for existing content.
- Events still queued when the process is killed with SIGKILL, or crashes,
  are lost. On SIGTERM/SIGINT the queue is flushed before exit. Flushing
  waits for the output to accept the data, so with a stalled consumer the
  process does not exit until it is killed (the systemd unit does so after
  `TimeoutStopSec`).

With `state_file`, delivery across restarts is **at-least-once**:

- For each file, logwizz saves the offset just past the last complete line,
  but only once every event from the lines before it has been written and
  flushed to the output. After a crash or SIGKILL, reading resumes from the
  last saved offset, so events since then are emitted again, but no line is
  skipped. After SIGTERM/SIGINT the final offsets are saved once the queue
  has been flushed, so nothing is repeated.
- On startup, a saved offset is used only if the file at the path is still
  the same file (`dev`, `ino`), is at least as long as the offset, and still
  starts with the same bytes (a fingerprint of the first 256 bytes, which
  detects a reused inode). Otherwise the file changed while logwizz was
  stopped: it is read from the beginning, with a warning. Files without a
  saved offset follow `startup_mode`.
- The state file is written atomically (temporary file, `fsync`, rename,
  directory `fsync`), at most every `state_flush_ms`, with mode `0600`. If
  it is missing, unreadable or invalid, logwizz warns and falls back to
  `startup_mode`; it never refuses to start. Failed writes are counted in
  `state_save_errors` and retried.
- Not covered: a file rotated away while logwizz was stopped is not read
  again, so lines appended to it after the last save and before the
  rotation are missed; the same applies to a file that was still being
  drained after a rotation at shutdown. A line still incomplete at a
  restart is read again from its start.
- `on_full = "drop"` does not hold back saved offsets: events it drops
  are lost, as configured.

In both modes:

- Incomplete trailing lines (no newline yet) are not emitted at shutdown.
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
INFO statistics stats=files_monitored=2 bytes_read=10512 lines_processed=97 lines_truncated=0 bytes_skipped=0 partial_lines_flushed=0 rule_matches=4 events_emitted=4 events_dropped=0 events_rate_limited=0 events_deduplicated=0 output_errors=0 read_errors=0 notify_overflows=0 rotations=1 truncations=0 state_saves=0 state_save_errors=0
```

`files_monitored` is a gauge: files currently open, excluding rotated files
being drained. All other values are counters since startup. Error counters
count episodes: a file that stays unreadable is counted once, not once per
retry.

| Counter | Meaning |
|---|---|
| `bytes_read` | Bytes read from monitored files. |
| `lines_processed` | Lines passed to the rules, including truncated ones. |
| `lines_truncated` | Lines cut at `max_line_bytes`. |
| `bytes_skipped` | Content bytes beyond `max_line_bytes` that were not matched. |
| `partial_lines_flushed` | Unterminated lines emitted because their file was truncated, rotated or deleted. |
| `rule_matches` | (line, rule) matches, before rate limiting and deduplication. |
| `events_emitted` | Events accepted into the output queue. An event is written unless the output fails or the process is killed first. |
| `events_dropped` | Events discarded because the queue was full (`on_full = "drop"`), the output had failed, or shutdown interrupted a blocked send. |
| `events_rate_limited`, `events_deduplicated` | Matches suppressed by `[limits]`. |
| `output_errors` | Output write failures (each one stops the daemon). |
| `read_errors` | Episodes of unreadable files or paths that are not regular files. |
| `notify_overflows` | inotify queue overflows (each one triggers a full rescan). |
| `rotations`, `truncations` | Detected replacements and truncations. |

`rule_matches` = `events_emitted` + `events_dropped` + `events_rate_limited` +
`events_deduplicated`.

### Memory use

Every buffer has a configured bound. The worst case is approximately:

- per monitored file: up to 2 × `max_line_bytes` of incomplete-line data
  (the current file plus one rotated file being drained)
- the output queue: `max_queue_bytes`, plus one event
- the output writer: 64 KiB, plus one formatted event. Escaping can make a
  formatted event up to about 6 × the line length (`\u0001` for each control
  byte)
- deduplication: about 100 bytes × `dedup_max_entries` (≈ 0.4 MiB by default)
- a fixed 64 KiB read buffer, plus the compiled rules (at most 2 MiB each)

With the defaults, this is about 9 MiB plus 128 KiB per monitored file,
whatever the log content, on top of a baseline of roughly 5 MiB. With the
systemd unit's `MemoryMax=128M`, that leaves room for several hundred files.
If you raise `max_line_bytes`, `max_queue_bytes`, the number of files or
`dedup_max_entries`, check the sum against `MemoryMax`.

### Diagnostics

Diagnostics go to stderr, at the level set by `diagnostics`. They contain
paths, error messages and counts, but never log line content, at any level.
If `destination = "stderr"`, events and diagnostics are interleaved on the
same stream.

## Deployment with systemd

[`packaging/logwizz.service`](packaging/logwizz.service) runs logwizz as a
transient unprivileged user (`DynamicUser=yes`) with read-only access to the
filesystem, no capabilities, no network, and a `@system-service` system call
filter. Events go to stdout, and from there to the journal in a separate
`logwizz` namespace (`LogNamespace=logwizz`, systemd 245 or newer).

```sh
install -D -m 0640 -g adm config/logwizz.example.toml /etc/logwizz/logwizz.toml
install -m 0644 packaging/logwizz.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now logwizz
journalctl --namespace=logwizz -u logwizz -o cat -f
```

The service user only exists while the service runs, so it reads the
configuration through its supplementary group: keep the file group-owned by
`adm` (or the group from your drop-in) and not world-writable. A config that
only root can read makes `--check-config` fail with "Permission denied" and the
service never starts.

The unit provides `/var/lib/logwizz` (`StateDirectory=`) for
`state_file = "/var/lib/logwizz/offsets.json"`.

Read access to logs comes from `SupplementaryGroups=adm`, which is right for
Debian and Ubuntu. On other distributions, grant read access with a group or
an ACL. For example, `/var/log/secure` on RHEL-family systems is root-only:

```sh
groupadd -r logwizz
setfacl -m g:logwizz:r /var/log/secure
chgrp logwizz /etc/logwizz/logwizz.toml
# Then set SupplementaryGroups=logwizz in a drop-in (systemctl edit logwizz).
```

The unit passes `systemd-analyze verify`, and `systemd-analyze security`
rates it **0.4 SAFE**. The remaining findings are deliberate:
`SupplementaryGroups` provides log access, and `PrivateUsers=yes` would unmap
that group and break it. The unit has also been exercised on a booted Ubuntu
24.04 host (systemd 255): reading `auth.log` and `syslog` through `adm`, real
logrotate runs, no sandbox denials, restart on failure and a clean stop. See
[docs/HOST-VERIFICATION.md](docs/HOST-VERIFICATION.md), and rerun it with
`tests/host/run-vm.sh`.

The namespace keeps logwizz's output out of the main journal. That matters:
on Debian and Ubuntu, rsyslog copies the main journal into `/var/log/syslog`,
so without the namespace a watched syslog file would contain every event
logwizz writes, and the rules would match them again. The same applies when
you run logwizz outside the packaged unit: **do not watch a file that receives
logwizz's own output.** The namespace has its own retention settings in
`/etc/systemd/journald@logwizz.conf`.

## Security

- Runs unprivileged. Needs read access to the configured files and search
  access to their directories, nothing else.
- Never executes anything from the configuration. Patterns are data.
- Regexes use the Rust `regex` crate, which guarantees linear-time matching
  (no catastrophic backtracking), with a compiled-size limit per pattern.
- Bounded resources: configuration size (1 MiB), line length, per-file
  partial-line buffer, event queue (by count and by bytes), dedup table, rule
  and file counts. See [Memory use](#memory-use).
- Configured paths are followed if they are symlinks. The identity tracked is
  the target's, and retargeting the link counts as a rotation. Paths are
  validated to be absolute and normalised.
- A world-writable configuration file is refused.
- Human output escapes control characters, Unicode bidi controls,
  zero-width characters and line separators, so log content cannot inject
  terminal sequences or visually reorder a line. JSON output is escaped by
  `serde_json`.
- Diagnostics never contain log line content.

## Compatibility and limitations

- **Platform:** Linux only (inotify, `sigwait`, `pread`). Developed and
  tested on Ubuntu 24.04 with kernel 6.18 on ext4. Rust's standard library
  requires Linux 3.2 or newer, and other distributions and kernels are
  expected to work, but only the configuration above has been tested.
- **inotify limits:** logwizz uses one inotify instance and one watch per
  distinct parent directory, plus at most one per configured symlink whose
  target is in another directory. Overflows of `fs.inotify.max_queued_events` are
  recovered by rescanning.
- **Network and FUSE filesystems:** changes made on other hosts generate no
  inotify events. Detection relies on reconciliation (`reconcile_interval_ms`).
- Not supported in 0.1.0: glob patterns, runtime
  configuration reload, compressed or rotated-file catch-up, multi-line
  records.
- Rule evaluation is sequential per line. Throughput falls roughly linearly
  with the number of regex rules. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Development

Quality gates (also run in CI):

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
bash .github/scripts/semver-next.test.sh
```

The `msrv` CI job builds the release binary with the toolchain named by
`rust-version` in `Cargo.toml` (locally: `cargo +1.85 build --release --locked`).
Raising the MSRV is a deliberate change: update `rust-version` and this README
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

## CI and releases

GitHub Actions run on every pull request and on `main`:

- **test**: `fmt`, `clippy -D warnings`, `cargo test`, the release build and the systemd unit check
  (`systemd-analyze verify` and a `security` threshold); the `msrv` job builds the release binary on the
  `rust-version` from `Cargo.toml`.
- **security**: Trivy scans `Cargo.lock` for CVEs (weekly too). A fixable CRITICAL fails the job.
- **codeql**: CodeQL `security-and-quality` analysis of the Rust code and the workflows (weekly too).
- **release**: each merged PR into `main` tags the next SemVer version and publishes a GitHub release. The release has
  `logwizz-vX.Y.Z-linux-x64` (static, musl), `logwizz.service`, `logwizz.example.toml` and `SHA256SUMS.txt`, with
  generated release notes. Git tags are the source of truth. A PR label picks the bump: `release:patch` (the default),
  `release:minor`, `release:major`, or `release:none` to skip the release. The version shows in `logwizz --version`.

Dependabot proposes weekly dependency and action updates (pinned by SHA) after a 7-day cooldown.

## License

Apache-2.0. See [LICENSE](LICENSE).
