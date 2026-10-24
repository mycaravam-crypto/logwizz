# Host verification

This document covers the verification of [`packaging/logwizz.service`](../packaging/logwizz.service) on a booted
systemd host: item 1 of #7, the last check before 0.1.0. Until then the unit had only been checked statically
(`systemd-analyze verify` and `security --offline`).

## Setup

| | |
|---|---|
| Host | Ubuntu 24.04 cloud image (`noble-server-cloudimg-amd64`), fresh VM per run |
| Kernel / systemd | 6.8.0-147-generic / systemd 255 (255.4-1ubuntu8.18) |
| Virtualisation | qemu, TCG (no KVM in the build container), 4 vCPUs, 3 GiB |
| logwizz | `main` at 113f614 plus this change, static musl release build (the release asset) |
| Installation | exactly as the README documents: binary, config `0640 root:adm`, unit, `systemctl enable --now` |
| Watched files | `/var/log/auth.log`, `/var/log/syslog` (example config), `/var/log/lwtest.log` (test file) |

Reproduce with `tests/host/run-vm.sh`. It boots the VM, runs [`tests/host/hostcheck.sh`](../tests/host/hostcheck.sh)
inside and prints one `RESULT` line per check: `PASS`, `FAIL`, or `KNOWN` for a documented limitation.

## Results (final run)

| Check | Result | Detail |
|---|---|---|
| `systemd-analyze verify` | PASS | |
| Service starts, `ExecStartPre` config check | PASS | after the fix below |
| Identity | PASS | transient UID 62686, supplementary group `adm`, `CapEff=0` |
| `/var/log/auth.log` via `adm` | PASS | `logger -p auth.notice` → event |
| `/var/log/syslog` via `adm` | PASS | regex rule |
| Append | PASS | |
| Rename + create rotation | PASS | late write to the old file is read; old data is emitted before new |
| copytruncate (writer continues after the truncate) | PASS | |
| copytruncate, truncate and regrow between two polls | KNOWN | missed; this is the documented copytruncate race |
| Delete + recreate | PASS | |
| Real `logrotate -f /etc/logrotate.d/rsyslog` | PASS | events from the new `auth.log` |
| Kernel inotify overflow (`max_queued_events=16`, reader stopped) | PASS | `notify_overflows=1`, event still delivered by the rescan |
| Sandbox denials (strace of the daemon, all failed syscalls) | PASS | no `EPERM`/`EACCES` in 202 failed calls (only `EAGAIN`, `ETIMEDOUT`, `ENOENT`) |
| Statistics on `SIGUSR1` | PASS | `read_errors=0`, `output_errors=0` |
| Resource use | PASS | about 1.3 MB memory, 4 tasks (limits: 128 MB, 16 tasks) |
| Online `systemd-analyze security` | PASS | **0.4 SAFE**, the same rating as the static check |
| `Restart=on-failure` after `kill -9` | PASS | restarted after 5 s |
| Clean stop | PASS | 0.32 s, exit 0, `Result=success`, the last event was flushed |
| Self-matching through journald and rsyslog | **FAIL** | 77 events re-matched logwizz's own output, see finding 2 |

The no-warnings check also failed in the final run, but that was the check itself. It counted logwizz's expected
"file truncated" warning from the copytruncate step. The script now excludes that warning.

## Findings

### 1. The documented install left the config unreadable (fixed)

The first run failed immediately. The README installed the configuration with `install -D -m 0640` as `root:root`.
The service runs as a transient `DynamicUser`, so it could not read the file. `--check-config` in `ExecStartPre` then
exited 2 with `Permission denied`, and the unit crash-looped.

**Fix (this change):** install the file as `0640` with group `adm`, the group the unit already grants through
`SupplementaryGroups`. The README and the unit header now explain this, and the RHEL snippet gets the matching
`chgrp`. `LoadCredential=` was considered, but it copies the file once at start, which conflicts with the planned
SIGHUP reload (#11).

### 2. logwizz matches its own events through journald and rsyslog (#21, open)

Events go to stdout and from there to the journal. rsyslog forwards the journal to `/var/log/syslog`. That file is in
the example config, so logwizz reads its own event lines back, and the rules match the embedded original line again.
Each round nests the previous event, and the line grows about 1.6× per round:

```
585 → 964 → 1495 → 2330 → 3773 → 6432 → 11523 bytes
```

The loop ends only because rsyslog cuts messages at 8 KiB. One real match therefore produces about 7 spurious events
and extra syslog volume. The README now warns about this. The recommended fix is `LogNamespace=` in the unit, plus
`kern.log` in the example config; see #21.

### 3. Transient EACCES on files that are created and then chowned (#22, open)

This was seen in 1 of 2 runs. `install -o root -g adm`, and likewise logrotate's `create`, makes the file root-only
before changing its group. When logwizz opened the file in that window, it logged `cannot access file; will retry`
and counted `read_errors=1`. The retry succeeded and nothing was lost, but the warning and the counter are
misleading.

### 4. Confirmed as documented

- **copytruncate race:** a truncate followed by a write larger than the old offset, both between two polls, is
  missed. The README already recommends rename-based rotation.
- **inotify overflow** (the manual check that was still open on #1 and #4) works on a real kernel: the overflow is
  counted, and the rescan still delivers events.

## Improvements

| # | Improvement | Tracking |
|---|---|---|
| 1 | Stop the syslog feedback loop (`LogNamespace=`, and `kern.log` in the example config) | #21 |
| 2 | Retry a fresh `EACCES` once before warning and counting it | #22 |
| 3 | Run `tests/host/run-vm.sh` in CI; GitHub runners have KVM, so a run takes about a minute | #24 |
| 4 | Run the host check on RHEL-family images together with the drop-in | #13 |
| 5 | Re-run the benchmarks on a dedicated machine before publishing numbers | #7, item 5 |

## Notes on the method

- **Strace instead of audit:** with `SystemCallErrorNumber=EPERM`, a filtered syscall fails quietly and the kernel
  logs nothing. The script therefore attaches strace to the daemon and lists every failed call.
- **Overflow test:** `fs.inotify.max_queued_events` is read when an inotify instance is created. The check lowers it
  first, restarts the service, then stops the reader during a burst of events.
- **Run-to-run variation:** results that depend on timing (findings 3 and 4) can differ between runs. Each run uses
  a fresh VM.
