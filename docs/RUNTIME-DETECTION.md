# Runtime detection with the audit log

logwizz can report a few signs of a compromise after deployment, such as a
web shell starting programs or someone editing `/etc/passwd`, by reading the
Linux audit log. logwizz reads it like any other log file. The setup has two
parts:

- **auditd** records selected system calls, using the rules in
  [`packaging/audit/logwizz.rules`](../packaging/audit/logwizz.rules).
- **logwizz** watches `/var/log/audit/audit.log` with the rules in
  [`config/runtime.toml`](../config/runtime.toml).

This needs no adapter, no new event format, no root access for logwizz and
no change to its core. Both parts are optional (#82).

| Rule | Detects | Audit key |
|---|---|---|
| `service_exec` | A service user (by default `www-data`) starts any program | `logwizz_service_exec` |
| `sensitive_write` | A write or attribute change to `/etc/passwd`, `shadow`, `group`, `sudoers`, `sudoers.d/`, `sshd_config` or `/root/.ssh/` | `logwizz_sensitive_write` |
| `audit_disabled` | One of these audit rules is removed, or auditing is turned off | – |
| `audit_lost` | The kernel dropped audit records (backlog or rate limit) | – |

## Why this design

The audit rule's key is the only link between the two parts. Each audit event
has a `SYSCALL` record line, and that one line holds the key, the process
(`pid`, `ppid`, `exe`), the real and login user (`uid`, `auid`) and the event's
serial number. One regex rule per key is enough, so logwizz does not need to
combine records or run a separate translator.

Alternatives considered:

| Source | Why not |
|---|---|
| A separate adapter that translates audit records into a new line format | It would need its own parser, record assembly, queues, restart handling, packaging and tests, all to produce a line that `audit.log` already contains. Build one only if a needed detection cannot be done from a single record. |
| journald alone | It does not record process starts or file writes. On some systems journald also receives audit records (`systemd-journald-audit.socket`), but whether it does varies, so use the file. |
| fanotify / inotify | These only see file events and cannot tell which process caused them. |
| eBPF | Requires its own privileged sensor and depends on the kernel version. That is out of scope for a small host monitor. |
| Polling the process list | Short-lived processes are missed. |

Outbound connections are **not** covered: none of the sources above reports
them reliably at an acceptable cost. They are not part of this feature.

## Setup (Debian, Ubuntu)

```sh
apt install auditd
grep log_group /etc/audit/auditd.conf    # expect: log_group = adm
ls -l /var/log/audit/audit.log           # expect: -rw-r----- root adm
install -m 0640 packaging/audit/logwizz.rules /etc/audit/rules.d/
# edit the uid in that file if your service user is not www-data (33)
augenrules --load
auditctl -l | grep logwizz_
```

Then copy the `[[files]]` and `[[rules]]` blocks of `config/runtime.toml` into
`/etc/logwizz/logwizz.toml` and run `systemctl reload logwizz`. The packaged
unit already reads `adm`-readable files, so it needs no new permissions.
`audit_lost` matches kernel messages, so it only works if logwizz also reads
`kern.log` or the kernel journal (`config/detection.toml` does).

Test it:

```sh
sudo -u www-data /bin/true     # service_exec
sudo sh -c ': >> /etc/passwd'  # sensitive_write: opens for writing, writes nothing
```

To remove it, delete `/etc/audit/rules.d/logwizz.rules`, run
`augenrules --load` again, and remove the rules from the logwizz
configuration. The `audit_disabled` alert this triggers is expected. Other
audit rules are not affected.

**RHEL family:** auditd ships with `log_group = root` there. Set
`log_group` to a group the service has in its `SupplementaryGroups` and
restart auditd. This has not been tested; see #53.

## Notifications and response

The events reach `logwizz-notify` like any other event: they are grouped by
rule, and raw lines are never sent. A notification shows the rule, the count
and the time window. To also show which program ran, add `exe` to
`NOTIFY_FIELDS`. Leave it out if program paths are sensitive.

The Fail2ban bridge only acts on rules you allowlist. These rules capture no
source address, so they never lead to a ban. Nothing kills processes or
changes the firewall.

When an alert fires:

1. Look up the full audit event by the `serial` field of the logwizz event:
   `ausearch -a <serial> -i`. It shows the command line (`PROCTITLE`), the
   files (`PATH`) and the user names.
2. For `service_exec`: find the parent process (`ppid`) and the service it
   belongs to (`systemctl status <ppid>`), then the deployed version of that
   service and its release and SBOM (see
   [release verification](RELEASE-VERIFICATION.md)).
3. For `sensitive_write`: compare the file with your backup or configuration
   management. `auid` shows who logged in, even after `sudo`.

## Tuning

- If the service legitimately runs programs, such as `sendmail` from PHP's
  `mail()` or image converters, list their paths in the rule's
  `[rules.exclude]` table under `exe`. Exec auditing adds a small cost to
  every process start by that user. For a service that starts programs very
  often, prefer narrowing the audit rule (`-F exe!=...`) so the records are
  never written.
- To watch other files, add `-w <path> -p wa -k logwizz_sensitive_write`.
  For other users, add another pair of `execve` rules.
- Keep exactly one key per audit rule. auditd hex-encodes the key field of a
  rule with several keys, and the pattern no longer matches.

## What this cannot see

Say it plainly, so nobody relies on more than this gives:

- **Only what the audit rules select.** Nothing is reported for other
  users, other files, or for reading files. Network connections are not
  covered at all.
- **Root can turn it off.** Removing the rules or disabling audit is
  reported (`audit_disabled`). Stopping auditd, killing it, or editing
  `audit.log` is not. If that matters, lock the rules until the next reboot
  with `-e 2` and forward the log off the host.
- **Lost records.** When the kernel's backlog is full or the rate limit is
  reached, records are dropped. `audit_lost` reports this from the kernel
  message, and `auditctl -s` shows the counter. The counter covers all audit
  rules on the host, not just these.
- **Time.** The logwizz event's `ts` is when logwizz read the line; the
  audit time is in the line itself. These rules have no thresholds, so the
  difference does not affect detection.
- **Files.** `audit.log` is read like any other file, with the usual
  rotation handling and at-least-once delivery (see the
  [reference](REFERENCE.md#delivery-guarantees)).
- **Only the format above is tested.** `tests/runtime.rs` checks the rules
  against audit lines in the documented auditd format. They have not yet
  been checked against a real host's `audit.log`; that comes first, in the
  host verification VM.
