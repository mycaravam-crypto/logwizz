# ADR: Optional Linux runtime event detection (#82)

**Status:** Proposed for review (2026-10-26). Architecture recommendation, **not** an implementation or proof of platform support.

## Context and decision

logwizz is a bounded, local, unprivileged Rust log/journal detector with explicit matching/threshold/sequence rules and JSONL events. Its notifier and optional Fail2ban bridge run separately. It is neither an EDR nor a full audit collector.

**Recommendation:** start with **Linux Audit / auditd** as the candidate telemetry source for an **optional read-only, external adapter**, subject to an empirical feasibility gate on Debian/Ubuntu. Do **not** add a root or audit-netlink reader to the logwizz core; do **not** add a kernel module or eBPF dependency. The adapter consumes only an administrator-allowlisted subset of audit events and emits a bounded, normalized local stream for existing logwizz matching. No runtime-event enforcement in the MVP.

This is a conditional architectural decision: auditd must demonstrably deliver the selected events, and available reader permissions and event-loss visibility must be proven on the actual distributions. If the gate fails, stop or select a different source in a separate ADR rather than quietly broadening privileges.

## Telemetry options

| Option | Coverage for selected runtime events | Permissions, complexity and limitations | Decision |
| --- | --- | --- | --- |
| Linux Audit / auditd | Kernel-generated exec and relevant file-operation audit records when specific rules are configured | Admin must configure audit rules; audit availability, rule conflicts, record correlation, loss/backlog and permissions vary; audit logs can contain sensitive data | **Preferred feasibility candidate** |
| journald only | Existing journal entries; optionally audit-transport entries when available | Does not guarantee complete process execution, file access or outbound connection telemetry; journal access and filtering vary | **Not sufficient alone**; may be an audited transport if coverage is verified |
| fanotify/inotify | Filesystem events for selected paths | Cannot establish comprehensive process-execution or reliable actor context; permissions and path semantics differ | Not a general runtime sensor |
| eBPF tracing | Potentially richer process/network context | Kernel/privilege/compatibility and support burden beyond small-host-monitor scope | Deferred |
| Periodic polling / process listing | Snapshots only | Misses short-lived events; weak attribution and fidelity | Not suitable for MVP detections |

Audit references: https://man7.org/linux/man-pages/man8/auditd.8.html ; https://www.linux.org/docs/man8/auditctl.html ; https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html .

## Trust boundaries and data flow

1. The administrator installs and owns a minimal, **opt-in** audit ruleset, separate from logwizz. Root or equivalent permissions are confined to audit configuration / kernel audit services; existing system audit policy must not be replaced.
2. auditd/kernel records are collected by an **external adapter**, with only the read permissions needed to consume its selected source. Investigate group/ACL access or a narrowly scoped service/bridge on the target OS. Never make the logwizz daemon run as root or grant it audit capabilities.
3. The adapter groups the multiple audit records for one audit serial and boot/session context, validates field types and lengths, redacts potentially sensitive arguments, applies a finite assembly timeout and **explicit queue and memory caps**, and normalizes events.
4. Adapter output enters logwizz as a configured **local file stream** or other already-supported input. Prefer a dedicated regular log file with rotation and the existing reader's offset/restart semantics for the first MVP; do not assume FIFOs have equivalent durability. This is a locally managed trusted path, not arbitrary log text. Pattern matching can initially use a strict line schema without modifying JSONL output v1.
5. Existing rules, thresholds, sequence correlation, and logwizz JSONL event emission apply. `logwizz-notify` continues to send aggregated minimal context; raw audit records and process arguments are **not** default remote payloads. Fail2ban bridge does not consume or authorize bans from runtime rules by default.

```text
kernel audit rules -> auditd -> optional audit adapter (bounded, unprivileged reader)
                                     | validated, redacted, local events
                                     v
                          dedicated rotated local log file
                                     |
                                     v
                           logwizz file rules / thresholds
                                     |
                                     v
                           JSONL -> logwizz-notify
```

### Candidate adapter line schema (internal input, not a core JSONL v1 change)

One **complete logical event** per line, with fields in a fixed documented order and escaped or encoded values. Proposed fields: `schema_version`, `event_id` (boot identity + audit serial), `event_time` (RFC3339 UTC), `kind` (`exec` or `file_change`), `uid`, `auid`, `pid`, `ppid` (when present), `exe`, and `path` (when present). Missing optional fields must remain explicitly missing; no fabricated executable, identity, port or address. Define and test escaping before writing a parser or enabling regex rules. Truncate safely at a documented byte cap and mark truncation. Exclude command-line arguments and environment from notifications; do not persist them by default.

The current logwizz event `ts` remains **emission time**, not the audit `event_time`. The current file reader counts windows in **read time**, unlike journal input. The MVP must either demonstrate that this is acceptable for initial non-threshold rules or separately implement explicitly validated event-time semantics before claiming accurate replay-sensitive threshold/sequence behavior on adapter files. Never quietly treat the two clocks as equivalent.

## MVP scope and deployment

**One source: auditd. Two narrowly scoped scenarios at most:**

- Execution of a program by a defined service identity or under a specifically reviewed executable/path policy, provided the source offers reliable identity/attribution. Avoid high-volume all-system `execve` auditing by default.
- Writes/rename/metadata changes to an administrator-selected sensitive path, only for operations the specific audit rule actually captures. Symlink/rename/mount semantics and actor attribution need explicit tests.

**No claims** of comprehensive execution coverage, all filesystem changes, or outbound connections. Outbound network telemetry is **out of MVP scope** until an adequate source is demonstrated.

Adapter enabled only by explicit install/configuration; opt-out removes audit rules installed specifically for it without touching unrelated audit configuration. Deb/Ubuntu are primary feasibility targets. Consider RHEL-family compatibility in design and packaging but defer live RHEL/Rocky verification to #53; do not claim it tested.

## Failure modes and security controls

- **No telemetry / permission denied / auditd disabled:** clear diagnostic and health signal; logwizz stays operational without runtime detection. No claims of normal/safe host based on missing input.
- **Kernel audit lost records, backlog or rate-limit hit:** expose and test `auditctl -s` lost/backlog counters or equivalent source health; document that these counters may be system-wide and cannot be assigned to this adapter alone.
- **Audit multi-record correlation:** key by boot/session + audit serial; bound incomplete events by number, bytes and time; evict visibly and account for incomplete records. Require monotonic output ordering where possible and test out-of-order delivery.
- **Adapter restart / rotated file / persistent offset:** deduplicate or document at-least-once duplicates; never report exactly-once guarantees without persistence. Health counters for late, malformed, dropped, truncated, rejected and emitted events.
- **Sensitive data:** source lines are untrusted, potentially containing usernames, paths and secrets. Reject control characters and injection; bounded redaction, least filesystem access, restricted file mode and rotation. Remote notifications remain allowlisted and minimal.
- **Overload:** configure queue/decode/record limits and failure policy; avoid silent loss. Prove measured resource envelopes; no blocking of the main detector.
- **Privilege and response:** never execute arbitrary commands or give adapter the ability to ban, kill or modify security policy. Existing Fail2ban policy remains separate and opt-in.

## Feasibility gate before implementation

On one disposable Debian/Ubuntu VM, collect evidence for:

- Audit availability and actual event record shapes for selected rules; prove expected events **and expected non-events**, including permission denied and rename cases.
- Distinct audit records belonging to a single event and correct attribution (uid/auid/pid/path) across processes; compare observed information with proposed schema.
- How an unprivileged adapter can read them without changing the core daemon or weakening overall sandboxing.
- Audit rules lifecycle, coexistence with an existing auditd policy, rotation/restart, loss/backlog reporting, and sensitivity of captured content.
- Measured events/s, CPU, resident memory, queue/drop behavior under a representative burst; choose limits based on measurements.

**Go/no-go:** proceed only if the two selected scenarios can be reproduced with bounded and observable loss, least privilege, and no secret leakage. Otherwise revise the scope/ADR.

## Acceptance tests and delivery plan

1. **Feasibility PR**: reproducible audit rule snippets and fixture corpus, permissions matrix, measured overhead and go/no-go decision. No production sensor or changed core permissions.
2. **Adapter MVP PR** (only after go): strict schema and parser tests; bounded event assembly; malformed/missing data, timeout and flood; start/stop/restart; file rotation; explicit loss counters; optional packaging.
3. **Integration PR**: offline fixtures through actual logwizz file rules to JSONL and notifier summary; verify rule identity, timestamps, redaction, duplicates, replay limitations and opt-out.
4. **Operations/security review**: installation/removal, rights, diagnostics, coverage gaps, incident triage and resource settings. Host test on Debian/Ubuntu; RHEL stays tracked separately.

Acceptance must verify one realistic runtime scenario end-to-end, no unbounded queue or privilege escalation, no raw logs/secrets in default notifications, an explicit unsupported-source diagnostic, and documented blind spots.

## Traceability

- Parent: #82 (runtime-detection exploration/MVP)
- Precedence: #91 (detection/Fail2ban hardening)
- RHEL validation deferred: #53
- Existing principles: docs/PROJECT.md, docs/REFERENCE.md, docs/DETECTION.md
- Existing response design: docs/active-response-design.md and docs/FAIL2BAN.md

This ADR is a **proposal requiring review**; no audit adapter or detection coverage is introduced by merging documentation alone.
