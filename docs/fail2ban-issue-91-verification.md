# Issue #91 — Fail2ban response verification and operating contract

## Decision: best-effort enforcement, no historic auto-ban

The optional Python bridge is an **online best-effort adapter**; logwizz's unprivileged, network-free core is unchanged. The bridge uses `journalctl --follow --since=now`: events emitted while the bridge is stopped can be lost for enforcement. It must **not** replay historical detections into live bans without a separate security and operational review. The `journalctl` exit status is propagated, and the systemd unit restarts on failure. Operators must monitor restart counts and gaps.

The bridge validates address syntax/global unicast status, normalized IPv4-mapped IPv6, ignored CIDRs and explicit rule allowlists. This **does not authenticate the provenance** of `fields.src`. Any detector using user-controlled log fields (for example X-Forwarded-For) needs trusted-proxy/source provenance validation before its rule can be allowlisted. IPv4/IPv6 parsing alone cannot prevent ban-by-spoofing.

## Failure-mode matrix

| Scenario | Intended behavior | Evidence | Status |
| --- | --- | --- | --- |
| Missing/invalid source, malformed JSON | Drop, never enforce | `test_bridge.py` format tests | Automated |
| Non-global, ignored IP, unauthorized rule | Drop, never enforce | `test_bridge.py` format/stream tests | Automated |
| Explicit blank/malformed allowlist | Reject configuration; bridge cannot start | `test_blank_explicit_allowlist_is_rejected` | Automated |
| Dry-run | No enforcement log written; each eligible event is reported on stderr as `would write: <line>` (journal under systemd) | `test_dry_run_never_creates_enforcement_log` | Automated |
| Journal command non-zero exit | Non-zero bridge exit, systemd restart | `test_journalctl_failure_status_is_propagated` | Simulated |
| Fail2ban not installed/stopped | Bridge may still write log; **no ban**; alarm required | Isolated VM | **Not verified** |
| Bridge restart / journal gap | No automatic history replay; possible missed enforcement | `--since=now` documented | Known limitation |
| Actual Fail2ban ban / unban | Only allowlisted addresses; unban as configured | Isolated VM | **Not verified** |
| Burst, queue pressure, resource caps | Document drops/backpressure and systemd MemoryMax=32M, TasksMax=16 | Bounded-load host measurements | **Not verified** |
| Forged but globally routable source | Source provenance must be verified in detector, not bridge | Threat model + detector-origin test | **Not verified** |

## Isolated Debian/Ubuntu host acceptance procedure

Use a disposable VM with console access and a snapshot. Never run a ban test against the VM's management address. No production host or external target. Install the logwizz bridge and Fail2ban jail/filter from this repository; keep production policy untouched. Confirm active jail, `fail2ban-client status`, and current firewall rules before testing. Restrict firewall testing to a disposable network namespace or an isolated VM interface. Use an IP reserved for a lab network and ensure test traffic really reaches the interface; the bridge intentionally refuses documentation/private addresses, so live bridge fixtures must originate from a source legitimately classified as global and controlled within the isolated lab.

1. With `BRIDGE_DRY_RUN=1`, emit one eligible detection into the dedicated logwizz journal and verify the bridge writes **no** line into `/var/log/logwizz/fail2ban.log` and instead logs one `would write:` line to stderr (visible in the bridge unit's journal); assert that Fail2ban's banned-address list remains unchanged.
2. Enable the bridge with a minimal allowlist; generate an eligible detector event from a verified, lab-controlled source; confirm the file output, filter match, Fail2ban jail state and effective firewall ban. Record timestamps and command outputs.
3. Verify the configured unban (short controlled `bantime` or `fail2ban-client set <jail> unbanip <address>`), including removal of the firewall action.
4. Repeat with unauthorized rules, spoofed sources, ignored IP ranges, invalid settings, missing `journalctl`, Fail2ban stopped, bridge disabled, and service restarts. Verify **zero unintended bans** and visible failure diagnostics.
5. Run a bounded replay at documented rates (e.g. 100, 1,000 and 10,000 events/s for 60 seconds) with a maximum input budget and CPU/memory telemetry. Record emitted, accepted, dropped and banned event counts, duration, maximum RSS, CPU, systemd restarts, journald rate-limit settings and any gaps. Do not claim zero loss without reconciled counters.
6. Store anonymized evidence with distro/kernel/systemd/Fail2ban/Python versions and exact configuration. Never include operational IPs, credentials or identifying logs in public artifacts.

## Release gate

Issue #91 must remain open until the VM evidence proves real ban **and** unban, dry-run no enforcement, backend failure behavior and meaningful bounded-load measurements. Debian/Ubuntu validation does not imply Rocky/RHEL validation (#53). Runtime observability architecture remains in #82. No automatic widening of privileges or policy.
