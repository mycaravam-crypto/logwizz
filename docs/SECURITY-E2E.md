# Security / Fail2ban end-to-end verification (#91)

This document describes **reproducible tests**, not pre-existing test results.

## Host matrix and test environment

The existing host workflow boots disposable cloud VMs for Debian 12,
Debian 13 and Ubuntu 24.04. The guest installs Fail2ban and nftables
and runs tests/host/fail2ban-e2e.sh from tests/host/hostcheck.sh.
Logs, systemd/guest diagnostics and RESULT lines are retained in each
hostcheck-logs-* CI artifact.

No production firewall or actual client is changed. All test IPs belong to
the documentation-only TEST-NET block; Fail2ban operates within the guest.

## Live acceptance checks

1. No ban when the bridge is off and before test input is written.
2. A normalized event bans the test IP in a real Fail2ban jail, installs
   the expected nftables set element, emits a V2 trusted journal report
   and delivers the verified status through a locally trusted HTTPS webhook.
3. A duplicate event does not create a duplicate action report.
4. The actual Fail2ban unban command removes the nftables membership.
5. ignoreip and malformed source input do not trigger an action report.
6. An intentionally failing firewall action still reaches the reporter,
   but cannot generate a verified claim without installed nftables state.
7. A stopped jail never emits a new report.
8. A 2,000-line input burst checks exactly 2,000 emitted detection events
   (no observed loss for this load), records RSS/CPU samples while the
   workload is processed, and requires each observed resident-memory sample
   to remain below 64 MiB. The test first waits for an emitted readiness
   marker from the monitored file, because `startup_mode = "tail"` intentionally
   ignores data written before the reader opens that file. This is a
   repeatable bounded-load check, not a worst-case CPU SLA, continuous peak
   memory measurement, or proof that all overload scenarios are lossless.

The bridge dry-run/no-enforcement, non-global-IP, rule allowlist and
invalid-settings paths are covered by packaging/fail2ban/test_bridge.py.
Rust regression tests cover journal replay, event ordering and thresholds,
cooldown, cursor recovery, bounded queue, and notifier delivery retry.

## Guarantee boundary

Fail2ban can invoke later actions even after an earlier firewall action
fails. PR #115 therefore independently queries nftables membership and the
active input-hook drop/reject rule before emitting a verified report.
This is evidence of nftables state at the inspection point; it is not proof
that a particular network packet was blocked or that no earlier rule
accepted traffic.

The verifier intentionally fails closed on iptables/custom nftables
backends. The monitoring daemon never needs firewall privileges.

## Reproduction and evidence

- CI: .github/workflows/host.yml
- VM bootstrap: tests/host/run-vm.sh
- Live integration: tests/host/fail2ban-e2e.sh
- Existing runtime tests: tests/host/hostcheck.sh
- Python unit tests: python3 packaging/fail2ban/test_report.py
- Bridge tests: python3 packaging/fail2ban/test_bridge.py
- Guest results: RESULT fail2ban_e2e PASS/FAIL in hostcheck-logs-* artifacts

Future extension: originate actual packets from a dedicated network namespace
to validate packet-path drop behavior, not merely ruleset state.
