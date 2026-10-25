# Project direction

## Purpose

logwizz is a small Linux log anomaly and event detector written in Rust. It watches local log files and the systemd journal, evaluates new entries against explicit rules and thresholds, and reports noteworthy activity.

It should be useful on a single host with low overhead and predictable resource use. It is not intended to become a full SIEM, a log database, or a general-purpose log shipper.

## Operating model

1. **Collect locally.** Read configured files and journal entries. Handle rotation and transient filesystem changes without requiring a remote service.
2. **Detect.** Match known events with literal or regular-expression rules. Use thresholds and grouping to detect patterns that only become suspicious across multiple entries, such as brute-force attempts, port scans and log floods.
3. **Summarize.** Convert matches into bounded detection summaries grouped by rule and time window. Keep counts, severity, window boundaries and minimal host/source metadata. Do not include raw log lines in the default notification payload.
4. **Deliver separately.** A small companion process sends summaries to configured channels. The core daemon remains network-free, and a delivery outage must not stall log monitoring.

## Notification direction

The first priority is a Telegram channel, with other transports kept behind the same small notification interface where practical.

A notification should answer: **what rule fired, how often, how severe, and over what period?** For example:

```text
logwizz alert · web1
Rule: ssh_failed_login
Severity: warning
Matches: 37
Window: 12:40–12:41 UTC
Source: 203.0.113.8
```

The notifier now emits this aggregate-first shape for Telegram, ntfy, webhook and email delivery. See [Notification operations](NOTIFICATIONS.md) for setup and delivery semantics.

Design requirements:

- Aggregate repeated matches by rule within a configurable, bounded time window.
- Do not send one notification per matching line.
- Exclude raw log messages and excerpts by default.
- Bound memory and payload size, and define flush behavior on window rollover and shutdown.
- Preserve delivery retry behavior and document duplicate-delivery semantics.
- Keep credentials out of command-line arguments and logs; verify TLS for HTTPS transports.
- Make transport failure visible without allowing it to block local detection.
- Test counts, grouping, window boundaries, failure paths and the absence of raw log content.

## Design principles

- **Small and focused:** solve host-level detection well before adding broad platform features.
- **Local-first:** no network access in the core daemon.
- **Explicit rules:** predictable matching and thresholds; avoid opaque behavior.
- **Bounded resources:** memory, queues, line length, state and payload sizes have limits.
- **Safe failure modes:** report failures, do not silently pretend delivery succeeded.
- **Observable:** useful counters and diagnostics without echoing sensitive log content.
- **Replaceable outputs:** structured events internally, notification transports outside the core.
- **Incremental changes:** small PRs with tests and docs, and no unrelated refactors.

## Near-term priorities

1. Validate aggregate behavior and delivery reliability on real hosts.
2. Improve retry observability and make pending-summary backlog easy to inspect.
3. Consider additional transports only after the shared summary interface is stable.

The README should remain a short entry point. Detailed configuration and runtime behavior belong in the [technical reference](REFERENCE.md); focused operational material belongs in the relevant guide.
