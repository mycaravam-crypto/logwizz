# logwizz

A small, high-performance Linux log monitoring tool written in Rust. It follows local log files and the systemd journal, matches new entries against configurable rules, and detects suspicious events and activity spikes without becoming a full SIEM or log shipper.

The core daemon stays local and network-free. A separate notifier groups detections by rule and event-time window, then sends compact summaries through Telegram, ntfy or a webhook. Notifications contain counts and minimal metadata, never raw log lines.

## Install

Download the static Linux x86-64 binary and checksums from [GitHub Releases](https://github.com/mycaravam-crypto/logwizz/releases):

```bash
v=X.Y.Z
base="https://github.com/mycaravam-crypto/logwizz/releases/download/v$v"
curl -fLO "$base/logwizz-v$v-linux-x64"
curl -fLO "$base/SHA256SUMS.txt"
sha256sum --ignore-missing -c SHA256SUMS.txt
sudo install -m 0755 "logwizz-v$v-linux-x64" /usr/local/bin/logwizz
logwizz --version
```

The notifier, `logwizz-notify-v$v-linux-x64`, is in the same release; see [the notification guide](docs/NOTIFICATIONS.md). For service deployment, use the [systemd guide](docs/REFERENCE.md#deployment-with-systemd). From source, use Rust 1.85 or newer (this builds both binaries):

```bash
cargo build --release --locked
```

## Quick start

Create `demo.log` and `demo.toml`:

```toml
[[files]]
path = "/tmp/demo.log"

[[rules]]
id = "error"
description = "Application error"
match_type = "literal"
pattern = "ERROR"
severity = "error"
```

Validate the configuration, then start monitoring:

```bash
logwizz --config demo.toml --check-config
logwizz --config demo.toml
```

In another terminal, append a matching line:

```bash
echo "ERROR disk full" >> /tmp/demo.log
```

logwizz emits a structured event for the matching rule. Use `config/logwizz.example.toml` as the starting point for a real host.

## What it does

- Monitors configured files and the systemd journal.
- Matches literal strings or Rust regular expressions.
- Supports bounded fixed and opt-in sliding threshold windows, including distinct-value counts for scans and brute force.
- Correlates rule sequences using `[rules.after]`, for example a login following a scan from the same source.
- Detects scans spanning multiple source addresses within one subnet and includes bounded samples of probed ports.
- Uses journal entry timestamps for detection windows when catching up; file inputs use read time.
- Excludes trusted sources (addresses, networks or exact values) per rule.
- Handles common log rotation, truncation, deletion and recreation cases.
- Bounds line sizes, queues and detection state to keep resource use predictable.
- Emits JSON Lines or human-readable events to stdout or stderr.
- Supports configuration validation, persisted input offsets, glob patterns, and SIGHUP reloads without restarting the daemon.

## Optional response and platforms

An optional [Fail2ban bridge](docs/FAIL2BAN.md) can pass detections from explicitly selected rules with validated, globally routable source IPs to a dedicated Fail2ban jail. It is disabled unless configured; dry-run testing, allowlists and a reviewed ban policy are recommended before enabling enforcement. Fail2ban owns bans and unbans; logwizz itself does not alter firewall policy.

Host checks cover Debian 12/13 and Ubuntu 24.04. RHEL-family packaging and guidance exist, but live RHEL/Rocky runtime validation is still outstanding ([#53](https://github.com/mycaravam-crypto/logwizz/issues/53)); do not treat it as verified platform support.

Optional [runtime detection](docs/RUNTIME-DETECTION.md) reads the Linux audit log to report programs started by a service user and changes to identity and access files. It needs auditd and the shipped audit rules, is off unless configured, and has not yet been verified on a real host ([#82](https://github.com/mycaravam-crypto/logwizz/issues/82)).

## Project boundaries

- **Detection:** local inputs, rules and thresholds; no network access in the core daemon.
- **Notifications:** a separate, replaceable delivery component. The notifier aggregates by rule and time window; outbound summaries exclude raw log content.
- **Scope:** a lightweight host-level detector, not a SIEM, long-term log store or general-purpose log forwarder.

Notification setup, window semantics, retry behavior and Telegram configuration are documented in [the notification guide](docs/NOTIFICATIONS.md). See [project direction](docs/PROJECT.md) for design boundaries.

## Documentation

- [Project direction and design principles](docs/PROJECT.md)
- [Documentation index](docs/README.md)
- [Configuration, event schema, behavior, operations, security and deployment reference](docs/REFERENCE.md)
- [Detection guide: per-source and subnet scans, SSH attacks, sequence rules and log floods](docs/DETECTION.md)
- [Runtime detection: service programs and identity file changes from the audit log](docs/RUNTIME-DETECTION.md)
- [Optional Fail2ban integration](docs/FAIL2BAN.md)
- [Benchmarks](docs/BENCHMARKS.md)
- [Host verification and systemd sandboxing](docs/HOST-VERIFICATION.md)
- [Example configuration](config/logwizz.example.toml)
- [Release binaries](https://github.com/mycaravam-crypto/logwizz/releases)
- [Release verification, provenance and SBOMs](docs/RELEASE-VERIFICATION.md)

## Development

Quality gates used in CI:

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
bash .github/scripts/semver-next.test.sh
```

The minimum supported Rust version is defined by `rust-version` in `Cargo.toml`. See the [reference](docs/REFERENCE.md#ci-and-releases) for CI, releases and detailed implementation notes.

## License

Apache-2.0. See [LICENSE](LICENSE).
