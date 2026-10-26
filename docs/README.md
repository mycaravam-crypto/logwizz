# logwizz documentation

Use this page to find the right level of detail.

## Start here

- [Project direction](PROJECT.md): purpose, boundaries, notification model and development priorities.
- [Main README](../README.md): overview, install and quick start.
- [Technical reference](REFERENCE.md): full configuration, event format, runtime behavior, operations, security and deployment.

## Guides

- [Detection guide](DETECTION.md): configure firewall logging and detect port scans, SSH brute force, scanner probes and log floods.
- [Runtime detection](RUNTIME-DETECTION.md): optional; programs started by a service user and changes to identity files, from the Linux audit log.
- [Fail2ban integration](FAIL2BAN.md): optional, standalone bridge from selected detection events to Fail2ban.
- [Notification operations](NOTIFICATIONS.md): Telegram setup, aggregation windows, delivery guarantees and security.
- [Benchmarks](BENCHMARKS.md): performance methodology and results.
- [Host verification](HOST-VERIFICATION.md): real systemd service validation and filesystem access.
- [Release verification](RELEASE-VERIFICATION.md): verify release provenance and inspect published CycloneDX SBOMs.

## Configuration and deployment

- [Example configuration](../config/logwizz.example.toml)
- [Detection rules](../config/detection.toml), [runtime detection rules](../config/runtime.toml) and [audit rules](../packaging/audit/logwizz.rules)
- [Systemd service](../packaging/logwizz.service)
- [Fail2ban integration files](../packaging/fail2ban/)
- [Notification service and example environment](../packaging/logwizz-notify.service), [environment template](../packaging/notify.env.example)

The notification transport is intentionally separate from the core daemon. It sends aggregate detection summaries, not raw log forwarding; see [Project direction](PROJECT.md).
