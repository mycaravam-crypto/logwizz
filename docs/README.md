# logwizz documentation

Use this page to find the right level of detail.

## Start here

- [Project direction](PROJECT.md): purpose, boundaries, notification model and development priorities.
- [Main README](../README.md): overview, install and quick start.
- [Technical reference](REFERENCE.md): full configuration, event format, runtime behavior, operations, security and deployment.

## Guides

- [Detection guide](DETECTION.md): configure firewall logging and detect port scans, SSH brute force, scanner probes and log floods.
- [Fail2ban integration](FAIL2BAN.md): optional, standalone bridge from selected detection events to Fail2ban.
- [Notification operations](NOTIFICATIONS.md): Telegram setup, aggregation windows, delivery guarantees and security.
- [Benchmarks](BENCHMARKS.md): performance methodology and results.
- [Host verification](HOST-VERIFICATION.md): real systemd service validation and filesystem access.

## Configuration and deployment

- [Example configuration](../config/logwizz.example.toml)
- [Detection rules](../config/detection.toml)
- [Systemd service](../packaging/logwizz.service)
- [Fail2ban integration files](../packaging/fail2ban/)
- [Notification service and example environment](../packaging/logwizz-notify.service), [environment template](../packaging/notify.env.example)

The notification transport is intentionally separate from the core daemon. It sends aggregate detection summaries, not raw log forwarding; see [Project direction](PROJECT.md).
