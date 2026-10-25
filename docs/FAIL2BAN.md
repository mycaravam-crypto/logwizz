# Optional Fail2ban integration

This integration is an independent bridge from Logwizz's structured events to
[Fail2ban](https://www.fail2ban.org/). Logwizz remains a detector: Fail2ban
owns retry policy, allowlists, firewall actions, ban duration and unban state.
Nothing in the Rust core depends on Fail2ban, and no bans are enabled by
installing the files alone.

## What it does

The optional bridge follows the packaged service's dedicated systemd journal
namespace, parses JSON events, and writes a normalized line only for an
explicit allowlist of rules with a valid source IP:

- `port_scan`
- `fast_scan`
- `tcp_flag_scan`
- `ssh_bruteforce`
- `ssh_probe`
- `scanner_user_agent`

Events without a `fields.src` address, malformed JSON, unrelated rules and
invalid IP addresses are ignored. The bridge uses Python's standard library;
it adds no Rust dependency and does not modify Logwizz configuration or
runtime behavior. It starts following from the current time, so it does not
replay old journal events on startup.

## Install

These steps assume the standard `packaging/logwizz.service` with
`LogNamespace=logwizz` and a working Logwizz installation.

Install the optional files:

```sh
sudo install -D -m 0755 packaging/fail2ban/logwizz-fail2ban-bridge \
  /usr/local/libexec/logwizz-fail2ban-bridge
sudo install -D -m 0644 packaging/fail2ban/logwizz-fail2ban-bridge.service \
  /etc/systemd/system/logwizz-fail2ban-bridge.service
sudo install -D -m 0644 packaging/fail2ban/filter.d/logwizz.conf \
  /etc/fail2ban/filter.d/logwizz.conf
sudo install -D -m 0644 packaging/fail2ban/jail.d/logwizz.local \
  /etc/fail2ban/jail.d/logwizz.local
sudo install -D -m 0644 packaging/fail2ban/logrotate.conf \
  /etc/logrotate.d/logwizz-fail2ban
```

The bridge runs as a dynamic unprivileged user with read access to the system
journal and writes `/var/log/logwizz/fail2ban.log`. Fail2ban normally runs as
root and can read that file. The log contains rule IDs and validated IP
addresses, not raw source log lines.

Review `/etc/fail2ban/jail.d/logwizz.local`, then explicitly enable the jail
by changing `enabled = false` to `enabled = true`. Review the ban policy and
add trusted management addresses to Fail2ban's `ignoreip` setting before
enabling automatic bans. Incorrect bans can lock you out of your own server,
which is a fairly efficient way to turn monitoring into an incident.

Start the bridge and reload Fail2ban:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now logwizz-fail2ban-bridge.service
sudo fail2ban-client reload
sudo fail2ban-client status logwizz
```

## Validate before enabling

First leave the jail disabled and check that the bridge emits normalized
events when a qualifying Logwizz event occurs:

```sh
sudo journalctl -u logwizz-fail2ban-bridge.service -f
sudo tail -F /var/log/logwizz/fail2ban.log
sudo fail2ban-regex /var/log/logwizz/fail2ban.log /etc/fail2ban/filter.d/logwizz.conf
python3 packaging/fail2ban/test_bridge.py
```

The normalized format is intentionally simple:

```text
logwizz rule=ssh_bruteforce src=203.0.113.66
```

After enabling the jail, verify it with `fail2ban-client status logwizz`.
Test on a disposable host or with a controlled test event before relying on
automatic blocking. The first version is a narrow integration, not a
replacement for reviewing your detection thresholds.

## Operational notes

- **Policy stays in Fail2ban.** The example uses `maxretry = 1` because
  Logwizz's threshold rules already aggregate activity. Tune `findtime`,
  `bantime` and the allowlist for your environment.
- **IPv4 and IPv6.** Both are accepted and written in canonical form
  (`2001:db8::1`). IPv4-mapped addresses (`::ffff:203.0.113.5`) are written
  as IPv4, so the ban hits the address the traffic actually comes from.
- **Duplicates.** Every eligible event produces one line. Threshold rules
  already report a source once per cooldown; a repeat for a source that is
  still banned does nothing in Fail2ban.
- **Use source-aware rules only.** `log_flood` and other events without a
  validated source address are not eligible.
- **Avoid self-lockout.** Configure `ignoreip` for loopback, management
  networks and trusted scanners before enabling the jail.
- **Keep the bridge log bounded.** The optional logrotate example uses
  `copytruncate` so the bridge can keep its open file descriptor. As with
  any copy-and-truncate rotation, a very small race window can lose a line.
- **No guarantee of zero false positives.** NAT, proxies, shared clients and
  noisy detection rules can make a source appear malicious. Validate the
  underlying logging and rule thresholds first.
- **Bridge downtime:** events emitted while the bridge is stopped are not
  replayed when it starts again; it follows from the current time to avoid
  replaying stale detections and causing stale bans.
- **Optional means optional.** To disable it, stop and disable
  `logwizz-fail2ban-bridge.service` and disable/remove the Fail2ban jail.
  Logwizz itself continues to run normally.

## Troubleshooting

- If the bridge cannot read the namespace, check that the service has access
  to the `systemd-journal` group and that
  `journalctl --namespace=logwizz -u logwizz.service -o cat` works on the host.
- If the event file stays empty, verify that Logwizz emits JSON events with a
  `fields.src` value for one of the eligible rules.
- If Fail2ban matches nothing, run `fail2ban-regex` against the exact file
  and filter shown above before enabling the jail.
