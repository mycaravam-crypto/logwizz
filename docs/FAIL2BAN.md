# Optional Fail2ban integration

This integration is an independent bridge from Logwizz's structured events to
[Fail2ban](https://www.fail2ban.org/). Logwizz remains a detector: Fail2ban
owns retry policy, allowlists, firewall actions, ban duration and unban state.
Nothing in the Rust core depends on Fail2ban, and no bans are enabled by
installing the files alone.

## What it does

The optional bridge follows the packaged service's dedicated systemd journal
namespace, parses JSON events, and writes a normalized line only for an
explicit allowlist of rules with a valid source IP. By default these are:

- `port_scan`
- `fast_scan`
- `slow_scan`
- `tcp_flag_scan`
- `ssh_bruteforce`
- `ssh_probe`
- `scanner_user_agent`

`BRIDGE_RULES` replaces the list, so any Logwizz rule with a `src` capture
can lead to a ban without a Fail2ban filter of its own: the one generic
`logwizz` filter matches every line the bridge writes.

A listed rule's `src` decides who is banned, so limit such rules to the log
they were written for with the rule's
[`files`](REFERENCE.md#limiting-a-rule-to-some-inputs) key: otherwise text
written into another monitored log (a request line, a user agent) can
match the rule with a chosen address.

Events without a `fields.src` address, malformed JSON, unlisted rules and
invalid IP addresses are ignored. So are addresses that are not globally
routable (loopback, private, link-local, shared/CGNAT, documentation,
multicast and other special-purpose ranges, also as IPv4-mapped IPv6), and
addresses in `BRIDGE_IGNORE`, whatever a log line claims. The bridge uses Python's standard library;
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
sudo install -D -m 0644 packaging/fail2ban/fail2ban-bridge.env.example \
  /etc/logwizz/fail2ban-bridge.env
```

## Settings

`/etc/logwizz/fail2ban-bridge.env` is optional; without it the bridge uses
the defaults.

| Variable | Default | Meaning |
|---|---|---|
| `BRIDGE_RULES` | the list above | Comma-separated rule IDs whose events may lead to a ban. |
| `BRIDGE_IGNORE` | empty | Comma-separated addresses and networks never written, e.g. `192.0.2.10,10.0.0.0/8`. |
| `BRIDGE_IGNORE_FILE` | unset | Absolute path of a file with more such addresses and networks, one per line; `#` starts a comment. Added to `BRIDGE_IGNORE`. See [One list of trusted networks](#one-list-of-trusted-networks). |
| `BRIDGE_DRY_RUN` | `0` | `1`: log each line it would write to the bridge's journal, and write nothing. The example file sets it. |
| `BRIDGE_JOURNAL_MODE` | `namespace` | Where events are read from: `namespace` (the `logwizz` journal namespace), `legacy` (the main journal) or `auto`. See [Hosts without journal namespaces](#hosts-without-journal-namespaces). |

An invalid value stops the bridge before it reads any event, with the
reason in `journalctl -u logwizz-fail2ban-bridge`. Its startup message
lists the active rules and mode. Leave out rules that can report your own
traffic (`ssh_login`, `login_after_scan`) and network rules (`subnet_scan`:
the event's `src` is only the last address of the network).

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

### One list of trusted networks

Trusted addresses are otherwise kept in three places: each rule's
`[rules.exclude]`, `BRIDGE_IGNORE` and Fail2ban's `ignoreip`. A network
missing from one of them is the usual way to ban yourself. Keep them in one
file, `/etc/logwizz/trusted-networks.list` (mode `0644`):

```text
# management VPN
198.51.100.0/24
# monitoring host
192.0.2.10
2001:db8:10::/48
```

and name it in `/etc/logwizz/fail2ban-bridge.env`:

```sh
BRIDGE_IGNORE_FILE=/etc/logwizz/trusted-networks.list
```

The bridge reads the file when it starts, so restart it after a change.
It runs as an unprivileged user and must be able to read the file; the
list is not a secret on the host. If the file is missing, unreadable,
larger than 1 MiB or has a line that is not an address or network, the
bridge stops with the reason and the line number instead of running
without the list.

Fail2ban has no setting that reads `ignoreip` from a file. Generate it from
the same list whenever the list changes:

```sh
list=$(sed 's/#.*//' /etc/logwizz/trusted-networks.list | xargs)
printf '[logwizz]\nignoreip = 127.0.0.1/8 ::1 %s\n' "$list" \
  | sudo tee /etc/fail2ban/jail.d/logwizz-ignore.local
sudo fail2ban-client reload
```

To also keep those sources out of Logwizz's reports, name the same file in
the rules' [`exclude_file`](REFERENCE.md#excluding-trusted-sources):

```toml
[rules.exclude_file]
src = "/etc/logwizz/trusted-networks.list"
```

and run `systemctl reload logwizz` after a change. This needs a Logwizz
binary that knows the key; older ones refuse the configuration.

### Hosts without journal namespaces

systemd older than 245 (Debian 10) has no journal namespaces. There,
`packaging/logwizz-legacy.service` sends Logwizz's events to the main
journal, and the default `namespace` mode reads nothing. Set

```sh
BRIDGE_JOURNAL_MODE=legacy
```

in `/etc/logwizz/fail2ban-bridge.env` and restart the bridge. It then
follows `logwizz.service` in the main journal; journald itself records which
unit wrote an entry, so other local users cannot inject events. `auto`
uses the namespace when the installed `journalctl` supports it and the main
journal otherwise. Use it only where Logwizz runs with the unit that matches
the host: on a newer system that still runs the legacy unit, `auto` picks
the namespace and reads nothing, so set `legacy` there. The startup message
names the journal in use.

The validation, rule list and output format are the same in every mode.
The bridge's unit tests cover the mode selection; a ban on a live Debian 10
host has not been verified.

## Validate before enabling

Start with `BRIDGE_DRY_RUN=1` (the example file's setting) and the jail
disabled, and check that the bridge would write normalized lines when a
qualifying Logwizz event occurs (`would write: ...` in its journal). Then
set `BRIDGE_DRY_RUN=0`, restart the bridge, and check the file:

```sh
sudo journalctl -u logwizz-fail2ban-bridge.service -f
sudo tail -F /var/log/logwizz/fail2ban.log
sudo fail2ban-regex /var/log/logwizz/fail2ban.log /etc/fail2ban/filter.d/logwizz.conf
python3 packaging/fail2ban/test_bridge.py
```

The normalized format is intentionally simple:

```text
2026-10-25 14:35:31 logwizz rule=ssh_bruteforce src=203.0.113.66
```

The timestamp is local time; Fail2ban ignores matches without one.

After enabling the jail, verify it with `fail2ban-client status logwizz`.
Test on a disposable host or with a controlled test event before relying on
automatic blocking. The first version is a narrow integration, not a
replacement for reviewing your detection thresholds.

### Repeat offenders

The `logwizz` jail bans for an hour, and a source that returns after each
ban gets the same hour again. There are two ways to make repeated bans
longer. Use one of them.

**Fail2ban 0.11 or later** (Debian 11 and later, Ubuntu 22.04 and later):
let the jail lengthen its own bans. Add to the `[logwizz]` section of
`/etc/fail2ban/jail.d/logwizz.local`:

```ini
bantime.increment = true
bantime.factor    = 1
bantime.maxtime   = 1w
```

Each further ban of the same address is then longer than the last (1 h,
2 h, 4 h, … up to a week), from Fail2ban's own ban history.

**Any version, including 0.10** (Debian 10): a second jail that watches
Fail2ban's log for bans by the `logwizz` jail. Install the two files, both
shipped disabled:

```sh
sudo install -D -m 0644 packaging/fail2ban/filter.d/logwizz-recidive.conf \
  /etc/fail2ban/filter.d/logwizz-recidive.conf
sudo install -D -m 0644 packaging/fail2ban/jail.d/logwizz-recidive.local \
  /etc/fail2ban/jail.d/logwizz-recidive.local
```

Review the file, set `enabled = true`, then:

```sh
sudo fail2ban-regex /var/log/fail2ban.log /etc/fail2ban/filter.d/logwizz-recidive.conf
sudo fail2ban-client reload
sudo fail2ban-client status logwizz-recidive
```

With its defaults, an address the `logwizz` jail banned three times within
a day is banned on all ports for a week. Bans by other jails, unbans and
bans restored after a Fail2ban restart do not count, and neither do this
jail's own bans.

A week-long ban of the wrong address is a week-long problem. Before
enabling either, put your management addresses in `ignoreip` (see
[One list of trusted networks](#one-list-of-trusted-networks)), and keep a
way in that does not depend on the banned address, such as a console.
`fail2ban-client set logwizz-recidive unbanip <address>` lifts a ban.

The filter is checked with `fail2ban-regex` from Fail2ban 1.0.2 against
sample log lines; a ban by this jail on a live host has not been verified.

### Ban notifications

The supplied `config/detection.toml` monitors `/var/log/fail2ban.log` and has a
`fail2ban_ban` rule. A Fail2ban `Ban <ip>` log entry produces a separate Logwizz
notification (after its aggregation window), whereas the original detection
notification alone says nothing about a ban. This also works for other
Fail2ban jails; no source-rule attribution is attempted. A Fail2ban `Ban` log
is a report from Fail2ban, **not proof that a firewall rule took effect**.
If there is no follow-up notification, do not infer the IP was not blocked:
check the jail and logs. Disable the Fail2ban file source on systems without
that log.

## Optional actionban reporting

The `logwizz-report.py` Fail2ban action emits an individual message **only after observing nftables enforcement state** for the just-banned address. It is opt-in: no existing jail changes unless explicitly configured. Install the action file:

```sh
sudo install -D -m 0644 packaging/fail2ban/action.d/logwizz-report.py /etc/fail2ban/action.d/logwizz-report.py
sudoedit /etc/fail2ban/jail.d/logwizz.local
```

The verification currently supports **the stock Fail2ban `nftables-multiport` backend only**, with the default `inet f2b-table f2b-chain` input chain and per-jail `addr-set-<jail>` (IPv4) / `addr6-set-<jail>` (IPv6). Configure the real nftables firewall action **first** and the reporter second:

```ini
[logwizz]
banaction = nftables-multiport
action = %(action_)s
         logwizz-report.py
```

Do **not** replace the firewall action with the reporter. For a different jail using the same nftables backend, add `logwizz-report.py` after its ban action. With iptables, custom nftables table/chain/set names, missing nft binaries or unsupported chains, the verifier **fails closed**: no verified notification is sent and Fail2ban logs a warning. Validate and reload:

```sh
sudo fail2ban-client -t
sudo fail2ban-client reload
sudo fail2ban-client status logwizz
sudo journalctl --namespace=logwizz SYSLOG_IDENTIFIER=logwizz-ban _UID=0 -n 20
```

The Python action performs **read-only**, bounded-time `nft -j list set` and `nft -j list chain` queries via fixed argument vectors (no shell or interpolation). It requires (1) the exact IP in the jail's nftables address set and (2) an active input-hook filter chain containing a rule matching that specific set and a drop/reject verdict. Only then does it send `LOGWIZZ_BAN_V2` via the namespaced journald socket (systemd >= 245); `logwizz-notify` emits `status: firewall_rule_verified` with evidence `nftables-set-and-input-drop-rule`. The daemon remains unprivileged; the verification runs in Fail2ban's existing root process.

**Guarantee boundary:** This is evidence of an installed nftables address-set entry **and active input-chain block rule at report time**. It does not inspect actual packet traversal, upstream accept rules or concurrent changes. It cannot certify end-to-end connectivity loss. Crucially, Fail2ban may execute the reporter after a *failed* firewall action: without both nftables checks succeeding, **no verified message is sent**. Missing notifications are inconclusive (unsupported backend, disabled/ignored/already-banned IP, backend failure, delivery failure). The existing `fail2ban_ban` log detection may still generate a separate **unverified** message; disable its source if only verified events are wanted. Historical `LOGWIZZ_BAN_V1` records retain the honest `actionban_reported` status.

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
- **Avoid self-lockout.** The bridge never writes non-global addresses, and
  Fail2ban's `ignoreself` (on by default) skips the host's own addresses.
  Still put management networks and trusted scanners in `BRIDGE_IGNORE`
  or Fail2ban's `ignoreip` before enabling the jail.
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
