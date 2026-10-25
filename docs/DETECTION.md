# Detecting scans and attacks

logwizz only sees what reaches a log file. This guide sets up the logging that
makes scans visible, and the rules in
[`config/detection.toml`](../config/detection.toml) that turn it into alerts:

| Rule | Detects | Needs |
|---|---|---|
| `port_scan` | One source probing 20+ closed ports within a minute (nmap `-sS`/`-sT`/`-sU`, masscan) | the firewall rules below |
| `fast_scan` | 100+ closed ports within 2 seconds (masscan-like rates) | the firewall rules below |
| `slow_scan` | 50+ closed ports within an hour (background scanners below `port_scan`'s rate) | the firewall rules below |
| `tcp_flag_scan` | TCP NULL, FIN and Xmas scans (nmap `-sN`, `-sF`, `-sX`) | the firewall rules below |
| `ssh_bruteforce` | 10+ failed or invalid-user SSH logins from one source within a minute, including key-only hosts that log no `Failed` line | `auth.log` |
| `ssh_probe` | A connection to sshd that never sends an SSH banner (nmap `-sV`, banner grabbers) | `auth.log` |
| `sudo_auth_failure` | A failed sudo password or a user not in sudoers | `auth.log` |
| `account_change` | A user, group or password created, changed or deleted | `auth.log` |
| `scanner_user_agent` | Requests with the user agent of nmap NSE, masscan, zgrab, sqlmap, nikto or nuclei | a web access log (combined format or Caddy JSON) |
| `ssh_login` | Every successful SSH login, with its source | `auth.log` |
| `fail2ban_ban` | fail2ban banning a source | `fail2ban.log` |
| `log_flood` | More than 5000 lines in a minute in any watched file | – |

Each detector reports a source once and then stays silent for that source
for its cooldown (10 minutes to an hour), so one scan is one notification.
Send them to your phone with [logwizz-notify](../README.md#notifications).

## 1. Make the firewall log scans

A SYN scan against a port with no listener produces no log line at all on a
default Linux system: the kernel answers with a reset and moves on. The
following nftables table logs those packets. It is a separate table with
policy `accept`, so it works next to an existing firewall (ufw, firewalld,
your own nftables rules) and changes nothing about what is allowed.

Save it as `/etc/nftables.d/logwizz.nft` (or append it to
`/etc/nftables.conf`), list your open ports in `open_tcp`/`open_udp`, and load
it with `nft -f /etc/nftables.d/logwizz.nft`:

```nft
table inet logwizz {
	# EXAMPLE VALUES, replace them: the ports that really listen on this
	# host (`ss -tulnp`). Connections to them are normal traffic and are not
	# logged; a listening port missing here makes its clients look like scans.
	set open_tcp { type inet_service; elements = { 22, 80, 443 } }
	set open_udp { type inet_service; elements = { 53, 123 } }

	chain input {
		type filter hook input priority filter - 1; policy accept;

		# NULL, FIN and Xmas scans: flag combinations no normal stack sends.
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 \
			limit rate 20/second log prefix "logwizz-badflags: " level warn
		tcp flags & (fin|syn|rst|psh|ack|urg) == fin \
			limit rate 20/second log prefix "logwizz-badflags: " level warn
		tcp flags & (fin|psh|urg) == fin|psh|urg \
			limit rate 20/second log prefix "logwizz-badflags: " level warn

		# New connections to closed ports.
		ct state new tcp flags & (syn|ack) == syn tcp dport != @open_tcp \
			limit rate 200/second burst 400 packets log prefix "logwizz-drop: " level info
		ct state new meta l4proto udp udp dport != @open_udp \
			limit rate 200/second burst 400 packets log prefix "logwizz-drop: " level info
	}
}
```

To load it at boot on Debian and Ubuntu, add `include "/etc/nftables.d/*.nft"`
to `/etc/nftables.conf` and `systemctl enable nftables`. With ufw, do not
enable `nftables.service`: the stock `/etc/nftables.conf` starts with
`flush ruleset` and removes ufw's rules. Load the table from a oneshot unit
instead, with `ExecStart=/usr/sbin/nft -f /etc/nftables.d/logwizz.nft` and
`WantedBy=multi-user.target`.

The `limit` clauses matter: masscan sends millions of packets per second,
and without a limit every one of them would be a line in `kern.log`. With
200 lines per second, a scan still crosses the `port_scan` threshold within
a fraction of a second, and the log stays small.

The kernel writes lines like this, which `port_scan` reads `SRC` and `DPT`
from:

```
Oct 25 10:00:00 web1 kernel: logwizz-drop: IN=eth0 OUT= MAC=... SRC=203.0.113.66 DST=198.51.100.1 LEN=44 TOS=0x00 PREC=0x00 TTL=41 ID=54321 PROTO=TCP SPT=61000 DPT=8080 WINDOW=1024 RES=0x00 SYN URGP=0
```

### Hosts with iptables

```sh
iptables -I INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 20/s -j LOG --log-prefix "logwizz-badflags: "
iptables -I INPUT -p tcp --tcp-flags ALL FIN -m limit --limit 20/s -j LOG --log-prefix "logwizz-badflags: "
iptables -I INPUT -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -m limit --limit 20/s -j LOG --log-prefix "logwizz-badflags: "
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -m multiport ! --dports 22,80,443 \
  -m limit --limit 200/s --limit-burst 400 -j LOG --log-prefix "logwizz-drop: "
```

Replace `22,80,443` with the ports that listen on this host (`ss -tulnp`),
as for `open_tcp` above. The last rule must come after your `ACCEPT` rules
for open ports, or use the `! --dports` list as shown. Repeat with `ip6tables` for IPv6.

### Where the lines end up

| System | File |
|---|---|
| Debian, Ubuntu (with rsyslog) | `/var/log/kern.log` (and `/var/log/syslog`) |
| RHEL, Rocky, Alma, CentOS | `/var/log/messages` |
| Debian 12+, Fedora, Arch without rsyslog | only the journal: configure the `[journal]` source in logwizz; see the README section on journal input |

Watch kernel messages in **one** file: on Debian and Ubuntu every firewall
line is in both `kern.log` and `syslog`, and watching both counts it twice.

## 2. Install the rules

```sh
install -m 0640 -g adm config/detection.toml /etc/logwizz/logwizz.toml
logwizz --check-config
systemctl restart logwizz
```

Adjust the `[[files]]` paths to your distribution (comments in the file),
and enable the web access log if you run a web server. On systems without
rsyslog, use the `[journal]` source instead of enabling file paths for the
same kernel or SSH messages. For example, add `[journal]` with
`matches = ["_TRANSPORT=kernel", "+", "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session"]`
and follow the README's journal-access drop-in instructions. To keep your
existing rules, copy the `[[rules]]` blocks you want into your configuration instead.

## 3. Test it

From another machine (scanning your own host from itself also works, the
packets then arrive on `lo`):

```sh
nmap -sS -p 1-1000 <host>      # port_scan
nmap -sN -p 1-100 <host>       # tcp_flag_scan
nmap -sV -p 22 <host>          # ssh_probe (often; depends on the sshd version)
```

and watch the events:

```sh
journalctl --namespace=logwizz -u logwizz -o cat -f
```

```json
{"v":1,"ts":"...","host":"web1","pid":812,"file":"/var/log/kern.log","rule":"port_scan","description":"One source probed many closed ports","severity":"critical","match_type":"regex","line":"... logwizz-drop: ... SRC=203.0.113.66 ... DPT=443 ...","truncated":false,"fields":{"src":"203.0.113.66","dpt":"443"},"threshold":{"group":"203.0.113.66","count":20,"window_secs":60}}
```

The host check (`tests/host/run-vm.sh`, and the **host** CI workflow) does
exactly this in a VM, with these rules.

## Tuning

- **Thresholds:** `count` and `window_secs` trade sensitivity for noise. A
  host that legitimately gets connections to many closed ports (for
  example a NAT gateway, or clients retrying a moved service) needs a higher
  `count` for `port_scan`, or those sources excluded in the firewall rules.
- **`log_flood`:** set `count` to a few times your normal peak lines per
  minute. Put it after `ignore` rules for known noise (see the README,
  *Reporting unknown lines*) to count only unknown lines.
- **Known scanners:** your own vulnerability scanner or monitoring will
  trigger these rules. For the firewall detectors, exclude its address in
  the nftables rules (`ip saddr != 192.0.2.10`), which also keeps it out of
  the kernel log. For the SSH and web rules, add it to the rule's
  `[rules.exclude]` table (`src = ["192.0.2.10"]`, networks such as
  `10.0.0.0/8` work too); see the
  [reference](REFERENCE.md#excluding-trusted-sources).

## What this cannot see

Say it plainly, so nobody relies on more than this gives:

- **Scans that only touch open ports** and complete normal connections look
  like normal traffic. `ssh_probe` and `scanner_user_agent` catch some of
  them, by what the scanner does once connected.
- **Slow scans** below the threshold (for example `nmap -T0`, one port every
  five minutes) never reach `count` within the window. Raise `window_secs`
  (up to a day) for a slow-scan rule if this matters, at the cost of more
  state.
- **Distributed scans** from many sources, each touching a few ports, stay
  below every per-source threshold.
- **Spoofed sources** can be used to fill a detector's group table. logwizz
  stays within its limits and counts `threshold_evictions`, but a real
  scanner's partial count can be evicted during such a flood.
- **Above the firewall log rate** (200 lines per second), further packets are
  not logged. One scan is still detected; many simultaneous scans may not all
  be.
- logwizz detects and reports. It does not block anything: use fail2ban,
  CrowdSec or firewall rules for that.
