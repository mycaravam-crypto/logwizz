# Active response via Fail2ban — design draft (#74)

**Decision: active response goes through the existing Fail2ban bridge.**
The bridge stays unprivileged and outside the daemon. It writes validated
lines for a configurable rule list (`BRIDGE_RULES`), refuses non-global
addresses (Python's `ipaddress.is_global`, which follows the IANA
special-purpose registries) and `BRIDGE_IGNORE` networks, has a dry-run mode
and fails closed on invalid settings. One generic Fail2ban filter matches
every bridge line, so no rule needs a filter of its own. Fail2ban, which
already runs privileged, does the banning, keeps ban state and unbans.
There is no privileged broker or socket protocol. See [FAIL2BAN.md](FAIL2BAN.md).

The broker design below is kept for reference. The first milestone's Rust
address guard (`src/active_response.rs`) was removed: the bridge does that
check itself.

## Goal

A logwizz rule may elect to request an IP ban based on a verified source
address after a bounded number of matches, even when Fail2ban has no
attack-specific filter. Fail2ban still needs an explicitly configured
**dedicated `logwizz` jail** for ban lifetime and unban.

## Trust boundaries

1. Log lines are attacker-controlled. No arbitrary regex substring may
   authorize a ban. Capture from a per-source, reviewed parser only, with
   explicit source-file scoping (so `/var/log/auth.log` sudo commands cannot
   impersonate nginx requests).
2. logwizz remains unprivileged. The detector emits a bounded structured
   request to an isolated broker. No `sh -c`, arbitrary command templates,
   user-selectable jail, untrusted executable path, or shell interpolation.
3. The privileged broker authenticates the sender, validates the exact
   requested operation, re-parses canonical IPs, consults local network
   inventory and administrator CIDR exclusions, enforces rate limits and
   deduplication, and invokes a fixed Fail2ban command with a fixed jail name.
4. Deny by default: disabled in configuration, threshold required, dry-run
   first. No automatic ban on process restart or state replay. Fail safely
   when Fail2ban is unavailable.
5. Log every decision without leaking raw log data. Ban/unban audit records
   must not feed another enforcement rule.

## First code milestone

(Removed; superseded by the bridge's address check.) `src/active_response.rs`
provided a **pure** `candidate_ip` function
with no I/O, side effects, or command execution. It rejects malformed
addresses, common special-use ranges, and explicit exact-address exclusions.
Unit tests cover invalid inputs, private/reserved IPv4/IPv6, allowlists, and
IPv4-mapped IPv6. **Do not use it alone as a firewall authorization.**

## Planned integration

- Add explicit per-file rule scoping and typed source-IP capture, independent
  of the existing general regex matches.
- Add an `[active_response]` section that defaults to disabled, requires
  minimum count / time window, allows CIDR allowlists, and supports dry-run.
- Add durable rate/cooldown controls and tests against duplicate or replayed
  events; guard against forged source IPs in user agents, URLs and SSH commands.
- Add a separate broker with narrowly limited filesystem/socket permissions,
  fixed Fail2ban jail, no shell, and least privilege.
- Provide a dedicated jail install example, Debian 10 compatible unit,
  security review, and integration tests against a disposable network
  namespace (never the operator's current SSH connection).

## Acceptance tests

- Default config preserves today's detection / Telegram behavior.
- No active response can happen without an explicit administrator opt-in.
- One malformed, private, local, allowlisted, spoofed or untrusted IP cannot
  result in a ban (including IPv4-mapped IPv6 and CIDR boundaries).
- Real signals require threshold, deduplicate correctly, and never ban
  on event replay or notifier restart.
- Mock broker tests show fail-closed behavior on crash, timeout and rejection.
- Isolated integration tests verify ban, TTL/unban and audit trail.

**Do not merge this foundation as an active banning feature.**
