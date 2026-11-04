#!/usr/bin/env python3
"""Experimental per-network-namespace Docker egress guard.

Deliberately separate from the production Rust daemon and host firewall profile.
Requires NET_ADMIN *only in its own container network namespace*.
"""
from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

TABLE = "logwizz_guard"
COUNTER = "denied"
READY = pathlib.Path("/run/logwizz-guard-ready")
STOP = False


def parse_allow(value: str) -> list[tuple[str, int]]:
    """Require explicit IPv4:TCP-port pairs. No default Internet access."""
    if not value.strip():
        raise ValueError("LOGWIZZ_EGRESS_ALLOW is required (IPv4:port[,IPv4:port...])")
    entries: set[tuple[str, int]] = set()
    for part in value.split(","):
        host, separator, port_text = part.strip().rpartition(":")
        if not separator or not host or not port_text.isdigit():
            raise ValueError(f"invalid IPv4:port entry: {part!r}")
        addr = ipaddress.ip_address(host)
        if not isinstance(addr, ipaddress.IPv4Address) or addr.is_multicast or addr.is_unspecified:
            raise ValueError(f"not a valid unicast IPv4 destination: {host}")
        port = int(port_text)
        if port < 1 or port > 65535:
            raise ValueError(f"TCP destination port out of range: {port}")
        entries.add((str(addr), port))
    return sorted(entries)


def ruleset(allowed: list[tuple[str, int]]) -> str:
    lines = [
        f"table inet {TABLE} {{",
        f"  counter {COUNTER} {{ packets 0 bytes 0 }}",
        "  chain output {",
        "    type filter hook output priority 0; policy accept;",
        '    oifname "lo" accept',
        "    ct state established,related accept",
    ]
    for addr, port in allowed:
        lines.append(f"    ip daddr {addr} tcp dport {port} accept")
    lines += [
        f"    counter name {COUNTER} drop",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def nft(*args: str, input_data: str | None = None) -> str:
    result = subprocess.run(
        ["nft", *args], input=input_data, capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise RuntimeError(f"nft {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def table_exists() -> bool:
    data = json.loads(nft("-j", "list", "tables"))
    return any(
        item.get("table", {}).get("name") == TABLE
        and item["table"].get("family") == "inet"
        for item in data.get("nftables", [])
    )


def counter_change(last: int, current: int) -> tuple[int, bool]:
    """Return new denied packets and whether an unexpected reset occurred."""
    if current < last:
        return 0, True
    return current - last, False


def denied_packets() -> int:
    data = json.loads(nft("-j", "list", "counter", "inet", TABLE, COUNTER))
    for entry in data.get("nftables", []):
        counter = entry.get("counter", {})
        if counter.get("name") == COUNTER and counter.get("table") == TABLE:
            return int(counter["packets"])
    raise RuntimeError("nftables deny counter missing")


def on_stop(_signal: int, _frame: object) -> None:
    global STOP
    STOP = True


def healthy() -> int:
    try:
        if not READY.is_file() or time.time() - READY.stat().st_mtime > 10:
            return 1
        denied_packets()
        return 0
    except (OSError, RuntimeError, ValueError, KeyError):
        return 1


def run() -> None:
    allowed = parse_allow(os.environ.get("LOGWIZZ_EGRESS_ALLOW", ""))
    path = pathlib.Path(os.environ.get("LOGWIZZ_EVENTS_PATH", "/events/egress.log"))
    if path.parent != pathlib.Path("/events") or path.name != "egress.log":
        raise ValueError("the events destination must be /events/egress.log")
    # A dedicated named Docker volume is trusted. Never share it with the app.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    policy = ruleset(allowed)
    # Refuse to overwrite any existing policy. No flushing of host or Docker rules.
    if table_exists():
        os.close(fd)
        raise RuntimeError(f"table {TABLE} already exists; refusing to replace it")
    nft("-c", "-f", "-", input_data=policy)
    nft("-f", "-", input_data=policy)
    signal.signal(signal.SIGTERM, on_stop)
    signal.signal(signal.SIGINT, on_stop)
    print("logwizz-guard: policy installed; monitoring aggregate denied packet counter", flush=True)
    last = denied_packets()
    with os.fdopen(fd, "a", encoding="ascii", buffering=1) as events:
        while not STOP:
            current = denied_packets()  # Failure ends the health loop; never drop enforcement.
            delta, reset = counter_change(last, current)
            if reset:
                # Reset is suspicious; alert instead of silently suppressing it or crashing.
                events.write(f"logwizz-egress-counter-reset: previous={last} current={current}\n")
            elif delta:
                events.write(f"logwizz-egress-deny: packets={delta} total_packets={current}\n")
            last = current
            READY.touch()
            time.sleep(1)
    # Intentionally do NOT delete nftables rules while a protected app may still run.


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--health":
        return healthy()
    if len(sys.argv) == 2 and sys.argv[1] == "--validate":
        try:
            print(ruleset(parse_allow(os.environ.get("LOGWIZZ_EGRESS_ALLOW", ""))), end="")
            return 0
        except (ValueError, TypeError) as exc:
            print(f"logwizz-guard: {exc}", file=sys.stderr)
            return 2
    if len(sys.argv) != 1:
        print("usage: guard.py [--validate|--health]", file=sys.stderr)
        return 2
    try:
        run()
        return 0
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print(f"logwizz-guard: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
