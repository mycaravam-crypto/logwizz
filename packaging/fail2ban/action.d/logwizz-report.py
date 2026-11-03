"""Verified nftables ban reporting for Logwizz (optional Fail2ban Python action).

This action runs after a separate nftables firewall action. Fail2ban itself
continues through failures, so the action independently verifies the IP's
membership in the expected nftables set AND an active input-hook drop/reject
rule referencing that exact set before emitting a verified report.

Only the stock nftables-multiport action with inet/f2b-table/f2b-chain and
default per-jail set names is supported. Unknown backends fail closed.
No shell, dynamic command strings, or firewall mutations are used here.
"""
import ipaddress
import json
import re
import socket
import subprocess

from fail2ban.server.action import ActionBase

JOURNAL_SOCKET = "/run/systemd/journal.logwizz/socket"
JOURNAL_IDENTIFIER = "logwizz-ban"
SYSLOG_PRIORITY_WARNING = 4
NFT_BINARY = "/usr/sbin/nft"
NFT_FAMILY = "inet"
NFT_TABLE = "f2b-table"
NFT_CHAIN = "f2b-chain"
VERIFIED_PREFIX = "LOGWIZZ_BAN_V2"
_JAIL_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
_NFT_TIMEOUT_SECS = 3
_NFT_OUTPUT_MAX = 65536


def _validated(jail, address, bantime):
    jail = str(jail)
    if not _JAIL_RE.fullmatch(jail):
        raise ValueError("invalid Fail2ban jail name")
    address = ipaddress.ip_address(str(address))
    duration = int(bantime)
    if duration < -1:
        raise ValueError("invalid Fail2ban ban duration")
    return jail, address, duration


def _nft_json(*args):
    """Read-only nftables query: each argument is fixed or validated."""
    result = subprocess.run(
        [NFT_BINARY, "-j", *args],
        check=True,
        timeout=_NFT_TIMEOUT_SECS,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if len(result.stdout) > _NFT_OUTPUT_MAX:
        raise ValueError("nftables output exceeds limit")
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        raise ValueError("unexpected nftables JSON response")
    return data["nftables"]


def _is_verified_nftables(jail, address):
    """Require exact set membership and active input-hook drop/reject rule."""
    family = "ip" if address.version == 4 else "ip6"
    set_name = ("addr-set-" if address.version == 4 else "addr6-set-") + jail

    # "get element" fails with nonzero status when the key is not in the set.
    elements = _nft_json(
        "get", "element", NFT_FAMILY, NFT_TABLE, set_name,
        "{", str(address), "}",
    )
    if not any(isinstance(obj, dict) and "element" in obj for obj in elements):
        return False

    nft = _nft_json("list", "chain", NFT_FAMILY, NFT_TABLE, NFT_CHAIN)
    base_chains = [
        obj["chain"] for obj in nft
        if isinstance(obj, dict) and isinstance(obj.get("chain"), dict)
    ]
    if not any(
        chain.get("family") == NFT_FAMILY
        and chain.get("table") == NFT_TABLE
        and chain.get("name") == NFT_CHAIN
        and chain.get("type") == "filter"
        and chain.get("hook") == "input"
        for chain in base_chains
    ):
        return False

    for obj in nft:
        if not isinstance(obj, dict) or not isinstance(obj.get("rule"), dict):
            continue
        rule = obj["rule"]
        if (
            rule.get("family") != NFT_FAMILY
            or rule.get("table") != NFT_TABLE
            or rule.get("chain") != NFT_CHAIN
        ):
            continue
        expressions = rule.get("expr")
        if not isinstance(expressions, list):
            continue
        contains_ip_set = any(
            isinstance(expr, dict)
            and isinstance(expr.get("match"), dict)
            and expr["match"].get("op") in ("==", "in")
            and expr["match"].get("right") == "@" + set_name
            and isinstance(expr["match"].get("left"), dict)
            and expr["match"]["left"].get("payload") == {
                "protocol": family, "field": "saddr"
            }
            for expr in expressions
        )
        blocks = any(
            isinstance(expr, dict) and ("drop" in expr or "reject" in expr)
            for expr in expressions
        )
        if contains_ip_set and blocks:
            return True
    return False


class Action(ActionBase):
    """Report only independently observed nftables rule+set membership."""

    norestored = True

    def __init__(self, jail, name):
        super().__init__(jail, name)
        if not _JAIL_RE.fullmatch(str(jail.name)):
            raise ValueError("invalid Fail2ban jail name")

    def ban(self, aInfo):
        jail, address, duration = _validated(
            self._jail.name, aInfo["ip"], aInfo["bantime"]
        )
        try:
            verified = _is_verified_nftables(jail, address)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            self._logSys.warning(
                "logwizz ban verification unavailable for %s (%s): %s",
                jail, address, type(exc).__name__
            )
            return
        if not verified:
            self._logSys.warning(
                "logwizz ban NOT verified for jail %s and IP %s; no report sent",
                jail, address,
            )
            return

        record = (
            f"{VERIFIED_PREFIX} jail={jail} ip={address} bantime={duration}"
        )
        # journald supplies _UID from trusted socket peer credentials.
        payload = (
            f"PRIORITY={SYSLOG_PRIORITY_WARNING}\n"
            f"SYSLOG_IDENTIFIER={JOURNAL_IDENTIFIER}\n"
            f"MESSAGE={record}\n"
        ).encode("ascii")
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, JOURNAL_SOCKET)

    def reban(self, aInfo):
        # Restored/repeated bans do not generate a fresh verified event.
        pass
