"""Safe, opt-in Fail2ban actionban reporting to Logwizz's journal namespace.

Native Python action: no shell command, tag interpolation or external process.
A callback reports that Fail2ban invoked this action, not that the firewall
actually enforced the ban. Place it after the firewall action in the jail.
"""
import ipaddress
import re
import socket

from fail2ban.server.action import ActionBase

JOURNAL_SOCKET = "/run/systemd/journal.logwizz/socket"
_JAIL_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")


def _record(jail, address, bantime):
    """Validate all dynamic data before writing one single-line report."""
    jail = str(jail)
    if not _JAIL_RE.fullmatch(jail):
        raise ValueError("invalid Fail2ban jail name")
    address = ipaddress.ip_address(str(address))
    # Fail2ban supplies an integer duration, with -1 for permanent bans.
    duration = int(bantime)
    if duration < -1:
        raise ValueError("invalid Fail2ban ban duration")
    return f"LOGWIZZ_BAN_V1 jail={jail} ip={address} bantime={duration}"


class Action(ActionBase):
    """Report one fresh actionban, without invoking a shell or ban command."""

    norestored = True

    def __init__(self, jail, name):
        super().__init__(jail, name)
        if not _JAIL_RE.fullmatch(str(jail.name)):
            raise ValueError("invalid Fail2ban jail name")

    def ban(self, aInfo):
        record = _record(self._jail.name, aInfo["ip"], aInfo["bantime"])
        # journald supplies the trusted _UID from socket peer credentials.
        payload = (
            "PRIORITY=4\n"
            "SYSLOG_IDENTIFIER=logwizz-ban\n"
            f"MESSAGE={record}\n"
        ).encode("ascii")
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, JOURNAL_SOCKET)

    def reban(self, aInfo):
        # Re-bans/restores are not a new actionban report.
        pass
