"""Tests for the optional Python Fail2ban action; no Fail2ban daemon required."""
import importlib.util
import pathlib
import socket
import sys
import tempfile
import types
import unittest
from unittest import mock


class FakeBase:
    def __init__(self, jail, name):
        self._jail = jail
        self._name = name


def load_action():
    root = pathlib.Path(__file__).parent
    module_file = root / "action.d" / "logwizz-report.py"
    package = types.ModuleType("fail2ban")
    server = types.ModuleType("fail2ban.server")
    action = types.ModuleType("fail2ban.server.action")
    action.ActionBase = FakeBase
    with mock.patch.dict(sys.modules, {
        "fail2ban": package,
        "fail2ban.server": server,
        "fail2ban.server.action": action,
    }):
        spec = importlib.util.spec_from_file_location("logwizz_report", module_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.report = load_action()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.socket_path = str(pathlib.Path(self.temp.name) / "journal.socket")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(self.listener.close)
        self.listener.bind(self.socket_path)
        self.listener.settimeout(0.1)
        self.report.JOURNAL_SOCKET = self.socket_path
        self.action = self.report.Action(types.SimpleNamespace(name="logwizz"), "logwizz-report")

    def received(self):
        return self.listener.recv(4096).decode("ascii")

    def test_report_is_native_journal_without_shell(self):
        self.assertTrue(self.action.norestored)
        self.action.ban({"ip": "198.51.100.24", "bantime": 3600})
        self.assertEqual(
            self.received(),
            "PRIORITY=4\nSYSLOG_IDENTIFIER=logwizz-ban\n"
            "MESSAGE=LOGWIZZ_BAN_V1 jail=logwizz ip=198.51.100.24 bantime=3600\n",
        )

    def test_ipv6_and_permanent_ban(self):
        self.action.ban({"ip": "2001:0db8::1", "bantime": -1})
        self.assertIn("ip=2001:db8::1 bantime=-1\n", self.received())

    def test_rejects_injected_metadata_without_sending(self):
        for data in [
            {"ip": '198.51.100.24"$(touch /tmp/unsafe)', "bantime": 3600},
            {"ip": "198.51.100.24", "bantime": "3600; touch /tmp/unsafe"},
            {"ip": "198.51.100.24", "bantime": -2},
        ]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.action.ban(data)
        with self.assertRaises(socket.timeout):
            self.received()
        with self.assertRaises(ValueError):
            self.report.Action(types.SimpleNamespace(name='logwizz";$(id)'), "bad")

    def test_reban_does_not_send_a_new_report(self):
        self.action.reban({"ip": "198.51.100.24", "bantime": 3600})
        with self.assertRaises(socket.timeout):
            self.received()


if __name__ == "__main__":
    unittest.main()
