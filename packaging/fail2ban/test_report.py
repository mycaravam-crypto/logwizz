"""Unit-level contract tests for verified Fail2ban nftables action.

No live firewall or Fail2ban daemon is required here; live host E2E is #91.
"""
import importlib.util
import logging
import pathlib
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


class FakeBase:
    def __init__(self, jail, name):
        self._jail = jail
        self._name = name
        self._logSys = logging.getLogger("test.fail2ban")


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


def chain_entries(jail="logwizz", verdict="drop", address_family="ip", hook="input", membership_op="in"):
    set_name = ("addr-set-" if address_family == "ip" else "addr6-set-") + jail
    return [
        {"metainfo": {"json_schema_version": 1}},
        {"chain": {
            "family": "inet", "table": "f2b-table", "name": "f2b-chain",
            "type": "filter", "hook": hook, "prio": -1, "policy": "accept",
        }},
        {"rule": {
            "family": "inet", "table": "f2b-table", "chain": "f2b-chain",
            "expr": [
                {"match": {
                    "op": membership_op,
                    "left": {"payload": {"protocol": address_family, "field": "saddr"}},
                    "right": "@" + set_name,
                }},
                {verdict: None},
            ],
        }},
    ]


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.report = load_action()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.socket_path = str(pathlib.Path(self.temp.name) / "journal.socket")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(self.listener.close)
        self.listener.bind(self.socket_path)
        self.listener.settimeout(0.05)
        self.report.JOURNAL_SOCKET = self.socket_path
        self.action = self.report.Action(types.SimpleNamespace(name="logwizz"), "logwizz-report")

    def received(self):
        return self.listener.recv(4096).decode("ascii")

    def nft(self, *, member=True, verdict="drop", hook="input", family="ip", membership_op="in"):
        def query(*args):
            if args[:2] == ("list", "set"):
                address = "198.51.100.24" if family == "ip" else "2001:db8::1"
                set_name = ("addr-set-" if family == "ip" else "addr6-set-") + "logwizz"
                return [{"set": {
                    "family": "inet", "table": "f2b-table",
                    "name": set_name,
                    "type": "ipv4_addr" if family == "ip" else "ipv6_addr",
                    "elem": [address] if member else [],
                }}]
            return chain_entries(
                verdict=verdict, hook=hook, address_family=family,
                membership_op=membership_op,
            )
        return mock.patch.object(self.report, "_nft_json", side_effect=query)

    def test_verified_ipv4_journal_record(self):
        self.assertTrue(self.action.norestored)
        with self.nft() as query:
            self.action.ban({"ip": "198.51.100.24", "bantime": 3600})
        self.assertEqual(query.call_count, 2)
        self.assertEqual(
            self.received(),
            "PRIORITY=4\nSYSLOG_IDENTIFIER=logwizz-ban\n"
            "MESSAGE=LOGWIZZ_BAN_V2 jail=logwizz ip=198.51.100.24 bantime=3600\n",
        )

    def test_legacy_equality_operator_remains_supported(self):
        with self.nft(membership_op="=="):
            self.action.ban({"ip": "198.51.100.24", "bantime": 60})
        self.assertIn("LOGWIZZ_BAN_V2", self.received())

    def test_verified_ipv6_permanent(self):
        with self.nft(family="ip6"):
            self.action.ban({"ip": "2001:0db8::1", "bantime": -1})
        self.assertIn("ip=2001:db8::1 bantime=-1\n", self.received())

    def test_failed_firewall_or_missing_backend_never_reports(self):
        for mode in ("missing_ip", "no_input_hook", "accept_not_drop", "no_backend"):
            with self.subTest(mode=mode):
                if mode == "missing_ip":
                    verify = self.nft(member=False)
                elif mode == "no_input_hook":
                    verify = self.nft(hook="forward")
                elif mode == "accept_not_drop":
                    verify = self.nft(verdict="accept")
                else:
                    verify = mock.patch.object(
                        self.report, "_nft_json", side_effect=FileNotFoundError
                    )
                with verify:
                    self.action.ban({"ip": "198.51.100.24", "bantime": 60})
                with self.assertRaises(socket.timeout):
                    self.received()

    def test_wrong_set_type_and_prefix_do_not_verify(self):
        def wrong_set(*args):
            if args[:2] == ("list", "set"):
                return [{"set": {
                    "family": "inet", "table": "f2b-table",
                    "name": "addr-set-logwizz", "type": "ipv4_addr",
                    "elem": [{"prefix": {"addr": "198.51.100.0", "len": 24}}],
                }}]
            return chain_entries()
        with mock.patch.object(self.report, "_nft_json", side_effect=wrong_set):
            self.action.ban({"ip": "198.51.100.24", "bantime": 60})
        with self.assertRaises(socket.timeout):
            self.received()

    def test_malformed_or_injected_values_rejected(self):
        for data in [
            {"ip": '198.51.100.24"$(touch /tmp/unsafe)', "bantime": 3600},
            {"ip": "198.51.100.24", "bantime": "1;id"},
            {"ip": "198.51.100.24", "bantime": -2},
        ]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.action.ban(data)
        with self.assertRaises(ValueError):
            self.report.Action(types.SimpleNamespace(name="bad;jail"), "bad")
        with self.assertRaises(socket.timeout):
            self.received()

    def test_nft_query_is_readonly_argv_with_timeout(self):
        response = mock.Mock(stdout='{"nftables":[{"set":{"elem":["198.51.100.24"]}}]}')
        with mock.patch.object(self.report.subprocess, "run", return_value=response) as run:
            self.report._nft_json(
                "list", "set", "inet", "f2b-table", "addr-set-logwizz"
            )
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/sbin/nft", "-j", "list", "set"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["timeout"], 3)
        self.assertTrue(run.call_args.kwargs["check"])

    def test_reban_does_not_send(self):
        self.action.reban({"ip": "198.51.100.24", "bantime": 3600})
        with self.assertRaises(socket.timeout):
            self.received()


if __name__ == "__main__":
    unittest.main()
