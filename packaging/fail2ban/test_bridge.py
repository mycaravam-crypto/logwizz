"""Unit tests for the optional Logwizz-to-Fail2ban bridge."""
import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import unittest

SCRIPT = Path(__file__).with_name("logwizz-fail2ban-bridge")
LOADER = SourceFileLoader("logwizz_fail2ban_bridge", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
BRIDGE = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(BRIDGE)


def event(rule: str, src: str) -> str:
    return json.dumps({"v": 1, "rule": rule, "fields": {"src": src}})


class FormatEventTests(unittest.TestCase):
    def test_eligible_ipv4_event(self):
        self.assertEqual(
            BRIDGE.format_event(event("ssh_bruteforce", "203.0.113.66")),
            "logwizz rule=ssh_bruteforce src=203.0.113.66",
        )

    def test_ipv6_is_validated_and_normalized(self):
        self.assertEqual(
            BRIDGE.format_event(event("port_scan", "2001:0db8:0:0::1")),
            "logwizz rule=port_scan src=2001:db8::1",
        )

    def test_unapproved_rule_is_ignored(self):
        self.assertIsNone(BRIDGE.format_event(event("log_flood", "203.0.113.66")))

    def test_missing_source_is_ignored(self):
        self.assertIsNone(BRIDGE.format_event(json.dumps({"rule": "port_scan"})))

    def test_invalid_ip_is_ignored(self):
        self.assertIsNone(BRIDGE.format_event(event("port_scan", "not-an-ip")))

    def test_malformed_json_is_ignored(self):
        self.assertIsNone(BRIDGE.format_event('{"rule":'))

    def test_non_object_json_is_ignored(self):
        self.assertIsNone(BRIDGE.format_event("[]"))


if __name__ == "__main__":
    unittest.main()
