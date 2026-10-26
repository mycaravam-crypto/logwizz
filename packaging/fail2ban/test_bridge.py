"""Unit tests for the optional Logwizz-to-Fail2ban bridge."""
import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import re
import unittest

SCRIPT = Path(__file__).with_name("logwizz-fail2ban-bridge")
LOADER = SourceFileLoader("logwizz_fail2ban_bridge", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
BRIDGE = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(BRIDGE)

DEFAULTS = BRIDGE.Settings({})
# Globally routable test addresses (documentation ranges are refused).
V4 = "185.220.101.7"
V6 = "2a01:4f8:0:0::1"


def event(rule: str, src: str) -> str:
    return json.dumps({"v": 1, "rule": rule, "fields": {"src": src}})


def fmt(raw: str, settings=DEFAULTS):
    return BRIDGE.format_event(raw, settings)


class FormatEventTests(unittest.TestCase):
    def test_eligible_ipv4_event(self):
        self.assertEqual(
            fmt(event("ssh_bruteforce", V4)),
            f"logwizz rule=ssh_bruteforce src={V4}",
        )

    def test_ipv6_is_validated_and_normalized(self):
        self.assertEqual(
            fmt(event("port_scan", V6)),
            "logwizz rule=port_scan src=2a01:4f8::1",
        )

    def test_ipv4_mapped_ipv6_becomes_ipv4(self):
        self.assertEqual(
            fmt(event("ssh_probe", f"::ffff:{V4}")),
            f"logwizz rule=ssh_probe src={V4}",
        )

    def test_duplicate_events_each_produce_a_line(self):
        # Fail2ban owns deduplication: a source that is already banned is not banned twice.
        raw = event("port_scan", V4)
        self.assertEqual(fmt(raw), fmt(raw))

    def test_unapproved_rule_is_ignored(self):
        self.assertIsNone(fmt(event("log_flood", V4)))
        self.assertIsNone(fmt(event("subnet_scan", V4)), "never a network rule by default")
        self.assertIsNone(fmt(event("login_after_scan", V4)), "a login may be your own")

    def test_missing_source_is_ignored(self):
        self.assertIsNone(fmt(json.dumps({"rule": "port_scan"})))

    def test_invalid_ip_is_ignored(self):
        for src in ["not-an-ip", f"{V4}:22", f"{V4}/32", f" {V4}", "example.com"]:
            self.assertIsNone(fmt(event("port_scan", src)), src)

    def test_malformed_json_is_ignored(self):
        self.assertIsNone(fmt('{"rule":'))

    def test_non_object_json_is_ignored(self):
        self.assertIsNone(fmt("[]"))

    def test_non_global_addresses_are_never_banned(self):
        for src in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.1.1",
            "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1",
            "192.0.2.1", "198.51.100.1", "203.0.113.66", "198.18.0.1",
            "::1", "::", "fe80::1", "fc00::1", "2001:db8::1", "ff02::1",
            "::ffff:127.0.0.1", "::ffff:10.0.0.1",
        ]:
            self.assertIsNone(fmt(event("port_scan", src)), src)


class SettingsTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(DEFAULTS.rules, BRIDGE.DEFAULT_RULES)
        self.assertEqual(DEFAULTS.ignore, ())
        self.assertFalse(DEFAULTS.dry_run)

    def test_rule_list_replaces_the_default(self):
        s = BRIDGE.Settings({"BRIDGE_RULES": " subnet_scan , port_scan,"})
        self.assertEqual(s.rules, {"subnet_scan", "port_scan"})
        self.assertIsNotNone(fmt(event("subnet_scan", V4), s))
        self.assertIsNone(fmt(event("ssh_bruteforce", V4), s))

    def test_ignored_networks(self):
        s = BRIDGE.Settings({"BRIDGE_IGNORE": "185.220.101.0/24, 2a01:4f8::/32"})
        self.assertIsNone(fmt(event("port_scan", V4), s))
        self.assertIsNone(fmt(event("port_scan", f"::ffff:{V4}"), s), "mapped")
        self.assertIsNone(fmt(event("port_scan", V6), s))
        self.assertIsNotNone(fmt(event("port_scan", "185.220.102.7"), s))

    def test_invalid_settings_fail_closed(self):
        for env in [
            {"BRIDGE_RULES": "port scan"},
            {"BRIDGE_RULES": "a;rm -rf /"},
            {"BRIDGE_RULES": " , "},
            {"BRIDGE_IGNORE": "10.0.0.0/33"},
            {"BRIDGE_IGNORE": "example.com"},
            {"BRIDGE_DRY_RUN": "yes"},
        ]:
            with self.assertRaises(ValueError, msg=env):
                BRIDGE.Settings(env)

    def test_dry_run(self):
        self.assertTrue(BRIDGE.Settings({"BRIDGE_DRY_RUN": "1"}).dry_run)


class FilterTests(unittest.TestCase):
    def test_generic_filter_matches_every_bridge_line(self):
        conf = (SCRIPT.parent / "filter.d" / "logwizz.conf").read_text()
        failregex = re.search(r"^failregex = (.*)$", conf, re.M).group(1)
        pattern = re.compile(failregex.replace("<HOST>", r"(?P<host>\S+)"))
        for rule, src in [("port_scan", V4), ("custom.rule:x-1", V6)]:
            line = fmt(event(rule, src), BRIDGE.Settings({"BRIDGE_RULES": rule}))
            m = pattern.match(line)
            self.assertIsNotNone(m, line)
            self.assertEqual(m.group("host"), line.rsplit("=", 1)[1])


if __name__ == "__main__":
    unittest.main()
