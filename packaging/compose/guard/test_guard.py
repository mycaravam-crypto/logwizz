"""Dependency-free config and ruleset checks, no root or Docker required."""
import importlib.util
import pathlib
import unittest


MODULE = pathlib.Path(__file__).with_name("guard.py")
spec = importlib.util.spec_from_file_location("logwizz_guard", MODULE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def test_missing_policy_fails_closed(self):
        with self.assertRaises(ValueError):
            guard.parse_allow("")

    def test_malformed_or_unsafe_destinations_rejected(self):
        for policy in ("example.com:443", "1.1.1.1", "0.0.0.0:443",
                       "224.0.0.1:443", "1.1.1.1:0", "1.1.1.1:99999",
                       "2001:db8::1:443", "1.1.1.1:443,"):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                guard.parse_allow(policy)

    def test_explicit_ip_port_allowlist_only(self):
        allowed = guard.parse_allow("198.18.0.2:8080,192.0.2.1:5432,198.18.0.2:8080")
        policy = guard.ruleset(allowed)
        self.assertEqual(len(allowed), 2)
        self.assertIn("ip daddr 198.18.0.2 tcp dport 8080 accept", policy)
        self.assertIn("ip daddr 192.0.2.1 tcp dport 5432 accept", policy)
        self.assertIn('oifname "lo" accept', policy)
        self.assertIn("ct state established,related accept", policy)
        self.assertLess(policy.index("ip daddr"), policy.index("counter name denied drop"))
        self.assertEqual(policy.count("counter name denied drop"), 1)
        self.assertNotIn("flush ruleset", policy)
        self.assertNotIn("hook forward", policy)

if __name__ == "__main__":
    unittest.main()
