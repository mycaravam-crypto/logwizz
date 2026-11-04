"""Dependency-free config and ruleset checks, no root or Docker required."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch


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

    def test_reset_is_reportable_without_losing_future_counts(self):
        self.assertEqual(guard.counter_change(10, 3), (0, True))
        self.assertEqual(guard.counter_change(3, 7), (4, False))
        self.assertEqual(guard.counter_change(3, 3), (0, False))

    def test_nft_nonzero_return_fails(self):
        class Failed:
            returncode = 1
            stderr = "permission denied"
            stdout = ""
        with patch.object(guard.subprocess, "run", return_value=Failed()), self.assertRaisesRegex(RuntimeError, "permission denied"):
            guard.nft("list", "tables")

    def test_parse_counter_valid_and_missing(self):
        good = '{"nftables":[{"counter":{"family":"inet","table":"logwizz_guard","name":"denied","packets":5,"bytes":200}}]}'
        with patch.object(guard, "nft", return_value=good):
            self.assertEqual(guard.denied_packets(), 5)
        with patch.object(guard, "nft", return_value='{"nftables":[]}'), self.assertRaisesRegex(RuntimeError, "missing"):
            guard.denied_packets()

    def test_table_existence_uses_explicit_list(self):
        present = '{"nftables":[{"table":{"family":"inet","name":"logwizz_guard"}}]}'
        absent = '{"nftables":[{"table":{"family":"inet","name":"other"}}]}'
        with patch.object(guard, "nft", return_value=present):
            self.assertTrue(guard.table_exists())
        with patch.object(guard, "nft", return_value=absent):
            self.assertFalse(guard.table_exists())
        with patch.object(guard, "nft", side_effect=RuntimeError("permission denied")), self.assertRaises(RuntimeError):
            guard.table_exists()

    def test_health_fails_closed_when_missing_stale_or_unreadable(self):
        with patch.object(guard, "READY") as ready, patch.object(guard, "denied_packets", return_value=0):
            ready.is_file.return_value = False
            self.assertEqual(guard.healthy(), 1)
            ready.is_file.return_value = True
            ready.stat.return_value.st_mtime = 0
            self.assertEqual(guard.healthy(), 1)
        with patch.object(guard, "READY") as ready, patch.object(guard, "denied_packets", side_effect=RuntimeError("counter unavailable")):
            ready.is_file.return_value = True
            with patch.object(guard.time, "time", return_value=100):
                ready.stat.return_value.st_mtime = 99
                self.assertEqual(guard.healthy(), 1)

if __name__ == "__main__":
    unittest.main()
