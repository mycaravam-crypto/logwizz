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
        self.assertIn("type filter hook output priority 0; policy drop;", policy)
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

    def test_unsafe_events_path_is_rejected_before_nftables_install(self):
        for path in ("/etc/passwd", "/events/../etc/passwd", "/events/other.log"):
            with self.subTest(path=path):
                with patch.dict(guard.os.environ, {
                    "LOGWIZZ_EGRESS_ALLOW": "198.18.0.2:8080",
                    "LOGWIZZ_EVENTS_PATH": path,
                }):
                    with patch.object(guard, "nft") as nft:
                        with self.assertRaisesRegex(ValueError, "events destination"):
                            guard.run()
                        nft.assert_not_called()

    def test_main_dispatch_and_exit_codes(self):
        with patch.object(guard.sys, "argv", ["guard.py", "--health"]), patch.object(
            guard, "healthy", return_value=1
        ) as health:
            self.assertEqual(guard.main(), 1)
            health.assert_called_once_with()

        with patch.object(guard.sys, "argv", ["guard.py", "--validate"]), patch.dict(
            guard.os.environ, {"LOGWIZZ_EGRESS_ALLOW": "198.18.0.2:8080"}
        ):
            self.assertEqual(guard.main(), 0)

        with patch.object(guard.sys, "argv", ["guard.py", "--validate"]), patch.dict(
            guard.os.environ, {"LOGWIZZ_EGRESS_ALLOW": ""}
        ):
            self.assertEqual(guard.main(), 2)

        with patch.object(guard.sys, "argv", ["guard.py", "--unknown"]):
            self.assertEqual(guard.main(), 2)

        with patch.object(guard.sys, "argv", ["guard.py"]), patch.object(
            guard, "run", side_effect=RuntimeError("simulated firewall failure")
        ):
            self.assertEqual(guard.main(), 1)

    def test_run_replaces_its_own_table_in_one_atomic_transaction(self):
        # A restarted guard must reinstall over its surviving table, in a single nft input.
        with patch.dict(guard.os.environ, {"LOGWIZZ_EGRESS_ALLOW": "198.18.0.2:8080"}):
            with patch.object(guard.pathlib.Path, "mkdir"), patch.object(
                guard.os, "open", return_value=42
            ), patch.object(guard, "nft", side_effect=[None, None, RuntimeError("stop")]) as nft:
                with self.assertRaisesRegex(RuntimeError, "stop"):
                    guard.run()
        for call in nft.call_args_list[:2]:
            policy = call.kwargs["input_data"]
            self.assertTrue(policy.startswith(f"table inet {guard.TABLE}\ndelete table inet {guard.TABLE}\n"))
            self.assertIn("policy drop;", policy)

    def test_run_aborts_if_policy_validation_fails(self):
        with patch.dict(guard.os.environ, {"LOGWIZZ_EGRESS_ALLOW": "198.18.0.2:8080"}):
            with patch.object(guard.pathlib.Path, "mkdir"), patch.object(
                guard.os, "open", return_value=42
            ), patch.object(
                guard, "nft", side_effect=RuntimeError("simulated nft validation failure")
            ) as nft:
                with self.assertRaisesRegex(RuntimeError, "simulated nft validation failure"):
                    guard.run()
                self.assertEqual(nft.call_count, 1)
                self.assertEqual(nft.call_args.args[:3], ("-c", "-f", "-"))

if __name__ == "__main__":
    unittest.main()
