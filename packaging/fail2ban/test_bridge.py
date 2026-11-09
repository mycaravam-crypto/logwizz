"""Unit tests for the optional Logwizz-to-Fail2ban bridge."""
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import io
import contextlib
import tempfile
from unittest.mock import patch
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
        self.assertEqual(DEFAULTS.journal_mode, "namespace")

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
        # An address is compared with networks of the other family too: no match, no error.
        self.assertIsNotNone(fmt(event("port_scan", "185.220.102.7"), s))
        self.assertIsNotNone(fmt(event("port_scan", "2a02:4f8::1"), s))

    def test_invalid_settings_fail_closed(self):
        for env in [
            {"BRIDGE_RULES": "port scan"},
            {"BRIDGE_RULES": "a;rm -rf /"},
            {"BRIDGE_RULES": " , "},
            {"BRIDGE_IGNORE": "10.0.0.0/33"},
            {"BRIDGE_IGNORE": "example.com"},
            {"BRIDGE_DRY_RUN": "yes"},
            {"BRIDGE_JOURNAL_MODE": ""},
            {"BRIDGE_JOURNAL_MODE": "Legacy"},
            {"BRIDGE_JOURNAL_MODE": "namespace;legacy"},
        ]:
            with self.assertRaises(ValueError, msg=env):
                BRIDGE.Settings(env)

    def test_dry_run(self):
        self.assertTrue(BRIDGE.Settings({"BRIDGE_DRY_RUN": "1"}).dry_run)

    def ignore_file(self, content):
        tmp = tempfile.NamedTemporaryFile("wb", suffix=".list", delete=False)
        self.addCleanup(Path(tmp.name).unlink)
        with tmp:
            tmp.write(content)
        return tmp.name

    def test_ignore_file_adds_to_the_ignore_list(self):
        path = self.ignore_file(
            b"# management\n185.220.101.0/24   # office\n\n  2a01:4f8::/32\n185.220.103.9\n")
        s = BRIDGE.Settings({"BRIDGE_IGNORE_FILE": path})
        self.assertEqual(len(s.ignore), 3)
        self.assertIsNone(fmt(event("port_scan", V4), s))
        self.assertIsNone(fmt(event("port_scan", V6), s))
        self.assertIsNone(fmt(event("port_scan", "185.220.103.9"), s))
        self.assertIsNotNone(fmt(event("port_scan", "185.220.102.7"), s))
        # Both sources apply.
        s = BRIDGE.Settings({"BRIDGE_IGNORE": "185.220.102.0/24", "BRIDGE_IGNORE_FILE": path})
        self.assertEqual(len(s.ignore), 4)
        self.assertIsNone(fmt(event("port_scan", "185.220.102.7"), s))
        self.assertIsNone(fmt(event("port_scan", V4), s))

    def test_empty_ignore_file_is_valid(self):
        s = BRIDGE.Settings({"BRIDGE_IGNORE_FILE": self.ignore_file(b"# nothing yet\n")})
        self.assertEqual(s.ignore, ())

    def test_ignore_file_problems_fail_closed(self):
        big = b"10.0.0.0/8\n" * (BRIDGE.MAX_IGNORE_FILE_BYTES // 11 + 1)
        for value, message in [
            ("/nonexistent/logwizz-ignore.list", "No such file"),
            ("relative.list", "absolute path"),
            ("", "absolute path"),
            (self.ignore_file(b"10.0.0.0/8\nexample.com\n"), "line 2"),
            (self.ignore_file(b"10.0.0.0/33\n"), "line 1"),
            (self.ignore_file(b"10.0.0.1, 10.0.0.2\n"), "line 1"),
            (self.ignore_file(b"\xff\xfe"), "not UTF-8"),
            (self.ignore_file(big), "larger than"),
        ]:
            with self.assertRaises(ValueError, msg=value) as caught:
                BRIDGE.Settings({"BRIDGE_IGNORE_FILE": value})
            self.assertIn(message, str(caught.exception))

    def test_unreadable_ignore_file_stops_before_the_journal(self):
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            popen = stack.enter_context(patch.object(BRIDGE.subprocess, "Popen"))
            stack.enter_context(patch.dict(BRIDGE.os.environ, {
                "BRIDGE_IGNORE_FILE": "/nonexistent/logwizz-ignore.list",
            }, clear=True))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = BRIDGE.main()
        self.assertEqual(code, 2)
        popen.assert_not_called()
        self.assertIn("BRIDGE_IGNORE_FILE", stderr.getvalue())


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

    def test_recidive_filter_matches_only_bans_of_the_logwizz_jail(self):
        conf = (SCRIPT.parent / "filter.d" / "logwizz-recidive.conf").read_text()
        failregex = re.search(r"^failregex = (.*)$", conf, re.M).group(1)
        pattern = re.compile(failregex.replace("<HOST>", r"(?P<host>\S+)"))
        # Fail2ban removes the timestamp before it applies the expression.
        prefix = " fail2ban.actions        [46533]: "
        for jail, text, host in [
            ("logwizz", f"Ban {V4}", V4),
            ("logwizz", f"Ban {V6}", V6),
            ("sshd", f"Ban {V4}", None),
            ("logwizz-recidive", f"Ban {V4}", None),
            ("logwizz", f"Unban {V4}", None),
            ("logwizz", f"Restore Ban {V4}", None),
            ("logwizz", f"Increase Ban {V4} (2 # 2h -> 2026-10-25 03:08:50)", None),
        ]:
            line = f"{prefix}NOTICE  [{jail}] {text}"
            m = pattern.match(line)
            self.assertEqual(m.group("host") if m else None, host, line)
        self.assertIsNone(pattern.match(f"{prefix}WARNING [logwizz] {V4} already banned"))
        self.assertIsNone(pattern.match(f" fail2ban.filter [1]: INFO [logwizz] Found {V4}"))

    def test_shipped_jails_are_disabled(self):
        for name in ("logwizz.local", "logwizz-recidive.local"):
            conf = (SCRIPT.parent / "jail.d" / name).read_text()
            self.assertRegex(conf, r"(?m)^enabled\s*=\s*false$", name)
            self.assertNotRegex(conf, r"(?m)^enabled\s*=\s*true", name)



NAMESPACE_CMD = ["journalctl", "--namespace=logwizz", "--unit=logwizz.service",
                 "--output=cat", "--follow", "--since=now"]
LEGACY_CMD = ["journalctl", "--unit=logwizz.service",
              "--output=cat", "--follow", "--since=now"]


class JournalModeTests(unittest.TestCase):
    def test_default_and_namespace_do_not_probe_journalctl(self):
        with patch.object(BRIDGE, "namespace_supported") as probe:
            self.assertEqual(BRIDGE.journal_command(DEFAULTS.journal_mode), NAMESPACE_CMD)
            self.assertEqual(BRIDGE.journal_command("namespace"), NAMESPACE_CMD)
            self.assertEqual(BRIDGE.journal_command("legacy"), LEGACY_CMD)
        probe.assert_not_called()

    def test_auto_follows_journalctl_support(self):
        with patch.object(BRIDGE, "namespace_supported", return_value=True):
            self.assertEqual(BRIDGE.journal_command("auto"), NAMESPACE_CMD)
        with patch.object(BRIDGE, "namespace_supported", return_value=False):
            self.assertEqual(BRIDGE.journal_command("auto"), LEGACY_CMD)

    def test_probe_reads_journalctl_help(self):
        for text, expected in [("  --namespace=NAMESPACE  Show ...\n", True),
                               ("  -u --unit=UNIT  Show ...\n", False)]:
            done = BRIDGE.subprocess.CompletedProcess([], 0, stdout=text)
            with patch.object(BRIDGE.subprocess, "run", return_value=done) as run:
                self.assertEqual(BRIDGE.namespace_supported(), expected)
            self.assertEqual(run.call_args.args[0], ["journalctl", "--help"])

    def run_main(self, env, **patches):
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(patch.object(BRIDGE, name, **value))
            follow = stack.enter_context(patch.object(BRIDGE, "follow", return_value=0))
            stack.enter_context(patch.dict(BRIDGE.os.environ, env, clear=True))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = BRIDGE.main()
        return code, follow, stderr.getvalue()

    def test_legacy_mode_reads_the_main_journal(self):
        code, follow, err = self.run_main(
            {"BRIDGE_DRY_RUN": "1", "BRIDGE_JOURNAL_MODE": "legacy"})
        self.assertEqual(code, 0)
        self.assertEqual(follow.call_args.args[2], LEGACY_CMD)
        self.assertIn("reading the main journal", err)

    def test_unset_mode_keeps_the_namespace(self):
        code, follow, err = self.run_main({"BRIDGE_DRY_RUN": "1"})
        self.assertEqual(code, 0)
        self.assertEqual(follow.call_args.args[2], NAMESPACE_CMD)
        self.assertIn("reading the journal namespace", err)

    def test_failed_probe_stops_before_following(self):
        for exc in (FileNotFoundError("journalctl missing"),
                    BRIDGE.subprocess.CalledProcessError(1, "journalctl")):
            code, follow, err = self.run_main(
                {"BRIDGE_JOURNAL_MODE": "auto"},
                namespace_supported={"side_effect": exc})
            self.assertEqual(code, 1)
            follow.assert_not_called()
            self.assertIn("journalctl", err)


class FollowProcessTests(unittest.TestCase):
    """Exercise the bridge stream and output path without running Fail2ban."""

    def run_stream(self, settings, feed, output, journal_exit_code=0, expected_code=0):
        class FakeJournal:
            def __init__(self):
                self.stdout = io.StringIO(feed)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stdout.close()

            def wait(self):
                return journal_exit_code

        calls = []

        def popen(argv, **kwargs):
            calls.append(argv)
            return FakeJournal()

        stderr = io.StringIO()
        with patch.object(BRIDGE, "OUTPUT", output), \
             patch.object(BRIDGE.subprocess, "Popen", side_effect=popen), \
             contextlib.redirect_stderr(stderr), contextlib.ExitStack() as stack:
            code = BRIDGE.follow(settings, stack)
        self.assertEqual(code, expected_code)
        self.assertEqual(calls, [NAMESPACE_CMD])
        return stderr.getvalue()

    def test_journalctl_failure_status_is_propagated(self):
        settings = BRIDGE.Settings({"BRIDGE_DRY_RUN": "1"})
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "fail2ban.log"
            self.run_stream(
                settings, "", output, journal_exit_code=7, expected_code=7
            )
            self.assertFalse(output.exists())

    def test_dry_run_never_creates_enforcement_log(self):
        settings = BRIDGE.Settings({"BRIDGE_DRY_RUN": "1"})
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "fail2ban.log"
            feed = "\n".join([
                event("port_scan", V4),
                event("port_scan", "127.0.0.1"),
                event("log_flood", V4),
                "broken-json",
                "",
            ])
            stderr = self.run_stream(settings, feed, output)
            self.assertFalse(output.exists())
            self.assertEqual(stderr.count("would write:"), 1)
            self.assertIn(f"src={V4}", stderr)

    def test_enabled_mode_writes_only_eligible_events(self):
        settings = BRIDGE.Settings({"BRIDGE_IGNORE": "185.220.102.0/24"})
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "fail2ban.log"
            feed = "\n".join([
                event("ssh_bruteforce", V4),
                event("port_scan", "185.220.102.7"),
                event("log_flood", V4),
                event("port_scan", "192.0.2.1"),
                "not-json",
                "",
            ])
            stderr = self.run_stream(settings, feed, output)
            self.assertEqual(stderr, "")
            lines = output.read_text().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertTrue(lines[0].endswith(f"logwizz rule=ssh_bruteforce src={V4}"))
            self.assertEqual(output.stat().st_mode & 0o777, 0o640)

    def test_blank_explicit_allowlist_is_rejected(self):
        # An explicitly configured empty policy must never silently enable defaults.
        for raw in ("", " ", "\t", "\n"):
            with self.assertRaisesRegex(ValueError, "explicit empty allowlist", msg=repr(raw)):
                BRIDGE.Settings({"BRIDGE_RULES": raw})
        # Separators alone leave no rule IDs and are rejected as invalid.
        for raw in (",", " , ", ",,"):
            with self.assertRaisesRegex(ValueError, "invalid rule IDs", msg=repr(raw)):
                BRIDGE.Settings({"BRIDGE_RULES": raw})

    def test_unauthorized_rule_with_global_src_does_not_enforce(self):
        # A client-controlled address is not intrinsically authenticated.
        # This proves rule gating, NOT provenance of fields.src.
        forged = event("log_flood", V4)
        self.assertIsNone(fmt(forged))

    def test_high_volume_rejected_events_produce_no_enforcement_lines(self):
        settings = BRIDGE.Settings({"BRIDGE_DRY_RUN": "1"})
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "fail2ban.log"
            # One trailing eligible event proves the whole feed was consumed.
            rejected = [event("log_flood", V4)] * 2000
            feed = "\n".join(rejected + [event("ssh_bruteforce", V4), ""])
            stderr = self.run_stream(settings, feed, output)
            self.assertEqual(stderr.count("would write:"), 1)
            self.assertFalse(output.exists())


class MainFailurePathTests(unittest.TestCase):
    """The optional bridge must stop safely when startup prerequisites fail."""

    def test_missing_journalctl_fails_without_enforcement_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "fail2ban.log"
            stderr = io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(BRIDGE, "OUTPUT", output))
                popen = stack.enter_context(patch.object(
                    BRIDGE.subprocess, "Popen",
                    side_effect=FileNotFoundError("journalctl missing"),
                ))
                stack.enter_context(patch.dict(BRIDGE.os.environ, {
                    "BRIDGE_DRY_RUN": "0",
                    "BRIDGE_RULES": "ssh_bruteforce",
                }, clear=True))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                code = BRIDGE.main()

            self.assertEqual(code, 1)
            popen.assert_called_once()
            self.assertIn("journalctl missing", stderr.getvalue())
            # Opening the sink is not enforcement: it must remain empty on startup failure.
            self.assertTrue(output.exists())
            self.assertEqual(output.read_text(), "")

    def test_invalid_configuration_aborts_before_starting_journal(self):
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            popen = stack.enter_context(patch.object(BRIDGE.subprocess, "Popen"))
            stack.enter_context(patch.dict(BRIDGE.os.environ, {
                "BRIDGE_RULES": "",
                "BRIDGE_DRY_RUN": "0",
            }, clear=True))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = BRIDGE.main()

        self.assertEqual(code, 2)
        popen.assert_not_called()
        self.assertIn("explicit empty allowlist", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
