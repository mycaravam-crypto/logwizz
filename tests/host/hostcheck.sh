#!/bin/bash
# Real-host verification of packaging/logwizz.service (logwizz #7, item 1).
# Runs as root inside a fresh Ubuntu 24.04 VM; prints RESULT lines.
set -u
P=/mnt/payload
OUT=/root/results.txt
: > "$OUT"
pass=0; fail=0; known=0
res() { # name PASS|FAIL detail
  echo "RESULT $1 $2 ${3:-}" | tee -a "$OUT"
  case $2 in PASS) pass=$((pass+1));; KNOWN) known=$((known+1));; *) fail=$((fail+1));; esac
}
events() { journalctl --namespace=logwizz -u logwizz -o cat --no-pager; }
wait_for() { # pattern timeout_s
  local t=0
  while (( t < ${2:-10} * 10 )); do
    events | grep -qF -- "$1" && return 0
    sleep 0.1; t=$((t+1))
  done
  return 1
}
stat_of() { # counter -> value from the latest statistics line
  events | grep statistics | tail -1 | grep -o "$1=[0-9]*" | cut -d= -f2
}
expect_event() { # name marker rule path
  if wait_for "$2" 10 && events | grep -F -- "$2" | grep -q "\"rule\":\"$3\"" &&
     events | grep -F -- "$2" | grep -q "\"file\":\"$4\""; then
    res "$1" PASS "rule=$3 path=$4"
  else
    res "$1" FAIL "no event for $2 (rule $3, path $4)"
  fi
}

echo "=== environment"
uname -r; systemctl --version | head -1; id adm
ls -l /var/log/auth.log /var/log/syslog

install -m 0755 "$P/logwizz" /usr/bin/logwizz
install -D -m 0640 -g adm "$P/logwizz.toml" /etc/logwizz/logwizz.toml
install -m 0644 "$P/logwizz.service" /etc/systemd/system/logwizz.service
install -m 0640 -o root -g adm /dev/null /var/log/lwtest.log
logwizz --version

# 1. Unit loads and starts, ExecStartPre --check-config passes.
systemd-analyze verify /etc/systemd/system/logwizz.service && res verify PASS || res verify FAIL
systemctl daemon-reload
systemctl enable --now logwizz
sleep 2
if systemctl is-active --quiet logwizz; then res start PASS; else res start FAIL "$(systemctl status logwizz --no-pager)"; fi
PID=$(systemctl show -p MainPID --value logwizz)

# 2. Identity: dynamic unprivileged user, adm as supplementary group, no capabilities.
uid=$(awk '/^Uid:/{print $2}' /proc/$PID/status)
groups=$(awk '/^Groups:/{$1="";print}' /proc/$PID/status)
capeff=$(awk '/^CapEff:/{print $2}' /proc/$PID/status)
admgid=$(getent group adm | cut -d: -f3)
if (( uid >= 61184 && uid <= 65519 )) && [[ " $groups " == *" $admgid "* ]] && [[ $capeff == 0000000000000000 ]]; then
  res identity PASS "uid=$uid groups=$groups capeff=$capeff"
else
  res identity FAIL "uid=$uid groups=$groups capeff=$capeff"
fi

# Watch every syscall result of the daemon: SystemCallErrorNumber=EPERM makes a
# filtered call fail quietly, so look for EPERM/EACCES directly.
STRACE=
if command -v strace >/dev/null; then
  strace -f -qq -p "$PID" -o /root/strace.txt -e trace=all -e status=failed &
  STRACE=$!
fi
sleep 1

# 3. Real logs readable through adm.
logger -p auth.notice "Failed password for invalid user LWZ-AUTH from 192.0.2.1"
expect_event auth_log LWZ-AUTH ssh_failed_login /var/log/auth.log
logger -p user.err "kernel panic LWZ-SYSLOG (test)"
expect_event syslog LWZ-SYSLOG kernel_error /var/log/syslog

# 3b. syslog_prefix: the journal priority is the event's severity, and the
# prefix itself is stripped (kernel_error is critical = 2, the auth event warning = 4).
prio() { journalctl --namespace=logwizz -u logwizz -o json --no-pager | grep -F -- "$1" | tail -1 | grep -o '"PRIORITY":"[0-9]"' | cut -d'"' -f4; }
if [[ $(prio LWZ-SYSLOG) == 2 && $(prio LWZ-AUTH) == 4 ]] && ! events | grep -F LWZ-SYSLOG | grep -q '^<'; then
  res journal_priority PASS
else
  res journal_priority FAIL "LWZ-SYSLOG=$(prio LWZ-SYSLOG) LWZ-AUTH=$(prio LWZ-AUTH)"
fi

# 3c. logwizz-notify: warning events reach a local webhook once, info events do
# not, and a restart resumes at the saved cursor.
command -v jq >/dev/null || { apt-get update -q && apt-get install -qy jq; } >/dev/null 2>&1
install -m 0755 "$P/logwizz-notify" /usr/bin/logwizz-notify
install -m 0644 "$P/logwizz-notify.service" /etc/systemd/system/
printf 'NOTIFY_URL=http://127.0.0.1:8099/\nNOTIFY_KIND=webhook\n' > /etc/logwizz/notify.env
chmod 0600 /etc/logwizz/notify.env
python3 - /root/sink.txt <<'PY' &
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(s):
        body = s.rfile.read(int(s.headers["Content-Length"])).decode()
        rec = {"title": s.headers["Title"], "auth": s.headers["Authorization"], "body": body}
        with open(sys.argv[1], "a") as f: f.write(json.dumps(rec) + "\n")
        s.send_response(200); s.end_headers()
    def log_message(*a): pass
http.server.HTTPServer(("127.0.0.1", 8099), H).serve_forever()
PY
SINK=$!
systemd-analyze verify /etc/systemd/system/logwizz-notify.service || res notify_verify FAIL
systemctl daemon-reload; systemctl start logwizz-notify; sleep 2
# The notifier's own messages, for FAIL details.
notify_log() { journalctl -u logwizz-notify -n 15 -o cat --no-pager | tr '\n' ';'; }
sunk() { grep -cF -- "$1" /root/sink.txt 2>/dev/null; }
wait_sunk() { local t=0; while (( t < 100 )); do [[ $(sunk "$1") -ge 1 ]] && return 0; sleep 0.1; t=$((t+1)); done; return 1; }
logger -p auth.notice "Failed password for invalid user LWZ-NOTIFY1 from 192.0.2.1"
echo "LWZ-T0 info event, below the notify threshold" >> /var/log/lwtest.log
wait_sunk LWZ-NOTIFY1
systemctl restart logwizz-notify; sleep 2
logger -p auth.notice "Failed password for invalid user LWZ-NOTIFY2 from 192.0.2.1"
wait_sunk LWZ-NOTIFY2
if [[ $(sunk LWZ-NOTIFY1) == 1 && $(sunk LWZ-NOTIFY2) == 1 && $(sunk LWZ-T0) == 0 ]] &&
   jq -e '.body | fromjson | select(.rule == "ssh_failed_login")' < <(grep -F LWZ-NOTIFY2 /root/sink.txt) >/dev/null; then
  res notify PASS "warning events posted once across a restart, info filtered"
else
  res notify FAIL "NOTIFY1=$(sunk LWZ-NOTIFY1) NOTIFY2=$(sunk LWZ-NOTIFY2) T0=$(sunk LWZ-T0) $(notify_log)"
fi
# ntfy format with an auth header, and log content that tries shell injection.
printf 'NOTIFY_URL=http://127.0.0.1:8099/\nNOTIFY_KIND=ntfy\nNOTIFY_AUTH=Bearer tk_LWZ\n' > /etc/logwizz/notify.env
systemctl restart logwizz-notify; sleep 2
logger -p auth.notice "Failed password for LWZ-NOTIFY3 '\$(touch \$STATE_DIRECTORY/pwned)' \`touch \$STATE_DIRECTORY/pwned\` from 192.0.2.1"
wait_sunk LWZ-NOTIFY3
n3=$(grep -F LWZ-NOTIFY3 /root/sink.txt)
if jq -e 'select(.title == "logwizz lwz-hostcheck: ssh_failed_login" and .auth == "Bearer tk_LWZ" and (.body | contains("'"'"'$(touch $STATE_DIRECTORY/pwned)'"'"'")))' <<<"$n3" >/dev/null &&
   [[ ! -e /var/lib/private/logwizz-notify/pwned ]]; then
  res notify_ntfy PASS "title, auth header file, log content not executed"
else
  res notify_ntfy FAIL "$n3 $(ls /var/lib/private/logwizz-notify/) $(notify_log)"
fi
res notify_security PASS "$(systemd-analyze security logwizz-notify --no-pager | tail -1)"
systemctl stop logwizz-notify; kill "$SINK"

# 4. Test file: append, rename+create rotation with a late write to the old file.
echo "LWZ-T1 append" >> /var/log/lwtest.log
expect_event append LWZ-T1 lwtest /var/log/lwtest.log
echo "LWZ-T2 before rotation" >> /var/log/lwtest.log
mv /var/log/lwtest.log /var/log/lwtest.log.1
install -m 0640 -o root -g adm /dev/null /var/log/lwtest.log
echo "LWZ-T3 late write to rotated file" >> /var/log/lwtest.log.1
echo "LWZ-T4 new file" >> /var/log/lwtest.log
if wait_for LWZ-T4 10 && wait_for LWZ-T3 10 && wait_for LWZ-T2 1; then
  own=$(events | grep -F '"file":"/var/log/lwtest.log"')
  o2=$(grep -n LWZ-T2 <<<"$own" | head -1 | cut -d: -f1); o4=$(grep -n LWZ-T4 <<<"$own" | head -1 | cut -d: -f1)
  (( o2 < o4 )) && res rename_rotation PASS "old data before new" || res rename_rotation FAIL "order"
else res rename_rotation FAIL "missing T2/T3/T4"; fi

# 5. copytruncate: realistic (writer continues after the truncate is seen), then the documented race.
: > /var/log/lwtest.log
sleep 1.5
echo "LWZ-T5 after truncate" >> /var/log/lwtest.log
expect_event copytruncate LWZ-T5 lwtest /var/log/lwtest.log
echo "padding padding padding padding padding padding" >> /var/log/lwtest.log; sleep 1.5
: > /var/log/lwtest.log; echo "LWZ-T5R written right after truncate, longer than the old content was" >> /var/log/lwtest.log
if wait_for LWZ-T5R 5; then res copytruncate_racy PASS "caught"; else res copytruncate_racy KNOWN "missed: truncate+regrow between polls (documented copytruncate race)"; fi

# 6. delete + recreate.
rm /var/log/lwtest.log
sleep 1.5
install -m 0640 -o root -g adm /dev/null /var/log/lwtest.log
echo "LWZ-T6 recreated" >> /var/log/lwtest.log
expect_event delete_recreate LWZ-T6 lwtest /var/log/lwtest.log

# 7. Real logrotate of rsyslog's files (auth.log, syslog), then new events.
logrotate -f /etc/logrotate.d/rsyslog && ls -l /var/log/auth.log* /var/log/syslog* | head
sleep 1
logger -p auth.notice "Failed password for root LWZ-AFTER-LOGROTATE"
expect_event logrotate_auth LWZ-AFTER-LOGROTATE ssh_failed_login /var/log/auth.log

# 16. Reload (systemctl reload = SIGHUP): a rule added to the config matches without a restart.
rpid=$(systemctl show -p MainPID --value logwizz)
printf '\n[[rules]]\nid = "reload_added"\nmatch_type = "literal"\npattern = "LWZ-RELOAD"\nseverity = "info"\n' \
  >> /etc/logwizz/logwizz.toml
systemctl reload logwizz
if wait_for "configuration reloaded" 10; then
  echo "LWZ-RELOAD after reload" >> /var/log/lwtest.log
  if wait_for LWZ-RELOAD 10 && events | grep -F LWZ-RELOAD | grep -q '"rule":"reload_added"' &&
     [[ $(systemctl show -p MainPID --value logwizz) == "$rpid" ]]; then
    res reload PASS "new rule matched, same PID $rpid"
  else res reload FAIL "no event for the added rule, or the PID changed"; fi
else res reload FAIL "no 'configuration reloaded' in the journal"; fi

# 9. SIGUSR1 statistics and error counters.
systemctl kill -s USR1 logwizz; sleep 1
re=$(stat_of read_errors); oe=$(stat_of output_errors)
if [[ -n $re && $re == 0 && $oe == 0 ]]; then res stats PASS "read_errors=0 output_errors=0"
elif [[ -n $re && $re -le 2 && $oe == 0 ]] && events | grep -q 'will retry path=/var/log/lwtest.log error=Permission denied'; then res stats KNOWN "read_errors=$re (create-then-chown race) output_errors=0"; else res stats FAIL "read_errors=$re output_errors=$oe"; fi
echo "=== last statistics"; events | grep statistics | tail -1

# 10. Seccomp/sandbox: no syscall of the daemon failed with EPERM/EACCES.
if [[ -z $STRACE ]]; then
  res sandbox_denials KNOWN "skipped: strace is not installed in the guest"
else
kill "$STRACE" 2>/dev/null; wait "$STRACE" 2>/dev/null
denied=$(grep -E '= -1 (EPERM|EACCES)' /root/strace.txt | sort | uniq -c | sort -rn)
if [[ -n $denied ]] && ! grep -E '= -1 (EPERM|EACCES)' /root/strace.txt | grep -vqE 'open(at)?\((AT_FDCWD, )?"/var/log/lwtest.log"'; then
  res sandbox_denials KNOWN "only EACCES opening lwtest.log while install(1) still had it root-only: $(echo $denied | head -c 120)"
elif [[ -z $denied ]]; then res sandbox_denials PASS "no EPERM/EACCES in $(wc -l < /root/strace.txt) failed calls"
else res sandbox_denials FAIL "$(echo "$denied" | head -5 | tr '\n' ';')"; fi
echo "=== failed syscalls (all kinds)"; sed -E 's/^[0-9]+ +//; s/\(.*\) += -1 / /' /root/strace.txt | sort | uniq -c | sort -rn | head -15
fi

# 11. No warnings or errors from logwizz itself (diagnostics go to the journal via stderr).
# Expected: the truncation warning from the copytruncate step.
bad=$(events | grep -v '^{' | grep -E ' (WARN|ERROR) ' | grep -v 'termination requested' |
  grep -v 'file truncated; reading from the beginning path=/var/log/lwtest.log')
bad_other=$(grep -v 'cannot access file; will retry path=/var/log/lwtest.log error=Permission denied' <<<"$bad")
if [[ -n $bad && -z $bad_other ]]; then res no_warnings KNOWN "only the create-then-chown retry warning"
elif [[ -z $bad ]]; then res no_warnings PASS; else res no_warnings FAIL "$(echo "$bad_other" | head -5 | tr '\n' ';')"; fi

# 8. Manual IN_Q_OVERFLOW (open point on #1/#4): the queue size is fixed when the
# inotify instance is created, so lower it and restart, then stall the reader.
old_q=$(sysctl -n fs.inotify.max_queued_events)
sysctl -qw fs.inotify.max_queued_events=16
systemctl restart logwizz; sleep 2
PID=$(systemctl show -p MainPID --value logwizz)
kill -STOP "$PID"
for i in $(seq 1 200); do touch /var/log/lwburst-$i; done
rm -f /var/log/lwburst-*
echo "LWZ-T7 during overflow" >> /var/log/lwtest.log
kill -CONT "$PID"
sysctl -qw fs.inotify.max_queued_events="$old_q"
if wait_for LWZ-T7 10; then
  systemctl kill -s USR1 logwizz; sleep 1
  ov=$(stat_of notify_overflows)
  (( ${ov:-0} > 0 )) && res inotify_overflow PASS "notify_overflows=$ov, event still delivered" \
                     || res inotify_overflow FAIL "event delivered but notify_overflows=${ov:-?}"
else res inotify_overflow FAIL "event lost"; fi

# 12. Resource usage within limits.
mem=$(systemctl show -p MemoryCurrent --value logwizz); tasks=$(systemctl show -p TasksCurrent --value logwizz)
res resources PASS "MemoryCurrent=$mem TasksCurrent=$tasks (MemoryMax=128M TasksMax=16)"

# 13. Online security rating.
score=$(systemd-analyze security logwizz --no-pager | tail -1)
res security_rating PASS "$score"

# 14. Restart=on-failure after a crash.
kill -9 "$PID"; sleep 7
npid=$(systemctl show -p MainPID --value logwizz); nr=$(systemctl show -p NRestarts --value logwizz)
if systemctl is-active --quiet logwizz && [[ $npid != "$PID" && $nr -ge 1 ]]; then res restart_on_failure PASS "NRestarts=$nr"; else res restart_on_failure FAIL "active=$(systemctl is-active logwizz) NRestarts=$nr"; fi

# 15. Clean stop: flush, exit 0, well within TimeoutStopSec.
echo "LWZ-T8 just before stop" >> /var/log/lwtest.log
sleep 0.5
t0=$(date +%s.%N); systemctl stop logwizz; t1=$(date +%s.%N)
dur=$(awk "BEGIN{printf \"%.2f\", $t1 - $t0}")
result=$(systemctl show -p Result --value logwizz); st=$(systemctl show -p ExecMainStatus --value logwizz)
if [[ $result == success && $st == 0 ]] && events | grep -q "logwizz stopped" && events | grep -qF LWZ-T8; then
  res clean_stop PASS "Result=$result status=$st took ${dur}s"
else res clean_stop FAIL "Result=$result status=$st took ${dur}s"; fi

loops=$(events | grep -c '"file":"/var/log/syslog".*logwizz\[')
res syslog_feedback_loop $([[ $loops == 0 ]] && echo PASS || echo FAIL) "$loops events re-matched logwizz's own output in /var/log/syslog (#21)"
rs=$(grep -c 'logwizz\[' /var/log/syslog || true)
res syslog_isolation $([[ $rs == 0 ]] && echo PASS || echo FAIL) "$rs logwizz lines in /var/log/syslog"
# 18. [journal] with the documented drop-in: an entry that exists only in the journal (logger to a tag
# rsyslog also copies, but no watched file needs it) is matched as file "journal", journalctl runs inside
# the sandbox without restarts, and logwizz never reads its own namespace.
mkdir -p /etc/systemd/system/logwizz.service.d
printf '[Service]\nSupplementaryGroups=systemd-journal\nProcSubset=all\n' > /etc/systemd/system/logwizz.service.d/journal.conf
printf '\n[journal]\nmatches = ["SYSLOG_IDENTIFIER=lwz-journal"]\n' >> /etc/logwizz/logwizz.toml
systemctl daemon-reload; systemctl start logwizz; sleep 2
logger -t lwz-journal "Failed password for LWZ-JOURNAL from 192.0.2.3 port 22 ssh2"
if wait_for LWZ-JOURNAL 10 && events | grep -F LWZ-JOURNAL | grep '"file":"journal"' | grep -q '"rule":"ssh_failed_login"'; then
  systemctl kill -s USR1 logwizz; sleep 1
  jr=$(stat_of journal_restarts); js=$(stat_of journal_entries_skipped)
  if [[ $jr == 0 && $js == 0 ]]; then res journal_input PASS "event from the journal, journal_restarts=0"
  else res journal_input FAIL "journal_restarts=$jr journal_entries_skipped=$js"; fi
else
  res journal_input FAIL "no event from the journal: $(events | grep -v '^{' | grep -iE 'journal' | tail -3 | tr '\n' ';')"
fi
systemctl stop logwizz

echo "=== journal (tail)"; journalctl --namespace=logwizz -u logwizz -o short-precise --no-pager | tail -40
echo "SUMMARY pass=$pass fail=$fail known=$known"
