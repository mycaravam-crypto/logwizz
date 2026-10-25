#!/usr/bin/env bash
# SMTP transport: aggregate summary by email, TLS modes, credentials and config checks.
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat > "$tmp/bin/journalctl" <<'MOCK'
#!/bin/sh
cat "$JOURNAL_FIXTURE"
MOCK
cat > "$tmp/bin/curl" <<'MOCK'
#!/bin/sh
printf '%s\n' "$@" >> "$CURL_ARGS_FILE"
config=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=$2; shift 2 ;;
    *) shift ;;
  esac
done
cp "$config" "$CAPTURE_CONFIG"
cat >> "$CAPTURE_MAIL"
exit 0
MOCK
chmod +x "$tmp/bin/journalctl" "$tmp/bin/curl"
ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
event_line() {
  jq -cn --arg cursor "$1" --arg ts "$ts" \
    '{__CURSOR:$cursor,MESSAGE:({v:1,ts:$ts,host:"test-host",rule:"ssh_failed_login",description:"Failed SSH authentication",severity:"warning",line:"RAW-SECRET-SHOULD-NOT-LEAVE-HOST",fields:{src:"203.0.113.7"}}|tojson)}'
}
{ event_line cursor-1; event_line cursor-2; event_line cursor-3; } > "$tmp/events.jsonl"

run() { # case-name env...
  local name=$1; shift
  mkdir -p "$tmp/$name/state" "$tmp/$name/runtime"
  set +e
  env PATH="$tmp/bin:$PATH" JOURNAL_FIXTURE="$tmp/events.jsonl" \
    CURL_ARGS_FILE="$tmp/$name/args" CAPTURE_CONFIG="$tmp/$name/config" CAPTURE_MAIL="$tmp/$name/mail" \
    STATE_DIRECTORY="$tmp/$name/state" RUNTIME_DIRECTORY="$tmp/$name/runtime" \
    NOTIFY_KIND=email NOTIFY_WINDOW_SECS=60 \
    SMTP_HOST=mail.example.test SMTP_FROM=logwizz@example.test SMTP_TO=admin@example.test \
    "$@" bash "$root/packaging/logwizz-notify" 2> "$tmp/$name/stderr"
  status=$?
  set -e
}
fail() { echo "FAIL: $*" >&2; exit 1; }

run starttls SMTP_USER=logwizz SMTP_PASSWORD=smtp-test-password
[[ $status -eq 1 ]] || fail "expected notifier exit 1 after mock journal EOF, got $status"
[[ $(grep -c '^Subject: ' "$tmp/starttls/mail") -eq 1 ]] || fail "expected exactly one email summary"
grep -F $'Subject: logwizz test-host: ssh_failed_login [warning] x3\r' "$tmp/starttls/mail" > /dev/null || fail "subject"
grep -F $'Matches: 3\r' "$tmp/starttls/mail" > /dev/null || fail "count or CRLF line endings"
if grep -F 'RAW-SECRET-SHOULD-NOT-LEAVE-HOST' "$tmp/starttls/mail"; then fail "raw log content leaked into email"; fi
grep -Fx 'url = "smtp://mail.example.test:587"' "$tmp/starttls/config" > /dev/null || fail "STARTTLS url"
grep -Fx 'ssl-reqd' "$tmp/starttls/config" > /dev/null || fail "TLS must be required"
grep -Fx 'mail-from = "logwizz@example.test"' "$tmp/starttls/config" > /dev/null || fail "mail-from"
grep -Fx 'mail-rcpt = "admin@example.test"' "$tmp/starttls/config" > /dev/null || fail "mail-rcpt"
grep -Fx 'user = "logwizz:smtp-test-password"' "$tmp/starttls/config" > /dev/null || fail "credentials"
if grep -F 'smtp-test-password' "$tmp/starttls/args" "$tmp/starttls/stderr"; then fail "SMTP password leaked into curl arguments or logs"; fi

run implicit SMTP_PORT=465 SMTP_TLS=implicit
grep -Fx 'url = "smtps://mail.example.test:465"' "$tmp/implicit/config" > /dev/null || fail "implicit TLS url"
if grep -F 'user =' "$tmp/implicit/config"; then fail "SMTP auth must be absent when credentials are unset"; fi

check_invalid() { # message env...
  local msg=$1; shift
  run invalid "$@"
  [[ $status -eq 2 ]] || fail "expected exit 2 for $*, got $status"
  grep -F "$msg" "$tmp/invalid/stderr" > /dev/null || fail "expected '$msg' for $*"
  if grep -F 'smtp-test-password' "$tmp/invalid/stderr"; then fail "secret in diagnostics"; fi
}
check_invalid SMTP_HOST 'SMTP_HOST=mail.example.test/x'
check_invalid SMTP_PORT SMTP_PORT=70000
check_invalid SMTP_PORT SMTP_PORT=0587
check_invalid SMTP_TLS SMTP_TLS=none
check_invalid 'email addresses' $'SMTP_TO=admin@example.test\nBcc: x@example.test'
check_invalid 'set together' SMTP_PASSWORD=smtp-test-password
echo "SMTP notification smoke tests passed"
