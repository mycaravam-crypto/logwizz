#!/bin/sh
# Minimal behavioral tests for packaging/logwizz-notify.
set -eu

repo_root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
bin=$tmp/bin
mkdir -p "$bin" "$tmp/state-success" "$tmp/state-failure"
real_path=$PATH

cat > "$bin/journalctl" <<'STUB'
#!/bin/sh
cat "$TEST_EVENT_FILE"
STUB
cat > "$bin/curl" <<'STUB'
#!/bin/sh
printf 'called\n' >> "$CURL_CALL_LOG"
exit "${FAKE_CURL_EXIT:-0}"
STUB
chmod +x "$bin/journalctl" "$bin/curl"

command -v jq >/dev/null 2>&1 || {
  echo "test-logwizz-notify: jq is required" >&2
  exit 77
}

event_file=$tmp/event.json
jq -cn --arg cursor cursor-test-1 \
  --arg message '{"rule":"test_rule","severity":"error"}' \
  '{__CURSOR:$cursor,MESSAGE:$message}' > "$event_file"

run_notifier() {
  state=$1
  curl_exit=$2
  log=$3
  mkdir -p "$state"
  TEST_EVENT_FILE=$event_file \
  CURL_CALL_LOG=$tmp/curl-calls \
  FAKE_CURL_EXIT=$curl_exit \
  PATH=$bin:$real_path \
  NOTIFY_URL=http://127.0.0.1:8099/ \
  NOTIFY_KIND=webhook \
  NOTIFY_LOG_SUCCESS=yes \
  STATE_DIRECTORY=$state \
  RUNTIME_DIRECTORY=$tmp \
    sh "$repo_root/packaging/logwizz-notify" >"$log" 2>&1 || :
}

run_notifier "$tmp/state-success" 0 "$tmp/success.log"
grep -q "delivered event for rule 'test_rule'" "$tmp/success.log"
grep -qx 'cursor-test-1' "$tmp/state-success/cursor"
test -s "$tmp/curl-calls"

: > "$tmp/curl-calls"
run_notifier "$tmp/state-failure" 22 "$tmp/failure.log"
grep -q 'delivery failed for rule' "$tmp/failure.log"
grep -q 'cursor unchanged' "$tmp/failure.log"
test ! -e "$tmp/state-failure/cursor"
test -s "$tmp/curl-calls"

echo "test-logwizz-notify: all tests passed"
