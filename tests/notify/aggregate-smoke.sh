#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/state-webhook" "$tmp/runtime-webhook" "$tmp/state-telegram" "$tmp/runtime-telegram"
cat > "$tmp/bin/journalctl" <<'MOCK'
#!/bin/sh
cursor=
for arg do case "$arg" in --after-cursor=*) cursor=${arg#--after-cursor=} ;; esac; done
seen=0
while IFS= read -r line; do
  if [ -n "$cursor" ] && [ "$seen" -eq 0 ]; then
    current=$(printf '%s' "$line" | jq -r '.__CURSOR')
    if [ "$current" = "$cursor" ]; then seen=1; fi
    continue
  fi
  printf '%s\n' "$line"
done < "$JOURNAL_FIXTURE"
MOCK
cat > "$tmp/bin/curl" <<'MOCK'
#!/bin/sh
printf '%s\n' "$@" >> "$CURL_ARGS_FILE"
body=
text=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --data-binary) body=$2; shift 2 ;;
    --data-urlencode) case "$2" in text=*) text=${2#text=} ;; esac; shift 2 ;;
    *) shift ;;
  esac
done
if [ -n "$body" ]; then printf '%s\n' "$body" >> "$CAPTURE_FILE"; fi
if [ -n "$text" ]; then printf '%s\n' "$text" >> "$CAPTURE_FILE"; printf '{"ok":true}\n'; fi
if [ "${CURL_FAIL:-0}" = 1 ]; then exit 22; fi
exit 0
MOCK
chmod +x "$tmp/bin/journalctl" "$tmp/bin/curl"
now=$(date -u +%s)
ts=$(date -u -d "@$now" '+%Y-%m-%dT%H:%M:%SZ')
event_line() {
  local cursor=$1 source=$2
  jq -cn --arg cursor "$cursor" --arg ts "$ts" --arg source "$source" \
    '{__CURSOR:$cursor,MESSAGE:({v:1,ts:$ts,host:"test-host",rule:"ssh_failed_login",description:"Failed SSH authentication",severity:"warning",line:"RAW-SECRET-SHOULD-NOT-LEAVE-HOST",fields:{src:$source}}|tojson)}'
}
{
  event_line cursor-1 203.0.113.7
  event_line cursor-2 203.0.113.7
  event_line cursor-3 203.0.113.8
} > "$tmp/events.jsonl"
set +e
PATH="$tmp/bin:$PATH" JOURNAL_FIXTURE="$tmp/events.jsonl" CAPTURE_FILE="$tmp/webhook.jsonl" CURL_ARGS_FILE="$tmp/webhook.args" STATE_DIRECTORY="$tmp/state-webhook" RUNTIME_DIRECTORY="$tmp/runtime-webhook" NOTIFY_KIND=webhook NOTIFY_URL=https://example.invalid/logwizz NOTIFY_WINDOW_SECS=60 bash "$root/packaging/logwizz-notify"
status=$?
set -e
[[ $status -eq 1 ]] || { echo "expected notifier exit 1 after mock journal EOF, got $status" >&2; exit 1; }
[[ $(wc -l < "$tmp/webhook.jsonl") -eq 1 ]] || { echo "expected exactly one aggregate webhook" >&2; exit 1; }
jq -e '.schema == "logwizz.notification/v1" and .count == 3 and .rule == "ssh_failed_login" and .source == "multiple" and .partial == true and (.line == null)' "$tmp/webhook.jsonl" >/dev/null
if grep -F 'RAW-SECRET-SHOULD-NOT-LEAVE-HOST' "$tmp/webhook.jsonl"; then echo "raw log content leaked into webhook summary" >&2; exit 1; fi
set +e
PATH="$tmp/bin:$PATH" JOURNAL_FIXTURE="$tmp/events.jsonl" CAPTURE_FILE="$tmp/telegram.txt" CURL_ARGS_FILE="$tmp/telegram.args" STATE_DIRECTORY="$tmp/state-telegram" RUNTIME_DIRECTORY="$tmp/runtime-telegram" NOTIFY_KIND=telegram TELEGRAM_BOT_TOKEN=123456:ABC_def-123 TELEGRAM_CHAT_ID=-100123 NOTIFY_WINDOW_SECS=60 bash "$root/packaging/logwizz-notify"
status=$?
set -e
[[ $status -eq 1 ]] || { echo "expected notifier exit 1 after mock journal EOF, got $status" >&2; exit 1; }
[[ $(grep -c "logwizz alert -" "$tmp/telegram.txt") -eq 1 ]] || { echo "expected exactly one Telegram summary" >&2; exit 1; }
grep -F 'Matches: 3' "$tmp/telegram.txt" >/dev/null
grep -F 'Rule: ssh_failed_login' "$tmp/telegram.txt" >/dev/null
if grep -F 'RAW-SECRET-SHOULD-NOT-LEAVE-HOST' "$tmp/telegram.txt"; then echo "raw log content leaked into Telegram summary" >&2; exit 1; fi
if grep -F '123456:ABC_def-123' "$tmp/telegram.args"; then echo "Telegram token leaked into curl arguments" >&2; exit 1; fi

# Failed delivery must retain the aggregate and cursor; a restart retries the
# stored summary instead of recounting already-consumed journal entries.
mkdir -p "$tmp/state-failure" "$tmp/runtime-failure"
set +e
PATH="$tmp/bin:$PATH" JOURNAL_FIXTURE="$tmp/events.jsonl" CAPTURE_FILE="$tmp/failure.jsonl" CURL_ARGS_FILE="$tmp/failure.args" STATE_DIRECTORY="$tmp/state-failure" RUNTIME_DIRECTORY="$tmp/runtime-failure" CURL_FAIL=1 NOTIFY_KIND=webhook NOTIFY_URL=https://example.invalid/logwizz NOTIFY_WINDOW_SECS=60 bash "$root/packaging/logwizz-notify"
status=$?
set -e
[[ $status -eq 1 ]] || { echo "expected failed delivery to leave notifier nonzero" >&2; exit 1; }
[[ -s "$tmp/state-failure/cursor" ]] || { echo "journal cursor was not persisted" >&2; exit 1; }
aggregate=$(find "$tmp/state-failure" -maxdepth 1 -name 'agg-*.json' -print -quit)
[[ -n "$aggregate" ]] || { echo "failed summary was not retained" >&2; exit 1; }
jq -e '.count == 3 and (.retry_after > 0)' "$aggregate" >/dev/null
rm -f "$tmp/retry.jsonl"
set +e
PATH="$tmp/bin:$PATH" JOURNAL_FIXTURE="$tmp/events.jsonl" CAPTURE_FILE="$tmp/retry.jsonl" CURL_ARGS_FILE="$tmp/retry.args" STATE_DIRECTORY="$tmp/state-failure" RUNTIME_DIRECTORY="$tmp/runtime-failure" NOTIFY_KIND=webhook NOTIFY_URL=https://example.invalid/logwizz NOTIFY_WINDOW_SECS=60 bash "$root/packaging/logwizz-notify"
status=$?
set -e
[[ $status -eq 1 ]] || { echo "expected notifier exit 1 after retry stream EOF, got $status" >&2; exit 1; }
[[ $(wc -l < "$tmp/retry.jsonl") -eq 1 ]] || { echo "expected one retried aggregate" >&2; exit 1; }
jq -e '.count == 3 and .rule == "ssh_failed_login"' "$tmp/retry.jsonl" >/dev/null

echo "aggregate notification smoke tests passed"
