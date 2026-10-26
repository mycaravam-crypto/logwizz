# Notification operations

logwizz detects locally. The separate `logwizz-notify` service reads structured events from the `logwizz` journal namespace, aggregates them and sends summaries. The core daemon itself has no network access.

`logwizz-notify` is a small static binary, released next to `logwizz`. It parses each event once in-process and starts `curl` only to deliver a summary, never per event, so a burst of detections does not slow it down (it consumes tens of thousands of events per second).

## Telegram setup

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy its token.
2. Determine the destination chat ID. Add the bot to the target chat or group and ensure it is allowed to post there.
3. Install the notifier and curl, which it uses for HTTPS:

   ```bash
   sudo apt install curl
   v=X.Y.Z   # the same release as logwizz
   base=https://github.com/mycaravam-crypto/logwizz/releases/download/v$v
   curl -fL -O "$base/logwizz-notify-v$v-linux-x64" -O "$base/logwizz-notify.service" \
     -O "$base/notify.env.example" -O "$base/SHA256SUMS.txt"
   sha256sum --ignore-missing -c SHA256SUMS.txt
   sudo install -m 0755 "logwizz-notify-v$v-linux-x64" /usr/bin/logwizz-notify
   sudo install -m 0644 logwizz-notify.service /etc/systemd/system/
   sudo install -m 0600 notify.env.example /etc/logwizz/notify.env
   sudoedit /etc/logwizz/notify.env
   ```

   From source, `cargo build --release --locked` builds both binaries; install `target/release/logwizz-notify` and the files from `packaging/`.

4. Set the following in `/etc/logwizz/notify.env`:

   ```bash
   NOTIFY_KIND=telegram
   TELEGRAM_BOT_TOKEN=123456:replace_with_real_token
   TELEGRAM_CHAT_ID=-1001234567890
   NOTIFY_WINDOW_SECS=60
   NOTIFY_MIN_PRIORITY=warning
   NOTIFY_MAX_PENDING=4096
   ```

5. Make sure logwizz emits JSON events to the journal with `syslog_prefix = true`, then start the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now logwizz-notify
   sudo systemctl status logwizz-notify
   journalctl -u logwizz-notify -f
   ```

Keep `notify.env` owned by root and mode `0600`. The bot token, endpoint URLs and the optional Authorization header are passed to curl on its standard input (`curl --config -`): they never appear in process arguments, diagnostics or files. curl is limited to HTTPS, including redirects, and TLS verification stays enabled.

| Variable | Default | Meaning |
|---|---|---|
| `NOTIFY_KIND` | `telegram` | `telegram`, `ntfy` or `webhook`. |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | required for Telegram | Bot token (`<digits>:<secret>`) and destination chat. |
| `NOTIFY_URL` | required for ntfy and webhook | HTTPS endpoint. |
| `NOTIFY_AUTH` | unset | Value of an `Authorization` header, such as `Bearer token`. |
| `NOTIFY_WINDOW_SECS` | `60` | Aggregation window, 10–3600 seconds. |
| `NOTIFY_MIN_PRIORITY` | `warning` | Lowest severity forwarded: `debug`, `info`, `notice`, `warning`, `error` (or `err`), `critical` (or `crit`). |
| `NOTIFY_MAX_PENDING` | `4096` | Maximum pending rule/window summaries, 1–65536. |
| `NOTIFY_FIELDS` | `login` | Captures that may be sent, comma-separated (up to 16 names of `a-z`, `0-9`, `_`). See [Sources and fields](#sources-and-fields). |

Invalid settings stop the notifier with exit code 2 and a message that names the variable but never its value.

## Telegram message format

Telegram messages use HTML formatting: the rule's description as a headline
with a severity marker (🔴 critical, 🟠 error, 🟡 warning, 🔵 notice), the rule,
severity and host, the count with its sources (tap a source to copy it) and the
window in UTC:

```text
🟡 SSH connection without a valid client banner
ssh_probe · warning · web1

3× from 203.0.113.8
🕐 2026-10-25 13:40–13:41 UTC
```

With several sources, the five most frequent are listed one per line with
their counts. ntfy receives the plain-text form shown under
[Other transports](#other-transports).

## Summary behavior

- Events are grouped by **rule and fixed event-time window**: a window starts at a multiple of `NOTIFY_WINDOW_SECS` since the epoch, in the event's own `ts`.
- Each summary contains the host, rule ID, description, severity, count, window start/end and the sources seen.
- The source of an event is a network group of a threshold rule (`group_prefix`, for example `194.180.49.0/24`), else its `src` (or `source`) capture, or else the group of a threshold rule, extended by the fields in `NOTIFY_FIELDS` (see [Sources and fields](#sources-and-fields)). If every event in a summary has the same source, that source is shown. Otherwise the summary says `multiple` and lists the five most frequent sources with their counts, for example `Sources: 203.0.113.8 (30), 198.51.100.4 (7) and 3 more`.
- Up to 32 distinct sources are tracked per summary. Beyond that, the least frequent one is replaced, so a source responsible for a large share of the matches is still listed even among thousands of one-off sources; the counts are then approximate and the message says so.
- Raw log lines, excerpts and captures other than the source and the fields in `NOTIFY_FIELDS` are never included in outbound summaries.

## Sources and fields

`NOTIFY_FIELDS` lists the captures that may leave the host; all others stay
local. A listed `login` is shown as `login@src`; the values of the other
listed fields follow the source, joined by ` · `. An event without an address
shows the field values alone. With `NOTIFY_FIELDS=login,key,tool,cmd,change`
and `config/detection.toml`:

| Rule | Source |
|---|---|
| `ssh_login` | `deploy@203.0.113.8 · ED25519 SHA256:4Qs8…` |
| `scanner_user_agent` | `203.0.113.8 · sqlmap` |
| `account_change` | `usermod · add 'deploy' to group 'sudo'` |

List only captures that cannot hold secrets: values from a fixed list
(`tool`), fixed formats (`key`) or messages that never contain passwords
(`change`). Never list a capture of failed-login usernames: people type
passwords into the username prompt.
- A window is sent once it is over: when a later window has started, or when its end has passed by the clock and the journal has gone quiet. While a backlog is read (after a restart, for example) a window is not sent until the backlog has moved past it, so it is not split into several summaries.
- On `systemctl stop` or `restart`, pending windows are sent before exit, open ones as partial summaries. Sending at shutdown stops after 30 seconds; what is left stays on disk for the next start.
- `NOTIFY_MAX_PENDING` caps pending rule/window summaries. When the cap is reached, the notifier pauses reading the journal without advancing its cursor, keeps delivering, and resumes once summaries have been sent. Entries wait in the journal meanwhile; nothing is lost.

## Other transports

The same aggregate summary is supported by:

- `NOTIFY_KIND=ntfy` with `NOTIFY_URL=https://ntfy.sh/your-topic`. The text message goes in the body, with `Title: logwizz <host>: <rule>`, a `Priority` from the severity (critical 5, error and warning 4, notice 3, info 2) and the severity as `Tags`.
- `NOTIFY_KIND=webhook` with `NOTIFY_URL=https://your-endpoint.example/path`. The body is the JSON below.

For these transports, `NOTIFY_AUTH` can contain an Authorization header value, such as `Bearer token`.

## Delivery and failure semantics

- The journal cursor and the pending summaries are saved together in one state file, `/var/lib/logwizz-notify/state.json` (under the service's `StateDirectory`, written atomically, mode `0600`), at most once a second and after every delivery. After a crash, reading resumes after the saved cursor, into the saved summaries: no event is counted twice or skipped.
- Delivery uses bounded curl timeouts and retries (10 seconds per attempt, 3 retries), then an exponential backoff between attempts (2 seconds up to 300 seconds). A failed summary stays pending for a later attempt; it does not block log detection in the core daemon.
- Delivery is **at least once**, not exactly once. A crash after a remote endpoint accepts a summary but before the state file is saved can produce a duplicate. Consumers should tolerate duplicate summaries.
- On normal window rollover, one summary is sent per rule/window. Shutdown or delayed delivery can produce a partial summary, marked with `partial: true` in webhook JSON and labelled in text transports.
- If journalctl exits, the notifier sends the windows that are over, saves its state and exits with status 1; systemd restarts it after 10 seconds. Open windows are kept and continue after the restart, so this produces no partial summaries.
- An event whose `ts` is missing or invalid is counted at the time the journal received it, with a warning. Messages in the namespace that are not logwizz events only advance the cursor.
- The notifier logs delivery errors (curl's first error line, without the URL) but never raw event content or credentials.
- The state file of the earlier shell notifier (`cursor` and `agg-*.json`) is imported on the first start and removed after the first save.

Webhook JSON uses schema `logwizz.notification/v1`, for example:

```json
{
  "schema": "logwizz.notification/v1",
  "host": "web1",
  "rule": "ssh_failed_login",
  "description": "Failed SSH authentication",
  "severity": "warning",
  "count": 37,
  "window_start": "2026-10-25T12:40:00Z",
  "window_end": "2026-10-25T12:41:00Z",
  "source": "multiple",
  "sources": [
    {"source": "203.0.113.8", "count": 30},
    {"source": "198.51.100.4", "count": 7}
  ],
  "distinct_sources": 2,
  "sources_approximate": false,
  "partial": false
}
```

`source` is the single source, `multiple`, or empty when no event had one. `sources` lists at most five sources, most frequent first; `distinct_sources` counts the tracked ones, and `sources_approximate` is `true` when more were seen than could be tracked. These three fields were added to v1 without changing the existing ones.

## Troubleshooting

- `systemctl status logwizz-notify`: process and restart status.
- `journalctl -u logwizz-notify -f`: configuration and delivery errors.
- `journalctl --namespace=logwizz -u logwizz -p warning`: check whether logwizz is producing events at the selected severity.
- `sudo jq '.summaries[] | {rule, window_start: .bucket, count, retry_count}' /var/lib/private/logwizz-notify/state.json`: pending summaries and their failed attempts (the service uses `DynamicUser`, so its state is under `/var/lib/private`).
- Verify the bot token, chat ID, bot membership/permissions, network egress and system clock.
- If you change the environment file, restart the service: `sudo systemctl restart logwizz-notify`.
