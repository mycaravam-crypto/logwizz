# Notification operations

logwizz detects locally. The separate `logwizz-notify` service reads structured events from the `logwizz` journal namespace, aggregates them and sends summaries. The Rust daemon itself has no network access.

## Telegram setup

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy its token.
2. Determine the destination chat ID. Add the bot to the target chat or group and ensure it is allowed to post there.
3. Install the notifier and its dependencies:

   ```bash
   sudo apt install curl jq
   sudo install -m 0755 packaging/logwizz-notify /usr/bin/logwizz-notify
   sudo install -m 0644 packaging/logwizz-notify.service /etc/systemd/system/
   sudo install -m 0600 packaging/notify.env.example /etc/logwizz/notify.env
   sudoedit /etc/logwizz/notify.env
   ```

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

Keep `notify.env` owned by root and mode `0600`. The service writes the Telegram API URL, including the bot token, to a mode-`0600` file inside its private runtime directory. Webhook/ntfy endpoint URLs and optional auth headers are also stored in private runtime files rather than passed as curl arguments. TLS verification remains enabled.

## Summary behavior

- Events are grouped by **rule and fixed event-time window**. `NOTIFY_WINDOW_SECS` defaults to 60 seconds and accepts 10–3600.
- Each summary contains the host, rule ID, description, severity, count, window start/end and optional source metadata.
- If every event in a summary has the same source, that source is included. If the source differs, the summary says `multiple`.
- Raw log lines, excerpts and captured log content are never included in outbound summaries.
- A window is sent after it closes. If the journal stream exits or the service shuts down first, pending windows are flushed as partial summaries where possible.
- `NOTIFY_MAX_PENDING` caps pending rule/window summaries (default 4096). If the cap is reached, the notifier stops consuming before advancing the cursor for the new event; the service restarts it after pending summaries are flushed or delivery recovers.

## Other transports

The same aggregate summary is supported by:

- `NOTIFY_KIND=ntfy` with `NOTIFY_URL=https://ntfy.sh/your-topic`
- `NOTIFY_KIND=webhook` with `NOTIFY_URL=https://your-endpoint.example/path`

For these transports, `NOTIFY_AUTH` can contain an Authorization header value, such as `Bearer token`. It is written to a private file rather than included in curl arguments. Endpoint URLs are also kept in a private curl config file rather than the process argument list. Use HTTPS endpoints.

## Delivery and failure semantics

- The journal cursor is saved only after an event has been persisted into its aggregate. Aggregate state is stored under the service's `StateDirectory`, separate from the core daemon.
- Delivery uses bounded curl timeouts, retries and an on-disk exponential backoff (2 seconds up to 300 seconds). A failed send leaves the summary on disk for a later attempt; it does not block log detection in the core daemon.
- Delivery is **at least once**, not exactly once. A process crash after a remote endpoint accepts a summary but before the local aggregate is removed can produce a duplicate. Consumers should tolerate duplicate summaries.
- On normal window rollover, one summary is sent per rule/window. Shutdown or delayed delivery can produce a partial summary, marked with `partial: true` in webhook JSON and labelled in text transports.
- The notifier logs delivery errors but does not log raw event content or credentials.

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
  "source": "203.0.113.8",
  "partial": false
}
```

## Troubleshooting

- `systemctl status logwizz-notify`: process and restart status.
- `journalctl -u logwizz-notify -f`: configuration and delivery errors.
- `journalctl --namespace=logwizz -u logwizz -p warning`: check whether logwizz is producing events at the selected severity.
- Verify the bot token, chat ID, bot membership/permissions, network egress and system clock.
- If you change the environment file, restart the service: `sudo systemctl restart logwizz-notify`.
