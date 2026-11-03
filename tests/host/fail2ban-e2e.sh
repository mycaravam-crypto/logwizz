#!/bin/bash
# Live Fail2ban + nftables verification in a disposable QEMU guest only.
set -euo pipefail
P=/mnt/payload
BAN=198.51.100.24
IGNORE=198.51.100.25
BROKEN=198.51.100.26
DISABLED=198.51.100.27
LOG=/var/log/logwizz/fail2ban.log
SINK=/root/fail2ban-e2e.jsonl
JAIL_READY_RETRIES=80
BAN_WAIT_RETRIES=120
UNBAN_WAIT_RETRIES=80
BURST_EVENTS=2000
# Both readiness and event collection are polled every 250 ms.
BURST_READY_RETRIES=80     # 20 seconds to observe an event from the monitored file
BURST_WAIT_RETRIES=120     # 30 seconds to collect the complete bounded burst
BURST_POLL_SECS=0.25
BURST_SAMPLE_EVERY=10     # collect resource snapshots about every 2.5 seconds
MAX_RSS_KIB=$((64 * 1024)) # 64 MiB
sink_pid=""
cleanup() {
  systemctl stop logwizz-notify fail2ban logwizz >/dev/null 2>&1 || true
  if [[ -n "$sink_pid" ]]; then kill "$sink_pid" >/dev/null 2>&1 || true; fi
  rm -f /usr/local/share/ca-certificates/lwz-f2b-e2e.crt
  update-ca-certificates >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v nft; command -v fail2ban-client; command -v jq
test -S /run/systemd/journal.logwizz/socket
install -D -m 0644 "$P/logwizz-fail2ban-filter.conf" /etc/fail2ban/filter.d/logwizz.conf
install -D -m 0644 "$P/logwizz-report.py" /etc/fail2ban/action.d/logwizz-report.py
mkdir -p /var/log/logwizz
install -m 0644 /dev/null "$LOG"
cat > /etc/fail2ban/jail.d/zz-logwizz-e2e.local <<'EOF'
[logwizz]
enabled = true
filter = logwizz
backend = polling
logpath = /var/log/logwizz/fail2ban.log
usedns = no
maxretry = 1
findtime = 60
bantime = 600
port = 2222
protocol = tcp
banaction = nftables-multiport
action = %(action_)s
         logwizz-report.py
EOF

# Local HTTPS sink for the real logwizz-notify service.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
  -keyout /root/lwz-f2b-e2e.key \
  -out /usr/local/share/ca-certificates/lwz-f2b-e2e.crt >/dev/null 2>&1
update-ca-certificates >/dev/null 2>&1
: > "$SINK"
python3 - "$SINK" <<'PY' &
import http.server
import ssl
import sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        with open(sys.argv[1], "ab") as output:
            output.write(body + b"\n")
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *_):
        pass

server = http.server.HTTPServer(("127.0.0.1", 8109), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    "/usr/local/share/ca-certificates/lwz-f2b-e2e.crt",
    "/root/lwz-f2b-e2e.key",
)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
sink_pid=$!
printf 'NOTIFY_URL=https://127.0.0.1:8109/\nNOTIFY_KIND=webhook\nNOTIFY_WINDOW_SECS=10\n' > /etc/logwizz/notify.env
chmod 0600 /etc/logwizz/notify.env
systemctl start logwizz-notify
fail2ban-client -t
# Cloud-init may have started Fail2ban before this jail file was installed.
# Always restart to load the dedicated test jail, then wait for the socket.
systemctl restart fail2ban
ready=0
for ((i=0;i<JAIL_READY_RETRIES;i++)); do
  if fail2ban-client ping >/dev/null 2>&1 &&
     fail2ban-client status logwizz >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.25
done
if (( ready == 0 )); then
  echo "Fail2ban test jail not ready"
  systemctl status fail2ban --no-pager || true
  journalctl -u fail2ban -n 45 --no-pager || true
  exit 1
fi
fail2ban-client status logwizz

write_match() {
  printf '%s logwizz rule=ssh_bruteforce src=%s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG"
}
status_has() {
  fail2ban-client status logwizz 2>/dev/null |
    grep -F 'Banned IP list:' | grep -Fq "$1"
}
nft_has() {
  nft get element inet f2b-table addr-set-logwizz '{' "$1" '}' >/dev/null 2>&1
}
report_count() {
  journalctl --namespace=logwizz SYSLOG_IDENTIFIER=logwizz-ban _UID=0 \
    -o cat --no-pager 2>/dev/null | grep -Fc "LOGWIZZ_BAN_V2 jail=logwizz ip=$1" || true
}
webhook_has() {
  jq -se --arg ip "$1" \
    'any(.[]; .schema == "logwizz.action/v1" and .status == "firewall_rule_verified" and .ip == $ip and .verification == "nftables-set-and-input-drop-rule")' \
    "$SINK" >/dev/null 2>&1
}

# No bridge process and no ban before injecting a single test event.
! systemctl is-active --quiet logwizz-fail2ban-bridge
! status_has "$BAN"
write_match "$BAN"
seen=0
for ((i=0;i<BAN_WAIT_RETRIES;i++)); do
  if status_has "$BAN" && nft_has "$BAN" &&
    (( $(report_count "$BAN") == 1 )) && webhook_has "$BAN"; then seen=1; break; fi
  sleep 0.25
done
if (( seen == 0 )); then
  echo "F2B status: $(fail2ban-client status logwizz)"
  echo "F2B log: $(journalctl -u fail2ban -n 35 --no-pager)"
  echo "nft: $(nft list table inet f2b-table 2>&1)"
  echo "nft get json: $(nft -j get element inet f2b-table addr-set-logwizz '{' "$BAN" '}' 2>&1)"
  echo "nft chain json: $(nft -j list chain inet f2b-table f2b-chain 2>&1)"
  echo "Fail2ban actions: $(fail2ban-client get logwizz actions 2>&1)"
  echo "Fail2ban file log: $(tail -n 100 /var/log/fail2ban.log 2>&1)"
  echo "report: $(journalctl --namespace=logwizz SYSLOG_IDENTIFIER=logwizz-ban -o cat --no-pager)"
  echo "sink: $(cat "$SINK")"
  exit 1
fi
echo 'PASS real ban, nftables rule and HTTPS notification'

# Duplicate events cannot produce a second ban callback.
write_match "$BAN"
sleep 3
(( $(report_count "$BAN") == 1 ))
fail2ban-client set logwizz unbanip "$BAN" >/dev/null
for ((i=0;i<UNBAN_WAIT_RETRIES;i++)); do
  if ! status_has "$BAN" && ! nft_has "$BAN"; then break; fi
  sleep 0.2
done
! status_has "$BAN"
! nft_has "$BAN"
echo 'PASS de-duplication and actual unban'

# Ignored sources and malformed lines cannot trigger a ban.
fail2ban-client set logwizz addignoreip "$IGNORE" >/dev/null
write_match "$IGNORE"
write_match 'not-an-ip'
sleep 4
! status_has "$IGNORE"
(( $(report_count "$IGNORE") == 0 ))
echo 'PASS ignoreip and invalid source'

# Fail2ban still executes a later report action when the firewall action
# returns failure. No nft entry => the reporter must fail closed.
cat > /etc/fail2ban/action.d/lwz-e2e-failing.conf <<'EOF'
[Definition]
actionban = /usr/bin/false
EOF
sed -i 's/^action = %(action_)s$/action = lwz-e2e-failing/' \
  /etc/fail2ban/jail.d/zz-logwizz-e2e.local
systemctl restart fail2ban
ready=0
for ((i=0;i<JAIL_READY_RETRIES;i++)); do
  if fail2ban-client status logwizz >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.25
done
(( ready == 1 ))
write_match "$BROKEN"
sleep 5
(( $(report_count "$BROKEN") == 0 ))
! nft_has "$BROKEN"
echo 'PASS failing firewall action is not verified'

fail2ban-client stop logwizz >/dev/null
write_match "$DISABLED"
sleep 3
(( $(report_count "$DISABLED") == 0 ))
echo 'PASS disabled jail generates no new report'

# Record bounded memory evidence under a burst without claiming a CPU SLO.
systemctl start logwizz
pid=$(systemctl show -p MainPID --value logwizz)

# Type=exec only confirms that execve succeeded, not that the tail-mode reader
# has opened /var/log/lwtest.log. A burst written before its first poll is
# deliberately skipped by startup_mode=tail. Observe an event through the same
# file reader and journal output before injecting the measured workload.
ready_marker="LWZ-T-READY-$$"
burst_ready=0
for ((i=0;i<BURST_READY_RETRIES;i++)); do
  printf '%s\n' "$ready_marker" >> /var/log/lwtest.log
  if journalctl --namespace=logwizz -u logwizz -o cat --no-pager |
      grep -F "$ready_marker" >/dev/null; then
    burst_ready=1
    break
  fi
  sleep "$BURST_POLL_SECS"
done
if (( burst_ready == 0 )); then
  echo "FAIL logwizz reader did not emit its readiness probe"
  journalctl --namespace=logwizz -u logwizz -n 25 --no-pager || true
  exit 1
fi

# The bundled host rule matches LWZ-T; verify that every line emerges as
# exactly one detection rather than measuring an unrelated, ignored burst.
for ((i=0;i<BURST_EVENTS;i++)); do
  printf 'LWZ-T-RESOURCE event %04d\n' "$i"
done >> /var/log/lwtest.log

observed=0
peak_rss_kib=0
for ((i=0;i<BURST_WAIT_RETRIES;i++)); do
  observed=$(journalctl --namespace=logwizz -u logwizz -o cat --no-pager |
    grep -Fc 'LWZ-T-RESOURCE event' || true)

  # Sample while the burst is being processed, not only once after it ends.
  if ! sample=$(ps -o rss=,%cpu= -p "$pid" 2>/dev/null); then
    echo "FAIL logwizz exited while processing the burst"
    exit 1
  fi
  read -r rss cpu <<< "$sample"
  if [[ ! "$rss" =~ ^[0-9]+$ ]] || (( rss == 0 || rss >= MAX_RSS_KIB )); then
    echo "FAIL memory limit: rss_kib=$rss limit=$MAX_RSS_KIB"
    exit 1
  fi
  if (( rss > peak_rss_kib )); then peak_rss_kib=$rss; fi
  if (( i % BURST_SAMPLE_EVERY == 0 )); then
    echo "SAMPLE resource rss_kib=$rss cpu_percent=$cpu emitted=$observed"
  fi

  if (( observed >= BURST_EVENTS )); then break; fi
  sleep "$BURST_POLL_SECS"
done
if (( observed != BURST_EVENTS )); then
  echo "FAIL burst event mismatch: emitted=$observed expected=$BURST_EVENTS"
  exit 1
fi
echo "PASS resource samples peak_rss_kib=$peak_rss_kib last_cpu_percent=$cpu emitted=$observed injected=$BURST_EVENTS"
