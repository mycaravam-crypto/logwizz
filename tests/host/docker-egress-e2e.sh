#!/usr/bin/env bash
# Root-only E2E test on a disposable Linux VM. Never run on a production host.
# Requires Docker, nftables, iproute2, journalctl, Python 3, and local BusyBox.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${LOGWIZZ_BIN:-$ROOT/target/debug/logwizz}"
IMAGE="${IMAGE:-busybox:1.36}"
NET=logwizz-egress-e2e
BR=br-lwtest
NS=lw-egress-ns
UPLINK=lw-up
PEER=lw-peer
TABLE=logwizz_egress_e2e
DEST=198.18.0.2

[[ $EUID -eq 0 ]] || { echo "Run as root on a disposable VM" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "Build LogWizz first: cargo build --locked" >&2; exit 1; }
for cmd in docker nft ip journalctl python3 sed grep; do
    command -v "$cmd" >/dev/null || { echo "Missing: $cmd" >&2; exit 1; }
done
docker image inspect "$IMAGE" >/dev/null || {
    echo "Pull $IMAGE before running this test" >&2
    exit 1
}
[[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || {
    echo "IPv4 forwarding is required (normally enabled by Docker)" >&2
    exit 1
}
# Fail rather than take over or delete any pre-existing network resources.
! docker network inspect "$NET" >/dev/null 2>&1 || { echo "$NET exists" >&2; exit 1; }
! nft list table inet "$TABLE" >/dev/null 2>&1 || { echo "$TABLE exists" >&2; exit 1; }
! ip link show "$UPLINK" >/dev/null 2>&1 || { echo "$UPLINK exists" >&2; exit 1; }
! ip netns list | grep -q "^$NS " || { echo "$NS exists" >&2; exit 1; }

TMP="$(mktemp -d)"
LW_PID=""
HTTP1=""
HTTP2=""
cleanup() {
    set +e
    [[ -z $LW_PID ]] || { kill "$LW_PID" 2>/dev/null; wait "$LW_PID" 2>/dev/null; }
    [[ -z $HTTP1 ]] || { kill "$HTTP1" 2>/dev/null; wait "$HTTP1" 2>/dev/null; }
    [[ -z $HTTP2 ]] || { kill "$HTTP2" 2>/dev/null; wait "$HTTP2" 2>/dev/null; }
    nft delete table inet "$TABLE" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    ip netns del "$NS" >/dev/null 2>&1
    ip link del "$UPLINK" >/dev/null 2>&1
    rm -rf "$TMP"
}
trap cleanup EXIT

docker network create --driver bridge \
    --opt "com.docker.network.bridge.name=$BR" \
    --subnet 172.28.241.0/24 "$NET" >/dev/null
ip netns add "$NS"
ip link add "$UPLINK" type veth peer name "$PEER"
ip link set "$PEER" netns "$NS"
ip addr add 198.18.0.1/30 dev "$UPLINK"
ip link set "$UPLINK" up
ip -n "$NS" addr add "$DEST/30" dev "$PEER"
ip -n "$NS" link set "$PEER" up
ip -n "$NS" link set lo up

echo "test" > "$TMP/index.html"
ip netns exec "$NS" python3 -m http.server 8080 --bind "$DEST" --directory "$TMP" >"$TMP/http-allowed.log" 2>&1 &
HTTP1=$!
ip netns exec "$NS" python3 -m http.server 8081 --bind "$DEST" --directory "$TMP" >"$TMP/http-denied.log" 2>&1 &
HTTP2=$!

sed -e "s/inet logwizz_egress/inet $TABLE/" \
    -e "s/br-logwizz/$BR/g" \
    -e "s/<ALLOW_IPV4>/$DEST/" \
    -e 's/<ALLOW_TCP_PORT>/8080/' \
    "$ROOT/packaging/docker/logwizz-egress.nft" > "$TMP/egress.nft"
nft -c -f "$TMP/egress.nft"
nft -f "$TMP/egress.nft"

# Run a separate, non-persistent detector; never touch production offsets.
sed -e '/^state_file = /d' -e '/^syslog_prefix = /d' \
    "$ROOT/config/docker-egress.toml" > "$TMP/logwizz.toml"
"$BIN" --config "$TMP/logwizz.toml" >"$TMP/events.jsonl" 2>"$TMP/logwizz.err" &
LW_PID=$!
sleep 2
kill -0 "$LW_PID" || { cat "$TMP/logwizz.err" >&2; exit 1; }
START="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# Both endpoints exist. Only the approved port should be reachable.
docker run --rm --pull never --network "$NET" "$IMAGE" \
    wget -q -T 5 -O /dev/null "http://$DEST:8080/"
sleep 0.5
if grep -q '"rule":"docker_egress_denied"' "$TMP/events.jsonl"; then
    echo "FAIL: allowed egress generated a denial" >&2
    exit 1
fi
if docker run --rm --pull never --network "$NET" "$IMAGE" \
    wget -q -T 3 -O /dev/null "http://$DEST:8081/"; then
    echo "FAIL: unapproved egress succeeded" >&2
    exit 1
fi
for ((i=0; i<50; i++)); do
    if grep -q '"rule":"docker_egress_denied"' "$TMP/events.jsonl"; then break; fi
    sleep 0.2
done
grep -q '"rule":"docker_egress_denied"' "$TMP/events.jsonl"
grep -q '"dpt":"8081"' "$TMP/events.jsonl"
journalctl -k --since "$START" -o cat --no-pager > "$TMP/kernel.log"
grep -q 'logwizz-egress-deny:' "$TMP/kernel.log"
echo "PASS: allowed egress works, denied egress is blocked and LogWizz detected it"
