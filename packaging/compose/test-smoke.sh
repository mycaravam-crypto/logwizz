#!/bin/sh
# Run only on a disposable Linux Docker Engine or Windows Docker Desktop with Linux containers.
set -eu
COMPOSE_FILE=packaging/compose/compose.test.yml
COMPOSE_PROJECT_NAME=logwizz-portable-test
export COMPOSE_PROJECT_NAME
clean() {
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap clean EXIT INT TERM

docker compose -f "$COMPOSE_FILE" up -d --build --wait
# Both endpoints share one destination. Port 8080 is allowed, 8081 must be denied.
docker compose -f "$COMPOSE_FILE" exec -T app wget -q -T 5 -O /dev/null http://172.31.244.10:8080/
if docker compose -f "$COMPOSE_FILE" exec -T app wget -q -T 3 -O /dev/null http://172.31.244.10:8081/; then
    echo "FAIL: forbidden outbound request succeeded" >&2
    exit 1
fi
# Refusal on an unopened port is not enough: verify nftables deny counter increased.
guard_id=$(docker compose -f "$COMPOSE_FILE" ps -q guard)
docker exec "$guard_id" nft -j list counter inet logwizz_guard denied > /tmp/logwizz-denied-counter.json
python3 - <<'PY'
import json
with open("/tmp/logwizz-denied-counter.json", encoding="utf-8") as f:
    items = json.load(f)["nftables"]
assert any(item.get("counter", {}).get("name") == "denied" and
           item["counter"]["packets"] > 0 for item in items), "no deny counter increments"
PY
ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if docker compose -f "$COMPOSE_FILE" logs --no-color logwizz | grep -q '"rule":"docker_egress_denied_aggregate"'; then
        ok=1
        break
    fi
    sleep 1
done
if [ "$ok" != 1 ]; then
    echo "FAIL: LogWizz did not emit a denied-egress aggregate event" >&2
    docker compose -f "$COMPOSE_FILE" logs guard logwizz
    exit 1
fi
docker compose -f "$COMPOSE_FILE" exec -T app wget -q -T 5 -O /dev/null http://172.31.244.10:8080/
echo "PASS: allowed egress, denied egress, nftables counter, LogWizz event, recovery"
