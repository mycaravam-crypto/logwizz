# Experimental portable Docker egress guard

**Status: preview only; not a production-ready LogWizz installation.** This
addition is independent of the existing Linux host daemon, journald input,
systemd units, Fail2ban bridge, and host-level Docker firewall rules.

## Architecture and boundaries

- The **guard** is a small Python + nftables container, with `NET_ADMIN`
  restricted to its *own* Docker network namespace. It does not run
  `privileged`, use `network_mode: host`, or mount `docker.sock`.
- The **application** uses `network_mode: service:guard`, so its outbound
  packets traverse the guard's network namespace. It has no `NET_ADMIN`.
- The **LogWizz monitor** runs unprivileged in a separate container. It reads
  an append-only text event file from a read-only volume and applies the
  existing LogWizz file/regex engine. Production logwizz binaries/configs
  are **not changed**.
- The guard enforces a **mandatory explicit allowlist of IPv4 + TCP port
  pairs** (`LOGWIZZ_EGRESS_ALLOW`, e.g. `198.18.0.2:8080`).
  All other new non-loopback outbound packets (including IPv6 and UDP)
  are dropped. Established replies and namespace loopback work.
- The guard polls an nftables deny **packet counter**, writing aggregated
  events such as `logwizz-egress-deny: packets=3 total_packets=8` to the
  shared file. An unexpected counter reset emits a separate
  `docker_egress_counter_reset` error event; it does not silently erase
  the observation or terminate monitoring. **No destination address, port, or source container identity
  is available** in these events. Do not present them as packet-level IDS.
- DNS via Docker's embedded loopback resolver (`127.0.0.11`) can be
  permitted by the loopback exception. It represents a possible DNS
  exfiltration channel and is *not* eliminated by this policy.
- This protects only containers that **share the guard network namespace**
  and cannot alter its rules. Do not give the protected application
  `NET_ADMIN`, mount the guard event volume, or attach it to a second network.

The shared-network model requires port publishing to live on the **guard**
container, not the application. Compose requires `depends_on` with
`condition: service_healthy` so the app starts only after `nftables`
installation and the guard's heartbeat have been verified.

## Linux disposable-host smoke test

Use a disposable Docker Engine. Do not run this on a production host.

```sh
python3 -m unittest discover -s packaging/compose/guard -p test_guard.py
bash packaging/compose/test-smoke.sh
```

The test builds two images, starts a test app that shares the guard namespace,
a fixed-IP test endpoint, and the LogWizz monitor. It proves:

1. Port 8080 to the allowed IPv4 endpoint works.
2. Port 8081 to the same endpoint fails **and** the nftables drop counter
   increments (so an unrelated connection refusal cannot count as success).
3. LogWizz emits a `docker_egress_denied_aggregate` event.
4. Allowed access still works after the denial.

All containers, test volumes, and the test network are removed on exit.
The test uses a fixed test-only subnet (`172.31.244.0/24`); Docker will
refuse creation if it conflicts with another network.

## Windows Docker Desktop target

Use **Linux containers** with Docker Desktop. Docker Desktop places them
inside a Linux VM; the guard does not alter Windows Defender Firewall.
Run `bash packaging/compose/test-smoke.sh` inside WSL2 or another Bash
environment with Docker CLI access. Require a real pass of the *deny counter
and LogWizz event*, not merely `docker compose up` succeeding. Docker
Desktop Enhanced Container Isolation may reject `NET_ADMIN`; that is an
unsupported environment until separately validated.

**Windows support remains unverified** until this test runs on an actual
Windows Docker Desktop machine. A passing Linux GitHub Actions job does
not establish Windows compatibility.

## Deployment risks / release gate

- The guard is **not a transparent proxy**. Existing connections established
  before guard installation may survive, and the allowlist does not follow
  DNS changes or runtime-configured ERP source hosts. A separate integration
  step must implement and test an operator-managed deployment policy.
- A guard crash, namespace replacement, or Docker restart changes lifecycle
  conditions. Prove fail-closed behavior across restarts before production
  use; `depends_on` governs startup only, not ongoing enforcement.
- Do not put this preview Compose file into a production application's
  default `docker-compose.yml` until Linux and Windows smoke tests and
  startup/restart/regression scenarios pass.
- Prefer pinned image digests and a documented upgrade/rollback path
  before promoting the preview to a released product.
