# Optional Docker egress guard

**Use case:** an application is compromised (for example by a malicious dependency)
and attempts an outbound connection that the application does not need.
nftables blocks the connection; LogWizz reports the denied attempt. This is
**not** supply-chain compromise attribution or a complete exfiltration defense.

## Setup (Linux Docker Engine, one dedicated bridge)

1. Put only the protected service(s) on a dedicated bridge with a stable name:

   ```yaml
   services:
     app:
       image: your-app:reviewed-tag
       networks: [guarded]
   networks:
     guarded:
       name: logwizz-guarded
       driver: bridge
       driver_opts:
         com.docker.network.bridge.name: br-logwizz
   ```

2. Start the network, then copy the **intentionally non-loadable template**
   to a local deployment file. Replace `<ALLOW_IPV4>` and `<ALLOW_TCP_PORT>`
   with the required **IPv4 destination** and TCP port. The unmodified
   template fails `nft -c` instead of silently using example values.
   Use stable destination addresses; DNS names are not supported.

   ```sh
   cp packaging/docker/logwizz-egress.nft /tmp/logwizz-egress.nft
   ${EDITOR:-vi} /tmp/logwizz-egress.nft
   sudo nft -c -f /tmp/logwizz-egress.nft
   sudo nft -f /tmp/logwizz-egress.nft
   sudo nft list table inet logwizz_egress
   ```

   The separate table uses a `forward` hook before Docker's filter rules.
   `drop` is authoritative; an `accept` here does **not** override another
   firewall chain's drop. All **new** forwarded IPv6 traffic from the selected
   bridge is denied, even if Docker enables IPv6. Already-established
   connections continue. Traffic between containers on the **same** bridge
   is explicitly allowed, including when Linux `br_netfilter` passes bridged
   packets through the inet forward hook. No other Docker network is intentionally affected.

3. To detect denied traffic, merge the `[journal]` and `[[rules]]` blocks from
   `config/docker-egress.toml` into the existing LogWizz config, or use that
   file as a standalone profile. Do **not** monitor the same kernel messages
   through both `kern.log` and the journal.

   The packaged service needs journal-read access. Use the instructions in
   `packaging/logwizz.service` (`SupplementaryGroups=systemd-journal`,
   `ProcSubset=all`) and then validate and reload:

   ```sh
   sudo logwizz --config /etc/logwizz/logwizz.toml --check-config
   sudo systemctl reload logwizz
   sudo journalctl --namespace=logwizz -u logwizz -o cat -f
   ```

   `logwizz-notify` works unchanged. Add `dst,proto,dpt` to its
   `NOTIFY_FIELDS` when those details are needed in alerts. It never needs
   a Docker socket or firewall privileges.

## Test and rollback

On a **disposable VM only**, with Docker, nftables, iproute2, Python 3,
journald and a locally available BusyBox image, run:

```sh
cargo build --locked
sudo LOGWIZZ_BIN="$PWD/target/debug/logwizz" bash tests/host/docker-egress-e2e.sh
```

The isolated test creates a dedicated Docker bridge and a temporary upstream
network namespace. A request to an allowed destination/port succeeds;
another request to the same destination on a blocked port fails and produces
a `docker_egress_denied` event. The test cleans up its own resources.

For a real deployment, remove the policy with:

```sh
sudo nft delete table inet logwizz_egress
```

Remove the optional LogWizz rule separately if no longer needed. This example
does not install persistent firewall configuration across reboots; integrate
the reviewed table into your host's existing firewall management when ready.

## Boundaries

- Only traffic **forwarded from `br-logwizz`** to other interfaces is controlled.
  Same-bridge traffic is exempt (not isolated), including with `br_netfilter`.
  Container-to-host INPUT traffic, host-network containers, host processes,
  and Docker's embedded DNS forwarding are not covered.
- Approved outbound endpoints may still be abused. Encrypted traffic is not
  inspected. Existing connections are not terminated on policy installation.
- Events identify the container's **source IP at the time**, not its durable
  Docker identity; do not automatically ban that IP using the public-IP
  Fail2ban bridge.
- Kernel log output is rate-limited; excess denied packets are still dropped
  but not all attempts necessarily generate an alert.
- Test against your Docker firewall backend and normal application
  connectivity before production use; do not deploy the test on a live host.

Issues: #118, #119.
