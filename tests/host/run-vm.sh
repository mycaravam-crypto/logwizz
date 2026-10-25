#!/usr/bin/env bash
# Boots a throwaway Ubuntu/Debian cloud VM, installs logwizz and the systemd unit
# exactly as the README documents, and runs hostcheck.sh inside it. Prints the
# RESULT lines and exits nonzero on any FAIL. See docs/HOST-VERIFICATION.md.
#
# Needs: qemu-system-x86_64, qemu-img, cloud-localds, genisoimage, curl,
# and the x86_64-unknown-linux-musl target. Uses KVM when /dev/kvm exists;
# without it the run takes a few minutes longer (pure emulation).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work=${WORK:-$(mktemp -d)}
image_url=${IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current}
image=${IMAGE:-noble-server-cloudimg-amd64.img}
checksum_file=${CHECKSUM_FILE:-SHA256SUMS}
checksum_tool=${CHECKSUM_TOOL:-sha256sum}

# These values are workflow parameters, but validate them because this script is
# also documented for local use and must not write outside WORK or execute an
# arbitrary checksum command.
[[ "$image" =~ ^[A-Za-z0-9._-]+$ && "$image" != "." && "$image" != ".." ]] || { echo "invalid IMAGE filename" >&2; exit 2; }
[[ "$checksum_file" =~ ^[A-Za-z0-9._-]+$ && "$checksum_file" != "." && "$checksum_file" != ".." ]] || { echo "invalid CHECKSUM_FILE filename" >&2; exit 2; }
case "$checksum_tool" in sha256sum|sha512sum) ;; *) echo "CHECKSUM_TOOL must be sha256sum or sha512sum" >&2; exit 2 ;; esac
command -v "$checksum_tool" >/dev/null || { echo "checksum tool not found: $checksum_tool" >&2; exit 2; }
[[ "$image_url" == https://* ]] || { echo "IMAGE_URL must use HTTPS" >&2; exit 2; }

cd "$work"
if [[ ! -f $image ]]; then
  curl -fsSL -o "$image" "$image_url/$image"
  curl -fsSL "$image_url/$checksum_file" | awk -v f="$image" '$NF == f || $NF == "*" f { print }' | "$checksum_tool" -c -
fi

rm -rf payload && mkdir payload
(cd "$root" && cargo build --release --locked --target x86_64-unknown-linux-musl)
install -m 0755 "$root/target/x86_64-unknown-linux-musl/release/logwizz" payload/logwizz
cp "$root/packaging/logwizz.service" "$root/packaging/logwizz-notify" "$root/packaging/logwizz-notify.service" \
  "$here/hostcheck.sh" "$here/logwizz.nft" "$root/docs/DETECTION.md" payload/
# The host config already watches auth.log and syslog. On Ubuntu 24.04, rsyslog
# copies kernel messages to syslog, so adding detection.toml's kern.log here
# would monitor each firewall line twice. Append the shipped rules only; the
# production detection config uses kern.log on its own to avoid that duplicate.
{ cat "$here/logwizz.toml"; echo; sed -n '/^\[\[rules\]\]/,$p' "$root/config/detection.toml"; } > payload/logwizz.toml

cat > user-data <<'EOF'
#cloud-config
package_update: true
packages:
  - rsyslog
  - jq
  - nftables
  - nmap
  - strace
runcmd:
  - [sh, -c, 'systemctl enable --now rsyslog; sleep 1; logger -p auth.notice "logwizz hostcheck bootstrap"; sleep 1; mkdir -p /mnt/payload && mount -o ro LABEL=PAYLOAD /mnt/payload && bash /mnt/payload/hostcheck.sh > /dev/ttyS1 2>&1; echo HOSTCHECK-DONE > /dev/ttyS1; poweroff']
EOF
printf 'instance-id: lwz-hostcheck\nlocal-hostname: lwz-hostcheck\n' > meta-data
cloud-localds seed.iso user-data meta-data
genisoimage -quiet -V PAYLOAD -r -J -o payload.iso payload
rm -f disk.qcow2 serial.log hostcheck.log
qemu-img create -q -f qcow2 -F qcow2 -b "$image" disk.qcow2 8G

accel=tcg,thread=multi
[[ -w /dev/kvm ]] && accel=kvm
timeout 3000 qemu-system-x86_64 -accel "$accel" -cpu max -smp 4 -m 3072 -nographic -no-reboot \
  -drive file=disk.qcow2,if=virtio \
  -drive file=seed.iso,media=cdrom,readonly=on \
  -drive file=payload.iso,media=cdrom,readonly=on \
  -nic user,model=virtio -serial file:serial.log -serial file:hostcheck.log -monitor none -display none >/dev/null

# The check writes to its own port (ttyS1): ttyS0 carries the kernel console, which interleaves with it, and a
# serial getty, whose hangup on start cuts off writers that already have it open.
grep -a -E '^(RESULT|SUMMARY)' hostcheck.log
echo "full log: $work/hostcheck.log (guest console: $work/serial.log)"
grep -a -q '^HOSTCHECK-DONE' hostcheck.log && ! grep -a -q '^RESULT [^ ]* FAIL' hostcheck.log
