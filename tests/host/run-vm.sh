#!/usr/bin/env bash
# Boots a throwaway Ubuntu 24.04 cloud VM, installs logwizz and the systemd unit
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
image_url=https://cloud-images.ubuntu.com/noble/current
image=noble-server-cloudimg-amd64.img

cd "$work"
if [[ ! -f $image ]]; then
  curl -fsSL -o "$image" "$image_url/$image"
  curl -fsSL "$image_url/SHA256SUMS" | grep " \*\?$image\$" | sha256sum -c -
fi

rm -rf payload && mkdir payload
(cd "$root" && cargo build --release --locked --target x86_64-unknown-linux-musl)
install -m 0755 "$root/target/x86_64-unknown-linux-musl/release/logwizz" payload/logwizz
cp "$root/packaging/logwizz.service" "$root/packaging/logwizz-notify" "$root/packaging/logwizz-notify.service" \
  "$here/hostcheck.sh" "$root/docs/DETECTION.md" payload/
# The host config plus every rule of the shipped detection config, so the check exercises those exact rules.
{ cat "$here/logwizz.toml"; echo; sed -n '/^\[\[rules\]\]/,$p' "$root/config/detection.toml"; } > payload/logwizz.toml

cat > user-data <<'EOF'
#cloud-config
package_update: false
packages: []
runcmd:
  - [sh, -c, 'mkdir -p /mnt/payload && mount -o ro LABEL=PAYLOAD /mnt/payload && bash /mnt/payload/hostcheck.sh > /dev/ttyS1 2>&1; echo HOSTCHECK-DONE > /dev/ttyS1; poweroff']
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
