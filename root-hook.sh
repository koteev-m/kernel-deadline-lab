#!/bin/bash
set -euo pipefail
root=$1
work=${LAB_WORK:-$(dirname "$root")}
abi=6.8.0-48-generic
for deb in "$work"/linux-*.deb; do
  dpkg-deb --fsys-tarfile "$deb" | tar --keep-directory-symlink --no-overwrite-dir -xpf - -C "$root"
done
# depmod and initramfs creation take place inside the builder's temporary chroot.
chroot "$root" depmod "$abi"
mkdir -p "$root/etc/initramfs-tools/conf.d"
echo MODULES=most > "$root/etc/initramfs-tools/conf.d/lab"
printf '%s\n' virtio_pci virtio_blk ext4 >> "$root/etc/initramfs-tools/modules"
cp "$root/boot/vmlinuz-$abi" "$work/kernel"
chroot "$root" mkinitramfs -o /boot/lab-initrd "$abi" || { echo 'mkinitramfs failure'; exit 1; }
mv "$root/boot/lab-initrd" "$work/initrd"
tool=$(find "$root/usr/lib" -type f -name bpftool -print -quit)
test -n "$tool" || { echo 'missing guest tool'; exit 1; }
install -m 0755 "$tool" "$root/usr/local/sbin/bpftool"
chroot "$root" /usr/local/sbin/bpftool version >/dev/null || { echo 'missing guest tool'; exit 1; }
install -d "$root/opt/lab" "$root/etc/systemd/system/multi-user.target.wants"
install -m 0644 "$work/guest.py" "$work/gate.bpf.c" "$root/opt/lab/"
printf '/dev/vda / ext4 defaults 0 0\n' > "$root/etc/fstab"
printf 'labguest\n' > "$root/etc/hostname"
rm -f "$root/etc/resolv.conf"
touch "$root/etc/resolv.conf"
truncate -s 0 "$root/etc/machine-id"
cat > "$root/etc/systemd/system/lab-probe.service" <<'EOF'
[Unit]
Description=Isolated capability probe
After=local-fs.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 -I -B /opt/lab/guest.py
[Install]
WantedBy=multi-user.target
EOF
ln -s ../lab-probe.service "$root/etc/systemd/system/multi-user.target.wants/lab-probe.service"

if [[ -d "$work/campaign" ]]; then
  install -m 0644 "$work/campaign/"*.py "$root/opt/lab/"
  if [[ -f "$work/proxy-bin" ]]; then install -m 0755 "$work/proxy-bin" "$root/opt/lab/xray"; fi
  sed -i 's@/opt/lab/guest.py@/opt/lab/full_guest.py@' "$root/etc/systemd/system/lab-probe.service"
fi
