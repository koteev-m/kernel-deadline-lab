#!/bin/bash
set -euo pipefail
umask 022
work=$1
mkdir -m 0755 "$work"
echo "HOST checking KVM"
python3 - <<'PY'
import fcntl, os
with open('/dev/kvm', 'r+b', buffering=0) as kvm:
    if fcntl.ioctl(kvm, 0xae00, 0) != 12:
        raise RuntimeError('KVM API mismatch')
    os.close(fcntl.ioctl(kvm, 0xae01, 0))
print('HOST KVM_CREATE_VM succeeded')
PY
cat > "$work/runner.list" <<'EOF'
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu noble main universe
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu noble-updates main universe
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://security.ubuntu.com/ubuntu noble-security main universe
EOF
apt_args=(-o "Dir::Etc::sourcelist=$work/runner.list" -o Dir::Etc::sourceparts=- -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false)
export DEBIAN_FRONTEND=noninteractive
apt-get "${apt_args[@]}" -qq update > "$work/host-apt.log"
apt-get "${apt_args[@]}" -qy --no-install-recommends install mmdebstrap qemu-system-x86 seabios ubuntu-keyring e2fsprogs > "$work/host-install.log"
python3 -I -B packages.py "$work"

echo "BUILD constructing Noble userland"
install -m 0644 gate.bpf.c guest.py "$work/"
install -m 0755 root-hook.sh "$work/"
extra=""
if [[ ${2:-} == full ]]; then
  extra=",tcpdump,openssl"
  install -d "$work/campaign"
  install -m 0644 campaign/*.py "$work/campaign/"
  python3 -I -B campaign/fetch_proxy.py "$work"
fi
export LAB_WORK="$work"
# A fixed base release supplies a coherent set of userspace libraries.
# Only the older kernel and its ABI tools come from the signed snapshot.
mmdebstrap --mode=root --variant=minbase --architectures=amd64 \
  --keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg \
  --setup-hook='mkdir -p "$1/etc/ssl/certs" && cp /etc/ssl/certs/ca-certificates.crt "$1/etc/ssl/certs/ca-certificates.crt"' \
  --include=ubuntu-keyring,ca-certificates,linux-libc-dev,libc6-dev,busybox-initramfs,zstd,systemd-sysv,udev,initramfs-tools,kmod,iproute2,nftables,python3,clang-18,llvm-18,libdw1t64,libnuma1,libpci3,libpython3.12t64,libslang2,libssl3t64,libtraceevent1,libunwind8,libbpf1,libcap2,libelf1t64,libzstd1"$extra" \
  --customize-hook="$work/root-hook.sh" noble "$work/root" \
  "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu noble main universe" > "$work/bootstrap.log" 2>&1 || {
    # Only expose known diagnostic categories. Never emit chroot or runner logs.
    for key in NO_PUBKEY 'Unable to locate package' 'unmet dependencies' 'hash sum mismatch' 'No space left' 'Failed to fetch' 'mkinitramfs failure' 'missing guest tool'; do
      if grep -Fqi "$key" "$work/bootstrap.log"; then echo "BUILD diagnostic: $key"; fi
    done
    grep -Eo "Unable to locate package [a-z0-9.+-]+|Package '[a-z0-9.+-]+' has no installation candidate|Package [a-z0-9.+-]+ is not available|Depends: [a-z0-9.+-]+|E: mmdebstrap failed|error while loading shared libraries: [a-zA-Z0-9.+_-]+|merged-/usr|Certificate verification failed" "$work/bootstrap.log" | sort -u | head -30 || true
    echo 'BUILD Noble bootstrap failed' ; exit 1
  }
test -s "$work/kernel"
test -s "$work/initrd"
truncate -s 4G "$work/guest.ext4"
mkfs.ext4 -q -F -m 0 -d "$work/root" "$work/guest.ext4"
echo "BUILD offline disk ready"
