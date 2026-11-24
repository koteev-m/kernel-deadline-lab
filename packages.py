"""Fetch the exact kernel ABI using the Ubuntu archive's signed SHA256 chain."""
import hashlib
import lzma
from pathlib import Path
import subprocess as sp
import sys

MIRROR = "https://snapshot.ubuntu.com/ubuntu/20241110T000000Z/"
SUITE = "dists/noble-security/"
INDEX = "main/binary-amd64/Packages.xz"
VERSION = "6.8.0-48.48"
ABI = "6.8.0-48"
PINS = {
    "linux-image-" + ABI + "-generic": "689036cb2ad6736577bc2bacf3fdaa9f95f17ce198828d925dcb54a5ecdd0b68",
    "linux-modules-" + ABI + "-generic": "0acd51172aebfb5a54ff01b11414f9fddf4c591919636106f20e6a5e6bbbf55e",
    "linux-modules-extra-" + ABI + "-generic": "b1eb6d1ce4ed91a0222825d55190d0120e17275d110e7a19eedaf3106b3b36cf",
    "linux-tools-" + ABI: "f1d6b2c48c32c8495d8d5d2d2ee1b53dcb23c5754e70622e290a6d3d81cd7178",
}


def fetch(relative, path):
    sp.run(["curl", "--proto", "=https", "--proto-redir", "=https", "-fsSL",
            "--connect-timeout", "15", "--max-time", "150", "-o", path, MIRROR + relative], check=True)


def verify(path, size, expected):
    if path.stat().st_size != int(size) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError("archive verification failed")


def main(work):
    fetch(SUITE + "InRelease", work/"InRelease")
    sp.run(["gpgv", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
            "--output", work/"Release", work/"InRelease"], check=True)
    release = (work/"Release").read_text()
    if "Origin: Ubuntu" not in release.splitlines() or "Suite: noble-security" not in release.splitlines():
        raise ValueError("signed distribution identity")
    rows = release.split("\nSHA256:\n", 1)[1].splitlines()
    entries = []
    for row in rows:
        if not row.startswith(" "):
            break
        digest, size, name = row.split()
        if name == INDEX:
            entries.append((digest, size))
    [(digest, size)] = entries
    index = work/"Packages.xz"
    fetch(SUITE + INDEX, index)
    verify(index, size, digest)
    found = set()
    for stanza in lzma.decompress(index.read_bytes()).decode().split("\n\n"):
        data = dict(line.split(": ", 1) for line in stanza.splitlines()
                    if not line.startswith(" ") and ": " in line)
        name = data.get("Package")
        if name not in PINS or data.get("Version") != VERSION:
            continue
        if name in found or data["Architecture"] != "amd64" or data["SHA256"] != PINS[name]:
            raise ValueError("kernel package identity")
        relative = data["Filename"]
        if not relative.startswith("pool/main/l/") or ".." in relative.split("/"):
            raise ValueError("package path")
        path = work/(name + ".deb")
        fetch(relative, path)
        verify(path, data["Size"], PINS[name])
        attrs = [sp.check_output(["dpkg-deb","-f",path,k],text=True).strip()
                 for k in ("Package","Version","Architecture")]
        if attrs != [name, VERSION, "amd64"]:
            raise ValueError("deb control record")
        found.add(name)
    if found != set(PINS):
        raise ValueError("incomplete authenticated kernel package set")
    print("SOURCE Ubuntu signed release, index and four pinned amd64 packages verified", flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
