"""Serial-only probe. Only fixed field names and version strings reach CI."""
from contextlib import contextmanager, ExitStack
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import socket
import subprocess as sp
import time
import traceback
import tty

BASE = Path("/opt/lab")
WORK = Path("/run/deadline-probe")
STATE = Path("/var/lib/deadline-preflight")
ABI = "6.8.0-48-generic"
NET = Path("/proc/self/ns/net")
SECOND = 1_000_000_000
PORT = 18080
STAGE = "startup"


def at():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def check(condition):
    if not condition:
        raise ValueError("precondition")


def run(*args, data=None):
    return sp.run(list(map(str, args)), input=data, stdout=sp.PIPE, stderr=sp.PIPE,
                  text=True, check=True, timeout=25).stdout


def send(event, **fields):
    channel.write((json.dumps(dict(event=event, **fields)) + "\n").encode())


def command():
    if not select.select([channel], [], [], 120)[0]:
        raise TimeoutError
    return channel.readline(160).decode().strip()


def stage(label):
    global STAGE
    STAGE = label
    send("stage", name=label)


def outcome(number, passed, **metrics):
    send("result", number=number, passed=bool(passed), **metrics)


def inside(name, *args):
    return run("ip", "netns", "exec", name, *args)


@contextmanager
def namespace(name):
    run("ip", "netns", "add", name)
    try:
        yield name
    finally:
        run("ip", "netns", "delete", name)


def nft_proof():
    stage("nft")
    def rules(ns=None):
        args = ["nft", "-j", "-s", "list", "ruleset"]
        return json.loads(inside(ns, *args) if ns else run(*args))["nftables"]
    before = rules()
    with namespace("probe-nft") as ns:
        initial = rules(ns)
        check(all(set(r) == {"metainfo"} for r in initial))
        run("ip", "netns", "exec", ns, "nft", "-f", "-", data=(
            "add table inet proof\nadd chain inet proof check_packets\n"
            "add rule inet proof check_packets counter\n"))
        got = [r for r in rules(ns) if "metainfo" not in r]
        check([list(r) for r in got] == [["table"], ["chain"], ["rule"]])
        check(got[0]["table"]["name"] == "proof" and got[1]["chain"]["name"] == "check_packets"
              and got[2]["rule"]["chain"] == "check_packets" and got[2]["rule"]["table"] == "proof")
        inside(ns, "nft", "delete", "table", "inet", "proof")
        check(rules(ns) == initial)
    check(rules() == before)
    outcome(7, True)


def compile_gate(name, cutoff):
    obj = WORK / (name + ".o")
    code = WORK / (name + ".insns")
    run("clang-18", "-DCHECK_LINUX_UAPI", "-fsyntax-only", BASE/"gate.bpf.c")
    run("clang-18", "-O2", "-target", "bpfel", f"-DDEADLINE_NS={cutoff}ULL",
        "-c", BASE/"gate.bpf.c", "-o", obj)
    run("llvm-objcopy-18", "--dump-section", f"classifier={code}", obj)
    return obj, hashlib.sha1(code.read_bytes()).hexdigest()[:16]


def attach(ns, dev, pref, obj):
    inside(ns, "tc", "filter", "add", "dev", dev, "egress", "protocol", "all",
           "pref", str(pref), "bpf", "obj", obj, "sec", "classifier", "direct-action", "skip_hw")


def read_filters(ns, dev, tags):
    rows = json.loads(inside(ns, "tc", "-j", "-s", "filter", "show", "dev", dev, "egress"))
    leaves = [r for r in rows if "options" in r]
    check(sorted(r["pref"] for r in leaves) == sorted([5, *tags]))
    count = None
    for r in leaves:
        check(r["protocol"] == "all" and r.get("chain", 0) == 0)
        opt = r["options"]
        check(opt["skip_hw"] and not opt.get("in_hw"))
        if r["pref"] == 5:
            [action] = opt["actions"]
            check(r["kind"] == "matchall" and action["kind"] == "gact"
                  and action["control_action"]["type"] == "continue")
            count = action["stats"]["packets"]
        else:
            prog = opt["prog"]
            check(r["kind"] == "bpf" and opt["direct-action"] and prog["tag"] == tags[r["pref"]])
            info = json.loads(inside(ns, "bpftool", "-j", "prog", "show", "id", str(prog["id"])))
            if isinstance(info, list):
                [info] = info
            check(info["type"] == "sched_cls" and not info.get("map_ids") and info["tag"] == prog["tag"])
    check(isinstance(count, int))
    return count


def udp(ns, ip):
    old = os.open(NET, os.O_RDONLY)
    target = os.open("/run/netns/" + ns, os.O_RDONLY)
    try:
        os.setns(target, os.CLONE_NEWNET)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip, PORT))
        return s
    finally:
        os.setns(old, os.CLONE_NEWNET)
        os.close(target)
        os.close(old)


def traffic_proof():
    ends = [("probe-a", "va", "192.0.2.1", "02:00:00:00:00:01"),
            ("probe-b", "vb", "192.0.2.2", "02:00:00:00:00:02")]
    stage("interfaces")
    with ExitStack() as stack:
        for ns, *_ in ends:
            stack.enter_context(namespace(ns))
        inside("probe-a", "ip", "link", "add", "va", "type", "veth", "peer", "name", "vb")
        inside("probe-a", "ip", "link", "set", "vb", "netns", "probe-b")
        deny, deny_tag = compile_gate("deny", 0)
        stage("fallback")
        for ns, dev, ip, mac in ends:
            inside(ns, "ip", "link", "set", dev, "address", mac)
            inside(ns, "ip", "addr", "add", ip + "/30", "dev", dev)
            inside(ns, "tc", "qdisc", "add", "dev", dev, "clsact")
            inside(ns, "tc", "filter", "add", "dev", dev, "egress", "protocol", "all",
                   "pref", "5", "matchall", "skip_hw", "action", "gact", "continue")
            attach(ns, dev, 20, deny)
            read_filters(ns, dev, {20: deny_tag})
        stage("attach")
        start = at()
        deadline = start + 20 * SECOND
        obj, tag = compile_gate("permit", deadline)
        tags = {10: tag, 20: deny_tag}
        for ns, dev, *_ in ends:
            attach(ns, dev, 10, obj)
            read_filters(ns, dev, tags)
        outcome(5, True, directions=2)
        for ns, dev, *_ in ends:
            inside(ns, "ip", "link", "set", dev, "up")
        sockets = []
        for i, (ns, dev, ip, _) in enumerate(ends):
            _, _, peer, mac = ends[1-i]
            inside(ns, "ip", "neigh", "replace", peer, "lladdr", mac, "nud", "permanent", "dev", dev)
            sockets.append(stack.enter_context(udp(ns, ip)))
        stage("packets")
        def probe(post):
            total = 0
            for i, s in enumerate(sockets):
                peer = ends[1-i][2]
                message = os.urandom(24)
                tx = at()
                check((tx >= deadline) == post)
                try:
                    check(s.sendto(message, (peer, PORT)) == len(message))
                except OSError as exc:
                    if not post or exc.errno != errno.ENOBUFS:
                        raise
                rx = sockets[1-i]
                if select.select([rx], [], [], 0.35)[0]:
                    data, address = rx.recvfrom(1024)
                    check(data == message and address == (ends[i][2], PORT))
                    total += 1
            return total
        received = probe(False)
        check(received == 2 and at() < deadline)
        while at() < deadline:
            time.sleep(min(0.1, max(0, deadline-at()) / SECOND))
        counts = [read_filters(ns, dev, tags) for ns, dev, *_ in ends]
        late = sum(probe(True) for _ in range(3))
        after = [read_filters(ns, dev, tags) for ns, dev, *_ in ends]
        outcome(6, late == 0 and min(b-a for a,b in zip(counts,after)) >= 3,
                seconds=20, before_rx=received, after_tx=6, after_rx=late,
                tx_delta_min=min(b-a for a,b in zip(counts,after)))


def located(exc):
    frames = traceback.extract_tb(exc.__traceback__)
    return next((f.lineno for f in reversed(frames) if f.filename == __file__), 0)


def experiment():
    os.umask(0o077)
    WORK.mkdir(exist_ok=True)
    bootid = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    send("hello", previous=STATE.exists())
    request = command().split()
    if STATE.exists():
        check(request == ["resume"])
        old, challenge = STATE.read_text().split()
        send("rebooted", changed=old != bootid, challenge=challenge)
        check(command() == "suspend")
        stage("suspend")
        choices = Path("/sys/power/mem_sleep")
        check("deep" in choices.read_text() and "mem" in Path("/sys/power/state").read_text().split())
        choices.write_text("deep")
        check("[deep]" in choices.read_text())
        mono = time.monotonic_ns()
        boot_ns = at()
        Path("/sys/power/state").write_text("mem")
        boot_ms = (at()-boot_ns)//1_000_000
        mono_ms = (time.monotonic_ns()-mono)//1_000_000
        send("awake", boot_ms=boot_ms, mono_ms=mono_ms,
             same=bootid == Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        return
    check(len(request) == 2 and request[0] == "start" and re.fullmatch(r"[a-f0-9]{32}",request[1]))
    stage("identity")
    release = platform.freedesktop_os_release()
    image_ok = (platform.machine() == "x86_64" and platform.release() == ABI
                and release.get("ID") == "ubuntu" and release.get("VERSION_ID") == "24.04"
                and run("dpkg", "--print-architecture").strip() == "amd64"
                and "6.8.0-48.48" in Path("/proc/version_signature").read_text())
    outcome(2, image_ok)
    pid1 = Path("/proc/1/comm").read_text().strip() == "systemd"
    outcome(3, pid1)
    isolated = [r["ifname"] for r in json.loads(run("ip", "-j", "link"))] == ["lo"]
    outcome(4, isolated)
    check(image_ok and pid1 and isolated)
    for name in ("systemd", "nftables", "iproute2", "python3", "clang-18", "llvm-18", "libbpf1"):
        value = run("dpkg-query","-W","-f=${Version}",name).strip()
        send("version", name=name, value=value)
    bpf_version = re.search(r"bpftool v([0-9.]+)", run("bpftool", "version"))
    if bpf_version:
        send("version", name="bpftool", value=bpf_version[1])
    send("version",name="kernel",value=platform.release())
    send("version",name="kernel-package",value="6.8.0-48.48")
    for operation, affected in [(nft_proof, [7]), (traffic_proof, [5, 6])]:
        try:
            operation()
        except Exception as exc:
            send("problem", stage=STAGE, kind=type(exc).__name__, line=located(exc), affected=affected)
    with STATE.open("x") as f:
        f.write(bootid+" "+request[1]+"\n")
        f.flush()
        os.fsync(f.fileno())
    os.sync()
    send("prepared")
    check(command() == "reboot")
    run("systemctl", "--no-block", "reboot")


if __name__ == "__main__":
    fd = os.open("/dev/ttyS1", os.O_RDWR | os.O_NOCTTY)
    tty.setraw(fd)
    channel = os.fdopen(fd, "r+b", buffering=0)
    try:
        experiment()
    except Exception as exc:
        send("fatal", stage=STAGE, kind=type(exc).__name__, line=located(exc))
        raise SystemExit(1)
