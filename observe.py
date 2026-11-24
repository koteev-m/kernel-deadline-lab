"""Orchestrate one hardware-accelerated guest and emit only allowlisted observations."""
import json
from pathlib import Path
import os
import queue
import re
import secrets
import socket
import subprocess as sp
import sys
import threading
import time

STAGES = {"startup","identity","nft","interfaces","fallback","attach","packets","suspend"}
TOOLS = {"qemu","kernel","kernel-package","systemd","nftables","iproute2","python3",
         "clang-18","llvm-18","libbpf1","bpftool"}
METRICS = {"directions","seconds","before_rx","after_tx","after_rx","tx_delta_min"}
ERRORS = {"ValueError","OSError","FileNotFoundError","KeyError","TimeoutError",
          "TimeoutExpired","CalledProcessError","PermissionError","RuntimeError","IndexError"}
results = {n:"NOT_OBSERVED" for n in range(1,10)}


def result(n, good):
    results[n] = "PASS" if good else "FAIL"
    print(f"CHECK {n} {results[n]}", flush=True)


def version(name, value):
    if name in TOOLS and re.fullmatch(r"[0-9][a-zA-Z0-9:.+~_-]{0,63}", value):
        print(f"VERSION {name} {value}", flush=True)


def reader(stream, name, bus):
    try:
        for line in stream:
            if len(line) <= 2048:
                try:
                    obj = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                if isinstance(obj, dict):
                    bus.put((name, obj))
    finally:
        bus.put((name, None))


def launch(work):
    qemu = "qemu-system-x86_64"
    version("qemu", sp.check_output(["dpkg-query","-W","-f=${Version}","qemu-system-x86"],text=True).strip())
    bus = queue.Queue()
    addr = work/"qmp.sock"
    argv = [qemu, "-nodefaults", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp","2",
            "-m","2048", "-global","ICH9-LPC.disable_s3=0","-rtc","base=utc,clock=host",
            "-display","none","-monitor","none","-nic","none","-serial","file:"+str(work/"console"),
            "-serial","stdio","-qmp","unix:"+str(addr)+",server=on,wait=off",
            "-kernel",str(work/"kernel"),"-initrd",str(work/"initrd"),
            "-append","root=/dev/vda rootfstype=ext4 rw rootwait console=ttyS0 quiet systemd.show_status=false",
            "-drive","file="+str(work/"guest.ext4")+",if=virtio,format=raw"]
    with (work/"qemu-private.log").open("wb") as diagnostic, socket.socket(socket.AF_UNIX) as qmp:
        vm = sp.Popen(argv,stdin=sp.PIPE,stdout=sp.PIPE,stderr=diagnostic,
                      env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
        try:
            for _ in range(100):
                if vm.poll() is not None:
                    raise RuntimeError("emulator startup")
                try:
                    qmp.connect(str(addr))
                    break
                except (FileNotFoundError,ConnectionRefusedError):
                    time.sleep(.1)
            else:
                raise TimeoutError("QMP socket")
            for stream,name in [(qmp.makefile("rb"),"qmp"),(vm.stdout,"guest")]:
                threading.Thread(target=reader,args=(stream,name,bus),daemon=True).start()
            def ask(op):
                qmp.sendall((json.dumps({"execute":op,"id":op})+"\n").encode())
            def tell(text):
                vm.stdin.write((text+"\n").encode())
                vm.stdin.flush()

            challenge = secrets.token_hex(16)
            phase = "first-boot"
            reset = kvm = first = armed = woke = False
            can_wake = None
            suspend_at = requested = None
            resumed = None
            bound = time.monotonic() + 230
            while time.monotonic() < bound:
                if suspend_at is not None and requested is None and time.monotonic()-suspend_at >= 5:
                    requested = time.monotonic()
                    ask("system_wakeup")
                try:
                    channel, msg = bus.get(timeout=.15)
                except queue.Empty:
                    continue
                if msg is None:
                    raise RuntimeError("transport ended")
                if channel == "qmp":
                    if "QMP" in msg:
                        ask("qmp_capabilities")
                    elif msg.get("id") == "qmp_capabilities" and "return" in msg:
                        ask("query-kvm")
                        ask("query-current-machine")
                    elif msg.get("id") == "query-kvm":
                        v = msg.get("return", {})
                        kvm = v.get("enabled") is True and v.get("present") is True
                        result(1, kvm)
                        if not kvm:
                            return
                    elif msg.get("id") == "query-current-machine":
                        can_wake = msg.get("return",{}).get("wakeup-suspend-support") is True
                    elif msg.get("event") == "RESET" and phase == "reboot":
                        reset = True
                    elif msg.get("event") == "SUSPEND" and phase == "sleep":
                        suspend_at = time.monotonic()
                        print("QMP SUSPEND",flush=True)
                    elif msg.get("event") == "WAKEUP" and requested is not None:
                        woke = True
                        print("QMP WAKEUP",flush=True)
                    elif msg.get("id") == "system_wakeup" and "error" in msg:
                        result(9,False)
                        return
                else:
                    kind = msg.get("event")
                    if kind == "hello" and phase == "first-boot" and msg.get("previous") is False:
                        first = True
                    elif kind == "hello" and phase == "reboot" and msg.get("previous") is True:
                        tell("resume")
                    elif kind == "stage" and msg.get("name") in STAGES:
                        print("GUEST", msg["name"], flush=True)
                    elif kind == "version":
                        version(msg.get("name"),msg.get("value",""))
                    elif kind == "result" and type(msg.get("number")) is int and 2 <= msg["number"] <= 7:
                        result(msg["number"],msg.get("passed") is True)
                        for key in sorted(METRICS & msg.keys()):
                            if type(msg[key]) is int and 0 <= msg[key] < 1000000:
                                print("METRIC",key,msg[key],flush=True)
                    elif kind in ("problem","fatal"):
                        print("GUEST_ERROR",
                              msg.get("stage") if msg.get("stage") in STAGES else "unknown",
                              msg.get("kind") if msg.get("kind") in ERRORS else "other",
                              msg["line"] if type(msg.get("line")) is int and 0 < msg["line"] < 2000 else 0, flush=True)
                        if kind=="fatal":
                            if phase=="sleep":
                                result(9,False)
                            return
                        for n in msg.get("affected",[]):
                            if n in (5,6,7) and results[n]=="NOT_OBSERVED":
                                result(n,False)
                    elif kind == "prepared" and phase == "testing":
                        phase = "reboot"
                        tell("reboot")
                    elif kind == "rebooted" and phase == "reboot":
                        valid = reset and msg.get("changed") is True and msg.get("challenge")==challenge
                        result(8,valid)
                        if not valid or not can_wake:
                            if not can_wake:
                                result(9,False)
                            return
                        phase = "sleep"
                        tell("suspend")
                    elif kind == "awake" and phase == "sleep":
                        resumed = msg
                if first and kvm and can_wake is not None and not armed:
                    armed = True
                    phase = "testing"
                    tell("start "+challenge)
                if woke and resumed is not None:
                    wall_ms = round((requested-suspend_at)*1000)
                    boot_ms, mono_ms = resumed["boot_ms"],resumed["mono_ms"]
                    delta = boot_ms-mono_ms
                    ok = resumed.get("same") is True and wall_ms>=4900 and abs(wall_ms-delta)<=1800
                    print("SLEEP_MS",int(wall_ms),int(boot_ms),int(mono_ms),flush=True)
                    result(9,ok)
                    return
            raise TimeoutError("observation window")
        finally:
            if vm.poll() is None:
                vm.terminate()
                try:
                    vm.wait(timeout=5)
                except sp.TimeoutExpired:
                    vm.kill()
                    vm.wait()


if __name__=="__main__":
    path = Path(sys.argv[1])
    try:
        launch(path)
    except Exception as exc:
        print("OBSERVER_ERROR",type(exc).__name__,flush=True)
        # Raw guest console is never published.
        for filename, markers in {"console":["Kernel panic","VFS: Unable to mount","ALERT!",
                                               "Failed to start","emergency mode"],
                                  "qemu-private.log":["failed to initialize kvm","No such file",
                                                      "Property","Permission denied"]}.items():
            if (path/filename).is_file():
                raw = (path/filename).read_bytes().lower()
                for marker in markers:
                    if marker.lower().encode() in raw:
                        print("DIAGNOSTIC",marker,flush=True)
    print("FINAL",json.dumps(results,sort_keys=True),flush=True)
    raise SystemExit(0 if set(results.values())=={"PASS"} else 1)
