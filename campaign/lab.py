"""Offline Linux-only transport experiment. Does not operate on host interfaces."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import subprocess as sp
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
NS = Path('/proc/self/ns/net')
SEC = 1_000_000_000
WINDOW = 600 * SEC
OBSERVERS = {}
sys.path.insert(0,str(HERE))
import retrans


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def now():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def window(mode):
    return 35 * SEC if mode == 'qualification' else WINDOW


def check_ticket(ticket, issued_mode=None):
    mode = ticket['mode'] if issued_mode is None else issued_mode
    require(ticket['mode'] == mode, 'TICKET_MODE_CHANGED')
    require(ticket['deadline'] == ticket['start'] + window(mode) and ticket['start'] > 0,
            'INVALID_ORIGINAL_DEADLINE')
    require(ticket['boot'] == boot(), 'OLD_BOOT_DENIED')


def put(path, obj):
    with path.open('x') as f:
        json.dump(obj, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def cmd(*args):
    return sp.check_output([str(a) for a in args], timeout=20, text=True)


def preflight():
    require(sys.platform == 'linux' and re.match(r'^6\.8\.', platform.release()),
            'BLOCKED_NO_NATIVE_LAB: Linux 6.8 required')
    require(os.geteuid() == 0 and hasattr(os, 'setns') and sys.byteorder == 'little',
            'root, Python 3.12+ and little-endian Linux required')
    require([r['ifname'] for r in json.loads(cmd('ip','-j','link'))] == ['lo'],
            'offline guest with only lo required')
    offsets = [l.split() for l in Path('/proc/self/timens_offsets').read_text().splitlines()]
    require({r[0] for r in offsets} == {'monotonic', 'boottime'} and
            all(r[1:] == ['0', '0'] for r in offsets), 'time namespace offsets')
    for name in ('clang-18', 'llvm-objcopy-18', 'tc', 'ip', 'nsenter', 'unshare', 'tcpdump',
                 'bpftool', 'nft', 'ss', 'sleep', 'findmnt', 'mount'):
        require(shutil.which(name), f'missing {name}')
    cmd('clang-18', '-fsyntax-only', '-DCHECK_LINUX_UAPI', HERE / 'gate.bpf.c')
    require(cmd('findmnt', '-no', 'FSTYPE', '-T', '/dev/shm').strip() == 'tmpfs',
            'ephemeral compiler storage required')


def private_net(stack):
    original = os.open(NS, os.O_RDONLY)
    try:
        os.unshare(os.CLONE_NEWNET)
        require(os.stat(NS).st_ino != os.fstat(original).st_ino, 'namespace did not change')
        fd = os.open(NS, os.O_RDONLY)
        stack.callback(os.close, fd)
    finally:
        os.setns(original, os.CLONE_NEWNET)
        os.close(original)
    # Absolute reference to the observer's retained fd, also valid in forked armer.
    return ['nsenter', '--net=/proc/%d/fd/%d' % (os.getpid(), fd), '--']


def build(folder, name, deadline):
    obj = folder / (name + '.o')
    raw = folder / (name + '.insns')
    cmd('clang-18', '-O2', '-target', 'bpfel', '-DDEADLINE_NS=%dULL' % deadline,
        '-c', HERE / 'gate.bpf.c', '-o', obj)
    cmd('llvm-objcopy-18', '--dump-section', 'classifier=' + str(raw), obj)
    # Linux v6.8 computes the 8-byte program tag from the original instructions.
    return obj, hashlib.sha1(raw.read_bytes()).hexdigest()[:16]


def add(ns, dev, priority, obj):
    cmd(*ns, 'tc', 'filter', 'add', 'dev', dev, 'egress', 'protocol', 'all', 'pref',
        str(priority), 'bpf', 'obj', obj, 'sec', 'classifier', 'direct-action', 'skip_hw')


def filters(ns, dev, tags):
    rows = json.loads(cmd(*ns, 'tc', '-j', '-s', 'filter', 'show', 'dev', dev, 'egress'))
    # tc can emit an additional header row without filter options.
    leaves = [r for r in rows if 'options' in r]
    if dev+'egress' in OBSERVERS:
        probes=[r for r in leaves if r['pref']==1]
        require(len(probes)==1 and probes[0]['kind']=='bpf' and probes[0]['protocol']=='all' and
                probes[0].get('chain',0)==0 and probes[0]['options']['direct-action'] and probes[0]['options']['skip_hw'] and
                probes[0]['options']['prog']['id']==OBSERVERS[dev+'egress'], 'OBS_PREF_CHANGED')
        leaves=[r for r in leaves if r['pref']!=1]
    require(sorted(r['pref'] for r in leaves) == sorted([5, *tags]), 'filter order/count')
    require(all(r.get('chain', 0) == 0 and r['protocol'] == 'all' for r in leaves),
            'unexpected protocol or chain')
    count = None
    for r in leaves:
        opts = r['options']
        if r['pref'] == 5:
            actions = opts['actions']
            require(r['kind'] == 'matchall' and opts['skip_hw'] and len(actions) == 1 and
                    actions[0]['kind'] == 'gact' and
                    actions[0]['control_action']['type'] == 'continue', 'entry counter action')
            count = actions[0]['stats']['packets']
            continue
        prog = opts['prog']
        require(r['kind'] == 'bpf' and opts['direct-action'] and opts['skip_hw'] and
                not opts.get('in_hw') and prog['tag'] == tags[r['pref']], 'unverified filter')
        info = json.loads(cmd(*ns, 'bpftool', '-j', 'prog', 'show', 'id', str(prog['id'])))
        if isinstance(info, list) and len(info) == 1:
            info = info[0]
        require(info['type'] == 'sched_cls' and info['tag'] == prog['tag'] and
                not info.get('map_ids'), 'unexpected program or mutable map')
    require(isinstance(count, int), 'missing pre-filter packet count')
    return {'packet_attempts': count, 'tc': rows}


def bracket(ns, dev, state, ticket, packet):
    # Test a copy of one Ethernet frame inside the kernel, independently of
    # real traffic and after tc's loading process has exited.
    rows = [r for r in state['tc'] if r.get('kind')=='bpf' and r['pref'] in (10,20) and 'options' in r]
    row = min(rows, key=lambda r: r['pref'])
    before = now()
    reply = json.loads(cmd(*ns, 'bpftool','-j','prog','run','id',
                           row['options']['prog']['id'], 'data_in',packet))
    after = now()
    if row['pref']==20 or before >= ticket['deadline']:
        require(reply['retval']==2, 'kernel test-run admitted expired/absent permit')
    elif after < ticket['deadline']:
        require(reply['retval']==0, 'kernel test-run denied a current permit')
    else:
        raise RuntimeError('test-run bracket crossed boundary')
    return dict(dev=dev, before=before, after=after, action=reply['retval'])


def spawn(stack, args, stdout, stderr=None):
    p = sp.Popen(args, stdin=sp.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
    def reap():
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(timeout=3)
            except sp.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=3)
    stack.callback(reap)
    return p


def resident(ns, dev, peerip, family):
    return json.loads(cmd(*ns, 'ip', '-j', family, 'route', 'get', peerip))[0]['dev'] == dev


def workload(stack, ns, out, name, *args):
    log = stack.enter_context((out / (name + '.jsonl')).open('xb', buffering=0))
    err = stack.enter_context((out / (name+'.stderr')).open('xb'))
    return spawn(stack, [*ns, sys.executable, '-I', '-B', '-c',
                         (HERE / 'traffic.py').read_text(), *args], log, err)


def capture(stack, ns, out, dev, *, legacy=False):
    pcap = stack.enter_context((out / (dev + '.pcap')).open('xb'))
    diag = stack.enter_context((out / (dev + '.capture')).open('xb'))
    index = json.loads(cmd(*ns,'ip','-j','link','show','dev',dev))[0]['ifindex']
    if legacy:
        args = ['tcpdump','-p','-U','-nn','-Q','in','-i','any','-y','LINUX_SLL2',
                '-Z','root','-s','0','-w','-','ifindex',str(index)]
    else:
        args = [sys.executable,'-I','-B',str(HERE/'frame_capture.py'),dev,str(index)]
    p = spawn(stack, [*ns,*args], pcap, diag)
    return p


def wait_until(predicate, timeout):
    end = time.monotonic() + timeout
    while not predicate():
        require(time.monotonic() < end, 'instrumentation did not become ready')
        time.sleep(.05)


def wait_observers(out, stage, names, processes, timeout, predicate):
    expiry = time.monotonic() + timeout
    while True:
        states = {dev: predicate(dev) for dev in names}
        codes = {dev: p.poll() for dev, p in zip(names, processes)}
        dead = any(code is not None for code in codes.values())
        if not dead and all(all(flags.values()) for flags in states.values()):
            return
        if dead or time.monotonic() >= expiry:
            # Fixed schema only. Keep a live flag separate from an actual exit code.
            report = {'stage': stage}
            for dev in names:
                report[dev] = dict(states[dev], exited=codes[dev] is not None,
                                   code=codes[dev] if codes[dev] is not None else 0)
            put(out / 'readiness-fault.json', report)
            raise RuntimeError('instrumentation did not become ready')
        time.sleep(.05)


def run(out, mode):
    preflight()
    require(os.getpid() == 1 and os.stat(NS).st_ino != INITIAL_NET,
            'run through the private PID/network wrapper')
    # tc's ELF loader may initialize its pins directory. Isolate it from any guest bpffs.
    require(Path('/sys/fs/bpf').is_dir(), 'guest bpffs mountpoint required')
    cmd('mount', '-t', 'bpf', 'bpf', '/sys/fs/bpf')
    out.mkdir(mode=0o700)
    os.umask(0o077)
    put(out/'environment.json', dict(kernel=platform.release(), arch=platform.machine(),
        boot=boot(), clang=cmd('clang-18','--version'), tc=cmd('tc','-V'),
        capture=cmd('tcpdump','--version'), bpf=cmd('bpftool','version'),
        time_offsets=Path('/proc/self/timens_offsets').read_text(),
        clocksource=Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip()))
    token = secrets.token_hex(12)
    with ExitStack() as stack:
        work = Path(stack.enter_context(tempfile.TemporaryDirectory(dir='/dev/shm')))
        c, peer, control = [private_net(stack) for _ in range(3)]
        dst = spawn(stack, [*peer, 'sleep', 'infinity'], sp.DEVNULL)
        peer_path = peer[1].split('=', 1)[1]
        wait_until(lambda: os.stat('/proc/%d/ns/net' % dst.pid).st_ino == os.stat(peer_path).st_ino, 3)
        cmd(*c, 'ip', 'link', 'add', 'uc0', 'type', 'veth', 'peer', 'name', 'up0',
            'netns', str(dst.pid))
        ends = [('uc0', c, '1', '2'), ('up0', peer, '2', '1')]
        cmd(*control, 'ip', 'link', 'set', 'lo', 'up')
        foreign = workload(stack, control, out, 'control', 'control')
        # Only read the initial offline guest rules, and retain their digest.
        hostfw = ['nsenter', '--net='+INITIAL_PATH, '--', 'nft', '-s', '-j', 'list', 'ruleset']
        before = hashlib.sha256(cmd(*hostfw).encode()).hexdigest()
        deny, deny_tag = build(work, 'deny', 0)
        for dev, ns, i, j in ends:
            links = json.loads(cmd(*ns, 'ip', '-j', '-d', 'link'))
            require({x['ifname'] for x in links} == {'lo', dev} and
                    all('UP' not in x['flags'] for x in links) and
                    next(x for x in links if x['ifname'] == dev)['linkinfo']['info_kind'] == 'veth',
                    'unexpected topology')
            cmd(*ns, 'ip', 'link', 'set', dev, 'address', '02:00:00:68:00:0' + i)
            cmd(*ns, 'ip', 'addr', 'add', '192.0.2.' + i + '/30', 'dev', dev)
            # Set the IPv6 address after link activation (below).
            cmd(*ns, 'tc', 'qdisc', 'add', 'dev', dev, 'clsact')
            cmd(*ns, 'tc', 'filter', 'add', 'dev', dev, 'egress', 'protocol', 'all',
                'pref', '5', 'matchall', 'skip_hw', 'action', 'gact', 'continue')
            add(ns, dev, 20, deny)
            filters(ns, dev, {20: deny_tag})
        # Passive observers and pre-existing sockets are created before the permit.
        apps = [workload(stack, ns, out, dev, token, dev[1]) for dev, ns, _, _ in ends]
        if mode == 'inspect':
            sys.path.insert(0,str(HERE))
            import readiness
            readiness.do(sys.modules[__name__],stack,out,ends,apps)
            return
        names = [d for d, *_ in ends]
        def endpoint_ready(dev):
            log = (out / (dev+'.jsonl')).read_text()
            return {'ready': '"kind": "ready"' in log, 'migrated': '"kind": "migrated"' in log}
        wait_observers(out, 1, names, apps, 8, endpoint_ready)
        caps = [capture(stack, ns, out, dev) for dev, ns, _, _ in ends]
        def capture_ready(dev):
            link = next(ns for d,ns,*_ in ends if d==dev)
            idx = json.loads(cmd(*link,'ip','-j','link','show','dev',dev))[0]['ifindex']
            expected = dict(bound=idx,ingress=True,kernel_time=True)
            seen = (out/(dev+'.capture')).read_text().splitlines()
            return {'listening': bool(seen and json.loads(seen[0])==expected)}
        wait_observers(out, 2, names, caps, 5, capture_ready)
        active = mode not in ('absent','late')
        if active:
            OBSERVERS.update(retrans.mount_observers(sys.modules[__name__],ends,work))
        ticket = dict(run=token, boot=boot(), start=now(), mode=mode)
        ticket['deadline'] = ticket['start'] + window(mode)
        put(out / 'ticket.json', ticket)
        permit, permit_tag = build(work, 'bounded', ticket['deadline'])
        forked = os.fork()
        if forked == 0:
            try:
                if mode == 'paused':
                    os.kill(os.getpid(), signal.SIGSTOP)
                elif mode == 'delay':
                    time.sleep(30)
                elif mode == 'late':
                    while now() <= ticket['deadline']:
                        time.sleep(.12)
                reread = json.loads((out / 'ticket.json').read_text())
                require(reread == ticket, 'attempt changed')
                check_ticket(reread, mode)
                times = {}
                tags = {20: deny_tag}
                if mode != 'absent':
                    tags[10] = permit_tag
                    for dev, ns, _, _ in ends:
                        prior = now()
                        add(ns, dev, 10, permit)
                        times[dev] = [prior, now()]
                states = {d: filters(ns, d, tags) for d, ns, _, _ in ends}
                put(out / 'attached.json', dict(at=now(), intervals=times, tags=tags, states=states))
                if mode == 'loss':
                    os.kill(os.getpid(), signal.SIGSTOP)
                os._exit(0)
            except BaseException as exc:
                print(repr(exc), file=sys.stderr, flush=True)
                os._exit(2)
        def stopped():
            pid, status = os.waitpid(forked, os.WUNTRACED)
            require(pid == forked and os.WIFSTOPPED(status), 'installer did not stop')
        if mode == 'paused':
            stopped()
            pause_at = now()
            time.sleep(30)
            put(out/'installer-pause.json', dict(begin=pause_at, end=now()))
            os.kill(forked, signal.SIGCONT)
        if mode == 'loss':
            stopped()
        if mode != 'loss':
            require(os.waitpid(forked, 0)[1] == 0, 'installer failed')
        packet = work/'frame.bin'
        packet.write_bytes(bytes.fromhex('02000068000102000068000288b5') + bytes(50))
        s = json.loads((out / 'attached.json').read_text())
        tags = {int(k): v for k, v in s['tags'].items()}
        if mode in ('delay', 'paused'):
            require(s['at'] - ticket['start'] >= 30 * SEC, 'delay too short')
        if mode == 'late':
            require(s['at'] >= ticket['deadline'], 'late attachment missing')
        for dev, ns, i, j in ends:
            filters(ns, dev, tags)
        checks = [bracket(ns,d,s['states'][d],ticket,packet) for d,ns,_,_ in ends]
        indexes = {}
        for dev, ns, _, _ in ends:
            cmd(*ns, 'ip', 'link', 'set', dev, 'up')
            indexes[dev] = json.loads(cmd(*ns, 'ip','-j','link','show','dev',dev))[0]['ifindex']
        for dev, ns, i, j in ends:
            cmd(*ns, 'ip', '-6', 'addr', 'add', '2001:db8:68::'+i+'/64',
                'nodad', 'dev', dev)
            for fam, ip in [('-4', '192.0.2.' + j), ('-6', '2001:db8:68::' + j)]:
                cmd(*ns, 'ip', fam, 'neigh', 'replace', ip, 'lladdr', '02:00:00:68:00:0' + j,
                    'nud', 'permanent', 'dev', dev)
                require(resident(ns, dev, ip, fam), 'wrong path')
        probes = retrans.launch(sys.modules[__name__],stack,ends,out,ticket['deadline']) if active else []
        if mode == 'xray':
            sys.path.insert(0, str(HERE))
            import proxy
            proxy.start(stack, c, peer, out)
            if os.environ.get('LAB_INSPECT_TLS')=='1':
                return
        if mode == 'loss':
            # Kill only the fork we created, after a real bidirectional application exchange.
            wait_until(lambda: all('"kind": "rx"' in (out / (d+'.jsonl')).read_text()
                                   for d, *_ in ends), 12)
            os.kill(forked, signal.SIGKILL)
            require(os.waitpid(forked, 0)[1] == signal.SIGKILL, 'no installer death witness')
        put(out/'watch.json', dict(begin=now(), installer='SIGKILL' if mode=='loss' else 'exited',
                                   tags=tags, brackets=checks, ifindexes=indexes, protected_pid=foreign.pid, firewall_before=before))
        print('OBSERVING', mode, 'T_boot_ns', ticket['deadline'], flush=True)
        clocks = stack.enter_context((out / 'clocks.jsonl').open('x', buffering=1))
        # Continue for 15 real, awake seconds after the first observed expiry,
        # even when resuming late from operator-controlled guest suspend.
        while True:
            require(all(p.poll() is None for p in [foreign, *caps, *apps]), 'observer or app exited')
            lo = now()
            clocks.write(json.dumps([lo, time.time_ns(), now(), time.monotonic_ns()]) + '\n')
            if lo >= ticket['deadline']:
                break
            time.sleep(.1)
        first = {d: filters(ns,d,tags)['packet_attempts'] for d,ns,_,_ in ends}
        for _ in range(150):
            lo = now()
            clocks.write(json.dumps([lo, time.time_ns(), now(), time.monotonic_ns()]) + '\n')
            time.sleep(.1)
        end = {d: filters(ns,d,tags) for d,ns,_,_ in ends}
        final_checks = [bracket(ns,d,end[d],ticket,packet) for d,ns,_,_ in ends]
        after = hashlib.sha256(cmd(*hostfw).encode()).hexdigest()
        require(before == after and all(p.poll() is None for p in [foreign, *caps, *apps]),
                'foreign baseline or witness changed')
        for p in caps:
            p.send_signal(signal.SIGINT)
            require(p.wait(timeout=6) == 0, 'capture failed')
        listeners = {}
        for d, ns, _, _ in ends:
            with (out/(d+'.jsonl')).open() as f:
                ready = next(r for r in map(json.loads, f) if r['kind']=='ready')
            listeners[d] = {}
            for family in ('4','6'):
                inode = next(s['inode'] for s in ready['sockets']
                             if s['family']==family and s['role']=='listener')
                ss = cmd(*ns, 'ss', '-H', '-'+family, '-lntpe', 'sport = :24443')
                require(len(ss.splitlines())==1 and f"pid={ready['pid']}," in ss and
                        f'ino:{inode}' in ss.split() and 'uid:65000' in ss.split(),
                        'listener owner or inode changed')
                listeners[d][family] = ss.strip()
        if active:
            retrans.collect(sys.modules[__name__],ends,out,probes,OBSERVERS)
        if mode == 'xray':
            proxy.finish(c, peer, out, ticket)
        put(out/'end.json', dict(end=now(), first=first, state=end, brackets=final_checks, firewall_after=after,
                                 protected_pid=foreign.pid, listeners=listeners))
        for dev in ('uc0','up0','control'):
            with (out/(dev+'.jsonl')).open('rb') as source:
                snapshot = source.read()
            last = snapshot.rfind(b'\n')
            (out/(dev+'.snapshot')).write_bytes(snapshot[:last+1])
        if os.environ.get('LAB_BOUNDARY')=='1' and mode=='normal':
            # A constructive trust-boundary control, confined to these two private veths.
            # Both old programs have expired. Remove only pref 10, then the whole qdisc.
            for dev, ns, _, _ in ends:
                cmd(*ns, 'tc','filter','del','dev',dev,'egress','pref','10','protocol','all','bpf')
                one = filters(ns,dev,{20:deny_tag})
                bracket(ns,dev,one,ticket,packet)
            baseline = {d:(out/(d+'.jsonl')).stat().st_size for d,*_ in ends}
            since = now()
            time.sleep(1.5)
            def received_since(dev):
                with (out/(dev+'.jsonl')).open('rb') as log:
                    log.seek(baseline[dev])
                    return any(row.get('kind')=='rx' and row['sent'] >= since
                               for row in (json.loads(line) for line in log if line.endswith(b'\n')))
            require(not any(received_since(d) for d,*_ in ends),'fallback admitted fresh data')
            for dev, ns, _, _ in ends:
                cmd(*ns,'tc','qdisc','del','dev',dev,'clsact')
            since = now()
            wait_until(lambda: all(received_since(d) for d,*_ in ends), 12)
            put(out/'boundary.json', dict(fallback_drop=True, removed_qdisc_delivered=True))
    print('EVIDENCE_CAPTURED; run assess.py on this directory')


def main():
    os.environ['LC_ALL'] = 'C'
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['qualification','inspect','normal','paused','delay','late','loss','absent','xray','old-boot'])
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.mode == 'old-boot':
        require(sys.platform == 'linux', 'native guest required')
        ticket = json.loads((args.output/'ticket.json').read_text())
        try:
            check_ticket(ticket)
        except RuntimeError as exc:
            if str(exc) == 'OLD_BOOT_DENIED':
                # Read-only reboot witness. Only the lab names/tags enter output.
                arm = json.loads((args.output/'attached.json').read_text())
                prior_tag = arm['tags']['10']
                progs = json.loads(cmd('bpftool','-j','prog','show'))
                require(all(p.get('tag') != prior_tag for p in progs), 'old permit still loaded')
                require([l['ifname'] for l in json.loads(cmd('ip','-j','link'))] == ['lo'],
                        'offline topology changed')
                for d in ('uc0','up0'):
                    require('"kind": "rx"' in (args.output/(d+'.jsonl')).read_text(),
                            'no pre-reboot transfer witness')
                print('OLD_BOOT_DENIED', ticket['boot'], boot(), 'old permit tag absent', prior_tag)
                return
            raise
        raise RuntimeError('same boot; replay check inconclusive')
    preflight()
    global INITIAL_NET, INITIAL_PATH
    if 'LAB_PRIVATE_PARENT' not in os.environ:
        fd = os.open(NS, os.O_RDONLY)
        os.set_inheritable(fd, True)
        os.environ['LAB_PRIVATE_PARENT'] = str(fd)
        os.execvp('unshare', ['unshare', '--mount','--propagation','private','--net',
                             '--pid','--fork','--mount-proc',sys.executable,'-I','-B',
                             str(HERE/'lab.py'), args.mode, str(args.output.resolve())])
    fd = int(os.environ.pop('LAB_PRIVATE_PARENT'))
    INITIAL_NET = os.fstat(fd).st_ino
    INITIAL_PATH = '/proc/1/fd/%d' % fd
    run(args.output.resolve(), args.mode)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, sp.SubprocessError) as exc:
        import traceback
        frames = traceback.extract_tb(exc.__traceback__)
        print('lab-sites', *(f.lineno for f in frames if Path(f.filename).name=='lab.py'),file=sys.stderr)
        frame = frames[-1]
        print('lab-fault', frame.lineno, type(exc).__name__, str(exc)[:180], file=sys.stderr)
        raise SystemExit(1)
