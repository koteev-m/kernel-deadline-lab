"""Read-only assessor of native observations."""
import argparse
import bisect
import json
from pathlib import Path
import re
import struct


def need(ok, message):
    if not ok:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text())


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def packets(path, ifindex):
    formats = {b'\xd4\xc3\xb2\xa1': ('<',1000), b'\xa1\xb2\xc3\xd4': ('>',1000),
               b'\x4d\x3c\xb2\xa1': ('<',1), b'\xa1\xb2\x3c\x4d': ('>',1)}
    with path.open('rb') as f:
        order, scale = formats[f.read(4)]
        major, minor, _, _, snap, dlt = struct.unpack(order+'HHiIII', f.read(20))
        need((major,minor,dlt) == (2,4,276) and snap >= 1500, 'bad capture format')
        while header := f.read(16):
            sec, frac, n, original = struct.unpack(order+'IIII', header)
            need(0 < n == original <= snap, 'truncated or corrupt frame')
            data = f.read(n)
            need(len(data) == n and frac*scale < 10**9, 'incomplete capture')
            need(len(data)>=20 and data[10] in (0,1,2,3) and
                 struct.unpack_from('!I',data,4)[0]==ifindex, 'unexpected interface/direction')
            yield sec*10**9 + frac*scale, data


def assess(d, *, qualification=False):
    ticket, watch, end = [load(d / (key+'.json')) for key in ('ticket','watch','end')]
    start, t, mode = ticket['start'], ticket['deadline'], ticket['mode']
    need((mode=='qualification') == qualification, 'wrong measurement class')
    need(t-start == (35_000_000_000 if qualification else 600_000_000_000), 'wrong duration')
    need(end['end'] > t and watch['protected_pid'] == end['protected_pid'] and
         watch['firewall_before'] == end['firewall_after'], 'baseline/endpoints')
    need({r['dev'] for r in end['brackets'] if r['action']==2 and r['before']>=t}
         == {'uc0','up0'}, 'missing native expired test-run')
    active = mode not in ('absent','late')
    clock = lines(d/'clocks.jsonl')
    need(len(clock)>2 and all(a<=b for a,_,b,_ in clock), 'clock brackets')
    # Packet capture uses realtime. Wall steps, long scheduling gaps and suspend
    # are outside this interpolation. Preserve captures for an external witness.
    if active:
        need(clock[0][2] < t <= clock[-1][0], 'no clock coverage on both sides')
    offsets = [real-lo for lo,real,_,_ in clock]
    realtime = [r for _,r,_,_ in clock]
    periods = [b[0]-a[0] for a,b in zip(clock,clock[1:])]
    stable = (max(offsets)-min(offsets) < 5_000_000 and max(periods) < 2_000_000_000
              and realtime == sorted(realtime))
    marker = re.compile(rb'U6K\|'+ticket['run'].encode()+rb'\|([cp])\|([46])\|([a-z-]+)\|(\d+)\|(\d+)\n')
    streams = {(str(ver), s) for ver in (4,6) for s in ('udp','inherited-udp','tcp','new-tcp')}
    result, violations, uncertain = {}, [], []
    for dev, side, remote in [('uc0','c','p'), ('up0','p','c')]:
        app = lines(d/(dev+'.snapshot'))
        need(not any(r['kind']=='error' for r in app), 'endpoint worker error')
        ready = next(r for r in app if r['kind']=='ready')
        child = next(r for r in app if r['kind']=='migrated')
        need(ready['child'] == child['pid'] and ready['net'] != child['net'] and
             max(ready['at'],child['at']) <= start, 'socket provenance')
        sockets = ready['sockets']
        cookies = {s['cookie'] for s in sockets}
        need(len(sockets)==6 and len(cookies)==1 and all((s['uid'],s['gid'])==(65000,65000)
             for s in sockets) and len(child['retained'])==2 and set(child['retained'])==cookies
             and child['fresh'] not in cookies, 'socket owner or namespace cookie')
        rx = [r for r in app if r['kind']=='rx']
        flows = {(r['family'],r['stream']) for r in rx if r['sent'] < t and r['sender']==remote}
        if active:
            need(flows==streams, 'missing positive comparator')
        post = [r for r in app if r['at'] >= max(t,watch['begin']) and r['kind'] in ('tx','connect')]
        need({(r['family'],r['stream']) for r in post} >= streams, 'missing post-expiry stimulus')
        for r in rx:
            if r['sent'] >= t or not active:
                violations.append([dev,'application',r])
        for family in ('4','6'):
            if active:
                keys = lambda rows: {tuple(r['connection']) for r in rows if r['kind']=='tx'
                                     and r['family']==family and r['stream']=='tcp'}
                need(keys(r for r in app if r['at'] < t) & keys(post), 'established TCP lost before boundary')
                before = [r for r in app if r['kind']=='tcp-info' and r['family']==family and r['at']<t]
                after = [r for r in app if r['kind']=='tcp-info' and r['family']==family and r['at']>=t]
                need(any(b['connection']==a['connection'] and a['retrans']>b['retrans']
                         for a in after for b in before[-1:]), 'no retransmission witness')
        need(end['state'][dev]['packet_attempts'] > end['first'][dev], 'no packets reached classifier after T')
        diag = (d/(dev+'.capture')).read_text()
        messages = [json.loads(x) for x in diag.splitlines()]
        need(len(messages)==2 and messages[0]==dict(bound=watch['ifindexes'][dev],ingress=True,kernel_time=True), 'capture bind identity')
        counters = messages[1]
        need(counters['drops']==0, 'capture loss unknown')
        seen, n, crossing = set(), 0, 0
        for ts, frame in packets(d/(dev+'.pcap'), watch['ifindexes'][dev]):
            n += 1
            matches = list(marker.finditer(frame))
            for m in matches:
                need(m[1].decode()==remote, 'wrong capture direction')
                seen.add((m[2].decode(),m[3].decode()))
                if int(m[5]) >= t:
                    violations.append([dev,'post-deadline origin',int(m[5]),ts])
            if not active:
                violations.append([dev,'closed-link frame',ts])
            elif stable:
                # Captures predating clock calibration by setup seconds are only
                # application evidence. Resolve the boundary via adjacent samples.
                idx = bisect.bisect_left(realtime,ts)
                if 0 < idx < len(clock):
                    window = clock[idx-1:idx+1]
                    upper = max(ts+x[2]-x[1] for x in window) + 1_000_000
                    if upper >= t:
                        crossing += 1
                elif ts >= realtime[-1]:
                    crossing += 1
        need(counters['kernel']==counters['frames']==n, 'capture file/count mismatch')
        if active:
            need(seen >= streams, 'missing wire comparator')
        if crossing:
            uncertain.append([dev,'delivery at/after boundary or within calibration uncertainty',crossing])
        result[dev] = {'wire_frames':n,'wire_streams':sorted(seen),'post_stimuli':len(post),
                       'queued_or_uncertain_delivery':crossing, 'app_rx':len(rx)}
    ctl = lines(d/'control.snapshot')
    need(all(r['kind']=='control' for r in ctl) and ctl[0]['at']<t<ctl[-1]['at']
         and len({(r['pid'],tuple(r['connection'])) for r in ctl}) == 1, 'foreign control')
    if not stable:
        uncertain.append('independent suspend/wall-clock correlation required')
    if mode=='loss':
        need(watch['installer']=='SIGKILL', 'missing death witness')
    status = 'DELIVERY_VIOLATION' if violations else 'REVIEW_REQUIRED' if uncertain else 'SYNTHETIC_CASE_OBSERVED'
    print(json.dumps(dict(mode=mode,status=status,transport=result,violations=violations[:10],
                          timing_review=uncertain),indent=2))
    return 1 if violations else 2 if uncertain else 0


if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('evidence',type=Path)
    raise SystemExit(assess(ap.parse_args().evidence))
