"""Dedicated established sockets, a bounded pre-gate journal and an ACK-loss fixture."""
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
CLIENT, SERVER = 24680, 24681
SIZE = 48
SECOND = 10**9
PINS = Path('/sys/fs/bpf')

def now():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)

def check(ok, name):
    if not ok:
        raise ValueError(name)

def one(data):
    return data[0] if isinstance(data, list) and len(data)==1 else data

def mount_observers(lab, ends, work):
    obj = work/'seq-observer.o'
    lab.cmd('clang-18','-g','-O2','-target','bpfel','-mcpu=v3','-I/usr/include/x86_64-linux-gnu',
            '-c', HERE/'seq_observer.c','-o',obj)
    installed = {}
    for dev, ns, *_ in ends:
        for direction in ('ingress','egress'):
            prefix = dev+direction
            pin, prog = PINS/(prefix+'map'), PINS/(prefix+'prog')
            lab.cmd('bpftool','map','create',pin,'type','array','key','4','value','32',
                    'entries','257','name','series')
            lab.cmd('bpftool','prog','load',obj,prog,'type','classifier','map','name','series','pinned',pin)
            p=one(json.loads(lab.cmd('bpftool','-j','prog','show','pinned',prog)))
            m=one(json.loads(lab.cmd('bpftool','-j','map','show','pinned',pin)))
            check(p['type']=='sched_cls' and p['map_ids']==[m['id']], 'OBS_MAP_ID')
            lab.cmd(*ns,'tc','filter','add','dev',dev,direction,'protocol','all','pref','1',
                    'bpf','object-pinned',prog,'direct-action','skip_hw')
            installed[prefix]=p['id']
    check(len(set(installed.values()))==4,'OBS_HOOK_IDS')
    return installed

def read_map(lab, ns, dev, direction, expected):
    prefix=dev+direction
    filters=json.loads(lab.cmd(*ns,'tc','-j','-s','filter','show','dev',dev,direction))
    items=[r for r in filters if r.get('pref')==1 and 'options' in r]
    check(len(items)==1 and items[0]['options']['prog']['id']==expected, 'OBS_HOOK_DRIFT')
    rows=json.loads(lab.cmd('bpftool','-j','map','dump','pinned',PINS/(prefix+'map')))
    def raw(values):
        return bytes(int(v,16) if isinstance(v,str) else v for v in values)
    table={int.from_bytes(raw(r['key']),'little'):raw(r['value']) for r in rows}
    count=struct.unpack_from('<Q',table[0])[0]
    check(count<=256,'OBS_OVERFLOW')
    keys=('at','seq','ack','sport','dport','length','family','flags','src','dst')
    return [dict(zip(keys,struct.unpack('<QIIHHHBBII',table[i]))) for i in range(1,count+1)]

def line(**data):
    print(json.dumps(dict(data,at=now(),pid=os.getpid())),flush=True)

def sample(s):
    data=s.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,128)
    check(len(data)==128,'TCP_INFO_LENGTH')
    return dict(cookie=int.from_bytes(s.getsockopt(socket.SOL_SOCKET,57,8),'little'),
                inode=os.fstat(s.fileno()).st_ino, state=data[0],
                unacked=struct.unpack_from('<I',data,24)[0],
                total=struct.unpack_from('<I',data,100)[0],
                acked=struct.unpack_from('<Q',data,120)[0])

def endpoint(side,t):
    import select
    import traffic
    from contextlib import ExitStack
    traffic.drop()
    local,other=(1,2) if side=='uc0' else (2,1)
    paths={4:('192.0.2.',socket.AF_INET),6:('2001:db8:68::',socket.AF_INET6)}
    with ExitStack() as stack:
        listen, clients, servers={}, {}, {}
        for f,(prefix,af) in paths.items():
            listener=stack.enter_context(traffic.sock(af,socket.SOCK_STREAM))
            listener.bind((prefix+str(local),SERVER))
            listener.listen(1)
            listen[f]=listener
        signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR1})
        line(kind='listening')
        signal.sigwait({signal.SIGUSR1})
        for f,(prefix,af) in paths.items():
            # The peer must have reached listen() before the fixed-port handshake.
            s=stack.enter_context(traffic.sock(af,socket.SOCK_STREAM))
            s.bind((prefix+str(local),CLIENT))
            s.settimeout(4)
            s.connect((prefix+str(other),SERVER))
            s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            clients[f]=s
        for f,listener in listen.items():
            listener.settimeout(4)
            server,peer=listener.accept()
            check(peer[1]==CLIENT,'UNEXPECTED_PEER')
            servers[f]=stack.enter_context(server)
            line(kind='connected',family=f,**sample(clients[f]))
        sent=False
        delivered={4:b'',6:b''}
        while True:
            clock=now()
            if not sent and clock>=t-10*SECOND:
                check(clock<t-7*SECOND,'PROBE_SEND_LATE')
                for f,s in clients.items():
                    s.sendall(bytes([local,f])*24)
                    line(kind='sent',family=f,**sample(s))
                sent=True
            for f,server in servers.items():
                if select.select([server],[],[],0)[0]:
                    data=server.recv(128)
                    check(bool(data),'PEER_CLOSED')
                    delivered[f]+=data
                    check((bytes([other,f])*24).startswith(delivered[f]),'PROBE_PAYLOAD')
                    if len(delivered[f])==SIZE:
                        line(kind='delivered',family=f)
            if clock>=t-11*SECOND:
                for f,s in clients.items():
                    line(kind='info',family=f,**sample(s))
            time.sleep(.09)

def launch(lab,stack,ends,out,t):
    # The child blocks SIGUSR1 before reporting both listening sockets.
    procs=[]
    for dev,ns,*_ in ends:
        log=stack.enter_context((out/(dev+'.probe')).open('xb',buffering=0))
        err=stack.enter_context((out/(dev+'.probe-error')).open('xb',buffering=0))
        p=lab.spawn(stack,[*ns,sys.executable,'-I','-B',str(HERE/'retrans.py'),dev,str(t)],log,err)
        procs.append(p)
    def listeners():
        check(all(p.poll() is None for p in procs),'PROBE_LISTEN_EXIT')
        for p,(d,*_) in zip(procs,ends):
            rows=(out/(d+'.probe')).read_text().splitlines()
            if not rows or json.loads(rows[0]).get('pid')!=p.pid or json.loads(rows[0]).get('kind')!='listening':
                return False
        return True
    lab.wait_until(listeners,5)
    for p in procs:
        p.send_signal(signal.SIGUSR1)
    def connected():
        if any(p.poll() is not None for p in procs):
            raise ValueError('PROBE_CONNECT')
        return all((out/(d+'.probe')).read_text().count('"connected"')==2 for d,_,_,_ in ends)
    lab.wait_until(connected,8)
    for dev,ns,i,j in ends:
        policy='add table inet ack_fixture\nadd chain inet ack_fixture received { type filter hook input priority -100; policy accept; }\n'
        for family,prefix in [('ip','192.0.2.'),('ip6','2001:db8:68::')]:
            policy+=f'add rule inet ack_fixture received iifname "{dev}" {family} saddr {prefix}{j} {family} daddr {prefix}{i} tcp sport {SERVER} tcp dport {CLIENT} tcp flags & (ack|syn|fin|rst) == ack counter drop\n'
        subprocess.run([*ns,'nft','-f','-'],input=policy,text=True,check=True)
    check(now()<t-10*SECOND,'ACK_RULE_ARM_LATE')
    return procs

def collect(lab, ends, out, procs, ids):
    check(all(p.poll() is None for p in procs),'PROBE_PROCESS_EXIT')
    data={}
    for dev,ns,*_ in ends:
        rules=json.loads(lab.cmd(*ns,'nft','-j','list','chain','inet','ack_fixture','received'))['nftables']
        counts=[e['counter']['packets'] for r in rules if 'rule' in r for e in r['rule']['expr'] if 'counter' in e]
        check(len(counts)==2,'ACK_RULE_COUNT')
        data[dev]={'drops':counts}
        for direction in ('ingress','egress'):
            data[dev][direction]=read_map(lab,ns,dev,direction,ids[dev+direction])
        raw=(out/(dev+'.probe')).read_bytes()
        data[dev]['app']=[json.loads(x) for x in raw[:raw.rfind(b'\n')+1].splitlines()]
    lab.put(out/'probe.json', data)

if __name__=='__main__':
    sys.path.insert(0,str(HERE))
    endpoint(sys.argv[1],int(sys.argv[2]))
