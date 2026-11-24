"""Observe only the proven external four-tuple. Each private egress has its own map."""
import json
from pathlib import Path
import struct

FIELDS='frames payload_frames payload_bytes first last first_data last_data first_seq last_seq fin rst'.split()
def one(value):
    return value[0] if isinstance(value,list) and len(value)==1 else value

def install(lab,work,ends,fixture,t):
    pins={}
    for dev,ns,i,j in ends:
        sport,dport,_=fixture.sockets[0 if dev=='uc0' else 1]
        obj=work/(dev+'-attempt.o')
        lab.cmd('clang-18','-g','-O2','-target','bpfel','-mcpu=v3','-I/usr/include/x86_64-linux-gnu',
                '-DDEADLINE_NS='+str(t)+'ULL','-DSRC_IP='+hex(0xc0000200+int(i)),
                '-DDST_IP='+hex(0xc0000200+int(j)),'-DSRC_PORT='+str(sport),'-DDST_PORT='+str(dport),
                '-c',Path(__file__).with_name('transport_attempt.c'),'-o',obj)
        pin=Path('/sys/fs/bpf')/(dev+'attemptmap')
        prog=pin.with_name(dev+'attemptprog')
        lab.cmd('bpftool','map','create',pin,'type','array','key','4','value',str(8*len(FIELDS)),'entries','2','name','history')
        lab.cmd('bpftool','prog','load',obj,prog,'type','classifier','map','name','history','pinned',pin)
        p=one(json.loads(lab.cmd('bpftool','-j','prog','show','pinned',prog)))
        m=one(json.loads(lab.cmd('bpftool','-j','map','show','pinned',pin)))
        lab.require(p['map_ids']==[m['id']] and p['type']=='sched_cls','attempt observer identity')
        lab.cmd(*ns,'tc','filter','add','dev',dev,'egress','protocol','all','pref','1','bpf',
                'object-pinned',prog,'direct-action','skip_hw')
        lab.OBSERVERS[dev+'egress']=p['id']
        pins[dev]=pin
    return pins

def read(lab,pin):
    rows=json.loads(lab.cmd('bpftool','-j','map','dump','pinned',pin))
    def raw(items): return bytes(int(v,16) if isinstance(v,str) else v for v in items)
    parts={int.from_bytes(raw(r['key']),'little'):dict(zip(FIELDS,struct.unpack('<11Q',raw(r['value'])))) for r in rows}
    lab.require(set(parts)=={0,1},'attempt map periods')
    return dict(before=parts[0],after=parts[1])
