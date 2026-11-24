"""A single isolated transport. The original BOOTTIME deadline is fixed before arm."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import time
import subprocess as sp

import transport
import rx_clock
import socket_trace
import transport_wire

def probe_process(f):
    return {k:dict(pid=p.pid,alive=p.poll() is None,**({'rc':p.returncode} if p.returncode is not None else {}))
            for k,p in f.procs.items() if not k.endswith('-test')}

def socket_state(lab,ns,pid,port):
    lines=lab.cmd(*ns,'ss','-HntoieapO')
    rows=[]
    for line in lines.splitlines():
        if f'pid={pid},' not in line: continue
        cols=line.split()
        if not any(x.endswith(':'+str(port)) for x in cols[:5]): continue
        if cols[0]=='LISTEN': continue
        row={'state':{'ESTAB':1,'SYN-SENT':2,'SYN-RECV':3,'FIN-WAIT-1':4,'FIN-WAIT-2':5,
                      'TIME-WAIT':6,'CLOSE':7,'CLOSE-WAIT':8,'LAST-ACK':9,'CLOSING':11}.get(cols[0],0),
             'recv_q':int(cols[1]),'send_q':int(cols[2])}
        for key in ('ino','bytes_received','bytes_sent','bytes_acked','bytes_retrans','notsent','segs_out','segs_in','lastsnd','lastrcv'):
            m=re.search(r'\b'+key+r':(\d+)',line)
            if m: row[key]=int(m[1])
        rows.append(row)
    return rows

def socket_sample(lab,f):
    c,peer=f.net
    def ext(ns,dev,name):
        return transport.transport(ns,dev,f.procs[name].pid,name,f.port,allow_absent=True)
    result=dict(begin=lab.now(),processes=probe_process(f))
    for key,fn,args in [('path_server',ext,(c,'uc0','server')),('path_client',ext,(peer,'up0','client')),
                         ('external_server',socket_state,(lab,c,f.procs['server'].pid,f.port)),
                         ('external_client',socket_state,(lab,peer,f.procs['client'].pid,f.port)),
                         ('inbound_client',socket_state,(lab,peer,f.procs['client'].pid,18884))]:
        try:
            result[key]=fn(*args)
        except (RuntimeError,ValueError,OSError,sp.SubprocessError):
            result[key+'_read_error']=True
    result['end']=lab.now()
    return result

def socket_options(pid,inode):
    import ctypes
    import socket
    matches=[p for p in Path('/proc',str(pid),'fd').iterdir()
             if os.readlink(p)==f'socket:[{inode}]']
    if len(matches)!=1:
        return {'fd_unknown':True}
    ref=os.pidfd_open(pid)
    try:
        libc=ctypes.CDLL(None,use_errno=True)
        fd=libc.syscall(438,ref,int(matches[0].name),0)  # pidfd_getfd on the qualified x86-64 ABI
        if fd<0: return {'read_errno':ctypes.get_errno()}
        with socket.socket(fileno=fd) as s:
            return {'user_timeout_ms':s.getsockopt(socket.IPPROTO_TCP,socket.TCP_USER_TIMEOUT),
                    'inode':os.fstat(fd).st_ino,'cookie':int.from_bytes(s.getsockopt(socket.SOL_SOCKET,57,8),'little')}
    finally:
        os.close(ref)

def programs(lab,ends,tags):
    ids={}
    for dev,ns,*_ in ends:
        state=lab.filters(ns,dev,tags)
        ids[dev]={str(r['pref']):[r['options']['prog']['id'],r['options']['prog']['tag']] for r in state['tc']
                  if r['pref'] in (10,20) and 'options' in r}
    return ids

def run(lab,stack,work,out,ends,foreign,before,hostfw,deny_tag,mode):
    measured=os.environ['LAB_TARGET']!='xray-repro'
    capture=[]
    if measured:
        try:
            trace=socket_trace.arm(lab,work,stack)
        except (OSError,ValueError,RuntimeError,sp.SubprocessError):
            trace=None
        capture=[lab.capture(stack,ns,out,dev) for dev,ns,*_ in ends]
        def bound(dev):
            path=out/(dev+'.capture')
            return path.is_file() and '"bound"' in path.read_text()
        lab.wait_until(lambda:all(bound(dev) for dev, *_ in ends),5)
        capture+=rx_clock.install(lab,stack,work,out,ends)
    ticket=dict(start=lab.now(),boot=lab.boot(),mode=mode)
    ticket['deadline']=t=ticket['start']+lab.window(mode)
    lab.put(out/'ticket.json',ticket)
    permit,tag=lab.build(work,'bounded',t)
    tags={20:deny_tag,10:tag}
    for dev,ns,i,j in ends:
        lab.add(ns,dev,10,permit)
        lab.filters(ns,dev,tags)
        lab.cmd(*ns,'ip','link','set',dev,'up')
        lab.cmd(*ns,'ip','neigh','replace','192.0.2.'+j,'lladdr','02:00:00:68:00:0'+j,'nud','permanent','dev',dev)
    lab.put(out/'watch.json',{'start':ticket['start']})
    f=transport.Fixture(out,'reality')
    c,peer=[ns for _,ns,*_ in ends]
    report={'duration':t-ticket['start']}
    try:
        f.start(stack,c,peer)
        if measured:
            pins=transport_wire.install(lab,work,ends,f,t)
            for label,pos in [('server',0),('client',1)]:
                try: report[label+'_tcp']=socket_options(f.procs[label].pid,f.sockets[pos][2])
                except (OSError,ValueError,AttributeError): report[label+'_tcp']={'unavailable':True}
            report['gate_before']=programs(lab,ends,tags)
        offsets=[('initial',0),('before',-1),('crossed',0),('later',2),('six',6),('final',15)]
        for label,sec in offsets:
            until=0 if label=='initial' else t+sec*10**9
            while (remaining:=until-lab.now())>0:
                time.sleep(min(.08,remaining/1e9))
            try: report[label]=socket_sample(lab,f)
            except (RuntimeError,ValueError,OSError,sp.SubprocessError): report[label]={'read_error':True,'at':lab.now()}
        try: lab.put(f.out/'end.json',f.finish(t))
        except (RuntimeError,ValueError,OSError,sp.SubprocessError):
            report['application_read_error']=True
        if measured:
            try: report['trace']=socket_trace.finish(lab,trace,f) if trace else {'unavailable':True}
            except (RuntimeError,ValueError,OSError,AttributeError,KeyError,TypeError):
                report['trace']={'read_error':True}
            for p in capture:
                lab.require(p.poll() is None,'missing receive witness')
                p.send_signal(signal.SIGINT)
                lab.require(p.wait(timeout=6)==0,'receive capture failed')
            report['gate_after']=programs(lab,ends,tags)
            for dev,ns,*_ in ends:
                index=json.loads(lab.cmd(*ns,'ip','-j','link','show','dev',dev))[0]['ifindex']
                wire=rx_clock.compare(out,dev,index,t)
                counters=json.loads((out/(dev+'.capture')).read_text().splitlines()[-1])
                report[dev]={'attempt':transport_wire.read(lab,pins[dev]),'wire':wire,'capture':counters}
            ctl=[json.loads(row) for row in (out/'control.jsonl').read_text().splitlines() if row.endswith('}')]
            report['control_stream']=len(set((r['pid'],tuple(r['connection'])) for r in ctl))==1 and ctl[0]['at']<t<ctl[-1]['at']
            report['control_exchanges']=len(ctl)
    finally:
        f.snapshot()
        report['firewall_same']=before==hashlib.sha256(lab.cmd(*hostfw).encode()).hexdigest()
        report['foreign_alive']=foreign.poll() is None
        lab.put(out/'xray-trial.json',report)
