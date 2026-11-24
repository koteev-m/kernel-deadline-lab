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
    return dict(begin=lab.now(),processes=probe_process(f),
                external_server=socket_state(lab,c,f.procs['server'].pid,f.port),
                external_client=socket_state(lab,peer,f.procs['client'].pid,f.port),
                inbound_client=socket_state(lab,peer,f.procs['client'].pid,18884),end=lab.now())

def run(lab,stack,work,out,ends,foreign,before,hostfw,deny_tag,mode):
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
    report={}
    try:
        f.start(stack,c,peer)
        offsets=[('initial',0),('before',-1),('crossed',0),('later',2),('final',15)]
        for label,sec in offsets:
            until=0 if label=='initial' else t+sec*10**9
            while lab.now()<until: time.sleep(min(.08,(until-lab.now())/1e9) if until>lab.now()+1_000_000 else .001)
            report[label]=socket_sample(lab,f)
        lab.put(f.out/'end.json',f.finish(t))
    finally:
        f.snapshot()
        report['firewall_same']=before==hashlib.sha256(lab.cmd(*hostfw).encode()).hexdigest()
        report['foreign_alive']=foreign.poll() is None
        lab.put(out/'xray-trial.json',report)
