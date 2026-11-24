"""Read native socket state and errno events on an instance confined to the offline guest."""
from decimal import Decimal
from pathlib import Path
import re

STATES={'ESTABLISHED':1,'SYN_SENT':2,'SYN_RECV':3,'FIN_WAIT1':4,'FIN_WAIT2':5,'TIME_WAIT':6,
        'CLOSE':7,'CLOSE_WAIT':8,'LAST_ACK':9,'LISTEN':10,'CLOSING':11,'NEW_SYN_RECV':12}

def arm(lab,work,stack):
    root=work/'trace'
    root.mkdir()
    lab.cmd('mount','-t','tracefs','tracefs',root)
    stack.callback(lab.cmd,'umount',root)
    instance=root/'instances'/'transport'
    instance.mkdir()
    stack.callback(instance.rmdir)
    (instance/'tracing_on').write_text('0')
    (instance/'trace_clock').write_text('boot')
    lab.require('[boot]' in (instance/'trace_clock').read_text(),'socket trace clock')
    for event in ('inet_sock_set_state','inet_sk_error_report'):
        where=instance/'events'/'sock'/event
        (where/'filter').write_text('sport == 24446 || dport == 24446 || sport == 18884 || dport == 18884')
        (where/'enable').write_text('1')
    exits=instance/'events/sched/sched_process_exit'
    (exits/'filter').write_text('comm == "measure-stream" || comm == "measure-echo"')
    (exits/'enable').write_text('1')
    (instance/'tracing_on').write_text('1')
    return instance

def finish(lab,instance,f):
    (instance/'tracing_on').write_text('0')
    stats=(instance/'per_cpu/cpu0/stats').read_text()
    def count(label):
        return int(re.search(r'^'+label+r':\s*(\d+)',stats,re.M)[1])
    lost=count('overrun')+count('dropped events')+count('commit overrun')
    raw=(instance/'trace').read_text()
    client_port=f.sockets[1][0]
    rows={}
    extra=set()
    exits={}
    for line in raw.splitlines():
        ex=re.search(r'\s(\d+\.\d+): sched_process_exit: comm=(measure-stream|measure-echo) pid=(\d+)',line)
        if ex:
            exits[ex[2]]=dict(at=int(Decimal(ex[1])*10**9),tid=int(ex[3]))
        m=re.search(r'\s(\d+\.\d+): (inet_sock_set_state|inet_sk_error_report): (.*)',line)
        if not m: continue
        p=dict(re.findall(r'(\w+)=([^ ]+)',m[3]))
        addrs=(p.get('saddr'),p.get('daddr'))
        ports=(int(p['sport']),int(p['dport']))
        if ports==(client_port,24446) and addrs==('192.0.2.2','192.0.2.1'):
            name='external_client'
        elif ports==(24446,client_port) and addrs==('192.0.2.1','192.0.2.2'):
            name='external_server'
        elif 18884 in ports and addrs==('127.0.0.1','127.0.0.1'):
            name='local_xray' if ports[0]==18884 else 'local_stream'
        else:
            if set(addrs)=={'192.0.2.1','192.0.2.2'} and 24446 in ports and min(ports)>0:
                extra.add(tuple(sorted(ports)))
            continue
        at=int(Decimal(m[1])*10**9)
        dst=rows.setdefault(name,{})
        if m[2]=='inet_sk_error_report':
            dst.setdefault('first_error_ns',at)
            dst['errno']=int(p['error'])
            dst['error_count']=dst.get('error_count',0)+1
        else:
            old=STATES.get(p['oldstate'].removeprefix('TCP_'),0)
            new=STATES.get(p['newstate'].removeprefix('TCP_'),0)
            if new==1:
                dst['established_ns']=at
                dst['established_count']=dst.get('established_count',0)+1
            if old==1:
                dst.setdefault('left_established_ns',at)
                dst['next_state']=new
            if new==7: dst['closed_ns']=at
    return dict(lost=lost,sockets=rows,task_exits=exits,extra_tuples=len(extra))
