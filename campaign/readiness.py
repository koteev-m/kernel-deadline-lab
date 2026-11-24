"""Non-arming diagnostic for the synthetic endpoints and their native capture processes."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess as sp
import time

def safe_note(line):
    if not isinstance(line,str) or not 0<len(line)<=400:
        return False
    line=line.replace('"',"'")
    if not re.fullmatch(r"[A-Za-z0-9 .,:'()\[\]_%=<>#+/-]+",line):
        return False
    return not re.search(r'[/\\]|[A-Fa-f0-9]{16,}|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|key=|token=|password|PRIVATE KEY',line,re.I)

def inspect_side(out,dev,app):
    rows=[json.loads(v) for v in (out/(dev+'.jsonl')).read_text().splitlines() if v.endswith('}')]
    ready=next((r for r in rows if r['kind']=='ready'),{})
    moved=next((r for r in rows if r['kind']=='migrated'),{})
    cookies={r['cookie'] for r in ready.get('sockets',[])}
    child=ready.get('child')
    code=app.poll()
    return dict(ready=bool(ready),migrated=bool(moved),app_running=code is None,app_exit=code,
                parent=app.pid,child=child,child_exists=bool(child and Path(f'/proc/{child}/stat').exists()),
                linked=bool(moved and child==moved['pid']),ns_changed=bool(moved and ready and moved['net']!=ready['net']),
                old_sockets=bool(moved and len(cookies)==1 and len(moved['retained'])==2 and
                                 set(moved['retained'])==cookies and moved['fresh'] not in cookies))

def do(lab,stack,out,ends,apps):
    names=[d for d,*_ in ends]
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        states={d:inspect_side(out,d,p) for d,p in zip(names,apps)}
        if all(s['ready'] and s['migrated'] for s in states.values()) or any(not s['app_running'] for s in states.values()):
            break
        time.sleep(.05)
    caps=[lab.capture(stack,ns,out,d) for d,ns,*_ in ends]
    until=time.monotonic()+5
    while time.monotonic()<until:
        if all(p.poll() is not None or 'listening on' in (out/(d+'.capture')).read_text() for d,p in zip(names,caps)):
            break
        time.sleep(.05)
    for (d,ns,*_),app,cap in zip(ends,apps,caps):
        s=inspect_side(out,d,app)
        s['capture_running']=cap.poll() is None
        if cap.poll() is None:
            cap.send_signal(signal.SIGINT)
        s['capture_exit']=cap.wait(timeout=3)
        s['capture_ready']='listening on' in (out/(d+'.capture')).read_text()
        notes=(out/(d+'.capture')).read_text().splitlines()
        diagnostic=sp.run([*ns,'tcpdump','-i','any','-L'],capture_output=True,text=True,timeout=5)
        notes.extend(diagnostic.stdout.splitlines()+diagnostic.stderr.splitlines())
        # Read the native counters before any controlled endpoint teardown.
        s['dlts_exit']=diagnostic.returncode
        s['pcap_header_bytes']=(out/(d+'.pcap')).stat().st_size
        if app.poll() is None:
            os.killpg(app.pid,signal.SIGTERM)
        s['app_exit_after_teardown']=app.wait(timeout=3)
        notes.extend((out/(d+'.stderr')).read_text().splitlines())
        scrubbed=[re.sub(r'/[a-zA-Z0-9._/-]+','[guest-path]',n.strip()) for n in notes]
        s['stderr']=[n for n in scrubbed if safe_note(n)][:24]
        lab.put(out/(d+'.instrument.json'),s)
