"""Offline one-series guest. The host selects an enumerated role on a private serial port."""
import base64
import json
import struct
import zlib
import os
from pathlib import Path
import platform
import re
import subprocess as sp
import sys
import time
import traceback
import tty

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import lab
import measure

STATE=Path('/var/lib/native-series')
ROLES={'qualification','inspect','normal','absent','delay','paused','late','loss','wall','sleep','reboot','xray','tls-inspect','closure-short','wall-final','proxy-final','xray-repro','xray-short','xray-proof'}

def emit(event,**values):
    port.write((json.dumps(dict(event=event,**values),separators=(',',':'))+'\n').encode())

def sentinel(create=False):
    if create:
        sp.run(['nft','-f','-'],input='add table inet witness\nadd chain inet witness inventory\nadd rule inet witness inventory counter\n',text=True,check=True)
    rows=json.loads(lab.cmd('nft','-s','-j','list','table','inet','witness'))['nftables']
    return [r for r in rows if 'metainfo' not in r]

def identity():
    lab.preflight()
    lab.require(platform.release()=='6.8.0-48-generic' and '6.8.0-48.48' in Path('/proc/version_signature').read_text(),'ABI')
    lab.require(platform.machine()=='x86_64' and platform.freedesktop_os_release()['VERSION_ID']=='24.04' and Path('/proc/1/comm').read_text().strip()=='systemd','guest')
    versions={k:lab.cmd('dpkg-query','-W','-f=${Version}',k).strip() for k in ('systemd','nftables','iproute2','libbpf1','clang-18','llvm-18','tcpdump','libpcap0.8t64','python3','util-linux','openssl')}
    versions.update(kernel=platform.release(),abi='6.8.0-48.48',bpftool=re.search(r'bpftool v([0-9.]+)',lab.cmd('bpftool','version'))[1])
    if (HERE/'xray').exists() and ROLE in ('xray','tls-inspect','closure-short','proxy-final','xray-repro','xray-short','xray-proof'):
        v=lab.cmd(HERE/'xray','version').split()
        lab.require(v[:2]==['Xray','26.11.9'],'proxy version')
        versions['xray']=v[1]
    emit('identity',versions=versions)

def observed(out):
    if not (out/'watch.json').is_file():
        return False
    for dev in ('uc0','up0'):
        with (out/(dev+'.jsonl')).open('rb') as f:
            if b'"kind": "rx"' not in f.read(4_000_000):
                return False
    return True

def clocks():
    return [lab.now(),time.monotonic_ns(),time.time_ns()]

def main():
    global ROLE
    ROLE='reboot'
    emit('hello',rebooted=STATE.exists() and (STATE/'reboot').is_file())
    command=port.readline(100).decode().strip().split()
    if command==['replay']:
        identity()
        saved=json.loads((STATE/'reboot').read_text())
        process=sp.run([sys.executable,'-I','-B',HERE/'lab.py','old-boot',STATE/'data'],capture_output=True,text=True,timeout=20)
        emit('replayed',valid=process.returncode==0 and process.stdout.startswith('OLD_BOOT_DENIED ') and saved['boot']!=lab.boot(),
             challenge=saved['challenge'])
        return
    role,challenge=command
    ROLE=role
    lab.require(role in ROLES and re.fullmatch('[a-f0-9]{32}',challenge),'role')
    identity()
    if role=='xray' and not (HERE/'xray').exists():
        emit('unavailable')
        return
    STATE.mkdir(mode=0o700)
    out=STATE/'data'
    fw=sentinel(True)
    lab.require([list(r) for r in fw]==[['table'],['chain'],['rule']],'sentinel')
    mode='normal' if role in {'wall','sleep','reboot'} else role
    if role=='tls-inspect':
        mode='xray'
    # Only the normal series runs the destructive, disposable qdisc boundary control.
    env=dict(os.environ,LAB_BOUNDARY='1' if role=='normal' else '0')
    env['LAB_INSPECT_TLS']='1' if role=='tls-inspect' else '0'
    if role in ('closure-short','wall-final','proxy-final'):
        mode='qualification' if role=='closure-short' else 'normal'
        env['LAB_TARGET']=role
    if role in ('xray-repro','xray-short','xray-proof'):
        env['LAB_TARGET']=role
        mode='normal' if role=='xray-proof' else 'qualification'
    with (STATE/'private-driver.log').open('wb') as private:
        proc=sp.Popen([sys.executable,'-I','-B',HERE/'lab.py',mode,out],
                      stdout=private,stderr=private,env=env)
        touched=False
        watching=False
        while proc.poll() is None:
            if not watching and (out/'watch.json').exists():
                ticket=measure.read(out,'ticket')
                watching=True
                emit('armed',start_ns=ticket['start'],deadline_ns=ticket['deadline'])
            if watching and not touched and role in ('reboot','wall','sleep','closure-short','wall-final'):
                remain=ticket['deadline']-lab.now()
                if (role=='reboot' or remain<5_000_000_000) and observed(out):
                    touched=True
                    if role=='reboot':
                        lab.put(STATE/'reboot',dict(boot=lab.boot(),challenge=challenge))
                        os.sync()
                        emit('rebooting',before_deadline=lab.now()<ticket['deadline'])
                        sp.run(['systemctl','--no-block','reboot'],check=True)
                        while True: time.sleep(1)
                    a=clocks()
                    if role=='sleep':
                        power=Path('/sys/power/mem_sleep')
                        power.write_text('deep')
                        lab.require('[deep]' in power.read_text(),'deep sleep')
                        emit('sleeping')
                        Path('/sys/power/state').write_text('mem')
                    else:
                        time.clock_settime_ns(time.CLOCK_REALTIME,time.time_ns()-3600*10**9)
                    b=clocks()
                    lab.put(STATE/'clock-event',dict(before=a,after=b))
                    emit('clock',before=a,after=b)
            time.sleep(.18)
    if (out/'xray-trial.json').exists():
        trial=measure.read(out,'xray-trial')
        trial['sentinel_intact']=sentinel()==fw
        trial['driver_exit']=proc.returncode
        emit('xray_trial',data=trial)
    for protocol in ('tls','reality'):
        if (out/protocol/'status.json').is_file():
            status=measure.read(out/protocol,'status')
            if (out/protocol/'end.json').is_file():
                status['end']=measure.read(out/protocol,'end')
            emit('transport_case',protocol=protocol,data=status)
    if (out/'proxy-stages.json').exists():
        emit('proxy_stages',data=measure.read(out,'proxy-stages'))
    if role=='inspect':
        for dev in ('uc0','up0'):
            note=out/(dev+'.instrument.json')
            if note.is_file():
                emit('instrument',side=dev,data=json.loads(note.read_text()))
    if proc.returncode:
        partial={'driver_exit':proc.returncode}
        for dev in ('uc0','up0'):
            pe=out/(dev+'.probe-error')
            if pe.exists():
                for ln in pe.read_text().splitlines():
                    if re.fullmatch(r'(?:ValueError|PermissionError|TimeoutError|ConnectionRefusedError|OSError): [A-Za-z0-9 _.,:\[\]-]{1,90}',ln):
                        emit('probe_note',label=dev,text=ln)
        if (out/'environment.json').exists():
            for side in ('uc0','up0'):
                log=out/(side+'.capture')
                if log.exists():
                    notes=[json.loads(s) for s in log.read_text().splitlines() if s.startswith('{') and s.endswith('}')]
                    partial[side+'_capture_bound']=any('bound' in v for v in notes)
                    for v in notes:
                        if 'error' in v:
                            emit('probe_note',label=side,text=v.get('reason','unknown'))
                        if 'frames' in v: partial[side+'_frames']=v['frames']
        mark=(STATE/'private-driver.log').read_text(errors='replace')
        for entry in mark.splitlines():
            if any(tag in entry for tag in ('libbpf:', 'Error:', ' error:', 'RTNETLINK', 'Cannot find', 'Unknown argument')):
                import readiness
                safe=re.sub(r'/[A-Za-z0-9._/-]+','[guest-path]',entry.strip()[:200])
                if readiness.safe_note(safe):
                    emit('probe_note',label='driver',text=safe)
            if entry.startswith('lab-sites '):
                partial['sites']=[int(i) for i in entry.split()[1:] if i.isdigit()][-5:]
            elif entry.startswith('lab-fault ') or entry.startswith('Error:') or entry.startswith('RTNETLINK answers:'):
                import readiness
                safe=re.sub(r'/[a-zA-Z0-9._/-]+','[guest-path]',entry[:250])
                if readiness.safe_note(safe):
                    emit('probe_note',label='driver',text=safe)
        for key in ('CAPTURE','BPF','LISTENER','STATS'):
            for line in mark.splitlines():
                if line.startswith(key+'_DETAIL '):
                    emit('detail',label=key,fields=json.loads(line.split(' ',1)[1]))
        if (out/'readiness-fault.json').is_file():
            partial['readiness']=measure.read(out,'readiness-fault')
        if (out/'ticket.json').is_file():
            t=measure.read(out,'ticket')
            partial.update(start_ns=t['start'],deadline_ns=t['deadline'])
        for key in ('attached','watch','end'):
            partial[key]=(out/(key+'.json')).is_file()
        for dev in ('uc0','up0'):
            file=out/(dev+'.jsonl')
            if file.is_file():
                rows=[json.loads(x) for x in file.read_text().splitlines() if x.endswith('}')]
                t=partial.get('deadline_ns')
                partial[dev+'_migrated']=any(r['kind']=='migrated' for r in rows)
                for f in ('4','6'):
                    for stream in ('udp','tcp','new-tcp','inherited-udp'):
                        partial[dev+f+'_'+stream]=sum(r['kind']=='rx' and r['family']==f and r['stream']==stream for r in rows)
                if t:
                    partial[dev+'_fresh_late_rx']=sum(r['kind']=='rx' and r['sent']>=t for r in rows)
                partial[dev+'_ready']=any(r['kind']=='ready' for r in rows)
                partial[dev+'_rx']=sum(r['kind']=='rx' for r in rows)
        emit('partial',data=partial)
        for dev in ('uc0','up0'):
            path=out/(dev+'.capture')
            if path.exists():
                detail=path.read_text(errors='replace')
                for token in ('Permission denied','Operation not permitted','syntax error','not supported','listening on'):
                    if token in detail:
                        emit('capture_diag',code=('Permission denied','Operation not permitted','syntax error','not supported','listening on').index(token))
        # Only source locations, fixed diagnostic names and integer exit status leave the guest.
        lines=(STATE/'private-driver.log').read_text(errors='replace').splitlines()
        mark=next((s for s in reversed(lines) if s.startswith('lab-fault ')), '')
        match=re.match(r'lab-fault (\d+) (\w+)',mark)
        diagnostic=next((w for w in ('Operation not permitted','Permission denied','unknown option','No such file','listener owner','private PID','did not become ready','filter order','socket inode','wrong path','installer failed','test-run','foreign baseline','Invalid argument','capture failed','Operation not supported') if any(w in s for s in lines)), 'unknown')
        emit('fault',line=int(match[1]) if match else 0,reason=diagnostic,rc=proc.returncode)
    if (out/'end.json').exists() and (out/'control.snapshot').exists():
        report=measure.measure(out,role)
        report['driver_completed']=proc.returncode==0
        report['sentinel_intact']=sentinel()==fw and len(fw)==3
        if role=='xray' and (out/'proxy-end.json').is_file():
            report['proxy']=measure.read(out,'proxy-end')
        emit('measurement',data=report)
        if role in ('closure-short','wall-final','proxy-final'):
            import rx_clock
            def frame_batch(side,offset,values):
                raw=struct.pack('<'+'Q'*len(values),values[0],*[b-a for a,b in zip(values,values[1:])])
                emit('frame_times',side=side,offset=offset,n=len(values),ticks=base64.b64encode(zlib.compress(raw)).decode('ascii'))
            for side in ('uc0','up0'):
                with (out/(side+'.clock')).open('rb') as journal:
                    batch=[]
                    offset=0
                    for raw in iter(lambda:journal.read(rx_clock.ROW.size),b''):
                        at=rx_clock.ROW.unpack(raw)[1]
                        batch.append(at)
                        if len(batch)==240:
                            frame_batch(side,offset,batch)
                            offset+=len(batch)
                            batch=[]
                    if batch:
                        frame_batch(side,offset,batch)
    emit('done')

if __name__=='__main__':
    fd=os.open('/dev/ttyS1',os.O_RDWR|os.O_NOCTTY)
    tty.setraw(fd)
    port=os.fdopen(fd,'r+b',buffering=0)
    try:
        main()
    except Exception as exc:
        trace=traceback.extract_tb(exc.__traceback__)
        emit('fatal',line=trace[-1].lineno,kind=type(exc).__name__,
             module=Path(trace[-1].filename).stem if Path(trace[-1].filename).parent==HERE else 'system')
