"""One manual job. Collect reduced measurements from isolated copy-on-write guests."""
from concurrent.futures import ThreadPoolExecutor
import base64
import itertools
import json
import struct
import zlib
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import subprocess as sp
import sys
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from readiness import safe_note
import xray_records

ROLES=['normal','late','loss','absent','wall','sleep','paused','delay','reboot']
PASS,FAIL,NP='PASS','FAIL','NOT_PROVEN'
def unique_fields(items):
    fields = dict(items)
    if len(fields) != len(items):
        raise ValueError('duplicate JSON field')
    return fields

def read(stream,kind,events):
    for line in stream:
        try:
            if len(line)>24000:
                raise ValueError('oversize record')
            value=json.loads(line, object_pairs_hook=unique_fields)
            if not isinstance(value,dict):
                raise ValueError('invalid record')
            events.put((kind,value))
        except (ValueError,UnicodeDecodeError):
            if kind=='serial':
                events.put((kind,{'event':'invalid_serial'}))
    events.put((kind,None))

def numeric_tree(value,key=''):
    if type(value) in (bool,int):
        return abs(value)<=10**20
    if isinstance(value,list):
        return len(value)<=(20 if key=='errors' else 5) and all(numeric_tree(x,key) for x in value)
    if isinstance(value,dict):
        return len(value)<80 and all(re.fullmatch(r'[a-z0-9_-]{1,40}',k) and numeric_tree(v,k) for k,v in value.items())
    if isinstance(value,str) and key in ('kernel_sha256','pcap_sha256'):
        return bool(re.fullmatch('[0-9a-f]{64}',value))
    if isinstance(value,str) and key in ('assessor_check','errors'):
        return bool(re.fullmatch('[A-Z][A-Z0-9_]{0,159}',value))
    return isinstance(value,str) and key in ('10','20') and bool(re.fullmatch('[0-9a-f]{16}',value))

XRAY_PARTS = frozenset({
    'duration','client_tcp','server_tcp','gate_before','gate_after','initial','before','crossed',
    'later','six','final','trace','uc0','up0','application_read_error','control_stream',
    'control_exchanges','firewall_same','foreign_alive','sentinel_intact','driver_exit',
})

def record_xray_part(evidence,message):
    key=message.get('key')
    data=message.get('data')
    trial=evidence.setdefault('trial',{})
    if not isinstance(key,str) or key not in XRAY_PARTS or key in trial or not numeric_tree(data):
        evidence['trial_record_errors']=evidence.get('trial_record_errors',0)+1
        return
    trial[key]=data
    if key in ('uc0','up0'):
        print('XRAY_WIRE',evidence['role'],key,json.dumps(data,separators=(',',':')),flush=True)

def receive_xray(e, message, books, challenge):
    event = message.get('event')
    try:
        if event == 'xray_part' and 'receipt_verified' not in e:
            record_xray_part(e, message)
        elif event == 'transport_case' and message.get('protocol') == 'reality' and 'transport' not in e and numeric_tree(message.get('data')) and 'receipt_verified' not in e:
            e['transport'] = {'reality': message['data']}
        elif event == 'rx_frames' and 'receipt_verified' not in e:
            side = message['side']
            books[side].add(message, e['armed_ticket'][1])
            print('XRAY_FRAMES', e['role'], side, message['offset'], message['rows'], flush=True)
        elif event == 'xray_receipt' and 'receipt_verified' not in e:
            e['frames'] = {side: book.summary() for side, book in books.items()}
            hashes = {side: book.raw_hash.hexdigest() for side, book in books.items()}
            expected = xray_records.receipt(challenge, e['armed_ticket'], e['trial'], e['transport']['reality'], hashes)
            e['receipt_verified'] = expected == message['digest']
        else:
            raise ValueError('unexpected or repeated record')
    except (ValueError, KeyError, IndexError, TypeError, struct.error):
        e['trial_record_errors'] = e.get('trial_record_errors', 0) + 1

def run_guest(work,role):
    evidence={'role':role}
    path=work/role
    path.mkdir()
    addr=path/'control'
    args=['qemu-system-x86_64','-nodefaults','-machine','q35,accel=kvm','-cpu','host','-smp','1',
          '-m','1152','-global','ICH9-LPC.disable_s3=0','-rtc','base=utc,clock=host','-display','none',
          '-monitor','none','-nic','none','-serial','file:'+str(path/'boot'),'-serial','stdio',
          '-qmp','unix:'+str(addr)+',server=on,wait=off','-kernel',work/'kernel','-initrd',work/'initrd',
          '-append','root=/dev/vda rootfstype=ext4 rw rootwait console=ttyS0 quiet systemd.show_status=false',
          '-drive','file='+str(work/'guest.ext4')+',if=virtio,format=raw,snapshot=on']
    bus=queue.Queue()
    challenge=secrets.token_hex(16)
    target_xray=role in ('xray-short','xray-proof')
    books={side:xray_records.FrameLedger() for side in xray_records.SIDES}
    with (path/'qemu').open('wb') as log,socket.socket(socket.AF_UNIX) as qmp:
        vm=sp.Popen(args,stdin=sp.PIPE,stdout=sp.PIPE,stderr=log,
                    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        try:
            end=time.monotonic()+820
            for i in range(250):
                if vm.poll() is not None:
                    raise RuntimeError('startup')
                try:
                    qmp.connect(str(addr)); break
                except (ConnectionRefusedError,FileNotFoundError):
                    time.sleep(.05)
            else:
                raise TimeoutError('socket')
            for stream,kind in [(qmp.makefile('rb'),'qmp'),(vm.stdout,'serial')]:
                threading.Thread(target=read,args=(stream,kind,bus),daemon=True).start()
            def ask(op):
                qmp.sendall((json.dumps({'execute':op,'id':op})+'\n').encode())
            def send(s):
                vm.stdin.write((s+'\n').encode())
                vm.stdin.flush()
            hello=started=rebooting=False
            sleep_at=wake_at=None
            while time.monotonic()<end:
                if sleep_at and not wake_at and time.monotonic()-sleep_at>=12:
                    wake_at=time.monotonic()
                    ask('system_wakeup')
                    evidence['qmp_sleep_to_request_ns']=int((wake_at-sleep_at)*10**9)
                try:
                    kind,m=bus.get(timeout=.15)
                except queue.Empty:
                    continue
                if m is None:
                    raise EOFError
                if kind=='qmp':
                    if 'QMP' in m:
                        ask('qmp_capabilities')
                    elif m.get('id')=='qmp_capabilities' and 'return' in m:
                        ask('query-kvm')
                    elif m.get('id')=='query-kvm':
                        evidence['kvm']=all(m.get('return',{}).get(k) is True for k in ('enabled','present'))
                        if not evidence['kvm']:
                            break
                    elif m.get('event')=='RESET' and rebooting:
                        evidence['qmp_reset']=True
                    elif m.get('event')=='SUSPEND' and role=='sleep' and evidence.get('sleep_intent'):
                        sleep_at=time.monotonic()
                    elif m.get('event')=='WAKEUP' and wake_at:
                        evidence['qmp_wakeup']=True
                else:
                    event=m.get('event')
                    if event=='hello' and m.get('rebooted') is False:
                        hello=True
                    elif event=='hello' and m.get('rebooted') is True and rebooting:
                        send('replay')
                    elif event=='identity':
                        v=m.get('versions',{})
                        if not (set(v)<=set('systemd nftables iproute2 libbpf1 clang-18 llvm-18 tcpdump libpcap0.8t64 python3 util-linux openssl kernel abi bpftool xray'.split())
                                and all(re.fullmatch('[0-9][a-zA-Z0-9:.+~_-]{0,60}',s) for s in v.values())):
                            raise ValueError('versions')
                        if target_xray and 'versions' in evidence:
                            raise ValueError('duplicate identity')
                        evidence['versions']=v
                    elif event=='armed' and type(m.get('deadline_ns')) is int:
                        if target_xray and 'armed_ticket' in evidence:
                            raise ValueError('duplicate ticket')
                        evidence['armed_ticket']=[m['start_ns'],m['deadline_ns']]
                        print('ARMED',role,*evidence['armed_ticket'],flush=True)
                    elif event=='rebooting' and role=='reboot':
                        rebooting=True
                        evidence['before_reboot']=m.get('before_deadline') is True
                    elif event=='replayed' and rebooting:
                        evidence['old_ticket_denied']=m.get('valid') is True and m.get('challenge')==challenge
                        break
                    elif event=='sleeping':
                        evidence['sleep_intent']=True
                    elif event=='clock' and numeric_tree([m['before'],m['after']]):
                        evidence['clock']=[m['before'],m['after']]
                    elif event=='instrument' and role=='inspect' and m.get('side') in ('uc0','up0'):
                        record=m['data']
                        notes=record.pop('stderr')
                        if isinstance(notes,list) and all(safe_note(line) for line in notes) and all(
                            re.fullmatch('[a-z_]+',k) and (v is None or type(v) in (bool,int)) for k,v in record.items()):
                            evidence[m['side']]=dict(record,stderr=notes)
                    elif event=='frame_times' and role in ('closure-short','wall-final','proxy-final'):
                        side=m.get('side')
                        n=m.get('n')
                        if type(n) is not int or not 1<=n<=240 or not isinstance(m.get('ticks'),str) or len(m['ticks'])>4096:
                            raise ValueError('receive batch bounds')
                        decoder=zlib.decompressobj()
                        raw=decoder.decompress(base64.b64decode(m['ticks'],validate=True),8*n+1)
                        if len(raw)!=8*n or not decoder.eof or decoder.unused_data:
                            raise ValueError('receive batch layout')
                        values=list(itertools.accumulate(struct.unpack('<'+'Q'*n,raw)))
                        if side not in ('uc0','up0') or not isinstance(values,list) or not 1<=len(values)<=240 or not all(type(v) is int and 0<v<10**16 for v in values):
                            raise ValueError('receive ledger format')
                        ledger=evidence.setdefault('ledger',{}).setdefault(side,dict(count=0,late=0,last=0))
                        if m.get('offset')!=ledger['count'] or values!=sorted(values) or values[0]<ledger['last']:
                            raise ValueError('receive ledger order')
                        deadline=evidence['armed_ticket'][1]
                        print('FRAME_TIMES',role,side,ledger['count'],','.join(map(str,values)),flush=True)
                        ledger['count']+=len(values)
                        ledger['late']+=sum(x>=deadline for x in values)
                        ledger['last']=values[-1]
                    elif target_xray and event in ('xray_part','transport_case','rx_frames','xray_receipt','xray_trial','invalid_serial'):
                        receive_xray(evidence,m,books,challenge)
                    elif event=='xray_part' and role in ('xray-short','xray-proof','xray-repro'):
                        record_xray_part(evidence,m)
                    elif event=='xray_trial' and role.startswith('xray-') and numeric_tree(m.get('data')):
                        evidence['trial']=m['data']
                    elif event=='transport_case' and m.get('protocol') in ('tls','reality') and numeric_tree(m.get('data')):
                        evidence.setdefault('transport',{})[m['protocol']]=m['data']
                    elif event=='proxy_stages' and numeric_tree(m.get('data')):
                        evidence['proxy_stages']=m['data']
                    elif event=='partial' and numeric_tree(m.get('data')):
                        evidence['partial']=m['data']
                    elif event=='measurement' and numeric_tree(m.get('data')):
                        evidence['measure']=m['data']
                    elif event=='detail' and m.get('label') in ('CAPTURE','BPF','LISTENER','STATS') and numeric_tree(m.get('fields')):
                        evidence.setdefault('detail',{})[m['label']]=m['fields']
                    elif event=='probe_note' and m.get('label') in ('uc0','up0','driver'):
                        if safe_note(m.get('text')):
                            evidence.setdefault('notes',[]).append([m['label'],m['text']])
                    elif event=='capture_diag' and type(m.get('code')) is int and 0<=m['code']<5:
                        evidence.setdefault('capture_diag',[]).append(m['code'])
                    elif event in ('fault','fatal'):
                        code=m.get('line',0)
                        diagnostics={'unknown','Operation not permitted','Permission denied','unknown option','No such file','listener owner','private PID','did not become ready','filter order','socket inode','wrong path','installer failed','test-run','foreign baseline','Invalid argument','capture failed','Operation not supported'}
                        evidence['fault']=[event,code if type(code) is int else 0,m.get('reason') if m.get('reason') in diagnostics else 'unknown']
                        if event=='fatal':
                            break
                    elif event in ('done','unavailable'):
                        if target_xray:
                            evidence['done']=event=='done'
                        break
                if hello and evidence.get('kvm') and not started:
                    started=True
                    send(role+' '+challenge)
            else:
                evidence['timeout']=True
        except Exception as exc:
            evidence['host_error']=type(exc).__name__
        finally:
            if vm.poll() is None:
                vm.terminate()
                try:
                    vm.wait(timeout=5)
                except sp.TimeoutExpired:
                    vm.kill()
                    vm.wait()
    print('EVIDENCE',json.dumps(evidence,separators=(',',':')),flush=True)
    return evidence

def judged(e):
    m=e.get('measure',{})
    if not m:
        return NP
    sides=[m['left'],m['right']]
    if any(p.get('peer_excess') for p in m.get('probes',{}).values()):
        return FAIL
    if m['origin_violations'] or any(s['wire_fresh'] or s['rx_after_new'] for s in sides):
        return FAIL
    role=e['role']
    closed=role in ('late','absent')
    if closed and any(s['wire_frames'] for s in sides):
        return FAIL
    if not(e.get('kvm') and m['driver_completed'] and m['source_assessor'] in (1,2)
           and e.get('armed_ticket')==[m['start_ns'],m['deadline_ns']]
           and m['duration_ns']==(35_000_000_000 if role in ('qualification','closure-short') else 600_000_000_000) and m['foreign_pid_same'] and m['firewall_same']
           and m['control_continuous'] and m['sentinel_intact']):
        return NP
    for s in sides:
        if not(s['frames_after_counter']>0 and s['listener_count']==2 and s['programs_unchanged']
               and s['test_after']==2 and s['test_before']==(2 if closed else 0)):
            return NP
        if role in ('closure-short','wall-final','proxy-final'):
            obs=s.get('rx_clock',{})
            ledger=e.get('ledger',{}).get('uc0' if s is sides[0] else 'up0',{})
            if not (ledger.get('count')==obs.get('matched') and ledger.get('late')==obs.get('at_or_after') and
                    ledger.get('last')==obs.get('last') and obs.get('kernel_sha256')==obs.get('pcap_sha256') and obs.get('kernel_sha256')):
                return NP
            if not (obs.get('matched')==s['wire_frames']==s['socket_kernel_frames'] and
                    obs.get('pre')==s['wire_frames']>0 and obs.get('at_or_after')==0 and
                    obs.get('reserve_drops')==obs.get('read_errors')==s['socket_drops']==0 and
                    0<obs['first']<=obs['last']<m['deadline_ns']):
                return NP
        elif not closed and (s['wire_boundary'] or s['wire_uncalibrated']):
            return NP
        if not closed and not all(s['established'+f] for f in ('4','6')):
            return NP
    if not closed:
        probes=m.get('probes',{})
        if set(probes)!={'uc04','uc06','up04','up06'} or not all(
                p.get('verified') and p['delta_post']>0 and p['delta_pre']>0 and p['pcap']>=2
                and p['post']>0 and p['peer_post']==0 for p in probes.values()):
            return NP
    if role in ('delay','paused','late'):
        least=min(s['attach_bracket_ns'][0] for s in sides)
        minimum=m['deadline_ns'] if role=='late' else m['start_ns']+30*10**9
        if least<minimum or (role=='paused' and m['stopped_ns']<30*10**9):
            return NP
    if role=='loss' and not m['installer_killed']:
        return NP
    if role in ('sleep','wall','closure-short','wall-final'):
        if 'clock' not in e:
            return NP
        a,b=e['clock']
        if role in ('wall','closure-short','wall-final'):
            if not(a[0]<=b[0]<m['deadline_ns'] and m['clock_segments']>=2 and b[2]-a[2]<-3599*10**9):
                return NP
        elif not(a[0]<m['deadline_ns']<b[0] and e.get('qmp_wakeup') and
                 abs((b[0]-a[0])-(b[1]-a[1])-e.get('qmp_sleep_to_request_ns',0))<2*10**9):
            return NP
    if role=='xray':
        x=m.get('proxy',{})
        if x.get('after',0):
            return FAIL
        if not (x.get('same') and x.get('listener') and x.get('live') and x.get('before') and x.get('post_tx') and e['versions'].get('xray')=='26.11.9'):
            return NP
    return PASS

def combine(*states):
    return FAIL if FAIL in states else NP if NP in states else PASS

def campaign(work):
    with ThreadPoolExecutor(max_workers=4) as workers:
        records=dict(zip(ROLES,workers.map(lambda role:run_guest(work,role),ROLES)))
    status={k:judged(v) for k,v in records.items()}
    n=records['normal'].get('measure',{})
    r=records['reboot']
    reboot=PASS if r.get('kvm') and r.get('before_reboot') and r.get('qmp_reset') and r.get('old_ticket_denied') else NP
    boundary=PASS if n.get('fallback_drop') and n.get('removed_qdisc_delivered') else NP
    positive=all(sum(n.get(side,{}).get('rx'+f+'_'+stream,0)>0 for f in ('4','6') for stream in ('tcp','new-tcp','udp','inherited-udp'))==8 for side in ('left','right'))
    a=PASS if positive and n.get('source_assessor') in (1,2) and n['duration_ns']==600_000_000_000 else NP
    synthetic={'A':combine(a,status['absent'],boundary),'B':status['normal'],'C':status['normal'],
               'D':status['delay'],'E':status['paused'],'F':combine(status['late'],status['normal']),
               'G':status['loss'],'H':combine(status['wall'],status['sleep']),'I':reboot,
               'J':PASS if all(v.get('measure',{}).get('sentinel_intact') and v['measure']['control_continuous']
                            and v['measure']['foreign_pid_same'] and v['measure']['firewall_same'] for k,v in records.items() if k!='reboot') else NP}
    proxy=NP
    if (a==PASS and FAIL not in synthetic.values() and n.get('sentinel_intact') and
        all(n[side]['programs_unchanged'] and n[side]['test_after']==2 and n[side]['frames_after_counter']>0
            and n[side]['wire_fresh']==n[side]['rx_after_new']==0 for side in ('left','right'))):
        proxy=judged(run_guest(work,'xray'))
    print('RESULT',json.dumps({'cases':synthetic,'series':status,'proxy':proxy,'boundary':boundary},sort_keys=True),flush=True)
    return 0 if set(synthetic.values())=={PASS} and proxy==PASS else 1

if __name__=='__main__':
    if sys.argv[2:]==['tls-inspect']:
        record=run_guest(Path(sys.argv[1]),'tls-inspect')
        sys.exit(0 if record.get('proxy_stages') else 1)
    if sys.argv[2:]==['inspect']:
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        record=run_guest(Path(sys.argv[1]),'inspect')
        complete=all(isinstance(record.get(d),dict) for d in ('uc0','up0'))
        print('RESULT',json.dumps({'diagnostic_complete':complete}),flush=True)
        sys.exit(0 if complete else 1)
    if sys.argv[2:]==['qualification']:
        record=run_guest(Path(sys.argv[1]),'qualification')
        quality=judged(record)
        print('QUALIFICATION',quality,flush=True)
        sys.exit(0 if quality==PASS else 1)
    sys.exit(campaign(Path(sys.argv[1])))
