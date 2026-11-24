"""Reduce private packet/transport observations to typed numeric evidence."""
import bisect
import contextlib
import io
import json
from pathlib import Path
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import assess
import seq_assess

def read(d,name):
    return assess.load(d/(name+'.json'))

def measure(d,role):
    ticket=read(d,'ticket')
    start,t=ticket['start'],ticket['deadline']
    arm,watch,end=(read(d,k) for k in ('attached','watch','end'))
    report={'start_ns':start,'deadline_ns':t,'duration_ns':t-start,'armed_ns':arm['at']}
    probes={} if role in ('late','absent') else seq_assess.evaluate(d,t,watch['ifindexes'])
    report['probes']=probes
    output=io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            assess.assess(d,qualification=role in ("qualification","closure-short"),probes=probes)
        original=json.loads(output.getvalue())
    except (KeyError,IndexError,StopIteration,ValueError) as exc:
        original={}
        name=re.sub('[^A-Z0-9]+','_',str(exc).upper()).strip('_')
        report['assessor_check']=name[:160] if isinstance(exc,ValueError) and name else type(exc).__name__.upper()
        report['assessor_line']=__import__('traceback').extract_tb(exc.__traceback__)[-1].lineno
    report['source_assessor']={'SYNTHETIC_CASE_OBSERVED':1,'REVIEW_REQUIRED':2,'DELIVERY_VIOLATION':3}.get(original.get('status'),0)
    report['origin_violations']=len(original.get('violations',[]))
    report['foreign_pid_same']=watch['protected_pid']==end['protected_pid']
    report['firewall_same']=watch['firewall_before']==end['firewall_after']
    control=assess.lines(d/'control.snapshot')
    report['control_exchanges']=len(control)
    report['control_continuous']=len({(r['pid'],tuple(r['connection'])) for r in control})==1 and control[0]['at']<t<control[-1]['at']
    report['installer_killed']=watch['installer']=='SIGKILL'
    if role=='paused':
        pause=read(d,'installer-pause')
        report['stopped_ns']=pause['end']-pause['begin']
    if role=='normal' and (d/'boundary.json').is_file():
        report.update(read(d,'boundary'))
    # Construct calibrated segments. Never interpolate through S3 or a realtime step.
    samples=assess.lines(d/'clocks.jsonl')
    segments=[[]]
    for sample in samples:
        if segments[-1]:
            last=segments[-1][-1]
            if sample[0]-last[0]>1_000_000_000 or abs((sample[1]-sample[0])-(last[1]-last[0]))>2_000_000:
                segments.append([])
        segments[-1].append(sample)
    intervals=[([r[1] for r in part],part) for part in segments]
    report['clock_segments']=len(intervals)
    before_mode=role not in ('absent','late')
    marker=re.compile(rb'U6K\|'+ticket['run'].encode()+rb'\|[cp]\|[46]\|[a-z-]+\|\d+\|(\d+)\n')
    for dev,key in [('uc0','left'),('up0','right')]:
        side={}
        report[key]=side
        rows=assess.lines(d/(dev+'.snapshot'))
        capture_log=(d/(dev+'.capture')).read_text().splitlines()
        counter=json.loads(capture_log[-1])
        side['socket_kernel_frames']=counter['kernel']
        side['socket_drops']=counter['drops']
        side['listener_count']=len(end['listeners'][dev])
        side['frames_after_counter']=end['state'][dev]['packet_attempts']-end['first'][dev]
        side['attach_bracket_ns']=arm['intervals'].get(dev,[])
        def programs(state):
            return {str(r['pref']):[r['options']['prog']['id'],r['options']['prog']['tag']]
                    for r in state['tc'] if r['kind']=='bpf' and r['pref'] in (10,20) and 'options' in r}
        side['programs']=programs(arm['states'][dev])
        side['programs_unchanged']=side['programs']==programs(end['state'][dev])
        side['test_before']=next(x['action'] for x in watch['brackets'] if x['dev']==dev)
        side['test_after']=next(x['action'] for x in end['brackets'] if x['dev']==dev)
        rx=[r for r in rows if r['kind']=='rx']
        tx=[r for r in rows if r['kind'] in ('tx','connect')]
        side['rx_after_new']=sum(r['sent']>=t for r in rx)
        side['rx_after_old']=sum(r['at']>=t>r['sent'] for r in rx)
        side['last_sent_delivered_ns']=max((r['sent'] for r in rx),default=0)
        side['last_rx_ns']=max((r['at'] for r in rx),default=0)
        side['first_new_tx_ns']=min((r['at'] for r in tx if r['at']>=t),default=0)
        for family in ('4','6'):
            for stream in ('tcp','udp','inherited-udp','new-tcp'):
                group=[r for r in rx if r['family']==family and r['stream']==stream]
                side['rx'+family+'_'+stream]=len(group)
                side['post'+family+'_'+stream]=sum(r['family']==family and r['stream']==stream and r['at']>=t for r in tx)
            info=[r for r in rows if r['kind']=='tcp-info' and r['family']==family]
            old=[r for r in info if r['at']<t]
            after=[r for r in info if old and r['at']>=t and r['connection']==old[-1]['connection'] and r['state']==1]
            side['established'+family]=bool(after and old[-1]['state']==1)
            side['retrans'+family]=max((r['retrans']-old[-1]['retrans'] for r in after),default=0)
        wire=unsigned=ambiguous=fresh=0
        # First and last calibration points only bound their local epoch. Associate early
        # setup captures using the first epoch only if strictly separated from all late times.
        for ts,frame in assess.packets(d/(dev+'.pcap'),watch['ifindexes'][dev]):
            wire+=1
            fresh+=sum(int(m[1])>=t for m in marker.finditer(frame))
            limits=[]
            for times,part in intervals:
                pos=bisect.bisect_left(times,ts)
                if 0<pos<len(part):
                    pair=part[pos-1:pos+1]
                    limits.append(max(ts+r[2]-r[1] for r in pair)+1_000_000)
            if not limits:
                # Known captures before clock sampling began. A later backwards step can
                # overlap old wall times, so use all epochs conservatively.
                possible=[ts+part[0][2]-part[0][1]+2_000_000 for times,part in intervals
                          if times[0]-90_000_000_000<=ts<=times[-1]+2_000_000]
                if not possible or max(possible)>=t:
                    ambiguous+=1
            elif max(limits)>=t:
                unsigned+=1
        if role in ('closure-short','wall-final','proxy-final'):
            import rx_clock
            side['rx_clock']=rx_clock.compare(d,dev,watch['ifindexes'][dev],t)
        side.update(wire_frames=wire,wire_fresh=fresh,wire_boundary=unsigned,wire_uncalibrated=ambiguous)
    return report
