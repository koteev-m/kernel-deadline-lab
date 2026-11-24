"""Qualify this meter once. Run the original 600 s interval only on measured qualification."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import host
from transport_wire import FIELDS

PROPERTIES = ('NETWORK_DEADLINE','PERSISTENT_CONNECTION_AT_CUTOFF','CONNECTION_SURVIVAL_AT_FINAL_OBSERVATION',
              'XRAY_PROCESS_AND_LISTENER','TERMINAL_SOCKET_REASON')


def counters(part, keys):
    return set(part)==set(keys) and all(type(part[key]) is int and part[key]>=0 for key in keys)


def attempt_period(row, t, after):
    if not counters(row, FIELDS) or max(row['payload_frames'],row['fin'],row['rst'])>row['frames']:
        return False
    if not row['frames']:
        return not any(row.values())
    if not (0<row['first']<=row['last'] and (row['first']>=t if after else row['last']<t)):
        return False
    if row['payload_frames']:
        return row['payload_bytes']>=row['payload_frames'] and row['first']<=row['first_data']<=row['last_data']<=row['last']
    return all(row[k]==0 for k in ('payload_bytes','first_data','last_data','first_seq','last_seq'))

def decide(e,seconds):
    trial=e.get('trial',{})
    p=e.get('transport',{}).get('reality',{})
    s=p.get('stages',{})
    z=p.get('end',{})
    checks={}
    metrics={}
    properties=dict.fromkeys(PROPERTIES,'NOT_PROVEN')
    try:
        checks['complete_telemetry']=(e.get('done') is True and e.get('receipt_verified') is True and
            e.get('trial_record_errors',0)==0 and set(trial)==host.XRAY_PARTS-{'application_read_error'} and
            not any(k in e for k in ('host_error','fault','timeout')))
        start,t=e['armed_ticket']
        checks['guest']=e['kvm'] and e['versions']['xray']=='26.11.9' and e['versions']['kernel']=='6.8.0-48-generic' and e['versions']['abi']=='6.8.0-48.48'
        checks['deadline']=t-start==trial['duration']==seconds*10**9
        checks['baseline']=trial['driver_exit']==0 and all(trial[k] for k in ('control_stream','foreign_alive','firewall_same','sentinel_intact'))
        checks['gates']=trial['gate_before']==trial['gate_after'] and all(set(trial['gate_after'][k])=={'10','20'} for k in ('uc0','up0'))
        checks['authenticated']=p['step']==0 and s['client_test_rc']==s['server_test_rc']==0 and all(s[k] for k in
            ('first_echo','openssl_trust','server_owner','client_owner','echo_owner','target_tls13_h2','transport','authenticated_request'))
        checks['provenance']=z['payload_provenance'] and z['pre_replies']>1 and z['server_pre']>=z['pre_replies'] and z['created_after']>0 and z['post_tx']>0
        checks['application_cut']=z['fresh_server']==z['fresh_replies']==0 and z['server_listener'] and z['client_listener']
        checks['socket_paths']=True
        for phase in ('initial','before','crossed','later','six','final'):
            sample=trial[phase]
            for side in ('client','server'):
                path=sample['path_'+side]
                original=trial['initial']['path_'+side]
                checks['socket_paths'] &= (path==original or (phase in ('six','final') and path==[])) and len(original)==3
        a,b=trial['crossed'],trial['later']
        checks['xray_processes']=all(
            trial[phase]['processes'][side]==trial['initial']['processes'][side] and
            trial[phase]['processes'][side]['alive'] is True and trial[phase]['processes'][side]['pid']>0
            for phase in ('before','crossed','later','six','final') for side in ('client','server'))
        checks['live_at_cut']=trial['before']['end']<t<=a['begin']<a['end']<b['begin']<b['end'] and all(
            v['external_'+side][0]['ino']==s['initial_'+side+'_inode'] and v['external_'+side][0]['state']==1
            for side in ('client','server') for v in (trial['initial'],trial['before'],a,b))
        local_a,local_b=a['inbound_client'][0],b['inbound_client'][0]
        for key,readback in [('crossed',local_a),('later',local_b)]:
            # Linux established idiag_rqueue is rcv_nxt - copied_seq.
            metrics[key+'_local_consumed_bytes']=readback['bytes_received']-readback['recv_q']
        metrics['local_whole_messages_after_lower_bound']=(metrics['later_local_consumed_bytes']//16-
                                  (metrics['crossed_local_consumed_bytes']+15)//16)
        checks['local_xray_reads']=local_a['ino']==local_b['ino'] and local_a['state']==local_b['state']==1 and metrics['local_whole_messages_after_lower_bound']>0
        # Established TCP write_seq delta. The cumulative ACK counter and Send-Q
        # are compared for the same socket on a stable ACK frontier after T.
        x,y=a['external_client'][0],b['external_client'][0]
        metrics['post_external_submitted_bytes']=y['bytes_acked']+y['send_q']-x['bytes_acked']-x['send_q']
        checks['transport_writes']=metrics['post_external_submitted_bytes']>0 and x['bytes_acked']==y['bytes_acked']
        for side in ('uc0','up0'):
            v=trial[side]; w=v['wire']; c=v['capture']; attempt=v['attempt']
            book=e['frames'][side]
            ints='matched pre at_or_after first last reality_packets reality_late reserve_drops read_errors'.split()
            checks[side+'_structure']=(set(v)=={'attempt','wire','capture'} and set(attempt)=={'before','after'} and
                counters(c,('drops','frames','kernel')) and counters({k:v for k,v in w.items() if k not in ('kernel_sha256','pcap_sha256')},ints) and
                attempt_period(attempt['before'],t,False) and attempt_period(attempt['after'],t,True))
            checks[side+'_ledger']=(book['count']==w['matched']==w['pre']+w['at_or_after'] and
                book['late']==w['at_or_after'] and book['first']==w['first'] and book['last']==w['last'] and
                book['pcap_sha256']==w['pcap_sha256'])
            checks[side+'_capture']=(0<w['reality_packets']<=w['matched']==c['frames']==c['kernel'] and
                c['drops']==w['reserve_drops']==w['read_errors']==w['at_or_after']==w['reality_late']==0 and
                w['pcap_sha256']==w['kernel_sha256'] and w['last']<t)
            checks[side+'_pre_gate']=attempt['before']['payload_frames']>0 and attempt['before']['last']<t
        post=trial['up0']['attempt']['after']
        checks['live_post_frames']=post['payload_frames']>0 and t<=post['first_data']<b['begin'] and t<=post['first']<=post['last']
        trace=trial['trace']
        client_trace=trace['sockets']['external_client']
        server_trace=trace['sockets']['external_server']
        checks['no_replacement']=trace['lost']==trace['extra_tuples']==0 and client_trace['established_count']==server_trace['established_count']==1
        established=all(0<row['established_ns']<t for row in (client_trace,server_trace))
        no_early_close=all(row.get('left_established_ns', b['end']+1)>b['end'] for row in (client_trace,server_trace))
        checks['original_during_attempt']=established and no_early_close and checks['live_at_cut'] and checks['live_post_frames']
        final=trial['final']
        persistent=bool(z['same_transport'] and all(
            final['external_'+side] and final['external_'+side][0]['ino']==s['initial_'+side+'_inode'] and
            final['external_'+side][0]['state']==1 and 'left_established_ns' not in row
            for side,row in [('client',client_trace),('server',server_trace)]))
        closed=client_trace.get('closed_ns',0)
        timeout=False
        if not persistent and closed:
            stream=p['children']['stream']
            error_at=client_trace.get('first_error_ns',0)
            left=client_trace.get('left_established_ns',0)
            stream_end=stream.get('exit_boot_ns',0)
            metrics.update(external_error_ns=error_at,external_end_ns=closed,stream_end_ns=stream_end,
                           errno=client_trace.get('errno',0))
            timeout=(client_trace.get('errno')==110 and client_trace.get('error_count')==1 and
                b['end']<error_at<=left<=closed<=final['end'] and client_trace.get('next_state')==7 and
                not final['external_client'] and closed-2_000_000<=stream_end<=final['end'] and
                stream.get('reason') in (1,2) and stream.get('rc') in (1,2) and
                trace['task_exits'].get('measure-stream',{}).get('at',0)>=stream_end-2_000_000)
        trusted=checks['complete_telemetry']
        if trusted:
            if checks['no_replacement'] and checks['live_at_cut'] and checks['original_during_attempt']:
                properties['PERSISTENT_CONNECTION_AT_CUTOFF']='PASS'
            if z['server_listener'] and z['client_listener'] and checks['xray_processes']:
                properties['XRAY_PROCESS_AND_LISTENER']='PASS'
            if persistent:
                properties['CONNECTION_SURVIVAL_AT_FINAL_OBSERVATION']='PASS'
                properties['TERMINAL_SOCKET_REASON']='OPEN_AT_FINAL'
            elif closed and closed<=final['end']:
                properties['CONNECTION_SURVIVAL_AT_FINAL_OBSERVATION']='FAIL'
                if timeout:
                    properties['TERMINAL_SOCKET_REASON']='ETIMEDOUT'
        if all(checks.values()):
            properties['NETWORK_DEADLINE']='PASS'
        checks['terminal_explained']=persistent or timeout
        qualified=all(checks.values())
        return dict(qualified=qualified,persistent=persistent,checks=checks,metrics=metrics,properties=properties,
                    result='PASS' if qualified else 'NOT_PROVEN')
    except (KeyError,IndexError,TypeError,ValueError) as exc:
        missing=exc.args[0] if isinstance(exc,KeyError) else type(exc).__name__
        return dict(qualified=False,persistent=False,checks=checks,metrics=metrics,
                    missing=str(missing)[:60],properties=properties,result='NOT_PROVEN')

if __name__=='__main__':
    work=Path(sys.argv[1])
    short=decide(host.run_guest(work,'xray-short'),35)
    print('QUALIFICATION',json.dumps(short),flush=True)
    if not short['qualified']:
        print('FINAL',json.dumps({'run':False,'result':'NOT_PROVEN'}),flush=True)
        sys.exit(1)
    full=decide(host.run_guest(work,'xray-proof'),600)
    print('FINAL',json.dumps(dict(run=True,**full)),flush=True)
    sys.exit(0 if full['result']=='PASS' else 1)
