"""Qualify this meter once. Run the original 600 s interval only on measured qualification."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import host

def decide(e,seconds):
    trial=e.get('trial',{})
    p=e.get('transport',{}).get('reality',{})
    s=p.get('stages',{})
    z=p.get('end',{})
    checks={}
    metrics={}
    try:
        start,t=e['armed_ticket']
        checks['guest']=e['kvm'] and e['versions']['xray']=='26.11.9' and e['versions']['kernel']=='6.8.0-48-generic' and e['versions']['abi']=='6.8.0-48.48'
        checks['deadline']=t-start==trial['duration']==seconds*10**9
        checks['baseline']=trial['driver_exit']==0 and all(trial[k] for k in ('control_stream','foreign_alive','firewall_same','sentinel_intact'))
        checks['gates']=trial['gate_before']==trial['gate_after'] and all(set(trial['gate_after'][k])=={'10','20'} for k in ('uc0','up0'))
        checks['authenticated']=p['step']==0 and s['client_test_rc']==s['server_test_rc']==0 and all(s[k] for k in
            ('first_echo','server_owner','client_owner','echo_owner','target_tls13_h2','transport','authenticated_request'))
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
        checks['live_at_cut']=t<=a['begin']<a['end']<b['begin'] and all(
            v['external_'+side][0]['ino']==s['initial_'+side+'_inode'] and v['external_'+side][0]['state']==1
            for side in ('client','server') for v in (a,b))
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
        # Qualifying the instruments includes observing a genuine later TCP close.
        # Long-lived connection acceptance is decided separately and remains mandatory for PASS.
        persistent=bool(z['same_transport'] and z['participants_alive'] and 'left_established_ns' not in client_trace and
                        'left_established_ns' not in server_trace)
        if not persistent:
            stream=p['children']['stream']
            closed=client_trace.get('left_established_ns',0)
            closed_at=stream.get('exit_boot_ns',0)
            metrics['external_end_ns']=closed
            metrics['stream_end_ns']=closed_at
            checks['qualified_terminal_observation']=(closed>b['end'] and closed_at>=closed-2_000_000 and
                client_trace.get('errno',0)>0 and client_trace.get('first_error_ns',0)>=t and
                stream.get('reason') in (1,2) and stream.get('rc') in (1,2) and
                trace['task_exits'].get('measure-stream',{}).get('at',0)>=closed_at-2_000_000)
        qualified=all(checks.values())
        return dict(qualified=qualified,persistent=persistent,checks=checks,metrics=metrics,
                    result='PASS' if qualified and persistent else 'NOT_PROVEN')
    except (KeyError,IndexError,TypeError,ValueError) as exc:
        missing=exc.args[0] if isinstance(exc,KeyError) else type(exc).__name__
        return dict(qualified=False,persistent=False,checks=checks,metrics=metrics,
                    missing=str(missing)[:60],result='NOT_PROVEN')

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
