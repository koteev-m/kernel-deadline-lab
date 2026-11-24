"""One short guest, then only the full measurements qualified on this exact disk."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import host

def proxy_ok(e,protocol):
    p=e.get('transport',{}).get(protocol,{})
    s=p.get('stages',{})
    result=p.get('end',{})
    t=e.get('measure',{}).get('deadline_ns',0)
    if not (e.get('versions',{}).get('xray')=='26.11.9' and p.get('step')==0
            and s.get('server_test_rc')==s.get('client_test_rc')==0 and
            all(s.get(k) is True for k in ('openssl_trust','echo_owner','server_owner','client_owner',
                                            'transport','authenticated_request','first_echo'))):
        return False
    if protocol=='reality':
        if not s.get('target_tls13_h2') or not all(
            e.get('measure',{}).get(side,{}).get('rx_clock',{}).get('reality_packets',0)>0
            for side in ('left','right')):
            return False
    return (all(result.get(k) is True for k in ('payload_provenance','same_transport','participants_alive','server_listener','client_listener'))
            and result.get('fresh_server')==result.get('fresh_replies')==0
            and result.get('server_pre',0)>=result.get('pre_replies',0)>1 and result.get('post_tx',0)>1
            and 0<result['last_reply'] and result['first_post']>=t>0)

def main(work):
    short=host.run_guest(work,'closure-short')
    wall_ok=host.judged(short)==host.PASS
    transport_ok=wall_ok and all(proxy_ok(short,p) for p in ('tls','reality'))
    print('QUALIFICATION',json.dumps(dict(wall=wall_ok,transport=transport_ok)),flush=True)
    result={}
    if wall_ok:
        result['wall']=host.judged(host.run_guest(work,'wall-final'))
    if transport_ok:
        actual=host.run_guest(work,'proxy-final')
        outcome=host.judged(actual)
        if actual.get('transport',{}).get('reality',{}).get('end',{}).get('fresh_server',0)>0:
            outcome=host.FAIL
        elif outcome==host.PASS and not proxy_ok(actual,'reality'):
            outcome=host.NP
        result['reality']=outcome
    print('TARGET_RESULT',json.dumps({k:result.get(k,host.NP) for k in ('wall','reality')}),flush=True)
    return 0 if list(result.values())==[host.PASS,host.PASS] else 1

if __name__=='__main__':
    sys.exit(main(Path(sys.argv[1])))
