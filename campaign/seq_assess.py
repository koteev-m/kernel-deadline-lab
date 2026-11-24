"""Join socket observations, tc entry records and independently captured receiver frames."""
import ipaddress
import struct
import assess
from retrans import CLIENT, SERVER, SIZE

def pcap_matches(d, dev, index, version, local, remote, target):
    count=0
    for _,frame in assess.packets(d/(dev+'.pcap'),index):
        eth=int.from_bytes(frame[:2],'big')
        ip=frame[20:]
        if version==4 and eth==0x800 and ip[9]==6:
            off=(ip[0]&15)*4
            length=int.from_bytes(ip[2:4],'big')-off
            addresses=[ip[12:16],ip[16:20]]
            prefix='192.0.2.'
        elif version==6 and eth==0x86dd and ip[6]==6:
            off=40
            length=int.from_bytes(ip[4:6],'big')
            addresses=[ip[8:24],ip[24:40]]
            prefix='2001:db8:68::'
        else:
            continue
        if [str(ipaddress.ip_address(a)) for a in addresses]!=[prefix+str(local),prefix+str(remote)]:
            continue
        tcp=ip[off:]
        if len(tcp)<20: continue
        data_offset=(tcp[12]>>4)*4
        if (struct.unpack('!HHI',tcp[:8])==(CLIENT,SERVER,target) and length-data_offset==SIZE
            and tcp[data_offset:data_offset+SIZE]==bytes([local,version])*(SIZE//2)):
            count+=1
    return count

def flow(d, data, dev, peer, family, deadline, indexes):
    local=1 if dev=='uc0' else 2
    remote=3-local
    own=data[dev]
    app=[r for r in own['app'] if r.get('family')==family]
    peerapp=[r for r in data[peer]['app'] if r.get('family')==family]
    facts={}
    errors=[]
    def test(ok,code):
        if not ok:
            errors.append(code)
    def packets(which,hook,src,dst,sport,dport):
        return [r for r in data[which][hook] if (r['src'],r['dst'],r['family'],r['sport'],r['dport'])==
                (src,dst,family,sport,dport)]
    sent=[r for r in app if r['kind']=='sent']
    initial=[r for r in app if r['kind']=='connected']
    samples=[r for r in app if r['kind']=='info']
    test(len(initial)==len(sent)==1,'SINGLE_SOCKET_WRITE')
    if not initial or not sent: return dict(errors=errors)
    init=initial[0]
    identity=(init['pid'],init['cookie'],init['inode'])
    test(all((r['pid'],r['cookie'],r['inode'])==identity and r['state']==1 for r in initial+sent+samples),'SOCKET_ID_STATE')
    data_out=[r for r in packets(dev,'egress',local,remote,CLIENT,SERVER) if r['length']]
    test(bool(data_out),'NO_PRE_GATE_SEGMENT')
    if not data_out: return dict(errors=errors)
    seq=data_out[0]['seq']
    end=(seq+SIZE) % (1<<32)
    test(all(r['seq']==seq and r['length']==SIZE for r in data_out),'DIFFERENT_RANGE')
    before=[r for r in data_out if r['at']<deadline]
    after=[r for r in data_out if r['at']>=deadline]
    incoming=[r for r in packets(peer,'ingress',local,remote,CLIENT,SERVER) if r['length']]
    pre=[r for r in incoming if r['at']<deadline]
    late=[r for r in incoming if r['at']>=deadline]
    # A repeated segment already past the classifier before T may be received later.
    # Preserve ambiguity unless a post-T send can be unequivocally paired with delivery.
    test(not late,'RECEIVER_BOUNDARY')
    test(all(r['seq']==seq and r['length']==SIZE for r in incoming),'PEER_RANGE')
    test(len(pre)==len(before)>=2,'POSITIVE_WIRE_CONTROL')
    test(bool(after),'NO_POST_GATE_STIMULUS')
    wire=pcap_matches(d,peer,indexes[peer],family,local,remote,seq)
    test(wire==len(incoming) and wire>=2,'INDEPENDENT_PCAP')
    ack=[r for r in packets(dev,'ingress',remote,local,SERVER,CLIENT)
         if r['flags']&16 and r['ack']==end and before and r['at']>=before[0]['at']]
    drops=own['drops'][0 if family==4 else 1]
    test(drops>0 and bool(ack),'NO_COVERING_ACK_AT_INPUT')
    awaiting=[r for r in samples if sent[0]['at']<=r['at']<deadline and r['unacked']==1]
    post=[r for r in samples if r['at']>=deadline]
    test(bool(awaiting and post),'UNACKED_BEFORE_AND_POST_SAMPLE')
    test(all(r['acked']==init['acked'] for r in sent+samples),'COVERING_ACK_ACCEPTED')
    test(bool(post) and all(r['unacked']==1 for r in post),'OUTSTANDING_AFTER')
    positive=awaiting[-1]['total']-init['total'] if awaiting else 0
    delta=post[-1]['total']-awaiting[-1]['total'] if post and awaiting else 0
    test(positive>0 and delta>0,'TCP_INFO_RETRANS_DELTA')
    delivered=[r for r in peerapp if r['kind']=='delivered']
    test(len(delivered)==1 and delivered[0]['at']<deadline,'PEER_SINGLE_READ')
    facts.update(seq=seq,end_seq=end,cover_ack=ack[0]['ack'] if ack else 0,
                 first_ns=before[0]['at'] if before else 0, positive_ns=before[1]['at'] if len(before)>1 else 0,
                 first_post_ns=after[0]['at'] if after else 0, last_peer_ns=pre[-1]['at'] if pre else 0,
                 first_ack_ns=ack[0]['at'] if ack else 0, ack_drops=drops,
                 pid=identity[0],cookie=identity[1],inode=identity[2],
                 baseline_total=init['total'],delta_pre=positive,delta_post=delta,
                 unacked_before=awaiting[-1]['unacked'] if awaiting else 0,
                 unacked_after=post[-1]['unacked'] if post else 0,
                 bytes_acked_start=init['acked'],bytes_acked_end=post[-1]['acked'] if post else 0,
                 before=len(before),post=len(after),peer_post=len(late),pcap=wire,
                 peer_excess=len(incoming)>len(before) and bool(late) and wire==len(incoming),
                 verified=not errors)
    facts['errors']=errors
    return facts

def evaluate(d,t,indexes):
    data=assess.load(d/'probe.json')
    return {dev+str(f):flow(d,data,dev,peer,f,t,indexes)
            for dev,peer in [('uc0','up0'),('up0','uc0')] for f in (4,6)}
