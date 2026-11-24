"""Exercise the actual guest encoder, serial reader, collector and final assessor offline."""
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
from pathlib import Path
import queue
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent/'campaign'))
import full_guest
import host
import rx_clock
import xray_only
import xray_records

T = 36_000_000_000
CHALLENGE = '0' * 32


def fixture():
    trial = dict(duration=35_000_000_000, driver_exit=0, control_stream=True, foreign_alive=True,
                 firewall_same=True, sentinel_intact=True, control_exchanges=4, client_tcp={}, server_tcp={})
    trial['gate_before'] = {dev:{'10':[3,'0'*16], '20':[4,'1'*16]} for dev in xray_records.SIDES}
    trial['gate_after'] = deepcopy(trial['gate_before'])
    for phase, begin in [('initial',T-10**9), ('before',T-10**7), ('crossed',T), ('later',T+2*10**9),
                         ('six',T+6*10**9), ('final',T+15*10**9)]:
        extra = 128 if phase=='later' else 0
        v = dict(begin=begin,end=begin+100)
        v['processes'] = {side:dict(pid=i,alive=True) for i,side in enumerate(('client','server'),10)}
        for inode, side in enumerate(('client','server'),101):
            v['external_'+side] = [dict(ino=inode,state=1,bytes_acked=64,send_q=extra)]
            v['path_'+side] = [23456,24446,inode]
        v['inbound_client'] = [dict(ino=250,state=1,bytes_received=64+extra,recv_q=0)]
        trial[phase] = v
    trial['final'].update(path_client=[],external_client=[])
    closed=T+8*10**9
    live=dict(established_count=1,established_ns=T-2*10**9)
    trial['trace']=dict(lost=0,extra_tuples=0,task_exits={'measure-stream':{'at':closed+200}},
                        sockets=dict(external_client=dict(live,first_error_ns=closed-10,left_established_ns=closed,
                                     closed_ns=closed,next_state=7,errno=110,error_count=1),external_server=live))
    stages=dict.fromkeys('first_echo openssl_trust server_owner client_owner echo_owner target_tls13_h2 transport authenticated_request'.split(),True)
    stages.update(client_test_rc=0,server_test_rc=0,initial_client_inode=101,initial_server_inode=102)
    end=dict(payload_provenance=True,pre_replies=10,server_pre=10,created_after=5,post_tx=5,
             fresh_server=0,fresh_replies=0,server_listener=True,client_listener=True,same_transport=False)
    status=dict(step=0,stages=stages,end=end,children={'stream':dict(exit_boot_ns=closed+100,reason=1,rc=2)})
    return trial,status


def veth(trial, side, index, t, directory):
    digest=hashlib.sha256(b'fixture frame').digest()
    at=t-1000
    raw=rx_clock.ROW.pack(0,at,index,0,2048,64,digest)
    (directory/(side+'.clock')).write_bytes(raw)
    import struct
    aggregate=hashlib.sha256(struct.pack('<QIIHI',0,index,0,2048,64)+digest).hexdigest()
    def period(at):
        return dict(frames=1,payload_frames=1,payload_bytes=16,first=at,last=at,first_data=at,last_data=at,
                    first_seq=123,last_seq=123,fin=0,rst=0)
    trial[side]=dict(capture=dict(frames=1,kernel=1,drops=0),attempt=dict(before=period(at),after=period(t+200)),
        wire=dict(matched=1,pre=1,at_or_after=0,first=at,last=at,reality_packets=1,reality_late=0,reserve_drops=0,
                  read_errors=0,kernel_sha256=aggregate,pcap_sha256=aggregate))


def evaluate(trial, status, ticket, modify=lambda x:x, versions=None, make_veth=veth):
    with tempfile.TemporaryDirectory() as tmp:
        directory=Path(tmp)
        for i,dev in enumerate(xray_records.SIDES,2):
            make_veth(trial,dev,i,ticket[1],directory)
        full_guest.port=io.BytesIO()
        xray_records.emit_trial(full_guest.emit,directory,CHALLENGE,ticket,trial,status)
        serial=modify(full_guest.port.getvalue().splitlines(keepends=True))
    events=queue.Queue()
    host.read(io.BytesIO(b''.join(serial)),'serial',events)
    e=dict(role='xray-short',armed_ticket=ticket,kvm=True,done=True,
           versions=versions or dict(xray='26.11.9',kernel='6.8.0-48-generic',abi='6.8.0-48.48'))
    books={side:xray_records.FrameLedger() for side in xray_records.SIDES}
    with redirect_stdout(io.StringIO()):
        while not events.empty():
            _,m=events.get_nowait()
            if m is not None:
                host.receive_xray(e,m,books,CHALLENGE)
    return xray_only.decide(e,35)


class Decision(unittest.TestCase):
    def assess(self,trial=None,status=None,modify=lambda x:x):
        default=fixture()
        return evaluate(trial or default[0],status or default[1],[T-35*10**9,T],modify)

    def test_confirmed_timeout_after_blocked_attempt(self):
        result=self.assess()
        self.assertEqual(result['result'],'PASS',result)
        self.assertEqual(result['properties'],dict(NETWORK_DEADLINE='PASS',PERSISTENT_CONNECTION_AT_CUTOFF='PASS',
            CONNECTION_SURVIVAL_AT_FINAL_OBSERVATION='FAIL',XRAY_PROCESS_AND_LISTENER='PASS',TERMINAL_SOCKET_REASON='ETIMEDOUT'))

    def test_close_before_attempt(self):
        trial,status=fixture()
        trace=trial['trace']['sockets']['external_client']
        trace.update(first_error_ns=T+3,left_established_ns=T+4,closed_ns=T+4)
        result=self.assess(trial,status)
        self.assertFalse(result['qualified'])
        self.assertNotEqual(result['properties']['NETWORK_DEADLINE'],'PASS')

    def test_open_at_final(self):
        trial,status=fixture()
        trial['trace']['sockets']['external_client']=dict(trial['trace']['sockets']['external_server'])
        for key in ('external_client','path_client'):
            trial['final'][key]=trial['later'][key]
        status['end']['same_transport']=True
        result=self.assess(trial,status)
        self.assertTrue(result['qualified'],result)
        self.assertEqual(result['properties']['CONNECTION_SURVIVAL_AT_FINAL_OBSERVATION'],'PASS')

    def test_reject_unexplained_error_and_changed_process(self):
        for change in ('errno','process'):
            trial,status=fixture()
            if change=='errno':
                trial['trace']['sockets']['external_client']['errno']=104
            else:
                trial['final']['processes']['server']['pid']+=1
            self.assertFalse(self.assess(trial,status)['qualified'])

    def test_serial_corruption_replay_and_omission(self):
        for match in (b'"key":"uc0"',b'"key":"up0"',b'"event":"transport_case"',b'"event":"rx_frames"',b'"event":"xray_receipt"'):
            for defect in ('missing','duplicate','corrupt'):
                with self.subTest(match=match,defect=defect):
                    def mutate(lines):
                        i=next(i for i,line in enumerate(lines) if match in line)
                        lines[i:i+1]={'missing':[],'duplicate':[lines[i]]*2,'corrupt':[b'{broken}\n']}[defect]
                        return lines
                    self.assertFalse(self.assess(modify=mutate)['qualified'])

    def test_valid_json_with_modified_payload(self):
        def mutate(lines):
            return [line.replace(b'"payload_bytes":16',b'"payload_bytes":15') if b'"key":"up0"' in line else line for line in lines]
        self.assertFalse(self.assess(modify=mutate)['qualified'])

    def test_signed_but_incomplete_native_section(self):
        trial,status=fixture()
        def incomplete(*args):
            veth(*args)
            del args[0][args[1]]['attempt']['after']['first_seq']
        result=evaluate(trial,status,[T-35*10**9,T],make_veth=incomplete)
        self.assertFalse(result['qualified'])


if __name__=='__main__':
    unittest.main()
