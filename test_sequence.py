"""Pure analysis regression fixtures. No sockets, guest or network changes."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent/'campaign'))
import seq_assess

class FlowEvidence(unittest.TestCase):
    def setUp(self):
        self.d={'uc0':{'app':[],'ingress':[],'egress':[],'drops':[2,0]},
                'up0':{'app':[{'family':4,'kind':'delivered','at':12}],'ingress':[]}}
        for at,kind,unacked,total in [(1,'connected',0,0),(9,'sent',1,0),(15,'info',1,1),(25,'info',1,2)]:
            self.d['uc0']['app'].append(dict(at=at,kind=kind,unacked=unacked,total=total,
                    cookie=7,inode=11,pid=4,state=1,acked=1,family=4))
        for at in (10,14,22):
            packet=dict(at=at,src=1,dst=2,family=4,sport=24680,dport=24681,length=48,seq=4294967280,ack=0,flags=24)
            self.d['uc0']['egress'].append(packet)
            if at<20: self.d['up0']['ingress'].append(dict(packet,at=at+1))
        self.d['uc0']['ingress'].append(dict(at=12,src=2,dst=1,family=4,sport=24681,dport=24680,length=0,seq=201,ack=32,flags=16))

    def result(self,n=2):
        with patch.object(seq_assess,'pcap_matches',return_value=n):
            return seq_assess.flow(None,self.d,'uc0','up0',4,20,{'up0':2})

    def test_complete(self):
        self.assertTrue(self.result()['verified'])

    def test_aggregate_without_wire_retry(self):
        self.d['uc0']['egress'].pop()
        self.assertIn('NO_POST_GATE_STIMULUS',self.result()['errors'])

    def test_identity_change(self):
        self.d['uc0']['app'][-1]['cookie']+=1
        self.assertIn('SOCKET_ID_STATE',self.result()['errors'])

    def test_wrong_sequence(self):
        self.d['uc0']['egress'][-1]['seq']+=1
        self.assertIn('DIFFERENT_RANGE',self.result()['errors'])

    def test_ack_accepted(self):
        self.d['uc0']['app'][-1]['acked']+=48
        self.assertIn('COVERING_ACK_ACCEPTED',self.result()['errors'])

    def test_missing_positive_control(self):
        self.d['up0']['ingress'].pop()
        self.assertIn('POSITIVE_WIRE_CONTROL',self.result(1)['errors'])

    def test_post_delivery(self):
        self.d['up0']['ingress'].append(copy.copy(self.d['uc0']['egress'][-1]))
        self.assertTrue(self.result(3)['peer_excess'])

    def test_pcap_gap(self):
        self.assertIn('INDEPENDENT_PCAP',self.result(0)['errors'])

if __name__=='__main__':
    unittest.main()
