"""Local regression for partial writes and terminal stream observations."""
from contextlib import redirect_stdout
import errno
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent/'campaign'))
import stream_probe as p

class Socket:
    def __init__(self,actions):
        self.actions=iter(actions)
        self.data=bytearray()
    def send(self,buf):
        n=next(self.actions)
        if isinstance(n,BaseException): raise n
        self.data.extend(buf[:n])
        return n

class Stream(unittest.TestCase):
    def test_partial_then_unwritable(self):
        with redirect_stdout(io.StringIO()) as log,patch.object(p,'now',return_value=333):
            o=p.Output()
            o.create(111)
            o.create(222)
            s=Socket([3,BlockingIOError(errno.EAGAIN,'busy'),InterruptedError(),13,16])
            for _ in range(4): o.flush(s)
        self.assertEqual(s.data,p.FRAME.pack(0,111)+p.FRAME.pack(1,222))
        self.assertEqual((o.sent,o.bytes,o.partial,o.again,o.offset,len(o.queue)),(2,32,1,2,0,0))
        self.assertEqual([json.loads(l)[0] for l in log.getvalue().splitlines()],['made','made','tx','tx'])
    def test_terminal_write_errors(self):
        for err in (errno.EPIPE,errno.ECONNRESET):
            with redirect_stdout(io.StringIO()):
                o=p.Output(); o.create(12)
                with self.assertRaises(OSError) as caught: o.flush(Socket([OSError(err,'terminal')]))
                self.assertEqual(caught.exception.errno,err)
                self.assertEqual(o.sent,0)
    def test_eof_and_fragments_without_reconnect(self):
        import socket
        with socket.socket() as fileno_socket:
            class Input:
                def __init__(self): self.parts=iter([p.FRAME.pack(0,123)[:7],p.FRAME.pack(0,123)[7:],b''])
                def __enter__(self): return self
                def __exit__(self,*a): pass
                def fileno(self): return fileno_socket.fileno()
                def setblocking(self,_): pass
                def getsockopt(self,*a): return bytes([1])+bytes(103)
                def getsockname(self): return ('127.0.0.1',12345)
                def recv(self,_): return next(self.parts)
            x=Input()
            with patch.object(p.socket,'TCP_INFO',11,create=True),patch.object(p.socket,'create_connection',return_value=x) as connect,patch.object(p.select,'select',return_value=([x],[],[])),patch.object(p,'now',return_value=123),redirect_stdout(io.StringIO()) as log:
                self.assertEqual(p.run(18884),2)
                connect.assert_called_once()
            rows=[json.loads(l) for l in log.getvalue().splitlines()]
            self.assertEqual(rows[-1]['reason'],1)
            self.assertEqual(rows[-1]['errno'],0)
            self.assertEqual(rows[-1]['replies'],1)
            self.assertEqual(rows[-1]['pending_rx'],0)

class Telemetry(unittest.TestCase):
    def test_both_numbered_veths_survive_serial_validation(self):
        import host
        evidence={'role':'xray-short'}
        witness={'attempt':{'after':{'payload_frames':3}},'wire':{'kernel_sha256':'a'*64,'at_or_after':0},'capture':{'drops':0}}
        with redirect_stdout(io.StringIO()) as output:
            for side in ('uc0','up0'):
                message=json.loads(json.dumps({'event':'xray_part','key':side,'data':witness}))
                host.record_xray_part(evidence,message)
        self.assertEqual(evidence['trial'],{'uc0':witness,'up0':witness})
        self.assertEqual(len(output.getvalue().splitlines()),2)
        self.assertNotIn('trial_record_errors',evidence)
    def test_rejected_or_duplicate_records_remain_visible(self):
        import host
        evidence={'role':'xray-proof'}
        with redirect_stdout(io.StringIO()) as output:
            for key,value in [('uc0',{'drops':0}),('uc0',{'drops':9}),('up0','invalid'),('unknown',{})]:
                host.record_xray_part(evidence,{'key':key,'data':value})
        self.assertEqual(evidence['trial_record_errors'],3)
        self.assertEqual(evidence['trial'],{'uc0':{'drops':0}})
        self.assertNotIn('invalid',output.getvalue())
if __name__=='__main__': unittest.main()
