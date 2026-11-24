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

if __name__=='__main__': unittest.main()
