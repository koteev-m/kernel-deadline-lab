"""One persistent local TCP stream. The 16-byte payload and pacing are fixed."""
from collections import deque
import errno
import json
import os
import select
import socket
import struct
import time

PERIOD=150_000_000
FRAME=struct.Struct('!QQ')
def now(): return time.clock_gettime_ns(time.CLOCK_BOOTTIME)
def event(*fields): print(json.dumps(fields),flush=True)

class Output:
    def __init__(self):
        self.queue=deque()
        self.offset=0
        self.created=self.sent=self.bytes=self.partial=self.again=0
    def create(self,at):
        if len(self.queue)>=4096:
            raise BufferError('bounded probe queue full')
        seq=self.created
        self.queue.append((seq,at,FRAME.pack(seq,at)))
        self.created+=1
        event('made',seq,at)
    def flush(self,conn):
        while self.queue:
            seq,stamp,payload=self.queue[0]
            try:
                n=conn.send(payload[self.offset:])
            except (BlockingIOError,InterruptedError):
                self.again+=1
                return
            if n<=0:
                raise OSError(errno.EPIPE,'zero stream write')
            self.offset+=n
            self.bytes+=n
            if self.offset<FRAME.size:
                self.partial+=1
                return
            self.queue.popleft()
            self.sent+=1
            self.offset=0
            event('tx',seq,stamp,now())

def run(port):
    out=Output()
    pending=bytearray()
    replies=blocked_reads=0
    reason=err=op=0
    with socket.create_connection(('127.0.0.1',port),timeout=5) as conn:
        conn.setblocking(False)
        fd_inode=os.fstat(conn.fileno()).st_ino
        first_state=conn.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,104)[0]
        local_port=conn.getsockname()[1]
        event('socket',local_port,fd_inode,first_state,now())
        next_frame=now()
        try:
            while True:
                tick=now()
                if tick>=next_frame:
                    out.create(tick)
                    next_frame=tick+PERIOD
                op=1
                r,w,_=select.select([conn],[conn] if out.queue else [],[],max(0,(next_frame-now())/1e9))
                if r:
                    op=2
                    try:
                        block=conn.recv(65536)
                    except (BlockingIOError,InterruptedError):
                        blocked_reads+=1
                    else:
                        if not block:
                            reason=1
                            break
                        pending.extend(block)
                        while len(pending)>=FRAME.size:
                            seq,stamp=FRAME.unpack_from(pending)
                            del pending[:FRAME.size]
                            event('rx',seq,stamp,now())
                            replies+=1
                if w:
                    op=3
                    out.flush(conn)
        except OSError as exc:
            reason,err=2,exc.errno or 0
        except BufferError:
            reason=3
        finally:
            at=now()
            try: state=conn.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,104)[0]
            except OSError: state=-1
            note=dict(exit_boot_ns=at,errno=err,operation=op,reason=reason,tcp_state=state,inode=fd_inode,
                      local_port=local_port,created=out.created,submitted=out.sent,bytes_sent=out.bytes,replies=replies,
                      pending_frames=len(out.queue),write_offset=out.offset,partial_writes=out.partial,
                      write_eagain=out.again,read_eagain=blocked_reads,pending_rx=len(pending))
            print(json.dumps(note),flush=True)
    return 2 if reason==1 else 1
