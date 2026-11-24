"""Receive on one offline veth and persist nanosecond pcap records in Linux cooked v2 format."""
import errno
import fcntl
import json
import os
import signal
import socket
import struct
import sys

SOL_PACKET = 263
IGNORE_OUTGOING = 23
PACKET_STATISTICS = 6
TIMESTAMP_NS = 35  # Linux x86-64 SO_TIMESTAMPNS_OLD, two signed 64-bit fields.
ALL_ETHERTYPES = 3
SNAPLEN = 262144
stopping = False


def stop(sig, frame):
    global stopping
    stopping = True


def check(ok, reason):
    if not ok:
        raise ValueError(reason)


def record(output, index, device, data, anc, flags, source):
    check(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'truncated record')
    name, protocol, direction, hardware, address = source
    check(name == device and direction in (0,1,2,3) and len(address) <= 8, 'unexpected interface or direction')
    stamps = [c for level,kind,c in anc if (level,kind)==(socket.SOL_SOCKET,TIMESTAMP_NS)]
    check(len(stamps)==1 and len(stamps[0])==16, 'missing kernel receive timestamp')
    sec, ns = struct.unpack('=qq',stamps[0])
    check(0 <= ns < 10**9, 'invalid timestamp')
    header = struct.pack('!HHIHBB8s',protocol,0,index,hardware,direction,len(address),address)
    size = len(header)+len(data)
    check(size <= SNAPLEN, 'record exceeds snap length')
    output.write(struct.pack('<IIII',sec,ns,size,size)+header+data)


def capture(device, index):
    check(device in ('uc0','up0') and socket.if_nametoindex(device)==index,'unverified veth')
    signal.signal(signal.SIGINT, stop)
    with socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,0) as rx:
        rx.setsockopt(SOL_PACKET,IGNORE_OUTGOING,1)
        rx.setsockopt(socket.SOL_SOCKET,TIMESTAMP_NS,1)
        rx.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,2*1024*1024)
        rx.bind((device,ALL_ETHERTYPES))
        name,protocol,*_ = rx.getsockname()
        check((name,protocol)==(device,ALL_ETHERTYPES),'socket bind mismatch')
        check(rx.getsockopt(SOL_PACKET,IGNORE_OUTGOING)==1 and rx.getsockopt(socket.SOL_SOCKET,TIMESTAMP_NS)==1,'socket option mismatch')
        err=rx.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
        if err==errno.ENETDOWN:
            req=struct.pack('16s24x',device.encode())
            flags=struct.unpack_from('=H',fcntl.ioctl(rx,0x8913,req),16)[0]
            check(not flags & 1,'unexpected link change during bind')
        elif err:
            raise OSError(err,os.strerror(err))
        rx.settimeout(.15)
        output=sys.stdout.buffer
        output.write(struct.pack('<IHHIIII',0xa1b23c4d,2,4,0,0,SNAPLEN,276))
        output.flush()
        print(json.dumps({'bound':index,'ingress':True,'kernel_time':True}),file=sys.stderr,flush=True)
        count=0
        while True:
            try:
                packet = rx.recvmsg(SNAPLEN,socket.CMSG_SPACE(16))
            except TimeoutError:
                if stopping:
                    break
                continue
            record(output,index,device,*packet)
            count+=1
        output.flush()
        os.fsync(output.fileno())
        kernel,drops=struct.unpack('=II',rx.getsockopt(SOL_PACKET,PACKET_STATISTICS,8))
        print(json.dumps(dict(frames=count,kernel=kernel,drops=drops)),file=sys.stderr,flush=True)
        check(drops==0 and kernel==count,'capture loss or incomplete drain')


if __name__=='__main__':
    try:
        capture(sys.argv[1],int(sys.argv[2]))
    except (OSError,ValueError,struct.error) as exc:
        print(json.dumps(dict(error=type(exc).__name__,errno=getattr(exc,'errno',None),reason=str(exc)[:100])),file=sys.stderr,flush=True)
        sys.exit(1)
