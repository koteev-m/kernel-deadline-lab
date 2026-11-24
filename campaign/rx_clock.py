"""Journal ingress copies independently of the existing cooked packet capture."""
import ctypes as C
import hashlib
import itertools
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys

HEADER=struct.Struct('<QQIIII')
ROW=struct.Struct('<QQIIHI32s')

def check(value,label):
    if not value:
        raise ValueError(label)

def install(lab,stack,work,out,ends):
    obj=work/'receive.o'
    lab.cmd('clang-18','-g','-O2','-target','bpfel','-mcpu=v3',
            '-I/usr/include/x86_64-linux-gnu','-c',Path(__file__).with_suffix('.c'),'-o',obj)
    processes=[]
    for dev,ns,*_ in ends:
        root=Path('/sys/fs/bpf')/('rx-clock-'+dev)
        root.mkdir()
        maps=root/'maps'
        maps.mkdir()
        lab.cmd('bpftool','prog','load',obj,root/'program','pinmaps',maps)
        prog=json.loads(lab.cmd('bpftool','-j','prog','show','pinned',root/'program'))
        if isinstance(prog,list):
            [prog]=prog
        check(prog['type']=='socket_filter' and len(prog['map_ids'])==2,'RX_CLOCK_ATTACHMENT_TYPE')
        p=lab.spawn(stack,[*ns,sys.executable,'-I','-B',__file__,dev,out,root],
                    subprocess.DEVNULL)
        processes.append(p)
        lab.wait_until(lambda:p.poll() is not None or (out/(dev+'.clock-ready')).exists(),5)
        check(p.poll() is None and (out/(dev+'.clock-ready')).exists(),'RX_CLOCK_NOT_BOUND')
    return processes

def listen(dev,out,root):
    index=socket.if_nametoindex(dev)
    lib=C.CDLL('libbpf.so.1',use_errno=True)
    callback=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p,C.c_size_t)
    def signature(name,ret,*args):
        fn=getattr(lib,name)
        fn.restype=ret
        fn.argtypes=args
        return fn
    get=signature('bpf_obj_get',C.c_int,C.c_char_p)
    new=signature('ring_buffer__new',C.c_void_p,C.c_int,callback,C.c_void_p,C.c_void_p)
    poll=signature('ring_buffer__poll',C.c_int,C.c_void_p,C.c_int)
    free=signature('ring_buffer__free',None,C.c_void_p)
    lookup=signature('bpf_map_lookup_elem',C.c_int,C.c_int,C.c_void_p,C.c_void_p)
    prog,events,counts=[get(os.fsencode(root/f)) for f in ('program','maps/records','maps/counts')]
    check(min(prog,events,counts)>=0,'RX_CLOCK_PINS')
    stopped=False
    def stop(*args):
        nonlocal stopped
        stopped=True
    signal.signal(signal.SIGINT,stop)
    with (out/(dev+'.clock')).open('xb') as journal,socket.socket(socket.AF_PACKET,socket.SOCK_RAW,0) as tap:
        errors=[]
        count=0
        @callback
        def receive(ctx,ptr,cap):
            nonlocal count
            try:
                order,boot,actual,size,direction,_=HEADER.unpack(C.string_at(ptr,HEADER.size))
                check(order==count and boot>0 and actual==index and 0<=direction<=3 and 14<=size<=cap-HEADER.size,'RX_CLOCK_RECORD')
                raw=C.string_at(ptr+HEADER.size,size)
                protocol=int.from_bytes(raw[12:14],'big')
                data=raw[14:]
                journal.write(ROW.pack(order,boot,actual,direction,protocol,len(data),hashlib.sha256(data).digest()))
                count+=1
                return 0
            except Exception:
                errors.append(True)
                return -1
        ring=new(events,receive,None,None)
        check(ring,'RX_CLOCK_RING')
        try:
            tap.setsockopt(263,23,1)
            tap.setsockopt(socket.SOL_SOCKET,50,prog)
            tap.bind((dev,3))
            check(tap.getsockname()[:2]==(dev,3) and tap.getsockopt(263,23)==1,'RX_CLOCK_BIND')
            (out/(dev+'.clock-ready')).touch()
            while True:
                n=poll(ring,100)
                check(not errors and (n>=0 or n==-4),'RX_CLOCK_POLL')
                if stopped and n==0:
                    break
            totals=(C.c_ulonglong*3)()
            check(lookup(counts,C.byref(C.c_uint(0)),C.byref(totals))==0,'RX_CLOCK_COUNTS')
            (out/(dev+'.clock-counts')).write_text(json.dumps(list(totals)))
            check(list(totals)==[count,0,0],'RX_CLOCK_LOSS')
        finally:
            free(ring)

def compare(out,dev,index,deadline):
    import assess
    counts=json.loads((out/(dev+'.clock-counts')).read_text())
    kernel_hash,pcap_hash=hashlib.sha256(),hashlib.sha256()
    previous=before=late=0
    first=None
    external=external_late=0
    with (out/(dev+'.clock')).open('rb') as journal:
        records=iter(lambda:journal.read(ROW.size),b'')
        for i,(packet,row) in enumerate(itertools.zip_longest(assess.packets(out/(dev+'.pcap'),index),records)):
            check(packet is not None and row is not None,'RX_CLOCK_LENGTH')
            _,frame=packet
            order,at,idx,direction,proto,length,digest=ROW.unpack(row)
            check((order,idx,direction,proto,length,digest)==
                  (i,index,frame[10],int.from_bytes(frame[:2],'big'),len(frame)-20,hashlib.sha256(frame[20:]).digest()),'RX_CLOCK_FRAME_MISMATCH')
            kernel_hash.update(struct.pack('<QIIHI',order,idx,direction,proto,length)+digest)
            pcap_hash.update(struct.pack('<QIIHI',i,index,frame[10],int.from_bytes(frame[:2],'big'),len(frame)-20)+hashlib.sha256(frame[20:]).digest())
            check(at>=previous and at>0,'RX_CLOCK_ORDER')
            data=frame[20:]
            if proto==0x0800 and len(data)>=40 and data[9]==6:
                offset=(data[0]&15)*4
                if len(data)>=offset+4 and 24446 in struct.unpack_from('!HH',data,offset):
                    external+=1
                    external_late+=at>=deadline
            previous=at
            if first is None: first=at
            if at<deadline: before+=1
            else: late+=1
    check(counts==[before+late,0,0] and before,'RX_CLOCK_TOTAL')
    return dict(kernel_sha256=kernel_hash.hexdigest(),pcap_sha256=pcap_hash.hexdigest(),matched=before+late,pre=before,at_or_after=late,first=first,last=previous,
                reality_packets=external,reality_late=external_late,reserve_drops=counts[1],read_errors=counts[2])

if __name__=='__main__':
    listen(sys.argv[1],Path(sys.argv[2]),Path(sys.argv[3]))
