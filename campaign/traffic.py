"""Synthetic endpoints only. The lab runner supplies their private namespaces."""
import ctypes
import json
import os
import signal
import socket
import stat
import struct
import sys
import threading
import time

PORT = 24443
UDP = 24444
write_lock = threading.Lock()


def now():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def event(kind, **fields):
    with write_lock:
        os.write(1, (json.dumps(dict(kind=kind, at=now(), pid=os.getpid(), **fields)) + '\n').encode())


def drop():
    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
        raise RuntimeError("no_new_privs")
    os.setgroups([])
    os.setgid(65000)
    os.setuid(65000)
    status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
    if any(set(status[k].split()) != {'65000'} for k in ('Uid','Gid')):
        raise RuntimeError("credential drop incomplete")
    if any(int(status[key], 16) for key in ('CapEff', 'CapPrm', 'CapAmb')):
        raise RuntimeError("capabilities retained")


def sock(family, proto):
    s = socket.socket(family, proto)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    return s


def worker(fn, *args):
    def run():
        try:
            fn(*args)
        except Exception as err:
            event('error', worker=fn.__name__, detail=repr(err))
            os._exit(2)
    threading.Thread(target=run, daemon=True).start()


def frame(run, side, family, stream, seq):
    t = now()
    return f"U6K|{run}|{side}|{family}|{stream}|{seq}|{t}\n".encode()


def receive(data, run, side, family):
    magic, ident, sender, version, stream, seq, issued = data.decode().strip().split('|')
    if (magic, ident, version) != ('U6K', run, family) or sender == side:
        raise RuntimeError("unrecognized synthetic payload")
    event('rx', stream=stream, family=family, sent=int(issued), seq=int(seq), sender=sender)


def udp_send(s, remote, run, side, family, stream):
    seq = 0
    while True:
        packet = frame(run, side, family, stream, seq)
        event('tx', family=family, stream=stream, seq=seq)
        try:
            s.sendto(packet, (remote, UDP))
        except OSError as err:
            event('io', stream=stream, family=family, errno=err.errno)
        seq += 1
        time.sleep(.20)


def udp_recv(s, run, side, family):
    while True:
        receive(s.recv(2048), run, side, family)


def read_tcp(conn, run, side, family):
    with conn, conn.makefile('rb') as lines:
        for line in lines:
            receive(line, run, side, family)


def accept(s, run, side, family):
    while True:
        conn, unused = s.accept()
        worker(read_tcp, conn, run, side, family)


def tcp_send(af, remote, run, side, family, persistent):
    stream = 'tcp' if persistent else 'new-tcp'
    seq = 0
    while True:
        with sock(af, socket.SOCK_STREAM) as s:
            s.settimeout(.65)
            event('connect', family=family, stream=stream)
            try:
                s.connect((remote, PORT))
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                connection = list(s.getsockname())[:2]
                while True:
                    event('tx', family=family, stream=stream, seq=seq, connection=connection)
                    s.sendall(frame(run, side, family, stream, seq))
                    seq += 1
                    if not persistent:
                        break
                    # tcpi_total_retrans in the stable initial Linux tcp_info prefix.
                    info = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
                    event('tcp-info', family=family, connection=connection,
                          state=info[0], retrans=struct.unpack_from('=I', info, 100)[0])
                    time.sleep(.2)
            except OSError as err:
                event('io', family=family, stream=stream, errno=err.errno)
        time.sleep(.30)


def control():
    drop()
    with socket.socket() as listener, socket.socket() as client:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        client.connect(listener.getsockname())
        server, _ = listener.accept()
        with server:
            client.settimeout(2)
            server.settimeout(2)
            while True:
                tag = os.urandom(1)
                client.sendall(tag)
                server.sendall(server.recv(1))
                if client.recv(1) != tag:
                    raise RuntimeError("foreign socket changed")
                event('control', connection=list(client.getsockname()))
                time.sleep(.4)


def endpoint(run, side):
    if any(stat.S_ISSOCK(os.fstat(i).st_mode) for i in (0, 1, 2)):
        raise RuntimeError("unexpected inherited socket")
    other = '2' if side == 'c' else '1'
    rows = []
    # Create the pre-arm sockets with C's actual fsuid. Restore privilege only
    # for creation of the empty migration namespace; no application I/O yet.
    os.setegid(65000)
    os.seteuid(65000)
    for family, af, anyip, remote in [
        ('4', socket.AF_INET, '0.0.0.0', '192.0.2.' + other),
        ('6', socket.AF_INET6, '::', '2001:db8:68::' + other)
    ]:
        udp = sock(af, socket.SOCK_DGRAM)
        udp.bind((anyip, UDP))
        listener = sock(af, socket.SOCK_STREAM)
        listener.bind((anyip, PORT))
        listener.listen(16)
        old = sock(af, socket.SOCK_DGRAM)
        old.bind((anyip, 0))
        rows.append((family, af, remote, udp, listener, old))

    identities = []
    for family, _, _, udp, listener, old in rows:
        for role, s in [('udp', udp), ('listener', listener), ('inherited', old)]:
            ident = os.fstat(s.fileno())
            if (ident.st_uid, ident.st_gid) != (65000, 65000):
                raise RuntimeError('socket inode owner')
            cookie = int.from_bytes(s.getsockopt(socket.SOL_SOCKET, 71, 8), sys.byteorder)
            identities.append(dict(family=family,role=role,inode=ident.st_ino,
                                   uid=ident.st_uid,gid=ident.st_gid,cookie=cookie))
    os.seteuid(0)
    os.setegid(0)
    child = os.fork()
    if child == 0:
        # Keep only the outbound UDP sockets opened before arm. New sockets in
        # this new netns have no path at all. Socket-netns ownership is observable.
        os.unshare(os.CLONE_NEWNET)
        drop()
        for family, af, remote, udp, listener, old in rows:
            udp.close()
            listener.close()
            worker(udp_send, old, remote, run, side, family, 'inherited-udp')
        with socket.socket() as fresh:
            new_cookie = int.from_bytes(fresh.getsockopt(socket.SOL_SOCKET, 71, 8), sys.byteorder)
        retained = [int.from_bytes(s.getsockopt(socket.SOL_SOCKET, 71, 8), sys.byteorder)
                    for _,_,_,_,_,s in rows]
        event('migrated', net=os.readlink('/proc/self/ns/net'), fresh=new_cookie, retained=retained)
        signal.pause()
        os._exit(0)

    drop()
    for family, af, remote, udp, listener, old in rows:
        old.close()
        worker(udp_recv, udp, run, side, family)
        worker(accept, listener, run, side, family)
        worker(udp_send, udp, remote, run, side, family, 'udp')
        for persistent in (True, False):
            worker(tcp_send, af, remote, run, side, family, persistent)
    event('ready', net=os.readlink('/proc/self/ns/net'), child=child, sockets=identities)
    status = os.waitpid(child, 0)
    raise RuntimeError(f"inherited-socket worker ended {status}")


if __name__ == '__main__':
    if sys.argv[1:] == ['control']:
        control()
    else:
        endpoint(*sys.argv[1:])
