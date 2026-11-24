"""Exercise an actual proxy pair and a single persistent, timestamped echo stream."""
from contextlib import closing
import json
import os
from pathlib import Path
import socket
import struct
import subprocess as sp
import sys
import tempfile
import time
import uuid

HERE=Path(__file__).resolve().parent
XR=HERE/'xray'
def now():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)

def server():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',18881))
        listener.listen(1)
        conn,_=listener.accept()
        with conn:
            while block:=conn.recv(4096):
                conn.sendall(block)

def client():
    with socket.create_connection(('127.0.0.1',18882),timeout=5) as sock:
        sock.setblocking(False)
        pending=b''
        index=0
        while True:
            issued=now()
            message=struct.pack('!QQ',index,issued)
            if sock.send(message)!=len(message):
                raise RuntimeError('short probe')
            print(json.dumps(['tx',index,issued]),flush=True)
            try:
                incoming=sock.recv(65536)
                if not incoming:
                    raise RuntimeError('closed stream')
                pending+=incoming
            except BlockingIOError:
                pass
            while len(pending)>=16:
                seq,stamp=struct.unpack('!QQ',pending[:16])
                pending=pending[16:]
                print(json.dumps(['rx',seq,stamp,now()]),flush=True)
            index+=1
            time.sleep(.15)

def start(stack,c,peer,out):
    import lab
    base=Path(stack.enter_context(tempfile.TemporaryDirectory()))
    name='echo.test'
    ident=str(uuid.uuid4())
    cert=base/'ca.pem'
    key=base/'leaf.pem'
    sp.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
            '-subj','/CN='+name,'-addext','subjectAltName=DNS:'+name,
            '-keyout',key,'-out',cert],check=True,stdout=sp.DEVNULL,stderr=sp.DEVNULL)
    tls={'network':'raw','security':'tls','tlsSettings':{'certificates':[
        {'certificateFile':str(cert),'keyFile':str(key)}]}}
    inbound={'listen':'192.0.2.1','port':24445,'protocol':'vless','settings':{
        'clients':[{'id':ident}],'decryption':'none'},'streamSettings':tls}
    config_server={'inbounds':[inbound],'outbounds':[{'protocol':'freedom'}]}
    outbound={'protocol':'vless','settings':{'vnext':[{'address':'192.0.2.1','port':24445,
        'users':[{'id':ident,'encryption':'none'}]}]},'streamSettings':{
        'network':'raw','security':'tls','tlsSettings':{'serverName':name}}}
    config_client={'inbounds':[{'listen':'127.0.0.1','port':18882,'protocol':'dokodemo-door',
        'settings':{'address':'127.0.0.1','port':18881,'network':'tcp'}}],'outbounds':[outbound]}
    for ns in (c,peer):
        lab.cmd(*ns,'ip','link','set','lo','up')
    for filename,config in [('server',config_server),('client',config_client)]:
        (base/(filename+'.json')).write_text(json.dumps(config))
    os.chown(base,65000,65000)
    for f in base.iterdir():
        f.chmod(0o400)
        os.chown(f,65000,65000)
    stages={}
    children={}
    def save():
        terms={'blocked':'target blocked by a finalrule','blackhole':'blackholing connection',
               'vless_request':'received request for tcp:127.0.0.1:18881','unknown_ca':'unknown authority',
               'expired_cert':'certificate has expired','cert_name':'certificate is valid for',
               'tls_failure':'tls:','refused':'connection refused','no_route':'no route to host',
               'denied':'permission denied','invalid_request':'invalid request','reset':'connection reset',
               'eof':'eof','local_target':'tcp:127.0.0.1:18881','lookup':'no such host',
               'closed':'closed stream','cert_error':'x509:','accepted':' accepted '}
        categories={}
        for label,p in children.items():
            log=(out/label).read_text(errors='replace').lower()
            categories[label]={k:True for k,v in terms.items() if v in log}
            categories[label]['alive']=p.poll() is None
            if p.returncode is not None:
                categories[label]['rc']=p.returncode
        tmp=out/'proxy-stages.next'
        lab.put(tmp,dict(stages=stages,children=categories))
        tmp.replace(out/'proxy-stages.json')
    def launch(ns,args,output):
        stream=stack.enter_context((out/output).open('wb'))
        prefix=[*ns,'setpriv','--reuid=65000','--regid=65000','--clear-groups','--no-new-privs']
        p=lab.spawn(stack,[*prefix,*map(str,args)],stream,sp.STDOUT)
        children[output]=p
        return p
    for label,ns in [('server',c),('client',peer)]:
        cfg=base/(label+'.json')
        config=json.loads(cfg.read_text())
        config['log']={'loglevel':'debug'}
        cfg.chmod(0o600)
        cfg.write_text(json.dumps(config))
        cfg.chmod(0o400)
        p=launch(ns,['env','SSL_CERT_FILE='+str(cert),XR,'run','-test','-c',cfg],label+'-test')
        stages[label+'_test_rc']=p.wait(timeout=8)
        save()
        lab.require(p.returncode==0,'proxy config test')
    stages['openssl_trust']=sp.run(['openssl','verify','-CAfile',cert,'-verify_hostname',name,cert],stdout=sp.DEVNULL,stderr=sp.DEVNULL).returncode==0
    echo=launch(c,[sys.executable,'-I','-B',__file__,'echo'],'echo-private')
    def wait_socket(ns,port,p=None):
        lab.wait_until(lambda: (p is None or p.poll() is None) and bool(lab.cmd(*ns,'ss','-H','-lnt','sport = :'+str(port)).strip()),10)
    wait_socket(c,18881,echo)
    stages['echo_listener']=f'pid={echo.pid},' in lab.cmd(*c,'ss','-Hlntp','sport = :18881')
    save()
    processes=[]
    for ns,label,port in [(c,'server',24445),(peer,'client',18882)]:
        proc=launch(ns,['env','SSL_CERT_FILE='+str(cert),XR,'run','-c',base/(label+'.json')],label+'-private')
        try:
            wait_socket(ns,port,proc)
        finally:
            stages[label+'_listener']=f'pid={proc.pid},' in lab.cmd(*ns,'ss','-Hlntp','sport = :'+str(port))
            save()
        processes.append(proc)
    launch(peer,[sys.executable,'-I','-B',__file__,'client'],'proxy-traffic')
    try:
        lab.wait_until(lambda: '"rx"' in (out/'proxy-traffic').read_text(),12)
    finally:
        stages['transport_server']=f'pid={processes[0].pid},' in lab.cmd(*c,'ss','-H4tnp','state','established','sport = :24445')
        stages['transport_client']=f'pid={processes[1].pid},' in lab.cmd(*peer,'ss','-H4tnp','state','established','dport = :24445')
        stages['echo_accepted']=f'pid={echo.pid},' in lab.cmd(*c,'ss','-H4tnp','state','established','sport = :18881')
        stages['first_echo']='"rx"' in (out/'proxy-traffic').read_text()
        save()
    def transport():
        return lab.cmd(*c,'ss','-H4tnp','state','established','sport = :24445').strip()
    first=transport()
    lab.require(len(first.splitlines())==1 and f'pid={processes[0].pid},' in first,'proxy TCP provenance')
    global PROCS, SOCKET
    PROCS=processes
    SOCKET=first.split()[2:4]
    lab.put(out/'proxy-start.json',dict(at=now(),pids=[p.pid for p in PROCS]))

def finish(c,peer,out,ticket):
    import lab
    rows=[json.loads(row) for row in (out/'proxy-traffic').read_text().splitlines() if row.endswith(']')]
    t=ticket['deadline']
    after=[r for r in rows if r[0]=='rx' and r[2]>=t]
    good=[r for r in rows if r[0]=='rx' and r[2]<t]
    tx=[r for r in rows if r[0]=='tx' and r[2]>=t]
    current=lab.cmd(*c,'ss','-H4tnp','state','established','sport = :24445').strip()
    same=SOCKET==current.split()[2:4] and f'pid={PROCS[0].pid},' in current
    listener=lab.cmd(*c,'ss','-Hlntp','sport = :24445')
    lab.put(out/'proxy-end.json',dict(before=len(good),after=len(after),post_tx=len(tx),same=same,
        live=all(p.poll() is None for p in PROCS),listener=f'pid={PROCS[0].pid},' in listener,
        last_pre_send=good[-1][2] if good else 0,last_pre_rx=good[-1][3] if good else 0,
        first_post_send=tx[0][2] if tx else 0))

if __name__=='__main__':
    (server if sys.argv[1]=='echo' else client)()
