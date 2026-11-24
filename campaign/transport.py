"""One authenticated, synthetic stream over the offline veth. Only typed evidence escapes."""
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess as sp
import sys
import tempfile
import time
import uuid

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import lab

def records(path):
    return [json.loads(row) for row in path.read_text().splitlines() if row.endswith(']')]

def emit(*values):
    print(json.dumps(values),flush=True)

def echo(port):
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(('127.0.0.1',port))
        listener.listen(1)
        conn,_=listener.accept()
        with conn:
            pending=b''
            while block:=conn.recv(4096):
                pending+=block
                while len(pending)>=16:
                    payload,pending=pending[:16],pending[16:]
                    seq,stamp=struct.unpack('!QQ',payload)
                    emit('echo',seq,stamp,lab.now())
                    conn.sendall(payload)

def stream(port):
    with socket.create_connection(('127.0.0.1',port),timeout=5) as conn:
        seq=0
        pending=b''
        conn.setblocking(False)
        while True:
            stamp=lab.now()
            payload=struct.pack('!QQ',seq,stamp)
            lab.require(conn.send(payload)==16,'short stream write')
            emit('tx',seq,stamp)
            try:
                block=conn.recv(65536)
                lab.require(block,'closed echo stream')
                pending+=block
            except BlockingIOError:
                pass
            while len(pending)>=16:
                payload,pending=pending[:16],pending[16:]
                emit('rx',*struct.unpack('!QQ',payload),lab.now())
            seq+=1
            time.sleep(.15)

def keypair():
    sk=sp.check_output(['openssl','genpkey','-algorithm','X25519','-outform','DER'],stderr=sp.DEVNULL)
    pk=sp.check_output(['openssl','pkey','-inform','DER','-pubout','-outform','DER'],input=sk,stderr=sp.DEVNULL)
    lab.require(sk[:-32]==bytes.fromhex('302e020100300506032b656e04220420') and
                pk[:-32]==bytes.fromhex('302a300506032b656e032100'),'X25519 format')
    return [base64.urlsafe_b64encode(v[-32:]).decode().rstrip('=') for v in (sk,pk)]

def endpoint(value):
    host,port=value.rsplit(':',1)
    address=ipaddress.ip_address(host.strip('[]').split('%')[0])
    return (getattr(address,'ipv4_mapped',None) or address),int(port)

def transport(ns,dev,pid,side,port):
    own,other=('192.0.2.1','192.0.2.2') if side=='server' else ('192.0.2.2','192.0.2.1')
    links=json.loads(lab.cmd(*ns,'ip','-j','link'))
    lab.require({r['ifname'] for r in links}=={'lo',dev} and
                json.loads(lab.cmd(*ns,'ip','-j','route','get',other))[0]['dev']==dev,'proxy route')
    external=[]
    for line in lab.cmd(*ns,'ss','-HtuanpeO').splitlines():
        if f'pid={pid},' not in line:
            continue
        proto,state,_,_,local,remote,*_=line.split()
        if state=='LISTEN' or remote.endswith(':*'):
            addr,localport=endpoint(local)
            lab.require(proto=='tcp' and state=='LISTEN' and (addr.is_loopback or
                        (side=='server' and str(addr)==own and localport==port)),'unexpected proxy listener')
            continue
        a,lport=endpoint(local)
        b,rport=endpoint(remote)
        if a.is_loopback and b.is_loopback:
            continue
        lab.require(proto=='tcp' and state=='ESTAB' and str(a)==own and str(b)==other and
                    (lport if side=='server' else rport)==port,'unexpected external socket')
        inode=int(re.search(r'\bino:(\d+)',line)[1])
        external.append([lport,rport,inode])
    lab.require(len(external)==1,'external transport identity')
    return external[0]

class Fixture:
    def __init__(self,out,protocol):
        self.out=out/protocol
        self.out.mkdir()
        self.protocol=protocol
        self.procs={}
        self.stages={}
        self.failure_stage=0

    def snapshot(self):
        tags={'unknown_ca':'unknown authority','rejected_target':'target blocked by a finalrule',
              'refused':'connection refused','reset':'connection reset','auth_error':'authentication failed',
              'cert_error':'x509:','invalid':'invalid','sni':'server name mismatch','peer_closed':'eof',
              'permission':'permission denied','resolve_error':'no such host','routing_error':'no route to host',
              'vless_request':'received request for tcp:127.0.0.1:'+str(self.echo_port)}
        children={}
        for label,p in self.procs.items():
            d={'alive':p.poll() is None}
            if p.returncode is not None: d['rc']=p.returncode
            if label not in ('echo','stream'):
                msg=(self.out/label).read_text(errors='replace').lower()
                d.update({k:True for k,v in tags.items() if v in msg})
            children[label]=d
        result=dict(stages=self.stages,children=children,step=self.failure_stage)
        (self.out/'status.json').write_text(json.dumps(result))
        return result

    def start(self,stack,c,peer):
        serverport,front,self.echo_port=(24445,18882,18881) if self.protocol=='tls' else (24446,18884,18883)
        self.port=serverport
        self.net=(c,peer)
        base=Path(stack.enter_context(tempfile.TemporaryDirectory()))
        cert,key=base/'cert.pem',base/'cert.key'
        name='echo.test'
        ident=str(uuid.uuid4())
        def launch(label,ns,args):
            output=stack.enter_context((self.out/label).open('wb'))
            p=lab.spawn(stack,[*ns,'setpriv','--reuid=65000','--regid=65000','--clear-groups','--no-new-privs',*map(str,args)],output,sp.STDOUT)
            self.procs[label]=p
            return p
        def owner(ns,port,p):
            return p.poll() is None and f'pid={p.pid},' in lab.cmd(*ns,'ss','-Hlntp','sport = :'+str(port))
        def wait(fn,seconds):
            lab.wait_until(fn,seconds)
        for ns in (c,peer): lab.cmd(*ns,'ip','link','set','lo','up')
        # Use a leaf with a matching SAN. The client installs only this fixture's CA.
        def ssl(*args):
            sp.run(['openssl',*args],check=True,stdout=sp.DEVNULL,stderr=sp.DEVNULL)
        ca,cakey,req=base/'root.pem',base/'root.key',base/'request'
        ssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2',
            '-subj','/CN=Offline Root','-addext','basicConstraints=critical,CA:TRUE','-keyout',cakey,'-out',ca)
        ssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN='+name,
            '-keyout',key,'-out',req)
        ext=base/'extensions'
        ext.write_text('subjectAltName=DNS:echo.test\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n')
        ssl('x509','-req','-in',req,'-CA',ca,'-CAkey',cakey,'-CAcreateserial','-days','2','-extfile',ext,'-out',cert)
        ssl('verify','-verify_hostname',name,'-CAfile',ca,cert)
        self.stages['openssl_trust']=True
        server_stream={'network':'raw','security':'tls','tlsSettings':{'certificates':[{'certificateFile':str(cert),'keyFile':str(key)}]}}
        client_stream={'network':'raw','security':'tls','tlsSettings':{'serverName':name,'disableSystemRoot':True,
                       'certificates':[{'usage':'verify','certificateFile':str(ca)}]}}
        if self.protocol=='reality':
            sk,pk=keypair()
            sid=secrets.token_hex(8)
            server_stream={'network':'raw','security':'reality','realitySettings':{'target':'127.0.0.1:18443',
                'serverNames':[name],'privateKey':sk,'shortIds':[sid]}}
            client_stream={'network':'raw','security':'reality','realitySettings':{'serverName':name,
                'password':pk,'shortId':sid,'fingerprint':'chrome'}}
        local_rule={'action':'allow','network':'tcp','ip':['127.0.0.1/32'],'port':str(self.echo_port)}
        common={'log':{'loglevel':'debug'}}
        s=dict(common,inbounds=[{'listen':'192.0.2.1','port':serverport,'protocol':'vless',
            'settings':{'clients':[{'id':ident}],'decryption':'none'},'streamSettings':server_stream}],
            outbounds=[{'protocol':'freedom','settings':{'finalRules':[local_rule,{'action':'block'}]}}])
        cl=dict(common,inbounds=[{'listen':'127.0.0.1','port':front,'protocol':'dokodemo-door',
            'settings':{'address':'127.0.0.1','port':self.echo_port,'network':'tcp'}}],
            outbounds=[{'protocol':'vless','settings':{'vnext':[{'address':'192.0.2.1','port':serverport,
            'users':[{'id':ident,'encryption':'none'}]}]},'streamSettings':client_stream}])
        for label,config in (('server',s),('client',cl)):
            (base/(label+'.json')).write_text(json.dumps(config))
        os.chown(base,65000,65000)
        for f in base.iterdir():
            f.chmod(0o400)
            if f!=cakey: os.chown(f,65000,65000)
        self.failure_stage=1
        for label,ns in (('server',c),('client',peer)):
            p=launch(label+'-test',ns,[HERE/'xray','run','-test','-c',base/(label+'.json')])
            self.stages[label+'_test_rc']=p.wait(timeout=8)
            lab.require(p.returncode==0,'config test')
        self.failure_stage=2
        ep=launch('echo',c,[sys.executable,'-I','-B',__file__,'echo',self.echo_port])
        wait(lambda:owner(c,self.echo_port,ep),10)
        self.stages['echo_owner']=True
        if self.protocol=='reality':
            target=launch('target',c,['openssl','s_server','-accept','127.0.0.1:18443','-cert',cert,
                '-key',key,'-tls1_3','-alpn','h2','-www','-ign_eof'])
            wait(lambda:owner(c,18443,target),10)
            r=sp.run([*c,'openssl','s_client','-connect','127.0.0.1:18443','-servername',name,
                '-verify_hostname',name,'-CAfile',ca,'-verify_return_error','-tls1_3','-alpn','h2'],
                input=b'',stdout=sp.PIPE,stderr=sp.STDOUT,timeout=5)
            self.stages['target_tls13_h2']=r.returncode==0 and b'ALPN protocol: h2' in r.stdout and b'Verify return code: 0 (ok)' in r.stdout
            lab.require(self.stages['target_tls13_h2'],'local TLS target')
        for idx,(label,ns,port) in enumerate((('server',c,serverport),('client',peer,front)),3):
            self.failure_stage=idx
            p=launch(label,ns,[HERE/'xray','run','-c',base/(label+'.json')])
            wait(lambda:owner(ns,port,p),10)
            self.stages[label+'_owner']=True
        launch('stream',peer,[sys.executable,'-I','-B',__file__,'stream',front])
        self.failure_stage=5
        def connected():
            return all(f'pid={self.procs[k].pid},' in lab.cmd(*ns,'ss','-Hntp','state','established',flt+' = :'+str(serverport))
                       for k,ns,flt in [('server',c,'sport'),('client',peer,'dport')])
        wait(connected,10)
        self.stages['transport']=True
        self.failure_stage=6
        target_request='received request for tcp:127.0.0.1:'+str(self.echo_port)
        wait(lambda:target_request in (self.out/'server').read_text(errors='replace').lower(),10)
        self.stages['authenticated_request']=True
        self.failure_stage=7
        wait(lambda:any(r[0]=='rx' for r in records(self.out/'stream')),12)
        self.sockets=self.external()
        self.stages['first_echo']=True
        self.failure_stage=0

    def external(self):
        c,peer=self.net
        left=transport(c,'uc0',self.procs['server'].pid,'server',self.port)
        right=transport(peer,'up0',self.procs['client'].pid,'client',self.port)
        lab.require(left[:2]==right[:2][::-1],'proxy tuple pairing')
        return [left,right]

    def finish(self,t):
        stream_rows=records(self.out/'stream')
        echo_rows=records(self.out/'echo')
        sent={r[1]:r[2] for r in stream_rows if r[0]=='tx'}
        echoes={r[1]:r[2] for r in echo_rows}
        replies=[r for r in stream_rows if r[0]=='rx']
        lab.require(len(echoes)==len(echo_rows) and all(sent.get(i)==stamp for i,stamp in echoes.items()) and
                    all(echoes.get(r[1])==r[2] for r in replies) and [r[1] for r in replies]==list(range(len(replies))),'echo payload provenance')
        c,peer=self.net
        def listening(ns,name,port):
            return f'pid={self.procs[name].pid},' in lab.cmd(*ns,'ss','-Hlntp','sport = :'+str(port))
        return dict(pre_replies=sum(r[3]<t for r in replies),server_pre=sum(r[3]<t for r in echo_rows),
                    fresh_server=sum(r[2]>=t for r in echo_rows),fresh_replies=sum(r[2]>=t for r in replies),
                    queued_replies=sum(r[2]<t<=r[3] for r in replies),post_tx=sum(stamp>=t for stamp in sent.values()),
                    last_reply=max((r[3] for r in replies),default=0),last_server=max((r[3] for r in echo_rows),default=0),
                    first_post=min((stamp for stamp in sent.values() if stamp>=t),default=0),
                    same_transport=self.external()==self.sockets,server_inode=self.sockets[0][2],client_inode=self.sockets[1][2],
                    server_listener=listening(c,'server',self.port),client_listener=listening(peer,'client',18884 if self.protocol=='reality' else 18882),
                    participants_alive=all(p.poll() is None for k,p in self.procs.items() if not k.endswith('-test')))

if __name__=='__main__':
    {'echo':echo,'stream':stream}[sys.argv[1]](int(sys.argv[2]))
