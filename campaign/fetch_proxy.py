"""Only the pinned binary from the public release is placed on the offline disk."""
import hashlib
from pathlib import Path
import struct
import subprocess as sp
import sys
import zipfile

VERSION = '26.11.9'
PIN = 'b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82'
def fetch(work):
    archive = work/'upstream.zip'
    url = 'https://github.com/XTLS/Xray-core/releases/download/v'+VERSION+'/Xray-linux-64.zip'
    sp.run(['curl','-fsSL','--proto','=https','--proto-redir','=https','--max-time','120','-o',archive,url],check=True)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=PIN:
        raise ValueError('release digest')
    with zipfile.ZipFile(archive) as z:
        [item] = [i for i in z.infolist() if i.filename=='xray' and 0<i.file_size<150_000_000]
        data = z.read(item)
    if data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',data,18)[0]!=62:
        raise ValueError('ELF architecture')
    (work/'proxy-bin').write_bytes(data)
    print('SOURCE upstream proxy release digest verified')

if __name__=='__main__':
    try:
        fetch(Path(sys.argv[1]))
    except (OSError,ValueError,sp.SubprocessError,zipfile.BadZipFile):
        print('SOURCE optional proxy unavailable')
