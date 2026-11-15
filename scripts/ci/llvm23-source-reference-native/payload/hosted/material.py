# SPDX-License-Identifier: MIT
"""Future one-original HTTPS intake and safe DATA source extraction; no build here."""
import hashlib
import http.client
import json
from pathlib import Path, PurePosixPath
import ssl
import tarfile
import time
from urllib.parse import urljoin,urlsplit


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def acquire(root,work,command):
    contract=json.loads((root/'contract.json').read_bytes());pin=contract['source'];target=work/'llvm-material'
    if target.exists():raise ValueError('one-shot fresh LLVM material intake required')
    target.mkdir(mode=0o700);archive=target/'archive.tar.xz';ledger=dict(status='STARTED',requests=[],body_bytes=0)
    start=time.monotonic();url=contract['source_url'];limit=192*1024**2
    def save():(target/'acquisition.json').write_text(json.dumps(ledger,sort_keys=True,indent=2)+'\n')
    save()
    try:
        while True:
            if len(ledger['requests'])>=4 or time.monotonic()-start>=600 or command.cancelled[0]:raise ValueError('LLVM HTTPS deadline/request/cancellation refusal')
            part=urlsplit(url)
            if part.scheme!='https' or part.username or part.password or part.port not in (None,443):raise ValueError('HTTPS-only original/redirect required')
            row=dict(host=part.hostname,path=part.path,bytes=0);ledger['requests'].append(row);save()
            connection=http.client.HTTPSConnection(part.hostname,timeout=min(30,600-(time.monotonic()-start)),context=ssl.create_default_context())
            try:
                connection.request('GET',part.path+('?' + part.query if part.query else ''),headers={'Accept-Encoding':'identity'})
                response=connection.getresponse();row['status']=response.status
                if response.status in (301,302,303,307,308):
                    location=response.getheader('Location')
                    if not location:raise ValueError('missing redirect location')
                    # Do not read redirect bodies; no automatic retry.
                    url=urljoin(url,location);continue
                if response.status!=200 or response.getheader('Content-Length') and int(response.getheader('Content-Length'))!=pin['bytes']:raise ValueError('unexpected original status/size')
                h=hashlib.sha256()
                with archive.open('xb') as stream:
                    while True:
                        if response.length==0:break
                        if command.cancelled[0] or time.monotonic()-start>=600:raise ValueError('LLVM intake deadline/cancellation')
                        remaining=limit-ledger['body_bytes']
                        if remaining<=0:raise ValueError('LLVM body byte bound')
                        chunk=response.read(min(1024**2,remaining))
                        if not chunk:break
                        stream.write(chunk);h.update(chunk);row['bytes']+=len(chunk);ledger['body_bytes']+=len(chunk);save()
                if row['bytes']!=pin['bytes'] or h.hexdigest()!=pin['sha256']:raise ValueError('LLVM whole size/SHA256 differs')
                break
            finally:connection.close()
        destination=target/'tree';destination.mkdir()
        seen=set();logical=0
        with tarfile.open(archive,'r|xz') as stream:
            for item in stream:
                if command.cancelled[0] or time.monotonic()-start>=600:raise ValueError('LLVM DATA extraction deadline/cancellation')
                p=PurePosixPath(item.name)
                if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='llvm-project-23.1.1.src' or item.name in seen or not(item.isfile() or item.isdir() or item.issym() or item.islnk()):raise ValueError('LLVM tar namespace/type refused')
                seen.add(item.name);logical+=item.size
                if len(seen)>600000 or logical>8*1024**3:raise ValueError('LLVM logical archive bounds')
                stream.extract(item,path=destination,filter='data');stream.members.clear()
        source=destination/'llvm-project-23.1.1.src'
        for component,expected in json.loads((root/'packages/port/llvm23-source-reference/inputs.json').read_bytes())['notices'].items():
            if sha(source/component/'LICENSE.TXT')!=expected:raise ValueError('LLVM source notice differs: '+component)
        ledger.update(status='EXACT_ARCHIVE_AND_SOURCE_DATA_RETAINED',sha256=pin['sha256'],bytes=pin['bytes'],members=len(seen),logical_bytes=logical,elapsed_seconds=time.monotonic()-start)
        save();return dict(archive=str(archive),root=str(source),acquisition_sha256=sha(target/'acquisition.json'))
    except BaseException as error:
        ledger.update(status='FAIL_NO_RETRY',error=type(error).__name__+': '+str(error));save();raise
