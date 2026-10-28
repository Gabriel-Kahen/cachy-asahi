# SPDX-License-Identifier: MIT
"""Check actual installed Done bytes and metadata inside the disposable guest."""
import hashlib,json,os,stat,struct
from pathlib import Path

ROOT=Path('/usr/local/share/desktop574')


def need(ok,msg):
    if not ok:raise ValueError(msg)


def verify(command):
    lock=json.loads((ROOT/'done-lock.json').read_bytes())
    need(lock['status']=='VERIFIED_RETAINED_DONE_PAIR_NOT_EXECUTED' and lock['name']=='cachy-asahi-fish-done' and lock['version']=='0.1.0-2','exact installed Done input required')
    need(command(['/usr/bin/pacman','-Q','cachy-asahi-fish-done']).strip()=='cachy-asahi-fish-done 0.1.0-2','installed package metadata differs')
    owned=set()
    for line in command(['/usr/bin/pacman','-Ql','cachy-asahi-fish-done']).splitlines():
        name,path=line.split(' ',1);need(name==lock['name'],'foreign installed owner')
        if not path.endswith('/'):owned.add(path.lstrip('/'))
    need(owned==set(lock['payload']),'actual installed Done ownership differs')
    result={}
    for name,row in lock['payload'].items():
        path=Path('/')/name;info=path.lstat()
        need(stat.S_ISREG(info.st_mode) and not any(p.is_symlink() for p in (path,*path.parents)) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==row['mode'] and info.st_size==row['size'],'installed Done node differs')
        raw=path.read_bytes();need(hashlib.sha256(raw).hexdigest()==row['sha256'],'installed Done bytes differ');result[name]=row['sha256']
    executables={}
    for name in ('fish','notify-send','timeout'):
        path=Path('/usr/bin')/name;need(path.is_file() and os.access(path,os.X_OK) and path.stat().st_size<=16*1024**2,'real system executable absent: '+name)
        raw=path.read_bytes();need(raw[:5]==b'\x7fELF\x02' and struct.unpack_from('<H',raw,18)[0]==183,'real AArch64 system executable required')
        executables[name]=dict(path=str(path),target=str(path.resolve()),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    return dict(status='PASS_ACTUAL_INSTALLED_DONE_PAYLOAD_METADATA',package=lock['name'],version=lock['version'],archive_sha256=lock['sha256'],files=result,executables=executables)
