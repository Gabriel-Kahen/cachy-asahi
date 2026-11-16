# SPDX-License-Identifier: MIT
"""Fixed kernel mountinfo preentry DATA proof; no tools, writes or authority."""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time

MAX_BYTES=1024**2
ALIASES=('/stage0','/work/build/stage0')
PHASES=('qualification-data','qualification-probe','prepare','makepkg','build','package')


def need(value,why):
    if not value:raise ValueError(why)


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def sha(value):return type(value)is str and re.fullmatch('[0-9a-f]{64}',value)is not None


def path(value):
    # Only canonical kernel octal escapes; no recursive/alternate spellings.
    def unescape(match):
        need(match[0]=='\\040','ambiguous/control/backslash mountinfo escape')
        return ' '
    result=re.sub(r'\\[0-9]{3}',unescape,value)
    need('\\'not in result and not any(ord(c)<32 or ord(c)==127 for c in result),'unsafe mountinfo path')
    p=PurePosixPath(result)
    need(p.anchor=='/'and p.as_posix()==result and all(x not in('.','..')for x in p.parts),'canonical absolute kernel path')
    return result


def options(value):
    rows=value.split(',')
    need(all(rows)and len(rows)==len(set(rows))and ('ro'in rows)^('rw'in rows),'unambiguous ro/rw mount options')
    return sorted(rows)


def parse(raw):
    need(type(raw)is bytes and 0<len(raw)<=MAX_BYTES and raw.endswith(b'\n'),'bounded complete kernel mountinfo')
    lines=raw.decode('utf-8',errors='strict').splitlines();need(0<len(lines)<=4096,'mountinfo row bound')
    rows={};ids=set();deadline=time.monotonic()+2
    for line in lines:
        need(time.monotonic()<deadline and 0<len(line)<=8192 and line.count(' - ')==1,'mountinfo line/deadline bound')
        left,right=line.split(' - ');a,b=left.split(' '),right.split(' ')
        need(len(a)>=6 and len(b)==3 and all(a+b),'complete mountinfo fields')
        need(re.fullmatch('[1-9][0-9]*',a[0])and re.fullmatch('[1-9][0-9]*',a[1])and
             re.fullmatch('(0|[1-9][0-9]*):(0|[1-9][0-9]*)',a[2]),'literal mount IDs/device')
        ident,parent=int(a[0]),int(a[1]);target=path(a[4]);root=path(a[3])
        need(ident not in ids and target not in rows,'unique kernel mount IDs/targets');ids.add(ident)
        need(re.fullmatch('[A-Za-z0-9_.+-]+',b[0])and all(32<ord(c)<127 for c in b[1]),'finite filesystem/source fields')
        rows[target]=dict(mount_id=ident,parent_id=parent,device=a[2],root=root,target=target,
            options=options(a[5]),optional=a[6:],fs_type=b[0],source=b[1],super_options=options(b[2]))
    need('/'in rows,'kernel root mount required')
    return rows


def context(value):
    need(type(value)is dict and set(value)=={'source','dispatch_sha256','input_admission_sha256','image_id','volume_token','phase'},'exact preentry context')
    s=value['source'];need(type(s)is dict and set(s)=={'sha','ref','map_sha256','approval','run','job'}and
        re.fullmatch('[0-9a-f]{40}',s['sha']or'')and re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',s['ref']or'')and
        sha(s['map_sha256'])and sha(s['approval'])and all(re.fullmatch('[1-9][0-9]{0,19}',s[k]or'')for k in('run','job')),'actual Source/provider context')
    need(sha(value['dispatch_sha256'])and sha(value['input_admission_sha256'])and
         re.fullmatch('sha256:[0-9a-f]{64}',value['image_id']or'')and
         re.fullmatch('[0-9a-f]{24}',value['volume_token']or'')and value['phase']in PHASES,'exact bound preentry phase/image/grant/token')
    return value


def verify(raw,ctx,name,helper_sha256):
    context(ctx);need(sha(helper_sha256)and re.fullmatch(r'kernel-mountinfo-[A-Za-z0-9-]{1,128}\.raw',name),'fixed proof helper/raw member')
    rows=parse(raw);aliases=ctx['phase']in('qualification-probe','makepkg','build','package')
    selected={'/work',*ALIASES}if aliases else{'/work'}
    relevant={target for target in rows if target=='/work'or target.startswith('/work/')or
              any(target==p or target.startswith(p+'/')for p in ALIASES)}
    need(relevant==selected,'no unexpected work/stage0 shadow or alias mounts')
    need('ro'in rows['/']['options']and 'rw'not in rows['/']['options'],'readonly kernel image root')
    work=rows['/work'];need('rw'in work['options']and 'ro'not in work['options']and
        'rw'in work['super_options']and work['parent_id']==rows['/']['mount_id'],'one writable work mount under kernel root')
    expected=(PurePosixPath(work['root'])/'build/stage0').as_posix()
    for target in ALIASES if aliases else():
        row=rows[target]
        need(row['root']==expected and row['device']==work['device']and row['fs_type']==work['fs_type']and
             row['source']==work['source']and row['super_options']==work['super_options'],'exact same-filesystem relative stage0 subroot')
        need('ro'in row['options']and 'rw'not in row['options']and
             row['parent_id']==(work['mount_id']if target.startswith('/work/')else rows['/']['mount_id']),'readonly alias and exact parent mount')
    for target in selected:
        need(not any(x=='unbindable'or x.startswith(('shared:','master:','propagate_from:'))for x in rows[target]['optional']),'private selected mount propagation')
    return dict(schema=13,status='PASS_KERNEL_MOUNTINFO_PREENTRY_DATA_ONLY',context=ctx,
        profile='stage0-aliases'if aliases else'work-only',helper_sha256=helper_sha256,
        mountinfo=dict(file=name,**pin(raw)),mounts={k:rows[k]for k in sorted(selected)},alias_root=expected if aliases else None,
        order=dict(stage='BEFORE_WORKSPACE_MUTATION_AND_TOOLS',commands_before=0,workspace_writes_before=0),
        native_acceptance=False,holds_preserved=True)


def read_kernel():
    def once():
        fd=os.open('/proc/self/mountinfo',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode),'kernel mountinfo regular proc file')
            raw=b''
            while True:
                block=os.read(fd,min(65536,MAX_BYTES+1-len(raw)))
                if not block:break
                raw+=block;need(len(raw)<=MAX_BYTES,'kernel mountinfo byte cap')
            need((before.st_dev,before.st_ino,before.st_mode)==tuple(getattr(os.fstat(fd),k)for k in('st_dev','st_ino','st_mode')),'stable kernel proc file')
            return raw
        finally:os.close(fd)
    first=once();need(first==once(),'kernel mount table changed during preentry');return first


def observe(ctx,name):
    raw=read_kernel()
    try:return raw,verify(raw,ctx,name,pin(Path(__file__).read_bytes())['sha256'])
    except ValueError:
        # No workspace mutation on refusal. The owned attach stderr retains
        # bounded, escaped fixed-proc DATA for diagnosis, never a PASS proof.
        print(json.dumps(dict(status='HOLD_KERNEL_MOUNTINFO_PREENTRY',code='KERNEL_MOUNTINFO_PROOF_REFUSED',
            mountinfo=pin(raw),mountinfo_base64=base64.b64encode(raw).decode('ascii')),sort_keys=True),file=sys.stderr,flush=True)
        raise


def validate(raw,receipt,ctx):
    need(receipt==verify(raw,ctx,receipt['mountinfo']['file'],pin(Path(__file__).read_bytes())['sha256']),
         'whole actual kernel preentry receipt/raw/context differs')
    return receipt
