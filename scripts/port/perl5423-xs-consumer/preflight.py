#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Read-only XS input preflight and future command plan; never execute a tool."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

HERE=Path(__file__).resolve().parent
CANDIDATE=dict(commit='c8e9baea97f83f652763e701143d6dec5b679f31',recipe_sha256='cf0df8990ac83f48a4c29978c932922108f0e01cb6d052209934da5b01af4068',source_sha256='16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725')
ARCH='usr/lib/perl5/5.42/core_perl';PURE='usr/share/perl5/core_perl';CORE=ARCH+'/CORE'
FIXTURE=('Makefile.PL','Consumer.xs','lib/CachyAsahi/Perl5423/Consumer.pm','t/roundtrip.t','provenance.pl')


def need(value,why):
    if not value:raise ValueError(why)


def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def sha(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def path(value):
    need(type(value) is str and re.fullmatch('/[A-Za-z0-9._+/-]+',value) and all(p not in ('','.','..') for p in value.split('/')[1:]),'canonical shell-safe absolute path')
    result=Path(value);need(not any(p.is_symlink() for p in (result,*result.parents)),'path aliases refused')
    return result


def read(value,cap=2*1024**2):
    p=path(str(value));fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded regular single-link input')
        pieces=[];size=0
        while block:=os.read(fd,min(65536,cap+1-size)):
            size+=len(block);need(size<=cap,'input byte bound');pieces.append(block)
        key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(size==before.st_size and key(before)==key(os.fstat(fd))==key(p.lstat()),'input changed during read')
        return b''.join(pieces)
    finally:os.close(fd)


def decode(raw):
    def unique(rows):
        out={}
        for key,value in rows:need(key not in out,'duplicate JSON key');out[key]=value
        return out
    def invalid(value):raise ValueError('noninteger JSON refused')
    need(len(raw)<=2*1024**2,'JSON byte bound')
    return json.loads(raw,object_pairs_hook=unique,parse_float=invalid,parse_constant=invalid)


def pinned(row,cap=64*1024**2):
    need(type(row) is dict and all(key in row for key in ('path','bytes','sha256')) and type(row['bytes']) is int and 0<row['bytes']<=cap and sha(row['sha256']),'explicit actual file pin required')
    raw=read(row['path'],cap);need(pin(raw)=={key:row[key] for key in ('bytes','sha256')},'actual input byte/hash differs')
    return raw


def metadata(raw):
    values={}
    for line in raw.decode().splitlines():
        if not line or line.startswith('#'):continue
        need(' = ' in line,'literal package metadata')
        key,value=line.split(' = ',1);values.setdefault(key,[]).append(value)
    return values


def validate(a,inputs,work):
    need(a['schema']==1 and a['candidate']==CANDIDATE and a['target_arch'] in ('x86_64','aarch64'),'exact reviewed1.3 candidate and target')
    root=path(a['root']['path']);kind=a['root']['kind'];need(kind in ('installed','extracted') and root!=Path('/'),'explicit disposable installed/extracted prefix')
    info=root.stat();need(stat.S_ISDIR(info.st_mode) and not stat.S_IMODE(info.st_mode)&0o022 and
        all(type(a['root'][k]) is int for k in ('owner_uid','device','inode')) and
        info.st_uid==os.getuid() and (info.st_uid,info.st_dev,info.st_ino)==tuple(a['root'][k] for k in ('owner_uid','device','inode')),'owned root identity/mode admission')
    artifact=a['artifact'];need(set(artifact)=={'kind','source','run','job'},'explicit artifact scope')
    if artifact['kind']=='native':
        need(a['target_arch']=='aarch64' and type(artifact['source']) is str and re.fullmatch('[0-9a-f]{40}',artifact['source']) and all(type(artifact[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',artifact[k]) for k in ('run','job')),'actual native artifact selectors required')
    else:need(artifact['kind']=='host' and a['target_arch']=='x86_64' and all(artifact[k] is None for k in ('source','run','job')),'bounded host scope; never native acceptance')
    archive=a['archive'];need(archive['name']=='perl-5.42.3-1.3-'+a['target_arch']+'.pkg.tar.zst' and Path(archive['path']).name==archive['name'],'exact candidate archive name')
    pinned(archive)
    need(inputs['schema']==1 and inputs['archive_sha256']==archive['sha256'] and inputs['candidate_recipe_sha256']==CANDIDATE['recipe_sha256'],'Root-reviewed archive/input-map join')
    rows=inputs['files'];need(type(rows) is dict and 1<=len(rows)<=5000,'finite complete candidate runtime/header map')
    required={'usr/bin/perl',CORE+'/perl.h',CORE+'/EXTERN.h',CORE+'/XSUB.h',CORE+'/config.h',CORE+'/patchlevel.h',CORE+'/libperl.so',ARCH+'/Config.pm',ARCH+'/Config_heavy.pl',PURE+'/ExtUtils/MakeMaker.pm'}
    need(required<=set(rows),'candidate executable/Config/MakeMaker/CORE inputs required')
    observed={'usr/bin/perl'}
    for prefix in (ARCH,PURE):
        nodes=list((root/prefix).rglob('*'));need(len(nodes)<=10000 and all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in nodes),'ordinary closed candidate runtime trees')
        observed.update(str(p.relative_to(root)) for p in nodes if p.is_file())
    need(observed==set(rows),'complete candidate runtime/header namespace differs')
    total=0
    for name,row in rows.items():
        need(re.fullmatch('[A-Za-z0-9._+/-]+',name) and all(x not in ('','.','..') for x in name.split('/')),'relative input leaf')
        body=read(root/name,32*1024**2);total+=len(body)
        need(dict(**pin(body),mode=stat.S_IMODE((root/name).stat().st_mode))==row,'candidate file pin differs: '+name)
    need(total<=128*1024**2,'candidate mapped byte bound')
    machine=183 if a['target_arch']=='aarch64' else 62
    for name in ('usr/bin/perl',CORE+'/libperl.so'):
        body=read(root/name,32*1024**2)
        need(len(body)>=64 and body[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',body,18)[0]==machine,'actual target ELF executable/library')
    need((root/'usr/bin/perl').stat().st_mode&0o111,'actual candidate executable permission')
    pkg=metadata(pinned(a['metadata']['pkginfo'],1024**2));build=metadata(pinned(a['metadata']['buildinfo'],1024**2))
    need(all(pkg.get(k)==[v] for k,v in [('pkgname','perl'),('pkgver','5.42.3-1.3'),('arch',a['target_arch'])]) and all(build.get(k)==[v] for k,v in [('pkgver','5.42.3-1.3'),('pkgarch',a['target_arch']),('pkgbuild_sha256sum',CANDIDATE['recipe_sha256'])]),'actual1.3 package/build metadata')
    pinned(a['inventory'],1024**2)
    need(set(a['toolchain'])=={'cc','ld','make'},'explicit compiler/linker-driver/make pins')
    for row in a['toolchain'].values():
        pinned(row,16*1024**2);need(path(row['path']).stat().st_mode&0o111,'actual executable toolchain input')
    work=path(str(work));wi=work.stat()
    need(wi.st_uid==os.getuid() and stat.S_IMODE(wi.st_mode)==0o700 and not work.is_relative_to(root) and not root.is_relative_to(work),'owned private disjoint fixture stage')
    leaves={str(p.relative_to(work)) for p in work.rglob('*') if p.is_file()}
    need(leaves==set(FIXTURE) and all(not p.is_symlink() for p in work.rglob('*')),'fresh exact fixture source stage, no prior outputs')
    for name in FIXTURE:need(read(work/name)==read(HERE/name),'reviewed original fixture bytes')
    return root,work


def plan(admission,admission_sha,inputs_file,inputs_sha,work):
    ar,ir=read(admission),read(inputs_file)
    need(pin(ar)['sha256']==admission_sha and pin(ir)['sha256']==inputs_sha,'externally reviewed whole admission/input pins')
    a,inputs=decode(ar),decode(ir);need(a['inputs_sha256']==inputs_sha,'admission input-map binding')
    root,work=validate(a,inputs,work);perl=str(root/'usr/bin/perl')
    env=dict(PATH=':'.join(dict.fromkeys(str(Path(a['toolchain'][k]['path']).parent) for k in ('cc','ld','make'))),HOME=str(work),LC_ALL='C',TZ='UTC',LD_LIBRARY_PATH=str(root/CORE),PERL_DL_NONLAZY='1',CACHY_XS_ROOT=str(root),CACHY_XS_PERL=perl,CACHY_XS_CORE=str(root/CORE),CACHY_XS_ADMISSION=str(path(str(admission))),CACHY_XS_ADMISSION_SHA256=admission_sha,CACHY_XS_INPUTS=str(path(str(inputs_file))),CACHY_XS_INPUTS_SHA256=inputs_sha)
    env.update({'CACHY_XS_'+k.upper():a['toolchain'][k]['path'] for k in ('cc','ld','make')})
    argv=[perl,'-I'+str(root/ARCH),'-I'+str(root/PURE)]
    return dict(status='PREFLIGHT_DATA_ONLY_XS_NOT_RUN',native_acceptance=False,cwd=str(work),environment_policy='REPLACE_ENTIRE_ENVIRONMENT_WITH_THIS_EXACT_MAP',environment=env,commands=[argv+['Makefile.PL'],[a['toolchain']['make']['path'],'-j2'],[a['toolchain']['make']['path'],'test'],argv+['provenance.pl']],archive=a['archive'],root=a['root'],artifact=a['artifact'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('admission','admission-sha256','inputs','inputs-sha256','work'):p.add_argument('--'+key,required=True)
    a=p.parse_args();print(encode(plan(Path(a.admission),a.admission_sha256,Path(a.inputs),a.inputs_sha256,Path(a.work))).decode(),end='')
