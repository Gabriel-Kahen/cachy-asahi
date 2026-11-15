# SPDX-License-Identifier: MIT
"""Finite hosted Source/DATA guards. Root authentication is an external premise."""
import hashlib
import importlib.util
import os
import json
import math
from pathlib import Path
import re
import stat

ROOT=Path(__file__).resolve().parents[1]
COMPONENT_MAP='__LIFECYCLE_CODE_MAP_SHA__'
ACTUAL=dict(source=None,ref=None,run=None,job=None,reader=None,authority=None,approval=None,artifact=None,image=None,container=None)
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-perl5423-installed-lifecycle-v1.yml')
OPERATION='perl5423-installed-lifecycle-native-v1'
MAX_JSON=1024**2

def need(ok,why):
    if not ok:raise ValueError(why)


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def path(value):
    p=Path(value)
    need(p.is_absolute() and '..' not in p.parts and not any(c in str(p) for c in '\0\n\r,:') and not any(x.is_symlink() for x in (p,*p.parents)),'ordinary absolute path required')
    return p


def read(value,limit=MAX_JSON):
    p=path(value);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit,'bounded single-link DATA required')
        data=bytearray()
        while chunk:=os.read(fd,min(65536,limit+1-len(data))):
            data.extend(chunk);need(len(data)<=limit,'DATA byte bound')
        key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(data)==before.st_size and key(before)==key(os.fstat(fd))==key(p.lstat()),'DATA changed during read')
        return bytes(data)
    finally:os.close(fd)


def decode(raw,limit=MAX_JSON):
    need(type(raw) is bytes and len(raw)<=limit,'bounded JSON bytes')
    def pairs(rows):
        out={}
        for k,v in rows:need(k not in out,'duplicate JSON key');out[k]=v
        return out
    def invalid(value):raise ValueError('nonfinite JSON')
    def real(value):
        f=float(value);need(math.isfinite(f),'finite JSON number');return f
    try:value=json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid,parse_float=real)
    except RecursionError as error:raise ValueError('JSON depth') from error
    stack=[(value,0)];count=0
    while stack:
        item,depth=stack.pop();count+=1;need(depth<=32 and count<=100000,'JSON structure bound')
        if isinstance(item,dict):stack.extend((v,depth+1) for v in item.values())
        elif isinstance(item,list):stack.extend((v,depth+1) for v in item)
    return value


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,file);module=importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name]=module;spec.loader.exec_module(module);return module



def verify_source(root,expected):
    root=Path(root);raw=read(root/'source-map.json');need(pin(raw)['sha256']==expected,'whole Root-reviewed hosted Source map')
    m=decode(raw);need(m['schema']==1 and m['actual']==ACTUAL and 1<=len(m['files'])<=320,'bounded unpublished closed Source')
    files=m['files'];nodes=[]
    for directory,dirs,names in os.walk(root,followlinks=False):
        base=Path(directory)
        for name in tuple(dirs):
            p=base/name;need(not p.is_symlink(),'Source directory alias')
            if base==root and name=='.git':dirs.remove(name)
            else:nodes.append(p)
        nodes.extend(base/name for name in names);need(len(nodes)<=1500,'bounded Source nodes')
    need(all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in nodes),'ordinary Source nodes')
    expected_names=set(files)|{'source-map.json'}
    need({str(p.relative_to(root)) for p in nodes if p.is_file()}==expected_names,'complete Source membership')
    dirs={str(p) for name in expected_names for p in Path(name).parents if str(p)!='.'}
    need({str(p.relative_to(root)) for p in nodes if p.is_dir()}==dirs,'complete Source directory membership')
    total=0
    for name,row in files.items():
        need(type(name) is str and re.fullmatch('[A-Za-z0-9._+/-]{1,240}',name) and all(x not in ('','.','..') for x in name.split('/')),'ordinary Source leaf')
        p=root/name;body=read(p,64*1024**2);total+=len(body)
        need(dict(**pin(body),mode=stat.S_IMODE(p.stat().st_mode))==row,'Source byte/mode drift: '+name)
    need(total<=96*1024**2 and read(root/ALIASES[0])==read(root/ALIASES[1]),'finite Source and identical workflow aliases')
    need(pin(read(root/'lifecycle-code-map.json'))['sha256']==COMPONENT_MAP,'exact pinned lifecycle code snapshot')
    return m


def context(source,map_sha,approval,env):
    need(re.fullmatch('[0-9a-f]{40}',source or '') and re.fullmatch('[0-9a-f]{64}',map_sha or '') and re.fullmatch('[0-9a-f]{64}',approval or ''),'Root Source/map/approval operand bindings')
    ref=env.get('GITHUB_REF','');run=env.get('GITHUB_RUN_ID','')
    need(env.get('GITHUB_SHA')==env.get('GITHUB_WORKFLOW_SHA')==source and ref.startswith('refs/heads/codex/') and re.fullmatch('[1-9][0-9]{0,19}',run),'same actual Source/ref/run')
    need(env.get('GITHUB_RUN_ATTEMPT')=='1' and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and env.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi' and env.get('GITHUB_WORKFLOW_REF') in {'Gabriel-Kahen/cachy-asahi/'+name+'@'+ref for name in ALIASES},'first dedicated manual workflow only')
    need(env.get('GITHUB_ACTIONS')=='true' and env.get('RUNNER_ARCH')=='ARM64' and env.get('RUNNER_OS')=='Linux' and os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1001,'actual hosted native coordinator1001 required')
    need(env.get('LIFECYCLE_OPERATION')==OPERATION and not any(k.startswith(('LD_','DOCKER_','GIT_','CACHY_OLD_FOUR_','CACHY_RETAINED_')) for k in env),'no ambient policy/loader/private-cache overrides in hosted entry')
    return dict(source=source,ref=ref,run=run,approval=approval,source_map_sha256=map_sha,component_map_sha256=COMPONENT_MAP,operation=OPERATION)


def daemon_data(info,version,host,socket,storage):
    need(host['system']=='Linux' and host['machine']=='aarch64' and host['uid']==host['gid']==1001,'actual native coordinator')
    need(version['Server']['Os']=='linux' and version['Server']['Arch'] in ('arm64','aarch64') and info['OSType']=='linux' and info['Architecture'] in ('arm64','aarch64'),'actual native daemon')
    need(socket['path']=='/var/run/docker.sock' and socket['uid']==0 and socket['socket'] is True and socket['stable'] is True,'authenticated stable root-owned local daemon socket')
    opts=info.get('SecurityOptions');need(type(opts) is list and not any('rootless' in x or 'userns' in x for x in opts),'initial rootful unremapped daemon profile only')
    need(info.get('CgroupVersion')=='2' and all(info.get(k) is True for k in ('CpuCfsQuota','MemoryLimit','SwapLimit','PidsLimit')),'actual cgroup enforcement required')
    need(type(info.get('ID')) is str and info['ID'] and storage['path']==info['DockerRootDir'] and storage['canonical'] is True and storage['accessible'] is True,'actual local visible daemon storage identity')
    need(type(storage['total_inodes']) is int and 0<storage['available_inodes']<=storage['total_inodes'] and storage['available_inodes']>=120000,'fixed inode pool required')
    need(storage['available_bytes']>=8*1024**3 and host['MemAvailable_bytes']>=8*1024**3,'hosted bootstrap storage/RAM admission reserve')
    rows=storage['work_filesystems'];need(type(rows) is list and len(rows)==4,'actual input/cache/carrier/work filesystem observations')
    base=Path(rows[0]['path'])
    need(base.is_absolute() and '..' not in base.parts and [r['path'] for r in rows]==[str(p) for p in (base,base/'perl-lifecycle-hosted',base/'alarm-cache',base/'pgo-hosted-retained')],'exact hosted allocation paths')
    for row in rows:
        need(row['canonical'] is row['accessible'] is True and all(type(row[k]) is int for k in ('device','available_bytes','total_inodes','available_inodes')) and row['available_bytes']>=8*1024**3 and 120000<=row['available_inodes']<=row['total_inodes'],'each actual bootstrap filesystem retains byte/inode reserve')
    return dict(schema=1,status='OBSERVED_ROOTFUL_NATIVE_LOCAL_DAEMON_PRECONDITIONS',info=info,version=version,host=host,socket=socket,storage=storage,native_acceptance=False)
