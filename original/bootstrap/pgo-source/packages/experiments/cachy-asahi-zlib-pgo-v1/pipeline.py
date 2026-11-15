#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite PGO construction inside the explicit offline native builder only."""
import argparse,gzip,hashlib,importlib.util,json,os,platform,re,shlex,shutil,signal,stat,sys,time,zlib
from pathlib import Path
sys.dont_write_bytecode=True
SOURCE_SHA='bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
WORK=Path('/tmp/build');PROFILE=Path('/tmp/profile')
PREFIX='/usr/lib/cachy-asahi/experiments/zlib-pgo-v1'
BASE='-O2 -g -march=armv8-a -mtune=generic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -frandom-seed=$@ -fno-lto'
LINK='-pie -Wl,-z,relro,-z,now,-z,max-page-size=65536,-z,common-page-size=16384 -fno-lto'
GENERATE=' -fprofile-generate=/tmp/profile -fprofile-reproducible=serial'
USE=' -fprofile-use=/tmp/profile -Werror=missing-profile -Werror=coverage-mismatch'
LOCALS={'arm_c01.py','corpus.py','pgo.py','supervisor.py','probe.c','strict-gzip.c','LICENSE.project','training.bin','validation.bin','corpus-policy.json','corpus_controls.py','profile_seal.py','pipeline.py'}
PAYLOAD=('libz.a','minigzip','example','probe','strict-gzip','zlib.h','zconf.h','LICENSE')
TOOLS=('gcc','gcc-ar','gcc-ranlib','ld','gcov-tool','make','as')
# Exact package DATA policy; runtime node, inode and ownership remain observations.
TOOL_POLICY={
  "as": {
    "hardlinks": [
      "/usr/bin/as"
    ],
    "mode": 493,
    "package": {
      "arch": "aarch64",
      "name": "binutils",
      "version": "2.46+r70+g155188ea10a7-1"
    },
    "package_info_sha256": "cc01559fae9be3cd44816664d2d74280d444ae4c473d98f9ef799eabdc2be920",
    "path": "/usr/bin/as",
    "payload": {
      "bytes": 660992,
      "sha256": "ff23e1813fd9b31af1113d13fe580c61a76b4978dbe64a29b0dd11424c04fe0e"
    },
    "resolved_path": "/usr/bin/as",
    "symlinks": {}
  },
  "cc1": {
    "hardlinks": [
      "/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/cc1"
    ],
    "mode": 493,
    "package": {
      "arch": "aarch64",
      "name": "gcc",
      "version": "16.1.1+r12+g301eb08fa2c5-1"
    },
    "package_info_sha256": "56802bce100ccff46ea6a02ec84eb0a61bb69ddef5aeebc6df3d36d8c032e2af",
    "path": "/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/cc1",
    "payload": {
      "bytes": 39473352,
      "sha256": "01be12f35423d142ca7d54518108ad265c422eff61213308f39d480dfca8d897"
    },
    "resolved_path": "/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/cc1",
    "symlinks": {}
  },
  "collect2": {
    "hardlinks": [
      "/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/collect2"
    ],
    "mode": 493,
    "package": {
      "arch": "aarch64",
      "name": "gcc",
      "version": "16.1.1+r12+g301eb08fa2c5-1"
    },
    "package_info_sha256": "56802bce100ccff46ea6a02ec84eb0a61bb69ddef5aeebc6df3d36d8c032e2af",
    "path": "/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/collect2",
    "payload": {
      "bytes": 1444840,
      "sha256": "340d42346cbd6f6b5bb36ff8c04605290d4e1b9d3a17712eea1b07adc16548df"
    },
    "resolved_path": "/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/collect2",
    "symlinks": {}
  },
  "gcc": {
    "hardlinks": [
      "/usr/bin/aarch64-unknown-linux-gnu-gcc",
      "/usr/bin/aarch64-unknown-linux-gnu-gcc-16.1.1",
      "/usr/bin/gcc"
    ],
    "mode": 493,
    "package": {
      "arch": "aarch64",
      "name": "gcc",
      "version": "16.1.1+r12+g301eb08fa2c5-1"
    },
    "package_info_sha256": "56802bce100ccff46ea6a02ec84eb0a61bb69ddef5aeebc6df3d36d8c032e2af",
    "path": "/usr/bin/gcc",
    "payload": {
      "bytes": 2365000,
      "sha256": "741ced8152a820a28ab88603dd1ceb2343245728ac784839e4b5390f2411890e"
    },
    "resolved_path": "/usr/bin/gcc",
    "symlinks": {
      "/usr/bin/cc": "gcc"
    }
  },
  "gcc-ar": {
    "hardlinks": [
      "/usr/bin/aarch64-unknown-linux-gnu-gcc-ar",
      "/usr/bin/gcc-ar"
    ],
    "mode": 493,
    "package": {
      "arch": "aarch64",
      "name": "gcc",
      "version": "16.1.1+r12+g301eb08fa2c5-1"
    },
    "package_info_sha256": "56802bce100ccff46ea6a02ec84eb0a61bb69ddef5aeebc6df3d36d8c032e2af",
    "path": "/usr/bin/gcc-ar",
    "payload": {
      "bytes": 67752,
      "sha256": "05d4a9c44e5093548fb55a4f09397efcbed205923d0320a6c9b4173a862467a5"
    },
    "resolved_path": "/usr/bin/gcc-ar",
    "symlinks": {}
  },
  "gcc-ranlib": {
    "hardlinks": [
      "/usr/bin/aarch64-unknown-linux-gnu-gcc-ranlib",
      "/usr/bin/gcc-ranlib"
    ],
    "mode": 493,
    "package": {
      "arch": "aarch64",
      "name": "gcc",
      "version": "16.1.1+r12+g301eb08fa2c5-1"
    },
    "package_info_sha256": "56802bce100ccff46ea6a02ec84eb0a61bb69ddef5aeebc6df3d36d8c032e2af",
    "path": "/usr/bin/gcc-ranlib",
    "payload": {
      "bytes": 67752,
      "sha256": "cdb075d640c9e51b25eb008b1d5d0f88edf798ff731eafedba61615cd66e7773"
    },
    "resolved_path": "/usr/bin/gcc-ranlib",
    "symlinks": {}
  },
  "gcov-tool": {
    "hardlinks": [
      "/usr/bin/gcov-tool"
    ],
    "mode": 493,
    "package": {
      "arch": "aarch64",
      "name": "gcc",
      "version": "16.1.1+r12+g301eb08fa2c5-1"
    },
    "package_info_sha256": "56802bce100ccff46ea6a02ec84eb0a61bb69ddef5aeebc6df3d36d8c032e2af",
    "path": "/usr/bin/gcov-tool",
    "payload": {
      "bytes": 1379304,
      "sha256": "6319d1a0f2c31a3397bfb899cd87d7d438afe99427944706e5d617a817500ca2"
    },
    "resolved_path": "/usr/bin/gcov-tool",
    "symlinks": {}
  },
  "ld": {
    "hardlinks": [
      "/usr/bin/ld",
      "/usr/bin/ld.bfd"
    ],
    "mode": 493,
    "package": {
      "arch": "aarch64",
      "name": "binutils",
      "version": "2.46+r70+g155188ea10a7-1"
    },
    "package_info_sha256": "cc01559fae9be3cd44816664d2d74280d444ae4c473d98f9ef799eabdc2be920",
    "path": "/usr/bin/ld",
    "payload": {
      "bytes": 2500416,
      "sha256": "b07b094ae88efa267dda9314058a805a0e05a6133c6f5a88fd524dbe37e32dac"
    },
    "resolved_path": "/usr/bin/ld",
    "symlinks": {}
  },
  "libgcov.a": {
    "hardlinks": [
      "/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/libgcov.a"
    ],
    "mode": 420,
    "package": {
      "arch": "aarch64",
      "name": "gcc",
      "version": "16.1.1+r12+g301eb08fa2c5-1"
    },
    "package_info_sha256": "56802bce100ccff46ea6a02ec84eb0a61bb69ddef5aeebc6df3d36d8c032e2af",
    "path": "/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/libgcov.a",
    "payload": {
      "bytes": 76142,
      "sha256": "c38d3a6a45de49c2f5c872258edbc3a406405246dea87abe8fc7ab4e2c853c2f"
    },
    "resolved_path": "/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/libgcov.a",
    "symlinks": {}
  },
  "make": {
    "hardlinks": [
      "/usr/bin/make"
    ],
    "mode": 493,
    "package": {
      "arch": "aarch64",
      "name": "make",
      "version": "4.4.1-3"
    },
    "package_info_sha256": "fdf0da5b3ee0ae8c14f9617dda297b3a14e497a4a42fe4fd5e86f87bf96af33d",
    "path": "/usr/bin/make",
    "payload": {
      "bytes": 335688,
      "sha256": "710d136a4d85822d8019a964c89a26e4b99bd3cb6ada125db6f2360bb19c7787"
    },
    "resolved_path": "/usr/bin/make",
    "symlinks": {}
  }
}
_TOOL_ROOT=Path('/')

def need(ok,why):
    if not ok:raise ValueError(why)

def encoded(value):return (json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))

def read(path,cap=16*1024**2):
    path=Path(path);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap and not any(p.is_symlink()for p in(path,*path.parents)),'bounded ordinary single-link input: '+str(path))
    raw=path.read_bytes();need(len(raw)==info.st_size,'input changed while read');return raw

def ordinary(path):
    path=Path(path).absolute();need('..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute path');return path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

def inputs(root):
    root=ordinary(root);policy=json.loads(read(root/'recipe-policy.json'))
    need(set(policy)=={'schema','source_sha256','local_files','training','validation','training_seconds','build_seconds','job_seconds'} and policy['schema']==1 and policy['source_sha256']==SOURCE_SHA,'closed recipe policy')
    need(policy['training_seconds']==120 and policy['build_seconds']==180 and policy['job_seconds']==1200,'fixed finite budgets')
    need(set(policy['local_files'])==LOCALS,'complete local source closure')
    for name,row in policy['local_files'].items():need(pin(read(root/name))==row,'local source pin: '+name)
    need(sha(read(root/'zlib-1.3.2.tar.gz',8*1024**2))==SOURCE_SHA,'pinned upstream source archive')
    for role in ('training','validation'):
        row=policy[role];need(set(row)=={'path','bytes','sha256'} and row['path']==role+'.bin' and pin(read(root/row['path']))=={k:row[k]for k in('bytes','sha256')},'frozen '+role+' bytes')
    need(policy['training']['sha256']!=policy['validation']['sha256'],'disjoint training and validation bytes');return policy

def environment(cflags=BASE,ldflags=LINK):
    return dict(PATH='/usr/bin:/bin',HOME='/tmp/build-home',TMPDIR='/tmp',LC_ALL='C',LANG='C',TZ='UTC',SOURCE_DATE_EPOCH='1791748800',PYTHONDONTWRITEBYTECODE='1',CC='gcc',AR='gcc-ar',RANLIB='gcc-ranlib',CPPFLAGS='',CFLAGS=cflags,LDFLAGS=ldflags,MAKEFLAGS='-j2',QEMU_RUN='')

def training_plan(output):
    output=Path(output)
    return [dict(label='train-encode',argv=[str(WORK/'minigzip'),'-6'],input='training.bin',output='train.gz'),dict(label='train-decode',argv=[str(WORK/'minigzip'),'-d'],input='train.gz',output='train.decoded'),dict(label='train-example',argv=[str(WORK/'example'),str(output/'example.gz')],input=None,output=None),dict(label='train-gun',argv=[str(WORK/'gun')],input='train.gz',output='gun.decoded')]

def apply_use_flags(makefile,configure_log,core):
    raw=read(makefile);log=read(configure_log);baseline=core.configured_flags(raw,log,'baseline');suffix=shlex.split(baseline['CFLAGS'])[len(shlex.split(BASE)):]
    need(suffix and suffix[0]=='-fPIC','configure feature suffix');text=raw.decode()
    for name,value in [('CFLAGS',BASE+USE+' '+' '.join(suffix)),('LDFLAGS',LINK+USE)]:
        text,count=re.subn(r'(?m)^('+name+r'[ \t]*=[ \t]*)[^\n]*$',lambda m:m[1]+value,text);need(count==1,'one profile-use assignment: '+name)
    makefile.write_text(text);return core.configured_flags(read(makefile),log,'pgo')

def guard():
    need(platform.machine()=='aarch64' and os.geteuid()>0 and os.environ.get('CACHY_ASAHI_CONTAINER')=='1' and Path('/.dockerenv').is_file(),'explicit ordinary-user native isolated builder required')
    need(not WORK.exists() and not PROFILE.exists(),'fresh fixed build/profile paths required')
    need(Path('/out').is_dir() and not Path('/out/pgo-v1-evidence').exists(),'fresh retained builder evidence destination')

class Runner:
    def __init__(self,supervisor,output,seconds=1200):
        self.output=output;output.mkdir(mode=0o700);self.command=supervisor.Commands(output,seconds=seconds,builder_uid=os.geteuid())
    def run(self,label,argv,*,env=None,data=None,cwd=None,timeout=180,expected=0):
        result=self.command.run(label,argv,cwd=cwd,env=environment()if env is None else env,data=data,timeout=timeout,expected=expected);record=self.command.rows[-1]
        need(record['group_absent']is True and record['leader_held_until_group_inspection']is True and 'cleanup_error'not in record,'owned live group cleanup');return result
    def diagnostics(self):return read(self.output/self.command.rows[-1]['log'],16*1024**2)

def _tool_state(info):
    return {key:getattr(info,'st_'+key)for key in('dev','ino','mode','nlink','uid','gid','size','mtime_ns','ctime_ns')}

def _tool_path(value):
    need(type(value)is str and value.startswith('/')and str(Path(value))==value and'..'not in Path(value).parts,'normalized installed-tool path')
    return _TOOL_ROOT.joinpath(*Path(value).parts[1:])

def _tool_lstat(value):return _tool_path(value).lstat()

def _tool_snapshot(value,observed,kind):
    info=_tool_lstat(value);record=dict(_tool_state(info),kind=kind)
    if value in observed:need(observed[value]==record,'installed-tool node/alias changed between stages: '+value)
    else:observed[value]=record
    need(info.st_uid==info.st_gid==0,'installed-tool root ownership: '+value)
    if kind=='symlink':need(stat.S_ISLNK(info.st_mode),'declared tool symlink kind: '+value)
    else:
        need((stat.S_ISDIR(info.st_mode)if kind=='directory'else stat.S_ISREG(info.st_mode))and not info.st_mode&0o022,'installed-tool nonwritable '+kind+': '+value)
    return info

def _tool_parents(value,observed):
    for parent in reversed(Path(value).parents):_tool_snapshot(str(parent),observed,'directory')

def _tool_regular(value,observed,cap,links=1,mode=None):
    _tool_parents(value,observed);before=_tool_snapshot(value,observed,'regular')
    need(before.st_nlink==links and 0<before.st_size<=cap,'installed-tool size/link policy: '+value)
    if mode is not None:need(stat.S_IMODE(before.st_mode)==mode,'installed-tool exact package mode: '+value)
    fd=os.open(_tool_path(value),os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        need(_tool_state(os.fstat(fd))==_tool_state(before),'installed-tool opened FD/path differs: '+value)
        chunks=[];size=0
        while True:
            block=os.read(fd,min(65536,cap-size+1))
            if not block:break
            size+=len(block);need(size<=cap,'installed-tool payload exceeds bound: '+value);chunks.append(block)
        need(size==before.st_size and _tool_state(os.fstat(fd))==_tool_state(before),'installed-tool changed during FD read: '+value)
    finally:os.close(fd)
    need(_tool_state(_tool_lstat(value))==_tool_state(before),'installed-tool path replaced after FD read: '+value)
    return b''.join(chunks)

def _tool_db_fields(raw):
    text=raw.decode();need('\0'not in text and len(text.splitlines())<=20000,'bounded installed package database DATA')
    fields={};current=None
    for line in text.splitlines():
        if not line:continue
        if line.startswith('%')and line.endswith('%'):
            current=line[1:-1];need(current and current not in fields,'duplicate installed package database field');fields[current]=[]
        else:
            need(current is not None,'installed package database field required');fields[current].append(line)
    return fields

def _tool_package(policy,observed):
    package=policy['package'];need(set(package)=={'name','version','arch'}and package['arch']=='aarch64','fixed native package identity policy')
    need(all(type(v)is str and re.fullmatch(r'[A-Za-z0-9+_.:@-]+',v)for v in package.values()),'bounded fixed installed package names')
    directory='/var/lib/pacman/local/'+package['name']+'-'+package['version']
    desc=_tool_db_fields(_tool_regular(directory+'/desc',observed,2*1024**2))
    need(all(desc.get(key)==[package[name]]for key,name in(('NAME','name'),('VERSION','version'),('ARCH','arch'))),'installed package name/version/architecture differs')
    files=_tool_db_fields(_tool_regular(directory+'/files',observed,2*1024**2)).get('FILES',[])
    need(files and len(files)==len(set(files))and all(not n.startswith('/')and'..'not in Path(n).parts and'\\'not in n for n in files),'closed ordinary installed package membership DATA')
    required=set(policy['hardlinks'])|set(policy['symlinks'])|{policy['path'],policy['resolved_path']}
    need(all(n.removeprefix('/')in files for n in required),'selected installed-tool package membership missing')
    return dict(package,selected_members=sorted(required),database='ROOT_OWNED_PACMAN_LOCAL_DATA')

def installed_tool(role,path,observation):
    need(role in TOOL_POLICY and path==TOOL_POLICY[role]['path'],'exact logical installed-tool role/path required')
    policy=TOOL_POLICY[role];observed=observation.setdefault('nodes',{});aliases={}
    observation.update(role=role,path=path,resolved_path=policy['resolved_path'],stage='NODE_LAYOUT')
    group=policy['hardlinks'];need(type(group)is list and group==sorted(set(group))and path in group and policy['resolved_path']==path,'exact regular/hardlink tool path policy')
    identity=None
    for member in group:
        _tool_parents(member,observed);info=_tool_snapshot(member,observed,'regular')
        need(info.st_nlink==len(group)and stat.S_IMODE(info.st_mode)==policy['mode'],'exact declared installed-tool hardlink group: '+member)
        node=(info.st_dev,info.st_ino);identity=node if identity is None else identity
        need(node==identity,'declared tool hardlink members do not share inode')
    for alias,target in policy['symlinks'].items():
        _tool_parents(alias,observed);_tool_snapshot(alias,observed,'symlink');actual=os.readlink(_tool_path(alias));aliases[alias]=actual
        need(actual==target and str(Path(alias).parent/target)in group,'exact declared installed-tool symlink route')
    observation['stage']='PACKAGE_DATABASE';observation['package']=_tool_package(policy,observed)
    observation['stage']='PAYLOAD_FD';raw=_tool_regular(path,observed,256*1024**2,links=len(group),mode=policy['mode'])
    need(pin(raw)==policy['payload'],'installed-tool exact package payload differs: '+role)
    for value,record in observed.items():
        need(_tool_state(_tool_lstat(value))=={k:v for k,v in record.items()if k!='kind'},'installed-tool node/parent/alias identity changed: '+value)
    need(all(os.readlink(_tool_path(alias))==target for alias,target in aliases.items()),'installed-tool symlink route changed during read')
    observation.update(stage='COMPLETE',status='PASS_PACKAGE_BOUND_INSTALLED_TOOL',payload=pin(raw),symlink_routes=aliases)
    return raw

def _tool_identity_diagnostics(runner,probe,error=None):
    output=Path(runner.output).parent;path=ordinary(output/'tool-identity-observations.json')
    previous=json.loads(read(path,4*1024**2))if path.exists()else dict(schema=1,role='INSTALLED_TOOL_IDENTITY_DATA',probes=[])
    need(len(previous['probes'])<5,'fixed five toolchain identity probes');previous['probes'].append(probe)
    raw=encoded(previous);need(len(raw)<=4*1024**2,'bounded installed-tool observations');path.write_bytes(raw)
    if error is not None:
        detail=dict(schema=1,status='INSTALLED_TOOL_IDENTITY_REFUSED',role='INSTALLED_TOOL_IDENTITY_DATA',error_type=type(error).__name__,error=str(error)[:2048],probe=probe)
        raw=encoded(detail);need(len(raw)<=4*1024**2,'bounded installed-tool error DATA')
        error_path=ordinary(output/'tool-identity-error.json')
        if error_path.exists():read(error_path,4*1024**2)
        error_path.write_bytes(raw)

def toolchain(runner):
    result={};identities={};probe=dict(status='UNFINISHED',tools=[])
    try:
        need(set(TOOL_POLICY)==set(TOOLS)|{'cc1','collect2','libgcov.a'},'exact ten installed-tool roles')
        for name in(*TOOLS,'cc1','collect2','libgcov.a'):
            row={};probe['tools'].append(row);raw=installed_tool(name,TOOL_POLICY[name]['path'],row);identities[name]=pin(raw)
        target=runner.run('tool-target',['gcc','-dumpmachine']).decode().strip();need(re.fullmatch(r'aarch64[-A-Za-z0-9_.]*linux[-A-Za-z0-9_.]*',target),'native GCC AArch64 Linux target')
        for name in TOOLS:
            policy=TOOL_POLICY[name];path=policy['path'];resolved=policy['resolved_path']
            version=runner.run('tool-'+name,[resolved,'--version']).decode().strip();need(version,'nonempty native tool version');result[name]=dict(path=path,resolved_path=resolved,**identities[name],version=version)
        for name,option in [('cc1','-print-prog-name=cc1'),('collect2','-print-prog-name=collect2'),('libgcov.a','-print-file-name=libgcov.a')]:
            path=runner.run('tool-path-'+name.replace('.','-'),['gcc',option]).decode().strip();need(path==TOOL_POLICY[name]['path'],'exact package-bound GCC companion path');result[name]=dict(path=path,resolved_path=TOOL_POLICY[name]['resolved_path'],**identities[name],version='gcc-derived '+name)
        probe['status']='PASS_ALL_TEN_INSTALLED_TOOL_IDENTITIES';_tool_identity_diagnostics(runner,probe)
        return dict(target=target,tools=result)
    except BaseException as error:
        probe['status']='FAIL';_tool_identity_diagnostics(runner,probe,error);raise

def source_map(directory):return {'upstream/'+p.relative_to(directory).as_posix():pin(read(p,8*1024**2))for p in sorted(directory.rglob('*'))if not p.is_dir()}

def fresh_source(root,core,expected=None):
    need(not WORK.exists(),'fresh same absolute source/build path');WORK.mkdir(mode=0o700);core.extract(root/'zlib-1.3.2.tar.gz',WORK);mapping=source_map(WORK)
    if expected is not None:need(mapping==expected,'clean source path/bytes identity')
    return mapping

def build_static(runner,phase,cflags,ldflags,core,use=False):
    runner.run('build-'+phase+'-configure',['./configure','--static','--prefix='+PREFIX],cwd=str(WORK),env=environment()if use else environment(cflags,ldflags))
    effective=apply_use_flags(WORK/'Makefile',WORK/'configure.log',core)if use else None
    runner.run('build-'+phase+'-static',['make','-j2','static'],cwd=str(WORK),env=environment(cflags,ldflags))
    profile_diagnostics(runner.diagnostics());return effective

def profile_diagnostics(raw):
    # Echoed -Werror=coverage-mismatch flags are commands, not diagnostics.
    need(not re.search(r'(?im)^[^\n]*\b(?:warning|error|fatal error):[^\n]*(?:profile|coverage)|^libgcov profiling error:',raw.decode()),'profile fallback/diagnostic refused')

def auxiliary(runner,root,phase):
    for name in ('probe','strict-gzip'):
        runner.run('build-'+phase+'-'+name+'-compile',['gcc',*shlex.split(BASE.replace('$@',name+'.o')),'-I'+str(WORK),'-DEXPERIMENT_VARIANT="pgo-v1"','-DEXPERIMENT_PREFIX="'+PREFIX+'"','-c',str(root/(name+'.c')),'-o',str(WORK/(name+'.o'))])
        runner.run('build-'+phase+'-'+name+'-link',['gcc',str(WORK/(name+'.o')),str(WORK/'libz.a'),'-o',str(WORK/name),*shlex.split(LINK)])

def correctness(runner,output,validation):
    roots=[output/'optimized-1',output/'optimized-2'];counts=dict(encodes=0,cross_decodes=0,strict_rejections=0,probes=0)
    data=[b'',b'x',b'cachy-asahi public workload\n'*4096,bytes(range(256))*1024]
    data += [bytes((i*13+i//257)&255 for i in range(n))for n in(16383,16384,16385)];data.append(validation)
    for index,root in enumerate(roots):
        probe=json.loads(runner.run('validate-probe-'+str(index),[str(root/'probe'),'--build-check'],timeout=15))
        need(probe==dict(status='PASS',variant='pgo-v1',prefix=PREFIX,zlib='1.3.2',source_sha256=SOURCE_SHA,roundtrips=21,negative_checks=42),'finite built probe identity');counts['probes']+=1
        for i,original in enumerate(data):
            for level in (1,6,9):
                label=f'validate-{index}-{i}-{level}';packed=runner.run(label+'-encode',[str(root/'minigzip'),'-'+str(level)],data=original,timeout=15)
                decoder=zlib.decompressobj(31);decoded=decoder.decompress(packed)+decoder.flush();need(decoded==original and decoder.eof and not decoder.unused_data,'independent Python whole-stream decode');counts['encodes']+=1
                for j,consumer in enumerate(roots):
                    decoded=runner.run(label+'-decode-'+str(j),[str(consumer/'strict-gzip')],data=packed,timeout=15);need(decoded==original,'cross-build strict decode');counts['cross_decodes']+=1
    reference=gzip.compress(data[2],mtime=0);bad=bytearray(reference);bad[-8]^=1
    for index,root in enumerate(roots):
        for i,invalid in enumerate((bytes(bad),reference[:-8],reference+b'garbage')):
            runner.run(f'validate-{index}-reject-{i}',[str(root/'strict-gzip')],data=invalid,expected=2,timeout=15);counts['strict_rejections']+=1
    return dict(**counts,input_pins=[pin(d)for d in data],includes_page_boundaries=[16383,16384,16385],physical16k='NOT RUN')

def retain_failed_profiles(directory,output):
    """Keep malformed/incomplete native counters as DATA before owned cleanup."""
    destination=output/'failed-profiles';destination.mkdir(mode=0o700);rows={};total=0
    entries=sorted(directory.iterdir());need(len(entries)<=4096,'failed profile leaf bound')
    for path in entries:
        try:
            body=read(path,4*1024**2);total+=len(body);need(total<=16*1024**2,'failed profile byte bound')
            (destination/path.name).write_bytes(body);rows[path.name]=pin(body)
        except(OSError,ValueError)as error:
            rows[path.name]=dict(retained=False,error_type=type(error).__name__,error=str(error)[:1024])
    (output/'failed-profile-inventory.json').write_bytes(encoded(rows));return rows

def construct(root,output):
    policy=inputs(root);root=ordinary(root);output=ordinary(output);guard()
    need(not output.exists() and output.parent.is_dir() and not root.is_relative_to(output),'fresh disjoint result directory');output.mkdir(mode=0o700)
    # Every imported helper is covered by the already reviewed local-source policy.
    load('corpus',root/'corpus.py');core=load('_pgo_core',root/'arm_c01.py');core.select_experiment('ARM-C03')
    old=load('_pgo_reference',root/'pgo.py');supervisor=load('_pgo_supervisor',root/'supervisor.py');seal=load('_pgo_seal',root/'profile_seal.py');corpora=load('_pgo_corpora',root/'corpus_controls.py');corpora.validate(root)
    runner=Runner(supervisor,output/'commands');prior={s:signal.signal(s,runner.command.cancel)for s in(signal.SIGINT,signal.SIGTERM)}
    report=dict(status='FAIL',source_sha256=SOURCE_SHA,hardware='NOT RUN',physical16k='NOT RUN',performance='NOT MEASURED',release='NOT_ADMITTED');made_work=False;made_profile=False
    try:
        observed=toolchain(runner);mapping=fresh_source(root,core);made_work=True;PROFILE.mkdir(mode=0o700);made_profile=True
        build_static(runner,'instrumented',BASE+GENERATE,LINK+GENERATE,core)
        runner.run('build-training-gun-compile',old._gun_compile(core),cwd=str(WORK))
        runner.run('build-training-gun-link',['gcc',str(WORK/'gun.o'),str(WORK/'libz.a'),'-o',str(WORK/'gun'),*shlex.split(LINK+GENERATE)],cwd=str(WORK))
        instrumented=output/'instrumented';instrumented.mkdir(mode=0o700)
        for name in ('libz.a','example','minigzip','gun','gun.o','Makefile','configure.log'):shutil.copyfile(WORK/name,instrumented/name)
        # Discard configure/build-probe counters. No heldout/correctness input has run.
        shutil.rmtree(PROFILE);PROFILE.mkdir(mode=0o700);plan=training_plan(output);training_results=[];began=time.monotonic()
        for row in plan:
            budget=120-(time.monotonic()-began);need(budget>0,'aggregate deterministic training deadline')
            source=root/'training.bin'if row['input']=='training.bin'else output/row['input']if row['input']else None
            raw=runner.run(row['label'],row['argv'],data=read(source)if source else None,cwd=str(WORK),timeout=budget)
            if row['output']:(output/row['output']).write_bytes(raw)
            training_results.append(dict(label=row['label'],stdout=pin(raw)))
        train=read(root/'training.bin');need(read(output/'train.decoded')==read(output/'gun.decoded')==train,'training exact roundtrips')
        decoder=zlib.decompressobj(31);need(decoder.decompress(read(output/'train.gz'))+decoder.flush()==train and decoder.eof and not decoder.unused_data,'independent training decode')
        need(zlib.decompress(read(output/'example.gz'),31)==b'hello, hello!\0','pinned upstream example fixed literals')
        native_profiles=old.profile_map(core,PROFILE);decoded=output/'decoded-profiles'
        runner.run('build-training-profile-decode',['gcov-tool','merge','-v','-w','1,1','-o',str(decoded),str(PROFILE),str(PROFILE)])
        old.check_profile_output(core,runner.diagnostics());old.profile_map(core,decoded);need(old.profile_map(core,PROFILE)==native_profiles,'decoder must not mutate original profiles')
        (output/'training-results.json').write_bytes(encoded(dict(plan=plan,results=training_results,profiles=native_profiles,instrumented={p.name:pin(read(p))for p in instrumented.iterdir()})))
        binding=dict(source_sha256=SOURCE_SHA,source_files={**mapping,**{'local/'+n:r for n,r in policy['local_files'].items()}},toolchain=observed,isa='armv8-a/generic',build_path=str(WORK),profile_path=str(PROFILE),prefix=PREFIX,
            training=dict(corpus=policy['training'],heldout=policy['validation'],command_plan_sha256=sha(encoded(plan)),results_sha256=sha(read(output/'training-results.json'))))
        sealed=seal.seal(PROFILE,binding,output/'profile-seal.json');original_seal=sealed['seal_sha256'];shutil.copytree(PROFILE,output/'profiles');shutil.rmtree(WORK);made_work=False
        effective=[];outputs=[]
        for attempt in (1,2):
            inputs(root);need(toolchain(runner)==observed,'exact training/use toolchain identity');seal.verify(PROFILE,binding,output/'profile-seal.json',expected_sha256=original_seal)
            fresh_source(root,core,mapping);made_work=True;effective.append(build_static(runner,'optimized-'+str(attempt),BASE+USE,LINK+USE,core,use=True))
            runner.run('build-optimized-'+str(attempt)+'-upstream-test',['make','teststatic'],cwd=str(WORK),env=environment(BASE+USE,LINK+USE));auxiliary(runner,root,'optimized-'+str(attempt))
            dest=output/('optimized-'+str(attempt));dest.mkdir(mode=0o700)
            for name in PAYLOAD:shutil.copyfile(WORK/name,dest/name)
            for name in ('minigzip','example','probe','strict-gzip'):(dest/name).chmod(0o755)
            for name in ('Makefile','configure.log'):shutil.copyfile(WORK/name,dest/(name+'.txt'))
            symbols=runner.run('build-optimized-'+str(attempt)+'-symbols',['gcc-nm',str(dest/'libz.a')]);need(b'__gcov_'not in symbols,'instrumented runtime survived profile-use build')
            elf=runner.run('elf-optimized-'+str(attempt),['readelf','-W','-h','-l',str(dest/'minigzip')]);need(b'AArch64'in elf,'native AArch64 ELF observation')
            outputs.append({n:pin(read(dest/n))for n in PAYLOAD});need(toolchain(runner)==observed,'toolchain changed during optimized build');seal.verify(PROFILE,binding,output/'profile-seal.json',expected_sha256=original_seal)
            shutil.rmtree(WORK);made_work=False
        need(outputs[0]==outputs[1],'two clean optimized payload builds differ');validation=correctness(runner,output,read(root/'validation.bin'));seal.verify(PROFILE,binding,output/'profile-seal.json',expected_sha256=original_seal)
        report.update(status='PASS_FINITE_PGO_CONSTRUCTION_AND_NATIVE_CORRECTNESS_ONLY',binding=binding,profile_seal_sha256=original_seal,outputs=outputs,effective_flags=effective,correctness=validation,native_page_size=os.sysconf('SC_PAGE_SIZE'),recipe_policy=pin(read(root/'recipe-policy.json')),profile_decode='GCC_NATIVE_DECODER_TRANSCRIPT_MATCHED',training_attempts=1,optimized_clean_builds=2,profile_use='SAME_SEALED_PROFILE_BOTH_BUILDS_NO_FALLBACK',optimization_acceptance='NOT RUN')
        return report
    except BaseException as error:
        report.update(error_type=type(error).__name__,error=str(error));raise
    finally:
        for sig,handler in prior.items():signal.signal(sig,handler)
        if report['status']=='FAIL' and made_profile and PROFILE.exists():
            report['failed_profiles']=retain_failed_profiles(PROFILE,output)
        if made_work:shutil.rmtree(WORK)
        if made_profile and PROFILE.exists():shutil.rmtree(PROFILE)
        (output/'result.json').write_bytes(encoded(report))
        leaves={p.relative_to(output).as_posix():pin(read(p,64*1024**2))for p in output.rglob('*')if p.is_file()}
        need(len(leaves)<=4096 and sum(r['bytes']for r in leaves.values())<=128*1024**2,'closed native evidence cap')
        (output/'receipt.json').write_bytes(encoded(dict(schema=1,status=report['status'],files=leaves,acceptance=False,performance='NOT MEASURED',hardware='NOT RUN')))
        shutil.copytree(output,Path('/out/pgo-v1-evidence'))

def check(output,root=None):
    output=ordinary(output);report=json.loads(read(output/'result.json',32*1024**2));need(report['status']=='PASS_FINITE_PGO_CONSTRUCTION_AND_NATIVE_CORRECTNESS_ONLY' and report['optimized_clean_builds']==2,'complete native construction required')
    if root is not None:
        policy=inputs(root);need(pin(read(Path(root)/'recipe-policy.json'))==report['recipe_policy'],'used recipe policy unchanged before packaging')
        need(all(report['binding']['source_files']['local/'+n]==p for n,p in policy['local_files'].items()),'used local sources unchanged before packaging')
    receipt=json.loads(read(output/'receipt.json'));leaves={p.relative_to(output).as_posix():pin(read(p,64*1024**2))for p in output.rglob('*')if not p.is_dir()and p!=output/'receipt.json'}
    need(len(leaves)<=4096 and sum(r['bytes']for r in leaves.values())<=128*1024**2,'closed passive evidence cap')
    need(set(receipt)=={'schema','status','files','acceptance','performance','hardware'} and receipt['schema']==1 and receipt['files']==leaves and receipt['status']==report['status'] and receipt['acceptance']is False,'complete retained native evidence receipt')
    for attempt,expected in enumerate(report['outputs'],1):need({n:pin(read(output/('optimized-'+str(attempt))/n))for n in PAYLOAD}==expected,'optimized payload pin differs')
    need(report['outputs'][0]==report['outputs'][1] and sha(read(output/'profile-seal.json'))==report['profile_seal_sha256'],'same payload/seal proof')
    source=Path(__file__).resolve().parent/'profile_seal.py'
    need(pin(read(source))==report['binding']['source_files']['local/profile_seal.py'],'retained profile validator source identity')
    validator=load('_pgo_check_seal',source);validator.verify(output/'profiles',report['binding'],output/'profile-seal.json',expected_sha256=report['profile_seal_sha256'])
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('build','check'));p.add_argument('--inputs',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:
        if a.action=='build':need(a.inputs is not None,'explicit input root');r=construct(a.inputs,a.output)
        else:r=check(a.output,a.inputs)
        print(json.dumps(dict(status=r['status'],hardware='NOT RUN',performance='NOT MEASURED',release='NOT_ADMITTED'),sort_keys=True));return 0
    except(OSError,ValueError,KeyError,TypeError)as error:print('PGO construction refused: '+str(error),file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
