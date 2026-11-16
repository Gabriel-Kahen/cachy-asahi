# SPDX-License-Identifier: MIT
"""Root-entry-gated native phases; frozen candidate bytes remain unchanged."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time

WORK=Path('/work/build');CANDIDATE=Path('/inputs/candidate')
DESTINATION=Path('/work/recipe/pkg/cachy-asahi-rust199-source-reference')
LLVM=Path('/opt/cachy-asahi/llvm23-source-reference')
REFERENCE_SHA='acb468c2a2ddf327d882835590facabdc89939131ba8c51ae35028688693c665'
INPUTS_SHA='4011253ed366f871b1f5e2cac1f5af0dc63049c1fa7badd293318adb44741672'
CONFIG_SHA='504ccbfc112d0258059f1d105c69fe0fb104331f232aaf93b096777bb24447fb'
STAGE0_BYTES={'cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz':11116188,'rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz':30768752,'rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz':66413136}
PROBE_VECTOR=['/usr/bin/python','-I','/work/reference-sandbox.py','probe']
BUILD_VECTOR=['/usr/bin/python','-I','./x.py','--config','bootstrap.toml','install','-j','2']
NATIVE_PROBE=['IN_PROCESS_SOURCE_PINNED_CANDIDATE_PROBE']
NATIVE_BUILD=['/usr/bin/python','-I','-B','./x.py','--config','bootstrap.toml','install','-j','2']
PROBE_COMMANDS=[['/stage0/bin/rustc','-vV'],['/stage0/bin/rustc','-vV'],['/stage0/bin/rustc','--print','sysroot'],['/stage0/bin/cargo','--version'],['/stage0/bin/rustdoc','--version'],[str(LLVM/'bin/llvm-config'),'--version'],[str(LLVM/'bin/llvm-config'),'--targets-built'],['/usr/bin/gcc','-dumpmachine'],[str(LLVM/'bin/ld.lld'),'--version']]
_ACTIVE=False


def need(value,why):
    if not value:raise ValueError(why)


def sha(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None
def digest(path):
    with path.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()


def read(path,cap=4*1024**2):
    need(path.is_absolute() and '..' not in path.parts and all(not x.is_symlink() for x in (path,*path.parents)),'ordinary absolute phase input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded regular phase input')
        raw=b''
        while block:=os.read(fd,min(65536,cap+1-len(raw))):raw+=block;need(len(raw)<=cap,'phase input cap')
        key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        need(len(raw)==before.st_size and key(before)==key(os.fstat(fd))==key(path.lstat()),'phase input changed')
        return raw
    finally:os.close(fd)


def environment(admission_sha,stage0_sha):
    need(sha(admission_sha) and sha(stage0_sha),'explicit qualification and stage0 pins')
    return dict(PATH=f'/stage0/bin:{LLVM}/bin:/usr/bin:/bin',HOME=str(WORK/'home'),CARGO_HOME=str(WORK/'cargo-home'),
        LIBGIT2_NO_VENDOR='1',LIBSSH2_SYS_USE_PKG_CONFIG='1',LIBSQLITE3_SYS_USE_PKG_CONFIG='1',CARGO_NET_OFFLINE='true',
        CACHY_ASAHI_RUST199_STAGE0_SHA256=stage0_sha,CACHY_ASAHI_RUST199_BUILD='1',
        CACHY_ASAHI_RUST199_ADMISSION='/inputs/candidate-admission.json',CACHY_ASAHI_RUST199_ADMISSION_SHA256=admission_sha,
        LC_ALL='C',TZ='UTC',DESTDIR=str(WORK/'dest'),MAKEFLAGS='-j2')


def project(work,image,argv,qualified_root):
    need(work==WORK and image==Path(qualified_root),'fixed native work and original qualified image selector')
    if argv==PROBE_VECTOR:return list(NATIVE_PROBE)
    need(argv==BUILD_VECTOR,'only the two exact frozen sandbox vectors may be projected')
    return list(NATIVE_BUILD)


def inverse_projection(argv):
    if argv==NATIVE_PROBE:return list(PROBE_VECTOR)
    need(argv==NATIVE_BUILD,'only exact recorded native projection vectors')
    return list(BUILD_VECTOR)


def extraction_vectors(materials):
    return [['/usr/bin/bsdtar','--no-same-owner','--no-same-permissions','-xf',str(WORK/'verified-materials'/name),'-C',str(WORK/('stage0-unpack' if row['role']=='stage0' else ''))] for name,row in materials.items()]


def kernel_guard(action):
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(os.uname().machine=='aarch64' and status['Uid'].split()==['1001']*4 and status['Gid'].split()==['1001']*4,'actual kernel native alarm1001 phase')
    need(all(int(status[k].strip(),16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) and status['NoNewPrivs'].strip()=='1','actual cap0/NNP phase')
    limits={k:Path('/sys/fs/cgroup',k).read_text().strip() for k in ('cpu.max','memory.max','memory.swap.max','pids.max')}
    need(limits=={'cpu.max':'200000 100000','memory.max':'8589934592','memory.swap.max':'0','pids.max':'512'},'actual bounded native phase resources')
    need(action=='package' or os.getuid()==os.geteuid()==1001,'non-fakeroot prepare/build/probe')


def readonly_inputs(action):
    mounts={}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left,sep,right=line.partition(' - ');parts=left.split();need(sep and len(parts)>=6,'complete phase mountinfo')
        need(parts[4] not in mounts,'no duplicate phase mount targets');mounts[parts[4]]=set(parts[5].split(','))
    def protected(path):
        candidates=[name for name in mounts if path==Path(name) or Path(name) in path.parents]
        flags=mounts[max(candidates,key=len)];need('ro' in flags and 'rw' not in flags,'actual read-only input: '+str(path))
    need('ro' in mounts['/'] and 'rw' not in mounts['/'],'actual readonly native image root')
    need(LLVM.is_dir() and all(not p.is_symlink() for p in (LLVM,*LLVM.parents)),'normal real private LLVM prefix; no builder symlink')
    protected(LLVM);protected(CANDIDATE);protected(Path('/materials'))
    if action in ('build','package','probe'):
        for name in ('/stage0',str(WORK/'stage0')):
            need(name in mounts and 'ro' in mounts[name] and 'rw' not in mounts[name],'both stage0 aliases independently mounted read-only')
            need(Path(name).is_dir() and not Path(name).is_symlink(),'ordinary stage0 mount root')
        one,two=Path('/stage0').stat(),(WORK/'stage0').stat();need((one.st_dev,one.st_ino)==(two.st_dev,two.st_ino),'both stage0 aliases identify the same prepared tree')


def run_phase(action,a,call):
    """Entry authenticates a, image/public-TEST qualification and Source first.

    call(argv, timeout=seconds, cwd=Path, env=dict, capture=bool) must return a naturally
    retired CompletedProcess-like result and retain its raw log/ownership row.
    """
    global _ACTIVE
    need(not _ACTIVE and threading.current_thread() is threading.main_thread() and callable(call),'serial Root-entry-owned phase callback required')
    need(action in ('prepare','build','package','probe') and a['schema']==1 and a['operation']=='rust199-source-reference-native-v1','fixed separately admitted native operation')
    q=a['candidate_admission'];need(set(q)=={'path','sha256'} and q['path']=='/inputs/candidate-admission.json' and sha(q['sha256']) and
         sha(a['stage0_tree_sha256']) and sha(a['rootfs_tree_sha256']) and sha(a['qualified_llvm_tree_sha256']) and
         type(a['image_id']) is str and re.fullmatch('sha256:[0-9a-f]{64}',a['image_id']),'whole actual Root qualification/image/tree pins')
    kernel_guard(action);readonly_inputs(action)
    raw=read(CANDIDATE/'reference.py');need(hashlib.sha256(raw).hexdigest()==REFERENCE_SHA and digest(CANDIDATE/'inputs.json')==INPUTS_SHA and digest(CANDIDATE/'bootstrap.toml')==CONFIG_SHA,'whole frozen dd6871d5 reference/config/input pins')
    spec=importlib.util.spec_from_file_location('rust199_frozen_candidate',CANDIDATE/'reference.py');candidate=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(CANDIDATE/'reference.py'),'exec'),candidate.__dict__)
    original=candidate.admission(Path(q['path']),q['sha256'],CANDIDATE/'inputs.json');m=candidate.load(CANDIDATE/'inputs.json')
    root=Path(original['environment']['root']);need(root.is_absolute() and root!=Path('/') and '..' not in root.parts and str(root)==original['environment']['root']==a['image_root'] and
         original['environment']['tree_sha256']==a['rootfs_tree_sha256'] and
         original['stage0']['assembled_tree_sha256']==a['stage0_tree_sha256'] and original['qualification_evidence']['path']=='/inputs/qualification.json','original qualification rejoined; no fabricated rootfs substitute')
    need(candidate.tree_digest(LLVM)==a['qualified_llvm_tree_sha256'],'actual private LLVM prefix differs from qualified installed package')
    materials=a['materials'];need(type(materials) is dict and set(materials)==set(m['archives']),'all five Root-retained materials required')
    for name,row in m['archives'].items():
        item=materials[name];path=Path('/materials')/name;expected=STAGE0_BYTES.get(name,row['bytes'])
        need(item==dict(path=str(path),bytes=expected,sha256=row['sha256']) and path.is_file() and not path.is_symlink() and path.stat().st_size==expected and
             candidate.digest(path)==row['sha256'],'actual exact local material: '+name)
    if action=='prepare':
        need(WORK.is_dir() and not WORK.is_symlink() and not any(WORK.iterdir()),'fresh private preparation root')
        for name in materials:(WORK/name).symlink_to(materials[name]['path'])
    else:
        need(candidate.tree_digest(WORK/'stage0')==a['stage0_tree_sha256'] and candidate.tree_digest(Path('/stage0'))==a['stage0_tree_sha256'],'read-only assembled stage0 whole-tree joins')
    env=environment(q['sha256'],a['stage0_tree_sha256']);saved_env=dict(os.environ)
    saved_run=candidate.subprocess.run;saved_output=candidate.subprocess.check_output;saved_sandbox=candidate.sandbox_command
    extracts=extraction_vectors(m['archives']);state=dict(extract=0,probe=0,build=0,project=0);started=time.monotonic();budget={'prepare':600,'probe':60,'build':14400,'package':600}[action]
    probe_clock=[started if action=='probe' else None]
    def invoke(argv,seconds,cwd,capture=False):
        remaining=budget-(time.monotonic()-started);need(remaining>0,'phase aggregate deadline')
        result=call(argv,timeout=min(seconds,remaining),cwd=cwd,env=dict(env),capture=capture)
        need(type(result.returncode) is int and result.returncode==0,'owned child did not exit naturally zero')
        return result
    def output(argv,**kwargs):
        index=state['probe'];need(kwargs=={'text':True} and index<len(PROBE_COMMANDS) and argv==PROBE_COMMANDS[index],'only exact ordered source probe children')
        need(probe_clock[0] is not None,'source probe only in its explicit phase');remaining=60-(time.monotonic()-probe_clock[0]);need(remaining>0,'aggregate60-second probe deadline')
        state['probe']+=1;body=invoke(argv,min(30,remaining),WORK/'rustc-1.99.0-src',True).stdout
        need(type(body) is bytes and len(body)<=1024**2,'bounded raw probe stdout');return body.decode()
    def run(argv,**kwargs):
        need(kwargs=={'check':True},'only candidate check=True calls')
        if action=='prepare':
            index=state['extract'];need(index<len(extracts) and argv==extracts[index],'only five exact ordered bsdtar extractions');state['extract']+=1
            return invoke(argv,600,WORK)
        need(action=='build','no subprocess run in this phase')
        if argv==NATIVE_PROBE:
            need(state['probe']==0 and state['build']==0,'probe executes once before bootstrap');probe_clock[0]=time.monotonic();candidate.probe()
            need(state['probe']==len(PROBE_COMMANDS) and time.monotonic()-probe_clock[0]<60,'all original probe children observed within60seconds');return None
        need(argv==NATIVE_BUILD and state['probe']==len(PROBE_COMMANDS) and state['build']==0,'one exact stage2 bootstrap after successful probe')
        state['build']+=1;return invoke(argv,14400,WORK/'rustc-1.99.0-src')
    def sandbox(work,image,argv):
        expected=PROBE_VECTOR if state['project']==0 else BUILD_VECTOR
        need(state['project']<2 and argv==expected,'exact two ordered sandbox projections');state['project']+=1
        return project(work,image,argv,original['environment']['root'])
    _ACTIVE=True
    try:
        os.environ.clear();os.environ.update(env)
        candidate.subprocess.run=run;candidate.subprocess.check_output=output;candidate.sandbox_command=sandbox
        if action=='prepare':candidate.prepare(WORK,m,original);need(state['extract']==5,'all material extractions completed')
        elif action=='build':candidate.build(WORK,m,original,Path(original['environment']['root']));need(state==dict(extract=0,probe=9,build=1,project=2),'exact native phase command scope completed')
        elif action=='probe':candidate.probe();need(state['probe']==9,'exact original qualification probe completed')
        else:candidate.package(WORK,DESTINATION)
        need(time.monotonic()-started<budget,'phase aggregate deadline')
        return dict(schema=1,status='COMPLETED_NATIVE_PHASE_DATA',phase=action,candidate_sha256=REFERENCE_SHA,candidate_admission_sha256=q['sha256'],
            stage0_tree_sha256=a['stage0_tree_sha256'],commands=state,projection='EXPLICIT_NATIVE_PHASES_NO_NAMESPACE_EQUIVALENCE',
            probe_projection=dict(kind='IN_PROCESS_PHASE',pid=None,child_receipts=state['probe']),native_acceptance=False,holds_preserved=True)
    finally:
        candidate.subprocess.run=saved_run;candidate.subprocess.check_output=saved_output;candidate.sandbox_command=saved_sandbox
        os.environ.clear();os.environ.update(saved_env);_ACTIVE=False


if __name__=='__main__':raise SystemExit('Use the Root-gated actor entry; no standalone phase authorization')
