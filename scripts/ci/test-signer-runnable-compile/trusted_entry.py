# SPDX-License-Identifier: MIT
"""Future trusted Root CI entry; author controls never invoke native main.

Root's authenticated workflow captures original entry before decoding this body,
stages fixed bytes in protected Root directories, then installs ROOT_CODE_ROWS.
The hosted ARM/Linux runtime and writer exclusion are Root's selected premises;
fresh checks below are current correspondence, not retroactive admission.
"""
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import stat
import sys
import time
from types import ModuleType

ROOT_CODE_ROWS=None
BASE='/var/tmp/cachy-asahi-test-signer-compile'
PREFIX='scripts/ci/test-signer-compile-v2'
SOURCE13_COMMIT='1e8fd873345c02dd2f678d8e143c8e22fe7a6e84'
BASELINE_COMMIT='1e8fd873345c02dd2f678d8e143c8e22fe7a6e84'
MANIFEST_SHA='c9e7bb8f8d2d876ec0cafe93fe855f9d864fcb264417e2396d13ce54e7637058'
OUTER_SHA='22ab60121191de19244a832eed139a5ba7a1bfef9d4f959f6159d1450603f4e4'
GATE_SHA='9f46925bf72bcdf86c33d706c7d3110f1de41b59f702754eff6e09b2e1afab90'
WORKFLOW='.github/workflows/native-arm-runner-observation.yml'
BRANCH='codex/signer-native-compile-receiver'
RUNTIME_ROW={'bytes':7845048,'mode':493,'sha256':'c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960'}
SOURCE_ROWS={'abi_layout.c': {'bytes': 22615, 'mode': 420, 'sha256': '278432c15fd759707986f90b1e5e08c19a934c849ef3368ddcdf1141031294a6'}, 'compile_lane_v2.py': {'bytes': 14816, 'mode': 420, 'sha256': '13c06d5a1b2316f517cca74c2ffaf568c3051268256a1cf659f7e990bcdfeae4'}, 'exec_filter.inc': {'bytes': 735, 'mode': 420, 'sha256': '0e26f261f2f9d1c9eb2de15fa70eb3a6c4158c3eaab5bb9f330ceb8dd32bdc19'}, 'group_process_v2.py': {'bytes': 19256, 'mode': 420, 'sha256': 'a8c9044e13f16ead4ed0271b4448f0ec0e3be8a891de66f23a836245ac0bfffb'}, 'guardian.py': {'bytes': 23775, 'mode': 420, 'sha256': 'f2a832f3e01c59a2fd61907301818cb85dc511828f0ea40b416ecb3c66ef4446'}, 'inspection.py': {'bytes': 11897, 'mode': 420, 'sha256': '9658a91a003e17b3f3606b5b1ea03af279a5390e6b02c377fed2ea8dd458159a'}, 'observation_entry.py': {'bytes': 12522, 'mode': 420, 'sha256': '540db1ab5a877fd2486673e86d2a1216c036dd9d8bec3953f44f467ee4966071'}, 'passive.py': {'bytes': 40917, 'mode': 420, 'sha256': 'b844e94ae9cf69882550526a93aed3606398e9252175472be0bf6f2888eba1c9'}, 'reobserve.py': {'bytes': 42040, 'mode': 420, 'sha256': '045620837bb30cdfa719a4e45e216b3aeec389b7fc7da3c08ed86db81e44bdc7'}, 'root_entry.py': {'bytes': 5930, 'mode': 420, 'sha256': '24467b0cc3fc0bbbdee45e5e4905cc4a1e51484712b219c92d2ed555b0774299'}, 'thread_filter.inc': {'bytes': 828, 'mode': 420, 'sha256': '0811954954a107744eaef4592d2be070e30312ed5dbbae716acf6c65e83039ed'}, 'witness_shim.c': {'bytes': 6826, 'mode': 420, 'sha256': 'f5ad7cc5d6247bfa673226c842ee9795a4619f6adfd6062b9edfd0b5872af537'}, 'workspace.py': {'bytes': 8724, 'mode': 420, 'sha256': '8fe059b38492ef56c25d34157774db56087b86e265fb7c64a9ae8dc15ae305f8'}}
CODE_NAMES={'bootstrap.py','native_workspace.py','trusted_entry.py','correspondence.py'}
FIXED_BOOTSTRAP={'bytes': 21103, 'mode': 420, 'sha256': '9009e5bfa2fc94b3bc8e7b3d8af590e0e76bd4924371a469ff47bab9ae462537'}
FIXED_WORKSPACE={'bytes':11033,'mode':420,'sha256':'1f9667ba10006eb1d010c5e69e50b3e950d12f05baaa22600e0f4804a801ea96'}
MANIFEST_ROW={'bytes': 3817, 'mode': 420, 'sha256': '847724d891bfab356aafee742aa4ef1162450b014bf40263ce290897888c4455'}
BASELINE_PINS_ROW={'bytes': 751, 'mode': 420, 'sha256': '102f64b2852df6862886eac1610f4397e5da1540964a1b7811a2234bfdaba8a6'}
PUBLICATION_ROW={'bytes': 1582, 'mode': 420, 'sha256': 'ca62e926f12c411184f50d65fd37972a450f80f43525a25584f6d0bf7a57dd26'}
# These are selected ordinary hosted-runner premises, not sampled measurements.
PREMISES={k:True for k in (
 'trusted_fixed_compiler_and_helper_call_paths','no_group_or_session_escape',
 'no_late_spawn_after_terminal_empty','complete_same_namespace_proc_visibility',
 'single_owner_no_competing_reaper','selected_runtime_public_SIGCHLD_waitability',
 'blocking_call_latency_and_partial_birth_uncertainty_accepted',
 'Root_loaded_Source_and_helper_no_exec_privilege_verified')}
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
class Refused(ValueError):pass
class Cancelled(KeyboardInterrupt):pass
def need(value,code):
    if not value:raise Refused(code)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def canon(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def identity(value):return tuple(getattr(value,k) for k in FIELDS)
def row(raw,mode=0o644):return dict(bytes=len(raw),mode=mode,sha256=digest(raw))
def sha(value,n=64):return type(value) is str and len(value)==n and all(c in '0123456789abcdef' for c in value)
def paths(environment,expected):
    need(sha(expected,40) and environment.get('GITHUB_SHA')==expected,'manual-expected-current-binding-commit')
    need(environment.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi' and
         environment.get('GITHUB_WORKFLOW_REF')=='Gabriel-Kahen/cachy-asahi/'+WORKFLOW+'@refs/heads/'+BRANCH,'registered-workflow-context')
    run,attempt=environment.get('GITHUB_RUN_ID'),environment.get('GITHUB_RUN_ATTEMPT')
    need(all(type(v) is str and v.isascii() and v.isdigit() and 0<int(v)<10**20 for v in (run,attempt)),'run-context')
    suffix=run+'-'+attempt
    return BASE+'/source-'+suffix+'/'+PREFIX,'job-'+suffix

def runtime_metadata(io,py):
    need(io.getuid()==io.geteuid()==io.getgid()==io.getegid()==0,'actual-Root-parent')
    uname=io.uname();need(uname.sysname=='Linux' and uname.machine=='aarch64','actual-native-ARM-Linux')
    need(py.implementation.name=='cpython' and tuple(py.version_info[:2])==(3,12),'actual-CPython312')
    flags={k:getattr(py.flags,k) for k in ('isolated','no_site','dont_write_bytecode','optimize')}
    need(flags==dict(isolated=1,no_site=1,dont_write_bytecode=1,optimize=0),'selected-isolated-runtime-flags')
    need(type(py.executable) is str and py.executable.startswith('/') and len(py.executable)<=1024,'runtime-executable')
    return dict(sysname=uname.sysname,machine=uname.machine,implementation_name=py.implementation.name,
        python_version_info=list(py.version_info[:3]),python_flags=flags,python_executable=py.executable,
        parent_uid=io.getuid(),parent_gid=io.getgid(),child_uid=1001,child_gid=1001)

class Frame:
    def __init__(self,entry,clock):
        need(type(entry) in (int,float) and math.isfinite(entry) and entry>=0,'original-entry')
        self.entry,self.work,self.end=entry,entry+120,entry+130
        self.clock=clock;self.last=entry;self.cancelled=False;self.uncertain=False
    def cancel(self):
        if self.cancelled:raise Cancelled('sticky-cancellation')
    def handler(self,*args):self.cancelled=True;raise Cancelled('signal')
    def live(self,cleanup=False):
        now=self.clock();need(type(now) in (int,float) and math.isfinite(now) and now>=self.last,'monotonic-clock');self.last=now
        if not cleanup:self.cancel()
        need(now<(self.end if cleanup else self.work),'original-endpoint')

class Custody:
    """Finite owned descriptor reads under the selected Root staging premise."""
    def __init__(self,io,frame):self.io,self.frame=io,frame;self.owned={};self.uncertain=False
    def _open(self,name,flags,**kwargs):
        self.frame.live()
        try:fd=self.io.open(name,flags,**kwargs)
        except BaseException:self.uncertain=True;raise
        valid=type(fd) is int and fd>=0 and fd not in self.owned
        if not valid:self.uncertain=True
        need(valid,'new-owned-FD')
        self.owned[fd]=None
        try:self.owned[fd]=identity(self.io.fstat(fd))
        except BaseException:self.uncertain=True;raise
        return fd
    def directory_chain(self,path):
        need(type(path) is str and path.startswith('/') and str(Path(path))==path and '..' not in Path(path).parts,'normalized-directory')
        pieces=Path(path).parts;need(len(pieces)<=24,'finite-ancestry')
        fd=None;records=[]
        for i in range(len(pieces)):
            named='/' if i==0 else pieces[i];actual='/' if i==0 else str(Path(*pieces[:i+1]))
            fd=self._open(named,self.io.O_RDONLY|self.io.O_DIRECTORY|self.io.O_NOFOLLOW|self.io.O_NONBLOCK,**({} if i==0 else {'dir_fd':fd}))
            held=self.owned[fd];need(stat.S_ISDIR(held[2]) and held[3:5]==(0,0) and held[5]>=1 and held==identity(self.io.stat(actual,follow_symlinks=False)),'held-named-Root-ancestor')
            if actual==BASE or actual.startswith(BASE+'/'):
                need(stat.S_IMODE(held[2])==0o755,'protected-Root-stage-directory')
            # /var/tmp is intentionally allowed its normal world-writable sticky mode.
            records.append(dict(fd=fd,path=actual,identity=held[:6]))
        return fd,tuple(records)
    def check_caps(self,fd):
        held=identity(self.io.fstat(fd));need(not held[2]&0o6000,'no-setid')
        try:cap=self.io.getxattr(fd,'security.capability')
        except OSError as error:
            need(error.errno==errno.ENODATA,'filecap-read-supported');cap=b''
        need(type(cap) is bytes and not cap,'no-filecap')
        need(identity(self.io.fstat(fd))==held,'noexec-held-drift')
        return held
    def read(self,parent,name,expected=None,bound=1024**2):
        need(type(name) is str and Path(name).name==name and name not in ('.','..'),'fixed-leaf')
        self.frame.live();before=identity(self.io.stat(name,dir_fd=parent,follow_symlinks=False))
        need(stat.S_ISREG(before[2]) and before[3:5]==(0,0) and before[5]==1 and stat.S_IMODE(before[2])==0o644 and 0<before[6]<=bound,'Root-Source-leaf')
        fd=self._open(name,self.io.O_RDONLY|self.io.O_NOFOLLOW|self.io.O_NONBLOCK,dir_fd=parent)
        need(self.owned[fd]==before,'source-open-drift');self.check_caps(fd)
        chunks=[];count=0;primary=None
        try:
            while count<=before[6]:
                self.frame.live();value=self.io.read(fd,min(65536,before[6]+1-count))
                need(type(value) is bytes,'read-bytes')
                if not value:break
                count+=len(value);need(count<=before[6],'read-cap');chunks.append(value)
            raw=b''.join(chunks);need(len(raw)==before[6],'complete-read')
            need(expected is None or row(raw)==expected,'exact-Root-Source-row')
            need(before==identity(self.io.fstat(fd))==identity(self.io.stat(name,dir_fd=parent,follow_symlinks=False)),'source-final-held-named')
            self.frame.live();return raw
        except BaseException as error:primary=error;raise
        finally:self.retire_preserving(fd,primary)
    def no_exec_file(self,path,selected):
        self.frame.live();before=identity(self.io.stat(path,follow_symlinks=False))
        need(stat.S_ISREG(before[2]) and before[3:5]==(0,0) and before[5]==1 and before[6]==selected['bytes'] and stat.S_IMODE(before[2])==selected['mode'],'selected-noexec-file')
        fd=self._open(path,self.io.O_RDONLY|self.io.O_NOFOLLOW|self.io.O_NONBLOCK);primary=None
        try:
            need(self.owned[fd]==before,'noexec-open-identity');self.check_caps(fd)
            need(before==identity(self.io.fstat(fd))==identity(self.io.stat(path,follow_symlinks=False)),'noexec-named-drift');self.frame.live()
            return dict(row={k:selected[k] for k in ('bytes','mode','sha256')},uid=0,gid=0,nlink=1,mode=selected['mode'],filecap_present=False,setid_present=False)
        except BaseException as error:primary=error;raise
        finally:self.retire_preserving(fd,primary)
    def retire_preserving(self,fd,primary):
        try:self.close_one(fd)
        except BaseException as error:
            self.frame.cancelled|=isinstance(error,(Cancelled,KeyboardInterrupt))
            if primary is None:raise
            primary.entry_cancelled=self.frame.cancelled;primary.entry_uncertain=True
    def close_one(self,fd):
        original=self.owned.pop(fd)
        try:
            self.frame.live(cleanup=True);held=identity(self.io.fstat(fd))
            # Own directory mkdirs may change nlink/size/times. Anchor ownership remains.
            need(original is not None and held[:5]==original[:5],'close-owned-anchor')
            self.io.close(fd);self.frame.live(cleanup=True)
        except BaseException:self.uncertain=True;raise
    def close(self):
        first=None
        for fd in reversed(tuple(self.owned)):
            try:self.close_one(fd)
            except BaseException as error:
                self.frame.cancelled|=isinstance(error,(Cancelled,KeyboardInterrupt))
                if first is None:first=error
        if first is not None:raise first

def load(raw,name):
    module=ModuleType('Root_trusted_'+name[:-3]);module.__file__=PREFIX+'/'+name
    exec(compile(raw,PREFIX+'/'+name,'exec',dont_inherit=True),module.__dict__)
    return module

def code_rows():
    rows=ROOT_CODE_ROWS
    need(type(rows) is dict and set(rows)==CODE_NAMES,'Root-launcher-code-pins-unfilled')
    for name,value in rows.items():
        need(type(value) is dict and set(value)=={'bytes','mode','sha256'} and type(value['bytes']) is int and 0<value['bytes']<=1024**2 and value['mode']==0o644 and sha(value['sha256']),'Root-code-row:'+name)
    need(rows['bootstrap.py']==FIXED_BOOTSTRAP and rows['native_workspace.py']==FIXED_WORKSPACE,'frozen-bootstrap-helpers')
    return rows

def main(*,entry,expected_binding_commit):
    """Root workflow is the issuer. Author tests never execute this native path."""
    rows=code_rows();f=Frame(entry,time.monotonic);f.live()
    source_path,job_name=paths(os.environ,expected_binding_commit);runtime=runtime_metadata(os,sys)
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'no-existing-timer')
    old={};timer_owned=False;c=Custody(os,f);result=None;first=None;proof_result=None;selection=None
    try:
        for signum in (signal.SIGALRM,signal.SIGINT,signal.SIGTERM):
            old[signum]=signal.getsignal(signum);signal.signal(signum,f.handler)
        f.live();remaining=f.work-time.monotonic();need(remaining>0,'original-alarm-cutoff')
        timer_owned=True
        try:signal.setitimer(signal.ITIMER_REAL,remaining)
        except BaseException:f.uncertain=True;raise
        base_fd,base_ancestors=c.directory_chain(BASE)
        prefix_fd,source_ancestors=c.directory_chain(source_path)
        # All staged raw bodies are read/cap-checked before decoding any other Source.
        raw={name:c.read(prefix_fd,name,SOURCE_ROWS[name]) for name in sorted(SOURCE_ROWS)}
        code={name:c.read(prefix_fd,name,rows[name]) for name in sorted(CODE_NAMES)}
        manifest_raw=c.read(prefix_fd,'source-manifest.json',MANIFEST_ROW);manifest=json.loads(manifest_raw)
        need(digest(canon(manifest))==MANIFEST_SHA and manifest.get('source_rows')==SOURCE_ROWS,'Source13-manifest')
        baseline_pins=json.loads(c.read(prefix_fd,'bootstrap-source-pins.json',BASELINE_PINS_ROW))
        need(baseline_pins.get('helper_rows')=={'bootstrap.py':FIXED_BOOTSTRAP,'native_workspace.py':FIXED_WORKSPACE} and baseline_pins.get('unchanged_Source13_manifest_sha256')==MANIFEST_SHA
             and baseline_pins.get('published_receiver_source_commit')==SOURCE13_COMMIT and baseline_pins.get('published_receiver_prefix')==PREFIX,'baseline-helper-pins')
        outer_raw=c.read(prefix_fd,'accepted-candidate.json',bound=4*1024**2);need(digest(outer_raw)==OUTER_SHA,'accepted-complete-outer-pin')
        outer=json.loads(outer_raw);need(outer_raw==canon(outer) and set(outer)=={'schema_version','purpose','source_pins','configuration','context','observation','provenance','entry','deadline_at','selected','execution_grant_issued','compile_allowed'},'complete-outer-envelope')
        gate_raw=c.read(prefix_fd,'root-gate-receipt.json');need(digest(gate_raw)==GATE_SHA,'accepted-Root-gate-pin')
        publication_raw=c.read(prefix_fd,'receiver-publication.json',PUBLICATION_ROW);publication=json.loads(publication_raw)
        need(publication.get('status')=='PASS_RECEIVER_SOURCE_ONLY_BINDING_PENDING' and publication.get('source_commit')==BASELINE_COMMIT
             and publication.get('manifest_canonical_sha256')==MANIFEST_SHA and publication.get('source_rows')==13
             and publication.get('changed_C_files')==['abi_layout.c','witness_shim.c']
             and publication.get('native_trial_started') is False and publication.get('execution_grants') is False,'published-baseline-proof')
        workflow_raw=c.read(prefix_fd,'compile-workflow.yml');workflow_row=row(workflow_raw)
        f.live();bootstrap=load(code['bootstrap.py'],'bootstrap.py');passive=load(raw['passive.py'],'passive.py')
        correspondence=load(code['correspondence.py'],'correspondence.py');f.live()
        # Fresh current runtime bytes are checked after ordinary host trust; no retrospective grant.
        runtime_sample=passive.PassiveIO().sample(sys.executable,f.work)
        need(runtime_sample['row']['bytes']==RUNTIME_ROW['bytes'] and runtime_sample['row']['mode']==RUNTIME_ROW['mode'] and runtime_sample['row']['sha256']==RUNTIME_ROW['sha256'],'current-runtime-ELF-drift')
        passive.linkage(runtime_sample['body'])
        runtime['row']=dict(RUNTIME_ROW);runtime['python_executable']=runtime_sample['canonical']
        elf={path:item for path,item in outer['observation']['candidate']['files'].items() if item.get('kind')=='ELF'}
        need(0<len(elf)<=4096,'finite-selected-ELF-noexec')
        checked={path:c.no_exec_file(path,item) for path,item in sorted(elf.items())}
        ws=dict(base_fd=base_fd,base_path=BASE,base_identity=identity(os.fstat(base_fd))[:6],job_name=job_name,child_uid=1001,child_gid=1001,ancestors=base_ancestors)
        need(ws['base_identity'][3:5]==(0,0) and stat.S_IMODE(ws['base_identity'][2])==0o755,'protected-workspace-base')
        for ancestor in base_ancestors:
            held=identity(os.fstat(ancestor['fd']))[:6]
            need(held==ancestor['identity']==identity(os.stat(ancestor['path'],follow_symlinks=False))[:6] and held[2]&0o001,'fresh-held-workspace-ancestry-child-traversal')
        env=dict(LANG='C',LC_ALL='C',PATH='/usr/bin:/bin',TMPDIR=BASE+'/'+job_name+'/outputs')
        checks=dict(runtime=runtime,no_exec_privilege=dict(checked_files=checked,complete=True),
            custody=dict(workspace_held_named=True,base_root_protected=True,child_traversal=True,selected_premises=dict(PREMISES)))
        context=dict(source13_commit=SOURCE13_COMMIT,baseline_commit=BASELINE_COMMIT,workflow_source_commit=os.environ['GITHUB_SHA'],manual_expected_commit=expected_binding_commit)
        proof_result=correspondence.generate(outer=outer,gate_receipt_sha256=GATE_SHA,source_rows=SOURCE_ROWS,code_rows=rows,checks=checks,environment=env,context=context)
        candidate=outer['observation']['candidate']
        selection=dict(schema_version=1,purpose='ROOT_SELECTED_SIGNER_COMPILE_TOOLCHAIN_V1',observation_sha256=OUTER_SHA,source_manifest_sha256=MANIFEST_SHA,
            **{k:candidate[k] for k in ('gcc_directory','gcc_discovery','helper_discovery','roles','files','headers','inventories')},
            provenance=outer['provenance'],observer_gate_receipt_sha256=GATE_SHA,proofs=proof_result['proofs'],environment=env)
        selection_raw=canon(selection);f.live()
        # The six opaque objects are issued ONLY here, after actual checked correspondence.
        tokens={}
        for name in bootstrap.TOKENS:
            token=object();tokens[name]=(token,token)
        provision=dict(bootstrap.PROVISION_TEMPLATE)
        provision.update(publication_proof_sha256=digest(publication_raw),registered_workflow=dict(repository='Gabriel-Kahen/cachy-asahi',branch=BRANCH,path=WORKFLOW,source_commit=expected_binding_commit,row=workflow_row),
            runtime_selection=dict(executable=sys.executable,row=dict(RUNTIME_ROW),Source_selection_sha256=proof_result['proofs']['runtime']),
            helper_row=dict(FIXED_WORKSPACE),helper_Source_selection_sha256=proof_result['proofs']['Source_review'],selection_sha256=digest(selection_raw),
            proofs=proof_result['proofs'],environment=env,child_uid=1001,child_gid=1001,premises=dict(PREMISES))
        authority=dict(source_fd=prefix_fd,source_path=source_path,source_identity=identity(os.fstat(prefix_fd)),source_uid=0,source_gid=0,
            source_io=os,clock=time.monotonic,cancel=f.cancel,cancel_types=(Cancelled,KeyboardInterrupt),workspace_provision=ws,workspace_io=os,tokens=tokens)
        bootstrap.ROOT_PROVISION=provision;bootstrap.ROOT_AUTHORITY=authority
        f.live();result=bootstrap.run(entry=entry,outer_work_end=f.work,outer_cleanup_end=f.end,observation_raw=outer_raw,selection_raw=selection_raw)
    except BaseException as error:
        first=error;f.cancelled|=isinstance(error,(Cancelled,KeyboardInterrupt)) or bool(getattr(error,'bootstrap_cancelled',False));f.uncertain|=bool(getattr(error,'bootstrap_uncertain',False))
    finally:
        try:c.close()
        except BaseException as error:
            f.uncertain=True;f.cancelled|=isinstance(error,(Cancelled,KeyboardInterrupt))
            if first is None:first=error
        if timer_owned:
            try:signal.setitimer(signal.ITIMER_REAL,0)
            except BaseException as error:
                f.uncertain=True;f.cancelled|=isinstance(error,(Cancelled,KeyboardInterrupt))
                if first is None:first=error
        for signum,handler in old.items():
            try:signal.signal(signum,handler)
            except BaseException as error:
                f.uncertain=True;f.cancelled|=isinstance(error,(Cancelled,KeyboardInterrupt))
                if first is None:first=error
        try:f.live(cleanup=True)
        except BaseException as error:
            f.uncertain=True
            if first is None:first=error
    inner=result.get('result',{}) if type(result) is dict else {}
    cancelled=f.cancelled or bool(inner.get('cancelled'))
    uncertain=f.uncertain or c.uncertain or bool(inner.get('uncertain'))
    okay=first is None and not cancelled and not uncertain and type(result) is dict and result.get('result',{}).get('status')=='PASS_STATIC_COMPILE_AND_METADATA_ONLY'
    return dict(status='PASS' if okay else 'FAIL',returncode=0 if okay else 1,first_cause=inner.get('first_cause') if first is None else type(first).__name__,
        reason=inner.get('first_cause') if first is None else str(first)[:256],cancelled=cancelled,uncertain=uncertain,result=result,
        correspondence=proof_result,selection=selection,original_entry=entry,work_end=f.work,cleanup_end=f.end,
        directory_absence_claimed=False,authority_origin='ROOT_AUTHENTICATED_HOSTED_ARM_WORKFLOW',
        GPG_executed=False,shim_executed=False,ABI_object_executed=False)
