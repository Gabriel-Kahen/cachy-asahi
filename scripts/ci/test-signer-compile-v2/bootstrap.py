# SPDX-License-Identifier: MIT
"""Deferred Root bootstrap. Shipped None choices refuse before reads or actors.

Root must adopt this body and provision authority in a trusted runtime before
calling run. Hashes and JSON do not authenticate that runtime or issue grants.
Original entry is captured by Root before this Source is decoded or imported.
"""
import hashlib
import json
import math
from pathlib import Path
import stat
from types import SimpleNamespace

ROOT_PROVISION=None
ROOT_AUTHORITY=None
COMMIT='ea698489f29eae42aba35e3cc224180f95a42887'
PREFIX='scripts/ci/test-signer-compile-v2'
MANIFEST_SHA='51e4486016951d94ed414db376645efcc0868aef60304dd03df874cd313f1f66'
OBSERVATION_SHA='22ab60121191de19244a832eed139a5ba7a1bfef9d4f959f6159d1450603f4e4'
GATE_SHA='9f46925bf72bcdf86c33d706c7d3110f1de41b59f702754eff6e09b2e1afab90'
SOURCE_ROWS={'abi_layout.c': {'bytes': 22614, 'mode': 420, 'sha256': '31072027916ab85ddc9b2d70f487665fa9a762f20b82b2964565f3148250ad0a'}, 'compile_lane_v2.py': {'bytes': 14950, 'mode': 420, 'sha256': 'de6acb3c8bda4ec2a7946235f1eb949655778097fc20dcecdbd8665f77623829'}, 'exec_filter.inc': {'bytes': 735, 'mode': 420, 'sha256': '0e26f261f2f9d1c9eb2de15fa70eb3a6c4158c3eaab5bb9f330ceb8dd32bdc19'}, 'group_process_v2.py': {'bytes': 22109, 'mode': 420, 'sha256': 'bc4be94861dee7db998c340b86952adb2d7c606937fe499fa3a1dfc23e8198af'}, 'guardian.py': {'bytes': 23775, 'mode': 420, 'sha256': 'f2a832f3e01c59a2fd61907301818cb85dc511828f0ea40b416ecb3c66ef4446'}, 'inspection.py': {'bytes': 11896, 'mode': 420, 'sha256': '0a4977cb241a537f5ee01d7c2988690c85a354ab881324269c0027b1a7b80c8d'}, 'observation_entry.py': {'bytes': 12522, 'mode': 420, 'sha256': '540db1ab5a877fd2486673e86d2a1216c036dd9d8bec3953f44f467ee4966071'}, 'passive.py': {'bytes': 40917, 'mode': 420, 'sha256': 'b844e94ae9cf69882550526a93aed3606398e9252175472be0bf6f2888eba1c9'}, 'reobserve.py': {'bytes': 42040, 'mode': 420, 'sha256': '045620837bb30cdfa719a4e45e216b3aeec389b7fc7da3c08ed86db81e44bdc7'}, 'root_entry.py': {'bytes': 5930, 'mode': 420, 'sha256': '24467b0cc3fc0bbbdee45e5e4905cc4a1e51484712b219c92d2ed555b0774299'}, 'thread_filter.inc': {'bytes': 828, 'mode': 420, 'sha256': '0811954954a107744eaef4592d2be070e30312ed5dbbae716acf6c65e83039ed'}, 'witness_shim.c': {'bytes': 6826, 'mode': 420, 'sha256': 'f5ad7cc5d6247bfa673226c842ee9795a4619f6adfd6062b9edfd0b5872af537'}, 'workspace.py': {'bytes': 8724, 'mode': 420, 'sha256': '8fe059b38492ef56c25d34157774db56087b86e265fb7c64a9ae8dc15ae305f8'}}
MANIFEST_ROW={'bytes': 3817, 'mode': 420, 'sha256': 'b1e14c7aeabc3151788c36eedbcc347399bf140d0096ff55a77c4f231a4de2e7'}
HELPER_ROW={'bytes':11033,'mode':420,'sha256':'1f9667ba10006eb1d010c5e69e50b3e950d12f05baaa22600e0f4804a801ea96'}
PROOFS={'driver_search','header_include','loader','no_exec_privilege','containment','native_providers','runtime','Source_review'}
PREMISES={'trusted_fixed_compiler_and_helper_call_paths','no_group_or_session_escape',
 'no_late_spawn_after_terminal_empty','complete_same_namespace_proc_visibility',
 'single_owner_no_competing_reaper','selected_runtime_public_SIGCHLD_waitability',
 'blocking_call_latency_and_partial_birth_uncertainty_accepted',
 'Root_loaded_Source_and_helper_no_exec_privilege_verified'}
TOKENS=('Source','compile','reobserve','workspace','ancestry','group')
PROVISION_TEMPLATE=dict(source_commit=COMMIT,source_prefix=PREFIX,manifest_sha256=MANIFEST_SHA,
 observation_sha256=OBSERVATION_SHA,observer_gate_receipt_sha256=GATE_SHA,
 publication_proof_sha256=None,registered_workflow=None,runtime_selection=None,
 helper_row=None,helper_Source_selection_sha256=None,selection_sha256=None,
 proofs={k:None for k in sorted(PROOFS)},environment=dict(LANG='C',LC_ALL='C',PATH=None,TMPDIR=None),
 child_uid=None,child_gid=None,group_peer_sha256='ec2871f460a23556adb3b8dcefb54cf67fc2b03eccbf091b6e06946dc03e9338',
 premises={k:None for k in sorted(PREMISES)})
AUTHORITY_KEYS={'source_fd','source_path','source_identity','source_uid','source_gid',
 'source_io','clock','cancel','cancel_types','workspace_provision','workspace_io','tokens'}

class Refused(ValueError):pass
def need(value,code):
    if not value:raise Refused(code)
def sha(value):return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def path(value):
    return type(value) is str and 0<len(value)<=4096 and value.startswith('/') and str(Path(value))==value and '..' not in Path(value).parts and '\0' not in value

def row(value,bound=1024**2):
    return type(value) is dict and set(value)=={'bytes','mode','sha256'} and type(value['bytes']) is int and 0<value['bytes']<=bound and value['mode'] in (0o644,0o755) and type(value['mode']) is int and sha(value['sha256'])
def identity(value):
    return tuple(getattr(value,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def frame(entry,outer_work_end,outer_cleanup_end):
    need(all(type(v) in (int,float) and math.isfinite(v) for v in (entry,outer_work_end,outer_cleanup_end)) and 0<=entry<outer_work_end<outer_cleanup_end,'original-frame')
    work=min(entry+120,outer_work_end);cleanup=min(entry+130,outer_cleanup_end)
    need(work<cleanup,'original-frame');return work,cleanup

def bindings():
    """Module-owned selected authority only; never accept caller expectations."""
    p,a=ROOT_PROVISION,ROOT_AUTHORITY
    need(type(p) is dict and set(p)==set(PROVISION_TEMPLATE),'Root-provision-unfilled')
    for k,v in (('source_commit',COMMIT),('source_prefix',PREFIX),('manifest_sha256',MANIFEST_SHA),
                ('observation_sha256',OBSERVATION_SHA),('observer_gate_receipt_sha256',GATE_SHA)):
        need(p[k]==v,'Root-literal:'+k)
    for k in ('publication_proof_sha256','helper_Source_selection_sha256','selection_sha256','group_peer_sha256'):
        need(sha(p[k]),'Root-selection-missing:'+k)
    need(p['group_peer_sha256']=='ec2871f460a23556adb3b8dcefb54cf67fc2b03eccbf091b6e06946dc03e9338','Root-guardian-review')
    w=p['registered_workflow']
    need(type(w) is dict and set(w)=={'repository','branch','path','source_commit','row'} and
         w['repository']=='Gabriel-Kahen/cachy-asahi' and type(w['branch']) is str and w['branch'].startswith('codex/') and
         type(w['path']) is str and w['path'].startswith('.github/workflows/') and w['path'].endswith('.yml') and
         type(w['source_commit']) is str and len(w['source_commit'])==40 and all(c in '0123456789abcdef' for c in w['source_commit']) and row(w['row']),'Root-workflow-unfilled')
    r=p['runtime_selection']
    need(type(r) is dict and set(r)=={'executable','row','Source_selection_sha256'} and path(r['executable']) and row(r['row'],64*1024**2) and r['row']['mode']==0o755 and sha(r['Source_selection_sha256']),'Root-runtime-unfilled')
    need(p['helper_row']==HELPER_ROW and row(p['helper_row']),'Root-helper-unfilled')
    need(type(p['proofs']) is dict and set(p['proofs'])==PROOFS and all(sha(v) for v in p['proofs'].values()),'Root-proof8-unfilled')
    need(type(p['premises']) is dict and set(p['premises'])==PREMISES and all(v is True for v in p['premises'].values()),'Root-group-premises-unfilled')
    need(all(type(p[k]) is int and 0<p[k]<2**31 for k in ('child_uid','child_gid')),'Root-child-unfilled')
    env=p['environment']
    need(type(env) is dict and set(env)=={'LANG','LC_ALL','PATH','TMPDIR'} and env['LANG']==env['LC_ALL']=='C' and
         type(env['PATH']) is str and env['PATH'] and all(path(v) for v in env['PATH'].split(':')) and path(env['TMPDIR']),'Root-environment-unfilled')
    need(type(a) is dict and set(a)==AUTHORITY_KEYS,'Root-authority-unfilled')
    need(type(a['source_fd']) is int and a['source_fd']>=0 and path(a['source_path']) and a['source_path'].endswith('/'+PREFIX),'Root-held-prefix')
    ident=a['source_identity']
    need(type(ident) is tuple and len(ident)==9 and all(type(v) is int and 0<=v<2**64 for v in ident) and stat.S_ISDIR(ident[2]) and ident[5]>=1,'Root-prefix-identity')
    need(all(type(a[k]) is int and 0<=a[k]<2**32 for k in ('source_uid','source_gid')) and ident[3:5]==(a['source_uid'],a['source_gid']),'Root-selected-Source-owner')
    need(a['source_io'] is not None and a['workspace_io'] is not None and callable(a['clock']) and callable(a['cancel']),'Root-native-providers-unfilled')
    need(type(a['cancel_types']) is tuple and 0<len(a['cancel_types'])<=8 and all(isinstance(t,type) and issubclass(t,BaseException) for t in a['cancel_types']),'Root-cancel-types')
    tokens=a['tokens'];need(type(tokens) is dict and set(tokens)==set(TOKENS),'Root-preissued-tokens-unfilled')
    for k in TOKENS:
        pair=tokens[k];need(type(pair) is tuple and len(pair)==2 and type(pair[0]) is object and pair[0] is pair[1],'Root-preissued:'+k)
    ws=a['workspace_provision']
    need(type(ws) is dict and set(ws)=={'base_fd','base_path','base_identity','job_name','child_uid','child_gid','ancestors'} and path(ws['base_path']) and type(ws['job_name']) is str and
         ws['child_uid']==p['child_uid'] and ws['child_gid']==p['child_gid'] and
         env['TMPDIR']==str(Path(ws['base_path'])/ws['job_name']/'outputs'),'Root-workspace-provision-unfilled')
    return p,a

class SourceReader:
    """Borrow Root-held prefix; each new leaf FD is retired exactly once.

    Native operations are deferred to Root's selected provider. Full held/named
    identity and exact raw bytes are checks within Root writer exclusion; no
    universal hard syscall wall-clock bound or ancestry proof is claimed here.
    """
    def __init__(self,authority,end,cleanup_end=None):
        self.a,self.io,self.end=authority,authority['source_io'],end
        self.cleanup_end=end if cleanup_end is None else cleanup_end
        self.last=None;self.cancelled=self.uncertain=False;self.first=None
    def live(self,cleanup=False):
        now=self.a['clock']();need(type(now) in (int,float) and math.isfinite(now) and (self.last is None or now>=self.last),'loader-clock')
        self.last=now
        if not cleanup:self.a['cancel']()
        need(now<(self.cleanup_end if cleanup else self.end),'loader-original-end')
    def prefix(self):
        a=self.a;need(identity(self.io.fstat(a['source_fd']))==a['source_identity']==identity(self.io.stat(a['source_path'],follow_symlinks=False)),'loader-prefix-drift')
    def read(self,name,expected):
        need(type(name) is str and Path(name).name==name and name not in ('.','..') and row(expected) and expected['mode']==0o644,'loader-fixed-leaf')
        fd=None;before=None;raw=b'';primary=None;open_started=False;open_returned=False
        try:
            self.live();self.prefix()
            named=self.io.stat(name,dir_fd=self.a['source_fd'],follow_symlinks=False);before=identity(named)
            need(stat.S_ISREG(before[2]) and before[3:5]==(self.a['source_uid'],self.a['source_gid']) and before[5]==1 and stat.S_IMODE(before[2])==expected['mode'] and before[6]==expected['bytes'],'loader-leaf-gate')
            self.live();open_started=True
            fd=self.io.open(name,self.io.O_RDONLY|self.io.O_NOFOLLOW|self.io.O_NONBLOCK,dir_fd=self.a['source_fd'])
            need(type(fd) is int and fd>=0 and fd!=self.a['source_fd'],'loader-new-owned-FD')
            open_returned=True
            need(identity(self.io.fstat(fd))==before,'loader-open-identity')
            chunks=[];count=0
            while count<=expected['bytes']:
                self.live();chunk=self.io.read(fd,min(65536,expected['bytes']+1-count))
                need(type(chunk) is bytes,'loader-read-type')
                if not chunk:break
                count+=len(chunk);need(count<=expected['bytes'],'loader-read-overrun');chunks.append(chunk)
            raw=b''.join(chunks)
            need(len(raw)==expected['bytes'] and digest(raw)==expected['sha256'],'loader-raw-pin')
            need(identity(self.io.fstat(fd))==before==identity(self.io.stat(name,dir_fd=self.a['source_fd'],follow_symlinks=False)),'loader-leaf-drift')
            self.prefix();self.live()
        except BaseException as error:
            primary=error;self.cancelled|=isinstance(error,self.a['cancel_types'])
            self.uncertain|=open_started and not open_returned
        finally:
            if fd is not None and type(fd) is int and fd>=0 and fd!=self.a['source_fd']:
                try:
                    # A replaced/foreign descriptor is not blindly closed.
                    self.live(cleanup=True)
                    need(before is not None and identity(self.io.fstat(fd))==before,'loader-close-identity')
                    self.io.close(fd);self.live(cleanup=True)
                except BaseException as error:
                    self.uncertain=True;self.cancelled|=isinstance(error,self.a['cancel_types'])
                    if primary is None:primary=error
        if primary is not None:
            if self.first is None:self.first=primary
            primary.bootstrap_cancelled=self.cancelled
            primary.bootstrap_uncertain=self.uncertain
            raise primary
        return raw

def verified_sources(reader):
    """Verify every raw unit plus manifest and selected helper before any exec."""
    manifest_raw=reader.read('source-manifest.json',MANIFEST_ROW)
    manifest=json.loads(manifest_raw)
    need(digest(canonical(manifest))==MANIFEST_SHA and manifest.get('source_rows')==SOURCE_ROWS and manifest.get('selected') is False and manifest.get('execution_grant_issued') is False,'loader-manifest')
    raw={name:reader.read(name,SOURCE_ROWS[name]) for name in sorted(SOURCE_ROWS)}
    helper=reader.read('native_workspace.py',ROOT_PROVISION['helper_row'])
    reader.live();return raw,manifest,helper

def load_units(raw,helper):
    """Only fixed verified units; compile flags never inherit caller futures."""
    need(type(raw) is dict and set(raw)==set(SOURCE_ROWS),'loader-closed-unit-set')
    for name,body in raw.items():
        need(type(body) is bytes and len(body)==SOURCE_ROWS[name]['bytes'] and digest(body)==SOURCE_ROWS[name]['sha256'],'loader-before-compile-pin')
    need(type(helper) is bytes and len(helper)==HELPER_ROW['bytes'] and digest(helper)==HELPER_ROW['sha256'],'loader-helper-before-compile-pin')
    units={}
    for name,body in list(sorted(raw.items()))+[('native_workspace.py',helper)]:
        if not name.endswith('.py'):continue
        scope={'__name__':'Root_selected_'+name[:-3],'__file__':PREFIX+'/'+name}
        code=compile(body,PREFIX+'/'+name,'exec',dont_inherit=True)
        exec(code,scope);units[name[:-3]]=SimpleNamespace(**scope)
    return units

def run(*,entry,outer_work_end,outer_cleanup_end,observation_raw,selection_raw):
    """Root invokes after independent provision; no issuer or self-authorizing CLI."""
    p,a=bindings();work_end,cleanup_end=frame(entry,outer_work_end,outer_cleanup_end)
    need(type(observation_raw) is bytes and 0<len(observation_raw)<=4*1024**2 and digest(observation_raw)==p['observation_sha256'],'Root-full-outer-pin')
    need(type(selection_raw) is bytes and 0<len(selection_raw)<=4*1024**2 and digest(selection_raw)==p['selection_sha256'],'Root-selection-pin')
    observation=json.loads(observation_raw);selection=json.loads(selection_raw)
    need(observation_raw==canonical(observation) and selection_raw==canonical(selection),'Root-canonical-payloads')
    need(selection.get('source_manifest_sha256')==MANIFEST_SHA and selection.get('observation_sha256')==OBSERVATION_SHA and
         selection.get('observer_gate_receipt_sha256')==GATE_SHA and selection.get('proofs')==p['proofs'] and selection.get('environment')==p['environment'],'Root-selected-literals')
    reader=SourceReader(a,work_end,cleanup_end);raw,manifest,helper_raw=verified_sources(reader)
    reader.live();units=load_units(raw,helper_raw);reader.live()
    tokens=a['tokens'];helpers=[];samples=[]
    def workspace_factory(work,cleanup):
        need((work,cleanup)==(work_end,cleanup_end),'workspace-original-frame')
        cls=units['workspace'].Workspace;pair=tokens['workspace'];ancestry=tokens['ancestry']
        helper=units['native_workspace'].NativeWorkspaceFactory(cls,expected_workspace_class=cls,
            provision=a['workspace_provision'],expected_provision=a['workspace_provision'],
            admission=pair[0],expected_admission=pair[1],ancestry=ancestry[0],expected_ancestry=ancestry[1],
            io=a['workspace_io'],expected_io=a['workspace_io'],clock=a['clock'],cancel=a['cancel'],cancel_types=a['cancel_types'])
        helpers.append(helper);return helper(work,cleanup)
    def reobserve_factory(selected,outer,selected_sha,manifest_sha,work):
        need(work==work_end,'reobserve-original-frame');pair=tokens['reobserve']
        return units['reobserve'].Reobserver(units['passive'],selection=selected,observation=outer,
            selection_sha256=selected_sha,observation_sha256=selected['observation_sha256'],manifest_sha256=manifest_sha,
            admission=pair[0],expected_admission=pair[1],work_end=work,io_factory=units['passive'].PassiveIO,clock=a['clock'])
    def sample(pathname,work):
        need(work==work_end,'sample-original-frame');reader.live()
        if not samples:samples.append(units['passive'].PassiveIO())
        return samples[0].sample(pathname,work)
    def runner_factory(table,entered,work,cleanup):
        need((entered,work,cleanup)==(entry,work_end,cleanup_end),'runner-original-frame');pair=tokens['group']
        backend=units['group_process_v2'].NativeBackend(units['guardian'],admission=pair[0],expected_admission=pair[1],expected_guardian=units['guardian'])
        group=dict(entered=entry,guardian_sha256=SOURCE_ROWS['guardian.py']['sha256'],guardian_peer_sha256=p['group_peer_sha256'],
            premises=p['premises'],child_uid=p['child_uid'],child_gid=p['child_gid'],output_path=p['environment']['TMPDIR'])
        toolchain=table
        return units['group_process_v2'].OwnedCommands(backend,admission=pair[0],expected_admission=pair[1],
            group_selection=group,expected_group_selection=group,toolchain=toolchain,expected_toolchain=toolchain,work_end=work,cleanup_end=cleanup)
    result=None;primary=None;helper_result=None
    try:
        result=units['root_entry'].run(units=dict(lane=units['compile_lane_v2'],inspection=units['inspection']),
            raw_sources=raw,manifest=manifest,manifest_sha256=MANIFEST_SHA,observation=observation,selection=selection,
            selection_sha256=p['selection_sha256'],source_admission=tokens['Source'][0],expected_source_admission=tokens['Source'][1],
            compile_admission=tokens['compile'][0],expected_compile_admission=tokens['compile'][1],
            workspace_factory=workspace_factory,expected_workspace_factory=workspace_factory,
            runner_factory=runner_factory,expected_runner_factory=runner_factory,
            reobserve_factory=reobserve_factory,expected_reobserve_factory=reobserve_factory,
            sample=sample,expected_sample=sample,cancel=a['cancel'],cancel_types=a['cancel_types'],
            entry=entry,outer_work_end=outer_work_end,outer_cleanup_end=outer_cleanup_end)
    except BaseException as error:primary=error
    finally:
        if helpers:
            helper=helpers[0]
            try:helper_result=helper.close_result if helper.closed else helper.close()
            except BaseException as error:
                if primary is None:primary=error
                helper_result=dict(status='FAIL',first_cause=type(error).__name__,cancelled=isinstance(error,a['cancel_types']),uncertain=True)
        try:
            a['cancel']();now=a['clock']();need(type(now) in (int,float) and math.isfinite(now) and now<cleanup_end,'bootstrap-original-cleanup-end')
        except BaseException as error:
            if primary is None:primary=error
            if helper_result is None:helper_result={}
            helper_result.update(status='FAIL',cancelled=helper_result.get('cancelled',False) or isinstance(error,a['cancel_types']),uncertain=True)
    if primary is not None:
        primary.bootstrap_cancelled=isinstance(primary,a['cancel_types']) or bool(helper_result and helper_result.get('cancelled'))
        primary.bootstrap_uncertain=True
        primary.bootstrap_retirement=helper_result
        primary.bootstrap_entry_result=result
        raise primary
    need(type(result) is dict,'Root-entry-result')
    if helper_result is not None and helper_result.get('status')!='PASS_HELPER_FDS_RETIRED_DIRECTORIES_RETAINED':
        result=dict(result);result['status']='FAIL';result['first_cause']=result.get('first_cause') or helper_result.get('first_cause') or 'bootstrap-retirement'
        result['cancelled']=result.get('cancelled',False) or helper_result.get('cancelled',False);result['uncertain']=True
    return dict(result=result,helper_retirement=helper_result,grants_issued_by_bootstrap=False,
                authority_origin='EXTERNAL_ROOT',directory_absence_claimed=False)
