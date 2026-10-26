# SPDX-License-Identifier: MIT
"""Finite typed inventory/selected operands; clocks and runtime calls stay held."""
import ast,json
from pathlib import Path
import common as C
COUNTS={
 'scripts/update/generic_policy.py':{'protected_names':{604:2},'authorize':{604:1}},
 'scripts/update/full_root.py':{'Limits':{604:1}},
 'scripts/update/scale_update.py':{'__init__':{604:1},'selection':{604:1},'observed_after':{604:1}},
 'scripts/update/aux_runtime.py':{'apps6_selection_guard':{604:1,603:1}},
 'scripts/ci/full-development-composition/setup4_inputs.py':{'expected_lock':{604:2}},
 'scripts/ci/full-root-upgrade/root_upgrade.py':{'selection':{604:2},'database':{604:1}},
 'scripts/ci/full-root-upgrade/construct_repository.py':{'validate_base':{604:2}},
 'scripts/ci/full-root-upgrade-caller/container.py':{'inputs':{31:1,21:1,604:1}},
 'scripts/ci/full-root-upgrade-caller/upgrade_hook.py':{'quiesce':{604:1},'run':{604:1}},
 'scripts/ci/full-root-failed-update/caller.py':{'quiesce':{604:1},'run':{604:1}},
 'scripts/ci/full-root-postcommit-failure/caller.py':{'quiesce':{604:1},'run':{604:1}},
 'scripts/ci/full-root-failed-update/run.py':{'arm':{604:1}},
 'scripts/ci/full-root-postcommit-failure/run.py':{'arm':{604:1},'database_after':{604:1,605:1},'prepare_verifier':{604:1},'verify_after':{604:1}}}
STRINGS={
 'scripts/ci/full-root-upgrade-caller/upgrade_hook.py':{'quiesce':{'0.1.0-5':('0.1.0-6',1)},'driver_command':{'public/packages/cachy-asahi-apps-a/cachy-asahi-apps-0.1.0-6-any.pkg.tar.xz':('public/packages/cachy-asahi-apps-a/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz',1)}},
 'scripts/ci/full-root-failed-update/caller.py':{'quiesce':{'0.1.0-5':('0.1.0-6',1)},'driver_command':{'public/packages/cachy-asahi-apps-a/cachy-asahi-apps-0.1.0-6-any.pkg.tar.xz':('public/packages/cachy-asahi-apps-a/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz',1)}},
 'scripts/ci/full-root-postcommit-failure/caller.py':{'quiesce':{'0.1.0-5':('0.1.0-6',1)},'driver_command':{'public/packages/cachy-asahi-apps-a/cachy-asahi-apps-0.1.0-6-any.pkg.tar.xz':('public/packages/cachy-asahi-apps-a/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz',1)}},
 'scripts/ci/full-root-upgrade/root_upgrade.py':{'committed':{'0.1.0-6':('0.1.0-16',1)}},
 'scripts/ci/full-root-failed-update/run.py':{'arm':{'0.1.0-6':('0.1.0-16',2)},'assess':{'0.1.0-6':('0.1.0-16',1)}},
 'scripts/ci/full-root-postcommit-failure/run.py':{'precommit':{'0.1.0-6':('0.1.0-16',1)},'arm':{'0.1.0-6':('0.1.0-16',1),'AUTHENTICATED_APPS5_TO6_CHILD_SELECTION':('AUTHENTICATED_APPS6_TO16_CHILD_SELECTION',1)},'boundary':{'0.1.0-6':('0.1.0-16',1),'AUTHENTICATED_APPS5_TO6_CHILD_SELECTION':('AUTHENTICATED_APPS6_TO16_CHILD_SELECTION',1)},'prepare_verifier':{'var/lib/pacman/local/cachy-asahi-apps-0.1.0-5':('var/lib/pacman/local/cachy-asahi-apps-0.1.0-6',1),'0.1.0-5':('0.1.0-6',1),'0.1.0-6':('0.1.0-16',1)}}}
NUMBERS={604:607,603:606,605:608,31:34,21:24}
SELECTED={'scripts/ci/full-root-upgrade/root_upgrade.py','scripts/ci/full-root-upgrade/construct_repository.py','scripts/update/aux_runtime.py','scripts/update/linked_runtime.py','scripts/ci/full-root-postcommit-failure/run.py'}
OLD_BEFORE='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5';OLD_AFTER='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3';OLD_PACKAGE='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7'
def walk(n,scope='<module>'):
 if isinstance(n,(ast.FunctionDef,ast.ClassDef)):scope=n.name
 yield n,scope
 for child in ast.iter_child_nodes(n):yield from walk(child,scope)
def transform(raw,name):
 p=C.profile();text=raw.decode();tree=ast.parse(raw);lines=raw.splitlines(keepends=True);offset=[0]
 for line in lines:offset.append(offset[-1]+len(line))
 edits=[];counts={};string_counts={};strings=STRINGS.get(name,{});declared=COUNTS.get(name,{})
 for n,scope in walk(tree):
  if not isinstance(n,ast.Constant):continue
  v=n.value;after=v
  if type(v)is int and v in declared.get(scope,{}):after=NUMBERS[v];counts[(scope,v)]=counts.get((scope,v),0)+1
  if type(v)is str:
   if v in strings.get(scope,{}):after=strings[scope][v][0];string_counts[(scope,v)]=string_counts.get((scope,v),0)+1
   if v==OLD_BEFORE:after=p['before']['sha256']
   elif v==OLD_AFTER:after=p['after']['sha256']
   elif name in SELECTED and v==OLD_PACKAGE:after=p['selected']['archive']['sha256']
   elif name.endswith('/construct_repository.py')and scope=='<module>'and v=='c5481ad6bfd1539ab9a289bc9541133b979858f7':after=p['selected']['native']
   elif name.endswith('/construct_repository.py')and scope=='<module>'and v=='aa4d6ed7865aab606a55e7de94e50d6966f47f7b926a39efd4b3f64eec403778':after=p['selected']['recipe']
   elif name.endswith('/construct_repository.py')and scope=='convert_provenance'and v=='0.1.0-6':after='0.1.0-16'
   elif name.endswith('/construct_repository.py')and scope=='convert_provenance'and v=='PUBLIC_ROOT_PAIR_AUTHORITY_AND_COMPLETE_BUILDINFO':after='EXACT_ROOT_ACCEPTED_NATIVE_PAIR94_RAW575_AND_COMPLETE_BUILDINFO'
   elif name.endswith('/construct_repository.py')and scope=='convert_provenance'and v=='NOT_PRESENT_NOT_FABRICATED':after='PRESENT_VERIFIED_NATIVE575_BUILD_DATA_ONLY'
   elif name.endswith('/root_upgrade.py')and scope=='selection'and v in('0.1.0-5','0.1.0-6'):after={'0.1.0-5':'0.1.0-6','0.1.0-6':'0.1.0-16'}[v]
   elif name.endswith('/aux_runtime.py')and scope=='apps6_selection_guard'and v=='0.1.0-6':after='0.1.0-16'
   elif name.endswith('/aux_runtime.py')and scope=='apps6_selection_guard'and v=='0.1.0-5':after='0.1.0-6'
   elif name.endswith('/persistent_scope.py')and scope=='held'and type(v)is bytes and v==b'max_packages: int = 604':after=b'max_packages: int = 607'
  if type(v)is bytes and name.endswith('/persistent_scope.py')and scope=='held'and v==b'max_packages: int = 604':after=b'max_packages: int = 607'
  if type(v)is str and name.endswith('/container.py')and scope=='<module>'and v in('cachy-asahi-boot-report','cachy-asahi-dns','cachy-asahi-sysctl'):C.need(False,'new project already in original604 selector')
  if after==v:continue
  a=offset[n.lineno-1]+n.col_offset;b=offset[n.end_lineno-1]+n.end_col_offset;edits.append(dict(start=a,end=b,before=raw[a:b].decode(),after=repr(after)))
 C.need(counts=={(scope,n):count for scope,rs in declared.items()for n,count in rs.items()},'exact typed607 inventory operand counts '+name)
 C.need(string_counts=={(scope,n):row[1]for scope,rs in strings.items()for n,row in rs.items()},'exact selected Apps6 to16 scoped string counts '+name)
 out=raw
 for r in sorted(edits,key=lambda r:r['start'],reverse=True):out=out[:r['start']]+r['after'].encode()+out[r['end']:]
 # An exact package set extension; unrelated syscall errno21/31 and all clocks hold.
 extra=[]
 if name.endswith('/full-root-upgrade-caller/container.py'):
  node=next(n for n in ast.parse(out).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PROJECTS'for t in n.targets));segment=ast.get_source_segment(out.decode(),node);after=segment+" | {'cachy-asahi-boot-report','cachy-asahi-dns','cachy-asahi-sysctl'}";C.need(out.decode().count(segment)==1,'one complete bootstrap project selector');out=out.decode().replace(segment,after,1).encode();extra.append(dict(before=segment,after=after))
 if name.endswith('/aux_runtime.py'):
  before="before.get('cachy-asahi-setup')=='0.1.0-6'";C.need(out.decode().count(before)==1,'Setup6 remains protected, not an Apps target');
 if name.endswith('/construct_repository.py'):
  before="scripts/ci/expanded604-apps6-public-pair-updater/selected_package.py";after='scripts/ci/latest607-updater/selected_package.py';C.need(out.decode().count(before)==2,'two exact selected package helper routes');out=out.decode().replace(before,after).encode();extra.append(dict(before=before,after=after,count=2))
 restored=out.decode()
 for r in reversed(extra):C.need(restored.count(r['after'])==r.get('count',1),'one exact extra inverse');restored=restored.replace(r['after'],r['before'])
 restored=restored.encode()
 for r in sorted(edits,key=lambda r:r['start']):
  a=r['start'];b=a+len(r['after'].encode());C.need(restored[a:b]==r['after'].encode(),'exact inverse operand');restored=restored[:a]+r['before'].encode()+restored[b:]
 C.need(restored==raw,'whole original604 runtime body inverse '+name);compile(out,name,'exec');return out,dict(before=C.pin(raw),after=C.pin(out),edits=edits,extra=extra,whole_inverse=True)
