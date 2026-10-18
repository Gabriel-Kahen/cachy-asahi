#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite maintained installed16K source composition; default authorizes no actor."""
import argparse,ast,hashlib,importlib.util,json,shutil,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/glibc-gnu-provider-installed16k'
NEW='scripts/ci/glibc-debian-maintained-installed16k'
MAINTAINED='scripts/ci/glibc-debian-maintained-lifecycle'
NATIVE='scripts/ci/glibc-debian-maintained-provider-lifecycle'
MODULES=('contract.py','adapter.py','prepare.py','guest.py','run.py','export.py','sandbox.py','scrub.py','support.py','snapshot_progress.py','observer_progress.py')
RULES={
 'contract.py':[(OLD,NEW,1),("NATIVE='scripts/ci/glibc-gnu-provider-lifecycle'","NATIVE='"+NATIVE+"'",1),('org.cachy-asahi.gnu-installed16k','org.cachy-asahi.debian-maintained-installed16k',1),('_installed16k_','_debian_maintained_installed16k_',1),('PASS_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY','PASS_DEBIAN_MAINTAINED_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY',1)],
 'adapter.py':[('caa_gnu_installed16k=1','caa_debian_maintained_installed16k=1',1)],
 'prepare.py':[('/installed16k','/debian-maintained-installed16k',2),("'installed16k'","'debian-maintained-installed16k'",2),("'installed16k/","'debian-maintained-installed16k/",3),('init-installed16k','init-debian-maintained-installed16k',2),('CAA_INSTALLED16K_PREPARE','CAA_DEBIAN_MAINTAINED_INSTALLED16K_PREPARE',1),('GNU16K_','C3ALPM16K_',1),('b852e3fc647d63699c5f42003a748cbd2268991dc2615a494dc3cdda4d757d12','a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9',1)],
 'guest.py':[('/installed16k','/debian-maintained-installed16k',7),('caa_gnu_installed16k=1','caa_debian_maintained_installed16k=1',1),('GNU_INSTALLED16K','DEBIAN_MAINTAINED_INSTALLED16K',4)],
 'run.py':[('/installed16k','/debian-maintained-installed16k',2),('init-installed16k','init-debian-maintained-installed16k',1),('caa_gnu_installed16k=1','caa_debian_maintained_installed16k=1',1),('GNU_INSTALLED16K','DEBIAN_MAINTAINED_INSTALLED16K',2),('CAA_INSTALLED16K_PREPARE','CAA_DEBIAN_MAINTAINED_INSTALLED16K_PREPARE',1),('caa-gnu-installed16k-','caa-debian-maintained-installed16k-',1)],
 'export.py':[('CAA_INSTALLED16K_PREPARE','CAA_DEBIAN_MAINTAINED_INSTALLED16K_PREPARE',1)],'snapshot_progress.py':[], 'observer_progress.py':[], 'sandbox.py':[],'scrub.py':[('CAA_INSTALLED16K_PREPARE','CAA_DEBIAN_MAINTAINED_INSTALLED16K_PREPARE',1)],'support.py':[]}
GATE="""def gate(acceptances):
    return load('maintained_installed_phase_gate',HERE/'phase_gate.py').validate(sys.modules[__name__],acceptances)
"""
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

def source(root):
 value=json.loads((HERE/'source-pins.json').read_bytes());need(len(value['files'])==119,'finite current119 source closure')
 for name,row in value['files'].items():
  p=root/name;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<=2*1024**2 and pin(p.read_bytes())==row,'exact current full-root/candidate helper differs: '+name)
 return value

def adapt(raw,name):
 text=raw.decode();count=0
 for before,after,n in RULES[name]:need(text.count(before)==n,'counted maintained installed16K anchor: '+name+' '+before[:80]);text=text.replace(before,after);count+=n
 if name=='contract.py':
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='gate');old=ast.get_source_segment(text,node);need(text.count(old)==1,'one original gate body');text=text.replace(old,GATE.rstrip())
 ast.parse(text);return text.encode(),count

def emit(root,output):
 root=root.absolute();output=output.absolute();held=source(root);need(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output');output.mkdir(mode=0o700)
 maintained=load('maintained_lifecycle_emitter',root/MAINTAINED/'adapter.py');selected={}
 # Reuse the complete existing emitter, retaining only its normal lifecycle role.
 with tempfile.TemporaryDirectory(prefix='caa3-installed16k-source-') as temp:
  native=Path(temp)/'emitted';composition=maintained.emit(root,native)
  for folder in (NATIVE,NATIVE+'-owner'):
   shutil.copytree(native/folder,output/folder)
   for p in (output/folder).iterdir():
    if p.is_file():selected[p.relative_to(output).as_posix()]=pin(p.read_bytes())
 target=output/NEW;target.mkdir(parents=True,mode=0o700);edits={}
 for name in MODULES:
  raw,count=adapt((root/OLD/name).read_bytes(),name);(target/name).write_bytes(raw);edits[name]=count
 (target/'phase_gate.py').write_bytes((HERE/'phase_gate.py').read_bytes());(target/'candidate_gate.py').write_bytes((root/MAINTAINED/'candidate_gate.py').read_bytes())
 candidate=composition['candidate'];phase=load('maintained_installed_prerequisites',HERE/'phase_gate.py')
 policy=dict(schema_version=1,status='UNBOUND_DO_NOT_EXECUTE',binding=dict(native_lifecycle=None,system16k=None),candidate=candidate,native_pair=phase.PAIR,authority='PRIVATE_TEST_ONLY_NO_RELEASE_ADMISSION',required_before_binding=['Actual Root accepted CURRENT maintained caa3 native normal ALPM lifecycle and ordered cleanup','Actual Root accepted CURRENT maintained caa3 staged16384 system-path runtime and ordered cleanup','Same actual a8e9f3 package/payload/native-pair/source-authority metadata; no old GNU/caa2 credit','Existing maintained owner full574 snapshot, bound lifecycle runner/inputs and live producer lease'],interruption='SEPARATE_NOT_A_PREREQUISITE')
 (target/'input-policy.json').write_bytes(encoded(policy));deps=dict(held['files'])|selected;(target/'dependencies.json').write_bytes(encoded(dict(schema_version=1,files=deps)))
 own={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in target.iterdir() if p.is_file()};(target/'source-manifest.json').write_bytes(encoded(dict(schema_version=1,files=own)))
 result=dict(status='SOURCE_ONLY_MAINTAINED_INSTALLED16K_INPUTS_UNBOUND',candidate=candidate,native_pair=phase.PAIR,original_source_files=len(held['files']),composed_normal_native_files=len(selected),composed_identity_edits=composition['roles']['lifecycle']['identity_edits'],literal_edits=edits,gate_body_replacements=1,original_native_adapter_edits=4,unchanged_native_bodies=20,runtime_observations=8,root_maps=16,scope='DISPOSABLE_FULL574_ALPM_NORMAL_LIFECYCLE_AND_RECOVERY',files={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in output.rglob('*') if p.is_file()},native='NOT_RUN',ALPM_installation='NOT_RUN',generic16k='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
 (output/'adaptation.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source,a.output),sort_keys=True))
