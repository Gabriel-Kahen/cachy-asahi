# SPDX-License-Identifier: MIT
"""Source-only default; fresh explicit native binding before any owned actors."""
import argparse,hashlib,json,os,re,shutil,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,adapter
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')

def source(root):
 root=Path(root).absolute();m=C.decode(C.read(root/'source-manifest.json',4*1024**2));C.need(m['purpose']=='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY'and m['actual']is None,'source-only contract')
 rows=adapter.source_rows(root);C.need(set(rows)==set(m['files'])|{'source-manifest.json',*WORKFLOWS}and all(rows[n]==p for n,p in m['files'].items()),'closed whole new case source')
 wf=C.read(root/'workflow.yml.in').replace(b'@ENTRY_SHA@',rows['entry.py']['sha256'].encode()).replace(b'@MANIFEST_SHA@',C.pin(C.read(root/'source-manifest.json',4*1024**2))['sha256'].encode())
 C.need(all(C.read(root/n)==wf for n in WORKFLOWS),'exact registered generated workflow copies');return dict(status='PASS_CLOSED_SOURCE_ONLY_NOT_EXECUTED',files=len(rows),actual=None,hardware='NOT_RUN')

def parent_modules(a):
 profile=C.decode(C.read(a.source/'profile.json',4*1024**2));adapter.verify(a.core_source,profile['source_profiles']['core800']);body=adapter.core(a.core_source);old=body.C.load('_original_core800_entry',a.core_source/'scripts/ci/core-native-lifecycle/entry.py');old.source(a.core_source);return profile,body,old

def identity(a):
 source(a.source);profile,body,old=parent_modules(a);e=os.environ;s=e.get('SOURCE_SHA')
 C.need(re.fullmatch('[0-9a-f]{40}',s or'')and s==e.get('GITHUB_SHA')==e.get('WORKFLOW_SHA')and e.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and e.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and e.get('GITHUB_RUN_ATTEMPT')=='1'and e.get('RUNNER_ARCH')=='ARM64'and re.fullmatch('codex/[a-z0-9-]+',e.get('GITHUB_REF_NAME',''))and re.fullmatch('[1-9][0-9]{0,19}',e.get('GITHUB_RUN_ID','')),'genuine first native workflow before actors')
 workspace=Path(e.get('GITHUB_WORKSPACE','')).absolute();C.need(re.fullmatch('/[A-Za-z0-9/_-]+',str(workspace)),'literal ordinary native workspace encoding');C.need(a.source==workspace/'case-source'and a.core_source==workspace/'core-source'and a.vm_source==workspace/'vm-source'and a.core7==workspace/'core7-inputs'and a.core64==workspace/'core64-inputs'and a.kernel_carrier==workspace/'kernel-inputs'and a.proof.parent==workspace/'core7-systemd-vm-parent','source-owned literal checkout/output layout')
 end=time.monotonic()+180;actual=dict(source=s,ref=e['GITHUB_REF_NAME'],run=int(e['GITHUB_RUN_ID']),attempt=1);proofs={}
 for role,root in(('core800',a.core_source),('ksm637',a.vm_source),('core7_carrier',a.core7),('kernel_carrier',a.kernel_carrier)):
  proofs[role]=body.C.S.prove(root,root/'.git',profile['source_profiles'][role],end)
 proofs['case']=body.C.S.prove(a.source,a.source/'.git',dict(source=s,ref=actual['ref'],files=adapter.source_rows(a.source)),end);body.C.packet(a.core7)
 # The complete original current64 proof is still held before TEST assembly.
 proofs['core64']=body.C.S.prove(a.core64,a.core64/'.git',body.C.profile()['retained64'],end)
 stamp=str(actual['run'])+':1:'+s;producer=hashlib.sha256(('core-real574:'+stamp).encode()).hexdigest()[:16];nonce=hashlib.sha256(('core-real-pid1:'+stamp).encode()).hexdigest()[:32]
 selected=dict(schema=1,scope=profile['purpose'],actual=actual,nonce=nonce,kernel=profile['kernel'],source_profiles={n:profile['source_profiles'][n]for n in('core800','ksm637','core7_carrier')},budgets=C.BUDGET);C.selection(selected)
 return dict(status='PASS_GENUINE_NEW_CASE_AND_ALL_IMMUTABLE_INPUT_SOURCES',workspace=str(workspace),source_sha=s,ref=actual['ref'],run_id=str(actual['run']),attempt=1,producer_token=producer,consumer_token=nonce,selection=selected,git=proofs,profile=C.pin(C.read(a.source/'profile.json',4*1024**2)))

def kernel_inputs(a,profile):
 target=a.proof.parent/'kernel-inputs';C.need(not target.exists(),'fresh kernel DATA projection');target.mkdir(mode=0o700);(target/'kernel').mkdir()
 rows=profile['source_profiles']['kernel_carrier']['files']
 for name,pin in rows.items():
  C.need(name.startswith('payload/')and'/'not in name[len('payload/'):],'whole flat genuine kernel payload');raw=C.read(a.kernel_carrier/name,256*1024**2);C.need(C.pin(raw)==pin,'every original kernel DATA byte');(target/'kernel'/name[len('payload/'):]).write_bytes(raw)
 return target

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('source','proof','execute','cleanup','retain','transport'));p.add_argument('--source',type=Path,default=C.HERE)
 for name in('core-source','vm-source','core7','core64','kernel-carrier','base','proof','output','receipt','public'):p.add_argument('--'+name,type=Path)
 a=p.parse_args();a.source=a.source.absolute()
 if a.mode=='source':print(C.encoded(source(a.source)).decode(),end='');return 0
 C.need(all(getattr(a,n)is not None for n in('core_source','vm_source','core7','core64','kernel_carrier','proof')),'explicit complete immutable source inputs; source-only default starts no actor')
 for name in('core_source','vm_source','core7','core64','kernel_carrier','proof','base','output','receipt','public'):
  if getattr(a,name)is not None:setattr(a,name,getattr(a,name).absolute())
 profile,body,old=parent_modules(a)
 if a.mode=='proof':
  value=identity(a);C.need(not a.proof.exists()and a.proof.parent.is_dir(),'fresh owned proof leaf');a.proof.write_bytes(C.encoded(value));kernel_inputs(a,profile)
  with open(os.environ['GITHUB_OUTPUT'],'a')as stream:stream.write('job_token='+value['producer_token']+'\n')
  return 0
 value=C.decode(C.read(a.proof,4*1024**2));C.selection(value['selection']);C.need(value['source_sha']==os.environ.get('SOURCE_SHA')==os.environ.get('GITHUB_SHA')and value['run_id']==os.environ.get('GITHUB_RUN_ID'),'same genuine new process binding')
 a.selected=value['selection'];a.case_source=a.source;a.source=a.core_source;a.workspace=a.core_source/'runtime/runtime-vm';a.kernel_inputs=a.proof.parent/'kernel-inputs'
 import controller,evidence
 if a.mode=='execute':C.need(identity(type('Args',(),dict(vars(a),source=a.case_source))())==value,'fresh all-source/current64 input proof before actors');return controller.execute(a)
 if a.mode=='cleanup':return evidence.cleanup(a)
 if a.mode=='retain':return evidence.retain(a)
 return body.C.load('_original_core800_transport',a.core_source/'scripts/ci/core-native-lifecycle/owner.py').transport(a)
if __name__=='__main__':
 import signal
 def cancelled(*_):raise KeyboardInterrupt()
 for number in(signal.SIGTERM,signal.SIGINT):signal.signal(number,cancelled)
 raise SystemExit(main())
