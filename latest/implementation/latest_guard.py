# SPDX-License-Identifier: MIT
"""Whole original Boot391 context plus bounded five-tool source additions."""
import contextlib,importlib.util,json,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];BASE=ROOT/'historical/boot391';MANIFEST='latest/source-manifest.json';WORKFLOWS={'.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current607-latest-tools.yml'}
import latest_plan as P
import latest_selection as S

def module(name,path,aliases=None):
 missing=object();saved={k:sys.modules.get(k,missing)for k in aliases or{}};sys.modules.update(aliases or{})
 try:
  spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
 finally:
  for k,v in saved.items():
   if v is missing:sys.modules.pop(k,None)
   else:sys.modules[k]=v

def original():
 sys.path.insert(0,str(BASE/'boot607'));A=module('_latest_full_original_boot_inputs',BASE/'boot607/accepted_inputs.py');G=module('_latest_full_original_boot_guard',BASE/'boot607/guard.py',{'accepted_inputs':A});return G

def verify():
 P.need(not sys.flags.optimize,'optimized guards refused');mf=json.loads((ROOT/MANIFEST).read_bytes());P.need(mf['schema_version']==1 and mf['status']=='SOURCE_ONLY_NATIVE607_LATEST_FIVE_NOT_ACCEPTED'and all(mf[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'strict source-only NULL actualmanifest');files=mf['files'];actual=set()
 for p in ROOT.rglob('*'):
  if p.relative_to(ROOT).parts[0]=='.git':continue
  P.need(not p.is_symlink(),'source directory/leaf alias refused')
  if p.is_file():actual.add(p.relative_to(ROOT).as_posix())
 P.need(actual==set(files)|WORKFLOWS|{MANIFEST},'entire closed latest607 source')
 for n,row in files.items():P.need(not Path(n).is_absolute()and '..'not in Path(n).parts and S.pin((ROOT/n).read_bytes())==row,'full latest607 source drift '+n)
 contexts=json.loads((HERE/'contexts.json').read_bytes())
 for role,row in contexts.items():
  auth=json.loads((HERE/'authority'/row['authorization']).read_bytes());pub=json.loads((HERE/'authority'/row['publication']).read_bytes());P.need(S.pin((HERE/'authority'/row['authorization']).read_bytes())==row['authorization_pin']and S.pin((HERE/'authority'/row['publication']).read_bytes())==row['publication_pin']and pub['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'and pub['source']==row['source']and pub['files']==pub['git_joins']==row['files'],'genuine whole original source authority')
  full=auth['files']if role=='boot391'else auth;P.need(len(full)==row['files'],'entire prior source authmap')
  subset={n:p for n,p in full.items()if n.startswith(row['original_prefix'])};P.need(len(subset)==row['staged_files']and{p.relative_to(ROOT/row['staged_prefix']).as_posix()for p in(ROOT/row['staged_prefix']).rglob('*')if p.is_file()}=={n.removeprefix(row['original_prefix'])for n in subset},'closed exact staged source role')
  for n,pin in subset.items():P.need(S.pin((ROOT/row['staged_prefix']/n.removeprefix(row['original_prefix'])).read_bytes())==pin,'all staged historical source bodies byteheld')
 G=original();old=G.verify();P.need(old['files']==391 and old['held_native606_files']==263,'full391 originalcontext and complete original606 proof')
 O,selection,C,adapter,bridge,original_api=G.original_context()
 import latest_owner as owner,latest_transaction_adapter as transaction,latest_preservation_adapter as preservation
 owner.owner(adapter.owner(BASE/'held606'));owner.bridge_source((BASE/'held606/scripts/ci/current606-native/bridge606.py').read_text());preservation.native606((BASE/'held606/scripts/ci/current606-native/tools606.py').read_bytes(),owner.OLD_SEQUENCE,owner.NEW_SEQUENCE);preservation.outer(adapter.lifecycle(BASE/'held606').encode())
 for role,_,_,_ in P.PRODUCTS:transaction.derive((HERE/'held/alpm_step.py').read_bytes(),role)
 import latest_workflow as workflow
 expected=workflow.derive((BASE/'.github/workflows/native-arm-current606-boot607.yml').read_text(),S.pin((HERE/'latest_run.py').read_bytes()),S.pin((ROOT/MANIFEST).read_bytes()))
 P.need(all((ROOT/n).read_text()==expected for n in WORKFLOWS),'full workflow finite inverse and stamps')
 import latest_transport_scope
 latest_transport_scope.verify(ROOT)
 successor()
 return dict(status=mf['status'],files=len(actual),whole_original_boot391=old,original604_physical_unselected=600,current606_physical_unselected=602,selected_four='EXACT_LOGICAL_RESTORATION_NO_INODE_CLAIM',bounds=P.BOUNDS,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None)

def authorize():
 G=original();old=G.authorize();value=json.loads((HERE/'input-policy.json').read_bytes());S.authorize(value,old['current606']);return value

def public_checkouts(packets):
 authorize();import latest_inputs
 G=original();checks=module('_latest_native_all_input_inspector',BASE/'held606/held-tools/scripts/checks/package_checks.py');P.need(set(packets)==set(S.PACKETS),'allfive exact public DATA checkouts')
 for role,path in packets.items():
  p=subprocess.run(['git','-C',str(path),'rev-parse','HEAD'],capture_output=True,text=True,timeout=15,check=True);P.need(p.stdout.strip()==S.PACKETS[role]['source'],'genuine published exactcarrier checkout')
 return latest_inputs.inspect(ROOT,BASE,packets,G,checks)

def successor():
 """Complete original544 source reconstruction; exact finite new bodies only."""
 import base64
 raw=(HERE/'welcome7-successor.json').read_bytes();v=json.loads(raw);auth=v['source_authorization'];pub=v['publication'];git=v['git_source_authorization'];P.need(S.pin((json.dumps(auth,sort_keys=True,indent=2)+'\n').encode())=={'bytes': 99931, 'sha256': 'ed66da31dccb7b3e132ba10a49eca8d17ec09d74ce8f42474d301d964b003756'} and len(auth)==544,'whole exact predecessor544 authorization')
 P.need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='ec3c051d48fd29fb6c7f352e63ab4b1392f66098',ref='codex/current607-combined-tools-v1',files=544,git_joins=544,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and git==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=auth),'genuine whole544 predecessor Git/publication context')
 actual={p.relative_to(ROOT).as_posix()for p in ROOT.rglob('*')if p.is_file()and p.relative_to(ROOT).parts[0]!='.git'};adds={'welcome7_inputs.py','latest/implementation/welcome7-custody.json','latest/implementation/welcome7-successor.json','latest/implementation/accepted/welcome7.json','latest/tests/test_welcome7.py'};P.need(set(v['additions'])==adds and actual-set(auth)==adds and set(auth)<=actual,'finite five additions, no old source omitted')
 for n,row in auth.items():
  before=base64.b64decode(v['before_bodies'][n],validate=True)if n in v['before_bodies']else(ROOT/n).read_bytes();P.need(S.pin(before)==row,'whole original544 beforebody/held leaf '+n)
 skip={MANIFEST,*WORKFLOWS,'latest/implementation/welcome7-successor.json'};after={n:S.pin((ROOT/n).read_bytes())for n in actual-skip if n not in auth or S.pin((ROOT/n).read_bytes())!=auth[n]};P.need(after==v['after']and all(v[k]is None for k in('actual_source','actual_ref','actual_run')),'exact complete proposed finite successor bodies, futureNULL')
 return dict(status=v['status'],predecessor_source=pub['source'],predecessor_files=544,files=549)
