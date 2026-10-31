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
 import_successor()
 return dict(status=mf['status'],files=len(actual),whole_original_boot391=old,original604_physical_unselected=600,current606_physical_unselected=602,selected_four='EXACT_LOGICAL_RESTORATION_NO_INODE_CLAIM',bounds=P.BOUNDS,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None)

def authorize():
 G=original();old=G.authorize();value=json.loads((HERE/'input-policy.json').read_bytes());S.authorize(value,old['current606']);return value

def public_checkouts(packets,*,apps8_packet):
 authorize();import latest_inputs
 G=original();checks=module('_latest_native_all_input_inspector',BASE/'held606/held-tools/scripts/checks/package_checks.py');P.need(set(packets)==set(S.PACKETS),'allfive exact public DATA checkouts')
 for role,path in packets.items():
  p=subprocess.run(['git','-C',str(path),'rev-parse','HEAD'],capture_output=True,text=True,timeout=15,check=True);P.need(p.stdout.strip()==S.PACKETS[role]['source'],'genuine published exactcarrier checkout')
 return latest_inputs.inspect(ROOT,BASE,packets,G,checks,apps8_packet=apps8_packet)

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

# BEGIN_SOURCE_OWNED_IMPORT_ORDER_GUARD
def import_successor():
 """Whole genuine549 source inverse; only isolated import ordering changes."""
 import base64
 proof_name='latest/implementation/welcome7-successor.json';adapter_name='latest/implementation/latest_preservation_adapter.py';guard_name='latest/implementation/latest_guard.py';v=json.loads((ROOT/proof_name).read_bytes());part=v['import_order_successor'];before=part['before'];auth=part['source_authorization'];pin=lambda x:S.pin((json.dumps(x,sort_keys=True,indent=2)+'\n').encode());P.need(pin(auth)=={'bytes': 100678, 'sha256': '6bdb59f9f4e9abfb553e784a408b3a121bcf782ea33c6ccf932a19b799d7c54f'} and len(auth)==549 and pin(before)=={'bytes': 100678, 'sha256': '6bdb59f9f4e9abfb553e784a408b3a121bcf782ea33c6ccf932a19b799d7c54f'} and set(before)==set(auth),'whole selected549 and exact predecessor view')
 pub=part['publication'];git=part['git_source_authorization'];P.need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='bd83ba448fd66ce313151e487aeb5b94a64c2a26',ref='codex/current607-welcome7-combined-tools-v1',files=549,git_joins=549,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and git==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=auth),'whole genuine549 predecessor publication/Git')
 P.need(set(part)=={'status','view','before','source_authorization','publication','git_source_authorization','before_bodies','actual_source','actual_ref','actual_run'}and part['status']=='FINITE_ISOLATED_IMPORT_ORDER_ONLY_NOT_ACCEPTED'and part['view']=='source-selected' and all(part[k]is None for k in('actual_source','actual_ref','actual_run')),'exact import-order scope/NULL actual')
 changed={adapter_name,guard_name,proof_name,MANIFEST,*WORKFLOWS};P.need(set(part['before_bodies'])==changed,'exact6 whole inverse bodies');actual={p.relative_to(ROOT).as_posix():S.pin(p.read_bytes())for p in ROOT.rglob('*')if p.is_file()and p.relative_to(ROOT).parts[0]!='.git'};P.need(set(actual)==set(before)and{n for n in before if before[n]!=actual[n]}==changed,'six changed543 held/no additions')
 bodies={}
 for n,row in before.items():
  raw=base64.b64decode(part['before_bodies'][n],validate=True)if n in changed else(ROOT/n).read_bytes();P.need(S.pin(raw)==row,'whole original549 beforebody/held leaf '+n);bodies[n]=raw
 text=(ROOT/adapter_name).read_text();P.need(text.count("('import sys\\nsys.path.insert(0,str(Path(__file__).resolve().parent))','import sys\\nsys.path.insert(0,str(Path(__file__).resolve().parent))\\nimport latest_domain as LD')")==1,'exact safe import seam');P.need(S.pin(text.replace("('import sys\\nsys.path.insert(0,str(Path(__file__).resolve().parent))','import sys\\nsys.path.insert(0,str(Path(__file__).resolve().parent))\\nimport latest_domain as LD')","('import sys\\nsys.path.insert','import sys\\nimport latest_domain as LD\\nsys.path.insert')",1).encode())==before[adapter_name],'whole original preservation adapter outside import relocation')
 text=(ROOT/guard_name).read_text();marker='\n# BEGIN_SOURCE_OWNED_IMPORT_ORDER_GUARD\n';P.need(text.count(marker)==1,'one finite source guard appendix');prefix=text.split(marker)[0];P.need(prefix.count(' successor()\n import_successor()\n return dict(')==1,'one mandatory new guard call');prefix=prefix.replace(' successor()\n import_successor()\n return dict(',' successor()\n return dict(',1);P.need(S.pin(prefix.encode())==before[guard_name],'whole old549 guard body inverse')
 old=json.loads(bodies[proof_name]);expected=dict(old);expected['before_bodies']=dict(old['before_bodies']);old_auth=old['source_authorization'];skip={MANIFEST,*WORKFLOWS,proof_name}
 for n,row in old_auth.items():
  if n not in expected['before_bodies']and S.pin((ROOT/n).read_bytes())!=row:P.need(S.pin(bodies[n])==row,'held original544 body for new adapter seam');expected['before_bodies'][n]=base64.b64encode(bodies[n]).decode()
 expected['after']={n:row for n,row in actual.items()if n not in skip and(n not in old_auth or row!=old_auth[n])};expected['import_order_successor']=part;P.need(v==expected,'only exact old metadata closure extension, whole prior proof beforebody retained')
 mf=json.loads((ROOT/MANIFEST).read_bytes())
 for n in changed-{MANIFEST,*WORKFLOWS}:mf['files'][n]=before[n]
 P.need(S.pin((json.dumps(mf,sort_keys=True,indent=2)+'\n').encode())==before[MANIFEST],'whole original source manifest inverse')
 for n in WORKFLOWS:P.need(S.pin((ROOT/n).read_bytes().replace(actual[MANIFEST]['sha256'].encode(),before[MANIFEST]['sha256'].encode()))==before[n],'whole exact workflow stamp inverse')
 return dict(status=part['status'],predecessor=pub['source'],source_files=549,changed=6,held=543,actual_run=None)

# BEGIN_EXACT_RUNTIME_SUCCESSOR
def verify():
 import runtime_successor
 return runtime_successor.verify(ROOT, 'latest/implementation/runtime-successor.json', {'bytes': 633565, 'sha256': 'f6a839df072ad2670653f5bffbbeceaebf84f37b9be40c57310c8f480ea1e535'})

# BEGIN_COMPLETE_NATIVE_BASE_SUCCESSOR
def verify():
 import native_base_successor
 return native_base_successor.verify(ROOT, 'latest/implementation/native-base-successor.json', {'bytes': 1038595, 'sha256': '6deb027fd9136ea5d9fbb015c6f0092dfa2f24aedc3899c2c30c7fb96d61dffd'})

# BEGIN_EARLY_LEGACY_PREFILL_SUCCESSOR
def verify():
 import early_prefill_successor
 return early_prefill_successor.verify(ROOT, 'latest/implementation/early-prefill-successor.json', {'bytes': 1330906, 'sha256': '5900dfa08a85fcc4b2594521105a5bbdab60aeb97ae3335d1e01e2db2bd844a2'})

# BEGIN_FINITE_LIFECYCLE_DESCRIPTOR_SUCCESSOR
def verify():
 import lifecycle_successor
 return lifecycle_successor.verify(ROOT, 'latest/implementation/lifecycle-successor.json', {'bytes': 1714297, 'sha256': '2096b05c0994afa899a91a146f743dd8238925d90a34c0d1684aeea21a306ab5'})

# BEGIN_EXACT_PREFILL_PATH_SUCCESSOR
def verify():
 import prefill_path_successor
 return prefill_path_successor.verify(ROOT, 'latest/implementation/prefill-path-successor.json', {'bytes': 683378, 'sha256': 'f9db4fa7fdd2adc1f03cbeb0019dfee55cc1b26cb0ec932ec0a0cdec5a583857'})

# BEGIN_BOUNDED_FAILURE_RETENTION_SUCCESSOR
def verify():
 import failure_retention
 return failure_retention.verify(ROOT, 'latest/implementation/failure-retention-successor.json', {'bytes': 694661, 'sha256': '58a56da3d9877aba7fee4e67a2f4d8de068542665f397f11c37b117dabe4c91c'})

# BEGIN_FRESH_ANCESTRY_COST_SUCCESSOR
def verify():
 import lifecycle_cost_successor
 return lifecycle_cost_successor.verify(ROOT, 'latest/implementation/lifecycle-cost-successor.json', {'bytes': 689441, 'sha256': '96982f8c625ad925b7f4d2f203785b41d973dc2d8c418b272cec37c6478eee37'})

# BEGIN_LAYERED4200_PROFILE
def verify():
 import budget_successor
 return budget_successor.verify(ROOT, 'latest/implementation/layered4200-successor.json', {'bytes': 739642, 'sha256': 'a62547e7eebbf5ecfe89eca6dfe19efd12a6054797c45dec05b5a48dcd5696c9'})

# BEGIN_ADDITIONAL_APPS8_COMPOSITION
def verify():
 import apps8_successor
 return apps8_successor.verify(ROOT, 'latest/implementation/apps8-successor.json', {'bytes': 793187, 'sha256': 'fbc31a87570589c3c2de89b6c9a586f4b9efa3e628956e313dcbca5927e9307a'})

# BEGIN_EXACT_SIX_TOOL_COMPOSITION
def verify():
 import next_successor
 return next_successor.verify(ROOT, 'latest/implementation/next-successor.json', {'bytes': 904408, 'sha256': 'dcbd2ac970b4cfce94cb6feeed6dadbfecc8bd4c7567881a645551987c9420ec'})

def public_checkouts(packets,*,apps8_packet,extra_packets):
 import next_successor
 return next_successor.public_checkouts(globals(),packets,apps8_packet=apps8_packet,extra_packets=extra_packets)

# BEGIN_EXACT_SIXCAP_SUPERVISOR_BINDING
def verify():
 import sixcap_successor
 return sixcap_successor.verify(ROOT, 'latest/implementation/sixcap-successor.json', {'bytes': 914727, 'sha256': '5678fb1761e85cfc47ebc3ecc17a965795f8bcf6d49cd8da91d6f5c73b3e4398'})

# BEGIN_EXACT_INSTALLED_STDOUT_CODEC_SUCCESSOR
def verify():
 import installed_codec_successor
 return installed_codec_successor.verify(ROOT, 'latest/implementation/installed-codec-successor.json', {'bytes': 925568, 'sha256': '2131b97eac69676acd457b122398255e68d9ae49663abd806c43feb4bc22a73a'})
