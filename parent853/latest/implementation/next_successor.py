# SPDX-License-Identifier: MIT
"""Whole accepted581 inverse, new six-tool bodies, full698/240 source custody."""
import base64,contextlib,importlib.util,json,sys,tempfile
from pathlib import Path
import lifecycle_cost_successor as O
pin,enc,rows,need=O.pin,O.enc,O.rows,O.need
MARKER='\n# BEGIN_EXACT_SIX_TOOL_COMPOSITION\n'
@contextlib.contextmanager
def parent(root,p):
 before=p['before'];changed=set(p['before_bodies']);bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in changed else(Path(root)/n).read_bytes()for n in before};need(all(pin(bodies[n])==w for n,w in before.items()),'every whole581 before body')
 with tempfile.TemporaryDirectory(prefix='current607-whole-original581-')as td:
  out=Path(td)/'source';out.mkdir()
  for n,b in bodies.items():q=out/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
  need(rows(out)==before,'complete physical581 before context');yield out,bodies

def guard_footer(name,want):return "def verify():\n import next_successor\n return next_successor.verify(ROOT, "+repr(name)+', '+repr(want)+")\n\ndef public_checkouts(packets,*,apps8_packet,extra_packets):\n import next_successor\n return next_successor.public_checkouts(globals(),packets,apps8_packet=apps8_packet,extra_packets=extra_packets)\n"

def verify(root,name,want):
 root=Path(root);raw=(root/name).read_bytes();need(pin(raw)==want and not sys.flags.optimize,'whole hard-pinned six-tool source profile');p=json.loads(raw);actual=rows(root);before=p['before'];changed=set(p['before_bodies']);added=set(p['added']);need(len(before)==581 and set(actual)==set(before)|added and{n for n in before if actual[n]!=before[n]}==changed,'complete581 source inverse/current closed membership');need(all(actual[n]==w for n,w in p['helpers'].items()),'every new/changed finite implementation body');old_guard=base64.b64decode(p['before_bodies'][p['guard']],validate=True).decode();need((root/p['guard']).read_text()==old_guard+MARKER+guard_footer(name,want),'whole old source guard held with one mandatory finite appendix')
 for n,edits in p['edits'].items():
  current=(root/n).read_text().splitlines(keepends=True);old=base64.b64decode(p['before_bodies'][n],validate=True).decode()
  for edit in reversed(edits):
   start,end=edit['new_lines'];need(''.join(current[start:end])==edit['after'],'exact finite changed source operand');current[start:end]=edit['before'].splitlines(keepends=True)
  need(''.join(current)==old,'whole original body outside explicitly recorded source edits')
 mf=json.loads((root/p['manifest']).read_bytes());need(mf['status']=='SOURCE_ONLY_NATIVE607_SIX_TOOLS_NOT_ACCEPTED'and all(mf[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance'))and mf['files']=={n:w for n,w in actual.items()if n not in{p['manifest'],*p['workflows']}},'complete new source manifest and no actual authority')
 pub=p['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='f48ea6b72a640e64815430eb2b1967bcf3bfb43a',ref='codex/current607-apps8-composition-v1',files=581,git_joins=581,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['source_authorization']==before and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=before),'genuine complete581 Root source/Git context')
 decision=p['parent_decision'];need(pin(enc(decision))==p['parent_decision_pin']and decision['status']=='ROOT_ACCEPTED_FINITE_NATIVE_APPS8_FIVE_TOOL_SOFTWARE_COMPOSITION'and decision['source']==pub['source']and decision['run_id']==39747308645 and decision['software_scope']['transactions']==25 and decision['software_scope']['fresh_graphs']==51 and decision['software_scope']['fresh_auxiliary_observations']==26,'whole finite prior five-tool acceptance, no new credit')
 import next_inputs as N,next_workflow as W
 N.profile();N.qualification();setup=json.loads((root/'latest/implementation/next-setup-source.json').read_bytes());need(setup['source']=='ed4fb355ff939bf269905592ba5d71517ffab373'and len(setup['files'])==698 and setup['publication']['source']==setup['git']['source']==setup['source']and setup['git']['files']==setup['files']and setup['decision']['run']==39742794397 and setup['decision']['real240_suites']==4,'complete accepted698 real-module source authority')
 for n,w in setup['copied_setup240'].items():need(actual['next/setup240/'+n]==w==setup['files']['setup240/'+n],'whole240 accepted installed/real-recovery source held')
 for n,w in setup['copied_ordinary'].items():need(actual['next/ordinary/'+n]==w==setup['files']['real606/'+n],'whole unchanged native ordinary uid/capability/NNP entry')
 need(len(setup['copied_setup240'])==240 and len(setup['copied_ordinary'])==4,'no partial real module source')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with parent(root,p)as(old,bodies):
   for n in p['workflows']:
    text=bodies[n]
    for stamp in(p['manifest'],'latest/implementation/latest_run.py'):need(text.count(before[stamp]['sha256'].encode())==1,'one complete checksum stamp');text=text.replace(before[stamp]['sha256'].encode(),actual[stamp]['sha256'].encode(),1)
    need(W.derive(text.decode()).encode()==(root/n).read_bytes(),'whole actual workflow outside exact five inputs/test entry/stamps')
   need((root/p['workflows'][0]).read_bytes()==(root/p['workflows'][1]).read_bytes(),'all registered/named aliases byte-identical')
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str((old/p['guard']).parent));s=importlib.util.spec_from_file_location('_whole_accepted581_source_guard',old/p['guard']);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);fact=m.verify();need(fact['files']==581,'whole accepted581 source gate completed')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 import latest_plan as P
 return dict(status='SOURCE_ONLY_NATIVE607_SIX_TOOLS_NOT_ACCEPTED',parent_source_guard=fact,files=len(actual),profile='NATIVE607_SIX_TOOLS_APPS10_WELCOME8_SETUP6_DOCTOR2_KSM2_BOOT1',parent_source=pub['source'],parent_run=39747308645,selected_existing=5,physically_protected=601,transactions=P.TRANSACTIONS,fresh_graphs=P.GRAPHS,auxiliary=P.AUXILIARY,whole_real240_suites=4,bounds=P.BOUNDS,Apps10_current606='UNBOUND_BEFORE_ACTORS'if N.profile()['apps10_current606']is None else'ISSUED_INPUT_ONLY_FRESH_PUBLIC15_PROOF_BEFORE_ACTORS',actual=None,hardware='NOT_RUN',GUI='NOT_RUN',release='NOT_ADMITTED')

def public_checkouts(api,packets,*,apps8_packet,extra_packets):
 api['authorize']();I=api['module']('_next_source_input_api',api['HERE']/'latest_inputs.py');G=api['original']();checks=api['module']('_next_whole_original_package_inspector',api['BASE']/'held606/held-tools/scripts/checks/package_checks.py');S=api['S'];need(set(packets)==set(S.PACKETS),'all five original public packet operands')
 import subprocess
 for role,path in packets.items():
  p=subprocess.run(['git','-C',str(path),'rev-parse','HEAD'],capture_output=True,text=True,timeout=15,check=True);need(p.stdout.strip()==S.PACKETS[role]['source'],'every original immutable carrier still held')
 return I.inspect(api['ROOT'],api['BASE'],packets,G,checks,apps8_packet=apps8_packet,extra_packets=extra_packets)
