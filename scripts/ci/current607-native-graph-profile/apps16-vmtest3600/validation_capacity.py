# SPDX-License-Identifier: MIT
"""Closed VM TEST allowance; unchanged shared deadline and complete source849 guard."""
import base64,contextlib,importlib.util,json,sys,tempfile
from pathlib import Path
import installed_codec_successor as O
pin,enc,rows,need=O.pin,O.enc,O.rows,O.need
MARKER='\n# BEGIN_EXPLICIT_VM_TEST_COMPONENT3600\n'
BOUNDS=dict(consumer=4200,owner=6600,component=3600,transaction=90,fixture=100,real_module_suite=240,cleanup=60)
PROFILE=dict(name='NATIVE607_APPS16_VM_TEST_COMPONENT3600_V1',kind='VM_VALIDATION_TEST_CAPACITY_ONLY',bounds=BOUNDS,shared_component_deadline='ONE_MONOTONIC_START_PLUS3600_SAME_VALUE_FOR_ALL65_FULL_GRAPHS_AND_ACTIONS_NO_RESET',old2400_fit='NOT_ESTABLISHED',outer4200_fit='NOT_ESTABLISHED',owner6600_fit='NOT_ESTABLISHED',numeric_outer_consumer_difference=600,consumer_difference_is_guaranteed_margin=False,performance='NOT_CLAIMED',M2_performance='NOT_RUN',native='NOT_RUN',release='NOT_ADMITTED')
def footer(name,want):return 'def verify():\n import validation_capacity\n return validation_capacity.verify(ROOT, '+repr(name)+', '+repr(want)+')\n'
@contextlib.contextmanager
def parent(root,p):
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in p['before_bodies']else(Path(root)/n).read_bytes()for n in p['before']};need({n:pin(b)for n,b in bodies.items()}==p['before'],'entire original849 source inverse')
 with tempfile.TemporaryDirectory(prefix='six-vmtest-whole849-')as td:
  old=Path(td)/'source';old.mkdir()
  for n,b in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
  need(rows(old)==p['before'],'whole physical original849 source context');yield old,bodies

def inspect(root,name,want):
 root=Path(root);raw=(root/name).read_bytes();need(pin(raw)==want and not sys.flags.optimize,'hardpinned finite VM TEST capacity proof');p=json.loads(raw);actual=rows(root);before=p['before'];changed=set(p['before_bodies']);added=set(p['added']);need(len(before)==849 and len(actual)==853 and set(actual)==set(before)|added and{n for n in before if actual[n]!=before[n]}==changed and all(actual[n]==w for n,w in p['helpers'].items()),'closed source853 whole849 held/helper/changed maps');need(all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'all new actual selectors NULL')
 profile=json.loads((root/p['profile']).read_bytes());need(profile==PROFILE and p['profile_value']==PROFILE,'fixed3600 VM TEST profile with honest whole-fit UNKNOWN');import latest_plan as P,latest_graph_timing as T
 need(P.BOUNDS==BOUNDS and(P.TRANSACTIONS,P.GRAPHS,P.AUXILIARY,len(P.REAL_PHASES))==(32,65,33,4)and T.PROFILE=='LATEST607_FRESH_GRAPH_TIMING_VMTEST3600_DATA_V1','all unchanged work and clocks except explicit shared component allowance')
 pub=p['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='c64cee1167d2ff81f1de0128f57c275819e32868',ref='codex/apps16-six-tool-composition-v1',files=849,git_joins=849,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=p['known_parent'])and p['source_authorization']==p['known_parent'],'whole genuine source849 publication/Git joins')
 need(before==(p['null_parent']if p['null']else p['known_parent'])and len(p['known_parent'])==len(p['null_parent'])==849,'exact frozen known/NULL parent choices; NULL never current publication authority')
 failure=p['failure_post'];diagnosis=p['failure_diagnosis'];need(pin(enc(failure))==p['failure_post_pin']and pin(enc(diagnosis))==p['failure_diagnosis_pin']and failure['status']=='PASS_COMPLETE_SOURCE849_READER2439_ONCE_ORIGINALS_FAILURE_DATA_AND_OLD_REFUSAL_POSTJOINS'and failure['source']==pub['source']and failure['run']==40177365810 and failure['source_files']==p['known_parent']and(len(failure['reader_files']),len(failure['originals']),len(failure['failure']))==(2439,985,966)and failure['collector']['exit']==failure['failure_reader']['exit']==0 and failure['collector']['cap']==failure['failure_reader']['cap']==900,'whole qualified prior failure custody only, no acceptance transfer');need(diagnosis['status']=='AUTHENTIC_SOURCE849_BOUND_SHARED_COMPONENT_DEADLINE_FAILURE_DATA_ONLY'and diagnosis['run_id']==failure['run']and diagnosis['native_acceptance']is diagnosis['cleanup_acceptance']is False and diagnosis['exact_failure']['complete_graphs']==56 and diagnosis['exact_failure']['failed_sequence']==56 and diagnosis['exact_failure']['component_cap']==2400,'prior2400 failure remains failure')
 mf=json.loads((root/p['manifest']).read_bytes());need(mf['files']=={n:w for n,w in actual.items()if n not in{p['manifest'],*p['workflows']}}and mf['VM_TEST_capacity']==PROFILE,'whole new source manifest and explicit TEST-only metadata');return p,actual,mf

def verify(root,name,want):
 root=Path(root);p,actual,mf=inspect(root,name,want);saved,paths=dict(sys.modules),sys.path[:]
 try:
  with parent(root,p)as(old,bodies):
   for n,edits in p['edits'].items():
    text=(root/n).read_text()
    for a,b in reversed(edits):need(text.count(b)==1,'one counted shared3600 profile seam');text=text.replace(b,a,1)
    need(text.encode()==bodies[n],'entire old runtime predicate outside explicit TEST capacity seam')
   need((root/p['guard']).read_bytes()==bodies[p['guard']]+MARKER.encode()+footer(name,want).encode(),'whole original849 guard plus mandatory capacity appendix')
   restored=dict(mf,files={n:w for n,w in mf['files'].items()if n not in p['added']});restored.pop('VM_TEST_capacity')
   for n in p['before_bodies']:
    if n not in{p['manifest'],*p['workflows']}:restored['files'][n]=p['before'][n]
   need(enc(restored)==bodies[p['manifest']],'whole original849 manifest inverse')
   for n in p['workflows']:need((root/n).read_bytes().replace(actual[p['manifest']]['sha256'].encode(),p['before'][p['manifest']]['sha256'].encode())==bodies[n],'entire original workflow/security/outer clock body held except manifest stamp')
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str(old/'latest/implementation'));s=importlib.util.spec_from_file_location('_whole_original849_vmtest_guard',old/p['guard']);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);fact=m.verify();need(fact['files']==849,'whole original849/842/840/838/581 security/source guard mandatory')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,files=len(actual),profile=PROFILE['name'],bounds=BOUNDS,parent849=fact,old2400_fit='NOT_ESTABLISHED',outer4200_fit='NOT_ESTABLISHED',owner6600_fit='NOT_ESTABLISHED',performance='NOT_CLAIMED',M2_performance='NOT_RUN',actual=None)
