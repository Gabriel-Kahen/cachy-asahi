# SPDX-License-Identifier: MIT
"""Private live ingress facade; original574 and historical APIs stay byte-exact."""
import base64,contextlib,hashlib,importlib.util,json,shutil,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location('_fresh_live_consumer',HERE/'fresh_consumer.py');V=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(V)
ROLE=Path('scripts/ci/welcome5-native-gui')

def copy_function(fn,space):
 value=types.FunctionType(fn.__code__,space,fn.__name__,fn.__defaults__,fn.__closure__);value.__kwdefaults__=fn.__kwdefaults__;return value
def module_copy(module):
 result=types.ModuleType('_fresh_live_'+module.__name__);space=vars(result);space.update(vars(module))
 for name,value in tuple(space.items()):
  if isinstance(value,types.FunctionType)and value.__globals__ is vars(module):space[name]=copy_function(value,space)
 return result
@contextlib.contextmanager
def imports():
 before=dict(sys.modules);paths=sys.path[:]
 try:yield
 finally:
  sys.path[:]=paths
  for name in set(sys.modules)-set(before):sys.modules.pop(name,None)
  sys.modules.update(before)
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def source_root(source):
 source=V.canonical(source);V.need(source==HERE.parent/'parent574/original','fixed live consumer/original source geometry');return source
def selection(source):
 source_root(source);p=V.policy();b=p['binding']
 # Structural only: cleanup/binding/retention remain usable after key expiry.
 return dict(schema_version=1,status='ROOT_SELECTED_CURRENT_TEST_SIGNATURES',carrier_source=b['carrier_source'],carrier_ref=b['carrier_ref'],index_pin=b['index_pin'],actual_source=None,actual_ref=None,minimal_run=None,overlay_run=None)
def workflow_transform(raw,binding):
 text=raw.decode();seams=[]
 def change(a,b,count=1):
  nonlocal text
  V.need(text.count(a)==count,'exact finite fresh/historical workflow seam');text=text.replace(a,b);seams.append(dict(before=a,after=b,count=count))
 anchor='      -\n        "name": "Checkout exact original GUI TEST signature overlay"'
 checkout='      - name: Checkout Root-selected fresh public TEST signing inputs\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        timeout-minutes: 2\n        with:\n          ref: '+binding['carrier_source']+'\n          path: fresh-test-signatures\n          persist-credentials: false\n'
 change(anchor,checkout+anchor)
 old='--renewal \\"$GITHUB_WORKSPACE/test-renewal\\"';new='--renewal \\"$GITHUB_WORKSPACE/fresh-test-signatures\\"';change(old,new)
 anchor='      - name: Fixed607 build boundary and early owned retirement controls before secrets'
 command='python3 -I -B gui607-source/implementation/fresh_adaptation.py --stage-historical --source "$GITHUB_WORKSPACE/gui607-source" --public "$GITHUB_WORKSPACE/held-public" --project "$GITHUB_WORKSPACE/project-public" --renewal "$GITHUB_WORKSPACE/test-renewal" --output "$RUNNER_TEMP/gui607-historical-source-assets"'
 stage='      - name: Stage exact historical DATA for all inherited Source controls\n        timeout-minutes: 3\n        run: '+command+'\n'
 change(anchor,stage+anchor)
 for name in('test_runner_context.py','test_observer.py'):
  a='gui607-source/implementation/'+name+' --assets "$RUNNER_TEMP/welcome5-assets"';change(a,a.replace('welcome5-assets','gui607-historical-source-assets'))
 a='--public "$RUNNER_TEMP/six991-inputs" --assets "$RUNNER_TEMP/welcome5-assets"';change(a,a.replace('welcome5-assets','gui607-historical-source-assets'))
 a='gui607-source/implementation/historical_source.py legacy-source-tests --source \\"$GITHUB_WORKSPACE/gui607-source\\" --assets \\"$RUNNER_TEMP/welcome5-assets\\"';change(a,a.replace('historical_source.py legacy-source-tests','fresh_adaptation.py --legacy-source-tests').replace('welcome5-assets','gui607-historical-source-assets'))
 a='"WELCOME5_GUI_ASSETS": "${{ runner.temp }}/welcome5-assets"';change(a,a.replace('welcome5-assets','gui607-historical-source-assets'))
 return text.encode(),seams
def workflow(raw):return workflow_transform(raw,V.policy()['binding'])
def packet_operands(carrier,p):
 root=V.canonical(carrier);b=p['binding'];return root if b['packet_path']=='.'else root/b['packet_path'],None,None
def _copy(root,name,want,destination):
 raw=V.checked(root,name,want);path=destination/name;V.need(not path.exists(),'fresh explicit public DATA copy');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644)
def verify_staged(source,assets):
 source_root(source);p=V.policy();root=V.canonical(assets)/'renewal';V.need(V.obj(V.read(root/'_consumer_binding.json'))==p,'exact Source-selected fresh binding in staged assets');plan,schema=V.contract();b=p['binding'];packet=root/'packet'
 index=V.obj(V.checked(packet,'index.json',b['index_pin']));files={'_consumer_binding.json':V.pin(V.enc(p))};public=dict(index['files'],**{'index.json':b['index_pin']});public.update(V.obj(base64.b64decode(schema['qualified_evidence']['publication_authorization'],validate=True))['files'])
 files.update({'packet/'+n:w for n,w in public.items()})
 for name in('native73','held77'):files.update({'_consumer_originals/'+name+'/'+n:w for n,w in plan['carriers'][name]['files'].items()})
 V.closed(root,files)
 return V.verify(packet,None,None,{name:root/'_consumer_originals'/name for name in('native73','held77')},selected=p)
def copy_staged(source,carrier,public,project,assets):
 source_root(source);p=V.policy();b=p['binding'];packet,qualification,context=packet_operands(carrier,p);plan,schema=V.contract();root=assets/'renewal';V.need(not root.exists(),'fresh new-signature DATA directory');root.mkdir(mode=0o700)
 files=V.obj(base64.b64decode(schema['qualified_evidence']['publication_authorization'],validate=True))['files']
 for name,want in files.items():_copy(packet,name,want,root/'packet')
 for name,original in [('held77',public),('native73',project)]:
  for leaf,want in plan['carriers'][name]['files'].items():_copy(original,leaf,want,root/'_consumer_originals'/name)
 (root/'_consumer_binding.json').write_bytes(V.enc(p));(root/'_consumer_binding.json').chmod(0o644)
 return verify_staged(source,assets)
def renewal(original,source):
 source=source_root(source);result=module_copy(original);space=vars(result);b=V.policy()['binding'];space.update(CARRIER=b['carrier_source'],REF=b['carrier_ref'],INDEX=b['index_pin'],SIGNER=b['fingerprint'])
 space['selection']=lambda supplied:selection(supplied)
 def overlay(root):
  root=V.canonical(root);fact=verify_staged(source,root.parent);return dict(V.obj(V.read(root/'packet/index.json')),consumer_verification=fact)
 def apply(supplied,assets,output,lock):
  V.need(source_root(supplied)==source,'fixed live renewal source');fact=verify_staged(source,assets);p=V.policy();b=p['binding'];packet=V.canonical(assets)/'renewal/packet';plan,_=V.contract();rows={r['role']:r for r in plan['documents']if r['role']in V.ARCHIVES};V.need(set(rows)=={'welcome5','dns2','doctor','orphans'},'four archive applications only; metadata signatures are not archives')
  for role,row in rows.items():
   archive=output/Path(row['path']).name;V.need(V.pin(V.read(archive,32*1024**2))=={k:row[k]for k in('bytes','sha256')},'fresh signature cannot substitute original archive body');shutil.copyfile(packet/row['signature_path'],output/(archive.name+'.sig'))
  for name in('welcome5-TEST.asc','TEST-public.asc'):shutil.copyfile(packet/'public-key.asc',output/name)
  (output/'control.json').write_bytes(V.enc(dict(signer=b['fingerprint'])));(output/'trust.json').write_bytes(V.enc([dict(key='welcome5-TEST.asc',signer=b['fingerprint'])]));(output/'test-signature-renewal.json').write_bytes(V.enc(fact));return lock
 space.update(overlay=overlay,apply=apply);return result
def candidates(original,source):
 source=source_root(source);result=module_copy(original);space=vars(result);prior_load=result.load;renewal_path=source/ROLE/'renewal.py';R=renewal(prior_load('_fresh_live_original_renewal',renewal_path),source)
 def candidate_load(name,path):
  if V.canonical(path)==renewal_path:return R
  return prior_load(name,path)
 space['load']=candidate_load;stage=result.stage
 def live_stage(supplied,assets,output):
  V.need(source_root(supplied)==source,'fixed live candidate source');verify_staged(source,assets)
  with imports():return stage(supplied,assets,output)
 space['stage']=live_stage;return result
def assets(original,source,C):
 source=source_root(source);result=module_copy(original);vars(result)['C']=C
 def prepare(supplied,public,project,out,carrier=None):
  V.need(source_root(supplied)==source,'fixed live asset source');policy=C.selection(source);p=V.policy();b=p['binding'];V.need(carrier is not None and not out.exists(),'explicit selected fresh carrier and fresh assets');selected=list(policy['inputs'].values());V.need(len({(r['carrier_source'],r['carrier_ref'],r['index_path'],r['index_pin']['sha256'])for r in selected})==1,'original single native pair carrier')
  original.revision(carrier,b['carrier_source']);original.revision(public,original.PUBLIC);original.revision(project,selected[0]['carrier_source']);packet,qualification,context=packet_operands(carrier,p)
  # Authenticate every original body and the seventh, new catalog before output.
  fact=V.verify(packet,qualification,context,dict(native73=project,held77=public),selected=p)
  with imports():value=result.assemble_data(source,public/'payload',project/'payload',out,policy,None)
  copied=copy_staged(source,carrier,public,project,out);V.need(copied==fact,'same exact Root-selected signing packet before/after ordinary DATA staging')
  return dict(value,status='PREPARED_FRESH_PUBLIC_TEST_SIGNED_NATIVE_INPUTS_ONLY',fresh_signatures=fact,new_carrier=selected[0]['carrier_source'])
 vars(result)['prepare']=prepare;return result
def job(original,source):
 source=source_root(source);selection(source)
 with imports():
  result=module_copy(original);C=candidates(load('_fresh_live_job_candidates',source/ROLE/'candidates.py'),source);vars(result).update(C=C,assets=assets(original.assets,source,C))
  for name in('prove','binding'):
   fn=getattr(result,name)
   def isolated(*args,_fn=fn,**kwargs):
    with imports():return _fn(*args,**kwargs)
   setattr(result,name,isolated)
 return result
def factory(original,source):
 source=source_root(source);selection(source);result=module_copy(original);space=vars(result);base_load=result.load;held_path=source/ROLE/'prepare.py';base_prepare=result.prepare_code
 def factory_load(name,path):
  if V.canonical(path)!=held_path:return base_load(name,path)
  held=module_copy(base_load('_fresh_live_original_prepare',held_path));C=candidates(base_load('_fresh_live_original_candidates',source/ROLE/'candidates.py'),source);vars(held)['A']=C;vars(held)['D']=base_load('_fresh_live_original_derive',source/ROLE/'derive.py');return held
 space['load']=factory_load
 def prepare_code(supplied,assets,out,profile,mode):
  V.need(source_root(supplied)==source,'fixed live factory source');fact=verify_staged(source,assets)
  with imports():value=base_prepare(supplied,assets,out,profile,mode)
  (out/'fresh-test-signing.json').write_bytes(V.enc(fact));return value
 space['prepare_code']=prepare_code
 V.need(space['emit'].__globals__ is space and base_prepare.__globals__ is space and space['service1800'].__globals__ is space,'actual executing factory globals bind live ingress before unchanged service/observer facades');return result
def stage_historical(source,public,project,renewal_root,output):
 """Separate exact old DATA for inherited SOURCE tests, never live authority."""
 import subprocess
 from unittest.mock import patch
 source=V.canonical(source);V.need(source==HERE.parent,'fixed complete fresh consumer Source');original=source_root(source/'parent574/original');output=V.canonical(output);V.need(not output.exists(),'fresh separate historical Source assets')
 with imports():
  sys.path.insert(0,str(HERE))
  G=load('_fresh_historical_source_guard',HERE/'source_guard.py');G.verify()
  C=load('_fresh_historical_candidates',original/ROLE/'candidates.py');sys.modules['candidates']=C;A=load('_fresh_historical_assets',original/ROLE/'assets.py');A.C=C;R=load('_fresh_historical_renewal',original/ROLE/'renewal.py');H=load('_fresh_historical_api',HERE/'historical_source.py');policy=C.selection(original)
  with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS_SOURCE_ONLY')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_SOURCE_ONLY')):
   A.assemble_data(original,V.canonical(public)/'payload',V.canonical(project)/'payload',output,policy,None);overlay=H.historical_overlay(R,V.canonical(renewal_root))
   target=output/'renewal';target.mkdir(mode=0o700)
   for name,w in dict(overlay['files'],**{'index.json':R.INDEX}).items():_copy(V.canonical(renewal_root),name,w,target)
 return dict(status='EXACT_HISTORICAL_SOURCE_ONLY_NOT_ACTOR_AUTHORITY',actor_ready=False,native_build='NOT_RUN',GUI='NOT_RUN',Root_acceptance=None)
def legacy_source_tests(source,assets):
 """Run the unchanged30 controls on the exact complete693 inverse only."""
 import tempfile
 source=V.canonical(source);assets=V.canonical(assets);V.need(source==HERE.parent,'fixed current Source for legacy inverse controls')
 with imports():
  sys.path.insert(0,str(HERE));G=load('_fresh_legacy_current_guard',HERE/'source_guard.py');G.verify();B=load('_fresh_legacy_complete_inverse',HERE/'build_inventory_guard.py');before=B.fresh_inverse({n:V.read(source/n,16*1024**2)for n in G.table(source)})
 with tempfile.TemporaryDirectory(prefix='fresh-live-exact-legacy693-')as td:
  old=Path(td)/'source';old.mkdir(mode=0o700)
  for name,raw in before.items():path=old/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644)
  H=load('_fresh_legacy_unchanged_worker',old/'implementation/historical_source.py');H.legacy_source_tests(old,assets)
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();mode=p.add_mutually_exclusive_group(required=True);mode.add_argument('--stage-historical',action='store_true');mode.add_argument('--legacy-source-tests',action='store_true');p.add_argument('--source',type=Path,required=True)
 for n in('public','project','renewal','output','assets'):p.add_argument('--'+n,type=Path)
 a=p.parse_args()
 if a.legacy_source_tests:legacy_source_tests(a.source,a.assets)
 else:print(V.enc(stage_historical(a.source,a.public,a.project,a.renewal,a.output)).decode(),end='')
