#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Actual selected-cleanup matrix; original owner/source/copy/teardown remain held."""
import os,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
SOURCE=Path('/source');WORK=Path('/work');OUT=Path('/out')
H=C.load('original_apps_lifecycle',C.HERE.parent/'apps-full574-native/lifecycle.py')

def args_request(argv,orphan_plan):
 values={};parts=argv[5:];i=0
 while i<len(parts):
  key=parts[i];C.need(key.startswith('--'),'original backend argv protocol');i+=1;name=key[2:].replace('-','_')
  if name=='confirm_disposable_transaction':values[name]=True
  elif name=='applications':
   names=[]
   while i<len(parts) and not parts[i].startswith('--'):names.append(parts[i]);i+=1
   C.need(names==['cache'],'only exact signed Cache catalog request');values[name]=names
  else:values[name]=parts[i];i+=1
 values.update(selected=['cachy-asahi-cache'],orphan_plan=str(orphan_plan),orphan_plan_sha256=C.sha(C.read(orphan_plan,16*1024**2)))
 return values

def invoke(calls,value,label,expected=0):
 path=WORK/(label+'-request.json');C.need(not path.exists(),'fresh private request');path.write_bytes(C.encoded(value));path.chmod(0o600)
 argv=['/usr/bin/python3','-I','-B','/source/scripts/orphans/selected.py','--request',str(path),'--request-sha256',C.sha(C.read(path))]
 return calls.call(argv,expected=expected),argv

def main():
 C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_APPS574_LIFECYCLE')=='1' and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'original native isolated actor only')
 C.source(SOURCE);os.chown(WORK,0,0);WORK.chmod(0o700);T=C.load('original_apps_transaction',SOURCE/'scripts/apps/transaction.py');adapter=C.adapter(SOURCE);calls=H.Calls()
 before=adapter.measure(Path('/seed'),T.limits());source_sha=T.sha(T.encoded(before['nodes']));caps=adapter.capability_map(Path('/seed'),before,T.limits());cap_sha=adapter.digest(caps)
 value=dict(status='FAIL',hardware='NOT_RUN',rollback='NOT_CLAIMED',source_tree_sha256=source_sha,source_capabilities_sha256=cap_sha)
 try:
  workspace=WORK/('interrupted' if '--interrupt' in sys.argv else 'main');prepared=calls.call([*H.backend('prepare-copy',workspace),'--source','/seed']);C.need(prepared['status']=='OWNED_COPY_PREPARED','original genuine copy required');owner=prepared['ownership_sha256'];H.retain_copy(workspace,owner)
  path,plan=H.planned(calls,workspace,'interrupted-install' if '--interrupt' in sys.argv else 'install','install',['cache']);install=H.apply_args(calls,workspace,owner,path,plan);install[3]='/source/'+C.LANE+'/install_dependency.py';installed=calls.call(install)
  C.need(installed['status']=='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION' and installed['prepared_add']=={'cachy-asahi-cache':'0.2.0-1','cachy-asahi-repository-runtime':'0.1.0-1'},'actual exact signed Cache+Runtime install required')
  assessment=WORK/(workspace.name+'-cleanup-assessment.json');readonly='/source/packages/tools/cachy-asahi-orphans/cachy-asahi-orphans'
  published=calls.call(['/usr/bin/python3','-I','-B',readonly,'assess','--root',str(workspace/'root'),'--dbpath',str(workspace/'root/var/lib/pacman'),'--output',str(assessment)],seconds=45)
  assessment_raw=C.read(assessment,4*1024**2);C.need(published['status']=='NOT_APPLIED' and published['sha256']==C.sha(assessment_raw),'original complete assessment publication required');observed=C.decode(assessment_raw)
  cache=observed['packages']['cachy-asahi-cache'];runtime=observed['packages']['cachy-asahi-repository-runtime']
  C.need(cache['reason']=='dependency' and cache['candidate'] is True and not cache['required_by'] and not cache['optional_required_by'] and runtime['reason']=='dependency' and runtime['required_by']==['cachy-asahi-cache'],'actual public ALLDEPS reason/leaf/Runtime-needed readback required')
  orphan_plan=WORK/(workspace.name+'-cleanup-orphan-plan.json');calls.call(['/usr/bin/python3','-I','-B',readonly,'plan',str(assessment),'--select','cachy-asahi-cache','--output',str(orphan_plan)],seconds=45)
  # Original inventory publication names stay finite and outside mutation root.
  path,plan=H.planned(calls,workspace,'remove-selected','remove',['cache']);argv=H.apply_args(calls,workspace,owner,path,plan);selected=args_request(argv,orphan_plan)
  C.save(OUT/'assessment.json',observed);(OUT/'orphan-plan.json').write_bytes(C.read(orphan_plan,16*1024**2))
  if '--interrupt' in sys.argv:
   request_path=WORK/'interruption-request.json';request_path.write_bytes(C.encoded(selected));request_path.chmod(0o600)
   command=['/usr/bin/python3','-I','-B','/source/scripts/orphans/selected.py','--request',str(request_path),'--request-sha256',C.sha(C.read(request_path))]
   interrupted=H.interrupted(calls,workspace,owner,command);state=adapter.measure(workspace/'root',T.limits());adapter.capability_map(workspace/'root',state,T.limits(),caps);interrupted.update(security_capabilities='EXACT_SOURCE_MAP_PRESERVED_AFTER_GROUP_ABSENCE',source_capabilities_sha256=cap_sha);C.save(OUT/'interruption.json',interrupted);return
  before_cases=calls.call(H.backend('inspect',workspace,owner))['before'];cases={}
  noop=dict(selected,selected=[]);cases['noop'],_=invoke(calls,noop,'noop');C.need(cases['noop']['status']=='NOT_APPLIED_NO_SELECTION','no-op must not transact')
  # Native callback executes no mutation and uses the exact original backend guards.
  cancel=SOURCE/C.LANE/'cancel.py';cancel_request=WORK/'cancel-request.json';cancel_request.write_bytes(C.encoded(selected));cancel_request.chmod(0o600)
  cases['cancel']=calls.call(['/usr/bin/python3','-I','-B',cancel,'--request',str(cancel_request),'--request-sha256',C.sha(C.read(cancel_request))]);C.need(cases['cancel']['status']=='CANCELLED_NOT_APPLIED','explicit operator cancellation required')
  lock=types.ModuleType('original_cache_lock');lock.__file__=str(SOURCE/'packages/tools/cachy-asahi-cache/cachy-asahi-cache');exec(compile(C.read(Path(lock.__file__)),lock.__file__,'exec'),lock.__dict__);held=lock.AlpmLock(str(workspace/'root'),workspace/'root/var/lib/pacman');held.acquire()
  try:cases['foreign_lock'],_=invoke(calls,selected,'foreign-lock',1);held.check();C.need(cases['foreign_lock']['status']=='FAIL','foreign lock must refuse')
  finally:held.release()
  after_cases=calls.call(H.backend('inspect',workspace,owner))['before'];C.need(after_cases==before_cases and not (workspace/'apps-pending.json').exists(),'noop/cancel/foreign-lock changed complete copied root or started transaction')
  cases['normal'],_=invoke(calls,selected,'normal');C.need(cases['normal']['status']=='PASS_SELECTED_CATALOG_ORPHAN_REMOVAL_IN_OWNED_COPY' and cases['normal']['prepared_add']=={} and cases['normal']['prepared_remove']=={'cachy-asahi-cache':'0.2.0-1'},'exact selected normal removal required')
  after_normal=calls.call(H.backend('inspect',workspace,owner))['before'];cases['stale'],_=invoke(calls,selected,'stale',1);after_stale=calls.call(H.backend('inspect',workspace,owner))['before'];C.need(cases['stale']['status']=='FAIL' and after_stale==after_normal and not (workspace/'apps-pending.json').exists(),'stale saved plan must refuse without any copied-root changes or transaction marker')
  rows=H.count(workspace);C.need(len(rows)==575 and 'cachy-asahi-cache' not in rows and rows['cachy-asahi-repository-runtime']=='0.1.0-1','unselected now-orphan Runtime must remain; no recursive cleanup')
  disposed=calls.call(H.backend('dispose-copy',workspace,owner),seconds=75);C.need(disposed['status']=='OWNED_COPY_DISPOSED','explicit original owner disposal required')
  after=adapter.measure(Path('/seed'),T.limits());adapter.capability_map(Path('/seed'),after,T.limits(),caps);C.need(T.sha(T.encoded(after['nodes']))==source_sha,'readonly source changed')
  value.update(status='PASS_NATIVE574_SELECTED_ORPHAN_CLEANUP',base_count=574,counts=[576,575],transactions=[installed,cases['normal']],cases=cases,case_preservation=dict(noop_cancel_foreign=dict(before=before_cases,after=after_cases),stale=dict(before=after_normal,after=after_stale),qualification='FULL_ROOT_DIGEST_EQUALITY_NOT_COMMIT_EVENT_PROOF'),actual_reason_graph=observed['packages'],selected=['cachy-asahi-cache'],dependency_reason_readback='ACTUAL_PUBLIC_ALPM_ALLDEPS_AND_ORPHANS2_GRAPH',source_preserved=True,user_trust_protected_preserved=True,workspaces_disposed=True,security_capabilities='EXACT_SOURCE_MAP_PRESERVED',interrupted_copy='NOT_RUN_SEPARATE_ACTOR_REQUIRED')
  C.result(value)
 except BaseException as error:value.update(error_type=type(error).__name__,error=str(error)[:1024]);raise
 finally:
  C.save(OUT/'lifecycle.json',value)
  for p in OUT.iterdir():
   if p.is_file() and not p.is_symlink():os.chown(p,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
if __name__=='__main__':main()
