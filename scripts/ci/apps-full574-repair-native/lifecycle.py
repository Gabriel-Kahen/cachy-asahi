#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Actual signed repairs in the original owned full574 copied-root actor."""
import ast,os,stat,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
SOURCE=Path('/source');WORK=Path('/work');OUT=Path('/out');INPUTS=Path('/inputs')
H=C.load('original_full574_lifecycle',SOURCE/'scripts/ci/apps-full574-native/lifecycle.py');H.C=C
TARGET='usr/share/doc/cachy-asahi-apps/README.md';UNSELECTED='usr/share/doc/cachy-asahi-cache/README.md'

def publish_inventory(path,summary):
 # First retain the exact original successful inventory, then publish ONLY that leaf.
 case=C.case(os.environ.get('CACHY_APPS574_REPAIR_CASE'))
 C.need(path.parent==WORK and path.name in {n+'-inventory.json' for n in ('install',case,'repair-refusals','remove-selected','remove-runtime')},'fixed successful public inventory leaf')
 raw=H.retain_inventory(path,summary);target=OUT/path.name;C.safe(target);before=target.lstat()
 C.need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.geteuid() and stat.S_IMODE(before.st_mode)==0o600 and C.read(target,16*1024**2)==raw,'original successful inventory export identity')
 ids=[os.environ[n] for n in ('OUTPUT_UID','OUTPUT_GID')];C.need(all(x.isdecimal() and 0<int(x)<2**31 for x in ids),'original ordinary host output identities')
 os.chown(target,*map(int,ids));after=target.lstat()
 C.need((after.st_dev,after.st_ino,after.st_nlink,stat.S_IMODE(after.st_mode),after.st_size)==(before.st_dev,before.st_ino,1,0o600,len(raw)) and (after.st_uid,after.st_gid)==tuple(map(int,ids)) and C.read(target,16*1024**2)==raw,'exact inventory ownership publication readback')
 return raw

def planned(calls,workspace,label,operation,names):
 C.need(label in ('install','repair-bytes','repair-missing','repair-refusals','remove-selected','remove-runtime') and workspace==WORK/'main','fixed private repair inventory scope required')
 # Reuse every original inventory read, ownership check, signer and plan assertion.
 raw=C.read(SOURCE/'scripts/ci/apps-full574-native/lifecycle.py').decode();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='planned');body=ast.get_source_segment(raw,node)
 old="('install','remove-selected','remove-runtime','interrupted-install')";C.need(body.count(old)==1,'one original finite inventory-label seam');body=body.replace(old,repr(('install','repair-bytes','repair-missing','repair-refusals','remove-selected','remove-runtime')))
 namespace=dict(vars(H),retain_inventory=publish_inventory);exec(compile(body,str(SOURCE/'scripts/ci/apps-full574-native/lifecycle.py')+':repair-labels','exec'),namespace);return namespace['planned'](calls,workspace,label,operation,names)

def owned(T,workspace,owner):
 C.need(workspace==WORK/'main','fixed owned repair workspace');C.safe(workspace/'root');info=workspace.lstat();raw=C.read(workspace/'apps-copy.json',65536);value=C.decode(raw);C.need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700 and C.sha(raw)==owner and value['token']==os.environ['OWNER_TOKEN'] and value['workspace']==T.inode(workspace) and value['root']==T.inode(workspace/'root') and value['source']=='/seed','original actual copy marker and root/workspace identity required')

def observed(T,adapter,workspace,owner):
 # Read-only preparation of the complete ACTUAL damaged map, not generic inspect
 # or a closure baseline exclusion. The backend authenticates before its own gate.
 owned(T,workspace,owner);value=adapter.measure(workspace/'root',T.limits());app=C.load('repair_inventory_apps',INPUTS/'apps-source/apps.py');client,release,_=app.helpers(INPUTS/'candidate/usr/share/cachy-asahi/repository-runtime');inventory=app.inventory_reader().collect(workspace/'root/var/lib/pacman',client,lambda row:app.package(row,release));C.need(len(inventory['packages'])==578,'actual current four candidates plus original574 required')
 owned(T,workspace,owner);return value,T.pins(value,inventory)

def inspected(T,calls,workspace,owner,path,plan,label):
 C.need(label in ('repair-bytes','repair-missing'),'two closed signed inspection cases');owned(T,workspace,owner)
 args=['/usr/bin/python3','-I','-B',str(SOURCE/'scripts/apps/repair_inspection.py'),'inspect-reinstall',*H.common(workspace,owner),*H.credentials(),'--applications',*plan['plan']['requested_applications'],'--plan',str(path),'--plan-sha256',C.sha(C.read(path))]
 value=calls.call(args) # Original610s caller surrounds normal CLI's600s worker.
 C.save(OUT/(label+'-inspection.json'),value) # Original, unmodified CLI receipt.
 C.load('actual_inspection_checks',Path(__file__).with_name('checks.py')).inspection(C,value,C.sha(C.read(path)))
 owned(T,workspace,owner);return value

def argv(calls,workspace,owner,path,plan,pins):
 return [*H.backend('apply',workspace,owner),*H.credentials(),'--operation',plan['plan']['operation'],'--applications',*plan['plan']['requested_applications'],'--plan',str(path),'--plan-sha256',C.sha(C.read(path)),*[part for key,value in pins.items() for part in ('--before-'+key.replace('_','-'),value)],'--confirm-disposable-transaction']

def leaf(workspace,name):
 C.need(workspace==WORK/'main' and name in (TARGET,UNSELECTED),'fixed owned copy leaf only');path=workspace/'root'/name;C.safe(path);info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o644,'ordinary exact root-owned repair leaf');raw=C.read(path,128*1024);return path,raw,info

def damage(workspace,name,missing=False):
 path,raw,info=leaf(workspace,name)
 if missing:path.unlink()
 else:path.write_bytes(raw+b'\nFULL574-EXPLICIT-REPAIR-FIXTURE\n')
 return path,raw,info

def restore(row):
 path,raw,info=row;C.need(path.is_file() and not path.is_symlink() and path.stat().st_nlink==1,'own damaged leaf restoration only');path.write_bytes(raw);os.chmod(path,stat.S_IMODE(info.st_mode));os.chown(path,info.st_uid,info.st_gid);os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns))

def repaired(value,damage_map):
 C.need(value['status']=='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION' and value['operation']=='reinstall' and value['prepared_add']=={'cachy-asahi-apps':'0.1.0-6'} and value['prepared_remove']=={} and value['commit_started'] is True and value['packages_committed'] is True and value['dependency_checks']=='ORDINARY_LIBALPM','actual selected same-version commit required')
 proof=value['full574_closure']['repair'];C.need(proof['status']=='SELECTED_SIGNED_ORDINARY_LEAVES_RESTORED' and proof['selected']==['cachy-asahi-apps'] and proof['before_damage']==damage_map,'actual original damaged/missing map joined to backend repair required')
 return value

def main():
 case=C.case(os.environ.get('CACHY_APPS574_REPAIR_CASE'))
 C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_APPS574_LIFECYCLE')=='1' and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'original owned native offline actor only');C.source(SOURCE);C.need(Path('/seed').is_mount() and WORK.is_mount(),'original disjoint source/work mounts required');os.chown(WORK,0,0);WORK.chmod(0o700)
 adapter=C.adapter(SOURCE);T=C.load('repair_source_transaction',SOURCE/'scripts/apps/transaction.py');baseline=adapter.measure(Path('/seed'),T.limits());source_sha=adapter.digest(baseline['nodes']);caps=adapter.capability_map(Path('/seed'),baseline,T.limits());caps_sha=adapter.digest(caps);user={n:v for n,v in baseline['nodes'].items() if n.startswith('home/') and v['type'] in ('file','symlink')};C.need(user,'real original user state required');calls=H.Calls();report=dict(status='FAIL',case=case,aggregate='BOTH_INDEPENDENT_ROOT_CASE_DECISIONS_REQUIRED',hardware='NOT_RUN',rollback='NOT_CLAIMED',source_preserved=False,workspaces_disposed=False)
 try:
  workspace=WORK/'main';prepared=calls.call([*H.backend('prepare-copy',workspace),'--source','/seed']);C.need(prepared['status']=='OWNED_COPY_PREPARED' and prepared['source_preserved'] is True,'original exact copy required');owner=prepared['ownership_sha256'];H.retain_copy(workspace,owner)
  path,plan=planned(calls,workspace,'install','install',['apps','cache','orphans']);installed=calls.call(H.apply_args(calls,workspace,owner,path,plan));C.need(installed['prepared_add']==C.VERSIONS,'actual current four native packages required');transactions=[installed];counts=[len(H.count(workspace))];C.need(counts==[578],'actual578 after install required');repairs={};refusals={};preparations={}
  for label,missing in ((case,case=='repair-missing'),):
   path,plan=planned(calls,workspace,label,'reinstall',['apps']);owned(T,workspace,owner);original=damage(workspace,TARGET,missing);preparation=inspected(T,calls,workspace,owner,path,plan,label);pins=preparation['before'];damage_map=preparation['damage'];preparations[label]=preparation
   attempts=argv(calls,workspace,owner,path,plan,pins);refusals[label+'-default-inspect']=calls.call(H.backend('inspect',workspace,owner),expected=1);C.need(refusals[label+'-default-inspect']['status']=='FAIL','default strict inspect must refuse damaged payload');repairs[label]=repaired(calls.call(attempts),damage_map);C.need(C.read(original[0])==original[1] and len(H.count(workspace))==578,'exact original signed leaf restored without inventory expansion')
  path,plan=planned(calls,workspace,'repair-refusals','reinstall',['apps']);before,pins=observed(T,adapter,workspace,owner);attempts=argv(calls,workspace,owner,path,plan,pins);stable_pins=dict(pins);wrong=list(attempts);wrong[wrong.index('--plan-sha256')+1]='0'*64;refusals['wrong-plan-sha']=H.zero(calls.call(wrong,expected=1))
  owned(T,workspace,owner);changed=damage(workspace,UNSELECTED)
  try:
   raw,pins=observed(T,adapter,workspace,owner);bad=argv(calls,workspace,owner,path,plan,pins);refusals['unselected-damage']=H.zero(calls.call(bad,expected=1));C.need(observed(T,adapter,workspace,owner)[1]==pins,'refused transaction changed complete damaged map')
  finally:restore(changed)
  cache=types.ModuleType('repair_actual_cache_lock');cache.__file__='/inputs/candidate/usr/bin/cachy-asahi-cache';exec(compile(C.read(Path(cache.__file__)),cache.__file__,'exec'),cache.__dict__);held=cache.AlpmLock(str(workspace/'root'),workspace/'root/var/lib/pacman');held.acquire()
  try:refusals['foreign-alpm-lock']=H.zero(calls.call(attempts,expected=1));held.check()
  finally:held.release()
  C.need(observed(T,adapter,workspace,owner)[1]==stable_pins,'refusals changed complete restored root')
  for label,names,expected in (('remove-selected',['apps','cache','orphans'],575),('remove-runtime',['runtime'],574)):
   path,plan=planned(calls,workspace,label,'remove',names);transactions.append(calls.call(H.apply_args(calls,workspace,owner,path,plan)));rows=H.count(workspace);counts.append(len(rows));C.need(len(rows)==expected,'actual removal count required')
   if expected==575:C.need(rows.get('cachy-asahi-repository-runtime')=='0.1.0-1','unselected required Runtime retained')
  disposed=calls.call(H.backend('dispose-copy',workspace,owner),seconds=75);C.need(disposed['status']=='OWNED_COPY_DISPOSED' and not workspace.exists(),'original explicit owned copy disposal required');after=adapter.measure(Path('/seed'),T.limits());adapter.capability_map(Path('/seed'),after,T.limits(),caps);C.need(adapter.digest(after['nodes'])==source_sha,'original readonly full source preserved')
  report.update(status='PASS_NATIVE574_AUTHENTICATED_SELECTED_REPAIR_CASE',base_count=574,counts=counts,transactions=transactions,repairs=repairs,refusals=refusals,preparations=preparations,inspection_files={label:C.ref(OUT,OUT/(label+'-inspection.json')) for label in preparations},source_preserved=True,workspaces_disposed=True,user_trust_protected_preserved=True,source_tree_sha256=source_sha,source_capabilities_sha256=caps_sha,security_capabilities='EXACT_SOURCE_MAP_PRESERVED',original_user_nodes=len(user));C.result(report)
 except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:1024]);raise
 finally:
  C.save(OUT/'lifecycle.json',report)
  for p in OUT.iterdir():
   if p.is_file() and not p.is_symlink():os.chown(p,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
if __name__=='__main__':main()
