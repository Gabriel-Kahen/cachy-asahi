#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real signed synthetic reinstall in a fresh mapped offline copy, never host DB."""
import argparse,hashlib,importlib.util,json,os,shutil,sys,tempfile
from pathlib import Path
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
HERE=Path(__file__).resolve().parent
BACKEND=HERE/'transaction.py';APPDIR=HERE.parent.parent/'packages/tools/cachy-asahi-apps'
sys.dont_write_bytecode=True
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value

def child(case):
 T=load('actual_repair_backend',BACKEND)
 a=argparse.Namespace(apps_source=str(APPDIR),apps_provenance_sha256=sha(APPDIR/'source-provenance.json'),repository_source=str(ROOT),workspace=str(case/'owned-copy'),source=str(case/'seed'),ownership_sha256=None,release=str(case/'bundle'),release_sha256=sha(case/'bundle/release.json'),catalog=str(case/'catalog.json'),catalog_sha256=sha(case/'catalog.json'),catalog_signature=str(case/'catalog.json.sig'),keyring=str(case/'public.gpg'),signer=(case/'signer').read_text(),operation='install',applications=['fixture'],confirm_disposable_transaction=True)
 app,c,r=T.app_source(a);prepared=T.prepare_copy(a);a.ownership_sha256=prepared['ownership_sha256'];root=Path(prepared['root']);source_before=T.observe(case/'seed',T.limits())['nodes'];records=[];refusals=[]
 for number,operation in enumerate(('install','reinstall','reinstall','reinstall','remove')):
  if number==1:(root/'usr/share/fixture/config').write_bytes(b'DAMAGED SELECTED FIXTURE\n')
  if number==2:(root/'usr/share/fixture/config').unlink()
  a.operation=operation;inventory=app.inventory_reader().collect(root/T.DB,c,lambda row:app.package(row,r));iv=case/f'inventory-{number}.json';iv.write_bytes(app.encoded(inventory));a.installed=str(iv);a.installed_sha256=sha(iv);a.command='plan';plan=app.execute(a);file=case/f'plan-{number}.json';file.write_bytes(app.encoded(plan));a.plan=str(file);a.plan_sha256=sha(file)
  before=T.observe(root,T.limits());pins=T.pins(before,inventory)
  for key,value in pins.items():setattr(a,'before_'+key,value)
  if operation=='reinstall':
   assert plan['plan']['additions']+plan['plan']['upgrades']+plan['plan']['removals']==[] and len(plan['plan']['reinstalls'])==1
   assert plan['plan']['before_inventory_sha256']==plan['plan']['after_inventory_sha256']
  if number==1:
   damaged_sha=sha(root/'usr/share/fixture/config');original=a.plan_sha256;a.plan_sha256='0'*64;bad=T.apply(a);assert bad['status']=='FAIL' and bad['commit_started'] is False and T.observe(root,T.limits())['nodes']==before['nodes'];a.plan_sha256=original;refusals.append(bad)
   note=root/'home/test/note';held=note.read_bytes();note.write_bytes(b'OWNED TEST DRIFT\n');changed=T.observe(root,T.limits())['nodes'];bad=T.apply(a);assert bad['status']=='FAIL' and bad['commit_started'] is False and T.observe(root,T.limits())['nodes']==changed;note.write_bytes(held);refusals.append(bad)
  argv=[sys.executable,'-I','-B',str(BACKEND),'apply']
  for name in ('workspace','ownership-sha256','apps-source','apps-provenance-sha256','repository-source','release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer','plan','plan-sha256','before-tree-sha256','before-database-sha256','before-packages-sha256','before-inventory-sha256','operation'):argv+=['--'+name,str(getattr(a,name.replace('-','_')))]
  argv+=['--applications','fixture','--confirm-disposable-transaction'];row=T.SUP.run(argv,env=dict(os.environ),cwd=str(ROOT),timeout=90,output_limit=1024**2)
  (case/f'worker-{number}.stdout').write_bytes(row['stdout']);(case/f'worker-{number}.stderr').write_bytes(row['stderr']);result=json.loads(row['stdout']);assert row['returncode']==0 and row['termination'] is None and row['direct_child_reaped'] and result['status']=='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION',(result,row['stderr'].decode());assert result['worker']['direct_child_reaped'] and result['worker']['termination'] is None;assert result['packages_committed'] is True
  if operation=='reinstall':
   assert result['prepared_add']=={'fixture':'1-1'} and result['prepared_remove']=={};assert (root/'usr/share/fixture/config').read_bytes()==b'TEST ONLY\n'
   if number==1:assert sha(root/'usr/share/fixture/config')!=damaged_sha
  assert (root/'usr/share/fixture/config').exists()==(operation!='remove')
  assert (root/'home/test/note').read_bytes()==b'preserved user bytes\n' and (root/'etc/pacman.d/public').read_bytes()==b'preserved base trust\n';assert not (root/T.DB/'db.lck').exists() and not (Path(a.workspace)/'apps-pending.json').exists();records.append(result)
 assert T.observe(case/'seed',T.limits())['nodes']==source_before
 T.dispose(Path(a.workspace),T.inode(Path(a.workspace)));assert not Path(a.workspace).exists()
 value={'status':'PASS_REAL_SIGNED_SYNTHETIC_SAME_VERSION_REPAIR','host_architecture':os.uname().machine,'transactions':records,'refusals':refusals,'damaged_selected_payload_restored':True,'missing_selected_leaf_restored':True,'repeat_reinstall_committed':True,'source_preserved':True,'copied_workspace_absent':True,'host_database':'NOT_ACCESSED','native_aarch64':'NOT_RUN','hardware':'NOT_RUN','trust':'ISOLATED_TEST_AUTHORITY_NOT_PRODUCTION','libalpm':{'path':str(T.I.LIBRARY),'sha256':sha(T.I.LIBRARY)}}
 (case/'result.json').write_bytes(T.encoded(value));print(json.dumps({'status':value['status'],'transactions':len(records),'refusals':len(refusals)}),flush=True)

def outer(output):
 if not output.is_absolute() or output.exists() or any(p.is_symlink() for p in output.parents):raise ValueError('fresh ordinary absolute private output required')
 output.mkdir(mode=0o700);work=Path(tempfile.mkdtemp(prefix='cachy-asahi-apps-repair-'));case=work/'case';case.mkdir(mode=0o700);(output/'private-work.json').write_text(json.dumps({'path':str(work),'status':'OWNED_TEMP_WORK_RETAINED_UNTIL_SUCCESS'})+'\n');fixture=load('actual_repair_fixture',ROOT/'scripts/update/test_snapshot.py');supervisor=load('actual_repair_supervisor',ROOT/'scripts/update/supervision.py')
 with tempfile.TemporaryDirectory(prefix='private-signing-',dir=output) as signing:
  with fixture.signing(Path(signing)/'keys') as (signer,public,sign):
   (case/'public.gpg').write_bytes(public);(case/'signer').write_text(signer);base=[dict(name='platform-fixture',version='1-1',arch='any',depend=[],provides=[],conflict=[],replaces=[],files=['boot/platform-fixture'])];bundle=fixture.make_bundle(case,signer,sign,base_packages=base);catalog=dict(schema_version=1,kind='development-application-catalog',target_arch='aarch64',release_sha256=sha(bundle/'release.json'),repository='fixture',applications=[dict(id='fixture',title='Synthetic fixture',description='Owned disposable repair only',packages=['fixture'])]);(case/'catalog.json').write_bytes(fixture.encoded(catalog));sign(case/'catalog.json')
   seed=case/'seed';local=seed/'var/lib/pacman/local/platform-fixture-1-1';local.mkdir(parents=True);(local.parent/'ALPM_DB_VERSION').write_bytes(b'9\n');(local/'desc').write_bytes(b'%NAME%\nplatform-fixture\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n');(local/'files').write_bytes(b'%FILES%\nboot/platform-fixture\n\n')
   for name,data in [('boot/platform-fixture',b'preserve platform\n'),('home/test/note',b'preserved user bytes\n'),('etc/pacman.conf',b'# preserve config\n'),('etc/pacman.d/public',b'preserved base trust\n')]:
    p=seed/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o644)
   (seed/'usr/share/fixture').mkdir(parents=True);env=dict(PATH='/usr/bin:/bin',HOME=str(case),LC_ALL='C.UTF-8',CACHY_ASAHI_APPS_TRANSACTION='79'*16,PYTHONDONTWRITEBYTECODE='1');argv=['/usr/bin/unshare','--user','--map-root-user','--mount','--net','/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'--child',str(case)];row=supervisor.run(argv,env=env,cwd=str(ROOT),timeout=180,output_limit=1024**2);(output/'stdout.log').write_bytes(row.pop('stdout'));(output/'stderr.log').write_bytes(row.pop('stderr'));(output/'owner.json').write_bytes(fixture.encoded(dict(argv=argv,**row)))
   if row['returncode']!=0 or row['termination'] is not None:raise RuntimeError('owned namespace fixture failed; retained stdout/stderr/owner and private case')
 shutil.copytree(case,output/'case',symlinks=True);shutil.rmtree(work);(output/'private-work.json').write_text(json.dumps({'path':str(work),'status':'REMOVED_AFTER_KNOWN_CHILD_RETIREMENT_AND_COPY_DISPOSAL'})+'\n');print((output/'case/result.json').read_text())
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);p.add_argument('--child',type=Path);a=p.parse_args()
 if a.child:child(a.child)
 elif a.output:outer(a.output)
 else:p.error('explicit fresh --output required')
