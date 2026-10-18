# SPDX-License-Identifier: MIT
"""Four fresh compiled Welcome builders on the held producer574 image."""
import contextlib,importlib.util,json,os,re,shutil,signal,sys
from pathlib import Path
import selection as S

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
@contextlib.contextmanager
def aliases(values):
 previous={k:sys.modules.get(k)for k in values};sys.modules.update(values)
 try:yield
 finally:
  for k,v in previous.items():
   if v is None:sys.modules.pop(k,None)
   else:sys.modules[k]=v

def test_public_key(ready,original,C):
 """Use the original producer's exact public-key row, never a basename guess."""
 roles=original['preparation']['signer_roles'];S.need(type(roles)is dict and set(roles)=={'ephemeral_TEST','upstream_ALARM'}and len(set(roles.values()))==2 and all(type(v)is str and re.fullmatch('[A-F0-9]{40}',v)for v in roles.values()),'two distinct original TEST/upstream signer roles')
 keys=original['keyrings'];S.need(type(keys)is list and len(keys)==2 and all(type(k)is dict and set(k)=={'path','size','sha256'}for k in keys)and {k['path']for k in keys}=={'keys/TEST-public.asc','keys/archlinuxarm.gpg'},'exact original producer public keyring paths')
 row=next(k for k in keys if k['path']=='keys/TEST-public.asc')
 return C.checked(ready,dict(path=row['path'],bytes=row['size'],sha256=row['sha256']),65536)

def welcome(source,output,producer,ready,image,lock,owned,C):
 lane=source/'scripts/ci/welcome5-native-upgrade';spec=load('_closed_welcome_selection',lane/'selection.py');spec.verify_source(source)
 with aliases({'selection':spec}):
  A=load('_closed_welcome_adapter',lane/'adapter.py');contract=A.module(source,'contract.py')
 with aliases({'selection':spec,'adapter':A}):return _welcome(source,output,producer,ready,image,lock,owned,C,spec,A,contract)

def _welcome(source,output,producer,ready,image,lock,owned,C,spec,A,contract):
 shared=A.builder(source,contract)
 checks=load('_closed_welcome_checks',source/'scripts/checks/package_checks.py');sys.path[:0]=[str(source/'scripts/build'),str(source/'scripts/checks')]
 bind=load('_closed_welcome_build',source/'scripts/build/build.py');compare=load('_closed_welcome_compare',source/'scripts/build/compare.py');gate=load('_closed_welcome_pair_gate',source/'scripts/ci/tools-native/run.py');gate.C=contract
 common=load('_closed_welcome_process',source/'scripts/virtual/common.py');plain=shared.docker;shared.docker=lambda *a,**k:owned.launch(plain(*a,**k))
 base=shared.inventory(lock.read_text());S.need(len(base)==574 and contract.digest(lock)==C.BUILDER,'exact held producer574 builder lock')
 work=output/'welcome-builds';work.mkdir(mode=0o700);names=[];products={};pairs={};epoch=json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['source_date_epoch']
 def execute(argv,log,seconds):
  S.need(seconds==240,'unchanged Welcome builder deadline');active=common.LoggedProcess(argv,log,env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC',HOME=str(output/'home')),limit=16*1024**2)
  try:active.process.wait(timeout=seconds);active.finish();S.need(active.process.returncode==0,'compiled Welcome builder failed')
  finally:
   if active.process.poll()is None:
    try:os.killpg(active.process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    active.process.wait(timeout=5)
   active.finish()
 for role in spec.NAMES:
  pair=[shared.build(source,work,base,image,lock,role,side,epoch,execute,names,checks,bind)for side in('a','b')];comparison=compare.compare(*(r['directory']for r in pair));gate.pair_gate(comparison)
  (work/(role+'-comparison.json')).write_bytes(S.encoded(comparison));pairs[role]=dict(comparison=comparison,builders=[r['directory'].name for r in pair],archives=[dict(path=str(r['archive'].relative_to(work)),**S.pin(r['archive'].read_bytes()))for r in pair])
  products[role]=dict(role=role,package_name=spec.PACKAGE,version=spec.policy()['products'][role]['version'],archive=pair[0]['archive'],payload=pair[0]['payload'],elf=pair[0]['elf'],tests=pair[0]['tests'])
 S.need(len(names)==len(set(names))==4,'four distinct compiled Welcome builders')
 context=output/'welcome-inputs';context.mkdir(mode=0o700);roles=C.read(ready/'manifest.json')['preparation']['signer_roles']
 sign=C.scoped_load('_closed_original_TEST_signer',Path(C.HERE).parents[2]/'scripts/ci/expanded600-installer-vm/materializer.py',{'contract':C});archives=[]
 for row in products.values():
  archive=row['archive'];dest=context/archive.name;shutil.copyfile(archive,dest);archives.append(dest);row.update(archive=dest.name,bytes=dest.stat().st_size,sha256=C.sha(dest),signer=roles['ephemeral_TEST'])
 sign.sign(producer/'private/test-signing',archives,roles['ephemeral_TEST'])
 for row in products.values():row.update(signature=row['archive']+'.sig',signature_pin=S.pin((context/(row['archive']+'.sig')).read_bytes()))
 (context/'products.json').write_bytes(S.encoded(products));(context/'pairs.json').write_bytes(S.encoded(pairs));shutil.copyfile(test_public_key(ready,C.read(ready/'manifest.json'),C),context/'TEST-public.asc')
 for role in spec.NAMES:shutil.copytree(source/'packages/tools'/role,context/'sources'/role)
 for p in(context,*context.rglob('*')):
  S.need(not p.is_symlink(),'ordinary Welcome inputs only');p.chmod(0o755 if p.is_dir()else 0o644)
 return context


def lifecycle_plan(*,root,context,target,ready,C):
 """Join actual original604 archive/signature and fresh5, never substitute fresh4."""
 checks=load('_closed_plan_package_checks',root/'heldwelcome/scripts/checks/package_checks.py')
 W=root/'copyworker/scripts/ci/current606-welcome5-copy'
 contract=load('_closed_copy_plan_contract',W/'contract.py')
 with aliases({'contract':contract}):plan=load('_closed_copy_plan_constructor',W/'plan.py')
 selected=C.read(target/'manifest.json');rows=[r for r in selected['packages']if r['name']=='cachy-asahi-welcome'];projects=[r for r in selected['projects']if r['name']=='cachy-asahi-welcome']
 S.need(len(rows)==len(projects)==1 and rows[0]['version']==projects[0]['version']=='0.1.0-4','exact original installed604 Welcome4 operand')
 row=rows[0];archive=target/row['archive'];signature=target/row['signature'];oldreport=checks.package(archive)
 S.need(not oldreport['errors']and C.sha(archive)==row['sha256']and archive.stat().st_size==row['size']and C.sha(signature)==row['signature_sha256']and signature.stat().st_size==row['signature_size'],'original604 physical archive/signature whole pins')
 payload={n:v for n,v in oldreport['members'].items()if v['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')}
 S.need(len(payload)==9,'whole original compiled Welcome payload')
 # The original manifest separates its archive row and project payload. Retain
 # BOTH original rows plus the original full manifest pin; add the independently
 # archive-checked payload for the copied-root contract without rewriting either.
 source_record=dict(row,payload=payload,original_project=projects[0],original_manifest=S.pin((target/'manifest.json').read_bytes()))
 archives=context/'archives';archives.mkdir(mode=0o700)
 def operand(product,src,sig):
  dest=archives/src.name;S.need(not dest.exists(),'distinct original4/candidate5 archives');shutil.copyfile(src,dest);shutil.copyfile(sig,dest.with_name(dest.name+'.sig'))
  return dict(product,path='/runner/inputs/archives/'+dest.name,bytes=dest.stat().st_size,sha256=C.sha(dest),signature=dict(path='/runner/inputs/archives/'+dest.name+'.sig',**S.pin(dest.with_name(dest.name+'.sig').read_bytes())))
 old=operand(dict(version=row['version'],signer=row['signer'],payload=payload,source_record=source_record),archive,signature)
 products=C.read(context/'products.json');newrow=products['cachy-asahi-welcome5'];new=operand({k:newrow[k]for k in('version','signer','payload')},context/newrow['archive'],context/newrow['signature']);newreport=checks.package(context/newrow['archive'])
 keys=context/'keys';keys.mkdir(mode=0o700);pub=test_public_key(ready,C.read(ready/'manifest.json'),C);shutil.copyfile(pub,keys/pub.name)
 S.need(row['signer']==newrow['signer']==C.read(ready/'manifest.json')['preparation']['signer_roles']['ephemeral_TEST'],'original4 and fresh5 signed by this exact producer TEST identity')
 keyrows=[dict(path='/runner/inputs/keys/'+pub.name,signer=row['signer'],**S.pin(pub.read_bytes()))]
 policy=C.read(root/'heldwelcome/scripts/ci/welcome5-native-upgrade/input-policy.json')
 value=plan.make(original4=old,new5=new,original604_manifest={'cachy-asahi-welcome':source_record},original4_report=oldreport,new5_report=newreport,fixture_policy=policy,verification_keys=keyrows)
 (context/'lifecycle-plan.json').write_bytes(S.encoded(value));return value
