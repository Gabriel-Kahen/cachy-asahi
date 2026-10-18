# SPDX-License-Identifier: MIT
"""Four distinct original Welcome builds on the unchanged producer574 image."""
import json,os,shutil,signal,sys
from pathlib import Path
import contract as P

def inspect_recipe(source,role,policy):
 checks=P.load('606_source_recipe_checks',source/'scripts/checks/package_checks.py')
 product=policy['products'][role];r=checks.recipe(source/product['recipe']/'PKGBUILD');m=r['metadata'];P.need(not r['errors']and m['pkgname']==[product['package_name']]and m['pkgver'][0]+'-'+m['pkgrel'][0]==product['version']and m.get('arch')==['any']and m.get('license')==['MIT']and not any(m.get(k)for k in('install','provides','conflicts','replaces','backup','makedepends','checkdepends'))and m.get('depends')==(['python>=3.11','networkmanager>=1.44']if role==P.ROLES[0]else['python>=3.11'])and r['input_sha256']=={n:v['sha256']for n,v in product['source_files'].items()},'exact public script-only606 recipe');return r

def prepare(root,producer,out,owned,original,C):
 P.verify(root);policy=P.policy();source=root/'held-tools';base_dir=producer/'private/desktop574';lock=base_dir/'installed-packages.lock';image=owned.image
 T=P.load('606_original_tools_contract',source/'scripts/ci/tools-native/contract.py');checks=P.load('606_original_package_checks',source/'scripts/checks/package_checks.py')
 T.NAMES=P.ROLES;T.spec=lambda:policy;T.final_spec=lambda:policy;T.verify_source=lambda _:P.verify(root)
 T.recipe=lambda _,role:inspect_recipe(source,role,policy)
 oldlog=T.check_log
 def check_log(path,role):
  text=path.read_text(errors='replace');P.need('skipped='not in text and 'OK (skipped='not in text,'native suite skip refused');return oldlog(path,role)
 T.check_log=check_log
 shared=P.load('606_unchanged_welcome_build',source/'scripts/ci/welcome-native/run.py');shared.C=T;plain=shared.docker;shared.docker=lambda *a,**k:owned.launch(plain(*a,**k))
 common=P.load('606_original_build_process',source/'scripts/virtual/common.py');sys.path[:0]=[str(source/'scripts/build'),str(source/'scripts/checks')];bind=P.load('606_original_build_binding',source/'scripts/build/build.py');comparison=P.load('606_original_build_compare',source/'scripts/build/compare.py');gate=P.load('606_original_pair_gate',source/'scripts/ci/tools-native/run.py');gate.C=T
 base=shared.inventory(lock.read_text());P.need(len(base)==574 and T.digest(lock)==C.BUILDER and base=={r['name']:r['version']for r in json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['packages']},'same exact producer574 inventory')
 work=out/'tools-builds';work.mkdir();names=[];products={};pairs={};epoch=json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['source_date_epoch']
 def execute(argv,log,seconds):
  P.need(seconds==240,'original build deadline');active=common.LoggedProcess(argv,log,env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC',HOME=str(out/'home')),limit=16*1024**2)
  try:active.process.wait(timeout=seconds);active.finish();P.need(active.process.returncode==0,'native606 package build failed')
  finally:
   if active.process.poll()is None:
    try:os.killpg(active.process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    active.process.wait(timeout=5)
   active.finish()
 for role in P.ROLES:
  pair=[shared.build(source,work,base,image,lock,role,side,epoch,execute,names,checks,bind)for side in('a','b')];result=comparison.compare(*(r['directory']for r in pair));gate.pair_gate(result);(work/(role+'-comparison.json')).write_bytes(P.encoded(result));pairs[role]=dict(comparison=result,builders=[r['directory'].name for r in pair],archives=[dict(path=str(r['archive'].relative_to(work)),**P.pin(r['archive'].read_bytes()))for r in pair]);products[role]=dict(role=role,name=policy['products'][role]['package_name'],version='0.1.0-2',archive=pair[0]['archive'],payload=pair[0]['payload'])
 P.need(len(names)==len(set(names))==4 and len(owned.rows)==4,'four distinct leased new builders')
 context=out/'tools606';context.mkdir();roles=original['preparation']['signer_roles'];sign=C.scoped_load('606_original_materializer_signer',root/'held604/scripts/ci/expanded600-installer-vm/materializer.py',{'contract':C});archives=[]
 for row in products.values():
  src=row['archive'];dest=context/src.name;shutil.copyfile(src,dest);archives.append(dest);row['archive']=dest.name;row.update(bytes=dest.stat().st_size,sha256=C.sha(dest),signer=roles['ephemeral_TEST'])
 sign.sign(producer/'private/test-signing',archives,roles['ephemeral_TEST'])
 for row in products.values():row['signature']=row['archive']+'.sig';row['signature_pin']=P.pin((context/row['signature']).read_bytes())
 (context/'products.json').write_bytes(P.encoded(products));(context/'pairs.json').write_bytes(P.encoded(pairs));shutil.copyfile(P.HERE/'input-policy.json',context/'tools-policy.json')
 for role in P.ROLES:shutil.copytree(source/'packages/tools'/role,context/'sources'/role)
 for p in(context,*context.rglob('*')):
  if not p.is_symlink():p.chmod(0o755 if p.is_dir()else 0o644)
 return context
