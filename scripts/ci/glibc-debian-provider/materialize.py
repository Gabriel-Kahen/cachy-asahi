#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""NEW Debian2.43 source bundle; original GNU source/pair is never accepted here."""
import argparse,hashlib,importlib.util,json,lzma,shutil,types
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import auth as A
HERE=Path(__file__).resolve().parent
RECIPE_SHA='ae4529fef261dc76c62cd5208a04bc68572bc504f5471c6fb954f052fca96617'
PATCH3_SHA='6959527f28b1363548c1e7adc76abc95546f584a4670cfd38016c7c134797d87'
INSPECTOR_SHA='70bcde37f56b5a4ea3a44993a6add82ef4627635801c0a7909b14aefbca00d92'
PATCHED_TREE='51979d25e61ba516e9fa73e147c75d021b4838e1'
need=A.need
sha=lambda p:hashlib.sha256(A.read(p)).hexdigest()
def original():
 path=HERE/'original_inspector.py';need(sha(path)==INSPECTOR_SHA,'exact original pure inspector required')
 spec=importlib.util.spec_from_file_location('debian_original_inspector',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def configuration(recipe,lock):
 need(sha(recipe/'PKGBUILD')==RECIPE_SHA and lock['version']=='2.43.caa2' and lock['pkgrel']==1 and lock['name']=='cachy-asahi-glibc-gnu-provider','exact NEW Debian recipe identity required')
 need(lock['payload_tree']==A.TREE and lock['expected_patched_payload_tree']==PATCHED_TREE and lock['source']==dict(path=A.ARCHIVE,url='https://deb.debian.org/debian/pool/main/g/glibc/'+A.ARCHIVE,bytes=21553420,sha256=A.ARCHIVE_SHA),'distinct exact Debian source/patch tree required')
 m=original();m.verify_patches(recipe,dict(patch_order=lock['patch_order'][:2]))
 need(len(lock['patch_order'])==3 and lock['patch_order'][2]['path']=='0003-debian-manual-omission.patch' and lock['patch_order'][2]['sha256']==sha(recipe/'0003-debian-manual-omission.patch')==PATCH3_SHA,'exact manual omission patch required')
 need(lock['prefix']=='/usr' and lock['layout']['multiarch']==lock['feature_choices']['multiarch']=='disabled' and lock['packaging']['stage_helper_sha256']==sha(recipe/'stage.py')=='43b1b441dcc384379ab80c4864bbf7ffd898d56e4ba629c0faa966c25a979e6c','unchanged layout/feature/staging policy required')
 omissions=A.decode(A.read(recipe/'manual-omissions.json',65536));need(len(omissions['removed'])==112 and all(n.startswith('manual/') for n in omissions['removed']) and not omissions['added'] and not omissions['changed'] and sha(recipe/'manual-omissions.json')==lock['documentation']['omissions_sha256'],'exact missing-manual policy required')
def verify_release(inputs,lock):
 admission=A.authority(HERE/'authority.json',inputs) # Before GPG, output creation or any native actor.
 chain=A.inspect_chain(inputs);need(lock['public_inputs']==[dict(path=n,**row) for n,row in A.PUBLIC_PINS.items()],'exact independent chain input lock required')
 need(A.ARCHIVE in A.PUBLIC_PINS and A.PUBLIC_PINS[A.ARCHIVE]==dict(bytes=21553420,sha256=A.ARCHIVE_SHA),'exact independent original object required')
 m=original();inspect=types.FunctionType(m.inspect.__code__,dict(m.__dict__,gzip=types.SimpleNamespace(open=lzma.open)))
 observed=inspect(Path(inputs)/A.ARCHIVE,A.TREE,lock['limits']);need(observed['sha256']==A.ARCHIVE_SHA,'source object changed after chain verification')
 return observed,dict(chain=chain,authority=admission,original_GNU_source='NOT_REUSED_DISTINCT_SOURCE',security='NO_CREDIT',release='NOT_ADMITTED')
def materialize(recipe,inputs,output):
 recipe=Path(recipe).absolute();inputs=Path(inputs).absolute();output=Path(output).absolute()
 need(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary output required')
 lock=A.decode(A.read(recipe/'source-lock.json',65536));configuration(recipe,lock);observed,auth=verify_release(inputs,lock)
 policy=A.decode(A.read(HERE/'authority.json',65536));names=list(A.PUBLIC_PINS)+[policy['decision']['path']]
 need(len(set(names))==len(names) and not set(names)&({'bundle.json','source-authentication.json'}|{p.name for p in recipe.iterdir()}),'closed noncolliding source/auth inputs required');output.mkdir(mode=0o700)
 try:
  for source in [*recipe.iterdir(),*(inputs/n for n in names)]:A.read(source);shutil.copyfile(source,output/source.name)
  (output/'source-authentication.json').write_text(json.dumps(auth,sort_keys=True,indent=2)+'\n')
  files={p.name:A.pin(A.read(p)) for p in sorted(output.iterdir())};need(len(files)<=32,'held finite bundle manifest bound')
  value=dict(schema_version=1,status='SOURCE_BUNDLE_READY_UNSELECTED_DEBIAN_PROVIDER',release='2.43',payload_tree=A.TREE,source=observed,authentication=auth,files=files,declared_patches=lock['patch_order'],configured_layout=lock['layout'],configured_features=lock['feature_choices'],package_version='2.43.caa2-1',native_build='NOT_RUN',private16k='NOT_RUN_NEW_SOURCE',security='NO_CREDIT',release_admission='NOT_GRANTED')
  (output/'bundle.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');return value
 except BaseException:shutil.rmtree(output);raise

def inputs(bundle,pin):
 bundle=Path(bundle).absolute();need(sha(bundle/'bundle.json')==pin,'new bundle caller pin differs');value=A.decode(A.read(bundle/'bundle.json',2*1024**2))
 need(value['status']=='SOURCE_BUNDLE_READY_UNSELECTED_DEBIAN_PROVIDER' and value['package_version']=='2.43.caa2-1' and value['payload_tree']==A.TREE and type(value['files']) is dict and len(value['files'])<=32,'NEW Debian source bundle required; no old pair/source reuse')
 need({p.name for p in bundle.iterdir()}==set(value['files'])|{'bundle.json'},'undeclared bundle member refused')
 for n,row in value['files'].items():need(Path(n).name==n and n not in ('.','..') and A.pin(A.read(bundle/n))==row,'closed bundle byte join differs')
 lock=A.decode(A.read(bundle/'source-lock.json',65536));configuration(bundle,lock);observed,auth=verify_release(bundle,lock)
 need(value['source']==observed and value['authentication']==auth and value['declared_patches']==lock['patch_order'] and value['configured_layout']==lock['layout'] and value['configured_features']==lock['feature_choices'],'new source/auth/layout receipt differs')
 return value
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--recipe',type=Path,required=True);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 try:print(json.dumps(materialize(a.recipe,a.inputs,a.output),sort_keys=True))
 except (ValueError,OSError,KeyError) as error:print(json.dumps(dict(status='REFUSED_DEBIAN_SOURCE_INPUTS',error=str(error),native='NOT_RUN',release='NOT_ADMITTED')));raise SystemExit(1)
