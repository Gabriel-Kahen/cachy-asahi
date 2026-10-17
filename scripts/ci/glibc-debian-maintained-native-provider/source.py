#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fresh caa3 bundle validation for the unchanged native executor; no actors."""
import hashlib,json,lzma,sys,tempfile,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import materialize as M
import authority as G
import bundle as B
HERE=Path(__file__).resolve().parent
AUTH_SHA=M.AUTH_SHA;INSPECTOR_SHA='70bcde37f56b5a4ea3a44993a6add82ef4627635801c0a7909b14aefbca00d92'
def inputs(directory,pin):
 directory=Path(directory).absolute();M.need(type(pin) is str and len(pin)==64 and all(c in '0123456789abcdef' for c in pin),'exact bundle manifest pin required')
 # Source-frozen authority gates even before opening untrusted bundle data.
 policy=json.loads((HERE/'authority.json').read_bytes());M.need(policy.get('status')=='ROOT_BOUND_DEBIAN_MAINTAINED_SOURCE_AUTHORITY','UNBOUND maintained source authority before native actors')
 a=M.helper('native_maintained_auth',HERE/'auth.py',AUTH_SHA);raw=a.read(directory/'bundle.json',2*1024**2);M.need(a.pin(raw)['sha256']==pin,'exact maintained bundle manifest differs');value=a.decode(raw)
 M.need(value.get('schema_version')==1 and value.get('status')=='SOURCE_BUNDLE_READY_UNSELECTED_MAINTAINED_DEBIAN_PROVIDER' and value.get('package_version')=='2.43.caa3-1' and value.get('prepared_tree')==G.EXPECTED['prepared_tree'],'distinct maintained caa3 bundle required; no old pair/source credit')
 files=value['files'];M.need(type(files) is dict and 1<=len(files)<=32 and {p.name for p in directory.iterdir()}==set(files)|{'bundle.json'},'closed flat bounded maintained bundle required')
 for name,row in files.items():
  M.need(type(name) is str and Path(name).name==name and name not in ('.','..') and type(row) is dict and set(row)=={'bytes','sha256'},'flat pinned source file required');M.need(a.pin(a.read(directory/name))==row,'bundle source file changed: '+name)
 decision=policy['decision']['path'];expected=set(a.PUBLIC_PINS)|set(B.KEY_COPIES.values())|{decision,'glibc_2.43-7.debian.tar.xz','auth.py','original_inspector.py','stage.py','authority.json','materialize.py','authority.py','source-lock.json','0002-held-builder-test-expectations.patch','source-provenance.json','NOTICE','LICENSE','PKGBUILD','source-authentication.json'}
 M.need(set(files)==expected,'complete exact maintained recipe/source/authority file set required')
 for name in ('authority.json','auth.py','original_inspector.py','materialize.py','authority.py','source-lock.json','0002-held-builder-test-expectations.patch','source-provenance.json','NOTICE','LICENSE'):
  M.need((directory/name).read_bytes()==(HERE/name).read_bytes(),'source-frozen helper/policy differs: '+name)
 M.need(a.pin(a.read(directory/'stage.py'))['sha256']==B.STAGE_SHA,'exact provider stage required')
 recipe_files={n:files[n] for n in sorted(files) if n not in ('PKGBUILD','source-authentication.json')};M.need(a.read(directory/'PKGBUILD')==B.render(recipe_files),'literal reviewed caa3 recipe/input closure differs')
 authority=G.check(HERE/'authority.json',directory,HERE/'auth.py')
 # A bundle receipt never replaces a fresh current signature/tree/patch replay.
 with tempfile.TemporaryDirectory(prefix='caa3-source-revalidate-',dir=directory.parent) as tmp:
  output=Path(tmp)/'prepared';prepared=M.materialize(directory,directory/M.ARCHIVE,output,HERE/'auth.py',HERE/'original_inspector.py')
  M.need(prepared['completed']==85 and prepared['after_tree']==G.EXPECTED['prepared_tree'],'all85 source preparations required')
  previous=a.decode(a.read(directory/'source-authentication.json',8*1024**2));M.need(previous['source_preparation']==prepared,'retained source preparation differs from actual complete replay')
  chain=a.decode(a.read(output/'source-chain.json',65536))['result']
 original=M.helper('native_maintained_inspector',HERE/'original_inspector.py',INSPECTOR_SHA);inspect=types.FunctionType(original.inspect.__code__,dict(original.__dict__,gzip=types.SimpleNamespace(open=lzma.open)));observed=inspect(directory/a.ARCHIVE,a.TREE,original.LIMITS);M.need(observed['sha256']==a.ARCHIVE_SHA,'complete exact original source object required')
 specification=M.lock();base=a.decode(a.read(HERE/'native-layout.json',65536))
 return dict(value,release='2.43',payload_tree=M.ORIG_TREE,source=observed,authentication=dict(authority=authority,chain=chain,source_preparation=prepared,old_native_pair='NOT_REUSED'),declared_patches=specification['series']['patches']+[dict(name=specification['project_patch']['path'],**specification['project_patch']['pin'])],configured_layout=base['layout'],configured_features=base['feature_choices'])
