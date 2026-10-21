# SPDX-License-Identifier: MIT
"""Separate complete effective profile, original403 always mandatory predecessor."""
import base64,importlib.util,json,sys,tarfile
from pathlib import Path
D=Path(__file__).resolve().parent;sys.path.insert(0,str(D));import common as C

def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def validate(root=C.ROOT):
 root=Path(root);p=C.load(root/'lane/effective-profile-proof.json');before=p['before'];after=p['files'];old=root/'core/profile';new=root/'effective-profile';K=module(root/'core/contract.py','effective_original_contract')
 C.need(K.closed(old)==before and K.closed(new)==after,'whole original and effective profiles')
 C.need(set(after)==set(before)|set(p['added'])and set(p['changed'])=={'profile.json','systemd/PKGBUILD','systemd/.SRCINFO'}and set(p['added'])=={'systemd/cachy-asahi-owned-userns.patch','systemd/caa-owned-userns.h','systemd/cachy-asahi-testlog.py','systemd/vmlinux.btf','systemd/vmlinux-input.json','systemd/cachy-asahi-btf.py','systemd/BTF-COPYING'}and p['held']==len(before)-3,'finite3 changed3 added complete effective partition')
 for n in before:
  if n not in p['changed']:C.need(before[n]==after[n],'every other original profile leaf held')
 for n,row in p['changed'].items():
  a=base64.b64decode(row['before_base64'],validate=True);b=base64.b64decode(row['proposed_base64'],validate=True);C.need(C.pin(a)==row['before']==before[n]and C.pin(b)==row['proposed']==after[n]and C.read(old/n)==a and C.read(new/n)==b,'whole effective recipe/profile inverse')
 for kind in K.KINDS:K.source(old,kind);K.source(new,kind)
 module(new/'systemd/cachy-asahi-btf.py','_exact_fixed_btf_source').validate(new/'systemd')
 C.need(C.read(new/'systemd/caa-owned-userns.h')==C.read(root/'lane/mechanism/caa-owned-userns.h'),'same exact child2 setup helper for preflight and test')
 inv=p['test_inverse'];raw=base64.b64decode(inv['whole_before_base64'],validate=True);C.need(C.pin(raw)==inv['before'],'whole original test body')
 text=raw.decode()
 for row in inv['edits']:C.need(row['count']==1 and text.count(row['before'])==1,'one additive original test seam');text=text.replace(row['before'],row['proposed'],1)
 C.need(C.pin(text.encode())==inv['proposed'],'complete effective test body')
 with tarfile.open(old/'systemd/systemd-8cc40e0c5e9234bf45084751ac53b1fbfe70b492.tar.gz','r:gz')as archive:
  member=archive.getmember('systemd-8cc40e0c5e9234bf45084751ac53b1fbfe70b492/src/test/test-process-util.c');C.need(member.isfile()and member.size==len(raw)and archive.extractfile(member).read()==raw,'whole actual original archive test body')
 # Reconstruct the patch from the full original/proposed bodies, never execute it on import.
 import difflib
 patch=''.join(difflib.unified_diff(raw.decode().splitlines(keepends=True),text.splitlines(keepends=True),fromfile='a/src/test/test-process-util.c',tofile='b/src/test/test-process-util.c')).encode()
 C.need(C.read(new/'systemd/cachy-asahi-owned-userns.patch')==patch,'complete actual package patch matches additive original inverse')
 return p

def authorize(root=C.ROOT,required=True):
 root=Path(root);p=validate(root);template=C.load(root/'lane/effective-selection-template.json');selection=C.load(root/'lane/effective-source-authorization.json');expected=dict(template);expected['status']='ROOT_SELECTED_EFFECTIVE_CORE_TEST_PROFILE_SOURCE_ONLY'
 C.need(template['status']=='UNSELECTED_EFFECTIVE_CORE_TEST_PROFILE_SOURCE_ONLY'and template['effective_profile_files']==p['files']and template['effective_profile_proof']==C.pin(C.read(root/'lane/effective-profile-proof.json'))and template['effective_profile']==C.pin(C.read(root/'effective-profile/profile.json')),'whole reviewable effective selection template')
 if required:C.need(template['original_source_policy']==C.pin(C.read(root/'lane/root-source-authorization.json'))and template['original_core_authority']==C.pin(C.read(root/'authority.json')),'original Root403 source-only input authority remains held')
 for key,name in(('namespace_header','caa-owned-userns.h'),('namespace_probe','probe.c'),('namespace_probe_validator','probe_receipt.py')):C.need(template[key]==C.pin(C.read(root/'lane/mechanism'/name)),'exact approved namespace source')
 C.need((selection==expected)if required else(selection in(template,expected)),'genuine exact Root effective profile source-only decision required')
 return selection
