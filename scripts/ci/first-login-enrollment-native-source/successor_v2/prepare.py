#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Stage only exact current recipes + maintained offline tools. Never run actors."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
FAMILY='scripts/ci/first-login-enrollment-native-source'


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def loader(path,name):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def construct(root,profile_sha256):
    # Use the existing descriptor-relative nofollow/single-link Source reader,
    # tree calculator and atomic no-replace publisher, with its exact basis pin.
    raw=(HERE/'profile.json').read_bytes();need(pin(raw)['sha256']==profile_sha256,'externally reviewed complete profile pin')
    profile=json.loads(raw);need(profile['actual']==dict.fromkeys(['source','ref','run','job','artifact','native_pair','signed_lifecycle','Reader','Root_acceptance']),'unissued current-three profile')
    root=Path(root);need(root.is_absolute()and root==root.resolve(),'canonical source input root before helper import');basis=root/FAMILY/'prepare.py';need(not any(p.is_symlink()for p in(basis,*basis.parents))and basis.stat().st_nlink==1 and basis.stat().st_size<=64*1024,'ordinary bounded whole constructor basis');need(pin(basis.read_bytes())=={k:profile['prior_factory']['prepare.py'][k]for k in ('bytes','sha256')},'whole maintained constructor basis')
    H=loader(basis,'current_first_login_held_constructor')
    need(H.absolute(root)==root and root==root.resolve(),'canonical source input root')
    before=H.read(basis)[0];need(pin(before)==pin(basis.read_bytes()),'stable held constructor')
    files={}
    for kind,recipe in profile['packages'].items():
        path=root/recipe['path'];bodies=H.snapshot(path);need(H.descriptors(bodies)==recipe['files'],'exact complete current recipe namespace/body/mode: '+kind)
        for name,value in bodies.items():files[recipe['path']+'/'+name]=value
    for name,row in profile['helpers'].items():
        raw,mode=H.read(root/name);need(dict(**pin(raw),mode=mode)==row,'whole maintained offline helper: '+name);files[name]=(raw,mode)
    # Close every historical v1 leaf selected as a reused constructor basis.
    for name,row in profile['prior_factory'].items():
        raw,mode=H.read(root/FAMILY/name);need(dict(**pin(raw),mode=mode)==row,'unchanged historical source basis');files[FAMILY+'/'+name]=(raw,mode)
    for name in ('prepare.py','native.py','profile.json','inputs.TEMPLATE.json'):
        files[FAMILY+'/successor_v2/'+name]=H.read(HERE/name)
    # Current recipes already carry exact local source checksums; no download,
    # generated .SRCINFO, makepkg or recipe shell execution occurs here.
    C=loader(root/'scripts/checks/package_checks.py','current_first_login_static_recipe_checks')
    for kind,recipe in profile['packages'].items():
        reviewed=C.recipe(root/recipe['path']/'PKGBUILD');need(not reviewed['errors'],'static recipe source/SHA/metadata: '+kind)
        md=reviewed['metadata'];need(md['pkgname']==[recipe['name']] and md['pkgver'][0]+'-'+md['pkgrel'][0]==recipe['version'],'exact current version')
        files['reviewed/'+kind+'.json']=(H.encoded(reviewed['input_sha256']),0o644)
    lock=dict(schema=1,kind=profile['kind'],operation=profile['operation'],files=H.descriptors(files),actual=profile['actual'])
    files['source.lock.json']=(H.encoded(lock),0o644)
    return H,files,dict(status='STAGED_CURRENT_SOURCE_ONLY_NOT_NATIVE_READY',profile=pin((HERE/'profile.json').read_bytes()),files=len(files),tree=H.tree(files),source_lock=pin(files['source.lock.json'][0]),actual=profile['actual'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--profile-sha256',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,'isolated source constructor')
    root=a.root;output=a.output
    need(root.is_absolute() and output.is_absolute() and not(output==root or root in output.parents or output in root.parents),'disjoint canonical source/output')
    H,files,result=construct(root,a.profile_sha256);H.publish(files,output);need(H.snapshot(output)==files,'complete staged source readback');print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
