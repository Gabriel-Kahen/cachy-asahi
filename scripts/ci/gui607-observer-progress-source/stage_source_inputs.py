# SPDX-License-Identifier: MIT
"""Stage exact historical DATA fixtures for source tests; never native evidence."""
import argparse,hashlib,importlib.util,json,os,shutil,stat,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('_gui_source_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(sp);sp.loader.exec_module(F)
FIXTURES={'bytes': 369602, 'sha256': '63cb46aca69fd99de229433b8ed7da4de0380bce4d80bc1c09dec81901556cb1'}
def profile():
 raw=F.read(HERE/'source-fixtures.json');F.need(F.pin(raw)==FIXTURES,'exact source fixture profile');return json.loads(raw)
def joined(root,expected):
 root=F.ordinary(root);paths=list(root.rglob('*'));files={p.relative_to(root).as_posix():p for p in paths if not p.is_dir()}
 F.need(set(files)==set(expected)and all(not p.is_symlink()for p in paths),'closed ordinary fixture members')
 for name,path in files.items():
  F.ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   before=os.fstat(fd);want=expected[name];F.need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==want['bytes']<=64*1024**2,'exact bounded fixture file')
   digest=hashlib.sha256();size=0
   while block:=os.read(fd,1024**2):
    size+=len(block);F.need(size<=want['bytes'],'fixture read cap');digest.update(block)
   F.need(dict(bytes=size,sha256=digest.hexdigest())==want and F.identity(before)==F.identity(os.fstat(fd))==F.identity(path.stat(follow_symlinks=False)),'whole exact stable source fixture '+name)
  finally:os.close(fd)
 return root

def stage(args):
 q=profile();raw=F.read(HERE/'profile.json');F.need(F.pin(raw)==F.PROFILE,'exact source profile');p=json.loads(raw)
 source=joined(args.source,p['result']['files']);roots={k:joined(getattr(args,k),v['files'])for k,v in q['carriers'].items()}
 source,out=F.paths(source,args.output)
 F.need(all(out!=r and out not in r.parents and r not in out.parents for r in roots.values()),'disjoint source fixture destination')
 out.mkdir(mode=0o700)
 # Execute only exact joined emitted source. stage_inputs decodes historical DATA,
 # not the old actual verifier, collector, producer or any native actor.
 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
 subprocess.run([sys.executable,'-I','-B','-Werror',str(source/'implementation/stage_inputs.py'),'--record',str(roots['record22']),'--output',str(out/'public991')],env=env,check=True,timeout=180)
 original=source/'parent574/original';sys.path.insert(0,str(original/'scripts/ci/welcome5-native-gui'))
 sp=importlib.util.spec_from_file_location('_joined_gui_asset_data',original/'scripts/ci/welcome5-native-gui/assets.py');A=importlib.util.module_from_spec(sp);sp.loader.exec_module(A)
 # Historical SOURCE fixtures use the recorded receipt epoch; this is not
 # assets.prepare/renewal.apply, which retain genuine current validity.
 spec=importlib.util.spec_from_file_location('_explicit_historical_fixture',source/'implementation/historical_source.py');H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
 R=A.C.load('_held_renewal_provenance',original/'scripts/ci/welcome5-native-gui/renewal.py');H.historical_overlay(R,roots['renewal'])
 A.assemble_data(original,roots['public_carrier']/'payload',roots['project_carrier']/'payload',out/'assets484',A.C.selection(original),None)
 renewal_out=out/'assets484/renewal';renewal_out.mkdir(mode=0o700)
 for name in q['carriers']['renewal']['files']:
  target=renewal_out/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(roots['renewal']/name,target)
 joined(out/'public991',q['fixtures']['public991']);joined(out/'assets484',q['fixtures']['assets484'])
 return dict(status='EXACT_HISTORICAL_SOURCE_FIXTURES_ONLY_NOT_CURRENT_AUTHORITY',public991=str(out/'public991'),assets484=str(out/'assets484'),record22=str(roots['record22']),native='NOT_RUN',actual_replay=False,renewal_expires=q['renewal_expires'])
if __name__=='__main__':
 ap=argparse.ArgumentParser(description=__doc__)
 for name in('source','record22','public_carrier','project_carrier','renewal','output'):ap.add_argument('--'+name.replace('_','-'),required=True)
 print(json.dumps(stage(ap.parse_args()),sort_keys=True,indent=2))
