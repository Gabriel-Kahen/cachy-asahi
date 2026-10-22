# SPDX-License-Identifier: MIT
"""Exact full380 inverse, complete original348/263 gates; no native credit."""
import base64,importlib.util,json,shutil,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
LANE='scripts/ci/current606-apps7-closed-owner'
def pin(raw):
 import hashlib
 return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def rows(root):return{p.relative_to(root).as_posix():pin(p.read_bytes())for p in root.rglob('*')if p.is_file()and p.relative_to(root).parts[0]!='.git'}
def validate(root,fact,want):
 root=Path(root);raw=(root/'apps11/successor.json').read_bytes();assert pin(raw)==want and not sys.flags.optimize
 p=json.loads(raw);before=p['before'];assert len(before)==380
 footer="\n# BEGIN_APPS11_FULL380\n_original_apps11_verify=verify\ndef verify(root=ROOT):\n result=_original_apps11_verify(root)\n M=module('_apps11_full380_source_guard',root/'apps11/source.py')\n return M.validate(root,result,"+repr(want)+")\n"
 assert (root/LANE/'contract.py').read_text().endswith(footer)
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in p['before_bodies']else(root/n).read_bytes()for n in before}
 assert all(pin(bodies[n])==w for n,w in before.items())
 for n,edits in p['edits'].items():
  if n==LANE+'/source-manifest.json':continue
  text=(root/n).read_text()
  if n.startswith('.github/workflows/'):
   for target in(LANE+'/source-manifest.json',LANE+'/owner.py'):
    new=pin((root/target).read_bytes())['sha256'];assert text.count(new)==1;text=text.replace(new,before[target]['sha256'],1)
  if n==LANE+'/contract.py':text=text.split('\n# BEGIN_APPS11_FULL380\n')[0]
  for a,b,count in reversed(edits):assert text.count(b)==count,(n,a);text=text.replace(b,a,count)
  assert text.encode()==bodies[n],n
 for n,w in p['helpers'].items():assert pin((root/n).read_bytes())==w,n
 decision=json.loads((root/'apps11/parent-qualification.json').read_bytes());assert decision['source']==p['parent_source']and decision['run']==39735431322 and decision['status']=='ROOT_ACCEPTED_FINITE_APPS8_CURRENT606_NATIVE_LIFECYCLE'
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='apps11-whole380-')as tmp:
   old=Path(tmp)/'source';old.mkdir()
   for n,body in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(body)
   assert rows(old)==before
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str(old/'apps8'));spec=importlib.util.spec_from_file_location('_whole_original_apps8_380',old/'apps8/source.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);held=m.verify();assert held['files']==380 and held['parent_inverse_files']==348
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,status='SOURCE_ONLY_APPS11_CURRENT606_REQUIRES_NEW_NATIVE',parent_source=p['parent_source'],parent_files=380,phases=['baseline6','upgrade7','upgrade11','same-version11','remove11','reinstall11','restore7','restore-original6'],actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')
def verify():
 sys.path.insert(0,str(ROOT/LANE));spec=importlib.util.spec_from_file_location('_apps11_owner_contract',ROOT/LANE/'contract.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C);return C.verify()
def emit(output):
 fact=verify();out=Path(output).absolute();assert not out.exists()and out.parent.is_dir()and not any(p.is_symlink()for p in(out,*out.parents))and not out.is_relative_to(ROOT)and not ROOT.is_relative_to(out)
 shutil.copytree(ROOT,out,ignore=lambda directory,names:['.git']if Path(directory)==ROOT else[]);assert rows(out)==rows(ROOT);return dict(fact,emitted=len(rows(out)))
