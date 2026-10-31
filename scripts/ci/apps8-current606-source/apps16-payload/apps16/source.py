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
def parent389(root,proof):
 p=proof['parent389'];before=p['files'];pub=p['publication'];assert len(before)==389
 assert pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='97666b742d1b29e469e6de171da6e7a0d15c18c7',ref='codex/apps14-current606-v1',files=389,git_joins=389,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
 assert p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=before)
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in p['before_bodies']else(root/n).read_bytes()for n in before}
 assert {n:pin(raw)for n,raw in bodies.items()}==before
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='apps16-whole389-')as tmp:
   old=Path(tmp)/'source';old.mkdir()
   for n,raw in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(raw)
   assert rows(old)==before
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str(old/'apps14'));spec=importlib.util.spec_from_file_location('_whole_original_apps14_389',old/'apps14/source.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);fact=m.verify();assert fact['files']==389 and fact['parent_files']==380
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(source=pub['source'],files=389,status='WHOLE_ORIGINAL_SOURCE_GUARD_EXECUTED_NOT_NATIVE_ACCEPTANCE')
def validate(root,fact,want):
 root=Path(root);raw=(root/'apps16/successor.json').read_bytes();assert pin(raw)==want and not sys.flags.optimize
 p=json.loads(raw);before=p['before'];assert len(before)==380
 predecessor=parent389(root,p)
 footer="\n# BEGIN_APPS16_FULL380\n_original_apps16_verify=verify\ndef verify(root=ROOT):\n result=_original_apps16_verify(root)\n M=module('_apps16_full380_source_guard',root/'apps16/source.py')\n return M.validate(root,result,"+repr(want)+")\n"
 assert (root/LANE/'contract.py').read_text().endswith(footer)
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in p['before_bodies']else(root/n).read_bytes()for n in before}
 assert all(pin(bodies[n])==w for n,w in before.items())
 for n,edits in p['edits'].items():
  if n==LANE+'/source-manifest.json':continue
  text=(root/n).read_text()
  if n.startswith('.github/workflows/'):
   for target in(LANE+'/source-manifest.json',LANE+'/owner.py'):
    new=pin((root/target).read_bytes())['sha256'];assert text.count(new)==1;text=text.replace(new,before[target]['sha256'],1)
  if n==LANE+'/contract.py':text=text.split('\n# BEGIN_APPS16_FULL380\n')[0]
  for a,b,count in reversed(edits):assert text.count(b)==count,(n,a);text=text.replace(b,a,count)
  assert text.encode()==bodies[n],n
 for n,w in p['helpers'].items():assert pin((root/n).read_bytes())==w,n
 decision=json.loads((root/'apps16/parent-qualification.json').read_bytes());assert decision['source']==p['parent_source']and decision['run']==39735431322 and decision['status']=='ROOT_ACCEPTED_FINITE_APPS8_CURRENT606_NATIVE_LIFECYCLE'
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='apps16-whole380-')as tmp:
   old=Path(tmp)/'source';old.mkdir()
   for n,body in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(body)
   assert rows(old)==before
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str(old/'apps8'));spec=importlib.util.spec_from_file_location('_whole_original_apps8_380',old/'apps8/source.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);held=m.verify();assert held['files']==380 and held['parent_inverse_files']==348
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,status='SOURCE_ONLY_APPS16_CURRENT606_REQUIRES_NEW_NATIVE',parent_source=p['parent_source'],parent_files=380,parent389=predecessor,phases=['baseline6','upgrade7','upgrade16','same-version16','remove16','reinstall16','restore7','restore-original6'],actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')
def verify():
 sys.path.insert(0,str(ROOT/LANE));spec=importlib.util.spec_from_file_location('_apps16_owner_contract',ROOT/LANE/'contract.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C);return C.verify()
def emit(output):
 fact=verify();out=Path(output).absolute();assert not out.exists()and out.parent.is_dir()and not any(p.is_symlink()for p in(out,*out.parents))and not out.is_relative_to(ROOT)and not ROOT.is_relative_to(out)
 shutil.copytree(ROOT,out,ignore=lambda directory,names:['.git']if Path(directory)==ROOT else[]);assert rows(out)==rows(ROOT);return dict(fact,emitted=len(rows(out)))
