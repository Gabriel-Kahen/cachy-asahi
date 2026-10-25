# SPDX-License-Identifier: MIT
"""Source-owned exact cache DATA before unchanged original archive CLI and seed."""
import hashlib,json,os,re,stat,sys,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
HELD_INPUTS={'archive20.py': {'bytes': 11096, 'sha256': 'e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968'}, 'archive32.py': {'bytes': 11102, 'sha256': 'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418'}, 'archive8.py': {'bytes': 11040, 'sha256': '5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565'}, 'retained_cache.py': {'bytes': 7987, 'sha256': '06e477f85d851d527276a544c01868c2a5b0a5d0a867380ab14c08d48a96130a'}}
PREFILL_PIN=dict(bytes=4717,sha256='2090bd8098783834ac7b11a19eb3d8cd047b7de5b01f77ddc4bb60cd57bea726')
KEY=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def held(name,row):
 path=HERE/name;assert not any(p.is_symlink()for p in(path,*path.parents));before=path.lstat();assert stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==row['bytes'];fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  assert KEY(before)==KEY(os.fstat(fd));parts=[];total=0
  while True:
   raw=os.read(fd,1024**2)
   if not raw:break
   total+=len(raw);assert total<=before.st_size;parts.append(raw)
  raw=b''.join(parts);assert KEY(before)==KEY(os.fstat(fd))==KEY(path.lstat())and dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==row
 finally:os.close(fd)
 module=types.ModuleType('_held_repair_prefill_'+name.replace('.','_'));module.__file__=str(path);exec(compile(raw,module.__file__,'exec'),module.__dict__);return module

def main():
 assert len(sys.argv)==2 and sys.argv[1]in('32','20','8');n=int(sys.argv[1]);workspace=Path(os.environ['GITHUB_WORKSPACE']).absolute();temporary=Path(os.environ['RUNNER_TEMP']).absolute();assert ROOT==workspace/'repair-source'and not any(p.is_symlink()for p in(temporary,*temporary.parents));source=os.environ['SOURCE_SHA'];assert re.fullmatch('[a-f0-9]{40}',source)and source==os.environ['GITHUB_SHA']==os.environ['GITHUB_WORKFLOW_SHA']
 deadline=time.monotonic()+180;R=held('retained_cache.py',HELD_INPUTS['retained_cache.py']);p=R.profile();proof=R.prove(workspace/p['checkout'],deadline,p);archive=held('archive'+str(n)+'.py',HELD_INPUTS['archive'+str(n)+'.py']);selected=archive.policy(HERE/('archive'+str(n)+'-policy.json'),ROOT/'scripts/ci/maintained-desktop574-inputs.json');P=held('legacy_prefill.py',PREFILL_PIN);receipt=P.prefill(workspace/p['checkout'],temporary/('frozen574-archive'+str(n)),selected,deadline);R.tick(deadline);assert receipt['requests']==0 and len(receipt['files'])==n and receipt['actual_authority']is False
 print(json.dumps(dict(status='REPAIR_LEGACY_EXACT_CACHE_DATA_ONLY',count=n,carrier_source=proof['source'],carrier_files=len(proof['files']),receipt=receipt,original_cli='REQUIRED_NEXT_UNCHANGED',original_index='REQUIRED_NEXT_UNCHANGED',original_seed='REQUIRED_NEXT_UNCHANGED',original_signature_and_trust='REQUIRED_UNCHANGED',actual_authority=False),sort_keys=True))
if __name__=='__main__':main()
