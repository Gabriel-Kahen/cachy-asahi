"""Unchanged32/20/8 archive transports into original owned574 context."""
import argparse,importlib.util,os,shutil,stat,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import common as C

def prepare_core(core):
 # copytree's absent-destination contract is essential: never reuse an old cache.
 C.private(core.parent)
 shutil.copytree(C.ROOT/'core',core)
 public={n.removeprefix('core/'):v for n,v in C.load(C.ROOT/'source-manifest.json')['files'].items()if n.startswith('core/')}
 C.need(C.files(core)==public,'whole fresh public core copy differs')
 expected_dirs={str(p)for n in public for p in Path(n).parents if str(p)!='.'}
 actual_dirs=set()
 for p in (core,*core.rglob('*')):
  C.need(not p.is_symlink(),'fresh core symlink refused')
  if p.is_dir():
   s=p.stat();C.need(s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)in(0o700,0o755),'fresh core owned nonwritable directory')
   if p!=core:actual_dirs.add(str(p.relative_to(core)))
 C.need(actual_dirs==expected_dirs,'fresh core directory graph differs')
 cache=core/'builder-context/deps';leaf='builder-context/deps/SHA256SUMS'
 C.need({n for n in public if n.startswith('builder-context/deps/')}=={leaf},'exact public cache authority')
 fd=os.open(cache,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);identity=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_nlink)
  C.need(stat.S_ISDIR(before.st_mode)and before.st_uid==os.getuid(),'owned ordinary copied cache')
  C.need(os.listdir(fd)==['SHA256SUMS']and C.pin(C.read(cache/'SHA256SUMS'))==public[leaf],'exact sole pinned checksum leaf')
  os.fchmod(fd,0o700)
  after=os.fstat(fd);named=cache.stat(follow_symlinks=False)
  C.need(identity(before)==identity(after)==identity(named)and stat.S_ISDIR(named.st_mode)and stat.S_IMODE(after.st_mode)==stat.S_IMODE(named.st_mode)==0o700,'same copied cache identity and private mode')
  C.need(os.listdir(fd)==['SHA256SUMS']and C.pin(C.read(cache/'SHA256SUMS'))==public[leaf]and C.files(core)==public,'copied cache or public core drift')
 finally:os.close(fd)
 C.private(cache)
 return cache

def main():
 started=__import__('time').monotonic();deadline=started+890
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();C.preflight();C.policy();out=C.private(a.output)
 C.need(C.load(out/'seed-report.json')['status']=='SIX_EXACT_EXISTING_SEED_FILES_READY','original six seed required')
 import native248_cache as cache_source,archive_prefill
 carrier_profile=cache_source.profile();carrier=C.ROOT.parent/carrier_profile['checkout']
 archive_carrier=cache_source.prove(carrier,deadline,carrier_profile)
 rows=[]
 for n in('32','20','8'):
  path=C.ROOT/'baseline'/('archive'+n+'.py');spec=importlib.util.spec_from_file_location('core_held_archive'+n,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  v=m.policy(C.ROOT/'baseline'/('archive'+n+'-policy.json'),C.ROOT/'baseline/maintained-desktop574-inputs.json')
  cache=out/('archive'+n);prefilled=archive_prefill.prefill(carrier,cache,v,deadline);index=m.prefetch(cache,v);seed=m.seed_exact(cache,out/'context/deps',v)
  C.save(out/('archive'+n+'-index.json'),index);rows.append(dict(kind=n,prefill=prefilled,helper=C.pin(C.read(path)),policy=C.pin(C.read(C.ROOT/'baseline'/('archive'+n+'-policy.json'))),index=index,seed=seed))
 core=out/'materialized-core';prepare_core(core)
 import recovery_cache
 recovered=recovery_cache.seed(core,deadline)
 C.need(not(out/'prefetch.json').exists(),'fresh cache proof export required')
 C.save(out/'prefetch.json',dict(status='PUBLIC_CACHE_SEEDED_AUTHENTICATION_NOT_RUN',recovery_cache=recovered))
 command=[sys.executable,'-I','-B',str(C.ROOT/'lane/acquire64.py'),'--core',str(core),'--evidence',str(out/'authentication64')]
 with(out/'acquire64.stdout').open('wb')as stdout,(out/'acquire64.stderr').open('wb')as stderr:
  r=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=C.BUDGET['new64'])
 C.need(r.returncode==0,'complete original64 authentication required');C.materialized(core)
 companion=C.ROOT/'lane/baseline_inputs.py';spec=importlib.util.spec_from_file_location('core_baseline_companion',companion);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);baseline_inputs=m.prepare(out,deadline)
 import native248_cache
 native248=native248_cache.seed(out,deadline)
 C.save(out/'prefetch.json',dict(scope=C.SCOPE,status='EXACT_EXISTING_ARCHIVE_TRANSPORTS_ONLY',rows=rows,baseline_inputs=baseline_inputs,recovery_cache=recovered,native248_cache=native248,archive_carrier=archive_carrier,trust='ORIGINAL_NATIVE574_SIGNATURE_CHECKS_STILL_MANDATORY'))
 print('PASS: original exact archive32/20/8 transports; native authority NOT_RUN')

if __name__=='__main__':main()
