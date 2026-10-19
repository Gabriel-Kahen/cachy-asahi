"""Unchanged32/20/8 archive transports into original owned574 context."""
import argparse,importlib.util,shutil,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import common as C
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();C.preflight();C.policy();out=C.private(a.output)
C.need(C.load(out/'seed-report.json')['status']=='SIX_EXACT_EXISTING_SEED_FILES_READY','original six seed required')
rows=[]
for n in('32','20','8'):
 path=C.ROOT/'baseline'/('archive'+n+'.py');spec=importlib.util.spec_from_file_location('core_held_archive'+n,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 v=m.policy(C.ROOT/'baseline'/('archive'+n+'-policy.json'),C.ROOT/'baseline/maintained-desktop574-inputs.json')
 cache=out/('archive'+n);index=m.prefetch(cache,v);seed=m.seed_exact(cache,out/'context/deps',v)
 C.save(out/('archive'+n+'-index.json'),index);rows.append(dict(kind=n,helper=C.pin(C.read(path)),policy=C.pin(C.read(C.ROOT/'baseline'/('archive'+n+'-policy.json'))),index=index,seed=seed))
core=out/'materialized-core';shutil.copytree(C.ROOT/'core',core)
cache=core/'builder-context/deps';cache.mkdir(mode=0o700)
command=[sys.executable,'-I','-B',str(C.ROOT/'lane/acquire64.py'),'--core',str(core),'--evidence',str(out/'authentication64')]
with(out/'acquire64.stdout').open('wb')as stdout,(out/'acquire64.stderr').open('wb')as stderr:
 r=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=C.BUDGET['new64'])
C.need(r.returncode==0,'complete original64 authentication required');C.materialized(core)
C.save(out/'prefetch.json',dict(scope=C.SCOPE,status='EXACT_EXISTING_ARCHIVE_TRANSPORTS_ONLY',rows=rows,trust='ORIGINAL_NATIVE574_SIGNATURE_CHECKS_STILL_MANDATORY'))
print('PASS: original exact archive32/20/8 transports; native authority NOT_RUN')
