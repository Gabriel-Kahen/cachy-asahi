#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Extract original stopped574 data and observe it; never execute its auxiliaries."""
import gzip,hashlib,os,shutil,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
ROOT=Path('/data/original574')

def main():
 C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_APPS574_SNAPSHOT')=='1' and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned native offline snapshot actor required')
 source=Path('/source');C.source(source);old=C.load('original_export',source/'scripts/ci/glibc-gnu-provider-lifecycle-owner/snapshot.py')
 old.DATA=Path('/data');old.ROOT=ROOT
 if '--cleanup' in sys.argv:
  old.cleanup();return
 result=dict(status='FAIL',point='NEVER_STARTED_READONLY_EXACT_OWNED574_IMAGE_ROOTFS',hardware='NOT_RUN')
 try:
  verify='--verify' in sys.argv
  original=C.decode(C.read(Path('/out/snapshot.json'))) if verify else None
  result['extraction']=original['extraction'] if verify else old.extract(Path('/data/source.tar'),ROOT,os.environ['SOURCE_TAR_SHA256'])
  if not verify:Path('/out/extraction.json').write_bytes(C.encoded(result['extraction']))
  adapter=C.adapter(source);T=C.load('transaction_observer',source/'scripts/apps/transaction.py');budget=T.limits();observed=adapter.measure(ROOT,budget)
  C.need(observed['complete'] is True,'complete original574 closure observation')
  apps=C.load('observed_apps',Path('/inputs/apps-source/apps.py'));client,release,_=apps.helpers(Path('/inputs/candidate/usr/share/cachy-asahi/repository-runtime'))
  inventory=apps.inventory_reader().collect(ROOT/T.DB,client,lambda row:apps.package(row,release));rows={r['name']:r['version'] for r in inventory['packages']}
  lock=''.join(n+' '+v+'\n' for n,v in sorted(rows.items())).encode();C.need(len(rows)==574 and C.sha(lock)==C.BASE,'exact actual574 database lock')
  base={k:inventory[k] for k in ('schema_version','target_arch','snapshot_id','packages')};base['kind']='complete-target-transaction'
  state=adapter.aux.checkpoint(ROOT,observed,budget);closure=adapter.digest(adapter.canonical_state(state))
  raw=C.encoded(observed);compressed=gzip.compress(raw,mtime=0);C.need(len(raw)<=256*1024**2 and len(compressed)<=64*1024**2,'bounded full source proof')
  if not verify:
   Path('/out/source-observation.json.gz').write_bytes(compressed);Path('/out/base.json').write_bytes(C.encoded(base));Path('/out/observed-inventory.json').write_bytes(apps.encoded(inventory))
  result.update(status='PASS_ORIGINAL574_APPS_CLOSURE_SNAPSHOT',tree_sha256=T.sha(T.encoded(observed['nodes'])),node_count=len(observed['nodes']),footprint=observed['footprint'],database_lock_sha256=C.sha(lock),source_inode=T.inode(ROOT),
   aux_inode_liveness='NOT_ESTABLISHED_NEVER_EXECUTED_OR_CONSUMED',raw_source_observation_sha256=C.sha(raw),compressed_source_observation_sha256=C.sha(compressed),base_sha256=C.sha(C.encoded(base)),source_packages_sha256=adapter.digest(inventory['packages']),source_closure_sha256=closure)
  if verify:C.need(all(result[k]==original[k] for k in ('tree_sha256','source_inode','source_packages_sha256','source_closure_sha256','database_lock_sha256','base_sha256')),'source changed after consumers')
 except BaseException as error:result.update(error=str(error)[:1024],error_type=type(error).__name__)
 finally:
  Path('/out/'+('snapshot-after.json' if '--verify' in sys.argv else 'snapshot.json')).write_bytes(C.encoded(result))
  for path in Path('/out').iterdir():
   C.need(path.is_file() and not path.is_symlink(),'ordinary finite snapshot evidence');os.chown(path,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
  for path in Path('/data').glob('*.json'):os.chown(path,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
 C.need(result['status']=='PASS_ORIGINAL574_APPS_CLOSURE_SNAPSHOT','original574 snapshot failed')
if __name__=='__main__':main()
