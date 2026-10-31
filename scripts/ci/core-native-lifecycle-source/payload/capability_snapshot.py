#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""GNU owned snapshot: pinned plain extractor plus exact capability preservation."""
import argparse,gzip,json,os,platform,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import owner as J
DATA=Path('/data');ROOT=DATA/'original574';OUT=Path('/out')
LANE='scripts/ci/glibc-gnu-provider-lifecycle'

def observe(source,api,mapping):
 budget=api['roots'].Limits(deadline=time.monotonic()+600,max_packages=574,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3)
 value=api['roots'].observe(ROOT,limits=budget,hardlinks='generic-development-internal')
 J.need(value['complete'] is True and set(value['unsupported_counts'])<={'absolute-symlink','auxiliary-present'},'complete original574 root observation')
 actual=api['caps'].restore(ROOT,value['nodes'],mapping,budget)
 J.need(actual==mapping,'exact complete original574 extracted capability map')
 rows=api['db'].database(ROOT,max_packages=574,max_files=100000,max_nodes=500000)
 lock=''.join(p['name']+' '+p['version']+'\n' for p in sorted(rows,key=lambda r:r['name'])).encode()
 J.need(len(rows)==574 and J.hashlib.sha256(lock).hexdigest()==J.LOCK,'exact original574 database from stopped-image export')
 import root_link_selection,aux_checkpoint
 root_link_selection.check(value,budget);aux_checkpoint.checkpoint(ROOT,value,budget)
 raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();compressed=gzip.compress(raw,mtime=0)
 J.need(len(raw)<=256*1024**2 and len(compressed)<=64*1024**2,'source observation export bound');(OUT/'original574-root.json.gz').write_bytes(compressed)
 return dict(node_sha256=J.hashlib.sha256(json.dumps(value['nodes'],sort_keys=True).encode()).hexdigest(),observation_sha256=J.hashlib.sha256(raw).hexdigest(),compressed_sha256=J.hashlib.sha256(compressed).hexdigest(),nodes=len(value['nodes']),database_sha256=J.hashlib.sha256(lock).hexdigest(),packages=574,shape='COMPLETE_SELECTED_ORIGINAL574_WITH_HELD_AUXILIARY_AND_INTERNAL_LINKS',security_capabilities=actual,source_capabilities_sha256=api['capabilities'].digest(actual),capabilities='PRESERVED_AND_COMPLETE_NODE_MAP_VERIFIED')

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--cleanup',action='store_true');args=parser.parse_args()
 J.need(os.getuid()==os.geteuid()==0 and platform.machine()=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_GNU_PROVIDER_SNAPSHOT')=='1','owned native observer only')
 J.need(DATA.is_mount() and not DATA.is_symlink() and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'explicit private data bind/offline namespace')
 source=Path('/source');common=J.load('snapshot_common',source/LANE/'common.py');api=common.helpers(source)
 derivative=J.load('Apps_pinned_export',source/'scripts/ci/apps-full574-native/export_extract.py')
 old=derivative.isolated(source,api['caps'],lambda p:common.read(p));old.DATA=DATA;old.ROOT=ROOT
 if args.cleanup:old.cleanup();return
 result=dict(status='FAIL',snapshot_point='NEVER_STARTED_READONLY_CONTAINER_OF_EXACT_FRESH_OWNED574_IMAGE',hardware='NOT_RUN')
 try:
  result['extraction']=old.extract(DATA/'source.tar',ROOT,os.environ['SOURCE_TAR_SHA256']);result['observation']=observe(source,api,result['extraction']['security_capabilities'])
  result['extraction'].update(capability_restoration='PRESERVED_AND_COMPLETE_NODE_MAP_VERIFIED',security_capabilities_sha256=result['observation']['source_capabilities_sha256']);result['status']='PASS_ORIGINAL574_DATA_SNAPSHOT'
 except BaseException as error:result.update(error_type=type(error).__name__,error=str(error)[:512])
 finally:
  (OUT/'snapshot.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
  uid,gid=int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID'])
  for path in OUT.iterdir():J.need(path.is_file() and not path.is_symlink(),'ordinary snapshot evidence');os.chown(path,uid,gid)
  for path in DATA.glob('*.json'):os.chown(path,uid,gid)
 J.need(result['status']=='PASS_ORIGINAL574_DATA_SNAPSHOT','source snapshot failed')
if __name__=='__main__':main()
