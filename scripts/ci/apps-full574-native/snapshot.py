#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Extract original stopped574 data and observe it; never execute its auxiliaries."""
import base64,gzip,hashlib,math,os,shutil,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
ROOT=Path('/data/original574')

def metadata_failure(error,extractor):
 """Observe the exact rejected old.records frame; no iterator or archive replay."""
 if type(error) is not ValueError or str(error)!='plain archive metadata; xattrs/unknown PAX refused':return None
 trace=error.__traceback__;frame=None
 for _ in range(32):
  if trace is None:break
  if trace.tb_frame.f_code is getattr(extractor,'apps_original_records',extractor.records).__code__ and trace.tb_frame.f_globals is vars(extractor):frame=trace.tb_frame;break
  trace=trace.tb_next
 if frame is None:return None
 member=frame.f_locals.get('member')
 if type(member) is not extractor.tarfile.TarInfo:return None
 def text(value,cap):
  if type(value) is not str:return dict(type=type(value).__name__,unsupported_shape=True)
  digest=hashlib.sha256();prefix=bytearray();size=0
  for start in range(0,len(value),4096):
   raw=value[start:start+4096].encode('utf8','surrogateescape');digest.update(raw);size+=len(raw)
   prefix.extend(raw[:max(0,cap-len(prefix))])
  return dict(type='parsed-text-utf8-surrogateescape',bytes=size,sha256=digest.hexdigest(),complete=size<=cap,prefix_base64=base64.b64encode(prefix).decode())
 def scalar(value):
  return dict(type=type(value).__name__,repr=text(repr(value),128))
 allowed={'path','linkpath','mtime','atime','ctime'}
 if hasattr(extractor,'apps_original_records'):allowed.add('SCHILY.xattr.security.capability')
 pax=member.pax_headers
 if type(pax) is not dict:return None
 entries=[];unknown=[]
 for key,value in pax.items():
  if len(entries)<8:entries.append(dict(key=text(key,128),value=text(value,512)))
  if key not in allowed and len(unknown)<8:unknown.append(text(key,128))
 value=dict(scope='EXACT_FROZEN_EXTRACTOR_RECORDS_CURRENT_HEADER_METADATA_GUARD_REFUSAL',extractor_function='records',extractor_source_sha256=C.sha(C.read(Path(extractor.__file__))),validated_nodes_before_header=len(frame.f_locals['result']),
  member=dict(name=text(member.name,4096),validated_name=text(frame.f_locals.get('n'),4096),type_hex=member.type.hex(),mode=scalar(member.mode),uid=scalar(member.uid),gid=scalar(member.gid),mtime=scalar(member.mtime),header_offset=scalar(member.offset),payload_offset=scalar(member.offset_data)),
  predicates=dict(uid_nonnegative=member.uid>=0,gid_nonnegative=member.gid>=0,mtime_finite=math.isfinite(member.mtime),mode_in_range=0<=member.mode<=0o7777,pax_keys_allowed=set(pax)<=allowed),
  pax=dict(count=len(pax),entries=entries,entries_omitted=max(0,len(pax)-8),unknown_keys_count=len(set(pax)-allowed),unknown_keys=unknown),
  semantics='OBSERVATION_ONLY_ORIGINAL_EXCEPTION_REFUSAL_UNCHANGED_NO_ARCHIVE_REREAD_NO_METADATA_STRIP')
 if hasattr(extractor,'apps_adapted_source_sha256'):value['adapted_extractor_source_sha256']=extractor.apps_adapted_source_sha256
 raw=C.encoded(value);C.need(len(raw)<=65536,'bounded first-header diagnostic')
 return dict(bytes=len(raw),sha256=C.sha(raw),value=value)

def main():
 C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_APPS574_SNAPSHOT')=='1' and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned native offline snapshot actor required')
 source=Path('/source');C.source(source);adapter=C.adapter(source)
 derivative=C.load('apps_export_derivative',Path(__file__).with_name('export_extract.py'));old=derivative.isolated(source,adapter.caps,C.read)
 old.DATA=Path('/data');old.ROOT=ROOT
 if '--cleanup' in sys.argv:
  old.cleanup();return
 result=dict(status='FAIL',point='NEVER_STARTED_READONLY_EXACT_OWNED574_IMAGE_ROOTFS',hardware='NOT_RUN')
 try:
  verify='--verify' in sys.argv
  original=C.decode(C.read(Path('/out/snapshot.json'))) if verify else None
  result['extraction']=original['extraction'] if verify else old.extract(Path('/data/source.tar'),ROOT,os.environ['SOURCE_TAR_SHA256'])
  T=C.load('transaction_observer',source/'scripts/apps/transaction.py');budget=T.limits();observed=adapter.measure(ROOT,budget)
  C.need(observed['complete'] is True,'complete original574 closure observation')
  capabilities=result['extraction']['security_capabilities']
  if not verify:
   restored=adapter.caps.restore(ROOT,observed['nodes'],capabilities,budget)
   C.need(restored==capabilities,'extracted full capability map')
   result['extraction']['capability_restoration']='PRESERVED_AND_COMPLETE_NODE_MAP_VERIFIED'
   result['extraction']['security_capabilities_sha256']=adapter.digest(restored)
   Path('/out/extraction.json').write_bytes(C.encoded(result['extraction']))
  actual_caps=adapter.capability_map(ROOT,observed,budget,capabilities)
  C.need(result['extraction']['capability_restoration']=='PRESERVED_AND_COMPLETE_NODE_MAP_VERIFIED' and adapter.digest(actual_caps)==result['extraction']['security_capabilities_sha256'],'exact extracted source capability map receipt')
  apps=C.load('observed_apps',Path('/inputs/apps-source/apps.py'));client,release,_=apps.helpers(Path('/inputs/candidate/usr/share/cachy-asahi/repository-runtime'))
  inventory=apps.inventory_reader().collect(ROOT/T.DB,client,lambda row:apps.package(row,release));rows={r['name']:r['version'] for r in inventory['packages']}
  lock=''.join(n+' '+v+'\n' for n,v in sorted(rows.items())).encode();C.need(len(rows)==574 and C.sha(lock)==C.BASE,'exact actual574 database lock')
  base={k:inventory[k] for k in ('schema_version','target_arch','snapshot_id','packages')};base['kind']='complete-target-transaction'
  state=adapter.aux.checkpoint(ROOT,observed,budget);closure=adapter.digest(adapter.canonical_state(state))
  raw=C.encoded(observed);compressed=gzip.compress(raw,mtime=0);C.need(len(raw)<=256*1024**2 and len(compressed)<=64*1024**2,'bounded full source proof')
  if not verify:
   Path('/out/source-observation.json.gz').write_bytes(compressed);Path('/out/base.json').write_bytes(C.encoded(base));Path('/out/observed-inventory.json').write_bytes(apps.encoded(inventory))
  result.update(status='PASS_ORIGINAL574_APPS_CLOSURE_SNAPSHOT',tree_sha256=T.sha(T.encoded(observed['nodes'])),node_count=len(observed['nodes']),footprint=observed['footprint'],database_lock_sha256=C.sha(lock),source_inode=T.inode(ROOT),
   aux_inode_liveness='NOT_ESTABLISHED_NEVER_EXECUTED_OR_CONSUMED',raw_source_observation_sha256=C.sha(raw),compressed_source_observation_sha256=C.sha(compressed),base_sha256=C.sha(C.encoded(base)),source_packages_sha256=adapter.digest(inventory['packages']),source_closure_sha256=closure,source_capabilities=actual_caps,source_capabilities_sha256=adapter.digest(actual_caps),capability_execution='NOT_RUN_METADATA_ONLY')
  if verify:C.need(all(result[k]==original[k] for k in ('tree_sha256','source_inode','source_packages_sha256','source_closure_sha256','database_lock_sha256','base_sha256','source_capabilities','source_capabilities_sha256')),'source changed after consumers')
 except BaseException as error:
  result.update(error=str(error)[:1024],error_type=type(error).__name__)
  try:
   diagnostic=metadata_failure(error,old)
   if diagnostic is not None:result['failed_archive_metadata']=diagnostic
  except Exception as diagnostic_error:result['metadata_diagnostic_error_type']=type(diagnostic_error).__name__
 finally:
  Path('/out/'+('snapshot-after.json' if '--verify' in sys.argv else 'snapshot.json')).write_bytes(C.encoded(result))
  for path in Path('/out').iterdir():
   C.need(path.is_file() and not path.is_symlink(),'ordinary finite snapshot evidence');os.chown(path,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
  for path in Path('/data').glob('*.json'):os.chown(path,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
 C.need(result['status']=='PASS_ORIGINAL574_APPS_CLOSURE_SNAPSHOT','original574 snapshot failed')
if __name__=='__main__':main()
