# SPDX-License-Identifier: MIT
"""Exact trusted original-decision predicate and finite projection DATA calculation."""
import hashlib,json,re
class C:
 @staticmethod
 def need(ok,why):
  if not ok:raise ValueError(why)
 @staticmethod
 def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
 @staticmethod
 def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
STATUSES={'fresh607': 'ROOT_ACCEPTED_SIGNED_LATEST607_FRESH_INSTALLER', 'baseline607': 'ROOT_ACCEPTED_SIGNED_LATEST607_APPS6_BASELINE'}
FLAGS={'numeric_ownership_verified', 'source_cache_preserved', 'private_trust_verified', 'root_guest_payload_verified', 'namespace_barrier', 'ordinary_parent_nnp_cap0', 'parent_inventory_preserved', 'parent_payload_verified', 'ownership_verified', 'preservation_verified', 'process_retirement', 'database_verified', 'payload_verified', 'committed', 'numeric_namespace_verified'}
PROJECTION_KIND='ROOT_SOURCE_BOUND_INSTALLED_PREREQUISITE_PROJECTION_V1'

def original_decision(kind,row,policy):
 lock=policy['after']if kind=='fresh607'else policy['before']
 C.need(kind in STATUSES and row.get('status')==STATUSES[kind]and
  type(row.get('schema_version'))is int and row['schema_version']==1 and
  re.fullmatch('[0-9a-f]{40}',row.get('source_sha')or'')and
  type(row.get('run_id'))is int and row['run_id']>0 and
  type(row.get('package_count'))is int and row['package_count']==607 and
  row.get('expected607_sha256')==lock['sha256'],'genuine source-bound issued exact607 role/target')
 C.need(type(row.get('ordinary_and_root_flags'))is dict and
  set(row['ordinary_and_root_flags'])==FLAGS and
  all(v is True for v in row['ordinary_and_root_flags'].values()),'all fifteen original ordinary/root flags')
 o=row.get('root_observation');C.need(type(o)is dict and o.get('complete')is True and
  type(o.get('deadline_seconds'))is int and o['deadline_seconds']==600 and
  type(o.get('elapsed_ms'))is int and 0<=o['elapsed_ms']<600000 and
  type(o.get('observed_nodes'))is int and 0<o['observed_nodes']<=200000 and
  type(o.get('missing_database_nodes'))is int and o['missing_database_nodes']==0 and
  o.get('missing_database_samples')==[] and
  type(o.get('footprint'))is dict and type(o['footprint'].get('nodes'))is int and o['footprint']['nodes']==o['observed_nodes']and
  type(o['footprint'].get('bytes'))is int and 0<=o['footprint']['bytes']<=6*1024**3,
  'complete retained independent root report within original readback cap')
 C.need(row.get('cleanup')=='PASS_SOURCE_BOUND_RETAINED_RECEIPTS'and
  row.get('qemu_natural_exit')is True and row.get('hardware')==row.get('M2')=='NOT_RUN'and
  row.get('release')=='NOT_ADMITTED'and type(row.get('limits'))is list and
  row['limits']and all(type(v)is str and 0<len(v)<=2048 for v in row['limits']),
  'original source-bound cleanup/limits retained; no new live absence or FD claim')
 if kind=='fresh607':C.need(row['source_sha']==policy['fresh_source'],'exact current installer source decision')
 return row


def projection(kind,record,policy,before_locks):
 C.need(kind in STATUSES and record is not None,'missing genuine role record remains UNBOUND')
 original=original_decision(kind,record['original'],policy)
 other=C.pin(''.join(n+' '+v+'\n'for n,v in sorted(before_locks.items())if n!='cachy-asahi-apps').encode())
 return dict(schema_version=1,projection_kind=PROJECTION_KIND,target_kind=kind,
  Apps_version='0.1.0-16'if kind=='fresh607'else'0.1.0-6',other606_lock_sha256=other['sha256'],
  record_source=record['source'],record_ref=record['ref'],record_files=record['files'],
  original=original,original_pin=C.pin(C.enc(original)),
  readback='RETAINED_SOURCE_BOUND_ROOT_REPORT_NOT_FRESH_FD_OBSERVATION',
  retirement='SOURCE_BOUND_RETAINED_RECEIPTS_NOT_LIVE_REOBSERVATION',
  scope='ONE_INSTALLED_PREREQUISITE_NOT_UPDATER_ACCEPTANCE')

