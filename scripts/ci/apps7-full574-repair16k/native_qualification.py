# SPDX-License-Identifier: MIT
"""Finite Root decision DATA predicates; caller must authenticate carrier+byte pins."""
import copy,json

SOURCE='c89868439988f99d4179d208d1198f6f9c94d5d5'
MANIFEST='c37c946199b43052594ece0ac24ae89a5cc77aa615ccf0b0abda9f28e3950a65'
PACKET='54352850a57a7e34e75c3a021fa20525eee59bf6'
CASES=('repair-bytes','repair-missing')
VERSIONS={'cachy-asahi-repository-runtime':'0.1.0-1','cachy-asahi-apps':'0.1.0-7','cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-2'}
RETAINED_SCOPE={
 'source_full_node_replay':'PASS_ORIGINAL_SOURCE_ONLY',
 'copied_root_preservation':'SOURCE_ENFORCED_RAW_MAPS_NOT_EXPORTED',
 'signature_cryptographic_reverification':'NOT_RUN_PASSIVE_NO_SUBPROCESSES',
 'live_cleanup_reobservation':'NOT_RUN_RETAINED_ORDERED_RECEIPTS_ONLY',
}
LITERALS={'status':'ROOT_ACCEPTED_NATIVE_APPS7_FULL574_SIGNED_REPAIR_CASE',
 'readonly_inspection':'PASS_AUTHENTICATED_NONCOMMIT_BEFORE_PINS',
 'cleanup':'PASS','ordered_cleanup':'PASS_RETAINED_ORDERED_SEVEN_ACTORS_THEN_PRODUCER',
 'generic16K':'NOT_RUN','hardware':'NOT_RUN','release':'NOT_ADMITTED'}
COUNTS={'schema_version':1,'attempt':1,'committed_transactions':4,'zero_commit_refusals':3,'strict_inspect_refusals':1}
SCHEMA_FIELDS=frozenset((*LITERALS,*COUNTS,'source_sha','source_manifest_sha256','packet_source','case','run_id','versions','counts','retained_scope'))
MAX_BYTES=65536

def need(ok,why):
 if not ok:raise ValueError(why)
def default_decisions():return {case:None for case in CASES}
def decode(raw):
 need(type(raw)is bytes and 0<len(raw)<=MAX_BYTES,'bounded native qualification JSON')
 def pairs(rows):
  value={}
  for k,v in rows:need(k not in value,'duplicate native qualification key');value[k]=v
  return value
 value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite native qualification JSON'))
 need(type(value)is dict,'native qualification JSON object');return value

def validate_record(case,record):
 need(type(case)is str and case in CASES,'explicit native repair case')
 need(type(record)is dict,'native repair decision NULL/UNSUPPLIED')
 need(type(record.get('source_sha'))is str and record['source_sha']==SOURCE,'same exact native repair source required')
 need(set(record)==SCHEMA_FIELDS and all(type(k)is str for k in record),'closed native qualification schema')
 for key,value in (('source_manifest_sha256',MANIFEST),('packet_source',PACKET),('case',case),*LITERALS.items()):
  need(type(record[key])is str and record[key]==value,'native qualification '+key)
 for key,value in COUNTS.items():need(type(record[key])is int and record[key]==value,'native qualification '+key)
 need(type(record['counts'])is list and all(type(n)is int for n in record['counts'])and record['counts']==[578,575,574],'native qualification counts')
 need(type(record['versions'])is dict and all(type(k)is str and type(v)is str for k,v in record['versions'].items())and record['versions']==VERSIONS,'native qualification versions')
 need(type(record['retained_scope'])is dict and all(type(k)is str and type(v)is str for k,v in record['retained_scope'].items())and record['retained_scope']==RETAINED_SCOPE,'native qualification retained/export scope')
 need(type(record['run_id'])is int and 0<record['run_id']<2**63,'actual native run identity required')
 need(len((json.dumps(record,sort_keys=True,indent=2,allow_nan=False)+'\n').encode())<=MAX_BYTES,'bounded native qualification record')
 return copy.deepcopy(record)

def validate(decisions):
 need(type(decisions)is dict and set(decisions)==set(CASES),'both exact native repair decisions required')
 need(all(type(decisions[c])is dict for c in CASES),'native repair decisions NULL/UNSUPPLIED')
 runs=[decisions[c].get('run_id')for c in CASES]
 need(all(type(n)is int and 0<n<2**63 for n in runs),'actual distinct native run identities required')
 need(len(set(runs))==2,'distinct native repair-case runs required')
 return {case:validate_record(case,decisions[case])for case in CASES}
