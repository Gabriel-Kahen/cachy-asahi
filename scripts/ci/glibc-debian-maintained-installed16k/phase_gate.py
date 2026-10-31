# SPDX-License-Identifier: MIT
"""Current maintained candidate actual normal-life plus staged16K prerequisites."""
import re
PAIR=dict(source_sha='78dfd3bbd85a61a84dda2dfc601796ee89edfd5f',run_id=38994309021,archive_sha256='a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9',payload=dict(node_count=1592,node_manifest_sha256='db12785a1e49a16cefe82bcad2aee0a776c3d5b78b1f767f54c4ebb28700c574'))
ARCHIVE_BYTES=18598440
STATUSES=dict(native_lifecycle='ROOT_ACCEPTED_DEBIAN_MAINTAINED_PROVIDER_NORMAL_LIFECYCLE',system16k='ROOT_ACCEPTED_DEBIAN_MAINTAINED_SYSTEM_PATHS_GENERIC16K')

def validate(C,acceptances):
 policy=C.decode(C.read(C.HERE/'input-policy.json',65536))
 C.need(policy['schema_version']==1 and policy['status']=='BOUND_BY_ROOT' and type(policy['binding']) is dict,'UNBOUND maintained installed16K: actual current normal lifecycle and staged16384 decisions required before outputs or actors')
 C.need(set(policy['binding'])==set(STATUSES),'normal lifecycle plus staged16K only, no interruption prerequisite')
 G=C.load('current_candidate_gate',C.HERE/'candidate_gate.py');G.identity(policy.get('candidate'));C.need(policy['native_pair']==PAIR,'exact independently accepted current native pair metadata')
 result={}
 for kind,status in STATUSES.items():
  row=C.decode(C.read(C.ref(acceptances,policy['binding'][kind],128*1024),128*1024));G.identity(row.get('candidate'))
  C.need(row['status']==status and row['hardware']=='NOT_RUN' and row['release']=='NOT_ADMITTED' and row['source_authority_sha256']==G.EXPECTED['authority_sha256'] and row['native_pair']==PAIR and row['provider_archive_sha256']==PAIR['archive_sha256'] and row['provider_archive_bytes']==ARCHIVE_BYTES,'actual current caa3 identity/authority/archive and native pair join required')
  C.need(re.fullmatch('[0-9a-f]{40}',row['source_sha']) and type(row['run_id']) in (int,str) and re.fullmatch('[1-9][0-9]{0,19}',str(row['run_id'])) and row['source_sha']!=G.EXPECTED['source_packet_ref'] and str(row['run_id'])!=str(PAIR['run_id']),'actual distinct lifecycle/runtime execution, not pair/source carrier')
  if kind=='native_lifecycle':C.need(row['ordered_cleanup']=='PASS' and row['ALPM_installation']=='PASS' and row['page_size']==4096,'actual normal ALPM-installed native lifecycle and cleanup required')
  else:C.need(row['cleanup']=='PASS' and row['page_size']==16384 and row['scope']=='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION' and row['ALPM_installation']=='NOT_RUN','actual staged-only16384 normal-interpreter runtime and cleanup required')
  result[kind]=row
 C.need(result['native_lifecycle']['source_sha']!=result['system16k']['source_sha'] and str(result['native_lifecycle']['run_id'])!=str(result['system16k']['run_id']),'independent native lifecycle and staged runtime decisions')
 return result
