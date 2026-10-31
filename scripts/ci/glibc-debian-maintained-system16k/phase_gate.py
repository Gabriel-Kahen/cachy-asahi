# SPDX-License-Identifier: MIT
"""First maintained-candidate16K inputs: pair+normal+held, never a prior16K."""
import json,re
SHARED='scripts/ci/glibc-debian-maintained-lifecycle/candidate_gate.py'
STATUS='ROOT_ACCEPTED_PROVIDER_STAGED16K_INPUTS'
def need(ok,message):
 if not ok:raise ValueError(message)
def shared(C):return C.load(C.SOURCE,SHARED)
def provenance(C,value):
 G=shared(C);G.identity(value['candidate']);ref=value['source_authority'];need(set(ref)=={'path','bytes','sha256'} and ref['bytes']==15506 and ref['sha256']==G.EXPECTED['authority_sha256'],'exact maintained source authority pin');row=value['native_pair'];need(set(row)=={'source_sha','run_id','archive_sha256','payload'} and re.fullmatch('[0-9a-f]{40}',row['source_sha']) and row['source_sha']!=G.EXPECTED['source_packet_ref'] and re.fullmatch('[1-9][0-9]{0,19}',str(row['run_id'])) and re.fullmatch('[0-9a-f]{64}',row['archive_sha256']),'actual maintained native pair provenance');return value

def validate(C,root,value):
 G=shared(C);G.identity(value.get('candidate'));need(value['status']==STATUS and not {'private16k','private16k_archive_sha256'}&value.keys(),'first16K phase refuses prior/private16K gate');files=value['files'];need(8<=len(files)<=256 and sum(r['bytes'] for r in files.values())<=512*1024**2,'unchanged256files/512MiB packet bounds')
 def ref(row,cap=256*1024**2):
  need(files.get(row['path'])=={k:row[k] for k in ('bytes','sha256')},'reference joins complete staged packet closure');return C.ref(root,row,cap)
 authority=value['source_authority'];need(authority['bytes']==15506 and authority['sha256']==G.EXPECTED['authority_sha256'],'exact new source authority decision');decision=json.loads(C.read(ref(authority,65536),65536));need(decision['status']=='ROOT_ACCEPTED_DEBIAN_MAINTAINED_SOURCE_AUTHORITY' and decision['candidate']['name']==G.EXPECTED['package'] and decision['candidate']['version']==G.EXPECTED['version'] and decision['candidate']['prepared_tree']==G.EXPECTED['prepared_tree'] and decision['release']=='NOT_ADMITTED','source-only authority never supplies native credit')
 pair=json.loads(C.read(ref(value['provider_pair'])));normal=json.loads(C.read(ref(value['probe_receipt'])));G.identity(pair.get('candidate'));G.identity(normal.get('candidate'))
 need(pair['status']=='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR' and pair['hardware']=='NOT_RUN' and re.fullmatch('[0-9a-f]{40}',pair.get('source_sha','')) and pair['source_sha']!=G.EXPECTED['source_packet_ref'] and re.fullmatch('[1-9][0-9]{0,19}',str(pair.get('run_id',''))),'actual new maintained native pair acceptance required')
 need(value['provider_pkgbuild_sha256']==pair['provider_pkgbuild_sha256']==G.EXPECTED['pkgbuild_sha256'] and value['archives']['a']['sha256']==value['archives']['b']['sha256']==pair['archive_sha256'],'new pair archives/actual recipe join')
 need(normal['status']=='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES' and normal['source_sha']==pair['source_sha'] and str(normal['run_id'])==str(pair['run_id']) and normal['files']==value['probes'] and set(normal['compile_receipts'])=={'a','b'},'matching new original normal compiler/probe decisions')
 for row in [value['held'],*value['archives'].values(),*value['probes'].values(),*normal['compile_receipts'].values()]:ref(row)
 owner=C.load(C.SOURCE,'scripts/ci/glibc-gnu-provider-lifecycle/common.py');candidate=owner.archive(ref(value['archives']['a']));need(candidate['metadata']['pkgname']==[G.EXPECTED['package']] and candidate['metadata']['pkgver']==[G.EXPECTED['version']],'actual new maintained package metadata');G.payload(candidate,pair)
 return dict(source_sha=pair['source_sha'],run_id=pair['run_id'],archive_sha256=pair['archive_sha256'],payload=pair['payload'])
