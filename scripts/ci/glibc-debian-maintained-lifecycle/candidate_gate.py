# SPDX-License-Identifier: MIT
"""Additional caa3 identity joins; original crypto/ALPM/runtime gates remain mandatory."""
import hashlib,json,re
EXPECTED=dict(package='cachy-asahi-glibc-gnu-provider',version='2.43.caa3-1',
 source_packet_ref='60e174c5db7f770c94064198516dd3ee07b51b7b',
 authority_sha256='88643eabd61a39df63ecaeb50bb20041d17cf4fd3adee55d82d43d3c1ca08707',
 prepared_tree='08ea2aef96bd3144cf02cbc68cbbb003dc25ed9f',
 pkgbuild_sha256='9d6d5e688c95febe85321abc69fbfe1b7781a02e318771ae43851d8c29f68bb8')
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def identity(value):need(value==EXPECTED,'exact new maintained Debian caa3 identity/source authority required');return value

def payload(candidate,receipt):
 nodes=candidate['nodes'];expected=receipt['payload']
 need(set(expected)=={'node_count','node_manifest_sha256'} and type(expected['node_count']) is int and 0<expected['node_count']<=60000,'actual caa3 payload traits required')
 need(len(nodes)==expected['node_count'] and hashlib.sha256(encoded(nodes)).hexdigest()==expected['node_manifest_sha256'],'new actual caa3 complete package node map differs')
 return expected

def validate(C,root,value,candidate=None):
 identity(value.get('candidate'))
 # This reference must be part of the same Root-frozen immutable packet closure.
 authority=value['source_authority']
 if value['status']=='ROOT_ACCEPTED_PROVIDER_LIFECYCLE_INPUTS':need(value['files'].get(authority['path'])=={k:authority[k] for k in ('bytes','sha256')},'authority joins immutable packet closure')
 path=C.ref(root,authority,65536)
 need(authority['bytes']==15506 and authority['sha256']==EXPECTED['authority_sha256'],'exact Root new source-authority decision pin')
 decision=json.loads(C.read(path,65536));need(decision['status']=='ROOT_ACCEPTED_DEBIAN_MAINTAINED_SOURCE_AUTHORITY' and decision['candidate']['version']==EXPECTED['version'] and decision['candidate']['prepared_tree']==EXPECTED['prepared_tree'] and decision['release']=='NOT_ADMITTED','new source-only authority decision required; no native credit')
 receipts={k:json.loads(C.read(C.ref(root,value[k]))) for k in ('provider_pair','probe_receipt','private16k')}
 for role,row in receipts.items():identity(row.get('candidate'))
 pair=receipts['provider_pair'];normal=receipts['probe_receipt'];private=receipts['private16k']
 need(pair['status']=='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR' and pair['hardware']=='NOT_RUN' and re.fullmatch('[0-9a-f]{40}',pair.get('source_sha','')) and re.fullmatch('[1-9][0-9]{0,19}',str(pair.get('run_id',''))),'actual Root caa3 native pair required')
 need(value['archives']['a']['sha256']==value['archives']['b']['sha256']==pair['archive_sha256'] and value['provider_pkgbuild_sha256']==pair['provider_pkgbuild_sha256']==EXPECTED['pkgbuild_sha256'],'new actual archive pair/BUILDINFO recipe join')
 need(normal['status']=='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES' and normal['source_sha']==pair['source_sha'] and str(normal['run_id'])==str(pair['run_id']) and normal['files']==value['probes'],'new actual normal compiler-probe receipt join')
 need(private['status']=='ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME' and private['native_source']==pair['source_sha'] and re.fullmatch('[0-9a-f]{64}',private['candidate_package_sha256']),'current-candidate actual private16K prerequisite; old GNU/caa2 runtime cannot transfer')
 if value['status']!='ROOT_ACCEPTED_PROVIDER_LIFECYCLE_INPUTS':need(private['candidate_package_sha256']==value['private16k_archive_sha256'],'bound current private16K archive join')
 # Original checks still require byte equality, package metadata/layout, ordinary
 # ELF interpreter, eight runtime cases, signatures and complete ownership.
 if candidate is None:
  first=C.ref(root,value['archives']['a']);second=C.ref(root,value['archives']['b'])
  need(C.read(first,256*1024**2)==C.read(second,256*1024**2),'new actual byte-identical pair required');candidate=C.archive(first)
 need(candidate['metadata']['pkgname']==[EXPECTED['package']] and candidate['metadata']['pkgver']==[EXPECTED['version']],'actual caa3 archive identity')
 payload(candidate,pair)
 return dict(candidate=EXPECTED,native_source=pair['source_sha'],native_run=pair['run_id'],payload=pair['payload'],authority='SOURCE_ONLY_NOT_RELEASE_ADMISSION')
