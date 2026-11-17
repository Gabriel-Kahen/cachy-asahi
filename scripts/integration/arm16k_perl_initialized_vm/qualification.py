# SPDX-License-Identifier: MIT
"""Compose existing Source65 contracts with fresh initialized inputs; never issue grants."""
import hashlib,importlib.util,json,time
from pathlib import Path
from types import SimpleNamespace
HERE=Path(__file__).resolve().parent
SOURCE65=dict(bytes=10598,sha256='da1c8749a281b767f50ca696cf7818d1925aa852057d7de011b4c3ddd8eca75d')
RAW=dict(bytes=1610612736,sha256='f30fa96283042b12229b455fe33918facb83a0650a8e7849fcaab493dda366cb')
PREPARED=dict(bytes=20564,sha256='04923eecb2548142f22498f306c2145bcdc35e60b27e3d1ffbd73d7d27ae7f26')
EMPTY_KIND='WARM_PERL_FIXED_POLICY_PATHS_AND_SSH_EMPTY_V1'

FROZEN_MATERIALS=dict(archive=dict(bytes=22071176,sha256='647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22'),signature=dict(bytes=119,sha256='c860013b12243cd560ba99229045e983346c363936b642ba188b5042d860a993'),public_TEST_certificate=dict(bytes=461,sha256='afc1336af3ca67e130de313594cd9836aa700ed84abc7270a9c687969bc555d6'),signing_receipt=dict(bytes=7621,sha256='db5e7067cd94327d372421f6c0144defaac4c98bb94ae260d41dab149409e5ae'))
FIXED_RESOURCES=dict(baseline_raw_bytes=1610612736,prepared_raw_bytes=1610612736,clone_allocated_cap_bytes=1342177280,readback_allocated_cap_bytes=1342177280,overlay_cap_bytes=536870912,logs_cap_bytes=67108864,reserve_bytes=2147483648,owner_memory_bytes=4294967296,guest_memory_bytes=2147483648,host_reserve_bytes=2147483648,cpus=2,pids=256,prepare_seconds=1350,boot_seconds=1200,cleanup_seconds=90,boot_overhead_seconds=120,gpg_seconds=15,install_seconds=60,probe_wait_seconds=400,remove_seconds=60,run_seconds=10,sync_seconds=10,log_bytes=1048576,guest_output_cap_bytes=268435456,case_staging_bytes=33554432,fixture_source_bytes=4194304,package_expanded_bytes=89013101,host_uid=1000,output_device=54)

def need(ok,why):
 if not ok:raise ValueError(why)
def canonical(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(v):
 raw=canonical(v);return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def module(name,root=HERE):
 s=importlib.util.spec_from_file_location('initialized_'+str(root)+'_'+name,root/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def source(expected):
 raw=(HERE/'source.lock.json').read_bytes();actual=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest());need(actual==expected,'explicit new initialized Source lock')
 seal=json.loads(raw);found={}
 for p in HERE.iterdir():
  need(p.is_file() and not p.is_symlink() and p.stat().st_nlink==1 and p.stat().st_mode&0o777==0o644,'closed ordinary initialized Source leaves')
  if p.name!='source.lock.json':
   body=p.read_bytes();found[p.name]=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),mode=0o644)
 need(found==seal['files'],'whole initialized Source membership/body/mode');return actual

def legacy(root):
 root=Path(root);need(root.is_absolute() and not any(p.is_symlink()for p in(root,*root.parents)),'explicit ordinary pinned Source65 directory')
 raw=(root/'source.lock.json').read_bytes();need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==SOURCE65,'exact immutable whole Source65 dependency')
 A=module('adapter',root);A.source(SOURCE65['sha256'])
 return SimpleNamespace(root=root,adapter=A,contracts=module('contracts',root),image=module('image',root),preboot=module('preboot',root),privacy=module('ssh_privacy',root))

def empty_inputs(proof,closure):
 need(type(proof)is dict and proof.get('kind')==EMPTY_KIND and {k:proof.get('raw_descriptor',{}).get(k)for k in RAW}==RAW and proof.get('source_lock')==SOURCE65,'new actual empty-proof Source/raw lineage; r72 presence alone refuses')
 need(proof.get('Source65_privacy_gate')==dict(status='REFUSED',category='ValueError',reason='SSH privacy protected target must be absent before inventory') and proof.get('may_prepare_lifecycle')is proof.get('may_use_old_namespace_or_ownership')is False,'old Source65 refusal is retained, never waived')
 need(proof.get('raw_identity_unchanged')is True and proof.get('file_payload_chunks_read')is proof.get('xattr_values_read')is proof.get('symlink_targets_decoded')is False,'bounded privacy proof without private values')
 need(type(closure)is dict and closure.get('status')=='COMPLETE_FINITE_POLICY_METADATA_AND_CLEANUP_ONLY' and closure.get('policy_exit_code')==0 and closure.get('scope_collected_twice')is True and closure.get('canonical_custody')=='SAME_FD_PIDFD_REAL_NB_CLOSE_ONLY' and closure.get('policy_result')==proof,'actual natural owned empty-proof terminal closure')
 ext=closure.get('external',{});need(ext.get('passed')is ext.get('reaped')is True and ext.get('exit')==0 and ext.get('group_census')=='EMPTY_TWICE' and ext.get('ownership')=='REAPED' and ext.get('output_complete')is True and ext.get('error')is None and ext.get('signals')==[] and ext.get('timeout')is False,'actual external natural/reaped empty proof')
 need(type(closure.get('owned_absence_independently_verified'))is list and len(closure['owned_absence_independently_verified'])==3 and closure.get('original_raw',{}).get('unchanged')is True and {k:closure.get('original_raw',{}).get(k)for k in RAW}==RAW,'three independent owned absences and original raw invariance')
 for row in closure['owned_absence_independently_verified']:
  ret=row.get('retirement',{});need(ret.get('passed')is ret.get('reaped')is True and ret.get('exit')==0 and ret.get('group_census')=='EMPTY_TWICE' and ret.get('ownership')=='REAPED' and ret.get('output_complete')is True and ret.get('error')is None and ret.get('signals')==[] and ret.get('timeout')is False,'each independent absence naturally reaped')
 for v in(proof,closure):need(all(v.get(k)is None for k in('Root_acceptance','Perl_baseline_qualification','Perl_preservation','M2','release')),'empty proof grants no later acceptance')
 return module('ssh_empty').require_empty(proof.get('root_ssh_emptiness'))

def authorize_scan(auth,proof,closure,now):
 need(type(auth)is dict and set(auth)==set(json.loads((HERE/'scan-authority.TEMPLATE.json').read_bytes())),'closed opt-in initialized scan declaration')
 need(auth['kind']=='ROOT_INITIALIZED_PERL_READONLY_SCAN_V1' and auth['issued_by']=='Root' and auth['accepted']is True,'new explicit Root opt-in scan authority; default Source65 is unchanged')
 need(auth['raw']==RAW and auth['prepared']==PREPARED and auth['source65_lock']==SOURCE65 and auth['empty_proof']==pin(proof) and auth['empty_closure']==pin(closure),'exact new raw/prepared and fresh complete proof/closure joins')
 need(type(auth['scan_seconds'])is int and 1<=auth['scan_seconds']<=900,'finite explicit scan seconds')
 need(type(now)is int and type(auth['created_utc'])is type(auth['expires_utc'])is int and 0<=now-auth['created_utc']<=3600 and now+auth['scan_seconds']<=auth['expires_utc']<=auth['created_utc']+3600,'finite new Root scan window')
 need(type(auth['scan_seconds'])is int and 1<=auth['scan_seconds']<=900 and auth['external_resource_enforcement']=='ROOT_CUSLS_WHOLE_PROCESS_MEMORY_CPU_PID_QUOTA_AND_OUTPUT_GUARD','bounded existing external enforcement required')
 need(type(auth['output_cap_bytes'])is int and 1<=auth['output_cap_bytes']<=128*1024**2 and auth['uid']==1000 and type(auth['uid'])is int and auth['output']is not None and auth['runtime_profile']is not None,'explicit bounded output, original host UID and runtime binding')
 source(auth['source_lock']);empty_inputs(proof,closure);return legacy(auth['source65_directory'])

def baseline_selection(base):
 need(type(base)is dict and base.get('raw')==RAW and base.get('prepared')==PREPARED,'new initialized raw/prepared certificate required; cold or no-package certificate is not reusable')
 return base


def qualify(document,scan,proof,closure,case,observed,certificates,scan_certificate):
 """Pure DATA join; Root supplies freshly issued certificates after actual scan."""
 need(type(document)is dict and set(document)==set(json.loads((HERE/'qualification.TEMPLATE.json').read_bytes())),'closed initialized qualification declaration')
 need(document['kind']=='ROOT_INITIALIZED_PERL_QUALIFICATION_INPUTS_V1' and document['issued_by']=='Root' and document['accepted']is True,'new Root qualification selection')
 source(document['source_lock']);need(document['source65_lock']==SOURCE65,'unchanged Source65 contracts')
 empty_inputs(proof,closure);dependency=legacy(document['source65_directory']);K,I=dependency.contracts,dependency.image
 need(document['empty_proof']==pin(proof) and document['empty_closure']==pin(closure),'new actual proof and closure pinned; no cold certificates')
 need(set(certificates)==set(K.EVIDENCE),'all existing Source65 evidence roles required')
 need(all(document[n]==K.json_pin(certificates[n])for n in K.EVIDENCE),'explicit fresh certificate byte joins')
 base=certificates['baseline_certificate'];runtime=certificates['runtime_certificate'];baseline_selection(base);inventory=K.baseline(base)
 need(len(inventory)==111 and 'perl'not in inventory and 'db5.3'not in inventory,'same fixed common111 initialized baseline, not installed package state')
 need(all(case['package'][k]==v for k,v in FROZEN_MATERIALS.items()),'same frozen package archive/signature/public TEST certificate/receipt')
 need(all(case['trust'][k]==v for k,v in dict(fingerprint='FECBCDECD0E8F525E9F5E64221EFA8518F14040E',created_utc=1794743263,expires_utc=1794916063,public_only=True,revoked=False,signature_valid=True).items()),'same frozen TEST certificate validity and authenticated signer; no extension or resigning')
 resources=certificates['resource_certificate'];need(all(resources[k]==v for k,v in FIXED_RESOURCES.items()) and resources['baseline_allocated_bytes']==634167296,'same finite lifecycle/resource limits with actual warmed allocation')
 need(resources['guest_filesystem_free_bytes']==scan['filesystem_free_bytes'] and resources['quota_guard']['source_lock']==document['source_lock'],'new actual free geometry and new Source resource binding')
 need(base['raw']==RAW and base['prepared']==PREPARED,'only the actual initialized raw/prepared; cold baseline rejects')
 owned=I.owners(scan,inventory);need(K.json_pin(owned)==base['ownership'],'complete new initialized ALPM ownership, not 111-name equivalence')
 namespace=K.json_pin({p:I.stable(row)for p,row in scan['nodes'].items()});need(namespace==runtime['baseline_namespace_pin'] and namespace==document['namespace'],'complete new initialized namespace pin')
 expected_scan=dict(kind='ROOT_BOUND_INITIALIZED_PERL_SCAN_V1',issued_by='Root',accepted=True,source_lock=document['source_lock'],source65_lock=SOURCE65,raw=RAW,prepared=PREPARED,empty_proof=pin(proof),empty_closure=pin(closure),namespace=namespace,ownership=K.json_pin(owned),records=K.json_pin(scan['records']),scan=K.json_pin(scan),Root_acceptance=None,Perl_preservation=None,VM_acceptance=None,M2=None,release=None)
 need(scan_certificate==expected_scan and document['scan_certificate']==pin(scan_certificate),'new Root-bound complete scan provenance; metadata-only or cold observations reject')
 I.qualify(scan,runtime['baseline_files'],owned)
 validated=K.validate(case,observed,**certificates) # Signatures/dependencies/resources/recovery unchanged.
 snap=module('policy').snapshot(scan);need(K.json_pin(snap)==document['initialized_state'],'exact public9 and empty SSH/parent initial-state join')
 need(scan['root_ssh_empty_proof']==proof['root_ssh_emptiness'],'same exact live empty aggregate on the qualified raw')
 return dict(status='VALIDATED_INITIALIZED_PERL_INPUTS_DATA_ONLY',raw=RAW,prepared=PREPARED,namespace=namespace,ownership=K.json_pin(owned),initialized_state=K.json_pin(snap),Source65_validation=validated,Root_acceptance=None,Perl_preservation=None,VM_acceptance=None,M2=None,release=None)
