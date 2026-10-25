# SPDX-License-Identifier: MIT
"""Exactly six archive inputs, fresh same-producer TEST signatures, no builds."""
import contextlib,hashlib,json,re,shutil,subprocess,sys
from pathlib import Path
import latest_plan as P
import latest_selection as S

@contextlib.contextmanager
def aliases(values):
 sentinel=object();saved={k:sys.modules.get(k,sentinel)for k in values};sys.modules.update(values)
 try:yield
 finally:
  for k,v in saved.items():
   if v is sentinel:sys.modules.pop(k,None)
   else:sys.modules[k]=v

def apis(source,base,G):
 def load(role,root,lane):
  home=root/'scripts/ci'/lane;C=G.module('_latest_'+role+'_input_contract',home/'contract.py');I=G.module('_latest_'+role+'_whole_native_inputs',home/'inputs.py',{'contract':C});return C,I
 return dict(apps=load('apps',base/'copyworker','current606-apps7-copy'),doctor=load('doctor',source/'roles/doctor-worker','current606-doctor2-copy'),ksm=load('ksm',source/'roles/ksm-worker','current606-ksm2-copy'))

def inspect(source,base,packets,G,checks,*,apps8_packet,extra_packets):
 P.need(type(packets)is dict and set(packets)==set(S.PACKETS),'exact five public packet operands')
 modules=apis(source,base,G);out={}
 for role,(C,I)in modules.items():
  with aliases({'contract':C}):value=I.inspect(packets[role]/'payload')
  if role=='apps':value=value['cachy-asahi-apps']
  out[role]=dict(archive=value.get('path',value.get('archive')),payload=value['payload'],authority='EXACT_ACCEPTED_NATIVE_PAIR_INPUT_ONLY')
 W=G.module('_latest_welcome7_pure_data',source/'welcome7_inputs.py');value=W.inspect(packets['welcome']/'payload',checks);out['welcome']=value
 with aliases({'accepted_inputs':G.A}):value=G.A.inspect(packets['boot']/'payload',checks)
 out['boot']=value
 import apps8_inputs as A8
 prior_apps8=A8.inspect(apps8_packet,checks)
 import next_inputs as NEXT
 new=NEXT.inspect(extra_packets,checks);out.update(apps=new['apps16'],welcome=new['welcome8'],setup=new['setup6']);out['_previous_apps8']=prior_apps8['custody'];out['_new_custody']=new['custody']
 for role,_,_,version in P.PRODUCTS:
  v=out[role];r=checks.package(v['archive']);P.need(not r['errors']and r['metadata']['.PKGINFO']['pkgname']==[P.product(role)[1]]and r['metadata']['.PKGINFO']['pkgver']==[version]and not any(r['metadata']['.PKGINFO'].get(k)for k in('install','backup','replaces','conflict')),'exact complete fixed tool archive/dependency metadata before signing');v['report']=r
 return out

def make(*,source,base,packets,producer,ready604,output,C,G,checks,nonce,apps8_packet,extra_packets):
 P.need(re.fullmatch('[a-f0-9]{32}',nonce or'')and not output.exists()and output.parent.is_dir(),'fresh owned source-nonce input context')
 candidates=inspect(source,base,packets,G,checks,apps8_packet=apps8_packet,extra_packets=extra_packets);manifest=C.read(ready604/'manifest.json');roles=manifest['preparation']['signer_roles'];P.need(set(roles)=={'ephemeral_TEST','upstream_ALARM'}and len(set(roles.values()))==2 and all(re.fullmatch('[A-F0-9]{40}',v or'')for v in roles.values()),'same original producer signer roles')
 keys=manifest['keyrings'];P.need(len(keys)==2 and{r['path']for r in keys}=={'keys/TEST-public.asc','keys/archlinuxarm.gpg'},'same original two public keys')
 for row in keys:P.need(C.sha(ready604/row['path'])==row['sha256']and(ready604/row['path']).stat().st_size==row['size'],'whole original public key bytes')
 products={r['name']:r for r in manifest['packages']};P.need(len(products)==604 and products['cachy-asahi-repository-runtime']['version']=='0.1.0-1','exact same original604 producer and protected Runtime1')
 output.mkdir(mode=0o700);archives=output/'archives';archives.mkdir(mode=0o700);selected={};sign=[]
 for role,name,old,new in P.PRODUCTS:
  candidate=candidates[role];selected[role]={}
  inputs=[('latest',candidate['archive'],new,candidate['report'])]
  if old is not None:
   original=products[name];P.need(original['version']==old and original['signer']==roles['ephemeral_TEST'],'same actual original selected archive/version/signer');path=ready604/original['archive'];P.need(C.sha(path)==original['sha256']and path.stat().st_size==original['size'],'whole exact fresh producer original restoration archive');report=checks.package(path);P.need(not report['errors']and report['metadata']['.PKGINFO']['pkgname']==[name]and report['metadata']['.PKGINFO']['pkgver']==[old],'original complete metadata');inputs.insert(0,('original',path,old,report))
  for version_role,path,version,report in inputs:
   target=archives/path.name;P.need(not target.exists(),'unique exact selected archive filename');shutil.copyfile(path,target);P.need(C.sha(target)==report['sha256'],'unsigned accepted/original archive bodies held');payload={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};P.need(payload and all(r['type']=='0'and r['uid']==r['gid']==0 for r in payload.values()),'ordinary root-owned exact selected payload');selected[role][version_role]=dict(name=name,version=version,archive=target.name,bytes=target.stat().st_size,sha256=C.sha(target),payload=payload,metadata=report['metadata']);sign.append(target)
 materializer=C.scoped_load('_latest_whole_original_TEST_signer',base/'held606/held604/scripts/ci/expanded600-installer-vm/materializer.py',{'contract':C});materializer.sign(producer/'private/test-signing',sign,roles['ephemeral_TEST'])
 verifier_api=C.load('_latest_whole_original_public_verifier',base/'held606/held604/scripts/ci/full-composition-installer-vm/producer.py');public=ready604/'keys/TEST-public.asc';verifier=None;home=producer/'private/latest607-public-verifier'
 try:
  verifier=verifier_api.PublicVerifier(home,[public])
  for role,rows in selected.items():
   for kind,row in rows.items():
    archive=archives/row['archive'];signature=archive.with_name(archive.name+'.sig');verifier(archive,signature,roles['ephemeral_TEST']);value=subprocess.run(verifier.argv+['--status-fd=1','--verify',str(signature),str(archive)],capture_output=True,timeout=30,check=True);status=value.stdout.decode();verifier_api.valid_signer(status,roles['ephemeral_TEST']);P.need(len(value.stdout)+len(value.stderr)<=65536 and not re.search(r'\[GNUPG:\] (KEYEXPIRED|SIGEXPIRED|BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYREVOKED|NO_PUBKEY)(?: |\n|$)',status),'complete fresh TEST expiry/revocation/status gates');P.need(C.sha(archive)==row['sha256']and archive.stat().st_size==row['bytes'],'signing preserved every archive body');row['signature']=dict(path=signature.name,bytes=signature.stat().st_size,sha256=C.sha(signature));row['signer']=roles['ephemeral_TEST'];row['verification']=dict(stdout=dict(bytes=len(value.stdout),sha256=hashlib.sha256(value.stdout).hexdigest()),stderr=dict(bytes=len(value.stderr),sha256=hashlib.sha256(value.stderr).hexdigest()),returncode=value.returncode)
 finally:
  if verifier is not None:verifier.close()
  # If construction failed, preserve uncertain home/producer for the original
  # owner refusal path; no guessed cleanup or deletion of private material.
 plan=dict(schema_version=1,status='READY_SIX_EXACT_TOOL_ARCHIVES_FRESH_ORIGINAL_TEST_SIGNATURES',scope='HISTORICAL_ACCEPTED_INPUTS_NO_COMBINED_CREDIT',nonce=nonce,nonce_authority='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION',original604_manifest=dict(bytes=(ready604/'manifest.json').stat().st_size,sha256=C.sha(ready604/'manifest.json')),signer_roles=roles,products=selected,carriers=S.PACKETS,apps8_input=candidates['_previous_apps8'],next_inputs=candidates['_new_custody'],new_tool_builds='NOT_RUN_REUSED_ACCEPTED_NATIVE_ARCHIVES',actual_source=None,actual_ref=None,actual_run=None)
 (output/'input-plan.json').write_bytes(C.encoded(plan))
 for path in output.rglob('*'):
  P.need(not path.is_symlink(),'ordinary exact source input context');path.chmod(0o755 if path.is_dir()else 0o444)
 output.chmod(0o755);return plan
