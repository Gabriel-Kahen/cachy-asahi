# SPDX-License-Identifier: MIT
"""Three exact new public pairs and qualified real-module custody, no composition credit."""
import hashlib,importlib.util,json,re,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCES={'apps10':('a2bbf5edd57a7a31951a1e9060c83698f29302c4',94),'welcome8':('e7ec3f2e7e78ec15d545fa53ec3d1089fa78129b',68),'setup6':('24f8d8ed9de7f4ea1aedcc9624110e553204b36c',384),'onboarding':('2dfef3b189f8343b9a9e94e7833f261145faa337',15),'apps10qualification':('180f3ad1440cd82b16b7b944e86b0ba11a1b238d',15)}
ARCHIVES={'apps10':('cachy-asahi-apps','0.1.0-10',26184,'28142e17a53d5a4d93503a16e768017745d19a0c310469d1f42e7d506013115c'),'welcome8':('cachy-asahi-welcome','0.1.0-8',40400,'1cbb8f5f9fd5f072ba2974837cf10dc7e90edbd236cbf3a34916cd0af3d4b240'),'setup6':('cachy-asahi-setup','0.1.0-6',27188,'a4fc772da0fd460f07380c4bc6bc1396688745907a993fe2591778082dae05c8')}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def load(name,path):s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def profile():
 p=json.loads((HERE/'next-inputs.json').read_bytes());need(p['status']=='EXACT_HISTORICAL_INPUTS_NO_NEW_SIX_TOOL_ACCEPTANCE'and set(p['profiles'])==set(SOURCES)and all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'strict finite input-only NULL actual profile')
 for role,(source,count)in SOURCES.items():
  row=p['profiles'][role];pub,g=row['publication'],row['git'];need(row['source']==pub['source']==g['source']==source and row['ref']==pub['ref']==g['ref']and len(row['files'])==pub['files']==pub['git_joins']==count and g['files']==row['files']and pub['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'and g['status']=='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN'and row['actual']is None and row['new_composition']=='NOT_QUALIFIED','whole original public source/Git input custody '+role)
  d=row['decision'];need(pin((json.dumps(d['value'],sort_keys=True,indent=2)+'\n').encode())==d['pin']==row['files'][d['path']],'whole issued original Root input-only decision '+role)
  if role in ARCHIVES:
   name,version,size,digest=ARCHIVES[role];need({k:row['archive'][k]for k in('bytes','sha256')}==dict(bytes=size,sha256=digest)and row['metadata']['pkgname']==[name]and row['metadata']['pkgver']==[version]and set(row['metadata'])=={'pkgname','pkgver','arch','license','depend','provides','conflict','replaces'},'exact pair/source metadata8 input '+role)
 onboarding=p['profiles']['onboarding']['decision']['value'];need(onboarding['status']=='ROOT_ACCEPTED_FINITE_CURRENT606_APPS7_SETUP6_COEXISTENCE_AND_SOFTWARE_ONBOARDING'and onboarding['source']=='ed4fb355ff939bf269905592ba5d71517ffab373'and onboarding['run']==39742794397 and onboarding['real240_suites']==4 and onboarding['six_installed_module_cases']==6 and onboarding['Runtime1']=='PROTECTED'and onboarding['GUI']==onboarding['hardware']==onboarding['generic16k']=='NOT_RUN','whole actual698 real-module qualification, no new six-tool acceptance')
 return p

def qualification():
 q=profile()['apps10_current606'];need(type(q)is dict,'NULL Apps10 current606 qualification BEFORE ACTORS')
 decision=q['decision'];need(pin((json.dumps(decision,sort_keys=True,indent=2)+'\n').encode())==q['pin'],'complete issued Apps10 current606 decision')
 row=profile()['profiles']['apps10qualification'];need(decision==row['decision']['value']and q['pin']==row['decision']['pin'],'issued decision exactly same genuine15-file public qualification record')
 need((decision['source'],decision['run'],decision['ref'])==('eeb7fc5c3bcaa5b152ca6eb97983f6c31f8d0cdb',39763705456,'codex/apps10-current606-v1'),'exact independently qualified Apps10/current606 source/run')
 need(decision['status']=='ROOT_ACCEPTED_FINITE_APPS10_CURRENT606_NATIVE_LIFECYCLE'and decision['counts']==[606,606,606,606,605,606,606,606]and decision['selected_versions']==['0.1.0-6','0.1.0-7','0.1.0-10','0.1.0-10',None,'0.1.0-10','0.1.0-7','0.1.0-6']and decision['transactions']==7 and decision['signed_installs']==6 and decision['installed_controls']==150 and decision['ordinary_homes']==['fresh','existing'],'whole separate Apps10 ordinary installed lifecycle, not combined credit')
 need(decision['other605']=='SOURCE_ENFORCED_FULL_PRIVATE_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPABILITY_PRESERVATION'and decision['Runtime1']=='PROTECTED_EXACT_NATIVE_PAIR_NO_TRANSACTION'and decision['selected_inode_restoration']=='NOT_CLAIMED'and decision['release']=='NOT_ADMITTED'and decision['hardware']=='NOT_RUN','full current606 preservation/cleanup qualification only')
 need(decision['source_files']==389 and decision['reader_files']==1695 and decision['public_files']==950 and decision['public_bytes']==43570011 and decision['cleanup']=='ORIGINAL_SOURCE_RECORDED_ORDERED_CONSUMER_CACHE_PRODUCER_RETIREMENT_PASS_NO_FRESH_ACTOR_QUERIES'and decision['source606']=='UNCHANGED_SOURCE_ENFORCED_FULL_REREADS'and decision['private_full_maps']=='NOT_EXPORTED_SOURCE_ENFORCED','whole issued source/reader/public/cleanup scope, no fresh actor claim')
 return dict(status='ISSUED_APPS10_CURRENT606_INPUT_QUALIFICATION_ONLY',source=decision['source'],run=decision['run'],decision=q['pin'],record_source=row['source'],result=decision['result'],post_replay=decision['post_replay'],originals=decision['originals'],new_composition='NOT_QUALIFIED')

def inspect_archives(role,root,checks):
 p=profile()['profiles'][role];name,version,size,digest=ARCHIVES[role];reports=[];L=load('_next_archive_stable_whole_reader',HERE/'apps8_git.py')
 for member in p['pair_paths']:
  path=Path(root)/member;need(pin(L.read(path.absolute(),time.monotonic()+120))==dict(bytes=size,sha256=digest),'exact declared accepted pair bytes '+role);r=checks.package(path);meta=r['metadata'];need(not r['errors']and r['sha256']==digest and all(meta['.PKGINFO'].get(k,[])==v for k,v in p['metadata'].items())and meta['.BUILDINFO']['pkgbuild_sha256sum']==[p['PKGBUILD']['sha256']],'complete eight-field source metadata and original recipe BUILDINFO '+role);reports.append(r)
 need(reports[0]==reports[1],'both complete accepted pair archive reports equal');report=reports[0];payload={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};need(payload and all(r['type']=='0'and r['uid']==r['gid']==0 for r in payload.values()),'complete ordinary root-owned selected payload')
 return dict(archive=Path(root)/p['archive']['path'],payload=payload,report=report,authority='EXACT_ACCEPTED_NATIVE_PAIR_INPUT_ONLY')

def inspect(packets,checks):
 p=profile();q=qualification();need(set(packets)==set(SOURCES),'five explicit new public DATA operands including independent current606 qualification');L=load('_next_full_source_git_custody',HERE/'apps8_git.py');receipts={};out={}
 for role,packet in packets.items():
  row=p['profiles'][role];packet=Path(packet).absolute();proof=L.prove(packet,packet/'.git',row,time.monotonic()+120);need(proof['tree']==row['tree'],'complete original immutable input tree '+role);index_raw=L.read(packet/'index.json',time.monotonic()+120);index=json.loads(index_raw);need(pin(index_raw)==row['index'],'whole exact input index '+role);d=row['decision'];need(L.read(packet/d['path'],time.monotonic()+120)==(json.dumps(d['value'],sort_keys=True,indent=2)+'\n').encode(),'whole issued Root input decision '+role);receipts[role]=dict(source=proof,decision=d['pin'],index=row['index'],scope='HISTORICAL_INPUT_ONLY_NO_CURRENT_COMPOSITION_CREDIT')
  if role=='apps10qualification':qualification_record(packet,index,L,time.monotonic()+120)
  if role in ARCHIVES:out[role]=inspect_archives(role,packet,checks)
 out['custody']=dict(status='SOURCE_BOUND_SIX_TOOL_NEW_INPUTS_ONLY',profiles=receipts,Apps10_current606=q,actual_authority=False,new_composition='NOT_QUALIFIED');return out

def validate_custody(value):
 p=profile();need(type(value)is dict and set(value)=={'status','profiles','Apps10_current606','actual_authority','new_composition'}and value['status']=='SOURCE_BOUND_SIX_TOOL_NEW_INPUTS_ONLY'and value['actual_authority']is False and value['new_composition']=='NOT_QUALIFIED'and value['Apps10_current606']==qualification()and set(value['profiles'])==set(SOURCES),'complete four new input authorities, no current acceptance')
 for role,row in value['profiles'].items():
  wanted=p['profiles'][role];need(set(row)=={'source','decision','index','scope'}and row['decision']==wanted['decision']['pin']and row['index']==wanted['index']and row['scope']=='HISTORICAL_INPUT_ONLY_NO_CURRENT_COMPOSITION_CREDIT'and row['source']==dict(status='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY',source=wanted['source'],ref=wanted['ref'],files=len(wanted['files']),blob_joins=len(wanted['files']),tree=wanted['tree']),'same source/full file/blob/tree provenance '+role)
 return value


def qualification_record(packet,index,L,deadline):
 row=profile()['profiles']['apps10qualification'];d=row['decision']['value'];read=lambda n:L.read(Path(packet)/n,deadline);decode=lambda n:json.loads(read(n))
 need(index['status']=='RETAINED_ROOT_FINITE_APPS10_CURRENT606_AND_ONCE_ORIGINALS_DATA_ONLY'and index['files']=={n:w for n,w in row['files'].items()if n!='index.json'}and index['native_source']==d['source']and index['native_ref']==d['ref']and index['native_run']==d['run']and index['Root_decision']==row['decision']['path']and index['new_native_acceptance']is False and index['publication_source']is index['publication_ref']is None,'closed15 historical qualification record and no composition authority')
 need(pin(read('qualification/Root-passive-result.json'))==d['result']and pin(read('qualification/Root-post-replay-pins.json'))==d['post_replay'],'complete prior positive result/postpins')
 result=decode('qualification/Root-passive-result.json');post=decode('qualification/Root-post-replay-pins.json');need(result['status']=='VERIFIED_APPS606_PROTOCOL_NOT_ROOT_ACCEPTANCE'and result['Apps10_current606']=='EIGHT_PHASES_CURRENT_DATA_REQUIRES_ROOT_REVIEW'and result['run_id']==d['run']and result['source_files']==389 and result['public_files']==950 and result['public_bytes']==43570011 and post['status']=='PASS_ALL389_SOURCE1695_READER_AND_ORIGINALS_AFTER_COMPLETE_POSITIVE'and len(post['source_files'])==389 and len(post['reader_files'])==1695,'whole original successful passive result and exact post-source/reader map counts')
 auth=decode('native-source/source-authorization.json');git=decode('native-source/Root-git-source-authorization.json');pub=decode('native-source/Root-committed-publication.json');published=decode('native-source/publication.json');need(auth==post['source_files']==git['files']and git['source']==pub['source']==published['source']==d['source']and git['ref']==pub['ref']==published['ref']==d['ref']and git['status']=='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN'and pub['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'and published['status']=='PUBLISHED_EXACT_CLOSED_TRIAL_SOURCE'and pub['files']==pub['git_joins']==published['files']==published['git_joins']==389,'genuine complete accepted389 source/publication/Git map join')
 need(set(d['originals'])=={'run.json','jobs.json','artifacts.json','artifact.zip','collection.json'}and post['originals']==d['originals'],'exact five once originals declared by Root')
 for name,wanted in d['originals'].items():need(pin(read('originals/'+name))==wanted,'fresh complete historical original bytes '+name)
 origin=result['origin']['original_artifact'];need(origin['status']=='VERIFIED_ORIGINAL_FRAMED_TRANSPORT_ONLY'and origin['artifact']==d['originals']['artifact.zip']and origin['files']==950 and origin['bytes']==43570011 and origin['context']['head_sha']==d['source']and origin['context']['run_id']==d['run']and origin['context']['nonce']==d['nonce']and origin['original_conclusion']=='success','original full framed-transport passive provenance joins Root qualification only')
 return dict(status='JOINED_PUBLIC15_ISSUED_APPS10_606_QUALIFICATION_DATA_ONLY',decision=row['decision']['pin'],record_source=row['source'],result=d['result'],post_replay=d['post_replay'],originals=d['originals'],fresh_inner_replay='NOT_PERFORMED_PRIOR_ROOT_FULL_POSITIVE_REQUIRED',current_composition='NOT_QUALIFIED')

# Existing five original inputs and Apps10/full606 qualification remain an
# independent historical gate. Apps16's native577 and separate606 records grant no new composition credit.
_before_apps16_inspect=inspect
_before_apps16_validate_custody=validate_custody
def inspect(packets,checks):
 qualification()
 import apps16_inputs as A16
 A16.qualification();need(type(packets)is dict and set(packets)==set(SOURCES)|set(A16.SOURCES),'all five historical plus three Apps16 input operands')
 old=_before_apps16_inspect({n:packets[n]for n in SOURCES},checks);current=A16.inspect({n:packets[n]for n in A16.SOURCES},checks)
 old['apps16']=current['apps16'];old['custody']=dict(prior=old['custody'],Apps16_native=current['custody']);return old

def validate_custody(value):
 import apps16_inputs as A16
 need(type(value)is dict and set(value)=={'prior','Apps16_native'},'explicit old five-input AND Apps16 native input custody')
 _before_apps16_validate_custody(value['prior']);A16.validate_custody(value['Apps16_native']);return value
