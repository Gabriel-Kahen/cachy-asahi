# SPDX-License-Identifier: MIT
"""Exact Apps16 native pair/carrier and separately qualified606 input custody.

The old five-input inspector/validator remains an independent historical gate.
These typed authorities select only Apps16's accepted archive and qualify its
separate finite606 prerequisite. They create no new composition/GUI/16K credit.
"""
import hashlib,importlib.util,json,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCES={'apps16':('950b0699a6e3f7a56758d4d17a5d30dabc7b6e11',94),'apps16qualification':('b011fb72b8055cd1d3c5c08227839847a83ef6c5',22),'apps16current606qualification':('8c3eabd772e2078875e0e3f230b3f236e334b393',16)}
NATIVE='135b8fb21941d0ea27da7d34b1fc7b9eb0939ee8'
NATIVE_REF='codex/apps16-pair-native-v1'
RUN=40170377974
ARCHIVE=dict(bytes=29664,sha256='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def profile():
 p=json.loads((HERE/'apps16-inputs.json').read_bytes());need(p['status']=='APPS16_NATIVE_INPUTS_ONLY_NO_NEW_COMPOSITION_ACCEPTANCE'and set(p['profiles'])==set(SOURCES)and all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'strict Apps16 input-only NULL actual profile')
 for role,(source,count)in SOURCES.items():
  r=p['profiles'][role];pub,g=r['publication'],r['git'];need(r['source']==pub['source']==g['source']==source and r['ref']==pub['ref']==g['ref']and len(r['files'])==pub['files']==pub['git_joins']==count and g['files']==r['files']and pub['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'and g['status']=='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN'and r['actual']is None and r['new_composition']=='NOT_QUALIFIED','whole accepted94/22 source/Git envelope '+role);d=r['decision'];need(pin(enc(d['value']))==d['pin']==r['files'][d['path']],'complete Apps16 Root input decision '+role)
 d=p['profiles']['apps16']['decision']['value'];r=p['profiles']['apps16qualification'];need(r['decision']['value']==d and r['decision']['pin']==p['profiles']['apps16']['decision']['pin'],'same complete native acceptance in carrier94 and record22')
 need((d['source'],d['ref'],d['run'],d['attempt'],d['recipe_source'])==(NATIVE,NATIVE_REF,RUN,1,'a32501a76b79b65d175c8eefc2b4f741ec0388e5')and d['status']=='ROOT_ACCEPTED_APPS16_NATIVE_BUILD_PAIRS_AND_FINITE_INSTALLED_LIFECYCLE','exact native Apps16 input qualification')
 need(d['accepted_pair']['archive']==ARCHIVE and d['accepted_pair']['package']=='cachy-asahi-apps'and d['accepted_pair']['version']=='0.1.0-16'and d['accepted_pair']['byte_identical']is True,'exact accepted Apps16 pair')
 need(d['reader']['files']==1687 and d['reader']['corrected_binding']=='GENUINE_RETAINED_ANCESTOR_BOUND_ORIGINAL_NO_FABRICATION'and d['installed_control_totals']==dict(apps=90,client=12,stage=24)and d['private574_maps']=='UNEXPORTED_SOURCE_ENFORCED'and d['retirement']=='SOURCE_RECORDED_NOT_LIVE_REOBSERVED','whole separate finite577 installed/security/retirement qualification')
 need(d['installed_current606']==d['full604']==d['generic16k']==d['hardware']==d['GUI']==d['M2']=='NOT_RUN'and d['release']=='NOT_ADMITTED','no full606/GUI/16K acceptance transfer')
 row606=p['profiles']['apps16current606qualification'];d606=row606['decision']['value']
 need(d606['status']=='ROOT_ACCEPTED_FINITE_APPS16_CURRENT606_NATIVE_LIFECYCLE'and(d606['source'],d606['ref'],d606['run'],d606['attempt'])==('fdf045f0d9c0d5c7646b160b3b9890969d7f9fcb','codex/apps16-current606-v1',40171836477,1)and d606['counts']==[606,606,606,606,605,606,606,606]and d606['selected_versions']==['0.1.0-6','0.1.0-7','0.1.0-16','0.1.0-16',None,'0.1.0-16','0.1.0-7','0.1.0-6']and d606['transactions']==7 and d606['signed_installs']==6 and d606['installed_controls']==150 and d606['ordinary_homes']==['fresh','existing'],'separately accepted exact Apps16/current606 input lifecycle')
 need(d606['other605']=='SOURCE_ENFORCED_FULL_PRIVATE_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPABILITY_PRESERVATION'and d606['Runtime1']=='EXACT_NATIVE_PAIR_PROTECTED_NO_TRANSACTION'and d606['selected_inode_restoration']=='NOT_CLAIMED'and d606['source606']=='SOURCE_ENFORCED_PRIVATE_FULL_REREADS'and d606['private_full_maps']=='NOT_EXPORTED_SOURCE_ENFORCED'and d606['source_files']==389 and d606['reader_files']==1695 and d606['public_files']==950 and d606['public_bytes']==43573492 and d606['hardware']=='NOT_RUN'and d606['GUI']=='NOT_QUALIFIED'and d606['page16k']=='NOT_QUALIFIED_BY_THIS_DOCKER_RESULT'and d606['release']=='NOT_ADMITTED','complete finite606 protection and strict hardware/GUI/16K boundaries')
 row=p['profiles']['apps16'];need({k:row['archive'][k]for k in('bytes','sha256')}==ARCHIVE and len(row['pair_paths'])==2 and all(row['files'][n]==ARCHIVE for n in row['pair_paths'])and row['metadata']['pkgname']==['cachy-asahi-apps']and row['metadata']['pkgver']==['0.1.0-16']and set(row['metadata'])=={'pkgname','pkgver','arch','license','depend','provides','conflict','replaces'},'exact pair paths and eight-field source package metadata')
 return p

def qualification():
 p=profile();s=p['selection'];need(type(s)is dict,'NULL Apps16 native input selection BEFORE ACTORS')
 need(s==dict(source=NATIVE,ref=NATIVE_REF,run=RUN,record_source=SOURCES['apps16qualification'][0],carrier_source=SOURCES['apps16'][0],current606_record_source=SOURCES['apps16current606qualification'][0],current606_source='fdf045f0d9c0d5c7646b160b3b9890969d7f9fcb',current606_run=40171836477),'exact finite native577 and separate606 input selector')
 d=p['profiles']['apps16']['decision'];return dict(status='ISSUED_APPS16_NATIVE_AND_CURRENT606_INPUT_ONLY',source=NATIVE,ref=NATIVE_REF,run=RUN,decision=d['pin'],carrier_source=SOURCES['apps16'][0],record_source=SOURCES['apps16qualification'][0],current606=profile()['profiles']['apps16current606qualification']['decision']['pin'],current606_source='fdf045f0d9c0d5c7646b160b3b9890969d7f9fcb',current606_run=40171836477,new_composition='NOT_QUALIFIED',full606='SEPARATE_FINITE_INPUT_ONLY_NO_COMPOSITION_CREDIT')

def record(packet,index,L,deadline):
 p=profile();row=p['profiles']['apps16qualification'];d=row['decision']['value'];read=lambda n:L.read(Path(packet)/n,deadline);obj=lambda n:json.loads(read(n))
 need(index['status']=='RETAINED_ROOT_FINITE_ACCEPTANCE_AND_ONCE_ORIGINALS_DATA_ONLY'and index['files']=={n:w for n,w in row['files'].items()if n!='index.json'}and(index['native_source'],index['native_ref'],index['native_run'])==(NATIVE,NATIVE_REF,RUN)and index['Root_decision']==row['decision']['path']and index['new_native_acceptance']is False and index['publication_source']is index['publication_ref']is None,'closed22 native qualification record, no composition authority')
 result=obj('qualification/Root-result.json');post=obj('qualification/Root-post-replay-pins.json');need(pin(read('qualification/Root-result.json'))==d['result']and pin(read('qualification/Root-post-replay-pins.json'))==d['post_replay'],'complete original Apps16 result and post pins')
 need(result['status']=='PASS_CURRENT_APPS16_NATIVE_PAIRS_AND_LIFECYCLE_PASSIVE_REPLAY'and result['source']==NATIVE and result['run']==str(RUN)and result['attempt']=='1'and result['Root_acceptance']=='NOT_ISSUED_BY_READER'and post['status']=='PASS_ALL115_NATIVE1687_READER42_RECIPE_AND_ORIGINALS_AFTER_COMPLETE_POSITIVE'and(len(post['source_files']),len(post['reader_files']),len(post['recipe_files']))==(115,1687,42),'whole prior native115/1687/42 passive result only')
 auth=obj('source-publication/source-authorization.json');git=obj('source-publication/Root-git-source-authorization.json');pub=obj('source-publication/Root-committed-publication.json');published=obj('source-publication/publication.json');need(auth==post['source_files']==git['files']and git['source']==pub['source']==published['source']==NATIVE and git['ref']==pub['ref']==published['ref']==NATIVE_REF and pub['files']==pub['git_joins']==published['files']==published['git_joins']==115 and git['status']=='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN'and pub['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'and published['status']=='PUBLISHED_EXACT_CLOSED_TRIAL_SOURCE','genuine whole accepted115 source/publication/Git joins')
 need(post['originals']==d['originals']and len(d['originals'])==8,'all eight once original roles')
 for name,wanted in d['originals'].items():need(pin(read('originals/'+name))==wanted,'complete original Apps16 once DATA '+name)
 for label in('a','b'):need(pin(read('accepted-pair/cachy-asahi-apps-'+label+'/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz'))==ARCHIVE,'record exact accepted pair archive')
 return dict(status='JOINED_PUBLIC22_APPS16_NATIVE_QUALIFICATION_DATA_ONLY',decision=row['decision']['pin'],result=d['result'],post_replay=d['post_replay'],originals=d['originals'],fresh_inner_replay='NOT_PERFORMED_PRIOR_ROOT_FULL_POSITIVE_REQUIRED',full606='NOT_TRANSFERRED',new_composition='NOT_QUALIFIED')

def inspect(packets,checks):
 p=profile();q=qualification();need(type(packets)is dict and set(packets)==set(SOURCES),'three explicit Apps16 carrier94/native22/current606record16 operands');L=load('_apps16_complete_input_git_custody',HERE/'apps8_git.py');receipts={};out=None
 for role,root in packets.items():
  row=p['profiles'][role];root=Path(root).absolute();end=time.monotonic()+120;source=L.prove(root,root/'.git',row,end);need(source['tree']==row['tree'],'complete original Apps16 input tree '+role);raw=L.read(root/'index.json',end);need(pin(raw)==row['index'],'whole Apps16 input index');index=json.loads(raw);need(L.read(root/row['decision']['path'],end)==enc(row['decision']['value']),'whole issued Apps16 input decision')
  extra=record(root,index,L,end)if role=='apps16qualification'else current606_record(root,index,L,end)if role=='apps16current606qualification'else None
  if role=='apps16':
   need(index['status']=='EXACT_ACCEPTED_APPS16_PAIR_INPUT_DATA_ONLY'and index['files']=={n:w for n,w in row['files'].items()if n!='index.json'}and index['actual']is None and(index['source'],index['ref'],index['run'])==(NATIVE,NATIVE_REF,RUN),'closed94 exact accepted input index')
   reports=[]
   for name in row['pair_paths']:
    path=root/name;need(pin(L.read(path,end))==ARCHIVE,'whole Apps16 accepted archive bytes');r=checks.package(path);meta=r['metadata'];need(not r['errors']and r['sha256']==ARCHIVE['sha256']and all(meta['.PKGINFO'].get(k,[])==v for k,v in row['metadata'].items())and meta['.BUILDINFO']['pkgbuild_sha256sum']==[row['PKGBUILD']['sha256']],'whole Apps16 eight-field metadata/recipe BUILDINFO')
    for name in('apps.py','inventory.py'):need(r['members']['usr/lib/cachy-asahi-apps/'+name]['sha256']==pin((HERE/'apps16-source'/name).read_bytes())['sha256'],'accepted archive matches complete source-defined installed Apps16 helper')
    reports.append(r)
   need(reports[0]==reports[1],'both complete Apps16 package reports equal');r=reports[0];payload={n:v for n,v in r['members'].items()if v['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};need(payload and all(v['type']=='0'and v['uid']==v['gid']==0 for v in payload.values()),'complete ordinary root-owned Apps16 payload');out=dict(archive=root/row['archive']['path'],payload=payload,report=r,authority='EXACT_ACCEPTED_NATIVE_PAIR_INPUT_ONLY')
  receipts[role]=dict(source=source,index=row['index'],decision=row['decision']['pin'],record=extra,scope='HISTORICAL_INPUT_ONLY_NO_CURRENT_COMPOSITION_CREDIT')
 return dict(apps16=out,custody=dict(status='SOURCE_BOUND_APPS16_NATIVE_INPUTS_ONLY',qualification=q,profiles=receipts,actual_authority=False,new_composition='NOT_QUALIFIED'))

def validate_custody(value):
 p=profile();need(type(value)is dict and set(value)=={'status','qualification','profiles','actual_authority','new_composition'}and value['status']=='SOURCE_BOUND_APPS16_NATIVE_INPUTS_ONLY'and value['qualification']==qualification()and value['actual_authority']is False and value['new_composition']=='NOT_QUALIFIED'and set(value['profiles'])==set(SOURCES),'whole finite Apps16 input-only custody')
 for role,row in value['profiles'].items():
  wanted=p['profiles'][role];need(set(row)=={'source','index','decision','record','scope'}and row['index']==wanted['index']and row['decision']==wanted['decision']['pin']and row['source']==dict(status='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY',source=wanted['source'],ref=wanted['ref'],files=len(wanted['files']),blob_joins=len(wanted['files']),tree=wanted['tree'])and row['scope']=='HISTORICAL_INPUT_ONLY_NO_CURRENT_COMPOSITION_CREDIT','complete94/22 input Git/decision/index receipt')
  if role=='apps16':need(row['record']is None,'carrier is not qualification record')
  elif role=='apps16current606qualification':need(row['record']==current606_receipt(wanted),'whole separately qualified current606 input receipt')
  else:
   d=wanted['decision']['value'];need(row['record']==dict(status='JOINED_PUBLIC22_APPS16_NATIVE_QUALIFICATION_DATA_ONLY',decision=wanted['decision']['pin'],result=d['result'],post_replay=d['post_replay'],originals=d['originals'],fresh_inner_replay='NOT_PERFORMED_PRIOR_ROOT_FULL_POSITIVE_REQUIRED',full606='NOT_TRANSFERRED',new_composition='NOT_QUALIFIED'),'complete finite qualified22 record custody')
 return value

def current606_record(packet,index,L,deadline):
 row=profile()['profiles']['apps16current606qualification'];d=row['decision']['value'];read=lambda n:L.read(Path(packet)/n,deadline);obj=lambda n:json.loads(read(n))
 need(index['status']=='RETAINED_ROOT_FINITE_ACCEPTANCE_AND_ONCE_ORIGINALS_DATA_ONLY'and index['files']=={n:w for n,w in row['files'].items()if n!='index.json'}and(index['native_source'],index['native_ref'],index['native_run'])==('fdf045f0d9c0d5c7646b160b3b9890969d7f9fcb','codex/apps16-current606-v1',40171836477)and index['Root_decision']==row['decision']['path']and index['new_native_acceptance']is False and index['publication_source']is index['publication_ref']is None,'whole16 Apps16/current606 qualification record only')
 result=obj('qualification/Root-result.json');post=obj('qualification/Root-post-replay-pins-20261025.json');need(pin(read('qualification/Root-result.json'))==d['result']and pin(read('qualification/Root-post-replay-pins-20261025.json'))==d['post_replay']and post['result']==d['result'],'entire separately qualified current606 result/post pins')
 need(result['status']=='VERIFIED_APPS606_PROTOCOL_NOT_ROOT_ACCEPTANCE'and result['Apps16_current606']=='EIGHT_PHASES_CURRENT_DATA_REQUIRES_ROOT_REVIEW'and result['Root_acceptance']=='NOT_ISSUED'and result['source']==d['source']and result['run_id']==d['run']and result['source_files']==389 and result['public_files']==950 and result['public_bytes']==43573492 and post['status']=='PASS_CURRENT_SOURCE389_READER1695_AND_SAME_ONCE_ORIGINAL_PUBLIC950_POST_REPLAY'and(len(post['source']),len(post['reader']),len(post['public']))==(389,1695,950)and post['reacquisition']is False,'full389/1695/950 source-owned result and once custody, no composition credit')
 auth=obj('source-publication/source-authorization.json');git=obj('source-publication/Root-git-source-authorization.json');pub=obj('source-publication/Root-committed-publication.json');published=obj('source-publication/publication.json');need(auth==post['source']==git['files']and git['source']==pub['source']==published['source']==d['source']and git['ref']==pub['ref']==published['ref']==d['ref']and pub['files']==pub['git_joins']==published['files']==published['git_joins']==389 and git['status']=='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN'and pub['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'and published['status']=='PUBLISHED_EXACT_CLOSED_TRIAL_SOURCE','whole accepted389 source/publication/Git join')
 binding=row['carrier_binding'];value=binding['value'];need(pin(enc(value))==binding['pin']==auth[binding['path']]and value['source']==SOURCES['apps16'][0]and value['archive']==ARCHIVE and value['native_source']==value['expected_native_source']==NATIVE and value['native_run']==value['expected_native_run']==RUN and value['files']==profile()['profiles']['apps16']['files'],'same full606 source-defined carrier94/archive/native identity')
 need(post['originals']==d['originals']and len(d['originals'])==6,'all six current606 once originals')
 for name,wanted in d['originals'].items():need(pin(read('originals/'+name))==wanted,'every entire current606 once original '+name)
 origin=result['origin']['original_artifact'];need(origin['status']=='VERIFIED_ORIGINAL_FRAMED_TRANSPORT_ONLY'and origin['artifact']==d['originals']['artifact.zip']and origin['files']==950 and origin['bytes']==43573492 and origin['context']['head_sha']==d['source']and origin['context']['run_id']==d['run']and origin['context']['nonce']==d['nonce']and origin['original_conclusion']=='success','original full framed transport joins separate Root component decision')
 return current606_receipt(row)

def current606_receipt(row):
 d=row['decision']['value'];return dict(status='JOINED_PUBLIC16_APPS16_CURRENT606_QUALIFICATION_DATA_ONLY',decision=row['decision']['pin'],source=d['source'],run=d['run'],result=d['result'],post_replay=d['post_replay'],originals=d['originals'],scope='FINITE_CURRENT606_INPUT_ONLY',fresh_inner_replay='NOT_PERFORMED_PRIOR_ROOT_FULL_POSITIVE_REQUIRED',new_composition='NOT_QUALIFIED')
