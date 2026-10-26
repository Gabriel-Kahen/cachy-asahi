# SPDX-License-Identifier: MIT
"""Additional accepted Apps8 carrier, separate from original606 Apps7/Runtime input."""
import importlib.util,json,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
PAIR=dict(bytes=23528,sha256='d4d83458765d732ae78664143c9042dcc1159b7d3e19f4b7976f8499c2619f4a')
def need(ok,why):
 if not ok:raise ValueError(why)
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def qualification():
 import latest_selection as S
 policy=json.loads((HERE/'input-policy.json').read_bytes());row=policy.get('apps8_current606');need(type(row)is dict,'NULL Apps8 full606 input qualification before producers')
 path=HERE/'accepted/apps8-current606.json';raw=path.read_bytes();value=json.loads(raw)
 need(S.pin(raw)=={k:row[k]for k in('bytes','sha256')}and value==row['decision'],'whole Root Apps8 current606 qualification')
 need((value['status'],value['source'],value['run'],value['ref'])==('ROOT_ACCEPTED_FINITE_APPS8_CURRENT606_NATIVE_LIFECYCLE','5c3c2d0ce5b4f6c2672c9367b722170687c7de69',39735431322,'codex/apps8-current606-carrier-env-v1'),'exact qualified full606 Apps8 source/run')
 need(value['counts']==[606,606,606,606,605,606,606,606]and value['selected_versions']==['0.1.0-6','0.1.0-7','0.1.0-8','0.1.0-8',None,'0.1.0-8','0.1.0-7','0.1.0-6']and value['transactions']==7 and value['signed_installs']==6 and value['installed_controls']==150 and value['ordinary_homes']==['fresh','existing'],'whole finite Apps8 lifecycle/controls qualifier')
 need(value['other605']=='SOURCE_ENFORCED_FULL_PRIVATE_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPABILITY_PRESERVATION'and value['Runtime1']=='PROTECTED_EXACT_NATIVE_PAIR_NO_TRANSACTION'and value['selected_inode_restoration']=='NOT_CLAIMED'and value['release']=='NOT_ADMITTED'and value['hardware']=='NOT_RUN','qualified input only; no current combined or hardware transfer')
 return dict(source=value['source'],run=value['run'],decision=S.pin(raw),scope='INPUT_QUALIFICATION_ONLY_NO_NEW_COMBINED_CREDIT')

def qualified_profile():
 p=json.loads((HERE/'apps8-qualified-profile.json').read_bytes())
 need(p['source']is not None and p['ref']is not None and type(p['files'])is dict,'NULL qualified Apps8 carrier before producers')
 need(p['source']=='6dbfdbad6d9ec75a230ce366096206de933b1c28'and p['ref']=='codex/apps8-current606-qualified-inputs-v1'and len(p['files'])==113,'exact whole qualified113 Apps8 input source')
 pub=p['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=p['source'],ref=p['ref'],files=len(p['files']),git_joins=len(p['files']),actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=p['source'],ref=p['ref'],files=p['files']),'genuine complete qualified Apps8 publication/Git source')
 old=json.loads((HERE/'apps8-carrier-profile.json').read_bytes());need({n.removeprefix('apps8/'):w for n,w in p['files'].items()if n.startswith('apps8/')}==old['files'],'whole nested original93 carrier remains exact')
 return p

def inspect(packet,checks):
 qualification();qualified=qualified_profile();profile=json.loads((HERE/'apps8-carrier-profile.json').read_bytes());L=load('_latest_apps8_full_git_proof',HERE/'apps8_git.py');packet=Path(packet).absolute();deadline=time.monotonic()+120
 proof=L.prove(packet,packet/'.git',qualified,deadline);Q=load('_latest_apps8_qualified_data_checker',HERE/'apps8_qualified_check.py');data=Q.check(packet);need(data==qualified['data_receipt'],'whole qualified input DATA receipt, no authority')
 tree=L.git(packet/'.git',deadline,'rev-parse',qualified['source']+':apps8').strip().decode();need(tree=='58e4aea8af2b8af57b67ec34a19b41baed60b253','exact original93 Git subtree including modes')
 archive_root=packet/'apps8';index=json.loads(L.read(archive_root/'index.json',deadline,1024**2));decision=json.loads(L.read(archive_root/index['acceptance'],deadline,1024**2))
 need(index['status']=='EXACT_ACCEPTED_APPS8_PAIR_INPUT_DATA_ONLY'and index['archives']==profile['archives']and decision==profile['acceptance']and decision['accepted_pair']['archive']==PAIR and decision['accepted_pair']['byte_identical']is True,'whole accepted Apps8 pair index/decision')
 actual=json.loads(L.read(packet/'qualification/Root-component-acceptance.json',deadline,1024**2));need(actual==json.loads((HERE/'accepted/apps8-current606.json').read_bytes()),'same exact accepted full606 qualifier')
 for name,key in(('Root-passive-result.json','result'),('Root-post-replay-pins.json','post_replay')):
  need(L.pin(L.read(packet/'qualification'/name,deadline,2*1024**2))==actual[key],'whole Apps8 current606 result/post proof')
 for name,want in actual['originals'].items():need(L.pin(L.read(packet/'qualification/originals'/name,deadline))==want,'all five original once-role hashes')
 product=inspect_archives(archive_root,checks,profile,L,deadline);product.update(authority='EXACT_ACCEPTED_NATIVE_PAIR_INPUT_ONLY',custody=dict(carrier=proof,data=data,original93=dict(source=profile['source'],tree=tree,files=93),archive=PAIR,qualification=qualification(),scope='INPUT_ONLY_NO_COMBINED_ACCEPTANCE'));return product

def inspect_archives(archive_root,checks,profile,L,deadline):
 # Pure raw DATA inspection, never selection/signature/native authority.
 reports=[]
 for row in profile['archives']:
  path=archive_root/row['path'];need(L.pin(L.read(path,deadline))==PAIR,'whole accepted Apps8 raw archive')
  report=checks.package(path);meta=report['metadata'];need(not report['errors']and meta['.PKGINFO']['pkgname']==['cachy-asahi-apps']and meta['.PKGINFO']['pkgver']==['0.1.0-8']and meta['.PKGINFO']['arch']==['any'],'complete actual Apps8 package metadata')
  need(meta['.BUILDINFO']['pkgbuild_sha256sum']==[profile['files']['recipe-source/packages/tools/cachy-asahi-apps8/PKGBUILD']['sha256']],'exact recipe BUILDINFO binding')
  for name in('apps.py','inventory.py'):
   need(report['members']['usr/lib/cachy-asahi-apps/'+name]['sha256']==L.pin((HERE/'apps8-source'/name).read_bytes())['sha256'],'trusted installed Apps8 helper source binding')
  reports.append(report)
 need(reports[0]==reports[1],'both complete Apps8 reports equal')
 report=reports[0];payload={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')}
 need(len(payload)==8,'complete eight-file Apps8 payload')
 return dict(archive=archive_root/profile['archives'][0]['path'],payload=payload,report=report)

def validate_custody(value):
 import re
 p=qualified_profile();need(type(value)is dict and set(value)=={'carrier','data','original93','archive','qualification','scope'},'complete additional Apps8 input custody')
 proof=value['carrier'];need(type(proof)is dict and set(proof)=={'source','ref','files','blob_joins','tree','status'}and proof['source']==p['source']and proof['ref']==p['ref']and proof['files']==proof['blob_joins']==len(p['files']) and proof['status']=='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY'and type(proof['tree'])is str and proof['tree']=='532b97ccd0763c6641fa8b6e29a9b3bee68444ca','complete source-enforced Apps8 commit/tree/all113blob proof')
 need(value['data']==p['data_receipt'],'whole exact qualified DATA receipt');need(value['original93']==dict(source='979b2d6ec7417e607a911d8c25bef2f1f7f72dcb',tree='58e4aea8af2b8af57b67ec34a19b41baed60b253',files=93),'exact nested93 old carrier provenance');need(value['archive']==PAIR and value['qualification']==qualification()and value['scope']=='INPUT_ONLY_NO_COMBINED_ACCEPTANCE','exact accepted Apps8 input/qualifier, no combined transfer');return value
