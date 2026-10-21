# SPDX-License-Identifier: MIT
"""Finite passive Welcome8 cache DATA; never package/build/GUI authority."""
import hashlib,json,math,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 209443, 'sha256': 'bff0c508b6a25093f330f7f2fc35a7570b4c0cca1e4629a8f0cbf37390447517'}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def exact(value,keys,why):need(type(value)is dict and set(value)==set(keys.split()),why)
def profile():
 raw=(HERE/'cache-profile.json').read_bytes();need(pin(raw)==PROFILE,'whole cache DATA profile');return json.loads(raw)
def validate(value):
 p=profile();exact(value,'schema status early preparation legacy_indexes seed_seconds seed_limit actual','whole source-owned preparation DATA')
 need(value['schema']==1 and type(value['schema'])is int and value['status']=='WELCOME8_RETAINED_INPUT_DATA_ONLY'and value['actual']is None and value['seed_limit']==50 and type(value['seed_seconds'])in(int,float)and math.isfinite(value['seed_seconds'])and 0<=value['seed_seconds']<=50,'bounded50s DATA-only seed envelope')
 early=value['early'];exact(early,'schema status cases seconds seconds_limit actual','whole early prefill envelope')
 need(early['schema']==1 and type(early['schema'])is int and early['status']=='WELCOME8_EXACT_LEGACY_PREFILL_DATA_ONLY'and early['actual']is None and early['seconds_limit']==50 and type(early['seconds'])in(int,float)and math.isfinite(early['seconds'])and 0<=early['seconds']<=50 and set(early['cases'])=={'32','20','8'},'bounded original-step early prefill')
 for case,a in p['archives'].items():
  r=early['cases'][case];exact(r,'status files requests index original_inputs actual_authority carrier_source_proof','whole exact prefill receipt')
  need(type(r['requests'])is int and r['actual_authority']is False and r==dict(status='EXACT_POLICY_CACHE_PREFILLED_NOT_AUTHENTICATED',files=a['files'],requests=0,index='NOT_CREATED_ORIGINAL_CLI_REQUIRED',original_inputs=p['lock'],actual_authority=False,carrier_source_proof=p['proof']),'exact source/Git/tree all1154 and no index fabrication')
 prep=value['preparation'];exact(prep,'status mode source carrier receipt authentication actual hardware release','whole maintained seed envelope')
 need(prep['status']=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY'and prep['mode']=='desktop574'and prep['source']==p['source']and prep['carrier']==p['proof']and prep['actual']is None and prep['hardware']=='NOT_RUN'and prep['release']=='NOT_ADMITTED'and prep['authentication']=='UNCHANGED_ORIGINAL_POLICY_CLI_INDEX_GPG_METADATA_ACQUIRE_BUILD_AND_RUNTIME_GATES_REQUIRED','exact maintained source proof, no acceptance authority')
 r=prep['receipt'];exact(r,'schema status mode original_lock inputs cache versions trust actual_authority','whole seed receipt')
 need(r['schema']==1 and type(r['schema'])is int and r['status']=='EXACT_PUBLIC_CACHE_INPUTS_JOINED_NOT_AUTHENTICATED'and r['mode']=='desktop574'and r['original_lock']==p['lock']and r['inputs']==p['selected']and r['versions']=='UNCHANGED'and r['actual_authority']is False and r['trust']=='ORIGINAL_FULL_SIGNATURE_METADATA_ACQUIRE_NATIVE_AND_PACKAGE_CHECKS_REQUIRED','original1148 bytes and authentication still mandatory')
 c=r['cache'];exact(c,'before_files after_files before_identity after_previous_identity directory_identity after_directory_identity mode owner added fresh_cache all_previous_inode_metadata_bytes_unchanged','whole existing-cache identity envelope')
 before=c['before_files'];need(type(before)is dict and set(p['mandatory_before'])<=set(before)<=set(p['mandatory_before'])|set(p['optional_before']),'original80 and only original rootfs/keyring leaves')
 need(before==dict(p['mandatory_before'],**{n:p['optional_before'][n]for n in before if n in p['optional_before']})and c['after_files']==dict(p['selected'],**{n:r for n,r in before.items()if n in p['optional_before']}),'whole before and after pins')
 need(c['fresh_cache']is False and c['all_previous_inode_metadata_bytes_unchanged']is True and c['mode']==0o700 and c['owner']=='CALLER_UID'and type(c['added'])is int and c['added']==len(set(p['selected'])-set(before)),'only exact additions, never replacement')
 d=c['directory_identity'];need(type(d)is list and len(d)==6 and all(type(n)is int for n in d)and d[0]>=0 and d[1]>0 and stat.S_ISDIR(d[2])and stat.S_IMODE(d[2])==0o700 and d[3]>=0 and d[4]>=0 and d[5]>0 and d==c['after_directory_identity'],'same complete existing directory')
 need(type(c['before_identity'])is dict and set(c['before_identity'])==set(before)and c['after_previous_identity']==c['before_identity'],'all original inode metadata held')
 for n,row in before.items():
  v=c['before_identity'][n];need(type(v)is list and len(v)==9 and all(type(x)is int for x in v),'whole file identity');dev,ino,mode,uid,gid,links,size,mtime,ctime=v;need(dev>=0 and ino>0 and stat.S_ISREG(mode)and uid==d[3]and gid>=0 and links==1 and size==row['bytes']and mtime>=0 and ctime>=0,'ordinary owned singlelink file unchanged')
 need(type(value['legacy_indexes'])is dict and set(value['legacy_indexes'])=={'32','20','8'},'all actual original CLI indexes')
 for case,a in p['archives'].items():
  i=value['legacy_indexes'][case];exact(i,'schema_version status original_inputs files bytes requests reused seconds_limit','closed original CLI index');need(all(type(i[k])is int for k in('schema_version','bytes','requests','reused','seconds_limit'))and i==dict(schema_version=1,status='EXACT_FROZEN574_ARCHIVE'+case+'_BYTES_ONLY_NOT_NATIVE_ACCEPTANCE',original_inputs=p['lock'],files=a['files'],bytes=a['total'],requests=0,reused=int(case),seconds_limit=180),'actual unchanged CLI full-reuse/zero-request index')
 return dict(status='PASS_WELCOME8_PASSIVE_INPUT_DATA_ONLY',source=p['source'],files=1154,selected=1148,before=len(before),native_authority=False)
