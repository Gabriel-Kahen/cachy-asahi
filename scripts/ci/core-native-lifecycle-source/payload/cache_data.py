# SPDX-License-Identifier: MIT
"""Finite full1154/1148 and original80 cache DATA, never package authority."""
import hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 209505, 'sha256': 'bb1d1140ce514a663ca3db13e80d82494b8ac95def72b1c3d13036e676fcf9e8'}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def profile():
 raw=(HERE/'cache-profile.json').read_bytes();need(pin(raw)==PROFILE,'whole fixed original cache profile');return json.loads(raw)
def validate(complete,legacy):
 p=profile();need(complete['status']=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY'and complete['mode']=='desktop574'and complete['source']==p['source']and complete['carrier']==p['proof']and complete['actual']is None and complete['hardware']=='NOT_RUN','full original1154 commit/tree/blob/cache proof only')
 r=complete['receipt'];need(r['status']=='EXACT_PUBLIC_CACHE_INPUTS_JOINED_NOT_AUTHENTICATED'and r['mode']=='desktop574'and r['original_lock']==p['lock']and r['inputs']==p['selected']and r['actual_authority']is False and r['versions']=='UNCHANGED','same full1148 signed inputs, no authentication waiver');c=r['cache'];before=c['before_files'];need(set(p['mandatory_before'])<=set(before)<=set(p['mandatory_before'])|set(p['optional_before']),'all original80 plus only original rootfs/keyring')
 expected=dict(p['mandatory_before'],**{n:p['optional_before'][n]for n in before if n in p['optional_before']});need(before==expected and c['after_files']==dict(p['selected'],**{n:v for n,v in before.items()if n in p['optional_before']}),'whole before80/rootfs/keyring and after1148 original bytes')
 need(c['fresh_cache']is False and c['all_previous_inode_metadata_bytes_unchanged']is True and c['mode']==0o700 and c['owner']=='CALLER_UID'and c['added']==len(set(p['selected'])-set(before)),'same owned cache with selected missing inputs only');d=c['directory_identity'];need(type(d)is list and len(d)==6 and all(type(v)is int for v in d)and d[0]>=0 and d[1]>0 and stat.S_ISDIR(d[2])and stat.S_IMODE(d[2])==0o700 and d[3]>=0 and d[4]>=0 and d[5]>0 and c['after_directory_identity']==d,'same complete owned0700 cache inode identity')
 need(set(c['before_identity'])==set(before)and c['after_previous_identity']==c['before_identity'],'all previous inode/owner/link/size/time identities held')
 for n,row in before.items():
  v=c['before_identity'][n];need(type(v)is list and len(v)==9 and all(type(k)is int for k in v),'whole existing file stat identity');dev,ino,mode,uid,gid,links,size,mtime,ctime=v;need(dev>=0 and ino>0 and stat.S_ISREG(mode)and uid==d[3]and gid>=0 and links==1 and size==row['bytes']and mtime>=0 and ctime>=0,'every existing file ordinary singlelink same bytes and metadata')
 need(set(legacy)=={'32','20','8'},'all three original CLI/seed cases')
 for case,want in p['archives'].items():
  value=legacy[case];i=value['index'];custody=value['custody'];need(set(i)=={'schema_version','status','original_inputs','files','bytes','requests','reused','seconds_limit'}and type(i['schema_version'])is int and i['schema_version']==1 and i['status']=='EXACT_FROZEN574_ARCHIVE'+case+'_BYTES_ONLY_NOT_NATIVE_ACCEPTANCE'and i['original_inputs']==p['lock']and i['files']==want['files']and i['bytes']==want['total'],'whole original policy index bytes and case')
  need(type(i['requests'])is int and i['requests']==0 and type(i['reused'])is int and i['reused']==int(case)and i['seconds_limit']==180,'unchanged hard180 legacy clocks and zero requests/full reuse')
  need(custody==dict(status='EXACT_ORIGINAL'+case+'_SEEDED_BEFORE_UNCHANGED_BUILD',files=int(case),bytes=want['total'],original_inputs=p['lock']),'exact original unmodified seed return')
 return dict(status='PASS_FINITE_CACHE_DATA_ONLY',previous_inputs=len(before),selected_inputs=1148,source_files=1154,actual_authority=False,authentication='ALL_ORIGINAL_CURRENT_GPG_METADATA_AND_NATIVE_GATES_REQUIRED')
