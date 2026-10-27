# SPDX-License-Identifier: MIT
"""Orphans source-proof facade for the byte-held Setup8 hosted producer."""
import re,stat
from pathlib import Path
import contract as O
need=O.need;safe=O.safe

def read(path,cap=16*1024**2):
 path=safe(path);before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=cap,'bounded ordinary single-link source required');raw=path.read_bytes();after=path.lstat()
 need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')),'source changed during read');return raw

def load(path,name):return O.load(name,path)
def save(path,value):path.write_bytes(O.encoded(value))
def verify(root,expected):
 need(O.digest(root/O.LANE/'source-manifest.json')==expected,'reviewed manifest digest differs');O.verify_source(root)

def validate_transport(root,value):
 """Replay held source/Git/cache1148 predicates and exact five fetch receipts."""
 need(value.get('status')=='PASS_RETAINED1148_AND_FIVE_ORIGINAL_NONPACKAGE_DATA' and value.get('actual') is None,'complete hosted input receipt required')
 inputs=O.read(root/'scripts/ci/maintained-desktop574-inputs.json');pairs={}
 for row in inputs['packages']:
  pairs[row['filename']]=dict(bytes=row['size'],sha256=row['sha256']);pairs[row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
 need(len(pairs)==1148,'exact1148 package inputs required');p=value['packages'];identity=p['carrier'];seed=p['receipt'];cache=seed['cache']
 profile=O.read(root/'scripts/ci/setup6-retained-helpers/carrier-profile.json')
 need(p.get('status')=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY' and p.get('mode')=='desktop574' and p.get('actual') is None and p.get('source')==profile['source']=='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad','fixed source-only package carrier required')
 need(identity.get('source')==profile['source'] and identity.get('ref')==profile['ref'] and identity.get('status')=='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY' and identity.get('files')==identity.get('blob_joins')==1154 and re.fullmatch('[0-9a-f]{40}',identity.get('tree','')),'complete immutable Git/blob proof required')
 lock=root/'scripts/ci/maintained-desktop574-inputs.json';need(seed.get('actual_authority') is False and seed.get('mode')=='desktop574' and seed.get('inputs')==pairs and seed.get('original_lock')==dict(bytes=lock.stat().st_size,sha256=O.digest(lock)),'all1148 DATA inputs/original lock must join')
 need(cache.get('before_files')=={} and cache.get('before_identity')==cache.get('after_previous_identity')=={} and cache.get('added')==1148 and cache.get('after_files')==pairs and cache.get('fresh_cache') is False and cache.get('all_previous_inode_metadata_bytes_unchanged') is True and cache.get('directory_identity')==cache.get('after_directory_identity'),'empty existing cache to exact1148 additions required')
 original=load(root/'scripts/ci/maintained_desktop574.py','hosted_receipt_plan');items=original.plan(inputs,Path('/context'));other=[r for r in items if r['target'].parent.name!='deps'];actual=value['nonpackages']
 need(len(items)==1153 and len(other)==len(actual)==5,'five original nonpackage receipts required')
 for expected,row in zip(other,actual):need(set(row)=={'filename','source','bytes'} and row['filename']==expected['filename'] and row['bytes']==expected['size'] and row['source'] in ('existing_exact_seed',expected['url']),'original five plan/fetch receipt differs')
 return dict(status='PASS_HOSTED_INPUT_RECEIPT_ONLY',packages=1148,nonpackages=5,source=profile['source'],native_authority=False)
