# SPDX-License-Identifier: MIT
"""Source proof and DATA-only carrier receipt replay for the held574 producer."""
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

def validate_packages(root,p):
 """Validate prepared DATA receipt before any original nonpackage fetch."""
 need(type(p) is dict and set(p)=={'status','source','mode','actual','carrier','receipt'},'exact package DATA receipt schema')
 helper=load(root/O.LANE/'data_carrier.py','orphans03_data_receipt_replay');pairs=helper.pairs(root);seed=p['receipt']
 need(type(seed) is dict and set(seed)=={'actual_authority','mode','inputs','original_lock','cache'},'exact DATA cache receipt schema');cache=seed['cache']
 helper.validate_receipt(root,p['carrier'])
 need(p.get('status')=='EXACT_RETAINED_DATA_ARCHIVE_PREPARATION' and p.get('mode')=='desktop574' and p.get('actual') is None and p.get('source')==helper.SOURCE,'fixed DATA-only package preparation required')
 lock=root/'scripts/ci/maintained-desktop574-inputs.json';need(seed.get('actual_authority') is False and seed.get('mode')=='desktop574' and seed.get('inputs')==pairs and seed.get('original_lock')==dict(bytes=lock.stat().st_size,sha256=O.digest(lock)),'all1148 DATA inputs/original lock must join')
 need(type(cache) is dict and set(cache)=={'before_files','before_identity','after_previous_identity','added','after_files','fresh_cache','all_previous_inode_metadata_bytes_unchanged','directory_identity','after_directory_identity','normalized_files_mode'},'exact cache custody schema')
 identity=cache.get('directory_identity');need(type(identity) is list and len(identity)==5 and all(type(n) is int for n in identity) and identity[0]>=0 and identity[1]>0 and identity[2]==0o700 and identity[3]>=0 and identity[4]>=0,'ordinary normalized cache custody identity')
 need(cache.get('before_files')=={} and cache.get('before_identity')==cache.get('after_previous_identity')=={} and type(cache.get('added')) is int and cache.get('added')==1148 and cache.get('after_files')==pairs and cache.get('fresh_cache') is False and cache.get('all_previous_inode_metadata_bytes_unchanged') is True and identity==cache.get('after_directory_identity') and cache.get('normalized_files_mode')==0o600,'empty existing owned cache to exact1148 normalized DATA additions required')
 return dict(status='PASS_PACKAGE_DATA_ONLY',packages=1148,source=helper.SOURCE,native_authority=False,git_authority=False,requests=1)

def validate_transport(root,value):
 """Replay complete pinned DATA closure/cache1148 and exact original five fetches."""
 need(type(value) is dict and set(value)=={'status','packages','nonpackages','actual'},'exact hosted DATA receipt schema')
 need(value.get('status')=='PASS_RETAINED1148_DATA_ARCHIVE_AND_FIVE_ORIGINAL_NONPACKAGE_DATA' and value.get('actual') is None,'complete hosted DATA input receipt required')
 package=validate_packages(root,value['packages']);lock=root/'scripts/ci/maintained-desktop574-inputs.json'
 original=load(root/'scripts/ci/maintained_desktop574.py','orphans03_hosted_original_plan');inputs=O.read(lock);items=original.plan(inputs,Path('/context'));other=[r for r in items if r['target'].parent.name!='deps'];actual=value['nonpackages']
 need(type(actual) is list and len(items)==1153 and len(other)==len(actual)==5,'five original nonpackage receipts required')
 for expected,row in zip(other,actual):need(type(row) is dict and set(row)=={'filename','source','bytes'} and row['filename']==expected['filename'] and type(row['bytes']) is int and row['bytes']==expected['size'] and row['source'] in ('existing_exact_seed',expected['url']),'original five plan/fetch receipt differs')
 return dict(status='PASS_HOSTED_DATA_INPUT_RECEIPT_ONLY',packages=1148,nonpackages=5,source=package['source'],native_authority=False,git_authority=False,requests=1)
