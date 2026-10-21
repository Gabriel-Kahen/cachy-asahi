#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Exact existing archive/helper; remove owned kernel only after all consumers."""
import argparse,base64,os,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import support as S
SHA='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'
def attempt(a,C):
 value=dict(status='KERNEL_ATTEMPT_ORIGINALS_ONLY_NOT_COMPLETED_BUILD_AUTHORITY',case=a.case,source=os.environ['SOURCE_SHA'],files={},errors=[])
 for name,relative,cap in [('receipt','helper/built/build-receipt.json',65536),('controller','controller.log',2*1024**2)]:
  path=a.work/relative
  if not path.exists() and not path.is_symlink():continue
  try:
   raw=C.read(path,cap);tail=raw if name=='receipt' else raw[-65536:];value['files'][name]=dict(bytes=len(raw),sha256=C.sha(raw),retained_bytes=len(tail),retained_sha256=C.sha(tail),base64=base64.b64encode(tail).decode(),complete=len(tail)==len(raw))
  except (OSError,ValueError) as e:value['errors'].append(dict(role=name,error_type=type(e).__name__))
 C.save(a.receipt.with_name('repair16k-kernel-attempt.json'),value);return value
def cleanup(a,C):
 C.need(a.work.is_absolute() and a.work.name=='managed-gui16k-kernel' and not any(p.is_symlink() for p in (a.work,*a.work.parents)),'dedicated ordinary kernel work')
 if not a.work.exists():return dict(status='NOT_CREATED',kernel='NOT_RUN')
 marker=C.decode(C.read(a.work/'ci-owner.json'));info=a.work.stat();C.need(marker==dict(source=os.environ['SOURCE_SHA'],case=a.case,identity=[info.st_dev,info.st_ino]) and info.st_uid==os.getuid() and info.st_mode&0o7777==0o700,'exact owned kernel inode/source/case')
 attempt(a,C) # Failed/partial originals survive the unchanged BUILT_ONLY guard.
 receipt=a.work/'helper/built/build-receipt.json';profile,image,config=S.kernel(C,a.source,a.work,receipt)
 # Preserve original kernel proof before deleting the exact work tree.
 r=C.decode(C.read(receipt,65536));cfg=C.read(config,262144)
 with image.open('rb') as stream:header=stream.read(64)
 C.save(a.receipt.with_name('repair16k-kernel-metadata.json'),dict(status='ACTUAL_COMPLETED_KERNEL_SOURCE_PROFILE_NOT_REUSED_BINARY_CLAIM',receipt=r,receipt_pin=C.row(receipt),profile=profile,config=dict(bytes=len(cfg),sha256=C.sha(cfg),base64=base64.b64encode(cfg).decode()),image_header=dict(bytes=len(header),sha256=C.sha(header),base64=base64.b64encode(header).decode())))
 original=C.load('kernel_consumer_supervisor',a.source/'scripts/ci/orphans-full574-native/supervise.py')
 who=S.bridge(a.source).load('kernel_ci_owner',a.source/S.LANE/'owner.py').identity(C,a.proof,a.source,a.case,a.handoff)
 original.check(a.handoff,who,a.job_outcome=='skipped')
 ordered=C.decode(C.read(a.ordered,65536));C.need(ordered['status']=='PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER' and ordered['case']==a.case and ordered['consumer']=='PASS_ALL_ACTORS_COPIES_KEYS_AND_SOURCE_RETIRED' and ordered['authority']=='PASS_REMOVED_AFTER_CONSUMER_ABSENCE' and ordered['producer']['status']=='PASS','ordered original source/actors/producer absence')
 if a.output.exists():
  state=a.output/'repair16k-state.json'
  if state.exists():C.need(C.decode(C.read(state))['status']=='PASS_VM_GROUP_AND_PRIVATE_MEDIA_RETIRED','VM/media unknown: keep kernel')
  C.need(not (a.output/'repair16k').exists() and not (a.output/'repair16k-media').exists(),'no surviving bridge/media backing state')
 C.need(shutil.rmtree.avoids_symlink_attacks,'safe owned directory deletion');shutil.rmtree(a.work);C.need(not a.work.exists(),'kernel work remains');return dict(status='PASS_OWNED_KERNEL_WORK_REMOVED',case=a.case,source=os.environ['SOURCE_SHA'],cache='PRESERVED_ARCHIVE_ONLY')
def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('seed','acquire','cleanup'));p.add_argument('--source',type=Path,required=True);p.add_argument('--case',choices=('repair-bytes','repair-missing'),required=True)
 for n in ('work','cache','output','receipt','proof','handoff','ordered'):p.add_argument('--'+n,type=Path,required=n in ('work','cache','output','receipt'))
 p.add_argument('--job-outcome',choices=('success','failure','cancelled','skipped'));a=p.parse_args(argv);C,_,_=S.authorize(a.source,a.case)
 if a.mode=='cleanup':
  result=dict(status='FAIL_KERNEL_RETAINED_ABSENCE_UNKNOWN',case=a.case)
  try:result=cleanup(a,C)
  except Exception as e:result.update(error_type=type(e).__name__,error=str(e)[:1024])
  C.save(a.receipt,result);return int(result['status'] not in ('NOT_CREATED','PASS_OWNED_KERNEL_WORK_REMOVED'))
 fetch=C.load('kernel_fetch',a.source/'scripts/virtual/generic16k/fetch_inputs.py');acquire=C.load('kernel_acquire',a.source/'scripts/ci/tools-generic16k/acquire_kernel.py');hit=os.environ.get('KERNEL_CACHE_HIT','');matched=os.environ.get('KERNEL_CACHE_MATCHED_KEY','')
 if a.mode=='seed':
  C.need(acquire.cache_state(a.cache,hit,matched)=='MISS','true cache miss only');seed=C.load('kernel_retained',a.source/'scripts/ci/tools-generic16k/retained_kernel.py');r=seed.download(a.cache,acquire,fetch.deadline_alarm,a.receipt)
  if r['status']=='RETAINED_ASSET_DOWNLOADED_HASH_VERIFIED':S.output('retained_archive',str(a.cache))
  else:C.need(r['status']=='RETAINED_ASSET_UNAVAILABLE','retained source failed')
  return 0
 C.need(not a.work.exists() and not a.work.is_symlink() and a.work.parent.is_dir(),'fresh owned kernel work');a.work.mkdir(mode=0o700);i=a.work.stat();C.save(a.work/'ci-owner.json',dict(source=os.environ['SOURCE_SHA'],case=a.case,identity=[i.st_dev,i.st_ino]));(a.work/'inputs').mkdir(mode=0o700)
 manifest,digest=fetch.load_manifest(a.source/'scripts/virtual/generic16k/inputs.json');acquire.acquire(fetch,manifest['inputs'][0],a.work/'inputs',digest,a.receipt,cache_archive=a.cache,cache_hit=hit,cache_matched_key=matched,retained_archive=os.environ.get('KERNEL_RETAINED_ARCHIVE') or None)
 helper=a.work/'helper';helper.mkdir(mode=0o700)
 for name in ('build_kernel.py','kernel.fragment'):shutil.copyfile(a.source/'scripts/ci/managed-gui-generic16k'/name,helper/name)
 return 0
if __name__=='__main__':raise SystemExit(main())
