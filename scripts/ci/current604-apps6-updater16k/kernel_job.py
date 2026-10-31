#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Existing exact kernel acquisition/build input and conservative owned cleanup."""
import argparse,base64,json,os,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import wiring as W
import vm as bridge
SHA='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'

def cleanup(work,output,source,case):
 C.need(work.is_absolute() and work.name=='managed-gui16k-kernel' and not any(p.is_symlink() for p in (work,*work.parents)),'dedicated ordinary kernel work')
 if not work.exists():return dict(status='NOT_CREATED',VM='NOT_RUN')
 marker=C.decode(C.read(work/'wiring-owner.json'));info=work.stat();C.need(marker['source']==source and marker['case']==case and marker['identity']==[info.st_dev,info.st_ino] and info.st_uid==os.getuid() and info.st_mode&0o7777==0o700,'recorded kernel directory identity')
 receipt=work/'helper/built/build-receipt.json'
 C.need(receipt.exists() and C.decode(C.read(receipt,65536))['status']=='BUILT_ONLY','RETAINED_KERNEL_BUILD_NOT_PROVEN_TERMINAL')
 home=output.with_name(output.name+'-job-home')
 if home.exists():
  child=C.decode(C.read(home/'child.json',256*1024));C.need(child['status']=='WAIT_RETURNED' and child['source']==source and child['case']==case and child['child']['group_absence_verified'] is True,'RETAINED_ORIGINAL_OWNER_GROUP_UNKNOWN')
 if output.exists():
  own=C.decode(C.read(output/'owner.json'));r=C.decode(C.read(output/'result.json'));vm=C.decode(C.read(output/'public/updater16k-cleanup.json'));job=C.decode(C.read(output/'wiring-owner.json'))
  C.need(own['output']==str(output) and own['purpose']=='expanded604-apps6-updater' and vm['status']=='PASS' and job['child']['group_absence_verified'] is True and r['producer_cleanup']=='PASS' and r['outer_cleanup']=='PASS' and r['caller_private_cleanup']=='PASS','RETAINED_CONSUMER_OR_PRODUCER_ABSENCE_UNKNOWN')
 C.need(shutil.rmtree.avoids_symlink_attacks,'safe owned tree removal');shutil.rmtree(work)
 if home.exists():
  C.need({p.name for p in home.iterdir()}=={'child.json'} and home.stat().st_uid==os.getuid() and not home.is_symlink(),'exact owned job HOME closure');(home/'child.json').unlink();home.rmdir()
 C.need(not work.exists(),'kernel remains');return dict(status='PASS_OWNED_KERNEL_WORK_REMOVED',source_archive_cache='PRESERVED_VERIFIED_ARCHIVE_ONLY')

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('seed','acquire','cleanup'));p.add_argument('--implementation',type=Path,required=True);p.add_argument('--source',required=True);p.add_argument('--case',choices=C.CASES,required=True)
 for n in ('work','cache','output','receipt'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args(argv);W.authorize(a.implementation,a.source,a.source,a.case)
 if a.mode=='cleanup':
  result=dict(status='FAIL')
  try:
   if (a.work/'helper/built/build-receipt.json').exists():
    bridge.kernel(argparse.Namespace(kernel_work=a.work,kernel_receipt=a.work/'helper/built/build-receipt.json',implementation=a.implementation))
    receipt=C.decode(C.read(a.work/'helper/built/build-receipt.json',65536));config=C.read(Path(receipt['config']['path']),262144)
    image=Path(receipt['image']['path']);C.need(image.is_relative_to(a.work) and Path(receipt['config']['path']).is_relative_to(a.work),'owned completed kernel metadata paths')
    with image.open('rb') as stream:header=stream.read(64)
    C.save(a.receipt.with_name('updater16k-kernel-metadata.json'),dict(status='ORIGINAL_COMPLETED_KERNEL_RECEIPT',receipt=receipt,receipt_pin=C.row(a.work/'helper/built/build-receipt.json'),config=dict(bytes=len(config),sha256=C.sha(config),base64=base64.b64encode(config).decode()),image_header=dict(bytes=len(header),sha256=C.sha(header),base64=base64.b64encode(header).decode()),whole_Image='NOT_EXPORTED_SOURCE_ENFORCED_JOIN_TO_GUEST_PROFILE'))
   result=cleanup(a.work,a.output,a.source,a.case)
  except Exception as e:result.update(error_type=type(e).__name__,error=str(e)[:2048])
  C.save(a.receipt,result);return int(result['status'] not in ('NOT_CREATED','PASS_OWNED_KERNEL_WORK_REMOVED'))
 fetch=W.load(a.implementation,'scripts/virtual/generic16k/fetch_inputs.py');acquire=W.load(a.implementation,'scripts/ci/tools-generic16k/acquire_kernel.py')
 hit=os.environ.get('KERNEL_CACHE_HIT','');matched=os.environ.get('KERNEL_CACHE_MATCHED_KEY','')
 if a.mode=='seed':
  C.need(acquire.cache_state(a.cache,hit,matched)=='MISS','true cache miss only');seed=W.load(a.implementation,'scripts/ci/tools-generic16k/retained_kernel.py');r=seed.download(a.cache,acquire,fetch.deadline_alarm,a.receipt)
  if r['status']=='RETAINED_ASSET_DOWNLOADED_HASH_VERIFIED':W.output('retained_archive',str(a.cache))
  else:C.need(r['status']=='RETAINED_ASSET_UNAVAILABLE','retained source failed')
  return 0
 C.need(not a.work.exists() and not a.work.is_symlink() and a.work.parent.is_dir(),'fresh owned kernel work');a.work.mkdir(mode=0o700);i=a.work.stat();C.save(a.work/'wiring-owner.json',dict(identity=[i.st_dev,i.st_ino],source=a.source,case=a.case));(a.work/'inputs').mkdir(mode=0o700)
 manifest,digest=fetch.load_manifest(a.implementation/'scripts/virtual/generic16k/inputs.json')
 acquire.acquire(fetch,manifest['inputs'][0],a.work/'inputs',digest,a.receipt,cache_archive=a.cache,cache_hit=hit,cache_matched_key=matched,retained_archive=os.environ.get('KERNEL_RETAINED_ARCHIVE') or None)
 helper=a.work/'helper';helper.mkdir(mode=0o700)
 for n in ('build_kernel.py','kernel.fragment'):shutil.copyfile(a.implementation/'scripts/ci/managed-gui-generic16k'/n,helper/n)
 return 0
if __name__=='__main__':raise SystemExit(main())
