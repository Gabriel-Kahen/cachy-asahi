#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Keep original closed public/failure bytes plus finite CI/kernel source proof."""
import argparse,base64,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import support as S
CAP=192*1024**2

def optional(C,path,cap=512*1024):
 if not path.exists() and not path.is_symlink():return None
 raw=C.read(path,cap);row=dict(bytes=len(raw),sha256=C.sha(raw),value=None)
 try:row['value']=C.decode(raw)
 except (ValueError,UnicodeError,RecursionError) as e:row['error_type']=type(e).__name__
 return row
def V(row):return row['value'] if row is not None and type(row.get('value')) is dict else {}
def retain(a,C):
 S.source(a.source,C);C.need(a.public.is_absolute() and not any(p.is_symlink() for p in (a.public,*a.public.parents)),'ordinary fixed public export');rows={};total=0
 if a.public.exists():
  for p in sorted(a.public.rglob('*')):
   C.need(not p.is_symlink(),'public links encoded by original retainer only')
   if p.is_dir():continue
   C.need(len(rows)<1500,'original collector entry bound');pin=C.row(p);C.need(pin['bytes']<=96*1024**2,'original collector per-file bound');total+=pin['bytes'];C.need(total<=CAP,'complete192MiB raw export cap');rows[p.relative_to(a.public).as_posix()]=pin
 else:a.public.mkdir(mode=0o700)
 # Never rewrite the original retention.json or any original failure bytes.
 base=optional(C,a.public/'retention.json',2*1024**2);kernel=optional(C,a.metadata);attempt=optional(C,a.metadata.with_name('repair16k-kernel-attempt.json'));cleanup=optional(C,a.kernel_cleanup,65536);proof=optional(C,a.proof,65536);ordered=optional(C,a.ordered,65536);handoff=optional(C,a.handoff,16384);acquire=optional(C,a.acquire,65536);seed=optional(C,a.seed,65536)
 who=V(handoff).get('identity');who=who if type(who) is dict else {}
 complete=(base is not None and V(base).get('status')==C.PASS+'_AND_ORDERED_TEARDOWN' and V(base).get('case')==a.case and V(base).get('native_host_acceptance') is False and not V(base).get('errors') and kernel is not None and cleanup is not None and V(cleanup).get('status')=='PASS_OWNED_KERNEL_WORK_REMOVED' and V(cleanup).get('case')==a.case and V(cleanup).get('source')==a.source_sha and ordered is not None and V(ordered).get('status')=='PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER' and V(ordered).get('case')==a.case and handoff is not None and V(handoff).get('status')=='DIRECT_JOB_REAPED_GROUP_ABSENT_INNER_CLEANUP_STILL_REQUIRED' and V(handoff).get('direct_reaped') is True and V(handoff).get('group_absent') is True and V(handoff).get('exit_code')==0 and V(handoff).get('cancellation_signal') is None and who.get('case')==a.case and who.get('source_sha')==a.source_sha and proof is not None and V(proof).get('case')==a.case and V(proof).get('source_sha')==a.source_sha)
 errors=[]
 if base:
  for name,pin in V(base).get('files',{}).items():C.need(rows.get(name)==pin,'original retained file hash differs: '+name)
  if set(rows)!=set(V(base).get('files',{}))|{'retention.json'}:complete=False;errors.append('original public closure incomplete or has unindexed data')
 else:errors.append('original retention missing')
 if kernel:
  try:
   k=kernel['value'];C.need(k['status']=='ACTUAL_COMPLETED_KERNEL_SOURCE_PROFILE_NOT_REUSED_BINARY_CLAIM','original completed kernel metadata');C.load('retained_profile_check',a.source/'scripts/ci/managed-gui-generic16k/kernel_contract.py').validate(k['profile']);r=k['receipt'];cfg=base64.b64decode(k['config']['base64'],validate=True);hdr=base64.b64decode(k['image_header']['base64'],validate=True)
   C.need(k['receipt_pin']==dict(bytes=len(C.encoded(r)),sha256=C.sha(C.encoded(r))) and k['config']['bytes']==len(cfg)==r['config']['bytes'] and k['config']['sha256']==C.sha(cfg)==r['config']['sha256'] and len(hdr)==k['image_header']['bytes']==64 and C.sha(hdr)==k['image_header']['sha256'] and hdr[56:60]==b'ARM\x64' and struct.unpack_from('<Q',hdr,24)[0]&1==0 and (struct.unpack_from('<Q',hdr,24)[0]>>1)&3==2 and {n:r['image'][n] for n in ('bytes','sha256')}==k['profile']['Image'] and {n:r['config'][n] for n in ('bytes','sha256')}==k['profile']['config'],'original raw kernel metadata joins')
   actual=optional(C,a.public/'lifecycle-public/repair16k-result.json',4*1024**2)
   C.need(actual and V(actual).get('kernel')==k['profile'] and V(actual).get('status')==C.PASS and V(actual).get('case')==a.case,'actual guest/profile/case joins')
  except (KeyError,TypeError,ValueError):complete=False;errors.append('original kernel or guest profile evidence incomplete/invalid')
 if not complete:errors.append('original run/source/kernel/ordered cleanup incomplete or failed; never admissible')
 own={};authorities={}
 try:
  C.need(getattr(a,'native_decisions',None) is not None and getattr(a,'kernel_authority_root',None) is not None,'immutable authority checkouts unavailable');native,binding=C.gate(a.source,a.case)
  for case,ref in binding['native_decisions'].items():
   data=native.checked(a.native_decisions,ref);name='repair16k-ci-authorities/native-'+case+'.json';own[name]=data;total+=len(data);authorities[case]=dict(source=binding['native_decision_source'],ref=ref,export=name)
  data=native.checked(a.kernel_authority_root,binding['kernel_authority']);name='repair16k-ci-authorities/prior-kernel-authority.json';own[name]=data;total+=len(data);authorities['kernel']=dict(source=binding['kernel_authority_source'],ref=binding['kernel_authority'],export=name)
 except (OSError,KeyError,ValueError):complete=False;errors.append('original native/prior-kernel authority evidence incomplete')
 for path in sorted(S.HERE.iterdir()):
  if path.is_dir():continue
  data=C.read(path,2*1024**2);name='repair16k-ci/'+path.name;C.need(name not in rows,'fresh own source evidence');own[name]=data;total+=len(data)
 value=dict(schema_version=1,status='GENERIC16K_REPAIR_ORIGINALS_RETAINED_NOT_ROOT_ACCEPTED',proof_complete=bool(complete),case=a.case,source_sha=a.source_sha,scope='GENERIC16K_VM_ONLY_NOT_NATIVE_HOST_OR_HARDWARE',files=rows,authorities=authorities,source_manifest=C.row(S.HERE/'source-manifest.json'),workflow=C.row(a.source/S.WF),kernel_attempt=attempt,kernel=kernel,kernel_cleanup=cleanup,kernel_acquisition=acquire,kernel_seed=seed,original_proof=proof,original_ordered_cleanup=ordered,original_handoff=handoff,errors=errors,original_lifecycle_retention=base,hardware='NOT_RUN',release='NOT_ADMITTED',root_maps='PRIVATE_SOURCE_ENFORCED_NOT_EXPORTED')
 for name,data in own.items():value['files'][name]=dict(bytes=len(data),sha256=C.sha(data))
 raw=C.encoded(value);C.need(len(raw)<=2*1024**2 and total+len(raw)<=CAP and len(rows)<1500,'complete metadata and originals within original caps')
 for name,data in own.items():path=a.public/name;path.parent.mkdir(exist_ok=True);path.write_bytes(data)
 with (a.public/'ci-retention.json').open('xb') as stream:stream.write(raw)
 return value

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('source','public','proof','ordered','handoff','metadata','kernel-cleanup','acquire','seed','native-decisions','kernel-authority-root'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--source-sha',required=True);p.add_argument('--case',choices=('repair-bytes','repair-missing'),required=True);a=p.parse_args(argv);C=S.bridge(a.source);result=retain(a,C);print(C.encoded(dict(status=result['status'],proof_complete=result['proof_complete'],case=a.case)).decode(),end='');return 0 if result['proof_complete'] else 1
if __name__=='__main__':raise SystemExit(main())
