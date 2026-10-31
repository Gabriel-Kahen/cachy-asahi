#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Seven ordinary originals, <=8MiB total, one existing bounded log frame."""
import argparse,base64,os,stat,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import wiring as W
NAMES=('result.json','public/result.json','public/adapter.json','public/producer.json','public/producer-cleanup.json','public/transaction-tail.log')
CAP=8*1024**2

def optional(path,cap):
 if not path.exists() and not path.is_symlink():return None
 raw=C.read(path,cap);return dict(bytes=len(raw),sha256=C.sha(raw),value=C.decode(raw))

def kernel_join(kernel,root):
 try:
  if kernel['status']!='ORIGINAL_COMPLETED_KERNEL_RECEIPT':return False
  receipt=kernel['receipt'];raw=C.encoded(receipt);config=base64.b64decode(kernel['config']['base64'],validate=True);header=base64.b64decode(kernel['image_header']['base64'],validate=True);proof=root['generic16k'];profile=proof['kernel']
  return (kernel['receipt_pin']==dict(bytes=len(raw),sha256=C.sha(raw))==proof['kernel_receipt'] and kernel['config']['bytes']==len(config) and kernel['config']['sha256']==C.sha(config)==receipt['config']['sha256']==profile['config']['sha256'] and len(config)==receipt['config']['bytes']==profile['config']['bytes'] and receipt['image']['sha256']==profile['Image']['sha256'] and receipt['image']['bytes']==profile['Image']['bytes'] and kernel['image_header']['bytes']==len(header)==64 and kernel['image_header']['sha256']==C.sha(header) and header[56:60]==b'ARM\x64' and struct.unpack_from('<Q',header,24)[0]&1==0 and (struct.unpack_from('<Q',header,24)[0]>>1)&3==2)
 except (KeyError,TypeError,ValueError):return False

def retain(source,target,kernel,source_sha,case,kernel_cleanup,acquisition,seed):
 C.need(case in C.CASES and source.is_absolute() and source.parent==Path('/tmp') and not source.is_symlink() and not target.exists() and not any(p.is_symlink() for p in (target,*target.parents)),'fixed owned original/output roles')
 rows={};raws={};total=0
 for name in NAMES:
  path=source/name
  if not path.exists():continue
  data=C.read(path,4*1024**2);total+=len(data);C.need(total<=CAP,'original transport8MiB raw bound');raws[name]=data;rows[name]=dict(bytes=len(data),sha256=C.sha(data))
 owner=optional(source/'owner.json',65536)
 if rows:C.need(owner and owner['value']['purpose']=='expanded604-apps6-updater' and owner['value']['output']==str(source) and owner['value']['case']==case,'actual original owner identity')
 job=optional(source/'wiring-owner.json',256*1024);vm=optional(source/'public/updater16k-cleanup.json',512*1024)
 root=C.decode(raws['result.json']) if 'result.json' in raws else None
 proof_errors=[]
 if root is not None and root.get('status')=='PASS':
  if not (set(rows)==set(NAMES) and root.get('scope')=='GENERIC16K_VM_APPS5_TO6_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY' and job and job['value']['status']=='PASS' and job['value']['source']==source_sha and job['value']['case']==case and job['value']['child']['exit_code']==0 and job['value']['child']['group_absence_verified'] is True and vm and vm['value']['status']=='PASS'):proof_errors.append('complete actual16K source/child/VM cleanup required for original PASS')
  try:valid=root['generic16k']['status']==C.PASS and root['generic16k']['guest']['page_size']==16384 and root['producer_cleanup']==root['outer_cleanup']==root['caller_private_cleanup']=='PASS'
  except (KeyError,TypeError):valid=False
  if not valid:proof_errors.append('complete actual16K/producer/outer teardown')
 else:proof_errors.append('original runtime missing or failed')
 metadata=dict(schema_version=1,status='ORIGINALS_RETAINED_NOT_ACCEPTED',case=case,source_sha=source_sha,files=rows,raw_bytes=total,scope='GENERIC16K_VM_APPS5_TO6_CURRENT604_SOFTWARE_ONLY',owner=owner,job=job,vm_cleanup=vm,kernel_cleanup=optional(kernel_cleanup,65536),kernel_acquisition=optional(acquisition,65536),kernel_seed=optional(seed,65536),kernel=kernel,private_root_maps='NOT_EXPORTED_SOURCE_ENFORCED',hardware='NOT_RUN',release='NOT_ADMITTED')
 if not kernel_join(kernel,root):proof_errors.append('original completed kernel receipt/config/header join missing or failed')
 if not (metadata['kernel_cleanup'] and metadata['kernel_cleanup']['value']['status']=='PASS_OWNED_KERNEL_WORK_REMOVED'):proof_errors.append('kernel teardown missing or failed')
 metadata.update(proof_complete=not proof_errors,proof_failures=proof_errors,completion='COMPLETE_ORIGINALS_AWAIT_ROOT_ADMISSION' if not proof_errors else 'INCOMPLETE_OR_FAILED_NOT_ADMISSIBLE')
 encoded=C.encoded(metadata);C.need(len(encoded)<=2*1024**2 and total+len(encoded)<=CAP,'complete seven-file8MiB closure including metadata')
 target.mkdir(mode=0o700)
 for name,data in raws.items():p=target/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
 (target/'retention.json').write_bytes(encoded);return metadata

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('implementation','source','target','kernel-metadata','kernel-cleanup','acquisition','seed'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--source-sha',required=True);p.add_argument('--case',choices=C.CASES,required=True);a=p.parse_args(argv)
 # Retention also works after preflight refusal; it never evaluates a bound
 # policy or launches an actor, and cannot turn missing originals into PASS.
 W.check_source(a.implementation)
 kernel=C.decode(C.read(a.kernel_metadata,512*1024)) if a.kernel_metadata.exists() else dict(status='NOT_AVAILABLE_NO_COMPLETED_KERNEL_CLAIM')
 result=retain(a.source,a.target,kernel,a.source_sha,a.case,a.kernel_cleanup,a.acquisition,a.seed)
 logger=W.load(a.implementation,'scripts/ci/log_evidence.py');data=logger.bundle(a.target);C.need(len(data)<=CAP,'original compressed frame bound')
 import base64,hashlib
 print('CACHY_ASAHI_EVIDENCE_BEGIN '+a.target.name+' sha256='+hashlib.sha256(data).hexdigest()+' bytes='+str(len(data)));print(base64.encodebytes(data).decode(),end='');print('CACHY_ASAHI_EVIDENCE_END '+a.target.name)
 return 0 if result['proof_complete'] else 1
if __name__=='__main__':raise SystemExit(main())
