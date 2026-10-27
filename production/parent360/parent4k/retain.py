#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed-role native4K public DATA; original private roots/caches never exported."""
import argparse,json,os,sys,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C
ROLES=('result.json','public/result.json','public/adapter.json','public/producer.json','public/producer-cleanup.json','public/transaction-tail.log','owner.json','native4k-wrapper.json','wiring-owner.json')
def retain(source,output,proof,cleanup):
 C.need(source.is_absolute()and source.parent==Path('/tmp')and source.name=='cachy-asahi-updater604-recovery4k-'+str(proof['run'])+'-'+str(proof['attempt'])+'-'+proof['case'],'fixed same-run native4K owner path');C.need(not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh bounded public artifact');output.mkdir(mode=0o700);rows={};missing=[];total=0
 for n in ROLES:
  p=source/n
  if not p.exists():missing.append(n);continue
  raw=C.read(p,4*1024**2);total+=len(raw);C.need(total<=8*1024**2,'unchanged original8MiB retained cap');target=output/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);rows[n]=C.pin(raw)
 cleanup_raw=C.read(cleanup,256*1024);total+=len(cleanup_raw);C.need(total<=8*1024**2,'unchanged original8MiB retained cap');(output/'job-cleanup.json').write_bytes(cleanup_raw);rows['job-cleanup.json']=C.pin(cleanup_raw)
 v=dict(status='SOURCE_BOUND_NATIVE_ARM4K_UPDATER604_PUBLIC_DATA_NOT_ACCEPTANCE',wrapper=proof,held_owner_source=C.HELD,files=rows,missing=missing,total_bytes=total,scope='ORIGINAL_NATIVE_DOCKER_COPY_CRYPTO_TRANSACTION_PRESERVATION_AND_CLEANUP_NO16K_OR_HARDWARE_CREDIT',private_roots_source_cache='NOT_EXPORTED',root_acceptance='NOT_ISSUED');(output/'retention.json').write_bytes(C.enc(v));archive=output/'evidence.zip'
 with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_STORED)as z:
  for n in sorted([*rows,'retention.json']):z.writestr(n,C.read(output/n,4*1024**2))
 return dict(status=v['status'],files=len(rows)+1,missing=missing,archive=C.pin(C.read(archive,9*1024**2)))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('implementation','source-output','output','cleanup'):p.add_argument('--'+n,type=Path,required=True)
 for n in('source','workflow-sha'):p.add_argument('--'+n,required=True)
 p.add_argument('--case',choices=C.CASES,required=True);a=p.parse_args();proof=C.authenticate(a.implementation.absolute(),a.source,a.workflow_sha,a.case);print(json.dumps(retain(a.source_output.absolute(),a.output.absolute(),proof,a.cleanup.absolute()),sort_keys=True))
