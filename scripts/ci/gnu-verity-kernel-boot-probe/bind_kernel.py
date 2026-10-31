#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Passive Root build-input binding; never supplies boot-run authority."""
import argparse,json,tempfile
from pathlib import Path
import contract as C

def descriptor(decision_raw,result_raw):
 v=C.obj(decision_raw);r=C.obj(result_raw);a=v['artifact']
 C.need(C.pin(result_raw)==v['strict_replay'],'whole Root accepted strict result')
 return dict(schema_version=1,status='ROOT_BOUND_KERNEL_BUILD_INPUT_ONLY',source=v['source'],ref=v['ref'],run_id=str(v['run']),attempt=v['attempt'],artifact=dict(id=a['id'],name=a['name'],bytes=a['bytes'],sha256=a['digest'].removeprefix('sha256:')),members=v['files'],Root_decision=C.pin(decision_raw),Root_strict_result=C.pin(result_raw),Image=v['Image'],config=v['config'],profile=v['profile'],kernel_release=C.P.RELEASE,historical_transport={n:C.pin(C.read(C.HERE/'kernel-provenance'/n,8*1024**2))for n in('run.json','artifacts.json','logs.zip','collection-outcome.json','bound-original.json')})

def bind(decision,result,originals,lane):
 # Whole accepted result plus passive original first-attempt transport replay.
 raw=C.read(decision);strict=C.read(result,2*1024**2);d=descriptor(raw,strict)
 C.need(lane.is_dir()and all(C.read(lane/n)==b'null\n'for n in('kernel-descriptor.json','Root-build-decision.json','kernel-build-result.json')),'bind fresh NULL input authority exactly once')
 with tempfile.TemporaryDirectory(prefix='boot-kernel-passive-',dir=lane.parent)as tmp:
  t=Path(tmp);(t/'input-policy.json').write_bytes(C.read(lane/'input-policy.json'));(t/'kernel-descriptor.json').write_bytes(C.encoded(d));(t/'Root-build-decision.json').write_bytes(raw);(t/'kernel-build-result.json').write_bytes(strict);import shutil;shutil.copytree(C.HERE/'kernel-provenance',t/'kernel-provenance');C.bound(t)
  from unittest.mock import patch
  with patch.object(C,'HERE',t):
   # Trusted kernel-reader support remains the same finite byte closure.
   shutil.copytree(lane/'kernel-reader',t/'kernel-reader');files,checked=C.input_replay(originals,d,t/'strict-original')
  C.need(checked==C.obj(strict),'whole genuine kernel strict result replay equals Root accepted DATA')
 for name,b in(('kernel-descriptor.json',C.encoded(d)),('Root-build-decision.json',raw),('kernel-build-result.json',strict)):(lane/name).write_bytes(b)
 C.bound(lane);return dict(status='PASSIVE_BOUND_BUILD_INPUT_ONLY_BOOT_NOT_RUN',descriptor=C.pin(C.encoded(d)),members=len(files),Image=d['Image'],actual_boot_source=None,actual_boot_ref=None,actual_boot_run=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('decision','result','originals','lane'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(bind(a.decision.absolute(),a.result.absolute(),a.originals.absolute(),a.lane.absolute()),sort_keys=True))
