#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit a finite private harness; no native work and no old acceptance binding."""
import argparse,hashlib,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import auth as A
HERE=Path(__file__).resolve().parent
COPY=('LICENSE','abi.py','base-devel-fileless-evidence.json','build-entry.sh','collect_tests.py','header_check.py','header_probe.c','normal-child-exec.patch','normal-client-policy.json','normal-exec-change.json','normal_clients.py','ownership.py','provider_stage.py','stage.py')
def emit(root,output):
 root=Path(root).absolute();output=Path(output).absolute();A.need(not sys.flags.optimize and not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary unoptimized harness output required')
 pins=A.decode(A.read(HERE/'dependency-pins.json',65536))['files']
 for n,row in pins.items():A.need(A.pin(A.read(root/n))==row,'original helper byte identity differs: '+n)
 old=root/'scripts/ci/glibc-gnu-provider';output.mkdir(mode=0o700)
 try:
  for n in COPY:shutil.copyfile(old/n,output/n)
  for src,dst in (('run.py','runner.py'),('materialize.py','original_inspector.py')):shutil.copyfile(old/src,output/dst)
  metadata=A.read(old/'metadata.py').decode();A.need(metadata.count('2.43.caa1')==2,'exact metadata version anchors required');(output/'metadata.py').write_text(metadata.replace('2.43.caa1','2.43.caa2'))
  for n in ('run.py','materialize.py','auth.py','authority.json','expected.SRCINFO'):shutil.copyfile(HERE/n,output/n)
  receipt=dict(status='EMITTED_PRIVATE_NEW_DEBIAN_SOURCE_HARNESS_ONLY',unchanged_runner_sha256=pins['scripts/ci/glibc-gnu-provider/run.py']['sha256'],unchanged_helpers={n:pins['scripts/ci/glibc-gnu-provider/'+n] for n in COPY},metadata_change='Only exact2 package version constants caa1→caa2; field/dependency/BUILDINFO checks unchanged.',entrypoint='Explicit new source validator/API; unchanged native execute/check/ABI/compiler/normal probes/ownership/cleanup; old job.admission/bindings never copied or called.',authority=A.decode(A.read(HERE/'authority.json',65536))['status'],native='NOT_RUN',old_native_pair='NOT_REUSED')
  (output/'adapter-receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
  files={p.name:A.pin(A.read(p)) for p in sorted(output.iterdir())};A.need(len(files)<=32,'original finite harness file bound');(output/'source-manifest.json').write_text(json.dumps(dict(schema_version=1,files=files),sort_keys=True,indent=2)+'\n');return receipt
 except BaseException:shutil.rmtree(output);raise
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source_root,a.output),sort_keys=True))
