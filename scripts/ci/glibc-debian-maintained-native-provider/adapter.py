#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit a source-pinned caa3 native harness; no native or prior acceptance."""
import argparse,hashlib,importlib.util,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import srcinfo
HERE=Path(__file__).resolve().parent
COPY=('LICENSE','abi.py','base-devel-fileless-evidence.json','build-entry.sh','collect_tests.py','header_check.py','header_probe.c','normal-child-exec.patch','normal-client-policy.json','normal-exec-change.json','normal_clients.py','ownership.py','provider_stage.py','stage.py')
CANDIDATE='scripts/ci/glibc-debian-maintained-provider'
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(ok,why):
 if not ok:raise ValueError(why)
def emit(root,bundle,bundle_pin,output):
 root=Path(root).absolute();bundle=Path(bundle).absolute();output=Path(output).absolute();need(not sys.flags.optimize and not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary unoptimized caa3 harness required')
 policy=json.loads((root/CANDIDATE/'authority.json').read_bytes());need(policy['status']=='ROOT_BOUND_DEBIAN_MAINTAINED_SOURCE_AUTHORITY','UNBOUND maintained authority; no harness or native actors')
 pins=json.loads((HERE/'dependency-pins.json').read_bytes())['files']
 for name,row in pins.items():need(pin((root/name).read_bytes())==row,'exact source helper differs: '+name)
 value=json.loads((bundle/'bundle.json').read_bytes());need(pin((bundle/'bundle.json').read_bytes())['sha256']==bundle_pin and value['package_version']=='2.43.caa3-1','exact new caa3 bundle required')
 need((bundle/'authority.json').read_bytes()==(root/CANDIDATE/'authority.json').read_bytes(),'bundle policy must equal frozen Root authority')
 old=root/'scripts/ci/glibc-gnu-provider';output.mkdir(mode=0o700)
 try:
  for name in COPY:shutil.copyfile(old/name,output/name)
  for src,dst in (('run.py','runner.py'),('materialize.py','original_inspector.py')):shutil.copyfile(old/src,output/dst)
  metadata=(old/'metadata.py').read_text();need(metadata.count('2.43.caa1')==2,'exact two metadata version anchors');(output/'metadata.py').write_text(metadata.replace('2.43.caa1','2.43.caa3'))
  for name in ('materialize.py','authority.py','bundle.py','source-lock.json','0002-held-builder-test-expectations.patch','source-provenance.json','NOTICE','authority.json','PKGBUILD.in'):shutil.copyfile(root/CANDIDATE/name,output/name)
  shutil.copyfile(root/'scripts/ci/glibc-debian-provider/auth.py',output/'auth.py')
  for name in ('source.py','run.py','native-layout.json'):shutil.copyfile(HERE/name,output/name)
  (output/'expected.SRCINFO').write_text(srcinfo.expected((bundle/'PKGBUILD').read_text()))
  receipt=dict(status='EMITTED_PRIVATE_CAA3_SOURCE_HARNESS_ONLY',unchanged_runner_sha256=pins['scripts/ci/glibc-gnu-provider/run.py']['sha256'],metadata_change='Exactly2 version constants caa1→caa3; all identity/dependency/BUILDINFO checks unchanged.',native='NOT_RUN',old_caa1_caa2_acceptance='NOT_REUSED');(output/'adapter-receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
  files={p.name:pin(p.read_bytes()) for p in sorted(output.iterdir())};need(len(files)<=32,'unchanged32-file harness cap')
  (output/'source-manifest.json').write_text(json.dumps(dict(schema_version=1,files=files),sort_keys=True,indent=2)+'\n')
  # Validate complete bundle through the emitted bridge, before any native actor.
  spec=importlib.util.spec_from_file_location('caa3_emitted_source',output/'source.py');m=importlib.util.module_from_spec(spec);oldpath=list(sys.path);sys.path.insert(0,str(output));cache={n:sys.modules.pop(n,None) for n in ('materialize','authority','bundle')}
  try:spec.loader.exec_module(m);m.inputs(bundle,bundle_pin)
  finally:
   sys.path[:]=oldpath
   for name,previous in cache.items():
    sys.modules.pop(name,None)
    if previous is not None:sys.modules[name]=previous
  return receipt
 except BaseException:shutil.rmtree(output);raise
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source-root',type=Path,required=True);p.add_argument('--bundle',type=Path,required=True);p.add_argument('--bundle-manifest-sha256',required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args();print(json.dumps(emit(args.source_root,args.bundle,args.bundle_manifest_sha256,args.output),sort_keys=True))
