#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Thin NEW-source entrypoint over the byte-pinned unchanged native pair executor."""
import argparse,hashlib,importlib.util,json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import source as S
M=S.M
HERE=Path(__file__).resolve().parent
def runner():
 receipt=json.loads((HERE/'adapter-receipt.json').read_bytes());path=HERE/'runner.py';M.need(hashlib.sha256(path.read_bytes()).hexdigest()==receipt['unchanged_runner_sha256']=='a755cb4e7191da3cdef785bbf77dfcc241dfe9e2b0da13d3e85ae7ccc17102a9','exact original executor required')
 spec=importlib.util.spec_from_file_location('maintained_debian_original_pair_executor',path);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
 r.PACKAGE='cachy-asahi-glibc-gnu-provider-2.43.caa3-1-aarch64.pkg.tar.xz';r.LABEL='org.cachy-asahi.glibc-debian-maintained-provider.job';r.inputs=S.inputs
 return r

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for key in ('bundle','base-dir','source-root','smoke-dir','smoke-manifest','output'):p.add_argument('--'+key,type=Path,required=True)
 for key in ('bundle-manifest-sha256','harness-manifest-sha256','owner-token'):p.add_argument('--'+key,required=True)
 p.add_argument('--execute',action='store_true');a=p.parse_args();M.need(not sys.flags.optimize,'ordinary unoptimized Python required');r=runner()
 harness=r.verify_sources(HERE,HERE/'source-manifest.json',a.harness_manifest_sha256);selected=S.inputs(a.bundle,a.bundle_manifest_sha256);smoke=r.verify_sources(a.smoke_dir,a.smoke_manifest,r.SMOKE)
 if not a.execute:print(json.dumps(dict(status='VALIDATED_NEW_DEBIAN_SOURCE_INPUTS_ONLY',source=selected['source'],native_build='NOT_RUN')));return 0
 # Old GNUcaa1 private16K/native-pair admission is never borrowed for this source.
 a.private16k_admission=dict(status='NOT_RUN_NEW_DEBIAN_SOURCE_NO_OLD_PAIR_CREDIT',source_authority=selected['authentication']['authority'])
 spec=importlib.util.spec_from_file_location('debian_normal_probes',HERE/'normal_clients.py');normal=importlib.util.module_from_spec(spec);spec.loader.exec_module(normal);normal.policy()
 runtime=r.process_module(r.ordinary(a.source_root)/'scripts/port/kernel-native-job/runtime.py')
 with runtime.cancellation_handlers():return r.execute(a,selected,smoke,harness,runtime)
if __name__=='__main__':
 try:raise SystemExit(main())
 except (ValueError,OSError,KeyError) as error:print(json.dumps(dict(status='REFUSED_BEFORE_NEW_NATIVE_ACTORS',error=str(error),security='NO_CREDIT',release='NOT_ADMITTED')));raise SystemExit(1)
