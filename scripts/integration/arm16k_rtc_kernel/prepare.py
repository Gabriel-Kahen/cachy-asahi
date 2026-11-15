#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit a small DATA-only RTC recipe. Never execute Linux scripts or tools."""
import argparse,hashlib,importlib.util,json,tarfile
from pathlib import Path
HERE=Path(__file__).resolve().parent


def contract():
 spec=importlib.util.spec_from_file_location('rtc_kernel_contract',HERE/'contract.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify_archive(path,C):
 lock=C.lock();C.checked(path,lock['archive']);wanted={lock['archive']['root']+'/drivers/rtc/'+a:b for a,b in [('Kconfig','rtc.Kconfig'),('Makefile','rtc.Makefile'),('rtc-pl031.c','rtc-pl031.c')]};found=set()
 with tarfile.open(path,'r|gz') as archive:
  for member in archive:
   if member.name in wanted:
    if not member.isfile() or member.size>131072:raise ValueError('bounded ordinary RTC source operand required')
    raw=archive.extractfile(member).read();expected=lock['data'][wanted[member.name]]
    if len(raw)!=expected['bytes'] or hashlib.sha256(raw).hexdigest()!=expected['sha256']:raise ValueError('RTC source differs from exact retained archive')
    found.add(member.name)
 if found!=set(wanted):raise ValueError('complete RTC source operands required')
 return C.dependencies()


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();C=contract();dependencies=verify_archive(a.archive,C)
 original=C.data();requested=C.construct(original)
 if C.inverse(requested)!=original:raise ValueError('exact requested-config inverse differs')
 out=a.output.absolute();out.mkdir(mode=0o700,parents=False,exist_ok=False);(out/'requested.config').write_bytes(requested)
 recipe={'schema_version':1,'status':'DATA_PREPARED_KERNEL_CODE_NOT_RUN','operation':C.lock()['operation'],'source':C.lock()['archive'],'requested_config':C.pin(out/'requested.config'),'baseline':C.pin(HERE/'data/baseline.config'),'feature_delta':C.delta(original,requested),'dependencies':dependencies,'original_tool_provenance':C.pin(HERE/'data/original-build-receipt.json'),'next':'Root must admit isolated tool image/configure-only; review/pin exact compiler facts before compile','resource_proposal':C.lock()['build'],'resource_authority':None,'configure':'NOT RUN','compile':'NOT RUN','guest_boot':'NOT RUN','M2':'NOT RUN','release_accepted':False}
 (out/'recipe.json').write_text(json.dumps(recipe,indent=2,sort_keys=True)+'\n');print(json.dumps(recipe,sort_keys=True))


if __name__=='__main__':main()
