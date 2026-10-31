#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact finite native-case/VM helper assembly; no Git/network or actors."""
import argparse,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
OWN=('adapter.py','contract.py','disk.py','guest.py','job.py','prepare.py','vm.py','test_lane.py','input-policy.json','source-pins.json','README.md')
def emit(source,output,native_source=None):
 source=Path(source).absolute();output=Path(output).absolute();C.need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)) and not output.is_relative_to(source),'fresh disjoint source output');value=C.decode(C.read(C.HERE/'source-pins.json'));pins=value['files'];C.need(len(pins)==123 and set(value['origins'])==set(pins),'exact native115/VM8 borrowed closure')
 baseline=source if native_source is None else Path(native_source).absolute();C.need(baseline.is_dir() and not any(p.is_symlink() for p in (baseline,*baseline.parents)) and not output.is_relative_to(baseline),'ordinary disjoint explicit native baseline')
 sources={n:(baseline if value['origins'][n]==C.NATIVE_SOURCE else source) for n in pins};C.need(sum(p==baseline for p in sources.values())==115 if baseline!=source else True,'exact frozen native source partition')
 for n,r in pins.items():C.need(C.row(sources[n]/C.relative(n))==r,'borrowed source differs: '+n)
 C.need(C.decode(C.read(C.HERE/'input-policy.json'))['status']=='UNBOUND_NEW_NATIVE_REPAIR_CASES_AND_ACCEPTED_KERNEL','template authority remains UNBOUND');output.mkdir(mode=0o700)
 for n in pins:
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(sources[n]/n,p)
 for n in OWN:
  p=output/C.LANE/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(C.HERE/n,p)
 rows={p.relative_to(output).as_posix():C.row(p) for p in output.rglob('*') if p.is_file()};C.need(len(rows)==134,'closed finite repair16K source rows');C.save(output/C.LANE/'source-manifest.json',dict(schema_version=1,status='SOURCE_ONLY_UNBOUND_FULL574_REPAIR16K',files=rows,native_case_authority='UNBOUND',assembly_sources=dict(native_source=C.NATIVE_SOURCE,native_manifest_sha256=C.NATIVE_MANIFEST,origins=value['origins']),VM='NOT_RUN',hardware='NOT_RUN'))
 return dict(status='SOURCE_ONLY_UNBOUND',source_rows=len(rows),native_source=C.NATIVE_SOURCE,native_manifest_sha256=C.NATIVE_MANIFEST,cases=C.CASES,actual='NOT_RUN',manifest=C.row(output/C.LANE/'source-manifest.json'))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--native-source',type=Path);a=p.parse_args();print(json.dumps(emit(a.source,a.output,a.native_source),sort_keys=True))
