#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Genuine finite Apps7/native159 +held16K kernel13 NULL-source assembly."""
import argparse,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
OWN=('adapter.py','contract.py','disk.py','guest.py','job.py','prepare.py','vm.py','test_lane.py','input-policy.json','source-pins.json','README.md','native_qualification.py')
def emit(source,output,native_source=None):
 source=Path(source).absolute();native=source if native_source is None else Path(native_source).absolute();output=Path(output).absolute()
 C.need(not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents))and not any(output.is_relative_to(p)for p in(source,native)),'fresh disjoint source output')
 value=C.decode(C.read(C.HERE/'source-pins.json'));pins=value['files'];C.need(len(pins)==172 and set(value['origins'])==set(pins)and sum(v==C.NATIVE_SOURCE for v in value['origins'].values())==159,'whole159 native role plus13 kernel dependencies')
 C.need(all(value[k]is None for k in('native_case_decisions','kernel_authority','actual_source','actual_ref'))and all(v is None for v in value['actual_runs'].values()),'source metadata is NULL future authority')
 sources={n:native if value['origins'][n]==C.NATIVE_SOURCE else source for n in pins}
 for root in(source,native):C.need(root.is_dir()and not any(p.is_symlink()for p in(root,*root.parents)),'ordinary explicit immutable source axes')
 for n,row in pins.items():C.need(C.row(sources[n]/C.relative(n))==row,'borrowed source differs: '+n)
 policy=C.decode(C.read(C.HERE/'input-policy.json'));C.need(policy==dict(schema_version=1,status='UNBOUND_NEW_NATIVE_REPAIR_CASES_AND_ACCEPTED_KERNEL',binding=None),'template authority remains UNBOUND')
 output.mkdir(mode=0o700)
 for n in pins:
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(sources[n]/n,p)
 for n in OWN:
  p=output/C.LANE/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(C.HERE/n,p)
 rows={p.relative_to(output).as_posix():C.row(p)for p in output.rglob('*')if p.is_file()};C.need(len(rows)==184,'finite Apps7 bridge184 source')
 C.save(output/C.LANE/'source-manifest.json',dict(schema_version=1,status='SOURCE_ONLY_UNBOUND_APPS7_FULL574_REPAIR16K',files=rows,native_case_authority=None,assembly_sources=dict(native_source=C.NATIVE_SOURCE,native_manifest_sha256=C.NATIVE_MANIFEST,kernel_media_source='591470fd0f870cad75b79aff9f87a6cb1ad1bcd8',origins=value['origins']),actual_source=None,actual_ref=None,actual_runs={case:None for case in C.CASES},VM='NOT_RUN',hardware='NOT_RUN'))
 return dict(status='SOURCE_ONLY_UNBOUND',source_rows=len(rows),native_source=C.NATIVE_SOURCE,cases=C.CASES,actual='NOT_RUN',manifest=C.row(output/C.LANE/'source-manifest.json'))
def template_emit(source,output,native_source=None):
 """Explicit fresh NULL emitter view; never edit a runtime policy in place."""
 import tempfile
 from unittest.mock import patch
 with tempfile.TemporaryDirectory()as td:
  template=Path(td)
  for name in OWN:shutil.copyfile(C.HERE/name,template/name)
  C.save(template/'input-policy.json',dict(schema_version=1,status='UNBOUND_NEW_NATIVE_REPAIR_CASES_AND_ACCEPTED_KERNEL',binding=None))
  with patch.object(C,'HERE',template):return emit(source,output,native_source)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('source','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--native-source',type=Path);p.add_argument('--template',action='store_true');a=p.parse_args();print(json.dumps((template_emit if a.template else emit)(a.source,a.output,a.native_source),sort_keys=True))
