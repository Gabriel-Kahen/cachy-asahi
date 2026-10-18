#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Closed source emitter; no original carrier fetch, Git or actor operation."""
import argparse,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def emit(source,output):
 C.need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output')
 rows=C.decode(C.read(C.HERE/'source-pins.json'))['files'];C.need(len(rows)<=512,'finite borrowed source')
 for n,r in rows.items():C.need(C.row(source/C.relative(n))==r,'frozen original source differs: '+n)
 output.mkdir(mode=0o700)
 for n,r in rows.items():
  target=output/n;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/n,target)
 lane=output/C.LANE;lane.mkdir(parents=True)
 for p in C.HERE.iterdir():
  if p.is_file() and p.name not in ('source-manifest.json',):shutil.copyfile(p,lane/p.name)
 files={str(p.relative_to(output)):C.row(p) for p in output.rglob('*') if p.is_file()};C.need(len(files)<=512,'complete emitted source bound');C.save(lane/'source-manifest.json',dict(schema_version=1,status='SOURCE_ONLY_UNBOUND',files=files,native='NOT_RUN',VM='NOT_RUN',hardware='NOT_RUN'))
 return dict(status='SOURCE_ONLY_UNBOUND',source_rows=len(files),before_sha256='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5',target_sha256='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3',cases=C.CASES)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.output.absolute()),sort_keys=True))
