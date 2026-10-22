# SPDX-License-Identifier: MIT
"""Reproduce only this closed source; no image, package, key, or actor operations."""
import argparse,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,adapter,entry

def emit(source,output):
 source=Path(source).absolute();output=Path(output).absolute();entry.source(source);C.need(not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents))and not(output.is_relative_to(source)or source.is_relative_to(output)),'fresh disjoint ordinary source output before write')
 rows=adapter.source_rows(source);output.mkdir(mode=0o700)
 for n,pin in rows.items():
  raw=C.read(source/n,32*1024**2);C.need(C.pin(raw)==pin,'whole source drift before emitted leaf');p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 C.need(adapter.source_rows(output)==rows,'exact whole emitted source bytes');return entry.source(output)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,default=C.HERE);p.add_argument('--output',type=Path);p.add_argument('--source-only',action='store_true');a=p.parse_args()
 C.need(a.source_only or a.output is not None,'source-only or explicit fresh output required');print(C.encoded(entry.source(a.source)if a.output is None else emit(a.source,a.output)).decode(),end='')
