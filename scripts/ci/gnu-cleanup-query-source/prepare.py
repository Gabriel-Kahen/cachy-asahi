#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce the exact GNU746 cleanup source; no actors or system mutation."""
import argparse,importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_held_gnu_source_io',HERE.parent/'gnu-source-parent-source/prepare.py')
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
PROFILE_SHA='ff05658dba4679f054037a01ddd9b16ea9218a33c9c4e7118d2081ef3bc30f63'

def profile():
 raw=F.read(HERE/'profile.json');F.need(F.pin(raw)['sha256']==PROFILE_SHA,'whole fixed GNU cleanup profile');v=json.loads(raw)
 changed={n:dict(before=v['before'].get(n),after=w)for n,w in v['after'].items()if v['before'].get(n)!=w}
 F.need(len(v['before'])==745 and len(v['after'])==746 and changed==v['changed'] and len(changed)==9 and set(v['before'])<=set(v['after']) and v['held']==737 and v['added']==['scripts/ci/gnu-immutable-source-native/cleanup-query-profile.json'],'whole737 held/eight replaced/one added source')
 F.need((v['cleanup_seconds'],v['observation_seconds'],v['shared_seconds'],v['owner_seconds'],v['qemu_seconds'])==(120,1200,4800,10500,10800)and v['acceptance']is False and v['native_fit']=='UNKNOWN','source-only profile and unchanged clocks')
 return v

def canonical(path):
 path=Path(path);F.need(path.is_absolute()and str(path)==os.path.normpath(str(path))and path==path.resolve(),'canonical normalized no-alias path');F.ordinary(path);return path

def emit(parent,output):
 parent,output=canonical(parent),canonical(output)
 F.need(not os.path.lexists(output)and output.parent.is_dir(),'fresh ordinary output')
 for root in(parent,HERE):F.need(not output.is_relative_to(root)and not root.is_relative_to(output),'disjoint source/factory/output')
 v=profile();before=F.tree(parent,checkout=True);F.need(F.pins(before)==v['before'],'entire pinned GNU745 parent')
 payload=F.tree(HERE/'payload');F.need(F.pins(payload)=={n:w['after']for n,w in v['changed'].items()},'whole nine readable cleanup replacements')
 proposed=before|payload;F.need(F.pins(proposed)==v['after'],'whole proposed746 before output')
 output.mkdir(mode=0o700)
 for n,raw in sorted(proposed.items()):
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True)
  with p.open('xb')as f:f.write(raw)
 F.need(F.pins(F.tree(output))==v['after'],'whole exact GNU746 emission')
 return dict(status='SOURCE_ONLY',files=746,held=737,replaced=8,added=1,parent_source=v['parent_source'],expected_source=v['expected_source'],native_fit='UNKNOWN',acceptance=False)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.parent,a.output),sort_keys=True))
