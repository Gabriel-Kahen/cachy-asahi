#!/usr/bin/env python3
"""Emit the exact mandatory-clock/optional-I/O source; no emitted code runs."""
import argparse,importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location("_held_updater_source_io",HERE/"prepare.py")
F=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(F)
PROFILE_SHA='8b351149c9100619c399d4370b61e80ff9501cccaf88bcd924e6728e319eaee2'

def profile():
 raw=F.read(HERE/'optional-io-profile.json')
 F.need(F.pin(raw)['sha256']==PROFILE_SHA,'whole optional I/O profile')
 value=json.loads(raw)
 F.need(len(value['before'])==len(value['after'])==489 and value['before'].keys()==value['after'].keys(),'closed source489')
 changed={n:dict(before=value['before'][n],after=value['after'][n])for n in value['before']if value['before'][n]!=value['after'][n]}
 F.need(changed==value['changed'] and len(changed)==5 and value['held']==484,'five changed484 held')
 return value

def emit(parent,output):
 parent,output=Path(parent).absolute(),Path(output).absolute()
 F.need(not parent.is_symlink()and not output.is_symlink(),'ordinary source/output')
 parent,output=parent.resolve(),output.resolve()
 F.need(not output.exists(),'fresh output')
 for source in(parent,HERE):F.need(not output.is_relative_to(source)and not source.is_relative_to(output),'disjoint output')
 value=profile();original=F.tree(parent,checkout=True)
 F.need(F.pins(original)==value['before'],'whole pinned optional I/O parent489')
 replacements=F.tree(HERE/'optional-io-payload')
 F.need(F.pins(replacements)=={n:v['after']for n,v in value['changed'].items()},'whole five optional I/O replacements')
 rows=original|replacements;F.need(F.pins(rows)==value['after'],'whole optional I/O output489 before creation')
 output.mkdir(mode=0o700)
 for n,raw in sorted(rows.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 F.need(F.pins(F.tree(output))==value['after'],'complete emitted optional I/O output489')
 return dict(status='SOURCE_ONLY',files=489,changed=5,held=484,source=value['expected_source'],native_fit='UNQUALIFIED',acceptance=False)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.parent,a.output),sort_keys=True))
