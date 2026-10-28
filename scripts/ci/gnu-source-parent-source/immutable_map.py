# SPDX-License-Identifier: MIT
"""Exact explicit GNU private loop-map source derivative; no actors."""
import importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_gnu_parent_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
PROFILE_SHA='48c638ac77c7c84d111603d682a36a73418a66f78bdacf42871d0d821f4b54c3'

def profile():
 raw=F.read(HERE/'immutable-map-profile.json');F.need(F.pin(raw)['sha256']==PROFILE_SHA,'whole immutable-map profile');v=json.loads(raw)
 changed={n:dict(before=v['before'][n],after=v['after'][n])for n in v['before']if v['before'][n]!=v['after'][n]}
 F.need(len(v['before'])==len(v['after'])==745 and v['before'].keys()==v['after'].keys()and changed==v['changed']and len(changed)==9 and v['held']==736,'nine changed736 held745')
 return v

def emit(parent,output):
 parent,output=Path(parent).absolute(),Path(output).absolute();F.ordinary(parent);F.ordinary(output)
 F.need(not output.exists()and output.parent.is_dir(),'fresh output with existing ordinary parent')
 for root in(parent,HERE):F.need(not output.is_relative_to(root)and not root.is_relative_to(output),'disjoint source/output')
 v=profile();before=F.tree(parent,checkout=True);F.need(F.pins(before)==v['before'],'whole pinned immutable parent745')
 payload=F.tree(HERE/'immutable-map-payload');F.need(F.pins(payload)=={n:r['after']for n,r in v['changed'].items()},'whole nine readable immutable replacements')
 F.need(F.pins(F.tree(HERE/'runtime-basis-special'))==v['runtime_basis_special'],'whole three original runtime basis leaves')
 proposed=before|payload;F.need(F.pins(proposed)==v['after'],'whole proposed immutable745 before output')
 output.mkdir(mode=0o700)
 for n,raw in sorted(proposed.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 F.need(F.pins(F.tree(output))==v['after'],'whole emitted immutable745')
 return dict(status='SOURCE_ONLY',files=745,changed=9,held=736,parent_source=v['parent_source'],expected_source=v['expected_source'],native_fit='UNKNOWN',acceptance=False)
