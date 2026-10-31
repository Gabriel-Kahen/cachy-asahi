#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact joint898 with NULL future qualification; no actor or admission."""
import argparse,hashlib,importlib.util,json,subprocess,sys
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/current606-latest-tools'
CARRIER='1b844adcae6c5dedd7e148dd3f8dc5ce1b41f3ef'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def ordinary(path):need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary source operand')
def validate(source,pins):
 ordinary(source);need(source.is_dir(),'source directory')
 for name,row in pins['files'].items():
  p=source/name;ordinary(p);need(p.is_file()and p.stat().st_nlink==1 and pin(p.read_bytes())==row,'canonical owner source differs: '+name)
 lane=source/LANE;need({p.name for p in lane.iterdir()}=={Path(n).name for n in pins['files']if n.startswith(LANE+'/')},'exact canonical owner namespace')
 need((lane/'input-policy.json').read_bytes()==(lane/'null-policy.json').read_bytes(),'canonical original NULL policy held')
 p=json.loads((lane/'input-policy.json').read_bytes());need(p['status']=='UNBOUND_JOINT_SOURCE_TEMPLATE'and p['joint_decisions']==dict(apps606=None,welcome606=None)and all(p[k]is None for k in('actual_source','actual_ref','actual_run','nonce','measurement','output','retirement','capture_receipt')),'canonical future qualification remains NULL')
 # Complete source pins hold the genuine prior606 prerequisite DATA. It cannot
 # substitute for either future component qualification or this joint actual.
 for n in('selection.py','selection-template.py'):need((lane/n).read_text().count('EXPECTED_JOINT = None')==1,'future immutable qualification constant NULL')
def emit(source,basis,output):
 pins=json.loads((HERE/'source-pins.json').read_bytes());need(pins['schema_version']==1 and pins['carrier']==CARRIER and pins['purpose']=='SOURCE_CARRIER_ONLY_NOT_NATIVE_AUTHORITY','fixed immutable source carrier')
 validate(source,pins);ordinary(basis);need(basis.is_dir(),'whole source carrier directory');lane=source/LANE;sys.path.insert(0,str(lane))
 spec=importlib.util.spec_from_file_location('_canonical_joint606_prepare',lane/'prepare.py');prepare=importlib.util.module_from_spec(spec)
 with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network')),patch.object(subprocess,'run',side_effect=AssertionError('no source emission actors')):
  spec.loader.exec_module(prepare)
  rows=prepare.emit(apps=basis/'historical/apps',welcome=basis/'historical/welcome',worker=basis/'worker',bridge=basis/'bridge',output=output)
  need(len(rows)==898,'genuine complete898 source emission')
  for name,row in pins['files'].items():need(pin((output/name).read_bytes())==row,'emitted canonical default differs: '+name)
  spec=importlib.util.spec_from_file_location('_canonical_joint606_default_entry',lane/'owner.py');owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
  try:owner.main(['--require-selection'])
  except ValueError as e:need('future accepted Apps606/Welcome606 decisions NULL'in str(e),'original default owner qualification refusal')
  else:raise ValueError('actual default owner entry accepted without qualification')
 return dict(status='PASS_CANONICAL_NULL_JOINT898_SOURCE_ONLY',files=len(rows),source_carrier=CARRIER,source_carrier_scope='SOURCE_BYTES_ONLY',default_owner_entry='REFUSED_NULL_BEFORE_ACTORS',actual_source=None,actual_ref=None,actual_run=None,native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('source','basis','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.basis.absolute(),a.output.absolute()),sort_keys=True))
