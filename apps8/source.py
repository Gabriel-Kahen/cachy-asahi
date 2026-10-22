# SPDX-License-Identifier: MIT
"""Closed new source and exact entire accepted348 inverse; no actors or native credit."""
import hashlib,importlib.util,json,shutil,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
LANE='scripts/ci/current606-apps7-closed-owner'
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def verify():
 sys.path.insert(0,str(ROOT/LANE));O=module('_apps8_complete_owner_contract',ROOT/LANE/'contract.py');result=O.verify()
 owner_hash=pin((ROOT/LANE/'owner.py').read_bytes())['sha256'];manifest_hash=pin((ROOT/LANE/'source-manifest.json').read_bytes())['sha256'];profile=json.loads((HERE/'carrier-profile.json').read_bytes());binding=profile['source']or'APPS8_CARRIER_NULL_UNPUBLISHED';workflows=[]
 for name in ('native-arm-build.yml','native-arm-current606-apps7-owned-copy.yml'):
  text=(ROOT/'.github/workflows'/name).read_text();assert text.count(owner_hash)==text.count(manifest_hash)==text.count(binding)==1,'exact workflow source stamps/carrier'
  workflows.append(text.replace(owner_hash,'OWNER_SOURCE_STAMP').replace(manifest_hash,'CLOSED_MANIFEST_STAMP').replace(binding,'EXACT_CARRIER_BINDING'))
 assert workflows[0]==workflows[1]and pin(workflows[0].encode())==json.loads((HERE/'workflow-profile.json').read_bytes()),'entire normalized workflow byte binding'
 before=json.loads((HERE/'parent348.json').read_bytes());assert len(before['files'])==348
 for name,want in before['files'].items():
  p=HERE/'inverse'/name if name in before['changed'] else ROOT/name
  assert pin(O.checked(p,want).read_bytes())==want,'whole348 inverse differs: '+name
 for p in ROOT.rglob('*.py'):
  if '.git'not in p.relative_to(ROOT).parts:compile(p.read_bytes(),str(p),'exec')
 return dict(status='PASS_SOURCE_ONLY_APPS8_CURRENT606_NO_ACCEPTANCE',files=result['files'],parent_source=before['source'],parent_run=before['run'],parent_inverse_files=348,actual=None,source_native=None,run_native=None,hardware='NOT_RUN',release='NOT_ADMITTED')

def emit(output,*,parent=False):
 fact=verify();output=Path(output).absolute()
 assert not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary disjoint output'
 assert output!=ROOT and ROOT not in output.parents and output not in ROOT.parents,'source/output alias'
 before=json.loads((HERE/'parent348.json').read_bytes());mf=json.loads((ROOT/LANE/'source-manifest.json').read_bytes())
 names=before['files'] if parent else set(mf['files'])|{LANE+'/source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-apps7-owned-copy.yml'}
 output.mkdir(mode=0o700)
 for name in names:
  origin=HERE/'inverse'/name if parent and name in before['changed'] else ROOT/name
  p=output/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(origin,p)
 return dict(fact,emitted=len(names),parent_inverse=parent)
