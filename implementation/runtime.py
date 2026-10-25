# SPDX-License-Identifier: MIT
"""Whole copied-root owner, with explicit latest607 preparation/materializer seams."""
import json,os,shutil,sys,types
from pathlib import Path
import common as C,baseline,cache
OLD='scripts/ci/expanded604-apps6-public-pair-updater'
OWNER_EDITS=[("row.get('final_package_count')==604","row.get('final_package_count')==607"),('source=a.implementation_revision,before_sha256=', 'source=Y.current_source,held_library_source=a.implementation_revision,before_sha256='),('GENERIC4K_PUBLIC_PAIRS_APPS5_TO6_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY','GENERIC4K_LATEST607_APPS6_TO16_COPIED_ROOT_SOFTWARE_ONLY'),('cachy-asahi-apps-0.1.0-6-any.pkg.tar.xz','cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz'),("('expanded604-verifier','expanded604-before-verifier')","('expanded604-verifier','expanded604-before-verifier','latest607-verifier')")]
def derive_owner(raw):
 text=raw.decode()
 for before,after in OWNER_EDITS:C.need(text.count(before)==1,'one latest607 owner integration seam '+before);text=text.replace(before,after,1)
 restored=text
 for before,after in reversed(OWNER_EDITS):C.need(restored.count(after)==1,'one whole owner inverse');restored=restored.replace(after,before,1)
 C.need(restored.encode()==raw,'entire original owner inverse; all lifetime/cleanup/retirement held');compile(text,'<latest607-whole-owner>','exec');return text

class Integration:
 def __init__(self,held,fresh,public,record,packets,current_source):
  self.held,self.fresh,self.public,self.record=map(C.safe,(held,fresh,public,record));self.packets={k:C.safe(v)for k,v in packets.items()};self.current_source=current_source;self.args=None
 def source_modules(self):
  # A complete fixed fresh source is a separate input, never the updater's own
  # acceptance. Its original public991 and issued22 decision guards run whole.
  original=baseline.source(self.fresh);L=C.load('_latest607_complete_input_revision',self.fresh/'implementation/loaders.py',{'common':original});L.revision(self.fresh,C.profile()['fresh_source']);L.revision(self.record,original.profile()['accepted_record_source']);accepted=C.load('_latest607_exact_six_record',self.fresh/'implementation/accepted.py',{'common':original});return original,accepted
 def inputs(self):
  original,accepted=self.source_modules();decision,_=accepted.public(self.record,self.public)
  L=C.load('_latest607_apps16_original_inputs',self.fresh/'parent853/latest/implementation/apps16_inputs.py');facts=L.inspect(self.packets,C.load('_latest607_exact_input_checks',self.held/'scripts/checks/package_checks.py'))
  C.need(facts['apps16']['report']['sha256']==C.profile()['selected']['archive']['sha256'],'same exact Apps16 input archive');return decision
 def stage(self,contract,_old_carrier,target,_old_binding,_old_authority,_old_implementation):
  self.inputs();return __import__('pair').emit(self.packets['apps16'],target)
 def candidate(self,_original,target,case):
  C.need(case in C.CASES,'closed original three transaction cases');source=C.ROOT/'cases'/case;before=C.rows(source);C.need(before==C.profile()['cases'][case],'whole selected607 capsule');target=C.safe(target);C.need(not os.path.lexists(target),'fresh candidate');shutil.copytree(source,target)
  folder=target/'scripts/ci/latest607-updater';folder.mkdir()
  for n in('selected_package.py','selected-input.json'):(folder/n).write_bytes(C.read(C.HERE/n))
  path=target/'upgrade-config.json';config=json.loads(C.read(path));config['code_pins'].update({p.relative_to(target).as_posix():C.pin(C.read(p))['sha256']for p in folder.iterdir()});path.write_bytes(C.enc(config));receipt=json.loads(C.read(target/'adapter.json'));receipt['latest607_selection']=dict(status='SOURCE_ONLY_NEW_APPS6_TO16_SELECTION_NOT_ACCEPTED',case=case,whole_original_adapter=C.pin(C.read(source/'adapter.json')),historical_config_sha256=receipt['config_sha256'],capsule_config=C.profile()['cases'][case]['upgrade-config.json'],current_emitted_config=C.pin(C.read(path)),before=C.profile()['before'],after=C.profile()['after'],archive=C.profile()['selected']['archive'],all_other606='HELD',actual=None);receipt['config_sha256']=C.pin(C.read(path))['sha256'];(target/'adapter.json').write_bytes(C.enc(receipt));C.need(before==C.rows(source),'late source capsule drift');return path,target/'scripts/ci/full-root-upgrade-caller'
 def materializer(self,contract,original,installer_policy):
  api=self
  def prepare(ready,producer,*args):
   C.need(len(args)==10,'entire original materializer call operands');eight,seven,audio,legacy,target,_old_policy,management,setup,welcome,_old_baseline=args;raw=producer/'private/latest607-base604';a=api.args
   # Reproduce genuine Apps6/full604 with the original accepted installer first.
   original.prepare(ready,producer,eight,seven,audio,legacy,raw,installer_policy,management,setup,welcome,a.installer_source,a.apps6_source,a.apps6_authority_source)
   helper=contract.scoped('_latest607_original_sign_copy',api.held/'scripts/ci/expanded600-installer-vm/materializer.py',{'contract':contract.OLD});verifier=C.load('_latest607_original_public_verifier',legacy/'scripts/ci/full-composition-installer-vm/producer.py');checks=C.load('_latest607_full_package_checks',legacy/'scripts/checks/package_checks.py');payload=C.load('_latest607_full_project_payload',legacy/'scripts/ci/full-development-composition/run.py')
   return baseline.prepare(api.fresh,raw,api.public,producer,target,helper=helper,verifier_api=verifier,checks=checks,payload_api=payload)
  return types.SimpleNamespace(prepare=prepare)
 def owner(self):
  contract=C.load('_latest607_whole_old_contract',self.held/OLD/'contract.py');oldgate=contract.scoped('_latest607_whole_old_gate',self.held/OLD/'gate.py',{'contract':contract});new=types.ModuleType('contract');new.__dict__.update(vars(contract));new.BEFORE=C.profile()['before']['sha256'];new.AFTER=C.profile()['after']['sha256'];new.locks=C.locks;oldload=contract.load;api=self
  def load(name,path):
   if name=='apps6_pair_stage'and Path(path)==contract.HERE/'baseline.py':return types.SimpleNamespace(stage=api.stage)
   return oldload(name,path)
  new.load=load
  def inputs(args,policy):
   api.args=args;old_api,old_materializer,old_policy,decisions,summary=oldgate.inputs(args,policy);installer,materializer,installer_policy=oldgate.installer(args.installer_source,policy);api.inputs();replacement=types.SimpleNamespace(**vars(installer));replacement.COMPOSITION=cache.api(installer.COMPOSITION);return replacement,api.materializer(contract,materializer,installer_policy),installer_policy,decisions,summary
  gate=types.SimpleNamespace(own_source=oldgate.own_source,inputs=inputs);adapter=types.SimpleNamespace(prepare=self.candidate);before_cache=cache.module(contract,C.read(self.held/OLD/'before_cache.py'));owner=types.ModuleType('_latest607_complete_original_owner');owner.__file__=str(self.held/OLD/'run.py');owner.Y=self;missing=object();aliases=dict(contract=new,adapter=adapter,gate=gate,before_cache=before_cache);saved={k:sys.modules.get(k,missing)for k in aliases}
  try:sys.modules.update(aliases);exec(compile(derive_owner(C.read(self.held/OLD/'run.py')),owner.__file__,'exec'),vars(owner))
  finally:
   for k,v in saved.items():
    if v is missing:sys.modules.pop(k,None)
    else:sys.modules[k]=v
  return owner

def extras(argv):
 import argparse
 p=argparse.ArgumentParser(add_help=False)
 for n in('latest-installer','six-public','six-record','apps16','apps16qualification','apps16current606qualification','latest-decisions'):p.add_argument('--'+n,type=Path,required=True)
 a,rest=p.parse_known_args(argv);return a,rest

def execute(held,argv):
 a,rest=extras(argv);authority=__import__('authority');authority.gates(a.latest_decisions);api=Integration(held,a.latest_installer,a.six_public,a.six_record,{k:getattr(a,k)for k in('apps16','apps16qualification','apps16current606qualification')},os.environ['GITHUB_SHA']);return api.owner().main(rest)
