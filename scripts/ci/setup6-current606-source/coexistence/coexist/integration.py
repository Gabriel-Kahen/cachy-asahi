# SPDX-License-Identifier: MIT
"""Finite extension of the original normal native606 owner, never copiedroot."""
import copy,json,os,shutil
from pathlib import Path
import latest_plan as P
import coexist_inputs as INPUTS
OLD=" checkpoint('baseline604',base);install('install606');install('same-version606');remove('remove604');install('reinstall606');remove('final604')"
NEW=" checkpoint('baseline604',base);install('install606');install('same-version606')\n import sys\n sys.path.insert(0,'/runner/real606')\n import component\n previous_ld,previous_aux=component.exercise(g,locals())\n remove('remove604');install('reinstall606');remove('final604')"
NATIVE_EDITS=(('import hashlib,json,os,pwd,sys','import hashlib,json,os,pwd,sys\nsys.path.insert(0,\'/runner/real606\')\nimport latest_restoration as SETUP_RESTORE'),('base_digest=I.preserve_base(L,state)','base_digest=I.preserve_base(L,SETUP_RESTORE.unselected_base(state))'),("I.preserve_base(L,state)==base_digest,'all604 original payload/inode/rawDB preserved'","I.preserve_base(L,SETUP_RESTORE.unselected_base(state))==base_digest,'all602 nonselected original payload/inode/rawDB physically preserved'"),('all604_preserved=True',"other602_physical_preservation=True,selected_setup_domain='EXACT_TYPED_ALPM_REQUIRES_FULL_APPS6_SETUP5_RESTORATION'"),('base604_state_sha256=base_digest',"unselected603_state_sha256=base_digest,selected_setup_restoration='REQUIRES_FULL606_COMPONENT_PROOF'"),(OLD,NEW))
OWNER_EDITS=(("    policy,summary=verify(args)  # No output, secrets, Docker or producer module before all input gates.","    Y.authorize()\n    policy,summary=verify(args)  # No output, secrets, Docker or producer module before all input gates."),("    save(out/'input-summary.json',dict(summary=summary['summary'],retention=summary['retention']))","    save(out/'input-summary.json',dict(summary=summary['summary'],retention=summary['retention']))\n    Y.prepare_nonce(out)"),("        X.validate(life.get('tools606'))","        X.validate(life.get('tools606'))\n        Y.validate_component(life.get('setup6_full606'),resultdir)"),("status='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'","status='PASS_NATIVE_FULL606_APPS7_SETUP6_COEXISTENCE_REQUIRES_REPLAY'"),('active.process.wait(timeout=1800)','active.process.wait(timeout=9000)'),('signal.setitimer(signal.ITIMER_REAL,6600)','signal.setitimer(signal.ITIMER_REAL,13800)'))
def one(text,old,new,count=1):P.need(text.count(old)==count,'exact counted native Setup seam: '+old[:80]);return text.replace(old,new)
def native_program(raw):
 text=raw.decode()
 for old,new in NATIVE_EDITS:text=one(text,old,new,2 if old=='all604_preserved=True'else 1)
 back=text
 for old,new in reversed(NATIVE_EDITS):back=one(back,new,old,2 if old=='all604_preserved=True'else 1)
 P.need(back.encode()==raw,'whole native606 body inverse outside one-Setup typed domain');compile(text,'<full606-setup6>','exec');return text

def owner_program(raw):
 text=raw
 for old,new in OWNER_EDITS:text=one(text,old,new)
 back=text
 for old,new in reversed(OWNER_EDITS):back=one(back,new,old)
 P.need(back==raw,'whole original normal606 owner/security/cleanup inverse');compile(text,'<owned-native-full606-setup6>','exec');return text

def bridge_program(raw):
 edits=(("('all604_preserved','user_preserved','trust_preserved')","('other602_physical_preservation','user_preserved','trust_preserved')"),("base604_preserved=True if report.get('status')=='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'else'UNKNOWN'","other602_physical_preservation=True if report.get('status')=='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'else'UNKNOWN',selected_setup_restoration='REQUIRES_FULL606_COMPONENT_PROOF'"));text=raw
 for old,new in edits:text=one(text,old,new)
 back=text
 for old,new in reversed(edits):back=one(back,new,old)
 P.need(back==raw,'whole original normal606 validator/export typed-domain inverse');return text

def stage_runner(guard,parent,runner):
 guard.verify();target=runner/'real606';P.need(not target.exists()and not(runner/'setup240').exists()and not(runner/'copyworker').exists(),'fresh exact source-only runner roles');shutil.copytree(guard.HERE,target);shutil.copytree(guard.ROOT/'setup240',runner/'setup240');shutil.copytree(guard.ROOT/'copyworker',runner/'copyworker');before=(runner/'tools606.py').read_bytes();(runner/'tools606.py').write_text(native_program(before))
 return dict(status='SOURCE_ONLY_FULL606_SETUP6_REAL_MODULES_DERIVATION',parent=guard.PARENT_SOURCE,native_before=parent.pin(before),native_after=parent.pin((runner/'tools606.py').read_bytes()),native_edits=NATIVE_EDITS,bounds=P.BOUNDS,expected_graphs=29,expected_real_suites=4,files={p.relative_to(runner).as_posix():parent.pin(p.read_bytes())for p in sorted(runner.rglob('*'))if p.is_file()},actual=None)

class Integration:
 def __init__(self,guard,anchor,context,packet,setup):
  self.G,self.anchor,self.P,self.A,self.X,self.C,self.packet,self.setup=guard,anchor,*context,packet,setup;self.nonce=None
 def __getattr__(self,name):return getattr(self.X,name)
 def authorize(self):
  self.G.verify();O=self.anchor.O;policy=O.authorize(O.read(O.HERE/'input-policy.json'));self.anchor.builds.public_checkout(self.packet,policy);self.anchor.builds.doctor_checkout(self.setup,policy);return policy
 def prepare_nonce(self,out):
  self.nonce=os.urandom(16).hex();(out/'setup6-selection.json').write_bytes(self.C.encoded(dict(purpose='FULL606_APPS7_SETUP6_COEXISTENCE_NATIVE_CORRECTNESS',nonce=self.nonce,authority='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION',actual_source=None,actual_ref=None,actual_run=None)))
  plan=out/'plan';P.need(not plan.exists(),'fresh source-owned normal606 nonce projection');plan.mkdir(mode=0o700);(plan/'bridge-selection.json').write_bytes((out/'setup6-selection.json').read_bytes())
 def prepare(self,root,producer,out,owned,ready,C):
  tools,runner=self.X.prepare(root,producer,out,owned,ready,C);context=self.anchor.builds.doctor(root=self.G.ROOT,packet=self.packet,doctor_packet=self.setup,ready604=out/'ready604',output=tools/'setup6',producer=producer,original_api=C)
  plan=C.read(context/'lifecycle-plan.json');apps=INPUTS.make(self.G,self.anchor,self.packet,out/'ready604',tools/'apps7',producer,C);products=dict(setup=INPUTS.products(plan,'/tools606/setup6/archives/',dict(original='original1',new='new2')),apps=INPUTS.products(apps,'/tools606/apps7/archives/',dict(original='original6',new='new7')))
  native=dict(purpose='FULL606_APPS7_SETUP6_COEXISTENCE_NATIVE_CORRECTNESS',nonce=self.nonce,nonce_authority='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION',products=products,original_plan=self.P.pin((context/'lifecycle-plan.json').read_bytes()),original606_manifest=plan['original606_manifest'],actual_source=None,actual_ref=None,actual_run=None);(context/'native-plan.json').write_bytes(C.encoded(native))
  ledger=stage_runner(self.G,self.P,runner);ledger['native_plan']=native
  (tools/'setup6-runner-derivation.json').write_bytes(C.encoded(ledger))
  for p in(runner,*runner.rglob('*'),tools,*tools.rglob('*')):P.need(not p.is_symlink(),'ordinary held source/input runner');p.chmod(0o755 if p.is_dir()else 0o644)
  return tools,runner
 def typed_bridge(self):
  import types
  module=types.ModuleType('_full_original_native606_typed_setup_bridge');module.__file__=str(self.P.HERE/'bridge606.py');text=bridge_program((self.P.HERE/'bridge606.py').read_text())
  with self.anchor.builds.aliases({'contract':self.P,'adapter':self.A,'build_pairs':self.X.build_pairs}):exec(compile(text,module.__file__,'exec'),vars(module))
  return module
 def validate(self,value):return self.typed_bridge().validate(value)
 def validate_component(self,value,resultdir):
  from validate import validate
  SC=self.C.load('_host_whole_setup240_gate',self.G.ROOT/'setup240/scripts/ci/setup6-real-modules/contract.py');validate(value,self.nonce,SC.validate_real,dict(line.split()for line in(self.G.ROOT/'copyworker/scripts/ci/current606-doctor2-copy/expected606.lock').read_text().splitlines()))
  self.C.need(self.C.read(resultdir/'setup6-full606.json')==value,'complete component/outer result join')
  import latest_restoration as REST
  before=self.C.read(resultdir/'setup6-selected-before.json');after=self.C.read(resultdir/'setup6-selected-after.json');clocks={e['acted_role']:e['transaction']['transaction_clock']for e in value['events']if e['phase'].startswith('restore-')};self.C.need(REST.records(before,after,clocks)==value['selected_logical_restoration'],'full selected rawbytes restoration replay');return value
 def prepare_export(self,out,report):
  view=dict(report)
  if report.get('status')=='PASS_NATIVE_FULL606_APPS7_SETUP6_COEXISTENCE_REQUIRES_REPLAY':view['status']='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION';self.validate_component(report['lifecycle']['setup6_full606'],out/'container')
  self.typed_bridge().prepare_export(out,view);report['tools606_scope']=view['tools606_scope'];report['scope']='NORMAL_NATIVE_FULL606_APPS7_SETUP6_COEXISTENCE_ONLY';report['native_acceptance']='REQUIRES_FULL_REPLAY_AND_ROOT_DECISION';report['Apps7_coexistence']='REQUIRES_FULL_NATIVE_COMPONENT_REPLAY'
 def export_names(self,out):
  names=self.X.export_names(out)
  if(out/'setup6-selection.json').is_file():
   P.need((out/'plan/bridge-selection.json').read_bytes()==(out/'setup6-selection.json').read_bytes(),'whole genuine normal606 nonce transport projection');names.extend(('setup6-selection.json','plan/bridge-selection.json'))
  apps=out/'tools606/apps7'
  if apps.exists():names.extend(p.relative_to(out).as_posix()for p in sorted(apps.rglob('*'))if p.is_file())
  home=out/'container'
  if home.exists():names.extend(p.relative_to(out).as_posix()for p in sorted(home.iterdir())if p.is_file()and p.name.startswith(('setup6','coexist')))
  return names
