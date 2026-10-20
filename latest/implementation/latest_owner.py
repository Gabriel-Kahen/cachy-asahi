# SPDX-License-Identifier: MIT
"""Bounded latest-five extension of the full original native606 owner."""
import hashlib,json,shutil,types
from pathlib import Path
import latest_plan as P
import latest_inputs as I
import latest_preservation_adapter as A
import latest_selection as S
OLD_SEQUENCE=" checkpoint('baseline604',base);install('install606');install('same-version606');remove('remove604');install('reinstall606');remove('final604')"
NEW_SEQUENCE=" checkpoint('baseline604',base);install('install606');install('same-version606')\n import latest_component\n previous_ld,previous_aux=latest_component.exercise(g,locals())\n remove('remove604');install('reinstall606');remove('final604')"
OWNER_EDITS=(
 ("    save(out/'input-summary.json',dict(summary=summary['summary'],retention=summary['retention']))","    save(out/'input-summary.json',dict(summary=summary['summary'],retention=summary['retention']))\n    Y.prepare_nonce(out)"),
 ("    policy,summary=verify(args)  # No output, secrets, Docker or producer module before all input gates.","    Y.authorize()\n    policy,summary=verify(args)  # No output, secrets, Docker or producer module before all input gates."),
 ("        X.validate(life.get('tools606'))","        X.validate(life.get('tools606'))\n        Y.validate_latest(life.get('latest607'),resultdir)"),
 ("status='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'","status='PASS_NATIVE607_LATEST_FIVE_TOOLS_REQUIRES_ORIGINAL_REPLAY'"),
 ("    home=producer_root/'private/expanded604-verifier'","    C.need(not (producer_root/'private/latest607-public-verifier').exists()and not (producer_root/'private/latest607-public-verifier').is_symlink(),'latest public verifier absence uncertain; preserve original producer')\n    home=producer_root/'private/expanded604-verifier'"),
)
def owner(raw):
 text=raw
 for before,after in OWNER_EDITS:text=A.one(text,before,after)
 inverse=text
 for before,after in reversed(OWNER_EDITS):inverse=A.one(inverse,after,before)
 P.need(inverse==raw and 'active.process.wait(timeout=1800)'in text and 'signal.setitimer(signal.ITIMER_REAL,6600)'in text,'whole original owner/caps/clocks inverse');compile(text,'<native-latest-tools-owner>','exec');return text

def bridge_source(raw):
 before="('all604_preserved','user_preserved','trust_preserved')";after="('other600_physical_preservation','user_preserved','trust_preserved')";text=A.one(raw,before,after)
 text=A.one(text,"base604_preserved=True if report.get('status')=='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'else'UNKNOWN'","other600_physical_preservation=True if report.get('status')=='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'else'UNKNOWN',selected_four_inode_restoration='NOT_CLAIMED'")
 inverse=text.replace(after,before,1).replace("other600_physical_preservation=True if report.get('status')=='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'else'UNKNOWN',selected_four_inode_restoration='NOT_CLAIMED'","base604_preserved=True if report.get('status')=='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'else'UNKNOWN'",1);P.need(inverse==raw,'entire original606 validator/export outside exact typed physicaldomain');return text

def emit_runner(source,base,runner):
 target=runner/'latest';shutil.copytree(source/'latest/implementation',target)
 # All fixture programs are trusted source leaves authenticated by the complete
 # new source manifest; packet source remains DATA and is never imported.
 boot=runner/'boot607';boot.mkdir()
 for name in('accepted_inputs.py','native_contract.py'):shutil.copyfile(base/'boot607'/name,boot/name)
 shutil.copyfile(base/'boot607/accepted-boot79/boot_fixture.py',boot/'boot_fixture.py')
 shutil.copyfile(base/'boot607/accepted-boot79/lifecycle.py',boot/'accepted-lifecycle.py');shutil.copytree(base/'copyworker',boot/'copyworker')
 fixtures={'apps-tests':base/'copyworker/held-apps','doctor-tests':source/'roles/doctor-worker/held-doctor','ksm-tests':source/'roles/ksm-worker/held-ksm','boot-tests':base/'boot607/accepted-boot79'}
 for name,path in fixtures.items():shutil.copytree(path,target/name)
 (target/'welcome-tests').mkdir();shutil.copyfile(source/'welcome6-test_cli.py',target/'welcome-tests/test_cli.py')
 shutil.copyfile(target/'latest_domain.py',runner/'latest_domain.py')
 before_tools=(runner/'tools606.py').read_bytes();text,edits=A.native606(before_tools,OLD_SEQUENCE,NEW_SEQUENCE);(runner/'tools606.py').write_text(text)
 before_outer=(runner/'lifecycle.py').read_bytes();text,outer_edits=A.outer(before_outer);(runner/'lifecycle.py').write_text(text)
 ledger=dict(status='SOURCE_ONLY_FINITE_LATEST_FIVE_NATIVE_COMPOSITION',original606=P.LOCK,original_tools=S.pin(before_tools),derived_tools=S.pin((runner/'tools606.py').read_bytes()),original_outer=S.pin(before_outer),derived_outer=S.pin((runner/'lifecycle.py').read_bytes()),native_inverse=edits,outer_inverse=outer_edits,bounds=P.BOUNDS,support_files={'latest_domain.py':S.pin((runner/'latest_domain.py').read_bytes()),**{'boot607/'+p.relative_to(boot).as_posix():S.pin(p.read_bytes())for p in sorted(boot.rglob('*'))if p.is_file()}},files={p.relative_to(target).as_posix():S.pin(p.read_bytes())for p in sorted(target.rglob('*'))if p.is_file()})
 for p in(target,boot,runner/'latest_domain.py',*target.rglob('*'),*boot.rglob('*')):P.need(not p.is_symlink(),'ordinary exact trusted source runner');p.chmod(0o755 if p.is_dir()else 0o644)
 return ledger

class Integration:
 def __init__(self,source,base,G,prior,packets,authorize):self.source,self.base,self.G,self.prior,self.packets,self._authorize=source,base,G,prior,packets,authorize;self.nonce=None
 def __getattr__(self,name):return getattr(self.prior,name)
 def authorize(self):return self._authorize()
 def prepare_nonce(self,out):
  import os
  self.nonce=os.urandom(16).hex();path=out/'latest607-selection.json';P.need(not path.exists()and not path.is_symlink(),'fresh original owner nonce');path.write_bytes(self.prior.P.encoded(dict(purpose='SOURCE_OWNED_NATIVE607_LATEST_FIVE_CONTEXT',nonce=self.nonce,authority='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION',actual_source=None,actual_ref=None,actual_run=None)));path.chmod(0o600)
 def prepare(self,root,producer,out,owned,ready,C):
  tools,runner=self.prior.prepare(root,producer,out,owned,ready,C);checks=C.load('_latest_whole_package_checks',root/'held-tools/scripts/checks/package_checks.py');plan=I.make(source=self.source,base=self.base,packets=self.packets,producer=producer,ready604=out/'ready604',output=tools/'latest',C=C,G=self.G,checks=checks,nonce=self.nonce)
  self.ledger=emit_runner(self.source,self.base,runner);self.ledger['input_plan']=plan;(tools/'latest607-runner-derivation.json').write_bytes(C.encoded(self.ledger))
  return tools,runner
 def validate(self,result):
  value=self.prior.validate(result);P.need(all(e['selected_four_domain']=='EXACT_TYPED_ALPM_NO_SELECTED_INODE_RESTORATION'for e in value['events'])and value['selected_four_logical_restoration']=='REQUIRES_LATEST_COMPONENT_COMPLETE_PROOF','complete606 receipt exact new physical/logicaldomain');return value
 def validate_latest(self,result,resultdir):
  import latest_validate
  before=self.prior.P.read(resultdir/'latest607-selected-before.json');after=self.prior.P.read(resultdir/'latest607-selected-after.json');fixture=self.G.module('_latest_original_full_boot_fixture_validator',self.base/'boot607/accepted-boot79/boot_fixture.py');return latest_validate.validate(result,before,after,self.nonce,boot_validator=fixture.validate)
 def prepare_export(self,out,report):
  view=dict(report)
  if report.get('status')=='PASS_NATIVE607_LATEST_FIVE_TOOLS_REQUIRES_ORIGINAL_REPLAY':
   self.validate_latest(report['lifecycle']['latest607'],out/'container');view['status']='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'
  self.prior.prepare_export(out,view);report['tools606_scope']=view['tools606_scope'];report['scope']='NATIVE_LATEST_FIVE_LOGICAL_FOUR_AND_PHYSICAL_OTHER602_ONLY';report['ordinary_copy607']='NOT_ISSUED';report['native_acceptance']='REQUIRES_FULL_ORIGINAL_REPLAY_AND_ROOT_DECISION'
 def export_names(self,out):
  names=self.prior.export_names(out)
  if(out/'latest607-selection.json').is_file():names.append('latest607-selection.json')
  home=out/'container'
  if home.exists():names.extend(str(p.relative_to(out))for p in sorted(home.iterdir())if p.is_file()and p.name.startswith('latest607'))
  return names
