# SPDX-License-Identifier: MIT
"""Finite insertion; whole original676 normal lifecycle and all clocks conserved."""
import json,shutil,sys,types
from pathlib import Path
import guard as G
sys.path.insert(0,str(G.ROOT/'coexist'))
# A separate module name prevents the same-name integration entry from aliasing itself.
I=G.module('_whole_parent676_integration',G.ROOT/'coexist/integration.py')
P=I.P
COMPONENT_EDITS=(("retained={};apps_retained={};transactions={}","retained={};apps_retained={};transactions={};onboarding_retained={};onboarding_result=None"),(" def users():\n  ordinary_absent(account.pw_uid)"," def users():\n  ordinary_absent(account.pw_uid)\n  for parent,before in onboarding_retained.items():P.need(DEV.registry(parent)==before,'all fresh-user developer files/config identities preserved')"),(" users();after_fixture=capture(want)"," if phase=='install-setup6':\n   progress('real-fresh-user-PTY-editor-C-build-existing-config')\n   onboarding_result,parent,before=DEV.run(g,context,supervised,account,nonce,deadline,ordinary_absent);onboarding_retained[parent]=before\n  users();after_fixture=capture(want)"),("(g['OUT']/'setup6-full606.json').write_bytes(C.encoded(result))","P.need(onboarding_result is not None and len(onboarding_retained)==1,'exact one complete joint606 journey');result['developer_onboarding']=onboarding_result;(g['OUT']/'setup6-full606.json').write_bytes(C.encoded(result))"))
def component_program(raw):
 text=raw.decode();head="from native_api import C as N\n";added=head+"sys.path.insert(0,'/runner/developer')\nimport fixture as DEV\n";edits=((head,added),*COMPONENT_EDITS)
 for old,new in edits:P.need(text.count(old)==1,'one explicit onboarding seam '+old[:65]);text=text.replace(old,new,1)
 back=text
 for old,new in reversed(edits):P.need(back.count(new)==1,'one onboarding inverse');back=back.replace(new,old,1)
 P.need(back.encode()==raw,'whole original component/security/graphs/transactions outside onboarding insertion');compile(text,'<native606-onboarding-insertion>','exec');return text
_original_stage=I.stage_runner

def stage_runner(guard,parent,runner):
 proxy=types.SimpleNamespace(HERE=G.ROOT/'coexist',ROOT=G.ROOT,verify=G.verify,PARENT_SOURCE=G.PARENT_SOURCE);ledger=_original_stage(proxy,parent,runner);target=runner/'developer';P.need(not target.exists(),'fresh developer runner role');shutil.copytree(G.HERE,target);path=runner/'real606/component.py';old=path.read_bytes();path.write_text(component_program(old));ledger.update(profile='FULL606_FRESH_USER_SOFTWARE_ONBOARDING',onboarding_bound=420,component_before=G.pin(old),component_after=G.pin(path.read_bytes()),files=G.files(runner));return ledger
I.stage_runner=stage_runner

class Integration(I.Integration):
 def validate_component(self,value,resultdir):
  answer=super().validate_component(value,resultdir)
  spec=G.module('_owned_developer_receipt',G.HERE/'receipt.py');spec.validate(value['developer_onboarding'],self.nonce);R=value['developer_onboarding'];spec.replay(G.raw(resultdir/'onboarding-evidence.zip'),R,G.raw(G.HERE/'held/hello.c'));P.need(G.pin(G.raw(resultdir/'onboarding-evidence.zip'))==R['evidence']and json.loads(G.raw(resultdir/'onboarding-result.json'))==R,'complete opaque developer evidence/receipt join');return answer
 def prepare_export(self,out,report):
  super().prepare_export(out,report);report['developer_onboarding_scope']='FULL606_SOFTWARE_PTY_SHELL_SCRIPTED_EDITOR_C_BUILD_AND_EXISTING_CONFIG_ONLY';report['independent_new_user_install']='NOT_RUN'
 def export_names(self,out):
  names=super().export_names(out);home=out/'container'
  if home.exists():names.extend(p.relative_to(out).as_posix()for p in sorted(home.iterdir())if p.is_file()and p.name.startswith('onboarding-'))
  return names
owner_program=I.owner_program
native_program=I.native_program
