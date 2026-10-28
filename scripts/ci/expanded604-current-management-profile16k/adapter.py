# SPDX-License-Identifier: MIT
"""Narrow the original full604/16K generator to one complete unchanged profile."""
import ast
import contract as C

BASE=C.module('_profile604_original_adapter',C.OLD+'/adapter.py',{'contract':C},lambda text:C.one(text,"C.HERE/'installed604.py'","source/C.OLD/'installed604.py'"))

def prepare(source,output,assets,ready,selected):
 C.profile(selected);BASE.prepare(source,output,assets,ready)
 for name in ('management_contract.py','management_root.py'):
  path=output/name;text=path.read_text()
  if name=='management_contract.py':
   text=C.one(text,"for stage in ('minimal','overlay'):",'for stage in '+repr((selected,))+':')
   text=C.one(text,'def verify_result(events,lock):','def verify_result(events,lock):\n    need({e["stage"] for e in events if "stage" in e}=={'+repr(selected)+'},"foreign or missing profile event")')
   text=C.one(text,'PASS_MANAGEMENT_NATIVE_METADATA_PIXELS_PENDING_REVIEW','PASS_SINGLE_PROFILE_MANAGEMENT_METADATA_PIXELS_PENDING_REVIEW')
  else:
   text=C.one(text,"stage==('minimal' if not profiles else 'overlay') and stage not in profiles and (not profiles or retired_profiles=={'minimal'})",'stage=='+repr(selected)+' and not profiles and not retired_profiles')
   text=C.one(text,"set(profiles)==retired_profiles=={'minimal','overlay'}",'set(profiles)==retired_profiles=={'+repr(selected)+'}')
  path.write_text('INDEPENDENT_PROFILE = '+repr(selected)+'\n'+text)
 def adapt(text):
  # Reuse the exact independent-profile operations after the original604 transform.
  return C.one(text,"'PASS_INSTALLED_WELCOME_MANAGEMENT_GUI_METADATA'",repr(C.PASS))
 profiles=C.module('_profile604_existing_profile_operations','scripts/ci/welcome-independent-profile-native/profile_adapter.py',adapt=adapt)
 profiles.GUI=C.PASS;receipt=profiles.runner(output,selected)
 path=output/'desktop574_runtime.py';text=path.read_text();text=C.one(text,"workflow_scope='installed604-welcome4-management-generic16k'","workflow_scope='independent-installed-current604-management-generic16k-profile'");path.write_text(text)
 proof=C.json_read(output/'runner-proof.json');proof.update(profile=selected,scope='ONE_PROFILE_NOT_FULL60416K_ACCEPTANCE',files={p.name:dict(bytes=len(C.read(p)),sha256=C.sha(C.read(p))) for p in output.iterdir() if p.is_file() and p.name not in ('runner-proof.json','candidate-lock.json')});C.save(output/'runner-proof.json',proof)
 for path in output.glob('*.py'):ast.parse(path.read_bytes())
 return output
