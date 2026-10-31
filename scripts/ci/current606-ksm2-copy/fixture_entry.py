# SPDX-License-Identifier: MIT
"""Actual installed help/version and native private-file KSM controls only."""
import importlib.util,json,os,subprocess,sys
from pathlib import Path
CONTEXT=Path('/var/tmp/caa-ksm2-fixture')
def need(ok,why):
 if not ok:raise ValueError(why)
def main():
 need(len(sys.argv)==3 and os.getuid()==os.geteuid()>0 and os.uname().machine=='aarch64','ordinary native copied-root fixture')
 work=Path(sys.argv[1]);role=sys.argv[2];need(role in('ksm1','ksm2')and work.is_relative_to(CONTEXT/'outputs'),'fixed source fixture/output')
 programs=['/usr/bin/cachy-asahi-ksmctl']
 if role=='ksm2':programs.append('/usr/bin/cachy-asahi-ksm-experiment')
 else:need(not os.path.lexists('/usr/bin/cachy-asahi-ksm-experiment'),'original1 helper must be absent')
 commands=[]
 for program in programs:
  for arg in('--help','--version'):
   row=subprocess.run([program,arg],stdin=0,capture_output=True,timeout=15)
   need(row.returncode==0 and len(row.stdout)+len(row.stderr)<=128*1024,'actual argparse-only command failed')
   commands.append(dict(program=program,argument=arg,exit_code=0))
 path=CONTEXT/'fixture_checks.py';spec=importlib.util.spec_from_file_location('held_ksm_native_private_controls',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 suite=m.suite(CONTEXT/'source',Path(programs[0]),None if role=='ksm1'else Path(programs[1]))
 need(suite==dict(reporting=18,experiment=26 if role=='ksm2'else 0,domain='PRIVATE_REGULAR_FILES_ONLY',live_kernel_write='NOT_RUN'),'whole native KSM source controls')
 print(json.dumps(dict(status='PASS_ACTUAL_INSTALLED_KSM_PRIVATE',recipe_role=role,CLI=len(commands),commands=commands,installed_controls=44 if role=='ksm2'else 18,suite=suite,live_kernel_write='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED'),sort_keys=True))
if __name__=='__main__':main()
