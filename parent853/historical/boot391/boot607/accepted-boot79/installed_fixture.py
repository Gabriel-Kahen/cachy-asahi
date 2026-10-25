# SPDX-License-Identifier: MIT
"""Ordinary installed CLI against exclusively explicit private TEST sources."""
import argparse,json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import boot_fixture as F

def run(root,fixture,tool=('/usr/bin/cachy-asahi-boot-report',),home=None):
 def invoke(argv,expected=0):
  # Every command carrying a journal query supplies the explicit fixture path.
  env=dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME=str(home or root),SYSTEMD_HOST='unreachable.invalid',SYSTEMD_JOURNAL_PATH='/must-not-read-host',SYSTEMD_PAGER=str(root/'must-not-execute'),PYTHONPATH=str(root/'must-not-import'))
  value=subprocess.run([*tool,*argv],stdin=subprocess.DEVNULL,capture_output=True,env=env,timeout=35);F.need(value.returncode==expected,'installed CLI exit differs: '+repr(argv)+': '+value.stderr.decode(errors='replace')[:256]);F.need(len(value.stdout)+len(value.stderr)<=128*1024,'installed CLI output cap');return value.stdout.decode()
 return F.exercise(root,fixture,invoke,'SYNTHETIC_JOURNAL_INSTALLED_CLI')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('root','fixture','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--home',type=Path)
 a=p.parse_args();F.need(os.getuid()!=0,'ordinary installed fixture user required');a.output.write_text(json.dumps(run(a.root,a.fixture,home=a.home),sort_keys=True,indent=2)+'\n');a.output.chmod(0o600)
