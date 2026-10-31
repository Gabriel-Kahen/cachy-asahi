#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Both installed programs, private models/offline NM only, ordinary users."""
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path

def need(ok,why):
 if not ok:raise ValueError(why)
def main(work,phase):
 need(os.getuid()==os.geteuid()>0 and work.is_absolute()and work.is_dir()and work.stat().st_uid==os.getuid()and not work.is_symlink(),'ordinary owned fixture')
 policy=json.loads(Path('/tools606/tools-policy.json').read_bytes());observed={}
 for role in('cachy-asahi-dns2','cachy-asahi-sysctl2'):
  product=policy['products'][role];program=Path('/usr/bin')/product['package_name'];s=program.lstat();raw=program.read_bytes();need(stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o755 and s.st_uid==s.st_gid==0 and dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==product['source_files'][product['package_name']],'exact installed public program')
  def command(argv):
   r=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,capture_output=True,timeout=25);need(r.returncode==0 and len(r.stdout)+len(r.stderr)<=128*1024,'installed private fixture failed: '+r.stderr.decode(errors='replace')[-512:]);return r
  command([program,'--help'])
  argv=['/usr/bin/python3','-I','-B','-Werror::ResourceWarning']
  argv+=['/runner/test_dns2_installed.py']if role.endswith('dns2')else['/tools606/sources/'+role+'/test_sysctl.py','--command-source',program]
  r=command(argv);text=(r.stdout+r.stderr).decode(errors='replace');need(all(m in text for m in product['check_markers'])and 'skipped='not in text and 'OK (skipped='not in text,'all installed27/28 controls required')
  observed[role]=dict(controls=product['controls'],version=product['version'],program_sha256=hashlib.sha256(raw).hexdigest(),suite=dict(exit=0,stdout_bytes=len(r.stdout),stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),stderr_bytes=len(r.stderr),stderr_sha256=hashlib.sha256(r.stderr).hexdigest()))
 receipt=dict(status='PASS_BOTH606_INSTALLED_PRIVATE_FIXTURES',phase=phase,products=observed,live_NM='NOT_RUN',kernel_mutation='NOT_RUN',hardware='NOT_RUN');path=work/(phase+'-receipt.json');need(not path.exists(),'fresh private receipt');path.write_text(json.dumps(receipt,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True))
if __name__=='__main__':main(Path(sys.argv[1]),sys.argv[2])
