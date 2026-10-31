#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ordinary-user installed byte-joined code; private model and offline tests, no live writes."""
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path

def need(ok,message):
 if not ok:raise ValueError(message)

def command(argv):
 row=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=25,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
 need(len(row.stdout)+len(row.stderr)<=128*1024 and row.returncode==0,'installed fixture failed: '+argv[-1]+': '+row.stderr.decode(errors='replace')[-512:])
 return row

def main(work):
 need(os.getuid()==os.geteuid()>0 and work.is_absolute()and work.is_dir()and not work.is_symlink()and work.stat().st_uid==os.getuid()and not(work/'receipt.json').exists(),'fresh owned ordinary-user output required')
 policy=json.loads(Path('/runner/input-policy.json').read_bytes());helped=[];suites={}
 for name in('cachy-asahi-dns','cachy-asahi-sysctl'):
  source=Path('/inputs/sources')/name;program=Path('/usr/bin')/name;expected=policy['products'][name]['source_files'][name];raw=program.read_bytes();info=program.lstat()
  need(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755 and len(raw)==expected['bytes']and hashlib.sha256(raw).hexdigest()==expected['sha256'],'installed program source identity differs')
  command([str(program),'--help']);helped.append(name)
  test=['/usr/bin/python3','-I','-B','-Werror::ResourceWarning']
  test+=['/runner/test_dns_installed.py']if name=='cachy-asahi-dns'else[str(source/'test_sysctl.py'),'--command-source',str(program)]
  row=command(test);text=(row.stdout+row.stderr).decode(errors='replace')
  need(all(marker in text for marker in policy['products'][name]['check_markers'])and 'skipped='not in text and 'OK (skipped='not in text,'installed actual suite markers/no-skips absent')
  suites[name]=dict(stdout_bytes=len(row.stdout),stdout_sha256=hashlib.sha256(row.stdout).hexdigest(),stderr_bytes=len(row.stderr),stderr_sha256=hashlib.sha256(row.stderr).hexdigest(),exit_code=row.returncode)
 keys=json.loads(command(['/usr/bin/cachy-asahi-sysctl','keys']).stdout)
 need(keys.get('key')=='vm.swappiness'and keys.get('status')in('AVAILABLE','UNAVAILABLE')and keys.get('preset')is None,'fixed read-only key query differs')
 if keys['status']=='AVAILABLE':need(type(keys.get('current'))is int and 0<=keys['current']<=200 and keys.get('target_range')==[0,100],'actual readonly key frame differs')
 receipt=dict(status='PASS_INSTALLED_PRIVATE_FIXTURES',dns='PASS_INSTALLED_21_PRIVATE_AND_OFFLINE_CONTROLS',sysctl='PASS_INSTALLED_PRIVATE_MODEL_CONTROLS',help=helped,sysctl_keys='PASS_READONLY_FIXED_KEYS',host_NM_write='NOT_RUN',host_sysctl_write='NOT_RUN',suites=suites)
 (work/'receipt.json').write_text(json.dumps(receipt,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True))

if __name__=='__main__':main(Path(sys.argv[1]))
