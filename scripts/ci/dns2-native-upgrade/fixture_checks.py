#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ordinary-user installed DNS version fixture; all NM writes are private models/offline."""
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path

def need(ok,message):
 if not ok:raise ValueError(message)

def command(argv):
 row=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=25,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
 need(len(row.stdout)+len(row.stderr)<=128*1024 and row.returncode==0,'installed DNS fixture failed: '+row.stderr.decode(errors='replace')[-512:]);return row

def main(work,role):
 need(os.getuid()==os.geteuid()>0 and work.is_absolute()and work.is_dir()and not work.is_symlink()and work.stat().st_uid==os.getuid()and not(work/'receipt.json').exists(),'fresh owned ordinary-user output required')
 policy=json.loads(Path('/runner/input-policy.json').read_bytes());need(role in('cachy-asahi-dns','cachy-asahi-dns2'),'exact baseline/candidate role required');product=policy['products'][role]
 program=Path('/usr/bin/cachy-asahi-dns');expected=product['source_files']['cachy-asahi-dns'];raw=program.read_bytes();info=program.lstat()
 need(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755 and len(raw)==expected['bytes']and hashlib.sha256(raw).hexdigest()==expected['sha256'],'installed exact selected-version program identity differs')
 command([str(program),'--help']);label='v1'if role=='cachy-asahi-dns'else'v2';row=command(['/usr/bin/python3','-I','-B','-Werror::ResourceWarning','/runner/test_dns_'+label+'_installed.py']);text=(row.stdout+row.stderr).decode(errors='replace')
 need(all(marker in text for marker in product['check_markers'])and 'skipped='not in text and 'OK (skipped='not in text,'complete installed21/27 suite/no-skips required')
 stream=dict(stdout_bytes=len(row.stdout),stdout_sha256=hashlib.sha256(row.stdout).hexdigest(),stderr_bytes=len(row.stderr),stderr_sha256=hashlib.sha256(row.stderr).hexdigest(),exit_code=row.returncode)
 receipt=dict(status='PASS_INSTALLED_DNS_PRIVATE_OFFLINE_FIXTURES',recipe_role=role,package_name='cachy-asahi-dns',version=product['version'],controls=21 if label=='v1'else 27,program_sha256=expected['sha256'],help='PASS',suite=stream,host_NM_write='NOT_RUN',live_DNS='NOT_RUN')
 (work/'receipt.json').write_text(json.dumps(receipt,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True))

if __name__=='__main__':main(Path(sys.argv[1]),sys.argv[2])
