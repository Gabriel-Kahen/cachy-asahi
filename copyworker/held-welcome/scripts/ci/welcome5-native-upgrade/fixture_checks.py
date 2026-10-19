#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Installed displayless CLI plus source-joined native report/schema fixtures."""
import hashlib,json,os,shlex,stat,subprocess,sys
from pathlib import Path
def need(ok,why):
 if not ok:raise ValueError(why)
def command(argv,seconds=25):
 p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=seconds,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'));need(p.returncode==0 and len(p.stdout)+len(p.stderr)<=128*1024,'Welcome fixture failed: '+p.stderr.decode(errors='replace')[-512:]);return p
def stream(p):return dict(stdout_bytes=len(p.stdout),stdout_sha256=hashlib.sha256(p.stdout).hexdigest(),stderr_bytes=len(p.stderr),stderr_sha256=hashlib.sha256(p.stderr).hexdigest(),exit_code=p.returncode)
def inputs(role):
 policy=json.loads(Path('/runner/input-policy.json').read_bytes());need(role in('cachy-asahi-welcome','cachy-asahi-welcome5'),'exact Welcome recipe role');p=policy['products'][role];root=Path('/inputs/sources')/role
 for n,r in p['source_files'].items():
  f=root/n;s=f.lstat();need(stat.S_ISREG(s.st_mode)and not f.is_symlink()and s.st_size==r['bytes']and hashlib.sha256(f.read_bytes()).hexdigest()==r['sha256'],'trusted fixture source differs')
 return p,root
def compile_fixture(root,work,name):
 flags=shlex.split(command(['/usr/bin/pkg-config','--cflags','--libs','gio-2.0']).stdout.decode());target=work/name
 sources=['test_management_report.c','management-report.c']if name=='report'else['test_management.c','management.c','management-report.c']
 argv=['/usr/bin/cc','-std=c11','-O2','-Wall','-Wextra','-Wformat=2','-Werror']+(['-DMANAGEMENT_TEST']if name=='root-guard'else[])+[str(root/n)for n in sources]+['-o',str(target),*flags]
 command(argv);return target
def root_guard(work,role):
 need(os.getuid()==os.geteuid()==0 and work.is_dir()and not work.is_symlink(),'owned root supervisor fixture');_,root=inputs(role);program=compile_fixture(root,work,'root-guard');p=command([str(program),'-p','/management/root-guard']);text=(p.stdout+p.stderr).decode();need('ok 1 /management/root-guard'in text and '# SKIP'not in text,'original root refusal assertion must execute without skip');return dict(status='PASS_ORIGINAL_ROOT_REFUSAL_ASSERTION',recipe_role=role,receipt=stream(p))
def main(work,role):
 need(os.getuid()==os.geteuid()>0 and work.is_absolute()and work.is_dir()and work.stat().st_uid==os.getuid()and not work.is_symlink()and not(work/'receipt.json').exists(),'fresh ordinary-user fixture');p,root=inputs(role);program=Path('/usr/bin/cachy-asahi-welcome');s=program.lstat();raw=program.read_bytes();products=json.loads(Path('/inputs/products.json').read_bytes());expected=products[role]['payload']['usr/bin/cachy-asahi-welcome']['sha256']
 need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o755 and hashlib.sha256(raw).hexdigest()==expected,'selected installed ELF payload differs');command([str(program),'--help'])
 cli=command(['/usr/bin/python3','-I','-B','-Werror::ResourceWarning',str(root/'test_cli.py'),str(program)]);need('Ran 5 tests'in(cli.stdout+cli.stderr).decode()and b'\nOK\n'in cli.stderr,'all installed CLI controls')
 report=compile_fixture(root,work,'report');r=command([str(report)]);text=r.stdout.decode();count=8 if role=='cachy-asahi-welcome'else 12;need('1..'+str(count)+'\n'in text and '# SKIP'not in text and 'not ok'not in text,'all source-pinned report/schema controls')
 result=dict(status='PASS_INSTALLED_WELCOME_DISPLAYLESS_AND_NATIVE_SCHEMA_FIXTURES',recipe_role=role,package_name='cachy-asahi-welcome',version=p['version'],program_sha256=expected,cli_controls=5,report_controls=count,CLI=stream(cli),schema=stream(r),GUI='NOT_RUN',live_DNS='NOT_RUN',hardware='NOT_RUN');(work/'receipt.json').write_text(json.dumps(result,sort_keys=True)+'\n');print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
 if sys.argv[1]=='--root-guard':print(json.dumps(root_guard(Path(sys.argv[2]),sys.argv[3]),sort_keys=True))
 else:main(Path(sys.argv[1]),sys.argv[2])
