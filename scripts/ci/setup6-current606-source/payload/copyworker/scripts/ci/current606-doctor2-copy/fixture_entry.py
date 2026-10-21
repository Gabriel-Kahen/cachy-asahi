# SPDX-License-Identifier: MIT
"""Actual installed Setup helper and six pure recovery tests; no shell claims."""
import hashlib,importlib.machinery,importlib.util,json,os,subprocess,sys,types
from pathlib import Path
CONTEXT=Path('/var/tmp/caa-setup6-fixture');PROGRAM=Path('/usr/bin/cachy-asahi-setup')

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def call(argv,seconds=10):
 result=subprocess.run(argv,stdin=0,capture_output=True,timeout=seconds)
 need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=128*1024,'bounded real installed Setup CLI')
 return result.stdout

def recovery_controls(work):
 """Whole qualified six-case body; only the private scratch parent is routed."""
 path=CONTEXT/'setup/recovery_preview.py';raw=path.read_text();anchor="scratch.parent==Path('/tmp')";replacement='scratch.parent==_PRIVATE_PARENT'
 need(raw.count(anchor)==1,'one exact qualified private scratch route')
 changed=raw.replace(anchor,replacement,1);need(changed.replace(replacement,anchor,1)==raw,'whole qualified pure recovery body inverse')
 module=types.ModuleType('_installed_setup6_complete_recovery');module.__file__=str(path);module._PRIVATE_PARENT=work
 exec(compile(changed,str(path),'exec'),module.__dict__)
 result=module.run_controls(PROGRAM,CONTEXT/'setup',work/'six-recovery-cases')
 need(result['tests']==6 and len(result['cases'])==6 and set(result['cases'].values())=={'PASS'}and result['private_fixtures_retired']is True,'all six real installed-helper private recovery assertions')
 return result

def main():
 need(len(sys.argv)==3 and os.getuid()==os.geteuid()>0 and os.uname().machine=='aarch64','ordinary native copied-root Setup fixture')
 work=Path(sys.argv[1]);role=sys.argv[2];need(role in('setup5','setup6')and work.is_relative_to(CONTEXT/'outputs'),'fixed private Setup output role')
 need(not Path('/dev/null').exists()and not Path('/dev/null').is_symlink(),'no fake device or copied-root device availability')
 raw=call(['/usr/bin/pacman','-Q']);rows=raw.decode().splitlines();inventory=dict(row.split()for row in rows);wanted=dict(row.split()for row in(CONTEXT/'expected606.lock').read_text().splitlines());wanted['cachy-asahi-setup']='0.1.0-5'if role=='setup5'else'0.1.0-6'
 need(len(rows)==len(inventory)==606 and inventory==wanted,'actual fixed pacman-Q complete606; Apps6 stays Apps6')
 actual=PROGRAM.read_bytes();expected=(CONTEXT/'setup'/('setup5.py'if role=='setup5'else'setup.py')).read_bytes();need(actual==expected,'whole exact installed selected Setup helper body')
 home=Path(os.environ['HOME']);before={p.relative_to(home).as_posix():pin(p.read_bytes())for p in home.rglob('*')if p.is_file()and not p.is_symlink()}
 call([str(PROGRAM),'--help'])
 for operation in('activate','remove','recover'):
  argv=[str(PROGRAM),operation,'--home',str(home),'--template-root','/usr/share/cachy-asahi']
  if operation=='activate':argv+=['--components','fish']
  value=call(argv);need(type(json.loads(value))is dict,'real installed readonly preview report')
 after={p.relative_to(home).as_posix():pin(p.read_bytes())for p in home.rglob('*')if p.is_file()and not p.is_symlink()};need(before==after,'preview cannot mutate retained ordinary home')
 controls=recovery_controls(work)if role=='setup6'else None
 digest=hashlib.sha256(''.join(n+' '+v+'\n'for n,v in sorted(inventory.items())).encode()).hexdigest()
 print(json.dumps(dict(status='PASS_ACTUAL_INSTALLED_SETUP_PURE_RECOVERY_ONLY',recipe_role=role,CLI=4,inventory_count=606,inventory_versions_sha256=digest,inventory_authority='SOURCE_OWNED_FIXED_PACMAN_Q',installed_controls=6 if controls else 0,controls=controls,full606_real_shell='NOT_RUN_DEVICE_FREE_COPY',Apps7_coexistence='NOT_RUN_BASELINE_APPS6',system_mutation='NONE_PRIVATE_RECOVERY_HOMES_ONLY',defaults_enabled=False),sort_keys=True))
if __name__=='__main__':main()
