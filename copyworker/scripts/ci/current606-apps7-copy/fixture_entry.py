# SPDX-License-Identifier: MIT
"""Actual signed installed frontend and original Apps7 controls, ordinary only."""
import hashlib,importlib.util,json,os,subprocess,sys
from pathlib import Path
CONTEXT=Path('/var/tmp/caa-apps7-fixture')

def need(ok,why):
 if not ok:raise ValueError(why)
def call(argv,seconds):
 value=subprocess.run(argv,stdin=0,capture_output=True,timeout=seconds)
 need(value.returncode==0 and len(value.stdout)+len(value.stderr)<=128*1024,'actual installed frontend command failed')
 return value

def main():
 need(len(sys.argv)==3 and os.getuid()==os.geteuid()>0 and os.uname().machine=='aarch64','ordinary native copied-root fixture')
 work=Path(sys.argv[1]);role=sys.argv[2];need(role in('apps6','apps7','apps14')and work.is_relative_to(CONTEXT/'outputs'),'fixed source fixture/output')
 value=call(['/usr/bin/cachy-asahi-apps','--help'],15);need(b'inventory'in value.stdout,'actual installed CLI inventory entry missing')
 snapshot=work/'actual-inventory.json';value=call(['/usr/bin/cachy-asahi-apps','inventory','--dbpath','/var/lib/pacman','--output',str(snapshot)],40)
 receipt=json.loads(value.stdout);raw=snapshot.read_bytes();need(0<len(raw)<=16*1024**2 and receipt['applied']=='NOT_APPLIED'and receipt['sha256']==hashlib.sha256(raw).hexdigest(),'actual readonly frontend/snapshot hash')
 identity=snapshot.lstat();need(identity.st_uid==os.geteuid()and identity.st_nlink==1 and __import__('stat').S_ISREG(identity.st_mode),'own ordinary snapshot identity')
 packages=json.loads(raw)['packages'];inventory={r['name']:r['version']for r in packages};need(len(packages)==len(inventory)==606 and inventory['cachy-asahi-apps']=={'apps6':'0.1.0-6','apps7':'0.1.0-7','apps14':'0.1.0-14'}[role]and inventory['cachy-asahi-repository-runtime']=='0.1.0-1','actual606 Apps/Runtime frontend metadata')
 versions_sha256=hashlib.sha256(''.join(n+' '+v+'\n'for n,v in sorted(inventory.items())).encode()).hexdigest()
 need(snapshot.lstat()==identity,'owned metadata snapshot drift before retirement');snapshot.unlink()
 tests=0;control=None
 if role in('apps7','apps14'):
  path=CONTEXT/'fixture_checks.py';spec=importlib.util.spec_from_file_location('held_installed_apps_controls',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  control=module.run_suite('apps',fixtures=CONTEXT);tests=control['tests'];need(tests==15 and control['status']=='PASS_INSTALLED_CONTROLS'and control['installed_source']is True,'all15 original installed Apps7 controls')
 print(json.dumps(dict(status='PASS_ACTUAL_INSTALLED_APPS_READONLY',recipe_role=role,CLI=2,inventory_count=len(inventory),inventory_sha256=hashlib.sha256(raw).hexdigest(),inventory_versions_sha256=versions_sha256,raw_inventory='OWN_TEMP_REMOVED_BOUNDED_HASH_ONLY_NOT_PAYLOAD_PROOF',installed_controls=tests,controls=control,applied='NOT_APPLIED'),sort_keys=True))
if __name__=='__main__':main()
