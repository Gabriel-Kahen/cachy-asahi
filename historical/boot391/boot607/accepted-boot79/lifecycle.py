# SPDX-License-Identifier: MIT
"""Boot-only offline native installed lifecycle; synthetic journal DATA only."""
import hashlib,json,os,pwd,stat,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import boot_fixture as F
NAMES=('cachy-asahi-boot-report',)
def need(ok,message):
 if not ok:raise ValueError(message)
def command(argv,expected=0,timeout=35):
 row=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout);need(len(row.stdout)+len(row.stderr)<=128*1024,'command cap');need(row.returncode==expected,'command failed: '+repr(argv)+': '+row.stderr.decode(errors='replace')[:256]);return row.stdout.decode()
def inventory():return dict(r.split()for r in command(['/usr/bin/pacman','-Q']).splitlines())
def snapshot(root):
 rows={}
 for p in [root,*root.rglob('*')]:
  st=p.lstat();rows[str(p.relative_to(root))]=dict(mode=st.st_mode,uid=st.st_uid,gid=st.st_gid,mtime_ns=st.st_mtime_ns,contents=p.readlink().as_posix()if p.is_symlink()else hashlib.sha256(p.read_bytes()).hexdigest()if p.is_file()else None)
 return rows

def main():
 need(os.getuid()==0 and Path('/.dockerenv').is_file()and os.uname().machine=='aarch64'and os.environ.get('CACHY_ASAHI_PRODUCT_LIFECYCLE')=='1','dedicated native ARM container required')
 original=json.loads(Path('/inputs/base.json').read_text());products=json.loads(Path('/inputs/products.json').read_text());need(len(original)==574 and inventory()==original and set(products)==set(NAMES),'exact574 and Boot-only inputs required')
 product=products[NAMES[0]];archive=Path('/inputs')/product['archive'];need(archive.parent==Path('/inputs')and archive.is_file()and not archive.is_symlink()and F.pin(archive)['sha256']==product['sha256'],'exact development archive required')
 hooks=Path('/tmp/product-hooks');hooks.mkdir();masked=set()
 for parent in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks','/builder-disabled-hooks'):
  for p in Path(parent).glob('*.hook'):
   if p.name not in masked:(hooks/p.name).symlink_to('/dev/null');masked.add(p.name)
 config=Path('/tmp/product-pacman.conf');config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Optional\nHookDir = '+str(hooks)+'\n');pacman=['/usr/bin/pacman','--config',str(config),'--noconfirm','--noscriptlet']
 account=pwd.getpwnam('alarm');homes=[];receipts={};events=[]
 for kind in ('fresh','existing'):
  home=Path('/tmp')/('product-home-'+kind);home.mkdir(mode=0o700)
  if kind=='existing':
   (home/'.config').mkdir();(home/'.config/user-sentinel').write_text('preserve existing configuration\n');(home/'.config/alias').symlink_to('user-sentinel')
  for p in [home,*home.rglob('*')]:os.chown(p,account.pw_uid,account.pw_gid,follow_symlinks=False)
  homes.append((home,snapshot(home)))
 fixture=Path('/runner/boot-fixture');fixture_hash=F.snapshot(fixture)
 def preserve():
  need(F.snapshot(fixture)==fixture_hash,'source-owned TEST DATA changed')
  for home,before in homes:need(snapshot(home)==before,'user configuration changed')
  for directory,before in receipts.items():need(F.snapshot(directory)==before,'private user reports lost/changed across package transitions')
 def installed(label):
  need(inventory()=={**original,NAMES[0]:'0.1.0-1'},'installed inventory differs')
  for member,expected in product['payload'].items():
   path=Path('/')/member;st=path.lstat();need(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==expected['mode']and F.pin(path)['sha256']==expected['sha256'],'installed payload differs');need(command(['/usr/bin/pacman','-Qqo',str(path)]).strip()==NAMES[0],'ALPM payload ownership differs')
  observations=[]
  for home,_ in homes:
   root=Path('/tmp')/('boot-'+home.name+'-'+label);root.mkdir(mode=0o700);os.chown(root,account.pw_uid,account.pw_gid)
   # Exercise under the ordinary installed account; no host journal is queried.
   result=Path('/out')/('boot-'+home.name+'-'+label+'.json')
   argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C','HOME='+str(home),'/usr/bin/python3','-I','-B','/runner/installed_fixture.py','--root',str(root),'--home',str(home),'--fixture',str(fixture),'--output',str(root/'receipt.json')]
   command(argv,timeout=100);row=json.loads((root/'receipt.json').read_bytes());F.validate(row,F.pin(fixture/'system.journal')['sha256']);need(all(p.lstat().st_uid==account.pw_uid for p in(root/'report').iterdir()),'ordinary user report ownership absent')
   receipts[root/'report']=F.snapshot(root/'report');observations.append(dict(home=home.name,boot=row))
  preserve();events.append(dict(phase=label,status='PASS',inventory_count=575,config_preserved=True,reports_preserved=True,observations=observations))
 def absent(label):
  need(inventory()==original,'original574 inventory not restored')
  need(all(not os.path.lexists(Path('/')/n)for n in product['payload']),'Boot payload remains after removal');preserve();events.append(dict(phase=label,status='PASS',inventory_count=574,config_preserved=True,reports_preserved=True))
 for label in ('install','same-version-reinstall'):command(pacman+['-U',str(archive)]);installed(label)
 command(pacman+['-R',*NAMES]);absent('remove');command(pacman+['-U',str(archive)]);installed('reinstall-after-removal');command(pacman+['-R',*NAMES]);absent('final-remove')
 result=dict(status='PASS_PRODUCTS_INSTALLED_CLI_LIFECYCLE',events=events,base_count=574,installed_count=575,user_config_preserved=True,user_reports_preserved=True,masked_hooks=len(masked),GUI='NOT_RUN',hardware='NOT_RUN',actual_page_size=os.sysconf('SC_PAGE_SIZE'),history_completeness='UNKNOWN',kernel_crash_diagnosis='NOT_ESTABLISHED');Path('/out/lifecycle.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
if __name__=='__main__':main()
