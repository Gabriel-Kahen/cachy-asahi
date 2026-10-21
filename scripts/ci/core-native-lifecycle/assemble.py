# SPDX-License-Identifier: MIT
"""Dedicated offline native actor: current original64 auth and private TEST Core7 signing."""
import argparse,datetime,hashlib,importlib.util,json,os,platform,re,shutil,stat,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
OUT=Path('/out');SOURCE=Path('/runner');CORE7=Path('/core7');CORE64=Path('/core64');BASE=Path('/base-cache')

def command(argv,deadline,*,env=None):
 remaining=deadline-time.monotonic();C.need(remaining>0,'original assembly deadline');number=len(list(OUT.glob('assembly-command-*.json')));C.need(number<256,'finite assembly command count')
 try:r=subprocess.run(argv,capture_output=True,timeout=min(30,remaining),env=env)
 except subprocess.TimeoutExpired as error:
  (OUT/('assembly-command-%03d.stdout'%number)).write_bytes(error.stdout or b'');(OUT/('assembly-command-%03d.stderr'%number)).write_bytes(error.stderr or b'');(OUT/('assembly-command-%03d.json'%number)).write_bytes(C.encoded(dict(argv=argv,status='TIMEOUT',limit=min(30,remaining))));raise
 (OUT/('assembly-command-%03d.stdout'%number)).write_bytes(r.stdout);(OUT/('assembly-command-%03d.stderr'%number)).write_bytes(r.stderr);(OUT/('assembly-command-%03d.json'%number)).write_bytes(C.encoded(dict(argv=argv,exit=r.returncode,stdout=C.pin(r.stdout),stderr=C.pin(r.stderr))));C.need(r.returncode==0,'bounded assembly command failed '+str(number));return r

def authentication_module():
 sys.path.insert(0,str(Path(__file__).resolve().parent/'core-tools'));import authenticate as A
 return A

def verify_inputs(deadline):
 C.packet(CORE7);lock=json.loads(C.read(SOURCE/'builder-inputs.lock.json'));rows=lock['packages'];C.need(len(rows)==64 and lock['signer_fingerprint']=='68B3537F39A313B3E574D06777193F152BDBE6A6','unchanged original64 lock')
 A=authentication_module()
 C.need(A.SIGNER==lock['signer_fingerprint'],'same original primary signer');evidence=OUT/'authentication64';evidence.mkdir(mode=0o700);records=[]
 for row in lock['keyring_files']:
  raw=C.read(SOURCE/'keyring'/row['filename']);C.need(C.pin(raw)==dict(bytes=row['size'],sha256=row['sha256']),'whole current original public key/trust/revocation bytes')
 with tempfile.TemporaryDirectory(prefix='core-auth-public-',dir='/tmp')as tmp:
  home=Path(tmp);gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve','--auto-key-locate','clear','--no-autostart']
  imported=command(gpg+['--import',str(SOURCE/'keyring/archlinuxarm.gpg')],deadline);(evidence/'key-import.stdout').write_bytes(imported.stdout);(evidence/'key-import.stderr').write_bytes(imported.stderr)
  listing=command(gpg+['--with-colons','--list-keys'],deadline);(evidence/'keys.colons').write_bytes(listing.stdout);(evidence/'keys.stderr').write_bytes(listing.stderr);C.need(not command(gpg+['--with-colons','--list-secret-keys'],deadline).stdout,'public-only current verification home')
  version=command(['/usr/bin/gpg','--version'],deadline).stdout;(evidence/'gpg-version.stdout').write_bytes(version)
  for row in rows:
   C.need(time.monotonic()<deadline,'original890s current authentication envelope')
   for signature in(False,True):
    item=A.native.signature_item(row)if signature else row;raw=C.read(CORE64/'packages'/item['filename'],128*1024**2);C.need(C.pin(raw)==dict(bytes=item['size'],sha256=item['sha256']),'all128 exact original input bytes before authentication')
   # Original cached acquisition and complete metadata/signature parser bodies, unchanged.
   A.fetch(row,CORE64/'packages');A.fetch(A.native.signature_item(row),CORE64/'packages')
   r=command(gpg+['--status-fd','1','--verify',str(CORE64/'packages'/(row['filename']+'.sig')),str(CORE64/'packages'/row['filename'])],deadline)
   text=type('Result',(),dict(returncode=r.returncode,stdout=r.stdout.decode(),stderr=r.stderr.decode()))();A.status(text);C.need(not re.search(r'^\[GNUPG:\] (KEYEXPIRED|KEYREVOKED|SIGEXPIRED)\b',text.stdout,re.M),'current expiry/revocation rules')
   observed=A.observe(CORE64/'packages'/row['filename'],row);name=row['name'];(evidence/(name+'.gpg-status')).write_bytes(r.stdout);(evidence/(name+'.gpg-stderr')).write_bytes(r.stderr);(evidence/(name+'.json')).write_bytes(C.encoded(observed));records.append(dict(name=name,archive=dict(bytes=row['size'],sha256=row['sha256']),signature=dict(bytes=row['signature_size'],sha256=row['signature_sha256']),status=C.pin(r.stdout),exit=0,observation=C.pin(C.encoded(observed))))
 return dict(status='PASS_CURRENT_ORIGINAL64_SIGNATURE_AND_COMPLETE_PKGINFO',signer=A.SIGNER,records=records,public_home_retired=True,limit=890,time_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),package_execution='NOT_RUN')

def signer_module():return C.load('unchanged_test_signer',C.HERE/'test_signer.py')

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-only',action='store_true');args=parser.parse_args()
 if args.source_only:authentication_module();signer_module();print(C.encoded(dict(status='PASS_SOURCE_HELD_TEST_SIGNER_IMPORT_ONLY',signing='NOT_RUN',native='NOT_RUN')).decode(),end='');return 0
 C.need(os.getuid()==os.geteuid()==0 and platform.machine()=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CACHY_CORE7_ASSEMBLY')=='1'and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned offline native assembly actor only')
 os.umask(0o077);deadline=time.monotonic()+890;auth=verify_inputs(deadline);(OUT/'authentication64.json').write_bytes(C.encoded(auth));scope=C.closure();profile=C.profile();base,_,installed=C.states();base_rows={r['name']:r for r in json.loads(C.read(Path('/runtime/scripts/ci/maintained-desktop574-inputs.json')))['packages']};products={};packages=OUT/'packages';C.need(not packages.exists(),'fresh private TEST assembly');packages.mkdir(mode=0o700)
 for name,row in {**{n:base_rows[n]for n in C.REPLACED},**scope['support']}.items():
  origin=CORE64/'packages'if name in scope['support']else BASE
  for suffix,size,sha in(('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])):
   raw=C.read(origin/(row['filename']+suffix),128*1024**2);C.need(C.pin(raw)==dict(bytes=size,sha256=sha),'original support/rollback exact byte join');(packages/(row['filename']+suffix)).write_bytes(raw)
  products[name+'-original']=dict(name=name,version=row['version'],file=row['filename'],signer=auth['signer'],archive=dict(bytes=row['size'],sha256=row['sha256']),signature=dict(bytes=row['signature_size'],sha256=row['signature_sha256']),kind='SUPPORT'if name in scope['support']else'ROLLBACK')
 # No signing secret is mounted or retained; authority is an owned container tmpfs.
 sign_end=time.monotonic()+180;authority=Path('/authority');C.need(authority.is_mount()and stat.S_IMODE(authority.stat().st_mode)==0o700,'dedicated private signing tmpfs')
 S=signer_module()
 for name,row in profile['packages'].items():
  raw=C.read(CORE7/'packages'/row['filename'],64*1024**2);C.need(C.pin(raw)=={k:row[k]for k in('bytes','sha256')},'accepted seven unchanged before signing');(packages/row['filename']).write_bytes(raw)
 signer=S.sign(OUT,authority,[packages/r['filename']for r in profile['packages'].values()]);C.need(signer!=auth['signer']and re.fullmatch('[A-F0-9]{40}',signer),'separate ephemeral TEST signer')
 gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(authority/'test-signing'),'--no-auto-key-retrieve']
 try:
  for name,row in profile['packages'].items():products[name]=dict(name=name,version=row['version'],file=row['filename'],signer=signer,archive={k:row[k]for k in('bytes','sha256')},signature=C.pin(C.read(packages/(row['filename']+'.sig'))),kind='CORE7')
  catalog=dict(schema=1,scope='DISPOSABLE_CORE7_TEST_ONLY',native_origin=profile['accepted_build'],signer_roles=dict(ephemeral_TEST=signer,upstream_ALARM=auth['signer']),products=products,before=base,after=installed,old_target261='UNCHANGED_UNACCEPTED',release='NOT_ADMITTED');(OUT/'catalog.json').write_bytes(C.encoded(catalog));command(gpg+['--output',str(OUT/'catalog.json.sig'),'--detach-sign',str(OUT/'catalog.json')],sign_end)
  env=dict(PATH='/usr/bin:/bin',HOME=str(authority),GNUPGHOME=str(authority/'test-signing'),LANG='C',LC_ALL='C',TZ='UTC');candidate=[str(packages/r['filename'])for r in profile['packages'].values()];r=command(['/usr/bin/repo-add','--include-sigs','--sign','--key',signer,str(OUT/'core7-test.db.tar.gz'),*candidate],sign_end,env=env);(OUT/'repo-add.stdout').write_bytes(r.stdout);(OUT/'repo-add.stderr').write_bytes(r.stderr)
 finally:
  command(['/usr/bin/gpgconf','--homedir',str(authority/'test-signing'),'--kill','all'],sign_end)
  for name in('S.gpg-agent','S.gpg-agent.extra','S.gpg-agent.browser','S.gpg-agent.ssh'):C.need(not os.path.lexists(authority/'test-signing'/name),'all signing agent endpoints absent before completion')
 index=dict(schema=1,status='SIGNED_CORE7_TEST_ASSEMBLY_DATA_ONLY',catalog=C.pin(C.read(OUT/'catalog.json')),catalog_signature=C.pin(C.read(OUT/'catalog.json.sig')),repository=C.pin(C.read(OUT/'core7-test.db.tar.gz')),repository_signature=C.pin(C.read(OUT/'core7-test.db.tar.gz.sig')),public_key=C.pin(C.read(OUT/'TEST-public.asc')),signer=signer,authentication64=C.pin(C.read(OUT/'authentication64.json')),private_signer='TMPFS_ONLY_AGENT_ENDPOINTS_ABSENT_CONTAINER_RETIREMENT_REQUIRED',installed='NOT_RUN',hardware='NOT_RUN');(OUT/'assembly.json').write_bytes(C.encoded(index))
 uid,gid=int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID'])
 for p in(OUT,*OUT.rglob('*')):
  if p.is_symlink():C.need(p.name in('core7-test.db','core7-test.db.sig','core7-test.files','core7-test.files.sig'),'only original repo-add aliases');continue
  C.need(p.is_file()or p.is_dir(),'ordinary complete public output');os.chown(p,uid,gid);p.chmod(0o700 if p.is_dir()else 0o600)
if __name__=='__main__':main()
