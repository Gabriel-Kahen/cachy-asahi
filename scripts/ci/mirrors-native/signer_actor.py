#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One offline native actor; fresh TEST signatures and public-only retained output."""
import importlib.util,json,os,platform,re,shutil,stat,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_auth as A
HERE=Path(__file__).resolve().parent
ENDPOINTS=('S.gpg-agent','S.gpg-agent.extra','S.gpg-agent.browser','S.gpg-agent.ssh')


def ordinary(path,cap):
 A.need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute input required')
 info=path.lstat();A.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=cap,'bounded single-link regular input required')
 return path.read_bytes()


class Commands:
 def __init__(self,deadline,home):
  self.deadline=deadline;self.rows=[];self.env=dict(PATH='/usr/bin:/bin',HOME=str(home),LANG='C',LC_ALL='C',TZ='UTC')
 def call(self,argv,operation,expected=0,timeout=30):
  remaining=self.deadline-time.monotonic();A.need(remaining>0 and len(self.rows)<40,'same120s signing/cleanup budget and finite commands required')
  A.need(not any('faked-system-time' in str(v) for v in argv),'actual job time; no fake signing clock')
  result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=min(timeout,remaining),env=self.env)
  A.need(len(result.stdout)+len(result.stderr)<=65536,'bounded signer public command output')
  self.rows.append(dict(operation=operation,exit=result.returncode,stdout=A.pin(result.stdout),stderr=A.pin(result.stderr)))
  A.need(result.returncode==expected if expected is not None else result.returncode!=0,'TEST signature command exit differs: '+operation)
  return result


class HeldProxy:
 def __init__(self,commands,role):self.commands=commands;self.role=role;self.listing=None
 def execute(self,argv,**kwargs):
  op='KEY_GENERATE' if '--quick-generate-key' in argv else 'PUBLIC_LIST' if '--list-keys' in argv else 'PUBLIC_EXPORT' if '--export' in argv else 'ARCHIVE_SIGN'
  result=self.commands.call(argv,self.role+'_'+op,timeout=kwargs.get('timeout',30))
  if op=='PUBLIC_LIST':self.listing=result.stdout
  return result.stdout.decode() if kwargs.get('text') else result.stdout
 def run(self,argv,**kwargs):self.execute(argv,**kwargs)
 def check_output(self,argv,**kwargs):return self.execute(argv,**kwargs)


def held_signer(proxy):
 spec=importlib.util.spec_from_file_location('_whole_held_mirror_TEST_signer',HERE/'held_test_signer.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.subprocess=proxy;return module


def key_lifetime(raw,fingerprint):
 rows=[line.split(':') for line in raw.decode().splitlines()];pub=[r for r in rows if r[0]=='pub'];fpr=[r[9] for r in rows if r[0]=='fpr']
 A.need(len(pub)==len(fpr)==1 and fpr[0]==fingerprint and pub[0][3]=='22' and pub[0][4]==fingerprint[-16:] and pub[0][5].isdigit() and pub[0][6].isdigit(),'one fresh Ed25519 primary key required')
 return dict(fingerprint=fingerprint,created_epoch=int(pub[0][5]),expires_epoch=int(pub[0][6]))


def retire(home,commands,role):
 if not home.exists():return
 commands.call(['/usr/bin/gpgconf','--homedir',str(home),'--kill','all'],role+'_RETIRE',timeout=20)
 A.need(all(not os.path.lexists(home/name) for name in ENDPOINTS),'private signer/verification agent endpoints remain')
 shutil.rmtree(home);A.need(not home.exists(),'private signing home removal required')


def sign(input_path,output,*,native=True):
 started_mono=time.monotonic();started=int(time.time());deadline=started_mono+120
 A.need(output.is_absolute() and output.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)) and not list(output.iterdir()) and output.stat().st_uid==os.getuid() and stat.S_IMODE(output.stat().st_mode)==0o700,'fresh owned0700 public output required')
 value=json.loads(ordinary(input_path,65536));A.need(type(value)is dict and set(value)=={'job','products'},'closed signing input required');job=value['job'];scope_start,scope_end=A.job_scope(job)
 A.need(scope_start<=started<=scope_end,'signer must run inside actual100min job window');products=value['products'];A.need(type(products)is dict and set(products)=={'a','b'},'exact two build inputs required')
 for side,row in products.items():
  A.need(type(row)is dict and set(row)=={'archive','bytes','sha256'} and type(row['archive'])is str and Path(row['archive']).parent==input_path.parent/side and re.fullmatch(r'cachy-asahi-mirrors-0\.2\.0-2-any\.pkg\.tar\.xz',Path(row['archive']).name),'exact two readonly native mirror archive roles required')
  A.need(A.pin(ordinary(Path(row['archive']),8*1024**2))=={k:row[k] for k in ('bytes','sha256')},'verified native archive bytes differ before signing')
 A.need(products['a']['bytes']==products['b']['bytes'] and products['a']['sha256']==products['b']['sha256'],'byte-identical native pair required')
 os.umask(0o077);work=Path(tempfile.mkdtemp(prefix='mirrors-test-signer-',dir='/tmp'));commands=Commands(deadline,work);homes=[];success=False
 try:
  paths={}
  for side,row in products.items():
   directory=work/side;directory.mkdir(mode=0o700);path=directory/Path(row['archive']).name;path.write_bytes(ordinary(Path(row['archive']),8*1024**2));paths[side]=path
  wrong_dir=work/'wrong-package';wrong_dir.mkdir(mode=0o700);wrong_path=wrong_dir/paths['a'].name;wrong_path.write_bytes(paths['a'].read_bytes())
  fingerprints={};keys={}
  for role,packages in (('main',[paths['a'],paths['b']]),('wrong',[wrong_path])):
   root=work/(role+'-authority');root.mkdir(mode=0o700);home=root/'test-signing';homes.append((home,role));public=work/(role+'-public');public.mkdir(mode=0o700)
   proxy=HeldProxy(commands,role.upper());fingerprint=held_signer(proxy).sign(public,root,packages);fingerprints[role]=fingerprint;keys[role]=key_lifetime(proxy.listing,fingerprint)
   shutil.copyfile(public/'TEST-public.asc',output/('TEST-public.asc' if role=='main' else 'WRONG-TEST-public.asc'))
  A.need(fingerprints['main']!=fingerprints['wrong'],'wrong-key fixture must be independently generated')
  for side,path in paths.items():shutil.copyfile(Path(str(path)+'.sig'),output/('build-'+side+'.sig'))
  shutil.copyfile(Path(str(wrong_path)+'.sig'),output/'wrong-key.sig')
  # Destroy both private keys before public-only verification and any completion receipt.
  for home,role in homes:retire(home,commands,role.upper())
  verifier=work/'public-verifier';verifier.mkdir(mode=0o700);homes.append((verifier,'public'))
  gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(verifier),'--no-auto-key-retrieve','--auto-key-locate','clear','--no-autostart']
  commands.call(gpg+['--import',str(output/'TEST-public.asc')],'PUBLIC_IMPORT')
  A.need(not commands.call(gpg+['--with-colons','--list-secret-keys'],'PUBLIC_NO_SECRET_KEYS').stdout,'verification home must contain no secret keys')
  archives={}
  for side,path in paths.items():
   row=commands.call(gpg+['--status-fd','1','--verify',str(output/('build-'+side+'.sig')),str(path)],'VERIFY_BUILD_'+side.upper())
   verification=A.verify_status(row.stdout,row.returncode,fingerprints['main'],max(scope_start,started-1),int(time.time()))
   archives[side]=dict(products[side],signature=A.pin((output/('build-'+side+'.sig')).read_bytes()),verification=verification)
  wrong=commands.call(gpg+['--status-fd','1','--verify',str(output/'wrong-key.sig'),str(paths['a'])],'REFUSE_WRONG_KEY',expected=None)
  A.need(('[GNUPG:] NO_PUBKEY '+fingerprints['wrong'][-16:]).encode() in wrong.stdout and b'[GNUPG:] VALIDSIG ' not in wrong.stdout,'actual unknown wrong TEST signer must be refused')
  tampered=work/'tampered.pkg.tar.xz';tampered.write_bytes(paths['a'].read_bytes()+b'\0'*4)
  tamper=commands.call(gpg+['--status-fd','1','--verify',str(output/'build-a.sig'),str(tampered)],'REFUSE_TAMPERED_BYTES',expected=None)
  A.need(('[GNUPG:] BADSIG '+fingerprints['main'][-16:]).encode() in tamper.stdout and b'[GNUPG:] VALIDSIG ' not in tamper.stdout,'actual tampered bytes must be refused')
  retire(verifier,commands,'PUBLIC');success=True
 finally:
  for home,role in homes:
   if home.exists():retire(home,commands,role.upper())
  if all(not home.exists() for home,_ in homes):shutil.rmtree(work)
 A.need(success and not work.exists() and time.monotonic()-started_mono<=120,'private signer root and agents must retire in120s')
 result=dict(schema_version=1,status='PASS_FRESH_TEST_SIGNATURES_PUBLIC_ONLY',job=job,
  actor=dict(architecture=platform.machine(),uid=os.getuid(),started_epoch=started,finished_epoch=int(time.time()),seconds=time.monotonic()-started_mono,limit=120),
  signer=fingerprints['main'],wrong_signer=fingerprints['wrong'],key_lifetimes=keys,public_key=A.pin((output/'TEST-public.asc').read_bytes()),wrong_public_key=A.pin((output/'WRONG-TEST-public.asc').read_bytes()),wrong_signature=A.pin((output/'wrong-key.sig').read_bytes()),archives=archives,
  negatives=dict(wrong_key=dict(exit=wrong.returncode,expected_rejection=True,status=A.pin(wrong.stdout)),tampered=dict(exit=tamper.returncode,expected_rejection=True,status=A.pin(tamper.stdout))),
  cleanup=dict(private_keys_removed=True,agent_endpoints_absent=True,private_root_removed=True,verifier_home_removed=True),operations=commands.rows)
 A.validate_signing(result,job,products,architecture='aarch64' if native else platform.machine())
 raw=(json.dumps(result,indent=2,sort_keys=True)+'\n').encode();A.need(len(raw)<=65536,'signing receipt cap')
 with (output/'signing.json').open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 A.need({p.name for p in output.iterdir()}=={'TEST-public.asc','WRONG-TEST-public.asc','build-a.sig','build-b.sig','wrong-key.sig','signing.json'},'only fixed public TEST outputs may be retained')
 return result


def tmpfs_tmp():
 rows=[r.split() for r in Path('/proc/self/mountinfo').read_text().splitlines()]
 return any(len(r)>6 and r[4]=='/tmp' and '-' in r and r[r.index('-')+1]=='tmpfs' for r in rows)


def main():
 A.need(os.getuid()==os.geteuid()>0 and platform.machine()=='aarch64' and Path('/.dockerenv').is_file() and Path('/tmp').is_mount() and tmpfs_tmp() and os.environ.get('CACHY_ASAHI_MIRRORS_TEST_SIGNER')=='1' and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'dedicated ordinary offline native TEST signer actor required')
 print(json.dumps(sign(Path('/inputs/signing-input.json'),Path('/out')),sort_keys=True))


if __name__=='__main__':main()
