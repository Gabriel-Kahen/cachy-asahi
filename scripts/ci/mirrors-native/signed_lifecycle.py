# SPDX-License-Identifier: MIT
"""Public-only TEST verification and Required ALPM gate inside disposable root."""
import hashlib,importlib.util,json,os,shutil,stat,subprocess,time
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from gate_diagnostics import Diagnostics
_SPEC=importlib.util.spec_from_file_location('_mirror_signature_status',Path(__file__).with_name('test_auth.py'))
AUTH=importlib.util.module_from_spec(_SPEC);_SPEC.loader.exec_module(AUTH)

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def raw(path,cap=8*1024**2):
 need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute signed input required')
 info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap,'bounded singlelink signed input required')
 return path.read_bytes()
def digest_inventory(value):return pin(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
def config_text(keyring,hooks):
 need(keyring.is_absolute() and hooks.is_absolute() and '\n' not in str(keyring)+str(hooks),'absolute private configuration paths required')
 return '[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(keyring)+'\nHookDir = '+str(hooks)+'\n'

class Gate:
 def __init__(self,C,L,inputs,work,base,product,hooks,config,diagnostics):
  self.C,self.L,self.inputs,self.work,self.base=C,L,inputs,work,base
  self.diagnostics=Diagnostics(diagnostics)
  need(not work.exists() and work.is_absolute() and work.parent==Path('/tmp') and not work.is_symlink(),'fresh dedicated temporary TEST verifier required')
  self.deadline=time.monotonic()+120;self.closed=False;self.verified=False;self.commands=[]
  self.upstream=Path('/etc/pacman.d/gnupg');self.upstream_before=self.upstream_snapshot()
  work.mkdir(mode=0o700);self.keyring=work/'public-keyring';self.keyring.mkdir(mode=0o700)
  self.gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(self.keyring),'--no-auto-key-retrieve','--auto-key-locate','clear','--no-autostart']
  self.receipt=dict(status='FAIL',signature_policy='SigLevel=Required;LocalFileSigLevel=Required',public_only=True,commands=self.commands,negatives=[],observations=[],cleanup=dict(verifier_removed=False,agent_endpoints_absent=False,upstream_trust_preserved=False))
  try:
   signed=inputs/'signed';self.job=json.loads(raw(inputs/'signing-job.json',65536));plan=json.loads(raw(inputs/'signing-input.json',65536))
   need(plan['job']==self.job and set(plan['products'])=={'a','b'},'same-job original signer input required')
   self.signing=json.loads(raw(signed/'signing.json',256*1024));AUTH.validate_signing(self.signing,self.job,plan['products'])
   now=int(time.time());need(self.job['proof_issued_epoch']<=now<=self.job['proof_issued_epoch']+6000,'verification must remain inside actual job clock')
   self.signer=self.signing['signer'];self.wrong_signer=self.signing['wrong_signer']
   name=product['archive'];need(Path(name).name==name and product['archive_b']=='build-b/'+name,'exact A/B lifecycle archive roles required')
   archives={'a':inputs/name,'b':inputs/product['archive_b']}
   for side,path in archives.items():
    body=raw(path);need(pin(body)=={k:plan['products'][side][k] for k in ('bytes','sha256')},'lifecycle archive differs from signed native pair')
    need(hashlib.sha256(body).hexdigest()==product['sha256' if side=='a' else 'sha256_b'],'source-bound native pair hash differs')
   need(raw(archives['a'])==raw(archives['b']),'signed A/B must be byte-identical native pair')
   public=raw(signed/'TEST-public.asc',65536);wrong_public=raw(signed/'WRONG-TEST-public.asc',65536)
   need(pin(public)==self.signing['public_key'] and pin(wrong_public)==self.signing['wrong_public_key'],'exact public TEST key exports required')
   for side in ('a','b'):need(pin(raw(signed/('build-'+side+'.sig'),65536))==self.signing['archives'][side]['signature'],'native detached signature pin differs')
   need(pin(raw(signed/'wrong-key.sig',65536))==self.signing['wrong_signature'],'wrong-key signature pin differs')
   (self.keyring/'gpg.conf').write_text('no-auto-key-retrieve\nauto-key-locate clear\nno-autostart\n')
   self.call(self.gpg+['--import',str(signed/'TEST-public.asc')],'import-main-public')
   listing=self.call(self.gpg+['--with-colons','--list-keys'],'list-only-main-public').stdout.decode()
   fprs=[line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
   need(fprs==[self.signer] and self.wrong_signer not in listing,'only main TEST key may be trusted')
   need(not self.call(self.gpg+['--with-colons','--list-secret-keys'],'list-no-secret-keys').stdout,'public verifier must contain no private key')
   trust=self.keyring/'ownertrust';trust.write_text(self.signer+':6:\n');self.call(self.gpg+['--import-ownertrust',str(trust)],'trust-main-TEST-only')
   verified={}
   for side,path in archives.items():
    result=self.call(self.gpg+['--status-fd','1','--verify',str(signed/('build-'+side+'.sig')),str(path)],'verify-build-'+side)
    verified[side]=AUTH.verify_status(result.stdout,result.returncode,self.signer,self.job['proof_issued_epoch'],now)
   self.receipt.update(signing_receipt_data=self.signing,job=self.job,signer=self.signer,wrong_signer=self.wrong_signer,signing_receipt=pin(raw(signed/'signing.json',256*1024)),public_key=pin(public),archives={side:dict(archive=pin(raw(path)),signature=pin(raw(signed/('build-'+side+'.sig'),65536)),verification=verified[side]) for side,path in archives.items()},wrong_key_not_trusted=True)
   config.write_text(config_text(self.keyring,hooks));self.pacman=['/usr/bin/pacman','--config',str(config),'--noconfirm','--noscriptlet']
   accepted=work/'accepted';accepted.mkdir(mode=0o700);self.archive=accepted/name;self.archive.write_bytes(raw(archives['a']));Path(str(self.archive)+'.sig').write_bytes(raw(signed/'build-a.sig',65536))
   self.check_base()
   for label in ('missing-signature','wrong-key','tampered'):
    case=work/label;case.mkdir(mode=0o700);candidate=case/name;candidate.write_bytes(raw(archives['a'])+(b'\0'*4 if label=='tampered' else b''))
    signature=Path(str(candidate)+'.sig')
    if label!='missing-signature':signature.write_bytes(raw(signed/('wrong-key.sig' if label=='wrong-key' else 'build-a.sig'),65536))
    result=self.call(self.gpg+['--status-fd','1','--verify',str(signature),str(candidate)],'reject-'+label+'-gpg',reject=True)
    tags={line.split()[1] for line in result.stdout.decode().splitlines() if line.startswith('[GNUPG:] ') and len(line.split())>1}
    wanted={'wrong-key':{'NO_PUBKEY','ERRSIG'},'tampered':{'BADSIG'},'missing-signature':{'NODATA','FAILURE'}}[label]
    need(tags&wanted or (label=='missing-signature' and not signature.exists()),'concrete signature refusal status required')
    alpm=self.call(self.pacman+['-U',str(candidate)],'reject-'+label+'-ALPM',reject=True)
    need(b'signature' in (alpm.stdout+alpm.stderr).lower(),'ALPM must concretely refuse candidate signature, not an unrelated error')
    self.check_base()
    self.receipt['negatives'].append(dict(case=label,gpg_exit=result.returncode,pacman_exit=alpm.returncode,pacman_signature_diagnostic=True,signature_rejected=True,inventory_count=574,inventory_unchanged=True,inventory=digest_inventory(base)))
   self.assert_upstream();self.verified=True;self.receipt.update(status='PASS_TEST_SIGNATURE_VERIFIED_BEFORE_CANDIDATE_OBSERVATION',verified_before_candidate_observation=True,verified_epoch=int(time.time()),verification_limit_seconds=120)
  except BaseException as error:
   self.receipt['error']=dict(kind=type(error).__name__,message=str(error)[:512])
   try:self.diagnostics.checkpoint('FAILED',self.receipt)
   finally:self.close()
   raise

 def call(self,argv,label,reject=False,cleanup=False):
  remaining=self.deadline-time.monotonic();need(cleanup or remaining>0,'public TEST verification120s deadline')
  start=int(time.time())
  try:
   result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',HOME=str(self.work)),timeout=15 if cleanup else min(30,remaining))
  except subprocess.TimeoutExpired as error:
   self.diagnostics.capture(argv,label,None,error.stdout or b'',error.stderr or b'',start,int(time.time()),error='TimeoutExpired')
   raise
  captured=self.diagnostics.capture(argv,label,result.returncode,result.stdout,result.stderr,start,int(time.time()))
  need(captured['complete'],'complete public diagnostic bodies required')
  need(len(result.stdout)+len(result.stderr)<=128*1024,'public verification command output cap')
  self.commands.append(dict(operation=label,exit=result.returncode,started_epoch=start,finished_epoch=captured['finished_epoch'],stdout=pin(result.stdout),stderr=pin(result.stderr)))
  need(type(result.returncode) is int and (result.returncode>0 if reject else result.returncode==0),'signed lifecycle command exit differs: '+label)
  return result
 def check_base(self):
  need(self.L.inventory()==self.base and len(self.base)==574,'signature refusals must preserve exact574 inventory')
  need(not os.path.lexists(Path('/usr/bin/cachy-asahi-mirrors')),'candidate payload appeared before verified install')
 def upstream_snapshot(self):
  if not os.path.lexists(self.upstream):return None
  need(self.upstream.is_dir() and not self.upstream.is_symlink(),'ordinary original upstream trust directory required')
  return dict(root=self.L.entry(self.upstream),files=self.L.snapshot(self.upstream))
 def assert_upstream(self):need(self.upstream_snapshot()==self.upstream_before,'original upstream574 trust/configuration changed')
 def before_observation(self,label):
  need(self.verified and not self.closed,'candidate observation requires completed current signature gate')
  need(int(time.time())<=self.job['proof_issued_epoch']+6000,'candidate observation outside actual job clock')
  self.assert_upstream();self.receipt['observations'].append(dict(phase=label,epoch=int(time.time()),signature_gate_complete=True))
 def close(self):
  if self.closed:return
  self.closed=True
  try:
   if self.keyring.exists():
    self.call(['/usr/bin/gpgconf','--homedir',str(self.keyring),'--kill','all'],'public-verifier-retire',cleanup=True)
    need(not any(os.path.lexists(self.keyring/name) for name in ('S.gpg-agent','S.gpg-agent.extra','S.gpg-agent.browser','S.gpg-agent.ssh')),'public verifier agent endpoint remains')
   self.receipt['cleanup']['agent_endpoints_absent']=True
   self.assert_upstream();self.receipt['cleanup']['upstream_trust_preserved']=True
  finally:
   if self.work.exists():shutil.rmtree(self.work)
   self.receipt['cleanup']['verifier_removed']=not self.work.exists()
   self.receipt['diagnostics']=dict(index=self.diagnostics.checkpoint(self.receipt['status'],self.receipt),directory='signature-verification')

def prepare(C,L,inputs,work,base,product,hooks,config,diagnostics):return Gate(C,L,inputs,work,base,product,hooks,config,diagnostics)


def validate_gate(value):
 need(type(value) is dict and value.get('status')=='PASS_TEST_SIGNATURE_VERIFIED_BEFORE_CANDIDATE_OBSERVATION' and value.get('signature_policy')=='SigLevel=Required;LocalFileSigLevel=Required' and value.get('public_only') is True and value.get('wrong_key_not_trusted') is True and value.get('verified_before_candidate_observation') is True,'complete Required public-only signature gate required')
 diagnostics=value.get('diagnostics');need(type(diagnostics) is dict and set(diagnostics)=={'index','directory'} and diagnostics.get('directory')=='signature-verification' and AUTH.whole(diagnostics.get('index'),512*1024),'complete bounded public diagnostic index required')
 signing=value.get('signing_receipt_data',{});job=value.get('job');archives=signing.get('archives',{})
 need(type(archives) is dict and set(archives)=={'a','b'},'both full native signing records required')
 rows={side:{k:row[k] for k in ('archive','bytes','sha256')} for side,row in archives.items()};AUTH.validate_signing(signing,job,rows)
 need(value.get('signing_receipt')==pin((json.dumps(signing,indent=2,sort_keys=True)+'\n').encode()),'exact canonical signing receipt bytes differ')
 start,end=AUTH.job_scope(job);need(value.get('signer')==signing['signer'] and value.get('wrong_signer')==signing['wrong_signer'] and value.get('public_key')==signing['public_key'] and AUTH.whole(value.get('signing_receipt'),256*1024),'same-job signer/public receipt join required')
 need(type(value.get('verified_epoch')) is int and signing['actor']['finished_epoch']<=value['verified_epoch']<=end and value.get('verification_limit_seconds')==120,'verification before observations within actual job clock required')
 observed=value.get('archives');need(type(observed) is dict and set(observed)=={'a','b'},'both lifecycle signature verifications required')
 for side,row in observed.items():
  proof=row.get('verification',{});wanted=signing['archives'][side]
  need(row.get('archive')=={k:wanted[k] for k in ('bytes','sha256')} and row.get('signature')==wanted['signature'],'lifecycle native archive/signature join differs')
  need(proof.get('status')=='PASS_CURRENT_TEST_SIGNATURE' and proof.get('fingerprint')==proof.get('primary_fingerprint')==signing['signer'] and proof.get('created_epoch')==wanted['verification']['created_epoch'] and proof.get('expires_epoch')==wanted['verification']['expires_epoch'] and AUTH.whole(proof.get('status_pin'),65536),'actual current primary signature verification required')
 negatives=value.get('negatives');need(type(negatives) is list and [r.get('case') for r in negatives]==['missing-signature','wrong-key','tampered'],'all three ordered Required ALPM refusals required')
 for row in negatives:need(type(row.get('gpg_exit')) is int and row['gpg_exit']>0 and type(row.get('pacman_exit')) is int and row['pacman_exit']>0 and row.get('pacman_signature_diagnostic') is True and row.get('signature_rejected') is True and type(row.get('inventory_count')) is int and row['inventory_count']==574 and row.get('inventory_unchanged') is True and AUTH.whole(row.get('inventory')),'concrete signature refusals and full574 preservation required')
 need(len({json.dumps(r['inventory'],sort_keys=True) for r in negatives})==1,'refusal inventories differ')
 observations=value.get('observations');need(type(observations) is list and [r.get('phase') for r in observations]==['staged-before-install','install','same-version-reinstall','reinstall-after-removal'] and all(r.get('signature_gate_complete') is True and type(r.get('epoch')) is int and value['verified_epoch']<=r['epoch']<=end for r in observations),'all staged/installed observations require preceding signature gate')
 need([r['epoch'] for r in observations]==sorted(r['epoch'] for r in observations),'observation signature tickets reordered')
 cleanup=value.get('cleanup');need(type(cleanup) is dict and set(cleanup)=={'verifier_removed','agent_endpoints_absent','upstream_trust_preserved'} and all(v is True for v in cleanup.values()),'public verifier retirement and unchanged upstream trust required')
 expected=['import-main-public','list-only-main-public','list-no-secret-keys','trust-main-TEST-only','verify-build-a','verify-build-b']+[name for case in ('missing-signature','wrong-key','tampered') for name in ('reject-'+case+'-gpg','reject-'+case+'-ALPM')]+['public-verifier-retire']
 commands=value.get('commands');need(type(commands) is list and [r.get('operation') for r in commands]==expected,'complete public verification command closure required')
 for row in commands:need(type(row.get('exit')) is int and (row['exit']>0 if row['operation'].startswith('reject-') else row['exit']==0) and type(row.get('started_epoch')) is int and type(row.get('finished_epoch')) is int and start<=row['started_epoch']<=row['finished_epoch']<=end and AUTH.whole(row.get('stdout'),128*1024,True) and AUTH.whole(row.get('stderr'),128*1024,True),'typed bounded complete signature command receipts required')
 return dict(status='PASS_REQUIRED_TEST_SIGNATURE_AND_ALPM_GATE',signer=value['signer'],verified_builds=2,refused_cases=3,observation_batches=4,upstream_trust='UNCHANGED')
