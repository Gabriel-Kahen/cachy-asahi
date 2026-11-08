# SPDX-License-Identifier: MIT
"""Fixed native commands. Importing starts no actor; tests need an explicit fake.

The owner authenticates Docker isolation. This adapter joins the process root,
uid/architecture, owner-staged sentinel and mapped Source; it cannot prove them
independently of the owner. No host-root claim follows from the test constructor.
"""
import copy, hashlib, json, math, os, platform, re, stat, time
import security_recovery as core
import security_recovery_fs as fs
from security_recovery_metadata import MetadataReference
from security_recovery_state import NAME, NEW, OLD, RecoveryPolicy, _baseline
SENTINEL=core.PREFIX+'native-scope.json'
SOURCE_MAP='opt/native-security-v1/source/native/source-map.json'
PRIOR=core.PREFIX+NAME+'-0.1.0-1-any.pkg.tar.zst'
TRUST='/'+core.PREFIX+'trust'
CMD_KEY=('/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',TRUST,'--no-auto-key-retrieve','--with-colons','--list-keys')
CMD_VERIFY=('/usr/bin/gpgv','--status-fd=1','--keyring','/'+core.KEYRING,'/'+core.ARCHIVE+'.sig','/'+core.ARCHIVE)
CMD_INSTALL=('/usr/bin/pacman','--config','/'+core.CONFIG,'--noconfirm','--noscriptlet','-U','/'+core.ARCHIVE)
CMD_QUERY=('/usr/bin/pacman','--config','/'+core.CONFIG,'-Q')
CMD_REMOVE=('/usr/bin/pacman','--config','/'+core.CONFIG,'--noconfirm','--noscriptlet','-R',NAME)
def need(ok,reason):
 if not ok:raise ValueError(reason)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def content(row):return {k:v for k,v in row.items()if k not in('dev','ino','nlink')}
def natural(result,cap):
 need(type(result)is dict and type(result.get('stdout'))is bytes and type(result.get('stderr'))is bytes and len(result['stdout'])+len(result['stderr'])<=cap,'bounded owned output')
 r=result.get('retirement');need(type(r)is dict and type(r.get('exit'))is int and r['exit']==0 and r.get('error')is None and r.get('timeout')is False and r.get('forced_retirement')is False and all(r.get(k)is True for k in('passed','reaped','group_absent','pid_reserved_until_retirement')),'natural successful owned command')
 need(type(r.get('wall_started'))is int and type(r.get('wall_finished'))is int and 0<r['wall_started']<=r['wall_finished'],'owned install wall interval');return r
def validate_test_key(raw,signer,now):
 need(type(raw)is bytes and len(raw)<=65536 and type(now)is int,'bounded scoped key listing')
 rows=[s.split(':')for s in raw.decode('utf-8').splitlines()];pubs=[r for r in rows if r[0]=='pub'];fprs=[r for r in rows if r[0]=='fpr']
 need(len(pubs)==len(fprs)==1 and not any(r[0]in('sub','ssb','sec')for r in rows),'one public TEST key only');p=pubs[0]
 need(len(p)>11 and p[1]==p[8]=='u'and p[2:4]==['255','22']and re.fullmatch('[1-9][0-9]{0,18}',p[5])and re.fullmatch('[1-9][0-9]{0,18}',p[6]),'ultimate-trusted expiring ed25519 TEST key')
 created,expires=int(p[5]),int(p[6]);need(expires-created==86400 and created<=now<expires,'fresh one-day TEST key and expiry')
 need(len(fprs[0])>9 and fprs[0][9]==signer and 's'in p[11].lower(),'exact TEST signer capability');uids=[r for r in rows if r[0]=='uid']
 need(len(uids)==1 and len(uids[0])>9 and uids[0][9]=='TEST ONLY security-maintenance <security@test.invalid>','closed TEST-only UID')
 return dict(fingerprint=signer,created_epoch=created,expires_epoch=expires,listing=pin(raw),scope='EPHEMERAL_TEST_ONLY')

class NativeCommandAdapter:
 def __init__(self,root_fd,binding,sentinel_pin,inputs,*,journal=None,runner):
  from security_interruption_owner import OwnedProcessRunner
  need(type(runner)is OwnedProcessRunner,'exact owned native runner required')
  self._setup(root_fd,binding,sentinel_pin,inputs,runner,journal,False)
 @classmethod
 def for_test(cls,root_fd,binding,sentinel_pin,inputs,runner,*,journal=None):
  need(getattr(runner,'test_only',False)is True,'explicit unbound fake backend');obj=cls.__new__(cls);obj._setup(root_fd,binding,sentinel_pin,inputs,runner,journal,True);return obj
 def _setup(self,root_fd,binding,sentinel_pin,inputs,runner,journal,test):
  required={'source','ref','run','attempt','map_sha256','token'}
  need(type(root_fd)is int and type(binding)is dict and required<=set(binding)and len(binding)<=12 and type(inputs)is core.Inputs and type(sentinel_pin)is core.Pin,'explicit native inputs')
  need(re.fullmatch('[0-9a-f]{40}',binding['source'])and re.fullmatch('refs/heads/codex/[A-Za-z0-9._+/-]+',binding['ref'])and type(binding['run'])is str and re.fullmatch('[1-9][0-9]{0,19}',binding['run'])and type(binding['attempt'])is int and binding['attempt']==1 and re.fullmatch('[0-9a-f]{64}',binding['map_sha256'])and re.fullmatch('[0-9a-f]{24,64}',binding['token']),'actual source/map/run/token binding')
  need(test or journal is not None,'durable native journal required')
  self.root_fd,self.binding,self.inputs=root_fd,copy.deepcopy(binding),inputs;self.runner,self.journal,self.test_only=runner,journal,test;self.sentinel_pin=sentinel_pin
  st=os.fstat(root_fd);self._root=(st.st_dev,st.st_ino);self.owner_uid,self.owner_gid=st.st_uid,st.st_gid;self.records=[];self.install_window=None;self._counts={};self._reference=False;self._verified_candidate=False;self._scope()
 def _scope(self):
  st=os.fstat(self.root_fd);need(stat.S_ISDIR(st.st_mode)and(st.st_dev,st.st_ino)==self._root,'same root capability')
  if not self.test_only:
   actual=os.stat('/');need((actual.st_dev,actual.st_ino)==self._root and os.geteuid()==self.owner_uid==self.owner_gid==0 and platform.machine()=='aarch64','uid0 ARM process-root binding');need(self.journal.binding==self.binding,'same native journal binding')
  raw,entry=fs.read_regular(self.root_fd,SENTINEL);self.sentinel_pin.check(raw)
  need(entry['mode']==0o600 and(entry['uid'],entry['gid'])==(self.owner_uid,self.owner_gid),'private owner-staged sentinel')
  need(json.loads(raw)==dict(protocol='security-recovery-native-scope-v1',binding=self.binding,caller_verified_source=True,disposable_native_image=True),'exact owner scope; not independent authorization')
  raw,_=fs.read_regular(self.root_fd,SOURCE_MAP);need(pin(raw)['sha256']==self.binding['map_sha256'],'verified mapped Source')
 def _execute(self,step,argv,seconds,cap):
  self._scope();need(type(seconds)is int and 1<=seconds<=180 and type(cap)is int and 1<=cap<=1048576,'finite command')
  if self.journal:
   phases={'signed-candidate-install':{'BASELINE_RECORDED','RECOVERY_INSTALL_INTENT'},'remove-reference-candidate':{'REFERENCE_READY','NORMAL_EPISODE_PASSED'},'prior-required-install':{'RECOVERY_BASELINE_RESTORED'}}
   if step in phases:need(self.journal.phase in phases[step],'command mutation phase')
  intent=dict(step=step,argv=list(argv),seconds=seconds,output_cap=cap)
  if self.journal:self.journal.append('COMMAND_INTENT',intent)
  env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',PYTHONDONTWRITEBYTECODE='1',GNUPGHOME=TRUST)
  result=self.runner.run(list(argv),env=env,cwd='/',pass_fds=(),seconds=seconds,output_cap=cap);retirement=natural(result,cap)
  record=dict(intent,stdout=pin(result['stdout']),stderr=pin(result['stderr']),retirement=copy.deepcopy(retirement),binding=self.binding);self.records.append(record)
  if step in('inspect-test-key','verify-signature','verify-prior-signature'):record['status_ascii']=result['stdout'].decode('ascii')
  if self.journal:self.journal.append('COMMAND_COMPLETED',record)
  self._scope();return core.CommandResult(result['stdout'],retirement)
 def _key(self,seconds=10):
  result=self._execute('inspect-test-key',CMD_KEY,seconds,65536);self.test_authority=validate_test_key(result.stdout,self.inputs.signer,int(time.time()));return self.test_authority
 def run(self,command):
  need(type(command)is core.Command,'fixed command object');specs={'verify-signature':(CMD_VERIFY,30,65536,2),'signed-candidate-install':(CMD_INSTALL,180,1048576,2),'verify-recovered':(CMD_QUERY,30,1048576,1)}
  need(command.step in specs,'unknown command');argv,seconds,cap,count=specs[command.step];need((command.argv,command.seconds,command.output_cap)==(argv,seconds,cap),'broadened command')
  self._counts[command.step]=self._counts.get(command.step,0)+1;need(self._counts[command.step]<=count,'finite command-role count; no retry');core._inputs(self.root_fd,self,self.inputs);start=time.monotonic()
  if command.step=='verify-signature':self._key()
  if command.step=='signed-candidate-install':
   need(self._verified_candidate and int(time.time())<self.test_authority['expires_epoch'],'verified unexpired candidate signature before install');self._verified_candidate=False
  remaining=seconds-math.ceil(time.monotonic()-start)if command.step=='verify-signature'else seconds;need(remaining>0,'aggregate signature deadline');result=self._execute(command.step,argv,remaining,cap)
  if command.step=='signed-candidate-install':self.install_window=dict(started_epoch=result.retirement['wall_started'],finished_epoch=result.retirement['wall_finished'])
  if command.step=='verify-signature':core.verify_signature(result.stdout,self.inputs.signer);self._verified_candidate=True
  core._inputs(self.root_fd,self,self.inputs);return result
 def _snapshot(self,names):return fs.snapshot(self.root_fd,names,owner_uid=self.owner_uid,owner_gid=self.owner_gid)
 def _baseline(self,baseline,names):
  policy=RecoveryPolicy(self.binding['source'],self.binding['ref'],self.binding['run'],tuple(names),self.owner_uid,self.owner_gid);policy.validate();_baseline(baseline,policy)
 def capture_reference(self,payload_names,baseline):
  self._baseline(baseline,payload_names)
  need(not self._reference and self._snapshot(payload_names)==baseline,'one reference from clean baseline');self._reference=True
  result=self.run(core.Command('verify-signature',CMD_VERIFY,30,65536));core.verify_signature(result.stdout,self.inputs.signer)
  self.run(core.Command('signed-candidate-install',CMD_INSTALL,180,1048576));snapshot=self._snapshot(payload_names);db=snapshot['db']
  need(snapshot['lock']is None and OLD not in db and{n:r for n,r in db.items()if not(n==NEW or n.startswith(NEW+'/'))}==baseline['db'],'reference changes only candidate DB')
  expected_db={n:content(r)for n,r in db.items()if n==NEW or n.startswith(NEW+'/')};files={}
  for name,row in expected_db.items():
   if row['kind']=='file':
    raw,entry=fs.read_regular(self.root_fd,'var/lib/pacman/local/'+name);need(entry==db[name],'reference snapshot/bytes');files[name]=raw
  authority=dict(archive=self.inputs.archive.__dict__,signature=self.inputs.signature.__dict__,config=self.inputs.config.__dict__,keyring=self.inputs.keyring.__dict__,signer=self.inputs.signer,binding=self.binding)
  reference=MetadataReference(files,expected_db,dict(self.install_window),copy.deepcopy(authority)).validate();payload={n:None if r is None else content(r)for n,r in snapshot['payload'].items()}
  if self.journal:
   record=json.dumps(reference.record(),sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
   self.journal.append('REFERENCE_READY',dict(reference=pin(record),snapshot_sha256=fs.snapshot_sha256(snapshot),install_window=dict(reference.install_window)))
  self.remove_candidate(baseline,payload_names)
  if self.journal:self.journal.append('BASELINE_RESTORED',dict(snapshot_sha256=fs.snapshot_sha256(baseline)))
  return dict(snapshot=snapshot,candidate_db=expected_db,candidate_payload=payload,reference=reference,install_window=dict(reference.install_window),commands=copy.deepcopy(self.records))
 def remove_candidate(self,baseline,payload_names=None):
  names=tuple(baseline['payload'])if payload_names is None else payload_names;before=self._snapshot(names)
  self._baseline(baseline,names)
  need(before['lock']is None and NEW in before['db']and OLD not in before['db']and{n:r for n,r in before['db'].items()if not(n==NEW or n.startswith(NEW+'/'))}==baseline['db'],'candidate-only removal scope')
  self._counts['remove']=self._counts.get('remove',0)+1;need(self._counts['remove']<=2,'finite warm/legacy removal roles')
  self._execute('remove-reference-candidate',CMD_REMOVE,180,1048576);need(self._snapshot(names)==baseline,'remove restores complete baseline')
 def install_prior(self,archive_pin,signature_pin):
  need(not self._counts.get('prior'),'one prior-install role; never retry');self._counts['prior']=1
  def check():
   core._inputs(self.root_fd,self,self.inputs)
   for name,expected in((PRIOR,archive_pin),(PRIOR+'.sig',signature_pin)):
    need(type(expected)is core.Pin,'prior immutable pins');raw,entry=fs.read_regular(self.root_fd,name);expected.check(raw);need(entry['mode']&0o022==0,'private prior inputs')
  check()
  self._key();result=self._execute('verify-prior-signature',CMD_VERIFY[:-2]+('/'+PRIOR+'.sig','/'+PRIOR),30,65536);core.verify_signature(result.stdout,self.inputs.signer)
  check();need(int(time.time())<self.test_authority['expires_epoch'],'prior TEST key expired')
  self._execute('prior-required-install',CMD_INSTALL[:-1]+('/'+PRIOR,),180,1048576)
  check()
