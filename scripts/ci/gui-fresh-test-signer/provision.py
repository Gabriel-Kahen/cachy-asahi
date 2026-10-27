#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Produce one owned native TEST environment from frozen public bytes; no keys."""
import argparse,hashlib,importlib.util,io,json,os,platform,posixpath,re,shutil,stat,sys,tarfile,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
PURPOSE='GUI_FRESH_TEST_SIGNER_PROVISION_V1'
PLAN_PIN={'bytes':9803,'sha256':'d62f13c376ea304dd550f44483800ee23326c0d92555fb504fbc8c1847a66b59'}
LOCK_PIN={'bytes':328101,'sha256':'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'}
BASE={'scripts/ci/sign_fixture.py':{'bytes':35990,'sha256':'430a52245fb2adb6a6c9fb68ee256570ca1c5468863f5e0f3b04145e0d9dcf85'},'scripts/ci/native_arm.py':{'bytes':28318,'sha256':'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'},'scripts/checks/package_checks.py':{'bytes':17706,'sha256':'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8'}}
PUBLIC=('production.json','environment.json','contract.json','acquisition.json','input-authentication.json','qualification.json','build-context.json','rootfs-inventory.json','overlay.json','source-provenance.json','cleanup.json','provision-plan.json')
LABEL='org.cachy-asahi.gui-provision-'
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def ordinary(p):
 p=Path(p);need(p.is_absolute()and p==p.resolve()and not any(x.is_symlink()for x in(p,*p.parents)),'canonical ordinary provisioning path');return p
def read(p,cap=4*1024**2):
 p=ordinary(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=cap,'bounded single-link provisioning input');b=bytearray()
  while part:=os.read(fd,min(65536,s.st_size+1-len(b))):b.extend(part);need(len(b)<=s.st_size,'stable provisioning extent')
  need(len(b)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(p.lstat()),'whole stable provisioning FD/path');return bytes(b)
 finally:os.close(fd)
def filepin(p,cap=2*1024**3):
 p=ordinary(p);s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=cap,'bounded ordinary artifact');h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1024**2):h.update(b)
  need(identity(s)==identity(os.fstat(f.fileno()))==identity(p.lstat()),'whole stable artifact identity')
 return dict(bytes=s.st_size,sha256=h.hexdigest())
def obj(b):
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'duplicate provisioning JSON field');d[k]=v
  return d
 return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite provisioning JSON'))
def save(p,v):
 raw=enc(v);need(len(raw)<=4*1024**2 and b'PRIVATE KEY'not in raw,'bounded public provisioning receipt');p=Path(p)
 fd,name=tempfile.mkstemp(prefix=p.name+'.',suffix='.partial',dir=p.parent)
 try:
  with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  os.chmod(name,0o600);os.replace(name,p)
 finally:Path(name).unlink(missing_ok=True)
def environment_module():
 s=importlib.util.spec_from_file_location('_gui_provision_environment',HERE/'environment.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def native_module(inputs):
 paths=sys.path[:];saved=sys.modules.get('package_checks')
 try:
  sys.path.insert(0,str(inputs/'scripts/checks'));sys.modules.pop('package_checks',None);s=importlib.util.spec_from_file_location('_gui_provision_native',inputs/'runner/native_arm.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
 finally:
  sys.path[:]=paths
  if saved is not None:sys.modules['package_checks']=saved
  else:sys.modules.pop('package_checks',None)
def load_plan(path,digest):
 raw=read(path);need(pin(raw)==PLAN_PIN and digest==PLAN_PIN['sha256'],'exact Root-reviewed no-key provisioning plan');p=obj(raw);need(p['purpose']==PURPOSE and p['input_mode']=='SOURCE_BUILT_SAME_JOB_NO_KEY'and p['source_lock']==dict(path='scripts/ci/inputs.lock.json',**LOCK_PIN),'closed source-built plan and lock');return p,raw
def inventory(lock):
 out={}
 for row in lock['rootfs_packages']:
  need(len(row['name'])==len(row['version'])==1 and row['name'][0]not in out,'complete unique base package inventory');out[row['name'][0]]=row['version'][0]
 return out
def validate_lock(plan,raw):
 need(pin(raw)==LOCK_PIN,'exact reviewed native ARM input lock');lock=obj(raw);need(plan['rootfs']==lock['rootfs']and plan['keyring_files']==lock['keyring_files']and plan['signer_fingerprint']==lock['signer_fingerprint']and plan['packages']==[r for r in lock['packages']if r['name']in('mpdecimal','python')],'only original locked rootfs/Python/mpdecimal/keyring rows');need(inventory(lock)==plan['base_inventory']and len(plan['base_inventory'])==165,'complete original165 inventory');q=''.join(n+' '+v+'\n'for n,v in sorted(plan['base_inventory'].items())).encode();need(pin(q)['sha256']==plan['base_inventory_sha256'],'typed unchanged pacman-Q inventory hash');providers={}
 for row in lock['rootfs_packages']:
  for name in row['name']+row['provides']:providers[re.split('[<>=]',name)[0]]=row['name'][0]
 for row in plan['packages']:
  for name in[row['name'],*row['provides']]:providers[re.split('[<>=]',name)[0]]=row['name']
 proof={}
 for row in plan['packages']:
  for dependency in row['depends']:need(re.fullmatch('[a-z0-9+_.-]+',dependency)and dependency in providers,'every exact tool dependency has a base/overlay provider');proof[dependency]=providers[dependency]
 need(all(name not in plan['base_inventory']for name in('python','mpdecimal')),'tool overlay stays explicitly outside ALPM base165');return lock,proof
def items(plan):
 rows=list(plan['keyring_files'])
 for row in[plan['rootfs'],*plan['packages']]:rows.extend([row,dict(filename=row['filename']+'.sig',url=row['url']+'.sig',size=row['signature_size'],sha256=row['signature_sha256'])])
 need(len(rows)==9 and len({r['filename']for r in rows})==9,'exact nine public acquisition inputs');return rows
def check_inputs(inputs,plan):
 cache=inputs/'cache';expected={r['filename']:dict(bytes=r['size'],sha256=r['sha256'])for r in items(plan)};need({p.name for p in cache.iterdir()}==set(expected),'complete exact acquired input namespace')
 for name,w in expected.items():need(filepin(cache/name)==w,'exact reviewed acquired public bytes')
 return expected
def tar_name(name):
 name=name.removeprefix('./').rstrip('/');need(name and not name.startswith('/')and '\\'not in name and all(x not in('','.','..')for x in name.split('/'))and all(ord(c)>=32 and ord(c)!=127 for c in name),'safe archive payload path');return name
def overlay(cache,plan,destination):
 nodes={};skipped={};logical=0;count=0
 for row in plan['packages']:
  metadata={};skipped[row['name']]=[]
  with tarfile.open(cache/row['filename'],'r|xz')as archive:
   for member in archive:
    count+=1;need(count<=plan['bounds']['package_members']and 0<=member.size<=plan['bounds']['member_bytes'],'bounded tool archive members');name=tar_name(member.name);need(not member.pax_headers or set(member.pax_headers)<={'path','linkpath'},'no foreign payload metadata');need(member.isfile()or member.isdir()or member.issym()or member.islnk(),'only ordinary package payload nodes');need(member.uid==member.gid==0 and not member.mode&0o7000,'root-owned nonprivileged payload modes')
    if name in('.PKGINFO','.BUILDINFO','.MTREE','.INSTALL'):
     need(member.isfile(),'ordinary excluded package metadata');raw=archive.extractfile(member).read(member.size+1);need(len(raw)==member.size,'whole excluded metadata');skipped[row['name']].append(name)
     if name=='.PKGINFO':
      for line in raw.decode().splitlines():
       if line and not line.startswith('#'):
        k,v=line.split(' = ',1);metadata.setdefault(k,[]).append(v)
     continue
    need(name=='usr'or name.startswith('usr/'),'tool overlay cannot modify package DB, configuration or key homes');entry=dict(type='directory'if member.isdir()else'file'if member.isfile()else'symlink'if member.issym()else'hardlink',mode=member.mode&0o777)
    if member.isfile():
     logical+=member.size;need(logical<=plan['bounds']['package_logical_bytes'],'bounded aggregate tool payload');raw=archive.extractfile(member).read(member.size+1);need(len(raw)==member.size,'whole bounded tool payload');entry['raw']=raw
    elif member.issym()or member.islnk():
     target=posixpath.normpath(posixpath.join(posixpath.dirname(name),member.linkname))if member.issym()else tar_name(member.linkname);need(not member.linkname.startswith('/')and(target=='usr'or target.startswith('usr/')),'closed relative payload links');entry['target']=member.linkname if member.issym()else target
    need(name not in nodes or nodes[name]==entry,'no conflicting payload overlay nodes');nodes[name]=entry
  for key,wanted in(('pkgname',[row['name']]),('pkgver',[row['version']]),('arch',['aarch64']),('depend',row['depends']),('provides',row['provides'])):need(metadata.get(key,[])==wanted,'exact locked package metadata '+key)
 for name,node in nodes.items():
  for parent in Path(name).parents:
   if parent.as_posix()in nodes:need(nodes[parent.as_posix()]['type']=='directory','no payload link ancestors')
  if node['type']=='hardlink':need(node['target']in nodes and nodes[node['target']]['type']=='file','closed hardlink to package regular file')
 need(not destination.exists(),'fresh tool overlay tar')
 with destination.open('xb')as f,tarfile.open(fileobj=f,mode='w',format=tarfile.PAX_FORMAT)as output:
  for name,node in sorted(nodes.items(),key=lambda pair:(pair[1]['type']=='hardlink',pair[0])):
   ti=tarfile.TarInfo(name);ti.mode=node['mode'];ti.uid=ti.gid=ti.mtime=0;ti.uname=ti.gname='';kind=node['type'];ti.type={'file':tarfile.REGTYPE,'directory':tarfile.DIRTYPE,'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE}[kind]
   if kind=='file':ti.size=len(node['raw']);output.addfile(ti,io.BytesIO(node['raw']))
   else:
    if'target'in node:ti.linkname=node['target']
    output.addfile(ti)
 return dict(status='UNREGISTERED_TOOL_OVERLAY',packages=[r['name']for r in plan['packages']],members=len(nodes),logical_bytes=logical,excluded_metadata=skipped,pin=filepin(destination),package_install=False,hooks=False,scriptlets=False,TEST_key_generation=False)

PRIVATE_CHECK="from pathlib import Path; homes=[Path(p) for p in ('/etc/pacman.d/gnupg','/root/.gnupg','/home/alarm/.gnupg')]; assert all(not (h/'private-keys-v1.d').exists() or ((h/'private-keys-v1.d').is_dir() and not any((h/'private-keys-v1.d').iterdir())) for h in homes); assert all(not (h/'secring.gpg').exists() or (h/'secring.gpg').stat().st_size==0 for h in homes)"
def dockerfile(uid,gid):
 need(type(uid)is int and type(gid)is int and 0<uid<2**31 and 0<gid<2**31,'exact non-root alarm UID/GID')
 return('FROM scratch\nADD rootfs.tar.gz /\nADD tool-overlay.tar /\nRUN '+json.dumps(['/usr/bin/python3','-I','-B','-c',PRIVATE_CHECK])+'\nRUN '+json.dumps(['/usr/bin/groupmod','--gid',str(gid),'alarm'])+'\nRUN '+json.dumps(['/usr/bin/usermod','--uid',str(uid),'--gid',str(gid),'alarm'])+'\nENV PATH=/usr/bin:/bin LANG=C.UTF-8 HOME=/home/alarm\nUSER alarm\n').encode()

PROBE=r'''
import hashlib,importlib,json,os,platform,stat,sys
from pathlib import Path
c=json.loads(sys.argv[1]);root=Path('/inputs');p=json.loads((root/'plan.json').read_bytes())
def need(ok,why):
 if not ok:raise ValueError(why)
def sha(path):
 with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
need(not any(os.environ.get(n)for n in('LD_PRELOAD','LD_LIBRARY_PATH','FAKETIME','FAKETIME_TIMESTAMP_FILE','GPG_AGENT_INFO','GNUPGHOME','PYTHONHOME','PYTHONPATH')),'no clock, key-home or loader override')
for name,w in c['source_files'].items():
 f=root/name;s=f.lstat();need(not f.is_symlink()and stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==w['bytes']and sha(f)==w['sha256'],'exact probe source file')
for row in c['inputs']:
 f=root/'cache'/row['filename'];s=f.lstat();need(not f.is_symlink()and stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==row['size']and sha(f)==row['sha256'],'exact public authentication input')
sys.path.insert(0,str(root/'runner'));import sign_fixture as C
r=dict(status='FAIL',TEST_key_generation=False,host_GPG=False,public_only_home_retired=False,signatures={},tools={},imports={},guard=None,error_type=None)
try:
 observed=C.environment();C.signer_guard(observed,c['baseline']);r['guard']=observed
 need(platform.python_version()=='3.14.8','exact unregistered Python overlay version')
 for name in p['qualification']['imports']:
  m=importlib.import_module(name);r['imports'][name]=dict(status='PASS_IMPORT',module=name)
 need(sys.modules['_decimal'].__libmpdec_version__=='4.0.1','exact mpdecimal overlay dependency')
 for name in p['qualification']['tools']:
  f=Path(name).resolve(strict=True);s=f.stat();need(f.is_relative_to('/usr')and stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022 and os.access(f,os.X_OK),'ordinary immutable executable');r['tools'][name]=dict(bytes=s.st_size,sha256=sha(f),resolved=str(f))
 text=C.checked(['/usr/bin/pacman','-Q'],'unchanged base165 package query',30);lines=text.splitlines();need(len(lines)==165 and len({x.split(' ')[0]for x in lines})==165,'complete unchanged base165');raw=('\n'.join(sorted(lines))+'\n').encode();digest=hashlib.sha256(raw).hexdigest();need(digest==p['base_inventory_sha256'],'unchanged full ALPM inventory');r.update(packages_sha256=digest,packages_count=165,python=platform.python_version(),mpdecimal=sys.modules['_decimal'].__libmpdec_version__)
 for home in('/home/alarm/.gnupg',):
  f=Path(home)/'private-keys-v1.d';need(not f.exists()or(f.is_dir()and not any(f.iterdir())),'no preexisting private key files')
 inner=None
 with C.gpg_home('gui-provision-public-auth-','/tmp')as home:
  try:
   g=['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve'];C.checked(g+['--import',str(root/'cache/archlinuxarm.gpg')],'pinned public upstream keyring import');secret=C.checked(g+['--with-colons','--list-secret-keys'],'public-only upstream keyring inspection');need(not any(x.startswith(('sec:','ssb:'))for x in secret.splitlines()),'no imported secret keys');need((root/'cache/archlinuxarm-revoked').read_bytes()==b'','reviewed revoked-root list empty');listing=C.checked(g+['--with-colons','--list-keys'],'current upstream primary inspection');current=None;found=False
   for line in listing.splitlines():
    fields=line.split(':')
    if fields[0]=='pub':current=fields
    elif fields[0]=='fpr'and current is not None:
     if fields[9]==p['signer_fingerprint']:
      need(current[1]not in('e','r')and(not current[6]or int(current[6])==0 or int(current[6])>__import__('time').time()),'upstream root currently valid');found=True
     current=None
   need(found,'exact upstream root full fingerprint')
   for row in[p['rootfs'],*p['packages']]:
    status=C.checked(g+['--status-fd','1','--verify',str(root/'cache'/(row['filename']+'.sig')),str(root/'cache'/row['filename'])],'current upstream detached signature',600);C.native.valid_signature(status,p['signer_fingerprint']);need(not any('[GNUPG:] '+x in status for x in('KEYEXPIRED','KEYREVOKED','SIGEXPIRED','FAILURE','ERROR','NODATA','BADARMOR','EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY')),'all current upstream signature statuses');r['signatures'][row['filename']]=dict(exit_code=0,status=status,input_sha256=row['sha256'],signature_sha256=row['signature_sha256'])
  except BaseException as error:inner=error
 r['public_only_home_retired']=True
 if inner is not None:raise inner
 r['status']='PASS_NO_KEY_NATIVE_TOOLS_AND_PUBLIC_INPUT_AUTHENTICATION'
except BaseException as error:r['error_type']=type(error).__name__
print(json.dumps(r,sort_keys=True,separators=(',',':')))
sys.exit(0 if r['status'].startswith('PASS_')else 1)
'''

def qualification_nonce(record):return hashlib.sha256(('qualification:'+record['nonce']).encode()).hexdigest()[:32]
def labels(record):return{LABEL+'nonce':record['nonce'],LABEL+'source':record['source_sha'],LABEL+'plan':record['plan_pin']['sha256'],LABEL+'context':record['context_sha256']}
def before_images(E):
 _,raw=E.command(['docker','image','ls','--no-trunc','--format','{{.ID}} {{.Repository}}:{{.Tag}}'],10);rows=[]
 for line in raw.decode('ascii').splitlines():
  pair=line.split();need(len(pair)==2 and re.fullmatch('sha256:[0-9a-f]{64}',pair[0]),'complete pre-build image inventory');rows.append(pair)
 return rows
def inspect_owned(E,record,allow_absent=False):
 current=before_images(E);ids={r[0]for r in current};identifier=record.get('image_id')
 if identifier not in ids:
  need(allow_absent,'produced immutable image is present');return None
 _,raw=E.command(['docker','image','inspect',identifier],10);rows=obj(raw);need(type(rows)is list and len(rows)==1,'one immutable produced image');row=rows[0];need(row['Id']==identifier and row['Architecture']=='arm64'and row['Os']=='linux'and row['Config']['User']=='alarm'and row.get('RepoDigests',[])in([],None)and row.get('RepoTags')==[record['tag']]and all(row['Config'].get('Labels',{}).get(k)==v for k,v in labels(record).items())and identifier not in{r[0]for r in record['before_images']},'actual new native image ID, original ownership, labels and context');return row
def context_rows(root):
 need({p.name for p in root.iterdir()}=={'Dockerfile','rootfs.tar.gz','tool-overlay.tar'},'exact offline build context');return{p.name:filepin(p)for p in sorted(root.iterdir())}
def probe_image(E,record,inputs,probe_contract):
 nonce=record['nonce'];image=record['image_id'];name='cachy-asahi-gui-signer-env-'+nonce;_,present=E.command(['docker','container','ls','-a','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}}']);need(not present.strip(),'fresh owned no-key probe container');argv=['docker','run','--rm','--cidfile',str(inputs.parent/'probe.cid'),'--name',name,'--pull=never','--platform=linux/arm64','--label','org.cachy-asahi.gui-signer-environment='+nonce,'--user',str(record['uid'])+':'+str(record['gid']),'--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--cgroupns=private','--pids-limit=128','--memory=512m','--cpus=2','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=128m,mode=0700,uid='+str(record['uid'])+',gid='+str(record['gid']),'--env','CACHY_ASAHI_TEST_SIGNER='+nonce,'--mount','type=bind,src='+str(inputs)+',dst=/inputs,readonly','--mount','type=bind,src='+str(inputs.parent/'probe-out')+',dst=/out','--entrypoint=/usr/bin/python3',image,'-I','-B','/inputs/runner/probe.py',enc(probe_contract).decode()]
 try:
  rc,raw=E.command(argv,900,required=False);value=obj(raw);need(rc==0 and value['status']=='PASS_NO_KEY_NATIVE_TOOLS_AND_PUBLIC_INPUT_AUTHENTICATION'and value['public_only_home_retired']is True and value['TEST_key_generation']is False and value['host_GPG']is False,'actual no-key current input authentication and cleanup');return value
 finally:
  with E.retirement():E.remove_container(name,nonce,image)

def snapshot_source(source,inputs,plan_raw,source_sha):
 source=ordinary(source);selected={};own=ordinary(Path(__file__));env=ordinary(HERE/'environment.py');need(own.is_relative_to(source)and env.is_relative_to(source),'producer/environment belong to actual selected source');names=set(BASE)|{'scripts/ci/inputs.lock.json',own.relative_to(source).as_posix(),env.relative_to(source).as_posix()}
 manifest_path=own.parent/'source-manifest.json';manifest_raw=read(manifest_path);manifest=obj(manifest_raw);need(manifest['schema_version']==1 and all(manifest[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance'))and type(manifest['files'])is dict and names<=set(manifest['files'])and len(manifest['files'])<=1024,'complete current Root source manifest before any acquisition')
 for name,w in manifest['files'].items():need(filepin(source/name,4*1024**2)==w,'every selected signer/workflow source manifest pin')
 names=set(manifest['files']);slice_name=own.parent.relative_to(source).as_posix();physical={p.relative_to(own.parent).as_posix()for p in own.parent.rglob('*')if p.is_file()};need(not any(p.is_symlink()or not(p.is_dir()or p.is_file())for p in own.parent.rglob('*'))and physical=={n[len(slice_name)+1:]for n in names if n.startswith(slice_name+'/')}|{'source-manifest.json'},'whole maintained route namespace without source omissions')
 for name in names:selected[name]=filepin(source/name,4*1024**2)
 need(all(selected[n]==w for n,w in BASE.items())and selected['scripts/ci/inputs.lock.json']==LOCK_PIN,'unchanged native acquisition/inventory/guard sources and Root lock');mapping={'scripts/ci/sign_fixture.py':'runner/sign_fixture.py','scripts/ci/native_arm.py':'runner/native_arm.py','scripts/checks/package_checks.py':'scripts/checks/package_checks.py','scripts/ci/inputs.lock.json':'native-inputs.lock.json'}
 for old,new in mapping.items():
  path=inputs/new;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(read(source/old));path.chmod(0o644);need(filepin(path)==selected[old],'whole selected source snapshot')
 for name,raw in(('plan.json',plan_raw),('runner/probe.py',PROBE.encode())):path=inputs/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644)
 return dict(source_sha=source_sha,source_root=str(source),files=selected,manifest_path=manifest_path.relative_to(source).as_posix(),manifest_pin=pin(manifest_raw),producer_path=own.relative_to(source).as_posix(),environment_path=env.relative_to(source).as_posix(),bootstrap_trust='ROOT_REVIEWED_FILE_BYTES_BEFORE_SOURCE_IMAGE_EXECUTION_PUBLIC_SIGNATURES_VERIFIED_INSIDE_NEW_IMAGE_AFTER_BUILD',TEST_key_generation=False,Root_acceptance=None)
def source_join(record):
 source=ordinary(record['source_root']);need(all(filepin(source/n,4*1024**2)==w for n,w in record['files'].items())and filepin(source/record['manifest_path'])==record['manifest_pin']and obj(read(source/record['manifest_path']))['files']==record['files'],'late complete selected source/manifest identity');need(record['files'][record['producer_path']]==filepin(Path(__file__))and record['files'][record['environment_path']]==filepin(HERE/'environment.py'),'same current producer/environment implementation')
def scan_rootfs(path,plan):
 count=logical=0
 with tarfile.open(path,'r|gz')as archive:
  for member in archive:
   count+=1;logical+=member.size if member.isfile()else 0;need(count<=plan['bounds']['rootfs_members']and logical<=plan['bounds']['rootfs_logical_bytes']and 0<=member.size<=plan['bounds']['member_bytes'],'bounded original rootfs tar scan')
 return dict(members=count,logical_bytes=logical,host_extraction=False)
def baseline(record):return dict(schema_version=1,purpose='TEST-ONLY-integration-signatures',nonce=record['nonce'],image_id=record['image_id'],manifest_sha256=PLAN_PIN['sha256'],entry_sha256=BASE['scripts/ci/sign_fixture.py']['sha256'],helpers_sha256={'runner/native_arm.py':BASE['scripts/ci/native_arm.py']['sha256'],'scripts/checks/package_checks.py':BASE['scripts/checks/package_checks.py']['sha256']})
def check_probe(value,plan,native):
 need(value['status']=='PASS_NO_KEY_NATIVE_TOOLS_AND_PUBLIC_INPUT_AUTHENTICATION'and value['public_only_home_retired']is True and value['TEST_key_generation']is False and value['host_GPG']is False and value['packages_count']==165 and value['packages_sha256']==plan['base_inventory_sha256']and value['python']=='3.14.8'and value['mpdecimal']=='4.0.1'and set(value['tools'])==set(plan['qualification']['tools'])and set(value['imports'])==set(plan['qualification']['imports']),'complete actual no-key dependency qualification');need(set(value['signatures'])=={r['filename']for r in[plan['rootfs'],*plan['packages']]},'all three original input signatures')
 for row in[plan['rootfs'],*plan['packages']]:
  result=value['signatures'][row['filename']];need(type(result['exit_code'])is int and result['exit_code']==0 and result['input_sha256']==row['sha256']and result['signature_sha256']==row['signature_sha256'],'exact original input/signature joins');native.valid_signature(result['status'],plan['signer_fingerprint']);need(not any('[GNUPG:] '+bad in result['status']for bad in('KEYEXPIRED','KEYREVOKED','SIGEXPIRED','FAILURE','ERROR','NODATA','BADARMOR','EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY')),'all current upstream status checks')
 for item in value['tools'].values():need(set(item)=={'bytes','sha256','resolved'}and type(item['bytes'])is int and 0<item['bytes']<=128*1024**2 and re.fullmatch('[0-9a-f]{64}',item['sha256'])and item['resolved'].startswith('/usr/'),'exact observed executable pins')

def build_image(out,inputs,plan,lock,providers,record,E,native):
 record['before_images']=before_images(E);record['tag']='cachy-asahi-gui-test-signer:'+record['nonce'];need(record['tag']not in{r[1]for r in record['before_images']},'new owned source-built image tag');save(out/'production.json',record);native.acquire(items(plan),inputs/'cache',out);record['inputs']=check_inputs(inputs,plan);actual=native.rootfs_inventory(inputs/'cache'/plan['rootfs']['filename']);need(actual==lock['rootfs_packages'],'unchanged native full original rootfs inventory');save(out/'rootfs-inventory.json',dict(packages=actual,base_packages=165,dependencies=providers,tar_scan=scan_rootfs(inputs/'cache'/plan['rootfs']['filename'],plan)))
 context=out/'context';context.mkdir(mode=0o700);shutil.copyfile(inputs/'cache'/plan['rootfs']['filename'],context/'rootfs.tar.gz');need(filepin(context/'rootfs.tar.gz')==dict(bytes=plan['rootfs']['size'],sha256=plan['rootfs']['sha256']),'exact rootfs context bytes');save(out/'overlay.json',overlay(inputs/'cache',plan,context/'tool-overlay.tar'));(context/'Dockerfile').write_bytes(dockerfile(record['uid'],record['gid']));rows=context_rows(context);record['context_sha256']=pin(enc(rows))['sha256'];save(out/'build-context.json',dict(files=rows,sha256=record['context_sha256'],labels=labels(record),offline=True,package_install=False,TEST_key_generation=False));source_join(record['source_provenance']);check_inputs(inputs,plan);save(out/'production.json',record)
 argv=['docker','build','--network=none','--pull=false','--platform=linux/arm64','--iidfile',str(out/'image.iid'),'--tag',record['tag']]
 for k,v in labels(record).items():argv+=['--label',k+'='+v]
 buildx=out/'buildx-state';need(not os.path.lexists(buildx),'fresh absent private Buildx state before build');buildx.mkdir(mode=0o700);info=buildx.lstat();need(ordinary(buildx)==buildx and stat.S_ISDIR(info.st_mode)and info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o700 and not any(buildx.iterdir()),'fresh owned empty mode0700 Buildx state')
 E.command(argv+[str(context)],600,buildx_config=buildx);identifier=read(out/'image.iid',128).decode('ascii').strip();need(re.fullmatch('sha256:[0-9a-f]{64}',identifier),'actual Docker iidfile immutable image ID');record['image_id']=identifier;save(out/'production.json',record);inspect_owned(E,record);source_files={p.relative_to(inputs).as_posix():filepin(p,4*1024**2)for p in inputs.rglob('*')if p.is_file()and not p.is_relative_to(inputs/'cache')};probe_contract=dict(baseline=baseline(record),source_files=source_files,inputs=items(plan));save(inputs/'probe-contract.json',probe_contract);value=probe_image(E,record,inputs,probe_contract);check_probe(value,plan,native);save(out/'input-authentication.json',value);return value,rows

def produce(args):
 source=ordinary(args.source);plan,plan_raw=load_plan(args.plan,args.plan_sha256);source_sha=os.environ.get('SOURCE_SHA');need(re.fullmatch('[0-9a-f]{40}',source_sha or'')and os.environ.get('WORKFLOW_SHA')==source_sha,'actual workflow/selected source identity');out=ordinary(args.output);need(not os.path.lexists(out)and out.parent.is_dir()and not out.is_relative_to(source)and not source.is_relative_to(out),'fresh disjoint private no-key environment');out.mkdir(mode=0o700);inputs=out/'inputs';inputs.mkdir(mode=0o700);(inputs/'cache').mkdir(mode=0o700);(out/'probe-out').mkdir(mode=0o700);record=dict(schema_version=1,purpose=PURPOSE,status='FAIL',source_sha=source_sha,plan_pin=PLAN_PIN,nonce=os.urandom(16).hex(),uid=os.getuid(),gid=os.getgid(),image_id=None,tag=None,before_images=None,context_sha256=None,source_provenance=None,inputs=None,contract_pin=None,TEST_key_generation=False,production_credentials_used=False,native_build='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',Root_acceptance=None,error_type=None);save(out/'production.json',record)
 try:
  (out/'provision-plan.json').write_bytes(plan_raw);record['source_provenance']=snapshot_source(source,inputs,plan_raw,source_sha);save(out/'source-provenance.json',record['source_provenance']);lock,providers=validate_lock(plan,read(inputs/'native-inputs.lock.json'));native=native_module(inputs);E=environment_module()
  with E.cancellation(),E.docker_config(out):
   E.host(dict(alarm_uid=record['uid'],alarm_gid=record['gid']));value,rows=build_image(out,inputs,plan,lock,providers,record,E,native);identifier=record['image_id'];contract=dict(schema_version=1,purpose=E.CONTRACT_PURPOSE,source_sha=source_sha,oci_ref=None,image_id=identifier,alarm_uid=record['uid'],alarm_gid=record['gid'],packages_sha256=plan['base_inventory_sha256'],tools={n:{k:w[k]for k in('bytes','sha256')}for n,w in value['tools'].items()});save(out/'contract.json',contract);record['contract_pin']=filepin(out/'contract.json');qualification=E.qualify(contract,qualification_nonce(record));need(qualification['packages_count']==165 and qualification['packages_sha256']==contract['packages_sha256']and{n:{k:w[k]for k in('bytes','sha256')}for n,w in qualification['tools'].items()}==contract['tools'],'independent second native qualification of observed tool pins');save(out/'qualification.json',qualification);need(context_rows(out/'context')==rows and check_inputs(inputs,plan)==record['inputs'],'late context and acquired input joins');source_join(record['source_provenance']);inspect_owned(E,record);record['status']='PASS_SOURCE_BUILT_SAME_JOB_NO_KEY';save(out/'production.json',record)
   save(out/'environment.json',dict(schema_version=1,purpose=E.PURPOSE,status='PASS',source_sha=source_sha,contract_sha256=record['contract_pin']['sha256'],image_id=identifier,oci_ref=None,uid=record['uid'],gid=record['gid'],preexisting_image=False,acquired_image=False,built_image=True,nonce=record['nonce'],image_observation=dict(id=identifier,architecture='arm64',os='linux',repo_digests=[],repo_tags=[record['tag']]),qualification=qualification,container_cleanup=dict(status='PASS',container_absent=True),production_pin=filepin(out/'production.json'),error=None))
  return contract
 except BaseException as error:record['error_type']=type(error).__name__;save(out/'production.json',record);raise

def owned_output(path):
 out=ordinary(path);s=out.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700,'owned private provisioning output');return out
def core_module(inputs):
 previous=sys.path[:];saved={n:sys.modules.get(n)for n in('native_arm','package_checks')}
 try:
  for n in saved:sys.modules.pop(n,None)
  sys.path[:0]=[str(inputs/'runner'),str(inputs/'scripts/checks')];s=importlib.util.spec_from_file_location('_gui_provision_core',inputs/'runner/sign_fixture.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
 finally:
  sys.path[:]=previous
  for n,v in saved.items():
   if v is None:sys.modules.pop(n,None)
   else:sys.modules[n]=v
def production_record(out,source_sha=None):
 record=obj(read(out/'production.json'));fields={'schema_version','purpose','status','source_sha','plan_pin','nonce','uid','gid','image_id','tag','before_images','context_sha256','source_provenance','inputs','contract_pin','TEST_key_generation','production_credentials_used','native_build','GUI','hardware','Root_acceptance','error_type'}
 need(type(record)is dict and set(record)==fields and record['schema_version']==1 and record['purpose']==PURPOSE and record['plan_pin']==PLAN_PIN and re.fullmatch('[0-9a-f]{40}',record['source_sha']or'')and(source_sha is None or record['source_sha']==source_sha)and re.fullmatch('[0-9a-f]{32}',record['nonce']or'')and(record['uid'],record['gid'])==(os.getuid(),os.getgid())and record['TEST_key_generation']is False and record['production_credentials_used']is False and all(record[n]=='NOT_RUN'for n in('native_build','GUI','hardware'))and record['Root_acceptance']is None,'strict Root-plan/source/owner no-key production receipt');return record
def validate_artifacts(out,record):
 plan,raw=load_plan(out/'provision-plan.json',PLAN_PIN['sha256']);inputs=out/'inputs';source=obj(read(out/'source-provenance.json'));need(source==record['source_provenance']and source['source_sha']==record['source_sha'],'exact selected source provenance');source_join(source)
 for old,new in(('scripts/ci/sign_fixture.py','runner/sign_fixture.py'),('scripts/ci/native_arm.py','runner/native_arm.py'),('scripts/checks/package_checks.py','scripts/checks/package_checks.py')):need(filepin(inputs/new)==BASE[old]and source['files'][old]==BASE[old],'exact immutable baseline snapshot')
 lock,providers=validate_lock(plan,read(inputs/'native-inputs.lock.json'));need(read(inputs/'plan.json')==raw and read(inputs/'runner/probe.py')==PROBE.encode(),'exact source-owned probe and plan');need(check_inputs(inputs,plan)==record['inputs'],'all acquired public files exact');native=native_module(inputs);need(native.rootfs_inventory(inputs/'cache'/plan['rootfs']['filename'])==lock['rootfs_packages'],'entire unchanged rootfs inventory on read-only recheck');context=obj(read(out/'build-context.json'));need(context_rows(out/'context')==context['files']and pin(enc(context['files']))['sha256']==context['sha256']==record['context_sha256']and context['labels']==labels(record)and read(out/'context/Dockerfile')==dockerfile(record['uid'],record['gid']),'entire offline build context and source-owned Dockerfile')
 need(context['files']['rootfs.tar.gz']==dict(bytes=plan['rootfs']['size'],sha256=plan['rootfs']['sha256']),'original locked rootfs build context')
 with tempfile.TemporaryDirectory(prefix='recheck-overlay-',dir=out)as td:
  expected=overlay(inputs/'cache',plan,Path(td)/'tool-overlay.tar');need(expected==obj(read(out/'overlay.json'))and expected['pin']==context['files']['tool-overlay.tar'],'independently reconstruct only two exact unregistered tool payloads')
 need(read(out/'image.iid',128).decode('ascii').strip()==record['image_id']and re.fullmatch('sha256:[0-9a-f]{64}',record['image_id']or''),'actual original Docker iidfile joins receipt');need(re.fullmatch('[0-9a-f]{64}',read(out/'probe.cid',128).decode('ascii').strip()),'actual original no-key probe container ID')
 pc=obj(read(inputs/'probe-contract.json'));expected_sources={p.relative_to(inputs).as_posix():filepin(p,4*1024**2)for p in inputs.rglob('*')if p.is_file()and not p.is_relative_to(inputs/'cache')and p.name!='probe-contract.json'};need(pc==dict(baseline=baseline(record),source_files=expected_sources,inputs=items(plan)),'entire original immutable probe contract/source/input join');value=obj(read(out/'input-authentication.json'));check_probe(value,plan,native);core=core_module(inputs);core.signer_guard(value['guard'],baseline(record));return plan,value

def validate_environment(envdir,source_sha):
 out=owned_output(envdir);record=production_record(out,source_sha);need(record['status']=='PASS_SOURCE_BUILT_SAME_JOB_NO_KEY'and record['error_type']is None and record['tag']=='cachy-asahi-gui-test-signer:'+record['nonce']and type(record['before_images'])is list and len(record['before_images'])<=4096,'completed owned source-built environment, never a caller-selected image')
 for row in record['before_images']:need(type(row)is list and len(row)==2 and re.fullmatch('sha256:[0-9a-f]{64}',row[0])and row[1]!=record['tag'],'exact pre-build inventory and originally absent tag')
 plan,value=validate_artifacts(out,record);contract=obj(read(out/'contract.json'));E=environment_module();expected=dict(schema_version=1,purpose=E.CONTRACT_PURPOSE,source_sha=source_sha,oci_ref=None,image_id=record['image_id'],alarm_uid=record['uid'],alarm_gid=record['gid'],packages_sha256=plan['base_inventory_sha256'],tools={n:{k:w[k]for k in('bytes','sha256')}for n,w in value['tools'].items()});need(contract==expected and filepin(out/'contract.json')==record['contract_pin'],'exact actual produced nine-field contract; NULL OCI only through production proof');qualification=obj(read(out/'qualification.json'));need(qualification['packages_count']==165 and qualification['packages_sha256']==contract['packages_sha256']and qualification['tools']==value['tools'],'independent qualification joins complete original inventory and actual observed tool pins');guard=qualification['guard'];need(guard==dict(arch='aarch64',uid=record['uid'],gid=record['gid'],user='alarm',capabilities={n:0 for n in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')},no_new_privs=1,root_read_only=True,tmpfs_private=True,interfaces=['lo'],local_docker_socket_exposed=False),'complete independently observed capability-free native qualification')
 env=obj(read(out/'environment.json'));need(env['status']=='PASS'and env['source_sha']==source_sha and env['production_pin']==filepin(out/'production.json')and env['contract_sha256']==record['contract_pin']['sha256']and env['qualification']==qualification and env['oci_ref']is None and env['image_id']==record['image_id']and env['preexisting_image']is False and env['built_image']is True and(env['uid'],env['gid'])==(record['uid'],record['gid']),'compatible environment receipt joins only actual source production')
 with E.docker_config(out):E.host(contract);inspect_owned(E,record);E.remove_container('cachy-asahi-gui-signer-env-'+record['nonce'],record['nonce'],record['image_id'])
 return contract

def cleanup(args):
 out=owned_output(args.output);record=production_record(out);E=environment_module();result=dict(schema_version=1,purpose=PURPOSE,status='FAIL',nonce=record['nonce'],source_sha=record['source_sha'],image_id=record['image_id'],contract_sha256=record['contract_pin']['sha256']if record['contract_pin']else None,removed_new_image=False,container_absent=None,error_type=None)
 try:
  with E.retirement(),E.docker_config(out):
   if record['context_sha256']is None or record['before_images']is None:result.update(status='PASS',container_absent=True)
   else:
    if record['image_id']is None:
     rows=before_images(E);found={row[0]for row in rows if row[1]==record['tag']};need(len(found)<=1,'one owned build tag')
     if found:record=dict(record,image_id=next(iter(found)))
    if record['image_id']is not None:
     
     for nonce in(record['nonce'],qualification_nonce(record)):E.remove_container('cachy-asahi-gui-signer-env-'+nonce,nonce,record['image_id'])
     result['container_absent']=True;image=inspect_owned(E,record,allow_absent=True)
     if image is not None:
      _,raw=E.command(['docker','container','ls','-a','--no-trunc','--filter','ancestor='+record['image_id'],'--format','{{.ID}}'],10);need(not raw.strip(),'no live or stopped image consumers before removal');E.command(['docker','image','rm','--no-prune',record['tag']],30);remaining=before_images(E);need(not any(row[1]==record['tag']for row in remaining),'owned source tag absent after removal');need(not any(row[0]==record['image_id']for row in remaining),'foreign image references preserved; source image retirement unfinished');result['removed_new_image']=True
    else:result['container_absent']=True
    result['status']='PASS';result['image_id']=record['image_id']
 except BaseException as error:result['error_type']=type(error).__name__;raise
 finally:save(out/'cleanup.json',result)
 return result

def export(args):
 root=owned_output(args.environment);production_record(root);out=ordinary(args.output);need(not os.path.lexists(out)and out.parent.is_dir()and not out.is_relative_to(root)and not root.is_relative_to(out),'fresh disjoint receipt-only public export');values={};total=0
 for name in PUBLIC:
  if(root/name).exists():
   raw=read(root/name);obj(raw);need(b'PRIVATE KEY'not in raw,'public-only provisioning JSON');total+=len(raw);need(total<=8*1024**2,'bounded aggregate receipt exports');values[name]=raw
 need('production.json'in values,'production failure/success evidence retained');out.mkdir(mode=0o700)
 for name,raw in values.items():(out/name).write_bytes(raw);(out/name).chmod(0o644)
 index=dict(schema_version=1,purpose='GUI_NO_KEY_PROVISION_PUBLIC_RECEIPTS',files={n:pin(b)for n,b in values.items()},archives_exported=False,image_exported=False,TEST_key_generation=False,Root_acceptance=None);(out/'index.json').write_bytes(enc(index));(out/'index.json').chmod(0o644);return index

def main():
 p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='action',required=True);q=s.add_parser('produce');q.add_argument('--source',type=Path,required=True);q.add_argument('--plan',type=Path,required=True);q.add_argument('--plan-sha256',required=True);q.add_argument('--output',type=Path,required=True);q=s.add_parser('cleanup');q.add_argument('--output',type=Path,required=True);q=s.add_parser('export');q.add_argument('--environment',type=Path,required=True);q.add_argument('--output',type=Path,required=True);a=p.parse_args();result=globals()[a.action](a);print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
