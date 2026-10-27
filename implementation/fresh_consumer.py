# SPDX-License-Identifier: MIT
"""Strict selected fresh TEST inputs; no signing or native/GUI acceptance."""
import base64,datetime,hashlib,json,os,re,stat,subprocess,tempfile,time
from pathlib import Path

HERE=Path(__file__).resolve().parent
PURPOSE='GUI607_FRESH_TEST_SIGNER_CONSUMER_V1'
SIGN_PURPOSE='GUI_FRESH_TEST_SIGNER_NATIVE_V1'
PASS='PASS_FRESH_TEST_SIGNATURES_ONLY_NO_GUI_OR_BUILD_ACCEPTANCE'
VERIFY='PASS_INDEPENDENT_PUBLIC_ONLY_TEST_SIGNATURE_VERIFICATION'
AUTHORITY='FRESH_TEST_SIGNATURES_ONLY_HISTORICAL_NATIVE_CREDIT_NEW_SOURCE_SELECTION_REQUIRED'
ARCHIVES4=('welcome5','dns2','doctor','orphans')
ROLES6=(*ARCHIVES4,'native73-index','held77-index')
ARCHIVES=set(ARCHIVES4)
ROLES=set(ROLES6)
BIND_FIELDS={'carrier_source','carrier_ref','packet_path','index_pin','production_path','production_index_pin','context_path','context_pin','signing_source','signing_ref','run','attempt','job','fingerprint','created','expires'}
POLICY_FIELDS={'schema_version','purpose','binding','actual_source','actual_ref','actual_run','Root_acceptance'}
CONTEXT_FIELDS={'schema_version','purpose','status','source','workflow_source','ref','run','attempt','job','mode','same_job','packet_index_pin','production_index_pin','qualification_pin','source_provenance_pin'}
PUBLIC_NAMES={'public-key.asc','catalog.json','catalog.json.sig','result.json','provenance.json','index.json'}|{'signatures/'+r+'.sig'for r in ROLES6}
PRODUCTION_NAMES={'production.json','environment.json','contract.json','acquisition.json','input-authentication.json','qualification.json','build-context.json','rootfs-inventory.json','overlay.json','source-provenance.json','cleanup.json','provision-plan.json','index.json'}
BAD={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','KEYREVOKED','SIGEXPIRED','FAILURE','ERROR','NODATA','BADARMOR'}
CAPS={'CapEff','CapPrm','CapBnd','CapInh','CapAmb'}
TOOLS={'/usr/bin/python3','/usr/bin/gpg','/usr/bin/gpgconf','/usr/bin/gpg-agent','/usr/bin/pacman'}
LIMIT=4*1024**2

def need(ok,why):
 if not ok:raise ValueError(why)
def exact(value,fields,why):
 need(type(value)is dict and set(value)==set(fields),why);return value
def integer(value,minimum=0):return type(value)is int and minimum<=value<2**63
def matches(value,pattern):return type(value)is str and re.fullmatch(pattern,value)is not None
def enc(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def obj(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON field');out[k]=v
  return out
 value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON required'))
 need(type(value)is dict,'JSON object required');return value

def canonical(value):
 raw=os.fspath(value);need(type(raw)is str and os.path.isabs(raw)and not raw.startswith('//')and raw==os.path.normpath(raw),'absolute canonical path required')
 path=Path(raw);need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary nonalias path required');return path

def relative(name):
 need(type(name)is str and 0<len(name)<=512 and not name.startswith('/')and '\\'not in name and all(32<=ord(c)<127 for c in name)and all(p not in('','.','..')for p in name.split('/')),'ordinary contained member required');return name

def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,cap=LIMIT):
 path=canonical(path);need(integer(cap)and cap<=2**31,'bounded read cap required');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded ordinary single-link input required');raw=bytearray()
  while part:=os.read(fd,min(65536,before.st_size+1-len(raw))):raw.extend(part);need(len(raw)<=before.st_size,'input grew during observation')
  need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable input FD/path required');return bytes(raw)
 finally:os.close(fd)

def expected_pin(value,cap=LIMIT):
 exact(value,{'bytes','sha256'},'exact input pin required');need(integer(value['bytes'])and value['bytes']<=cap and matches(value['sha256'],'[a-f0-9]{64}'),'typed bounded input pin required');return value

def checked(root,name,wanted,cap=LIMIT):
 raw=read(canonical(root)/relative(name),cap);need(pin(raw)==expected_pin(wanted,cap),'whole exact member pin differs: '+name);return raw

def closed(root,files,*,git=False,mode=None):
 root=canonical(root);need(root.is_dir()and type(files)is dict and 0<len(files)<=2048,'bounded closed input root required');wanted_dirs=set()
 for name,w in files.items():
  relative(name);expected_pin(w,64*1024**2);wanted_dirs.update(p.as_posix()for p in Path(name).parents if p!=Path('.'))
 found={};dirs=set()
 for directory,children,names in os.walk(root,followlinks=False):
  if Path(directory)==root and git:children[:]=[n for n in children if n!='.git'];names=[n for n in names if n!='.git']
  for name in children:
   p=Path(directory)/name;need(not p.is_symlink()and p.is_dir(),'ordinary input directory required');dirs.add(p.relative_to(root).as_posix())
  for name in names:
   p=Path(directory)/name;n=p.relative_to(root).as_posix();need(n in files,'foreign input member');need(mode is None or stat.S_IMODE(p.lstat().st_mode)==mode,'exact public file mode required');found[n]=pin(checked(root,n,files[n],64*1024**2))
 need(set(found)==set(files)and dirs==wanted_dirs,'complete file/directory closure required');return found

def current(created,expires):
 need(integer(created,1)and integer(expires,1)and expires-created==86400,'strict one-day TEST validity required')
 now=time.time();need(created<=now<expires,'fresh TEST signer is not currently valid')

def validate_policy(p,required=True):
 need(type(required)is bool,'literal selection requirement');exact(p,POLICY_FIELDS,'exact fresh signer consumer policy required')
 need(type(p['schema_version'])is int and p['schema_version']==1 and p['purpose']==PURPOSE and all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'source-only consumer policy authority')
 b=exact(p['binding'],BIND_FIELDS,'exact fresh signer binding fields required');missing=[k for k,v in b.items()if v is None]
 if missing:
  need(len(missing)==len(BIND_FIELDS),'partial fresh signer binding refused');need(not required,'fresh TEST signer selection remains NULL');return p
 for k in('carrier_source','signing_source'):need(matches(b[k],'[a-f0-9]{40}'),'full selected source identity required')
 for k in('carrier_ref','signing_ref'):need(matches(b[k],r'(?:refs/heads/)?codex/[a-z0-9][a-z0-9._/-]{0,199}')and '..'not in b[k],'explicit selected source ref required')
 if b['packet_path']=='.':
  need(b['production_path']=='@source/production'and b['context_path']=='@source/Root-qualification.json','published root requires exact source-bound evidence operands')
 else:
  for k in('packet_path','production_path','context_path'):relative(b[k]);need(not b[k].startswith('@source/')and Path(b[k]).parts[0]not in('_consumer_originals','_consumer_binding.json'),'external consumer reserved namespace refused')
  paths=[Path(b[k])for k in('packet_path','production_path','context_path')];need(all(not a.is_relative_to(z)and not z.is_relative_to(a)for i,a in enumerate(paths)for z in paths[i+1:]),'disjoint selected relative packet/production/context paths')
 for k in('index_pin','production_index_pin','context_pin'):expected_pin(b[k]);need(b[k]['bytes']>0,'nonempty selected index/context pin')
 need(integer(b['run'],1)and integer(b['attempt'],1)and type(b['job'])is str and 0<len(b['job'])<=256 and all(32<=ord(c)<127 for c in b['job']),'exact run/attempt/job binding required')
 need(matches(b['fingerprint'],'[A-F0-9]{40}')and integer(b['created'],1)and integer(b['expires'],1)and b['expires']-b['created']==86400,'new primary and structural one-day validity required')
 return p

def policy(required=True):return validate_policy(obj(read(HERE/'fresh-signer-policy.json')),required)
def contract():
 raw=read(HERE/'fresh-signer-contract.json');input_plan=obj(raw);schema=obj(read(HERE/'fresh-signer-schema.json'))
 need(pin(raw)==expected_pin(schema['input_plan_pin']),'exact reviewed GUI signing input plan');need(input_plan['schema_version']==1 and input_plan['purpose']=='GUI607_FRESH_TEST_SIGNING_INPUTS_SOURCE_ONLY'and input_plan['actual']is input_plan['Root_acceptance']is None,'source-only input plan')
 need(pin(enc(schema['provision_plan']))==expected_pin(schema['provision_plan_pin']),'exact reviewed provisioning plan')
 need(schema['upstream_signer_fingerprint']==schema['provision_plan']['signer_fingerprint']and schema['base_inventory_sha256']==schema['provision_plan']['base_inventory_sha256'],'reviewed upstream and complete base inventory pins')
 need(type(schema['retired_signers'])is list and schema['retired_signers']==[input_plan['historical_renewal']['recorded_signer']],'exact retired signer exclusion');return input_plan,schema

def status(text,fingerprint):
 need(matches(fingerprint,'[A-F0-9]{40}')and type(text)is str and 0<len(text.encode())<=LIMIT and '\0'not in text,'bounded typed GPG status required')
 rows=[]
 for line in text.splitlines():
  need(line.startswith('[GNUPG:] '),'only complete machine GPG status records');row=line.split()[1:];need(row,'nonempty GPG status');rows.append(row)
 need(not BAD&{r[0]for r in rows},'invalid, expired, revoked or unverified current signature')
 valid=[r for r in rows if r[0]=='VALIDSIG'];good=[r for r in rows if r[0]=='GOODSIG']
 need(len(valid)==len(good)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint,'one exact pinned-primary VALIDSIG and GOODSIG required')
 row=valid[0];need(row[5:10]==['4','0','1','8','00']and len(good[0])>=3 and good[0][1]in(fingerprint[-16:],fingerprint),'exact RSA/SHA256/version/class and GOODSIG primary required')
 need(matches(row[3],r'[0-9]{1,20}')and matches(row[4],r'[0-9]{1,20}')and 0<int(row[3])<=time.time()+1,'real signature creation time required')
 need(row[2]==time.strftime('%Y-%m-%d',time.gmtime(int(row[3]))),'GPG signature date/timestamp join')
 need(int(row[4])==0 or time.time()<int(row[4]),'signature has expired');return dict(fingerprint=fingerprint,created=int(row[3]),expires=int(row[4]))

def certificate(text,binding,nonce):
 need(type(text)is str and len(text.encode())<=65536 and '\0'not in text and matches(nonce,'[a-f0-9]{32}'),'bounded current certificate listing required')
 rows=[r.split(':')for r in text.splitlines()if r];pubs=[r for r in rows if r[0]=='pub'];uids=[r for r in rows if r[0]=='uid'];fps=[r for r in rows if r[0]=='fpr']
 need(len(pubs)==len(uids)==len(fps)==1 and not any(r[0]in('sec','ssb','sub')for r in rows),'one public primary and nonce identity required')
 p=pubs[0];need(len(p)>=10 and p[1]not in('e','r')and p[2:4]==['2048','1']and matches(p[5],r'[0-9]{1,20}')and matches(p[6],r'[0-9]{1,20}'),'current RSA2048 primary required')
 need(len(fps[0])>=10 and fps[0][9]==binding['fingerprint']and len(uids[0])>=10 and uids[0][9]=='CACHY-ASAHI TEST ONLY '+nonce+' <test-only@invalid.example>','exact selected primary and fresh nonce UID required')
 need((int(p[5]),int(p[6]))==(binding['created'],binding['expires']),'actual certificate creation/expiry differs from selection');current(int(p[5]),int(p[6]));return dict(fingerprint=binding['fingerprint'],created=int(p[5]),expires=int(p[6]))

STANDARD_MOUNTS={'/proc':('proc',{'rw','nosuid','nodev','noexec'}),'/dev':('tmpfs',{'rw','nosuid'}),'/dev/pts':('devpts',{'rw','nosuid','noexec'}),'/dev/mqueue':('mqueue',{'rw','nosuid','nodev','noexec'}),'/dev/shm':('tmpfs',{'rw','nosuid','nodev','noexec'}),'/sys':('sysfs',{'ro','nosuid','nodev','noexec'}),'/sys/fs/cgroup':('cgroup2',{'ro','nosuid','nodev','noexec'}),**{p:('proc',{'ro','nosuid','nodev','noexec'})for p in('/proc/bus','/proc/fs','/proc/irq','/proc/sys','/proc/sysrq-trigger')},**{p:('tmpfs',{'ro'})for p in('/proc/acpi','/proc/asound','/proc/scsi','/sys/firmware','/sys/devices/virtual/powercap')},**{p:('tmpfs',{'rw','nosuid'})for p in('/proc/interrupts','/proc/kcore','/proc/keys','/proc/latency_stats','/proc/timer_list','/proc/timer_stats','/proc/sched_debug')}}
MASKED_NULL={'/proc/interrupts','/proc/kcore','/proc/keys','/proc/latency_stats','/proc/timer_list','/proc/timer_stats','/proc/sched_debug'}
DEVICES={'/dev/null':(1,3),'/dev/zero':(1,5),'/dev/full':(1,7),'/dev/random':(1,8),'/dev/urandom':(1,9),'/dev/tty':(5,0),'/dev/pts/ptmx':(5,2)}
BIND_FS={'ext4','xfs','btrfs','tmpfs','overlay','fuse-overlayfs'}

def guard(g,baseline,uid):
 """Validate the complete baseline guard, not qualification's smaller schema."""
 exact(g,{'arch','uid','user','docker_marker','interfaces','docker_socket','caps','capabilities','no_new_privs','mounts','nonce','device_nodes','sockets'},'exact baseline signer guard')
 need(g['arch']=='aarch64'and integer(g['uid'],1)and g['uid']==uid and g['user']=='alarm'and g['docker_marker']is True and g['interfaces']==['lo']and g['docker_socket']is False and g['sockets']==[],'native isolated nonroot alarm signer required')
 exact(g['capabilities'],CAPS,'all five signer capability sets required');need(all(type(v)is int and v==0 for v in g['capabilities'].values())and type(g['caps'])is int and g['caps']==0 and type(g['no_new_privs'])is int and g['no_new_privs']==1,'capability-free NNP signer required')
 need(matches(g['nonce'],'[a-f0-9]{32}')and g['nonce']==baseline['nonce'],'actual guard/contract nonce join');table=g['mounts'];need(type(table)is dict and len(table)<=64,'bounded complete mount table')
 for path,row in table.items():
  need(type(path)is str and path.startswith('/'),'absolute observed mount');exact(row,{'fs','options','root'},'exact observed mount fields');flags=row['options']
  need(type(row['fs'])is str and type(flags)is list and all(type(f)is str for f in flags)and len(flags)==len(set(flags))and ('ro'in flags)!=('rw'in flags),'canonical observed mount flags')
  need(type(row['root'])is str and row['root'].startswith('/')and not any(c in row['root']for c in('\n','\0'))and not any(a in flags and b in flags for a,b in(('nosuid','suid'),('nodev','dev'),('noexec','exec'))),'ordinary mount root/security flags')
 need(table.get('/',{}).get('fs')in('overlay','fuse-overlayfs')and'ro'in table['/']['options']and table['/']['root']=='/','read-only disposable signer root')
 need(table.get('/inputs',{}).get('fs')in BIND_FS and'ro'in table['/inputs']['options']and table.get('/out',{}).get('fs')in BIND_FS and'rw'in table['/out']['options'],'read-only inputs and dedicated public output')
 need(table.get('/tmp',{}).get('fs')=='tmpfs'and table['/tmp']['root']=='/'and {'rw','nosuid','nodev'}<=set(table['/tmp']['options']),'private tmpfs signer key storage')
 for path,row in table.items():
  if path in('/','/inputs','/out','/tmp'):continue
  if path in('/etc/hosts','/etc/hostname','/etc/resolv.conf'):need(row['fs']in BIND_FS,'ordinary Docker metadata mount');continue
  need(path in STANDARD_MOUNTS,'foreign signer mount refused');fs,flags=STANDARD_MOUNTS[path];expected='/null'if path in MASKED_NULL else path.removeprefix('/proc')if fs=='proc'and path!='/proc'else'/'
  need(row['fs']==fs and flags<=set(row['options'])and row['root']==expected,'exact standard mount and subtree')
 need({'/proc','/dev','/dev/pts','/dev/shm','/dev/mqueue','/sys','/sys/fs/cgroup'}<=set(table),'complete standard Docker mount set')
 exact(g['device_nodes'],DEVICES,'complete exact observed device set')
 for path,(major,minor)in DEVICES.items():need(g['device_nodes'][path]==dict(kind='char',major=major,minor=minor)and type(g['device_nodes'][path]['major'])is type(g['device_nodes'][path]['minor'])is int,'exact standard device identity')

def report_scope(value):
 need(all(value[n]=='NOT_RUN'for n in('native_build','GUI','hardware'))and value['Root_acceptance']is None,'signing grants no build/GUI/hardware/Root acceptance')

def context(root_context,binding):
 c=exact(root_context,CONTEXT_FIELDS,'exact external Root signing context required')
 need(type(c['schema_version'])is int and c['schema_version']==1 and c['purpose']=='ROOT_SELECTED_ACTUAL_GUI_FRESH_TEST_SIGNING_CONTEXT'and c['status']=='ROOT_VALIDATED_ACTUAL_PUBLIC_TEST_SIGNING_PACKET','Root-selected genuine signing context required')
 need(c['mode']=='sign'and c['same_job']is True,'only same-job sign context; no-key qualification cannot select a signer')
 need(c['source']==c['workflow_source']==binding['signing_source']and c['ref']==binding['signing_ref']and c['run']==binding['run']and c['attempt']==binding['attempt']and c['job']==binding['job'],'exact Root source/workflow/ref/run/attempt/job join')
 need(integer(c['run'],1)and integer(c['attempt'],1)and type(c['job'])is str,'typed Root job/run/attempt identity')
 need(c['packet_index_pin']==binding['index_pin']and c['production_index_pin']==binding['production_index_pin'],'Root-bound signer and no-key packet index pins')
 for n in('packet_index_pin','production_index_pin','qualification_pin','source_provenance_pin'):expected_pin(c[n])
 return c

def sign_contract(c,binding,schema,image):
 exact(c,schema['contract_fields'],'exact signer contract fields');need(type(c['schema_version'])is int and c['schema_version']==1 and c['purpose']==SIGN_PURPOSE and c['source_sha']==binding['signing_source']and c['image_id']==image['image_id']and c['image_contract_sha256']==pin(enc(image))['sha256']and matches(c['nonce'],'[a-f0-9]{32}'),'source/image/nonce signer contract join')
 expected_pin(c['manifest_pin']);need(c['manifest_pin']==schema['input_plan_pin']and c['files']==schema['signing_files']and len(c['files'])==7,'complete original seven source and fixed GUI plan pins')
 files=c['files'];expected=dict(schema_version=1,purpose='TEST-ONLY-integration-signatures',nonce=c['nonce'],image_id=c['image_id'],manifest_sha256=c['manifest_pin']['sha256'],entry_sha256=files['runner/sign_fixture.py']['sha256'],helpers_sha256={n:files[n]['sha256']for n in('runner/native_arm.py','scripts/checks/package_checks.py')})
 need(c['baseline']==expected,'unchanged exact baseline contract/entry/helper pins');return c

def signature(saved,body_pin,fingerprint,*,catalog=False):
 key='body_pin'if catalog else'input_pin';exact(saved,{key,'signature_pin','status','gpg_exit'},'exact successful signature receipt')
 expected_pin(saved[key],8*1024**2);need(type(saved['gpg_exit'])is int and saved['gpg_exit']==0 and saved[key]==body_pin,'successful original/independent signature/body join');expected_pin(saved['signature_pin'],8192);status(saved['status'],fingerprint)

def _provision_receipts(d,prod,qual,image,pp,schema):
 auth=d['input-authentication.json'];exact(auth,{'status','TEST_key_generation','host_GPG','public_only_home_retired','signatures','tools','imports','guard','error_type','packages_sha256','packages_count','python','mpdecimal'},'complete no-key input authentication')
 need(auth['status']=='PASS_NO_KEY_NATIVE_TOOLS_AND_PUBLIC_INPUT_AUTHENTICATION'and auth['TEST_key_generation']is False and auth['host_GPG']is False and auth['public_only_home_retired']is True and auth['error_type']is None and type(auth['packages_count'])is int and auth['packages_count']==165 and auth['packages_sha256']==image['packages_sha256']and auth['python']=='3.14.8'and auth['mpdecimal']=='4.0.1'and auth['tools']==qual['tools'],'actual no-key imports/tools/current upstream signatures')
 need(type(auth['imports'])is dict and set(auth['imports'])==set(pp['qualification']['imports'])and all(v==dict(status='PASS_IMPORT',module=k)for k,v in auth['imports'].items()),'all exact source-selected dependency imports')
 files=schema['signing_files'];baseline=dict(schema_version=1,purpose='TEST-ONLY-integration-signatures',nonce=prod['nonce'],image_id=prod['image_id'],manifest_sha256=schema['provision_plan_pin']['sha256'],entry_sha256=files['runner/sign_fixture.py']['sha256'],helpers_sha256={n:files[n]['sha256']for n in('runner/native_arm.py','scripts/checks/package_checks.py')});guard(auth['guard'],baseline,prod['uid'])
 rows=[pp['rootfs'],*pp['packages']];need(type(auth['signatures'])is dict and set(auth['signatures'])=={r['filename']for r in rows},'all three original upstream signatures')
 for row in rows:
  r=exact(auth['signatures'][row['filename']],{'exit_code','status','input_sha256','signature_sha256'},'exact original upstream receipt')
  need(type(r['exit_code'])is int and r['exit_code']==0 and r['input_sha256']==row['sha256']and r['signature_sha256']==row['signature_sha256'],'exact original upstream input/signature pin');_upstream_status(r['status'],schema['upstream_signer_fingerprint'])
 inputs={r['filename']:dict(bytes=r['size'],sha256=r['sha256'])for r in pp['keyring_files']}
 for r in rows:inputs[r['filename']]=dict(bytes=r['size'],sha256=r['sha256']);inputs[r['filename']+'.sig']=dict(bytes=r['signature_size'],sha256=r['signature_sha256'])
 need(len(inputs)==9 and prod['inputs']==inputs,'all nine exact source acquisition operands');acq=exact(d['acquisition.json'],{'schema_version','acquisition','signature_authentication','inputs','counts'},'complete acquisition receipt')
 need(type(acq['schema_version'])is int and acq['schema_version']==1 and acq['acquisition']=='PASS'and acq['signature_authentication']=='NOT RUN'and acq['counts']==dict(total=9,**{'pass':9,'fail':0,'pending':0})and set(acq['inputs'])==set(inputs),'all transport operands acquired; separate current signature receipts required')
 need(all(type(v)is int for v in acq['counts'].values()),'strict integer acquisition counts')
 for n,w in inputs.items():need(acq['inputs'][n]==dict(status='PASS',expected_sha256=w['sha256'],expected_bytes=w['bytes']),'all exact acquired bytes passed')
 inventory=exact(d['rootfs-inventory.json'],{'packages','base_packages','dependencies','tar_scan'},'complete rootfs inventory receipt');base={}
 need(type(inventory['packages'])is list and len(inventory['packages'])==165 and type(inventory['base_packages'])is int and inventory['base_packages']==165,'full original base165 inventory')
 for r in inventory['packages']:
  need(type(r)is dict and type(r['name'])is list and type(r['version'])is list and len(r['name'])==len(r['version'])==1 and r['name'][0]not in base,'unique complete base package identity');base[r['name'][0]]=r['version'][0]
 need(base==pp['base_inventory']and pin(''.join(n+' '+v+'\n'for n,v in sorted(base.items())).encode())['sha256']==image['packages_sha256'],'complete unchanged installed base package inventory')
 providers={}
 for r in inventory['packages']:
  for name in r['name']+r['provides']:providers[re.split('[<>=]',name)[0]]=r['name'][0]
 for r in pp['packages']:
  for name in[r['name'],*r['provides']]:providers[re.split('[<>=]',name)[0]]=r['name']
 dependencies={}
 for r in pp['packages']:
  for name in r['depends']:need(matches(name,'[a-z0-9+_.-]+')and name in providers,'every exact tool dependency has a reviewed provider');dependencies[name]=providers[name]
 need(inventory['dependencies']==dependencies,'complete exact base/overlay dependency provider proof')
 scan=exact(inventory['tar_scan'],{'members','logical_bytes','host_extraction'},'bounded original rootfs scan');need(integer(scan['members'],1)and scan['members']<=pp['bounds']['rootfs_members']and integer(scan['logical_bytes'])and scan['logical_bytes']<=pp['bounds']['rootfs_logical_bytes']and scan['host_extraction']is False,'bounded rootfs bytes and no host extraction')
 overlay=exact(d['overlay.json'],{'status','packages','members','logical_bytes','excluded_metadata','pin','package_install','hooks','scriptlets','TEST_key_generation'},'exact two-tool overlay receipt')
 need(overlay['status']=='UNREGISTERED_TOOL_OVERLAY'and overlay['packages']==[r['name']for r in pp['packages']]and all(overlay[k]is False for k in('package_install','hooks','scriptlets','TEST_key_generation'))and integer(overlay['members'],1)and overlay['members']<=pp['bounds']['package_members']and integer(overlay['logical_bytes'])and overlay['logical_bytes']<=pp['bounds']['package_logical_bytes'],'only unregistered exact tool overlay without keys/install/hooks')
 build=exact(d['build-context.json'],{'files','sha256','labels','offline','package_install','TEST_key_generation'},'whole source-built offline context');exact(build['files'],{'Dockerfile','rootfs.tar.gz','tool-overlay.tar'},'exact three offline build members')
 for w in build['files'].values():expected_pin(w,2**31)
 need(build['files']['rootfs.tar.gz']==dict(bytes=pp['rootfs']['size'],sha256=pp['rootfs']['sha256'])and build['files']['tool-overlay.tar']==overlay['pin']and build['sha256']==pin(enc(build['files']))['sha256']==prod['context_sha256']and build['labels']=={'org.cachy-asahi.gui-provision-'+k:v for k,v in dict(nonce=prod['nonce'],source=prod['source_sha'],plan=prod['plan_pin']['sha256'],context=prod['context_sha256']).items()}and build['offline']is True and build['package_install']is False and build['TEST_key_generation']is False,'whole immutable source-owned build/overlay/context labels')

def _upstream_status(text,fingerprint):
 # Provisioning root signatures may use a different algorithm from the new
 # RSA2048 GUI signer. Preserve the exact original current-status parser here.
 need(type(text)is str and 0<len(text.encode())<=LIMIT and '\0'not in text,'bounded upstream GPG status');rows=[r.split()[1:]for r in text.splitlines()if r.startswith('[GNUPG:] ')]
 need(not BAD&{r[0]for r in rows},'invalid current upstream signature');valid=[r for r in rows if r[0]=='VALIDSIG'];need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint,'exact pinned upstream primary verification')

def receipts(packet_docs,production_docs,root_context,binding,input_plan,schema):
 """Validate retained evidence relationships before fresh public cryptography."""
 context(root_context,binding);d=production_docs;prod=d['production.json'];image=d['contract.json'];env=d['environment.json'];qual=d['qualification.json'];sp=d['source-provenance.json'];cleanup=d['cleanup.json'];pp=schema['provision_plan']
 exact(prod,{'schema_version','purpose','status','source_sha','plan_pin','nonce','uid','gid','image_id','tag','before_images','context_sha256','source_provenance','inputs','contract_pin','TEST_key_generation','production_credentials_used','native_build','GUI','hardware','Root_acceptance','error_type'},'exact no-key production receipt')
 need(type(prod['schema_version'])is int and prod['schema_version']==1 and prod['purpose']=='GUI_FRESH_TEST_SIGNER_PROVISION_V1'and prod['status']=='PASS_SOURCE_BUILT_SAME_JOB_NO_KEY'and prod['source_sha']==binding['signing_source']and prod['plan_pin']==schema['provision_plan_pin']and prod['error_type']is None and prod['TEST_key_generation']is False and prod['production_credentials_used']is False,'complete selected no-key source production');report_scope(prod)
 need(integer(prod['uid'],1)and integer(prod['gid'])and matches(prod['nonce'],'[a-f0-9]{32}')and matches(prod['image_id'],'sha256:[a-f0-9]{64}')and prod['tag']=='cachy-asahi-gui-test-signer:'+prod['nonce'],'actual owned image/nonroot source identity')
 need(d['provision-plan.json']==pp and pin(enc(pp))==schema['provision_plan_pin'],'entire fixed source provisioning plan')
 exact(image,{'schema_version','purpose','source_sha','oci_ref','image_id','alarm_uid','alarm_gid','packages_sha256','tools'},'exact produced image contract')
 expected_pin(prod['contract_pin']);need(integer(image['alarm_uid'],1)and integer(image['alarm_gid']),'typed produced alarm UID/GID')
 need(type(image['schema_version'])is int and image['schema_version']==1 and image['purpose']=='GUI-FRESH-TEST-SIGNER-IMAGE'and image['source_sha']==prod['source_sha']and image['oci_ref']is None and image['image_id']==prod['image_id']and(image['alarm_uid'],image['alarm_gid'])==(prod['uid'],prod['gid'])and image['packages_sha256']==schema['base_inventory_sha256']==pp['base_inventory_sha256']and pin(enc(image))==prod['contract_pin'],'same source-built native image contract and original package inventory')
 exact(image['tools'],TOOLS,'complete five executable pins')
 for w in image['tools'].values():expected_pin(w,128*1024**2)
 exact(sp,{'source_sha','source_root','files','manifest_path','manifest_pin','producer_path','environment_path','bootstrap_trust','TEST_key_generation','Root_acceptance'},'exact retained producer source provenance')
 need(sp==prod['source_provenance']and sp['source_sha']==prod['source_sha']and sp['files']==schema['producer_source_files']and sp['manifest_pin']==schema['producer_manifest_pin']and sp['manifest_path']=='scripts/ci/gui-fresh-test-signer/source-manifest.json'and sp['producer_path']=='scripts/ci/gui-fresh-test-signer/provision.py'and sp['environment_path']=='scripts/ci/gui-fresh-test-signer/environment.py'and sp['TEST_key_generation']is False and sp['Root_acceptance']is None and sp['bootstrap_trust']=='ROOT_REVIEWED_FILE_BYTES_BEFORE_SOURCE_IMAGE_EXECUTION_PUBLIC_SIGNATURES_VERIFIED_INSIDE_NEW_IMAGE_AFTER_BUILD','complete actual selected producer source and original source-manifest joins')
 need(pin(enc(sp))==root_context['source_provenance_pin']and pin(enc(qual))==root_context['qualification_pin'],'external Root-qualified source and qualification receipt pins')
 exact(qual,{'guard','tools','packages_sha256','packages_count'},'exact independent no-key qualification');need(type(qual['packages_count'])is int and qual['packages_count']==165 and qual['packages_sha256']==image['packages_sha256'],'independent unchanged base165 qualification')
 expected_guard=dict(arch='aarch64',uid=prod['uid'],gid=prod['gid'],user='alarm',capabilities={n:0 for n in CAPS},no_new_privs=1,root_read_only=True,tmpfs_private=True,interfaces=['lo'],local_docker_socket_exposed=False)
 need(qual['guard']==expected_guard and all(type(v)is int for v in qual['guard']['capabilities'].values())and integer(qual['guard']['uid'],1)and integer(qual['guard']['gid'])and type(qual['guard']['no_new_privs'])is int,'complete independent native capability-free qualification')
 need(all(type(qual['guard'][k])is bool for k in('root_read_only','tmpfs_private','local_docker_socket_exposed')),'literal independent qualification flags')
 exact(qual['tools'],TOOLS,'complete independent qualification tools')
 for n,w in qual['tools'].items():exact(w,{'bytes','sha256','resolved'},'exact qualified executable observation');need({k:w[k]for k in('bytes','sha256')}==image['tools'][n]and type(w['resolved'])is str and w['resolved'].startswith('/usr/'),'whole observed source-built executable pins')
 exact(env,{'schema_version','purpose','status','source_sha','contract_sha256','image_id','oci_ref','uid','gid','preexisting_image','acquired_image','built_image','nonce','image_observation','qualification','container_cleanup','production_pin','error'},'exact successful source-built environment receipt')
 need(type(env['schema_version'])is int and env['schema_version']==1 and env['purpose']=='GUI-FRESH-TEST-SIGNER-ENVIRONMENT'and env['status']=='PASS'and env['source_sha']==prod['source_sha']and env['contract_sha256']==prod['contract_pin']['sha256']and env['image_id']==prod['image_id']and env['oci_ref']is None and(env['uid'],env['gid'])==(prod['uid'],prod['gid'])and env['nonce']==prod['nonce']and env['preexisting_image']is False and env['acquired_image']is False and env['built_image']is True and env['qualification']==qual and env['production_pin']==pin(enc(prod))and env['error']is None and env['container_cleanup']==dict(status='PASS',container_absent=True),'same-job image production/environment/retired qualification joins')
 need(env['image_observation']==dict(id=prod['image_id'],architecture='arm64',os='linux',repo_digests=[],repo_tags=[prod['tag']]),'exact owned native image observation')
 need(type(prod['before_images'])is list and len(prod['before_images'])<=4096 and all(type(r)is list and len(r)==2 and matches(r[0],'sha256:[a-f0-9]{64}')and type(r[1])is str and r[0]!=prod['image_id']and r[1]!=prod['tag']for r in prod['before_images']),'image and owned tag absent before same-job production')
 exact(cleanup,{'schema_version','purpose','status','nonce','source_sha','image_id','contract_sha256','removed_new_image','container_absent','error_type'},'exact source-built image retirement')
 need(type(cleanup['schema_version'])is int and cleanup['schema_version']==1 and cleanup['purpose']==prod['purpose']and cleanup['status']=='PASS'and cleanup['nonce']==prod['nonce']and cleanup['source_sha']==prod['source_sha']and cleanup['image_id']==prod['image_id']and cleanup['contract_sha256']==prod['contract_pin']['sha256']and type(cleanup['removed_new_image'])is bool and cleanup['container_absent']is True and cleanup['error_type']is None,'actual completed same-source image/container retirement')
 _provision_receipts(d,prod,qual,image,pp,schema)
 saved=exact(packet_docs['result.json'],schema['sign_report_fields'],'exact genuine signer result');provenance=exact(packet_docs['provenance.json'],schema['public_provenance_fields'],'exact public signer provenance');verified=exact(provenance['independent_verification'],schema['verify_report_fields'],'exact independent public verification')
 c=sign_contract(saved['contract'],binding,schema,image)
 need(integer(saved['created'],1)and integer(saved['expiry'],1)and integer(verified['expiry'],1),'strict original/independent key timestamps')
 need(type(saved['schema_version'])is int and saved['schema_version']==1 and saved['purpose']==SIGN_PURPOSE and saved['status']==PASS and saved['fingerprint']==binding['fingerprint']and(saved['created'],saved['expiry'])==(binding['created'],binding['expires'])and saved['private_home_retired']is True and saved['production_credentials_used']is False,'actual successful fresh-key signer and private-home retirement');report_scope(saved);guard(saved['guard'],c['baseline'],prod['uid'])
 need(type(verified['schema_version'])is int and verified['schema_version']==1 and verified['status']==VERIFY and verified['contract']==c and verified['fingerprint']==saved['fingerprint']and verified['expiry']==saved['expiry']and verified['public_only_home_retired']is True and verified['Root_acceptance']is None,'actual independent public-only signature verification and home retirement');guard(verified['guard'],c['baseline'],prod['uid'])
 need(type(provenance['schema_version'])is int and provenance['schema_version']==1 and provenance['purpose']==SIGN_PURPOSE and provenance['status']==PASS and provenance['source_sha']==prod['source_sha']and provenance['image_id']==prod['image_id']and provenance['image_contract_sha256']==prod['contract_pin']['sha256']and provenance['image_production']==prod and provenance['signer']==dict(fingerprint=binding['fingerprint'],created=binding['created'],expiry=binding['expires'])and provenance['image_retirement']==cleanup,'complete public producer/source/image/fresh signer/retirement joins');report_scope(provenance)
 need(provenance['input_plan']==dict(input_plan,retired_signers=schema['retired_signers']),'exact original input plan plus derived retired signer exclusions')
 need(binding['fingerprint']not in schema['retired_signers'],'retired signer cannot become fresh authority');retired=provenance['signer_retirement'];need(type(retired)is list and len(retired)==2,'both signer and verifier actor retirements required')
 for row in retired:
  need(type(row)is dict and set(row)in({'status','container_absent','already_absent'},{'status','container_absent','id'})and row['status']=='PASS'and row['container_absent']is True,'strict complete owned actor retirement')
  need(row.get('already_absent')is True if'already_absent'in row else matches(row['id'],'[a-f0-9]{64}'),'observed actor absence or exact retired container ID')
 index=exact(packet_docs['index.json'],{'schema_version','kind','files','input_plan','signer','created','expires','actual_GUI','Root_acceptance'},'exact fresh signer packet index')
 need(type(index['schema_version'])is int and index['schema_version']==1 and index['kind']=='NEW_GUI_FRESH_TEST_SIGNING_OUTPUTS_REQUIRES_NEW_VERSIONED_SOURCE_REFERENCES'and index['input_plan']==schema['input_plan_pin']and index['signer']==binding['fingerprint']and(index['created'],index['expires'])==(binding['created'],binding['expires'])and index['actual_GUI']=='NOT_RUN'and index['Root_acceptance']is None,'new versioned TEST-only packet identity')
 need(integer(index['created'],1)and integer(index['expires'],1),'strict public packet timestamps')
 docs=input_plan['documents'];need(type(docs)is list and len(docs)==6 and{r['role']for r in docs}==set(ROLES6),'six exact original signing bodies');expected_inputs={}
 need(type(saved['signatures'])is dict and type(verified['signatures'])is dict and set(saved['signatures'])==set(verified['signatures'])==set(ROLES6),'all six original and independent signature receipts')
 for row in docs:
  need(row['signature_path']=='signatures/'+row['role']+'.sig'and row['carrier']in('native73','held77'),'closed original role/carrier signature selection');body={k:row[k]for k in('bytes','sha256')};expected_inputs[row['role']]=dict(carrier=row['carrier'],path=row['path'],pin=body)
  signature(saved['signatures'][row['role']],body,binding['fingerprint']);signature(verified['signatures'][row['role']],body,binding['fingerprint']);need(saved['signatures'][row['role']]['signature_pin']==verified['signatures'][row['role']]['signature_pin'],'independent exact detached signature bytes')
 catalog=exact(packet_docs['catalog.json'],{'schema_version','purpose','source_sha','nonce','signer','created','expires','inputs','signatures','authority_scope','native_build','GUI','hardware','Root_acceptance'},'exact new signed catalog')
 need(type(catalog['schema_version'])is int and catalog['schema_version']==1 and catalog['purpose']=='NEW_GUI_TEST_SIGNATURE_CATALOG'and catalog['source_sha']==binding['signing_source']and catalog['nonce']==c['nonce']and catalog['signer']==binding['fingerprint']and(catalog['created'],catalog['expires'])==(binding['created'],binding['expires'])and catalog['inputs']==expected_inputs and catalog['signatures']=={r:v['signature_pin']for r,v in saved['signatures'].items()}and catalog['authority_scope']==AUTHORITY,'whole exact new catalog and six immutable document/signature bindings');report_scope(catalog)
 need(integer(catalog['created'],1)and integer(catalog['expires'],1),'strict new catalog timestamps')
 catalog_pin=pin(enc(catalog));signature(saved['public_catalog'],catalog_pin,binding['fingerprint'],catalog=True);signature(verified['public_catalog'],catalog_pin,binding['fingerprint'],catalog=True);need(saved['public_catalog']['signature_pin']==verified['public_catalog']['signature_pin'],'independent exact catalog signature pin');return dict(contract=c,saved=saved,verified=verified,catalog=catalog)

def _gpg(argv,home):
 # Fixed public-only binary and isolated HOME; never sign, retrieve keys or
 # autostart an agent. TemporaryDirectory retires this public-only home.
 env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',HOME=str(home),GNUPGHOME=str(home))
 done=subprocess.run(['/usr/bin/gpg','--batch','--no-options','--no-tty','--no-autostart','--no-auto-key-retrieve','--no-auto-key-import','--homedir',str(home),*argv],stdin=subprocess.DEVNULL,capture_output=True,timeout=60,env=env)
 need(done.returncode==0 and len(done.stdout)<=LIMIT and len(done.stderr)<=LIMIT,'current public-only GPG verification failed');return done.stdout.decode('utf-8','strict')

def crypto(packet,bodies,binding,sign_contract,saved):
 packet=canonical(packet);need(type(bodies)is dict and set(bodies)==set(ROLES6),'six exact public verification bodies required')
 need(not any(os.environ.get(n)for n in('LD_PRELOAD','LD_LIBRARY_PATH','FAKETIME','FAKETIME_TIMESTAMP_FILE','GPG_AGENT_INFO','GNUPGHOME','PYTHONHOME','PYTHONPATH')),'clock, loader or external key-home override refused');current(binding['created'],binding['expires'])
 raw=checked(packet,'public-key.asc',saved['public_certificate_pin'],65536);need(raw.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----')and b'PRIVATE KEY'not in raw,'public-only selected TEST certificate required');observations={};key_before=pin(raw)
 with tempfile.TemporaryDirectory(prefix='gui-fresh-public-consumer-')as td:
  home=canonical(td);os.chmod(home,0o700);certificate(_gpg(['--with-colons','--show-keys',str(packet/'public-key.asc')],home),binding,sign_contract['nonce'])
  _gpg(['--import',str(packet/'public-key.asc')],home);need(not any(r.startswith(('sec:','ssb:'))for r in _gpg(['--with-colons','--list-secret-keys'],home).splitlines()),'no private keys in verifier')
  certificate(_gpg(['--with-colons','--list-keys'],home),binding,sign_contract['nonce'])
  for role in ROLES6:
   path=canonical(bodies[role]);row=saved['signatures'][role];body_before=pin(read(path,8*1024**2));need(body_before==row['input_pin'],'exact original body before current GPG');signature_before=pin(checked(packet,'signatures/'+role+'.sig',row['signature_pin'],8192))
   text=_gpg(['--status-fd','1','--verify',str(packet/'signatures'/str(role+'.sig')),str(path)],home);status(text,binding['fingerprint'])
   need(pin(read(path,8*1024**2))==body_before and pin(read(packet/'signatures'/str(role+'.sig'),8192))==signature_before,'whole immutable original body/signature after GPG');observations[role]=dict(input_pin=body_before,signature_pin=signature_before,status=text,gpg_exit=0)
  row=saved['public_catalog'];body_before=pin(checked(packet,'catalog.json',row['body_pin'],65536));signature_before=pin(checked(packet,'catalog.json.sig',row['signature_pin'],8192));text=_gpg(['--status-fd','1','--verify',str(packet/'catalog.json.sig'),str(packet/'catalog.json')],home);status(text,binding['fingerprint'])
  need(pin(read(packet/'catalog.json',65536))==body_before and pin(read(packet/'catalog.json.sig',8192))==signature_before and pin(read(packet/'public-key.asc',65536))==key_before,'unchanged current catalog/signature/certificate');observations['catalog']=dict(body_pin=body_before,signature_pin=signature_before,status=text,gpg_exit=0)
  need(not(home/'private-keys-v1.d').exists()or not any((home/'private-keys-v1.d').iterdir()),'public verifier never held private keys')
 current(binding['created'],binding['expires']);return dict(status='PASS_CURRENT_PUBLIC_ONLY_FRESH_TEST_VERIFICATION',signatures=observations,public_only_home_retired=True)

def _documents(root,names,files):
 out={}
 for name in names:
  if name.endswith('.json'):
   raw=checked(root,name,files[name]);out[name]=obj(raw);need(enc(out[name])==raw,'exact canonical producer JSON bytes')
 return out

def _embedded(schema):
 """Decode exact Source operands; never materialize a new Root receipt."""
 e=exact(schema['qualified_evidence'],{'production','qualification','reader','run','jobs','publication_scope','publication_authorization'},'complete Source-bound qualified signing evidence')
 def decode(value,cap=LIMIT):
  need(type(value)is str and len(value)<=4*((cap+2)//3),'bounded Source evidence encoding');raw=base64.b64decode(value,validate=True);need(len(raw)<=cap and base64.b64encode(raw).decode()==value and b'PRIVATE KEY BLOCK'not in raw,'exact public-only Source evidence bytes');return raw,obj(raw)
 need(type(e['production'])is dict and set(e['production'])==PRODUCTION_NAMES,'complete13 Source-bound production receipts')
 raw={};docs={}
 for name,value in e['production'].items():raw[name],docs[name]=decode(value);need(enc(docs[name])==raw[name],'unchanged canonical original production JSON')
 need(sum(map(len,raw.values()))<=8*1024**2,'bounded Source-bound production evidence');other={}
 for name in('qualification','reader','run','jobs','publication_scope','publication_authorization'):other[name]=decode(e[name])
 return raw,docs,other

def _epoch(text):
 need(type(text)is str,'exact retained terminal timestamp');return int(datetime.datetime.strptime(text,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp())

def _qualified(schema,b,pd):
 """Check actual Root/source/run/job evidence, then project context in memory."""
 raw,docs,e=_embedded(schema);qraw,q=e['qualification'];rraw,r=e['reader'];run=e['run'][1];jobs=e['jobs'][1];scope=e['publication_scope'][1];auth=e['publication_authorization'][1]
 need(pin(qraw)==b['context_pin']and q['status']=='ROOT_QUALIFIED_FRESH_PUBLIC_TEST_SIGNING_PACKET_ONLY'and(q['source'],q['run'],q['attempt'])==(b['signing_source'],b['run'],b['attempt'])and(q['fingerprint'],q['created'],q['expiry'])==(b['fingerprint'],b['created'],b['expires']),'exact genuine Root-qualified signing packet and selected identity')
 need(q['qualification']=='SOURCE_BOUND_SAME_JOB_NATIVE_QUALIFICATION_DUAL_PUBLIC_SIGNATURE_VERIFICATION_AND_ORDERED_RETIREMENT'and q['GUI']=='NOT_ACCEPTED'and q['M2']==q['hardware']=='NOT_RUN'and q['release']=='NOT_ADMITTED'and q['production_trust']=='NOT_GRANTED'and q['RSA_math_replayed']is False,'Root qualification grants only fresh public TEST signing scope')
 need(q['reader_result']==pin(rraw)and r['status']=='PASS_PASSIVE_FRESH_TEST_SIGNING_RECEIPTS_EXACT_RUN'and(r['source'],r['run'],r['attempt'])==(b['signing_source'],b['run'],b['attempt'])and r['GUI']==r['M2_hardware']=='NOT_RUN'and r['Root_acceptance']is None and r['production_trust']=='NOT_GRANTED'and r['publication']=='NOT_ISSUED_BY_READER','exact genuine passive reader bytes, source/run/attempt and non-acceptance scope')
 need(r['retirement_scope']=='SOURCE_BOUND_RECEIPTS_AND_JOB_LOGS_RAW_DOCKER_CIDS_NOT_EXPORTED','source-bound ordered retirement evidence scope')
 need(matches(b['job'],'[1-9][0-9]{0,19}')and type(r['host']['job_id'])is int and str(r['host']['job_id'])==b['job'],'exact selected native job ID from Root reader')
 need(type(run)is dict and type(run['id'])is int and run['id']==b['run']and type(run['run_attempt'])is int and run['run_attempt']==b['attempt']and run['status']=='completed'and run['conclusion']=='success'and run['event']=='workflow_dispatch'and run['head_sha']==run['head_commit']['id']==b['signing_source']and run['head_branch']==b['signing_ref'].removeprefix('refs/heads/')and run['workflow_id']==q['workflow_id']and run['path']=='.github/workflows/native-arm-build.yml','successful exact originating workflow source/ref/run/attempt')
 need(run['repository']['full_name']==run['head_repository']['full_name']=='Gabriel-Kahen/cachy-asahi','exact originating source repository')
 exact(jobs,{'total_count','jobs'},'complete original terminal job collection');need(type(jobs['total_count'])is int and jobs['total_count']==1 and type(jobs['jobs'])is list and len(jobs['jobs'])==1,'exactly one originating native job');job=jobs['jobs'][0]
 need(type(job['id'])is int and job['id']==r['host']['job_id']and job['run_id']==b['run']and type(job['run_attempt'])is int and job['run_attempt']==b['attempt']and job['head_sha']==b['signing_source']and job['head_branch']==run['head_branch']and job['workflow_name']==run['name']and job['name']=='native'and job['status']=='completed'and job['conclusion']=='success'and job['labels']==['ubuntu-24.04-arm'],'actual same-job native/signing terminal identity')
 steps=job['steps'];need(type(steps)is list and len(steps)<=64 and all(type(x)is dict and x['status']=='completed'and x['conclusion']=='success'and integer(x['number'],1)for x in steps),'all selected signing job steps completed successfully');by_name={x['name']:x for x in steps};need(len(by_name)==len(steps),'unique selected job step names')
 produce='Acquire exact public inputs and build authenticate and qualify the minimal source image without a TEST key';sign='Explicit sign mode only after same-job genuine image production and qualification';retire='Retire only the genuinely produced owned image and actors'
 for name in(produce,sign,retire,'Close fresh crypto outputs only in successful explicit sign mode','Upload closed crypto outputs only from successful explicit sign mode'):need(name in by_name,'genuine explicit sign-mode completion, not no-key-only mode')
 host=r['host'];need(host['run_start_epoch']==_epoch(run['run_started_at'])and host['run_end_epoch']==_epoch(run['updated_at'])and host['produce_start_epoch']==_epoch(by_name[produce]['started_at'])and host['produce_end_epoch']==_epoch(by_name[produce]['completed_at'])and host['sign_start_epoch']==_epoch(by_name[sign]['started_at'])and host['sign_end_epoch']==_epoch(by_name[sign]['completed_at']),'exact reader and terminal source/sign job intervals')
 need(host['run_start_epoch']<=_epoch(job['started_at'])<=host['produce_start_epoch']<=host['produce_end_epoch']<=host['sign_start_epoch']<=b['created']<=host['sign_end_epoch']<=_epoch(by_name[retire]['started_at'])<=_epoch(job['completed_at'])<=host['run_end_epoch'],'real key generation follows same-job production and precedes ordered retirement')
 production=docs['production.json'];observed=r['production'];signing=r['signing'];saved=pd['result.json'];c=saved['contract'];independent=pd['provenance.json']['independent_verification']
 need((observed['image_id'],observed['nonce'],observed['uid'],observed['gid'],observed['packages_count'])==(production['image_id'],production['nonce'],production['uid'],production['gid'],165)and observed['tools']==docs['qualification.json']['tools'],'reader original image/source-owner/tool/inventory joins')
 probes=['cachy-asahi-gui-signer-env-'+production['nonce'],'cachy-asahi-gui-signer-env-'+hashlib.sha256(('qualification:'+production['nonce']).encode()).hexdigest()[:32]];need(observed['owned_probe_names']==probes,'actual same-source no-key probe identities')
 need((signing['fingerprint'],signing['created'],signing['expiry'],signing['image_id'],signing['signer_nonce'])==(b['fingerprint'],b['created'],b['expires'],production['image_id'],c['nonce'])and signing['private_home_retired']is True and signing['independent_public_only_home_retired']is True and saved['private_home_retired']is True and independent['public_only_home_retired']is True and signing['Root_acceptance']is None,'reader fresh nonce/key/image and dual private/public home retirement')
 need(signing['catalog_pin']==pin(enc(pd['catalog.json']))and signing['scope']=='PASSIVE_PACKET_AND_SOURCE_BOUND_DUAL_GPG_EVIDENCE_NOT_RSA_REEXECUTION','exact qualified new catalog and passive/dual-evidence scope')
 cert=signing['certificate'];need(cert['status']=='PASS_PASSIVE_PUBLIC_CERTIFICATE_STRUCTURE'and(cert['fingerprint'],cert['created'],cert['expiry'])==(b['fingerprint'],b['created'],b['expires'])and cert['rsa_bits']==2048 and cert['rsa_exponent']==65537 and cert['uid']=='CACHY-ASAHI TEST ONLY '+c['nonce']+' <test-only@invalid.example>'and cert['key_flags']==3 and cert['self_signature_created']==b['created']and cert['self_signature_hash_algorithm']==10 and cert['self_signature_hash_prefix_consistent']is True and cert['packet_tags']==[6,13,2],'reader actual fresh public certificate/nonce structure')
 need(set(signing['signatures'])==set(ROLES6)|{'catalog'}and set(observed['signatures'])==set(docs['input-authentication.json']['signatures']),'all qualified six bodies/catalog and upstream inputs')
 for role,summary in signing['signatures'].items():
  parsed=summary['status'];packet=summary['packet'];original=saved['public_catalog']if role=='catalog'else saved['signatures'][role];v=status(original['status'],b['fingerprint'])
  need(parsed['status']=='PASS_STRICT_FRESH_TEST_SIGNATURE_STATUS'and parsed['signer_fingerprint']==parsed['primary_fingerprint']==b['fingerprint']and parsed['created_epoch']==v['created']and parsed['expires_epoch']==v['expires']and parsed['good_signature_key_id']==b['fingerprint'][-16:]and parsed['hash_algorithm']==8 and parsed['public_key_algorithm']==1 and parsed['signature_version']==4 and parsed['signature_class']=='00'and parsed['records'].get('GOODSIG')==parsed['records'].get('VALIDSIG')==1,'reader complete original current GPG status joins')
  need(packet['status']=='PASS_PASSIVE_DETACHED_SIGNATURE_STRUCTURE'and(packet['fingerprint'],packet['created'],packet['expiry'])==(b['fingerprint'],v['created'],v['expires'])and packet['issuer_key_id']==b['fingerprint'][-16:]and packet['hash_algorithm']==8 and packet['public_key_algorithm']==1 and packet['signature_version']==4 and packet['signature_class']==0,'reader detached packet and exact signed timestamp joins')
 for name,summary in observed['signatures'].items():
  original=docs['input-authentication.json']['signatures'][name];_upstream_status(original['status'],schema['upstream_signer_fingerprint']);rows=[x.split()[1:]for x in original['status'].splitlines()if x.startswith('[GNUPG:] VALIDSIG ')];v=rows[0]
  need(summary['status']=='PASS_STRICT_UPSTREAM_SIGNATURE_STATUS'and summary['signer_fingerprint']==summary['primary_fingerprint']==schema['upstream_signer_fingerprint']and summary['created_epoch']==int(v[3])and summary['expires_epoch']==int(v[4])and summary['created_date']==v[2]and summary['hash_algorithm']==int(v[8])and summary['public_key_algorithm']==int(v[7])and summary['signature_version']==int(v[5])and summary['signature_class']==v[9]and summary['records'].get('GOODSIG')==summary['records'].get('VALIDSIG')==1,'reader complete original upstream status/timestamp/algorithm joins')
 need(pin(raw['index.json'])==b['production_index_pin'],'exact selected original13 no-key receipt index')
 exact(auth,{'files','ref','source','status'},'exact Root publication Source authorization');need(auth['status']=='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN'and(auth['source'],auth['ref'])==(b['carrier_source'],b['carrier_ref'])and type(auth['files'])is dict and set(auth['files'])==PUBLIC_NAMES|{'LICENSE'},'published13-file exact Source/ref and Root Git/blob join')
 need(auth['files']['index.json']==b['index_pin']and auth['files']==dict(pd['index.json']['files'],**{'index.json':b['index_pin'],'LICENSE':auth['files']['LICENSE']}),'Source authorization matches original12 public leaves plus the sole license addition')
 need(scope['status']=='QUALIFIED_PUBLIC_TEST_PACKET_PREPARED_FOR_EXACT_PUBLICATION'and(scope['source'],scope['run'])==(b['signing_source'],b['run'])and(scope['fingerprint'],scope['created'],scope['expiry'])==(b['fingerprint'],b['created'],b['expires'])and scope['qualification']==pin(qraw)and scope['Root_addition']=={'LICENSE':auth['files']['LICENSE']}and len(scope['public_packet_members'])==12 and set(scope['public_packet_members'])==PUBLIC_NAMES and scope['bodies']=='UNCHANGED_SEPARATE_EXISTING_CARRIERS'and scope['production_trust']=='NOT_GRANTED'and scope['M2']=='NOT_RUN'and scope['secret_material']=='REFUSED_BY_QUALIFIED_READER','Root publication scope, qualification and unchanged exact public packet')
 normalized=dict(schema_version=1,purpose='ROOT_SELECTED_ACTUAL_GUI_FRESH_TEST_SIGNING_CONTEXT',status='ROOT_VALIDATED_ACTUAL_PUBLIC_TEST_SIGNING_PACKET',source=b['signing_source'],workflow_source=run['head_sha'],ref=b['signing_ref'],run=b['run'],attempt=b['attempt'],job=b['job'],mode='sign',same_job=True,packet_index_pin=b['index_pin'],production_index_pin=b['production_index_pin'],qualification_pin=pin(raw['qualification.json']),source_provenance_pin=pin(raw['source-provenance.json']))
 context(normalized,b)
 return raw,docs,normalized,auth['files']

def verify(packet,production_root=None,context_path=None,carriers=None,selected=None):
 """Use Source-bound genuine evidence or explicit external modeled operands."""
 p=policy()if selected is None else validate_policy(selected);b=p['binding'];packet=canonical(packet);input_plan,schema=contract();source_bound=production_root is None and context_path is None
 need(source_bound or(production_root is not None and context_path is not None),'production and Root context must be supplied together or both Source-bound')
 if source_bound:
  need(b['packet_path']=='.'and b['production_path']=='@source/production'and b['context_path']=='@source/Root-qualification.json','explicit Source-bound published-root policy required')
  source_raw,dd,embedded=_embedded(schema);qraw,q=embedded['qualification'];need(pin(qraw)==b['context_pin'],'exact Source-pinned actual Root qualification');current(b['created'],b['expires'])
  authorization=embedded['publication_authorization'][1];public_files=authorization['files'];need(type(public_files)is dict and set(public_files)==PUBLIC_NAMES|{'LICENSE'},'exact published13 public Source namespace')
 else:
  need(b['packet_path']!='.','published-root binding requires Source-bound evidence, never filesystem substitution');production_root=canonical(production_root);context_path=canonical(context_path);root=packet.parents[len(Path(b['packet_path']).parts)-1]
  need(packet==root/b['packet_path']and production_root==root/b['production_path']and context_path==root/b['context_path'],'all selected portable paths belong to one ordinary carrier root')
  context_raw=read(context_path);need(pin(context_raw)==b['context_pin'],'exact external Root context pin');root_context=obj(context_raw);need(enc(root_context)==context_raw,'canonical external Root context');context(root_context,b);current(b['created'],b['expires'])
 pi_raw=checked(packet,'index.json',b['index_pin']);pi=obj(pi_raw);need(enc(pi)==pi_raw,'canonical public packet index');exact(pi,{'schema_version','kind','files','input_plan','signer','created','expires','actual_GUI','Root_acceptance'},'strict public signer index')
 need(type(pi['files'])is dict and set(pi['files'])==PUBLIC_NAMES-{'index.json'},'exact original12 public signer packet leaves')
 if not source_bound:public_files=dict(pi['files'],**{'index.json':b['index_pin']})
 else:need(public_files==dict(pi['files'],**{'index.json':b['index_pin'],'LICENSE':public_files['LICENSE']}),'published Source adds only the authorized license to the exact original packet')
 need(sum(expected_pin(w)['bytes']for w in public_files.values())<=LIMIT,'bounded public signing packet');before_public=closed(packet,public_files,git=source_bound,mode=0o644);pd=_documents(packet,PUBLIC_NAMES,public_files)
 if source_bound:
  source_raw,dd,root_context,authorized_files=_qualified(schema,b,pd);need(authorized_files==public_files,'full Root publication authorization and packet closure join');di_raw=source_raw['index.json'];di=dd['index.json']
 else:
  di_raw=checked(production_root,'index.json',b['production_index_pin']);di=obj(di_raw)
 need(pin(di_raw)==b['production_index_pin']and enc(di)==di_raw,'exact canonical selected no-key receipt index');exact(di,{'schema_version','purpose','files','archives_exported','image_exported','TEST_key_generation','Root_acceptance'},'exact no-key receipt export index')
 need(type(di['schema_version'])is int and di['schema_version']==1 and di['purpose']=='GUI_NO_KEY_PROVISION_PUBLIC_RECEIPTS'and di['archives_exported']is False and di['image_exported']is False and di['TEST_key_generation']is False and di['Root_acceptance']is None and type(di['files'])is dict and set(di['files'])==PRODUCTION_NAMES-{'index.json'},'complete13 no-key public receipts, no partial failure export')
 production_files=dict(di['files'],**{'index.json':b['production_index_pin']});need(sum(expected_pin(w)['bytes']for w in production_files.values())<=8*1024**2,'bounded no-key receipt export')
 if source_bound:need({n:pin(raw)for n,raw in source_raw.items()}==production_files,'whole exact original13 Source-embedded no-key receipts')
 else:before_production=closed(production_root,production_files,mode=0o644);dd=_documents(production_root,PRODUCTION_NAMES,production_files)
 verified=receipts(pd,dd,root_context,b,input_plan,schema);exact(carriers,{'native73','held77'},'exact two original public carrier roots required');carrier_roots={n:canonical(r)for n,r in carriers.items()};disjoint=[packet,*carrier_roots.values()]+([]if source_bound else[production_root])
 need(all(not a.is_relative_to(z)and not z.is_relative_to(a)for i,a in enumerate(disjoint)for z in disjoint[i+1:]),'disjoint complete public/production/original carrier roots');before_carriers={}
 for alias,count in(('native73',226),('held77',98)):
  wanted=input_plan['carriers'][alias]['files'];need(len(wanted)==count,'entire original carrier map required');before_carriers[alias]=closed(carrier_roots[alias],wanted,git=True)
 bodies={}
 for row in input_plan['documents']:
  need(row['carrier']in carrier_roots and row['signature_path']=='signatures/'+row['role']+'.sig','only exact original selected body paths');wanted={k:row[k]for k in('bytes','sha256')};need(input_plan['carriers'][row['carrier']]['files'][row['path']]==wanted,'body joins whole original carrier map')
  checked(carrier_roots[row['carrier']],row['path'],wanted,8*1024**2);bodies[row['role']]=carrier_roots[row['carrier']]/relative(row['path']);checked(packet,row['signature_path'],verified['saved']['signatures'][row['role']]['signature_pin'],8192)
 checked(packet,'public-key.asc',verified['saved']['public_certificate_pin'],65536);checked(packet,'catalog.json',verified['saved']['public_catalog']['body_pin'],65536);checked(packet,'catalog.json.sig',verified['saved']['public_catalog']['signature_pin'],8192)
 actual=crypto(packet,bodies,b,verified['contract'],verified['saved']);need(type(actual)is dict and actual['status']=='PASS_CURRENT_PUBLIC_ONLY_FRESH_TEST_VERIFICATION'and actual['public_only_home_retired']is True and set(actual['signatures'])==set(ROLES6)|{'catalog'},'complete independent current six-body and catalog verification')
 need(closed(packet,public_files,git=source_bound,mode=0o644)==before_public,'late whole published packet closure')
 if not source_bound:need(closed(production_root,production_files,mode=0o644)==before_production and read(context_path)==context_raw,'late whole external no-key/context joins')
 for alias in carrier_roots:need(closed(carrier_roots[alias],input_plan['carriers'][alias]['files'],git=True)==before_carriers[alias],'late complete original carrier identity')
 late_plan,late_schema=contract();need(enc(late_plan)==enc(input_plan)and enc(late_schema)==enc(schema),'late entire Source-bound input/evidence operands');current(b['created'],b['expires'])
 return dict(status='PASS_SELECTED_CURRENT_FRESH_TEST_INPUTS_ONLY',fingerprint=b['fingerprint'],created=b['created'],expires=b['expires'],signing_source=b['signing_source'],signing_ref=b['signing_ref'],run=b['run'],attempt=b['attempt'],job=b['job'],carrier_source=b['carrier_source'],carrier_ref=b['carrier_ref'],packet_index_pin=b['index_pin'],production_index_pin=b['production_index_pin'],context_pin=b['context_pin'],catalog_pin=verified['saved']['public_catalog']['body_pin'],input_plan=schema['input_plan_pin'],signatures=actual['signatures'],native_build='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',Root_acceptance=None)
