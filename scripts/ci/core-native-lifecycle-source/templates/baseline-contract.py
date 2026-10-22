# SPDX-License-Identifier: MIT
"""Fixed accepted Core7, original13 support and complete574 rollback contract."""
import hashlib,json,math,re,stat,time
from pathlib import Path
import package_data as P
import source_proof as S
HERE=Path(__file__).resolve().parent
PROFILE={'bytes':449364,'sha256':'248a07fff03d33b14d6c3ae3e27592b1d0fe21bd92d7d93ead77bd9fe1118705'}
NAMES={'pacman','systemd','systemd-libs','systemd-resolvconf','systemd-sysvcompat','systemd-tests','systemd-ukify'}
REPLACED=NAMES-{'systemd-tests','systemd-ukify'}
CASES=('pristine','modified')
STAGES=('precommit-refused','install','reinstall','rollback','repeat-install','repeat-rollback')
FIXTURES=('etc/pacman.conf','etc/systemd/system.conf')
LABEL='org.cachy-asahi.core-native-lifecycle'
ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1'}
need=P.need;pin=S.pin
def read(path,cap=2*1024**2):return S.read(Path(path).absolute(),time.monotonic()+30,cap)
encoded=lambda v:(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def profile():
 raw=read(HERE/'input-profile.json');need(pin(raw)==PROFILE,'whole fixed Core7 lifecycle profile');v=json.loads(raw)
 need(v['schema']==1 and v['actual']is None and v['old_target261']=='UNCHANGED_UNACCEPTED'and v['counts']==dict(base=574,support=13,replacements=5,additions=2,installed=589,restored=574),'finite new component scope only');return v

def closure():
 v=profile();c=json.loads(read(HERE/'support-closure.json'));lock=json.loads(read(HERE/'builder-inputs.lock.json'));rows={r['name']:r for r in lock['packages']}
 need(pin(read(HERE/'builder-inputs.lock.json'))==v['retained64']['original_lock'],'unchanged complete original64 lock')
 need(len(rows)==64 and lock['signer_fingerprint']=='68B3537F39A313B3E574D06777193F152BDBE6A6'and set(c['support'])==set(v['support'])and len(c['support'])==13 and not c['unresolved'],'exact original13 declared dependency support')
 need(c['support']=={n:rows[n]for n in v['support']}and len(c['base'])==574 and set(c['candidate'])==NAMES and c['candidate']=={n:r['version']for n,r in v['packages'].items()},'whole original lock rows and seven accepted versions');return c

def states():
 c=closure();base=c['base'];supported=dict(base,**{n:r['version']for n,r in c['support'].items()});installed=dict(supported,**c['candidate'])
 need(len(base)==574 and len(supported)==587 and len(installed)==589 and set(base)&NAMES==REPLACED and not set(base)&c['support'].keys(),'exact574/587/589 inventories');return base,supported,installed

def packet(carrier):
 v=profile();carrier=Path(carrier);index=json.loads(read(carrier/'index.json'));need(pin(read(carrier/'index.json'))==v['core7']['index'],'whole accepted Core7 index')
 a=json.loads(read(carrier/'Root-component-acceptance.json'));positive=read(carrier/'Root-core-native-build-positive.json');need(pin(read(carrier/'Root-component-acceptance.json'))==v['accepted_build']['acceptance']and pin(positive)==v['accepted_build']['positive'],'genuine pinned Root acceptance/complete pair result')
 need(a['status']=='ROOT_ACCEPTED_FINITE_NATIVE_CORE_BUILD_PAIRS'and(a['source'],a['ref'],a['run'],a['attempt'])==tuple(v['accepted_build'][n]for n in('source','ref','run','attempt'))and a['byte_identical_packages']==7 and a['installed']=='NOT_RUN'and a['old_target261']=='UNCHANGED_UNACCEPTED','native build evidence never installation authority')
 need(index['source']==a['source']and index['run']==a['run']and set(index['packages'])==NAMES and index['signature_authority']is False,'whole original seven roles')
 result={}
 for n,row in v['packages'].items():
  raw=read(carrier/'packages'/row['filename'],64*1024**2);need(pin(raw)=={k:row[k]for k in('bytes','sha256')}==a['archives'][n],'same accepted A/B archive bytes')
  observed=P.archive(carrier/'packages'/row['filename']);need(observed['metadata']==row['fields']and observed['metadata']['arch']==['aarch64'],'complete accepted native PKGINFO')
  for field,file in(('metadata','PKGINFO'),('buildinfo','BUILDINFO')):
   original=read(carrier/'metadata'/(n+'.'+file));need(observed['data']['.'+file]==original,'complete original '+file+' bytes')
  result[n]=observed
 return result

def changes(before,after,packages,versions,fixture=()):
 """Every unrelated full node and DB record stays exact; no prefix-wide usr/etc exemption."""
 allowed=set(fixture);prefixes=[]
 for package in packages:
  for name,row in package['nodes'].items():
   if row['type']!='directory':allowed.add(name)
   elif name not in before and name in after:
    need(all(after[name].get(k)==v for k,v in row.items()),'new selected directory exact mode/owner');allowed.add(name)
 for name,version in versions:
  directory='var/lib/pacman/local/'+name+'-'+version;allowed.add(directory);prefixes.append(directory+'/')
 changed={n for n in set(before)|set(after)if before.get(n)!=after.get(n)}
 unexpected=sorted(n for n in changed if n not in allowed and not n.startswith(tuple(prefixes)))
 need(not unexpected,'unrelated/protected complete-root mutation: '+str(unexpected[:12]));return dict(changed_nodes=len(changed),unrelated_complete_nodes_preserved=True)

def commands_identity(row):
 need(type(row)is dict and row['group_absence_verified']is True and row['exit_code']==0,'actual foreground command exit and complete process retirement')
 return row

def load(name,path):
 import importlib.util,sys
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def helpers(root):return load('held_core574_helpers',Path(root)/'scripts/ci/glibc-gnu-provider-lifecycle/common.py').helpers(root)

def configuration(inputs,input_sha):
 inputs=Path(inputs);raw=read(inputs/'lifecycle-input.json');need(pin(raw)['sha256']==input_sha,'private source-owned index hash');v=json.loads(raw);need(v['scope']=='DISPOSABLE_CORE7_NATIVE_LIFECYCLE'and v['schema']==1 and v['core7_source']==profile()['core7']['source']and v['accepted_build']==profile()['accepted_build'],'fixed new native lifecycle binding only')
 need(re.fullmatch('[a-f0-9]{32}',v['token'])and re.fullmatch('sha256:[a-f0-9]{64}',v['image_id']),'owned image/token');need(v['base_lock']==profile()['base_lock']and pin(encoded(v['source_capabilities']))['sha256']==v['source_capabilities_sha256'],'same original574 graph/capabilities')
 need(re.fullmatch('[A-F0-9]{40}',v['test_signer'])and v['test_signer']!='68B3537F39A313B3E574D06777193F152BDBE6A6','strict TEST and upstream signer separation')
 actual={};aliases={}
 for path in inputs.rglob('*'):
  name=path.relative_to(inputs).as_posix()
  if path.is_symlink():aliases[name]=path.readlink().as_posix()
  elif path.is_file()and name!='lifecycle-input.json':actual[name]=pin(read(path,128*1024**2))
  else:need(path.is_dir()or name=='lifecycle-input.json','ordinary assembly namespace')
 need(actual==v['assembly_files']and aliases==v['assembly_aliases'],'whole source-produced public assembly membership/bytes and exact repo aliases')
 need(set(aliases)<={'core7-test.db','core7-test.db.sig','core7-test.files','core7-test.files.sig'}and all(Path(n).name==n and Path(target).name==target and target in actual for n,target in aliases.items()),'only exact ordinary repo-add sibling aliases')
 assembly=json.loads(read(inputs/'assembly.json'));need(assembly['status']=='SIGNED_CORE7_TEST_ASSEMBLY_DATA_ONLY'and assembly['signer']==v['test_signer']and assembly['installed']=='NOT_RUN'and assembly['authentication64']==pin(read(inputs/'authentication64.json')),'owned signing/data assembly joins')
 for key,name in(('catalog','catalog.json'),('catalog_signature','catalog.json.sig'),('repository','core7-test.db.tar.gz'),('repository_signature','core7-test.db.tar.gz.sig'),('public_key','TEST-public.asc')):need(assembly[key]==pin(read(inputs/name)),'all public signature/repository/catalog keys joined')
 auth=json.loads(read(inputs/'authentication64.json'));need(auth['status']=='PASS_CURRENT_ORIGINAL64_SIGNATURE_AND_COMPLETE_PKGINFO'and len(auth['records'])==64 and auth['signer']=='68B3537F39A313B3E574D06777193F152BDBE6A6'and auth['public_home_retired']is True,'fresh original full64 signature/metadata still required')
 need(v['rollback_rows']==rollback_rows(),'all five fixed original rollback archive metadata rows');return v,states()[0],None,None

def validate_child(index,child):
 need(child['status']=='PASS_DISPOSABLE_CORE7_NATIVE_LIFECYCLE'and child['public_home_cleanup']=='PASS'and set(child['cases'])==set(CASES),'all actual seven-package cases and public home retirement')
 need(child['lifecycle_seconds_limit']==3600 and type(child['seconds'])in(int,float)and math.isfinite(child['seconds'])and 0<=child['seconds']<=3600 and type(child['commands'])is list and len(child['commands'])<=128,'original lifecycle/command clocks and bounded raw records')
 need([row['argv']for row in child['commands']]==expected_commands(index),'all113 exact actual verification/scriptlet/installed CLI/unit-test commands in order')
 for row in child['commands']:
  commands_identity(row);need(type(row['time_limit'])in(int,float)and 0<row['time_limit']<=90 and row['output_limit']==1024**2,'original per-command clock/stream caps')
 for case,row in child['cases'].items():
  need(row['status']=='PASS_CORE7_INSTALLED_REINSTALLED_ROLLED_BACK_AND_REPEATED'and row['copy_lifetime']['cleanup']=='PASS-owned-workspace-removed'and row['copy_lifetime']['copy']['copy_byte_identical_before_initialization']is True,'whole copied-root identity/disposal')
  need(set(row['transactions'])==set(STAGES)and row['transactions']['precommit-refused']['commit_started']is False,'complete fixed lifecycle transaction matrix')
  for stage in STAGES[1:]:need(row['transactions'][stage]['status']=='COMMITTED_FULL_EXACT_INVENTORY'and row['transactions'][stage]['signature']=='REQUIRED_STRICT_LOCAL_LOAD','real exact signed commits at every mandatory stage')
  expected={case+'-'+stage for stage in('source-before','fixture-first','initial','precommit-refused',*STAGES[1:],'final','source-after')};need(set(row['snapshots'])==expected and all(r['capabilities']==pin(encoded(index['source_capabilities']))for r in row['snapshots'].values()),'all20 complete source/copy/stage graph and capability receipt rows')
 need(child['proc_preflight']['status']=='PASS_READONLY_PROC_PREFLIGHT'and child['proc_preflight']['cleanup']=='PASS_OWNED_EMPTY_PROBE_REMOVED','original readonly proc/dev confinement preflight')
 need(child['apparmor']['status']=='PASS_INSIDE_OWNED_TRIAL_APPARMOR_ENFORCE','original enforced confinement readback');return True

def rollback_rows():
 raw=read(HERE/'retained/desktop574-inputs.lock.json');need(pin(raw)==profile()['retained574']['files']['desktop574-inputs.lock.json'],'unchanged complete original574 archive lock');rows={r['name']:r for r in json.loads(raw)['packages']};need(len(rows)==574,'whole original574 role map');return{n:rows[n]for n in REPLACED}

def expected_commands(index):
 """Complete fixed public verification and two-case installed readback sequence."""
 gpg=['/usr/bin/gpg','--batch','--no-options','--homedir','/tmp/core-public-gpg','--no-auto-key-retrieve','--auto-key-locate','clear','--no-autostart'];result=[gpg+['--import','/runner/keyring/archlinuxarm.gpg','/inputs/TEST-public.asc'],gpg+['--with-colons','--list-secret-keys'],gpg+['--import-ownertrust','/tmp/core-public-gpg/ownertrust'],gpg+['--status-fd','1','--verify','/inputs/catalog.json.sig','/inputs/catalog.json'],gpg+['--status-fd','1','--verify','/inputs/core7-test.db.tar.gz.sig','/inputs/core7-test.db.tar.gz']];products={n:r['filename']for n,r in profile()['packages'].items()};products.update({n+'-original':r['filename']for n,r in {**rollback_rows(),**closure()['support']}.items()})
 for key in sorted(products):
  path='/inputs/packages/'+products[key];result.append(gpg+['--status-fd','1','--verify',path+'.sig',path])
 for case in CASES:
  root='/work/'+case+'/root'
  import fixture as F
  result.extend([F.baseline_argv(root,states()[0]['systemd'])]*2)
  for stage in STAGES[1:]:
   installed=stage in('install','reinstall','repeat-install')
   if stage!='reinstall':result.append(['/usr/bin/chroot',root,'/usr/bin/bash','--noprofile','--norc','-e','-x','-c','cd /; source /tmp/core-systemd.install; post_upgrade "$1" "$2"','original-complete-systemd-post-upgrade','262-1.2'if installed else states()[0]['systemd'],states()[0]['systemd']if installed else'262-1.2'])
   for argv in(('/usr/bin/pacman','--version'),('/usr/lib/systemd/systemd','--version'),('/usr/bin/udevadm','--version'),('/usr/bin/pacman','-Dk'),('/usr/bin/pacman','-Q')):result.append(['/usr/bin/chroot',root,*argv])
   if installed:
    result.append(['/usr/bin/chroot',root,'/usr/bin/ukify','--version'])
    for program in('test-id128','test-prioq','test-list'):result.append(['/usr/bin/chroot',root,'/usr/lib/systemd/tests/unit-tests/'+program])
   result.append(['/usr/bin/chroot',root,'/usr/bin/ldconfig'])
 result.append(['/usr/bin/gpgconf','--homedir','/tmp/core-public-gpg','--kill','all']);need(len(result)==127,'complete fixed command arithmetic');return result


def graph_exports(directory,index,child):
 """Require every complete bounded raw map, including immutable source readbacks."""
 import gzip,io
 directory=Path(directory);result={}
 for case,row in child['cases'].items():
  for label,record in row['snapshots'].items():
   need(record['file']==label+'-root.json.gz','exact graph export member')
   compressed=read(directory/record['file'],64*1024**2);need(pin(compressed)==record['compressed'],'whole compressed graph byte join')
   with gzip.GzipFile(fileobj=io.BytesIO(compressed))as stream:raw=stream.read(256*1024**2+1)
   need(len(raw)<=256*1024**2 and pin(raw)==record['raw'],'whole bounded expanded graph byte join');value=json.loads(raw)
   need(value['complete']is True and set(value['unsupported_counts'])<={'absolute-symlink','auxiliary-present'}and value['security_capabilities']==index['source_capabilities'],'complete graph and every capability retained')
   need(type(value['nodes'])is dict and len(value['nodes'])<=500000,'whole finite node map')
   if label.endswith(('-source-before','-source-after')):need(hashlib.sha256(json.dumps(value['nodes'],sort_keys=True).encode()).hexdigest()==index['source_nodes_sha256'],'unchanged complete original574 source node map')
   result[label]=value
 need(len(result)==22,'all22 complete source/copy/stage graph exports')
 import fixture as F
 for case,row in child['cases'].items():F.replay(directory,result,case,row)
 return result
