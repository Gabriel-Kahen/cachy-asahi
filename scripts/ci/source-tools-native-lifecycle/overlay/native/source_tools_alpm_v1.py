# SPDX-License-Identifier: MIT
"""Owned image actor. Failure carriers persist DATA; the consumer still rejects FAIL."""
import argparse,base64,json,os,pwd,re,shutil,signal,stat,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import source_tools_tools_v1 as T
need=T.need
PREFIX=T.PREFIX
SOURCE=T.SOURCE
STORE=T.STORE
PASS='PASS_SOURCE_TOOLS_NATIVE_ALPM_COMPONENT'
TEST_UID='TEST ONLY source-tools <source-tools@test.invalid>'
def prepare(root,context,map_hash):
 from common import verify_source
 root,context=Path(root),Path(context);manifest=verify_source(root,map_hash)
 target=context/'source-tools-alpm-v1'/'source';target.mkdir(parents=True)
 for name in sorted(set(manifest['files'])|{'native/source-map.json'}):
  source=root/name;out=target/name;out.parent.mkdir(parents=True,exist_ok=True)
  shutil.copyfile(source,out);out.chmod(stat.S_IMODE(source.stat().st_mode))
 return target

def dockerfile(base,map_hash):
 need(re.fullmatch('[0-9a-f]{64}',map_hash or ''),'explicit source-map checksum')
 ending='USER alarm\nWORKDIR /tmp\n'
 need(base.endswith(ending) and base.count(ending)==1,'exact genuine191 image suffix; no fallback')
 return base[:-len(ending)]+('COPY source-tools-alpm-v1/source/ /opt/native-source-tools-alpm-v1/source/\nRUN /usr/bin/python3 -I -B /opt/native-source-tools-alpm-v1/source/native/source_tools_alpm_v1.py --inside-image --retain-failure-image --map-sha256 '+map_hash+'\n'+ending)

def strict_signature(status,fingerprint):
    need(re.fullmatch('[0-9A-F]{40}',fingerprint or ''),'explicit TEST primary fingerprint')
    rows=[line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    forbidden={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','TRUST_NEVER','TRUST_UNDEFINED'}
    need(not any(row and row[0] in forbidden for row in rows),'bad/expired/revoked/unknown TEST signature refused')
    valid=[row for row in rows if row and row[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint,'exact TEST primary signer required')
    need(any(row and row[0]=='TRUST_ULTIMATE' for row in rows),'explicitly trusted TEST primary required')


def test_config(trust):
    trust=Path(trust)
    need(trust.is_absolute() and trust.name=='trust' and trust.parent.parent==Path('/tmp')
         and trust.parent.name.startswith('source-tools-test-'),'owned TEST trust path only')
    return ('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n'
            'GPGDir = '+str(trust)+'\nHookDir = /builder-disabled-hooks\n')


def retire_homes(run,homes,work):
    """Best-effort complete cleanup; never raises over the primary failure."""
    work=Path(work);failures=[];retired=[];no_sockets=True
    try:
        need(work.parent==Path('/tmp') and work.name.startswith('source-tools-test-') and not work.is_symlink(),'owned private cleanup directory')
        identity=work.stat();need(stat.S_ISDIR(identity.st_mode) and stat.S_IMODE(identity.st_mode)==0o700,'private directory identity/mode')
    except BaseException as error:
        return dict(homes_retired=False,no_sockets=False,private_directory_absent=False,failures=['ownership:'+type(error).__name__])
    for home in homes:
        home=Path(home);okay=True
        for step,argv,expected in (
            ('retire-'+home.name,['/usr/bin/gpgconf','--homedir',str(home),'--kill','all'],0),
            ('no-autostart-'+home.name,['/usr/bin/gpg-connect-agent','--homedir',str(home),'--no-autostart','/bye'],'nonzero')):
            try:
                need(home.parent==work and home.name in ('signing','trust') and not home.is_symlink(),'owned GPG home')
                run(step,argv,expected)
            except BaseException as error:okay=False;failures.append(step+':'+type(error).__name__)
        try:
            sockets=any(stat.S_ISSOCK(path.lstat().st_mode) for path in home.rglob('*'))
            need(not sockets,'scoped GPG socket remains')
        except BaseException as error:okay=False;no_sockets=False;failures.append('sockets-'+home.name+':'+type(error).__name__)
        if okay:retired.append(home.name)
    try:
        current=work.stat();need((current.st_dev,current.st_ino)==(identity.st_dev,identity.st_ino) and not work.is_symlink(),'private cleanup identity changed')
        shutil.rmtree(work)
    except BaseException as error:failures.append('private-directory:'+type(error).__name__)
    return dict(homes_retired=set(retired)=={'signing','trust'},no_sockets=no_sockets,
                private_directory_absent=not os.path.lexists(work),failures=failures)


def primary_failure(primary,cleanup):
    if primary is not None:return primary
    if cleanup['failures'] or not all(cleanup[k] for k in ('homes_retired','no_sockets','private_directory_absent')):
        return ValueError('scoped TEST signing/trust cleanup unqualified')
    return None


def check_result(raw):
 """Require the unchanged recipe's three positive JSON results, not a test echo."""
 need(type(raw) is bytes and len(raw)<=1024**2 and b'Starting check()' in raw,
      'actual bounded original makepkg check() log')
 rows=[]
 for line in raw.splitlines():
  if line.startswith(b'{'):
   value=json.loads(line);need(type(value) is dict,'check JSON object');rows.append(value)
 need(len(rows)==3 and rows[0]==dict(payload_files=None,private_source_files=11,status='PASS')
      and rows[1]==dict(payload_files=17,private_source_files=11,status='PASS'),
      'exact source and installed payload checker results')
 result=rows[2];workflow=result.get('workflow',{})
 need(result.get('status')=='PASS' and result.get('staged_payload_files')==17
      and result.get('checkout_hidden') is True and result.get('moved_prefix') is True
      and result.get('network_namespace')=='loopback-only'
      and result.get('removal')=='EXACT_FILE_INVERSE_USER_CONTENT_PRESERVED'
      and result.get('alpm_installation')==result.get('native_build')=='NOT_RUN'
      and workflow.get('status')=='PASS' and workflow.get('controls')==17
      and workflow.get('exact_contexts')==4 and workflow.get('packages_per_release')==2
      and workflow.get('retained_releases')==2 and workflow.get('source_execution')=='NOT_RUN',
      'actual complete original 17-control moved/offline recipe check')
 need(type(workflow.get('commands')) is list and len(workflow['commands'])==17,
      'all original recipe workflow observations required')
 return result


def retain_first_failure(scope,report):
 """Bound original failing command/log identity; no second actor authority."""
 try:
  rows=report.get('commands',[]);failure=report.get('first_failure')
  need(type(rows) is list and len(rows)<=160 and type(failure) is dict,'bounded failure identity')
  index=failure.get('command_index');row=rows[index] if type(index) is int and 0<=index<len(rows) else None
  data=dict(status='UNKNOWN',command_index=index,supervision=None,log=None)
  if row is not None and row.get('success') is False:
   need(len(T.encoded(row))<=16*1024,'failure command row cap')
   name=row.get('log');need(type(name) is str and re.fullmatch(r'[0-9]{3}-[A-Za-z0-9._+-]{1,96}\.log',name),'fixed failure log basename')
   raw=T.ordinary(scope/name,1024**2);need(T.data_pin(raw)==row.get('log_pin'),'original first-failure log pin')
   data=dict(status='RETAINED_ORIGINAL_COMMAND_DATA',command_index=index,command=row,
             supervision=row.get('supervision'),log=dict(name=name,**T.data_pin(raw)))
  report['first_failure_data']=data
 except BaseException as error:
  report['first_failure_data']=dict(status='UNKNOWN',reason=type(error).__name__)
 try:save_result(scope,report)
 except BaseException as error:
  report.setdefault('retention_failures',[]).append('first-failure:'+type(error).__name__)


def preserve_command_failure(commands,scope,report,step,argv,cwd,expected,error,before):
 """Retain immediately and preserve original exception identity over DATA errors."""
 try:retain_exception(commands,scope,step,argv,cwd,expected,error,before)
 except BaseException as later:report.setdefault('retention_failures',[]).append('command:'+type(later).__name__)
 report['commands']=commands.records
 if report.get('first_failure') is None:
  report['first_failure']=dict(phase=step,type=type(error).__name__,message=str(error)[:1024],command_index=len(commands.records)-1)
 retain_first_failure(scope,report)


def build_pair(run,source,recipes,policy,alarm,report):
 """Two fresh inodes, one stable logical path; never rewrite metadata."""
 result={};config=source/policy['makepkg_config']['path'];slot=PREFIX/'build-current';seen=set()
 for label in ('a','b'):
  directory=recipes/label
  need(not os.path.lexists(slot),'fresh fixed build slot')
  need(set(p.name for p in directory.iterdir())==set(policy['recipe']['source_files']),'separate clean exact recipe tree')
  identity=directory.stat();key=(identity.st_dev,identity.st_ino)
  need(key not in seen,'independent source directory identity');seen.add(key)
  for path in (directory,*directory.iterdir()):os.chown(path,alarm.pw_uid,alarm.pw_gid)
  item=dict(label=label,version=T.VERSION,recipe_sha256=policy['recipe']['source_files']['PKGBUILD']['sha256'],build_step='build-'+label,check_invoked=False,check_tests=0,check_policy='POSITIVE_CHECK_NO_NOCHECK',build_directory=dict(logical=str(slot),retained=str(directory),identity=dict(device=key[0],inode=key[1]),initial_files=sorted(policy['recipe']['source_files'])))
  report['builds'][label]=item;directory.rename(slot);primary=None
  try:
   argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(slot),'PKGDEST='+str(slot),'SRCDEST='+str(slot),'BUILDDIR='+str(slot),'SOURCE_DATE_EPOCH='+policy['build_pair']['source_date_epoch'],'PACKAGER='+policy['build_pair']['packager'],'/usr/bin/makepkg','--cleanbuild','--nodeps','--nosign','--noconfirm','--config',str(config)]
   raw=run('build-'+label,argv,cwd=slot);item['check_invoked']=b'Starting check()' in raw
   check=check_result(raw);need(item['check_invoked'],'actual positive original check() required')
   item['check_tests']=17;item['check_result']=T.data_pin(T.encoded(check));archive=slot/policy['recipe']['archive']
   need(archive.is_file() and not archive.is_symlink(),'actual built archive')
   item['archive']=dict(filename=archive.name,**T.pin(archive));result[label]=directory/archive.name;report['stages'].append('build-'+label)
  except BaseException as error:
   primary=error;raise
  finally:
   try:
    need(not os.path.lexists(directory) and slot.is_dir() and not slot.is_symlink(),'known build tree custody')
    slot.rename(directory)
   except BaseException as later:
    item['source_retirement_failure']=type(later).__name__
    if primary is None:raise
 return result

def retain_exception(commands,scope,step,argv,cwd,expected,error,before):
 """DATA only when Commands lacks a row; never wait, probe or signal."""
 if len(commands.records)!=before:return
 name='%03d-%s.log'%(before,step);path=scope/name
 raw=T.ordinary(path,1024**2) if path.exists() else b''
 if not path.exists():path.write_bytes(raw)
 commands.records.append(dict(step=step,argv=list(map(str,argv)),cwd=str(cwd),expected=expected,success=False,log=name,log_pin=T.data_pin(raw),supervision=None,channels='stdout+stderr combined in pipe order',exception_type=type(error).__name__,output_state='UNKNOWN_IF_SUPERVISION_DID_NOT_RETURN',exception_retention='DATA_ONLY_NO_SECOND_WAIT_OR_SIGNAL_AUTHORITY'))
 (scope/'commands.json').write_bytes(T.encoded(commands.records))

def protected_state():
 roots=dict(alpm_db='/var/lib/pacman',alarm_home='/home/alarm',root_home='/root',global_trust='/etc/pacman.d/gnupg',global_config='/etc/pacman.conf',package_cache='/var/cache/pacman')
 return {name:T.snapshot_receipt(Path(path)) for name,path in roots.items()}

def save_result(scope,report):
 (scope/'commands.json').write_bytes(T.encoded(report['commands']));(scope/'result.json').write_bytes(T.encoded(report))
 for path in scope.iterdir():path.chmod(0o644)
 for directory in (scope,scope.parent,STORE):directory.chmod(0o755)
def final_result(scope,report):
 """A partial write/chmod failure permanently disqualifies the carrier exit."""
 try:save_result(scope,report)
 except BaseException as later:
  report['status']='FAIL';report.setdefault('retention_failures',[]).append('final-export:'+type(later).__name__)
  if report['first_failure'] is None:
   report['first_failure']=dict(phase='final-export',type=type(later).__name__,message='original result DATA could not be persisted',command_index=None)
 return report


def carrier_exit(report,retain_failure_image=False):
 """Never publish a successful image around missing or stale result DATA."""
 if type(report) is not dict or report.get('retention_failures',[]) != []:
  return 1
 if report.get('status')==PASS:
  return 0 if report.get('first_failure') is None and report.get('failure') is None else 1
 return 0 if retain_failure_image and report.get('status')=='FAIL' else 1


def inside(source,map_hash):
 source=Path(source)
 need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and source==SOURCE and Path('/builder-packages.lock').is_file(),'explicit owned disposable native image root only')
 from common import verify_source
 verify_source(source,map_hash);need(not STORE.exists(),'fresh fixed evidence store')
 scope=STORE/'journey'/'source-tools-alpm-v1';scope.mkdir(parents=True)
 report=dict(schema_version=1,operation=T.OPERATION,status='FAIL',source_map_sha256=map_hash,version=T.VERSION,contract=T.pin(source/'native/source-tools-contract-v1.json'),stages=[],inventory={},payloads={},builds={},signatures={},business={},commands=[],signature_policy=dict(SigLevel='Required',LocalFileSigLevel='Required'),native=dict(architecture=os.uname().machine,page_bytes=os.sysconf('SC_PAGE_SIZE'),execution='OWNED_IMAGE_BUILD_STAGE',physical_M2='NOT_RUN',release='NOT_ADMITTED'),first_failure=None,cleanup=dict(homes_retired=False,no_sockets=False,private_directory_absent=False,failures=['INITIALIZATION_NOT_COMPLETED']))
 work=None;commands=None;primary=None;pacman=None;baseline=None;baseline_reasons=None;phase='initialize'
 save_result(scope,report)
 try:
  policy,base=T.source_policy(source)
  need(Path('/builder-packages.lock').read_bytes()==base,'exact genuine191 base349 image')
  need(all(not os.path.lexists('/'+name) for name in policy['recipe']['payload_files']),'17 payload paths initially absent')
  work=Path(tempfile.mkdtemp(prefix='source-tools-test-',dir='/tmp'));work.chmod(0o700)
  signing,trust=work/'signing',work/'trust'
  for home in (signing,trust,work/'command-home'):home.mkdir(mode=0o700)
  alarm=pwd.getpwnam('alarm');W=T.load_workflow(source,policy)
  commands=W.Commands(scope,work/'command-home','/usr/bin:/bin',timeout=180,total=450,max_output=1024**2);report['commands']=commands.records
  def run(step,argv,expected=0,cwd=work):
   nonlocal phase
   phase=step;before=len(commands.records)
   try:return commands.run(step,list(map(str,argv)),Path(cwd),expected)
   except BaseException as error:
    preserve_command_failure(commands,scope,report,step,argv,cwd,expected,error,before);raise
  def inventory(step):return b''.join(sorted(run(step,['/usr/bin/pacman','-Q']).splitlines(keepends=True)))
  def reasons(step):
   return {key:b''.join(sorted(run(step+'-'+key,['/usr/bin/pacman',flag]).splitlines(keepends=True))) for key,flag in (('explicit','-Qqe'),('dependencies','-Qqd'))}
  baseline=protected_state();report['restore']={name:dict(before=value,after=None,unchanged=False) for name,value in baseline.items()}
  need(inventory('baseline-inventory')==base,'actual exact349 initial inventory')
  baseline_reasons=reasons('baseline-reasons');report['install_reasons_before']={k:T.data_pin(v) for k,v in baseline_reasons.items()}
  report['inventory']['baseline']=dict(**T.data_pin(base),count=349,version=None)
  user=PREFIX/'user-data';user.mkdir(mode=0o755);(user/'keep.txt').write_bytes(b'SYNTHETIC user data; preserve across TEST install/remove.\n')
  T._own_tree(user,alarm.pw_uid,alarm.pw_gid);sentinel=T.pin(user/'keep.txt')
  recipes=T.extract_recipes(source,PREFIX/'build-inputs',policy)
  archives=build_pair(run,source,recipes,policy,alarm,report)
  phase='compare';report['comparison']=T.compare_archives(run,archives,policy,map_hash);report['stages'].append('compare')
  gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(signing),'--no-auto-key-retrieve','--pinentry-mode','loopback','--passphrase','']
  run('generate-test-key',gpg+['--quick-generate-key',TEST_UID,'ed25519','sign','1d'])
  listing=run('test-primary-fingerprint',gpg+['--with-colons','--list-keys']).decode()
  fingerprints=[line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
  need(len(fingerprints)==1 and re.fullmatch('[0-9A-F]{40}',fingerprints[0]),'one TEST primary');fingerprint=fingerprints[0]
  public=work/'TEST-public.asc';public.write_bytes(run('export-only-test-public',gpg+['--armor','--export',fingerprint]))
  verifier=['/usr/bin/gpg','--batch','--no-options','--homedir',str(trust),'--no-auto-key-retrieve']
  for label in ('a','b'):
   archive=archives[label];run('sign-'+label,gpg+['--local-user',fingerprint,'--output',str(archive)+'.sig','--detach-sign',str(archive)])
  unknown=run('untrusted-signature-control',verifier+['--status-fd=1','--verify',str(archives['a'])+'.sig',str(archives['a'])],'nonzero')
  need(b'NO_PUBKEY' in unknown,'unknown TEST key refusal')
  run('import-only-test-public',verifier+['--import',str(public)])
  membership=run('trust-key-membership',verifier+['--with-colons','--list-keys']).decode()
  need([line.split(':')[9] for line in membership.splitlines() if line.startswith('fpr:')]==[fingerprint],'trust only TEST primary')
  ownertrust=work/'ownertrust.txt';ownertrust.write_text(fingerprint+':6:\n');run('trust-only-test-primary',verifier+['--import-ownertrust',str(ownertrust)])
  for label in ('a','b'):
   archive=archives[label];step='verify-'+label
   status=run(step,verifier+['--status-fd=1','--verify',str(archive)+'.sig',str(archive)]).decode();strict_signature(status,fingerprint)
   signature=Path(str(archive)+'.sig');report['signatures'][label]=dict(signer=fingerprint,status=status,verify_step=step,signature=dict(**T.pin(signature),base64=base64.b64encode(signature.read_bytes()).decode('ascii')))
  tampered=work/'tampered.pkg.tar.zst';tampered.write_bytes(archives['a'].read_bytes()+b'tamper')
  bad=run('tampered-signature-control',verifier+['--status-fd=1','--verify',str(archives['a'])+'.sig',str(tampered)],'nonzero')
  need(b'BADSIG' in bad or b'ERRSIG' in bad,'tampered signature refusal')
  public_text=public.read_text('ascii');need(public_text.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----') and 'PRIVATE KEY' not in public_text,'public TEST key only')
  report['public_key']=dict(**T.pin(public),text=public_text);report['fingerprint']=fingerprint
  config=work/'pacman.conf';config.write_text(test_config(trust));report['signature_config']=T.pin(config)
  run('required-signature-config',['/usr/bin/cat',str(config)]);pacman=['--config',str(config)];report['stages'].append('sign')
  run('install',['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-U',str(archives['a'])])
  actual=inventory('installed-inventory');need(actual==T.inventory_expected(base,T.VERSION),'exact350 installed inventory')
  report['inventory']['installed']=dict(**T.data_pin(actual),count=350,version=T.VERSION)
  report['payloads']['installed']=T.check_payload('/',policy,run,pacman);report['stages'].append('install')
  report['business']['system']=T.business(run,Path('/usr/bin')/T.NAME,user/'system',alarm.pw_uid,alarm.pw_gid,'system',source,policy);report['stages'].append('commands-system')
  moved=user/'moved-prefix';moved.mkdir()
  for name,item in policy['recipe']['payload_files'].items():
   target=moved/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile('/'+name,target);target.chmod(item['mode'])
   need(T.pin(target)=={k:item[k] for k in ('bytes','sha256')},'moved exact installed payload')
  for target in (moved,*moved.rglob('*')):
   need(not target.is_symlink(),'moved aliases refused');os.chown(target,alarm.pw_uid,alarm.pw_gid)
   if target.is_dir():target.chmod(0o755)
  report['business']['moved']=T.business(run,moved/'usr/bin'/T.NAME,user/'relocated',alarm.pw_uid,alarm.pw_gid,'moved',source,policy);report['stages'].append('commands-moved')
  exports_before=T.snapshot(user);report['exports_before']=T.snapshot_receipt(user)
  run('remove',['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-R',T.NAME])
  actual=inventory('removed-inventory');need(actual==base,'exact349 final inventory')
  report['inventory']['removed']=dict(**T.data_pin(actual),count=349,version=None)
  report['payload_absent']=all(not os.path.lexists('/'+name) for name in policy['recipe']['payload_files'])
  report['private_roots_absent']=all(not os.path.lexists(name) for name in ('/usr/lib/cachy-asahi/source-tools','/usr/share/doc/'+T.NAME,'/usr/share/licenses/'+T.NAME))
  need(report['payload_absent'] and report['private_roots_absent'],'all package files/private roots removed');report['stages'].append('remove')
  after_reasons=reasons('restored-reasons');need(after_reasons==baseline_reasons,'exact reasons restored')
  report['install_reasons_after']={k:T.data_pin(v) for k,v in after_reasons.items()}
  need(T.snapshot(user)==exports_before and T.pin(user/'keep.txt')==sentinel,'fixture/exports preserved')
  report['exports_preserved']=True;report['exports_after']=T.snapshot_receipt(user);report['stages'].append('restore')
 except BaseException as error:
  primary=error
  if report['first_failure'] is None:report['first_failure']=dict(phase=phase,type=type(error).__name__,message=str(error)[:1024],command_index=len(report['commands'])-1)
  report['failure']=dict(report['first_failure']);retain_first_failure(scope,report)
 finally:
  try:
   cleanup_failures=[]
   if commands is not None and work is not None:
    try:
     cleanup_commands=W.Commands(scope,work/'command-home','/usr/bin:/bin',timeout=20,total=90,max_output=1024**2);cleanup_commands.records=commands.records
     def clean_run(step,argv,expected=0):
      before=len(cleanup_commands.records)
      try:return cleanup_commands.run(step,list(map(str,argv)),work,expected)
      except BaseException as error:
       retain_exception(cleanup_commands,scope,step,argv,work,expected,error,before);raise
    except BaseException as error:
     cleanup_failures.append('cleanup-supervisor:'+type(error).__name__)
     def clean_run(step,argv,expected=0):raise ValueError('owned cleanup supervisor unavailable')
    if primary is not None and pacman is not None:
     try:
      actual=b''.join(sorted(clean_run('cleanup-inventory',['/usr/bin/pacman','-Q']).splitlines(keepends=True)))
      if any(line.startswith((T.NAME+' ').encode()) for line in actual.splitlines()):clean_run('cleanup-remove',['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-R',T.NAME])
      need(b''.join(sorted(clean_run('cleanup-restored-inventory',['/usr/bin/pacman','-Q']).splitlines(keepends=True)))==base,'failure cleanup restores349')
     except BaseException as error:cleanup_failures.append('ALPM-restore:'+type(error).__name__)
    cleanup=retire_homes(clean_run,(signing,trust),work);cleanup['failures']+=cleanup_failures;report['cleanup']=cleanup
   elif work is not None:
    try:
     need(work.parent==Path('/tmp') and work.name.startswith('source-tools-test-') and not work.is_symlink(),'known unlaunched private directory')
     shutil.rmtree(work);report['cleanup']=dict(homes_retired=True,no_sockets=True,private_directory_absent=True,failures=[],no_child_launched=True)
    except BaseException as error:report['cleanup']['failures'].append(type(error).__name__)
   if baseline is not None:
    try:
     after=protected_state();report['restore']={name:dict(before=value,after=after[name],unchanged=value==after[name]) for name,value in baseline.items()}
     need(all(value['unchanged'] for value in report['restore'].values()),'complete DB/home/trust/config/cache restoration')
    except BaseException as error:
     report['cleanup']['failures'].append('protected-state:'+type(error).__name__)
     if primary is None:primary=error
   primary=primary_failure(primary,report['cleanup'])
   if primary is None:
    report['stages'].append('cleanup')
    if report['stages']==list(T.STAGES):report['status']=PASS
   report['commands']=[] if commands is None else commands.records;report['phase']=phase
  except BaseException as later:
   report['status']='FAIL'
   report['cleanup'].setdefault('failures',[]).append('cleanup-unexpected:'+type(later).__name__)
   if primary is None:
    primary=later
    report['first_failure']=dict(phase='cleanup',type=type(later).__name__,message=str(later)[:1024],command_index=None)
  report['commands']=[] if commands is None else commands.records
  if primary is not None:
   if report['first_failure'] is None:report['first_failure']=dict(phase='cleanup',type=type(primary).__name__,message=str(primary)[:1024],command_index=None)
   report['status']='FAIL';report['failure']=dict(report['first_failure']);retain_first_failure(scope,report)
  final_result(scope,report) # Bounded originals precede every outer status guard.
 return report

def export(output,map_hash):
 """Bounded DATA export even when the original image-stage operation failed."""
 from common import verify_source
 verify_source(Path(__file__).resolve().parents[1],map_hash)
 output=Path(output).absolute();scope=STORE/'journey'/'source-tools-alpm-v1'
 need(os.getuid()==os.geteuid()!=0 and not os.path.lexists(output) and not any(p.is_symlink() for p in output.parents),'unprivileged fresh DATA export')
 raw=T.ordinary(scope/'result.json',4*1024**2);report=json.loads(raw)
 need(report.get('schema_version')==1 and report.get('operation')==T.OPERATION and report.get('source_map_sha256')==map_hash,'same-source lifecycle DATA identity')
 commands_raw=T.ordinary(scope/'commands.json',4*1024**2);commands=json.loads(commands_raw)
 need(type(commands) is list and len(commands)<=160 and commands==report['commands'],'finite standalone command index join')
 files={'result.json':raw,'commands.json':commands_raw};total=len(raw)+len(commands_raw)
 for row in commands:
  name=row['log'];need(re.fullmatch(r'[0-9]{3}-[A-Za-z0-9._+-]{1,96}\.log',name) and name not in files,'unique command log')
  body=T.ordinary(scope/name,1024**2);need(T.data_pin(body)==row['log_pin'],'original raw log pin')
  total+=len(body);need(total<=24*1024**2,'finite lifecycle DATA total');files[name]=body
 output.mkdir(mode=0o700)
 for name,body in files.items():
  with (output/name).open('xb') as stream:stream.write(body)
  (output/name).chmod(0o600)
 return report

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--inside-image',action='store_true');parser.add_argument('--retain-failure-image',action='store_true');parser.add_argument('--map-sha256',required=True)
 args=parser.parse_args();need(args.inside_image,'explicit owned image operation')
 def cancel(number,frame):raise KeyboardInterrupt('native image actor cancelled')
 handlers={number:signal.signal(number,cancel) for number in (signal.SIGINT,signal.SIGTERM)}
 try:
  value=inside(Path(__file__).resolve().parents[1],args.map_sha256)
  print(json.dumps(dict(status=value['status'],first_failure=value['first_failure'],diagnostic_carrier_only=value['status']!=PASS)),flush=True)
  # A carrier image can retain failed originals; its guest independently requires PASS.
  sys.exit(carrier_exit(value,args.retain_failure_image))
 finally:
  for number,handler in handlers.items():signal.signal(number,handler)
