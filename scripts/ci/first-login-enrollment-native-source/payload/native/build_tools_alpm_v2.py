# SPDX-License-Identifier: MIT
"""Owned image actor. Failure carriers persist DATA; the consumer still rejects FAIL."""
import argparse,base64,json,os,pwd,re,shutil,signal,stat,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import build_tools_tools_v2 as T
need=T.need
PREFIX=T.PREFIX
SOURCE=T.SOURCE
STORE=T.STORE
PASS='PASS_FIRST_LOGIN_ENROLLMENT_NATIVE_ALPM_COMPONENT'
TEST_UID='TEST ONLY build-tools <build-tools@test.invalid>'
def prepare(root,context,map_hash):
 from common import verify_source
 root,context=Path(root),Path(context);manifest=verify_source(root,map_hash)
 target=context/'first-login-enrollment-alpm-v1'/'source';target.mkdir(parents=True)
 for name in sorted(set(manifest['files'])|{'native/source-map.json'}):
  source=root/name;out=target/name;out.parent.mkdir(parents=True,exist_ok=True)
  shutil.copyfile(source,out);out.chmod(stat.S_IMODE(source.stat().st_mode))
 return target

def dockerfile(base,map_hash):
 need(re.fullmatch('[0-9a-f]{64}',map_hash or ''),'explicit source-map checksum')
 ending='USER alarm\nWORKDIR /tmp\n'
 need(base.endswith(ending) and base.count(ending)==1,'exact genuine191 image suffix; no fallback')
 script=('test "$BASHPID" -eq 1 || exit 125; '
  '/usr/bin/python3 -I -B /opt/native-first-login-enrollment-alpm-v1/source/native/build_tools_alpm_v2.py '
  '--inside-image --retain-failure-image --map-sha256 '+map_hash+
  ' & build_tools_owner=$!; build_tools_status=0; wait "$build_tools_owner" || build_tools_status=$?; exit "$build_tools_status"')
 return base[:-len(ending)]+('COPY first-login-enrollment-alpm-v1/source/ /opt/native-first-login-enrollment-alpm-v1/source/\n'
  +'RUN '+json.dumps(['/usr/bin/bash','--noprofile','--norc','-p','-c',script])+'\n'+ending)

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
         and trust.parent.name.startswith('build-tools-test-'),'owned TEST trust path only')
    return ('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n'
            'GPGDir = '+str(trust)+'\nHookDir = /builder-disabled-hooks\n')


def retire_homes(run,homes,work):
    """Best-effort complete cleanup; never raises over the primary failure."""
    work=Path(work);failures=[];retired=[];no_sockets=True
    try:
        need(work.parent==Path('/tmp') and work.name.startswith('build-tools-test-') and not work.is_symlink(),'owned private cleanup directory')
        identity=work.stat();need(stat.S_ISDIR(identity.st_mode) and stat.S_IMODE(identity.st_mode)==0o700,'private directory identity/mode')
    except BaseException as error:
        return dict(homes_retired=False,no_sockets=False,private_directory_absent=False,failures=['ownership:'+type(error).__name__])
    for home in homes:
        home=Path(home);okay=True
        for step,argv,expected in (
            ('retire-'+home.name,['/usr/bin/gpgconf','--homedir',str(home),'--kill','all'],0),
            ('no-autostart-'+home.name,['/usr/bin/gpg-connect-agent','--homedir',str(home),'--no-autostart','/bye'],0)):
            try:
                need(home.parent==work and home.name in ('signing','trust') and not home.is_symlink(),'owned GPG home')
                raw=run(step,argv,expected)
                if step.startswith('no-autostart-'):
                    need(raw==b'gpg-connect-agent: no gpg-agent running in this session\n','complete exact TEST no-agent diagnostic required')
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





def retain_first_failure(scope,report):
 """Bound original failing command/log identity; no second actor authority."""
 try:
  rows=report.get('commands',[]);failure=report.get('first_failure')
  need(type(rows) is list and len(rows)<=320 and type(failure) is dict,'bounded failure identity')
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



def retain_exception(commands,scope,step,argv,cwd,expected,error,before):
 """DATA only when Commands lacks a row; never wait, probe or signal."""
 if len(commands.records)!=before:return
 name='%03d-%s.log'%(before,step);path=scope/name
 raw=T.ordinary(path,1024**2) if path.exists() else b''
 if not path.exists():path.write_bytes(raw)
 commands.records.append(dict(step=step,argv=list(map(str,argv)),cwd=str(cwd),expected=expected,success=False,log=name,log_pin=T.data_pin(raw),supervision=None,channels='stdout+stderr combined in pipe order',exception_type=type(error).__name__,output_state='UNKNOWN_IF_SUPERVISION_DID_NOT_RETURN',exception_retention='DATA_ONLY_NO_SECOND_WAIT_OR_SIGNAL_AUTHORITY'))
 (scope/'commands.json').write_bytes(T.encoded(commands.records))

def unknown_image_build_context(map_hash,reason='NO_RETAINED_CONTEXT'):
 """Unavailable build policy stays explicit DATA; it grants no actor authority."""
 need(type(map_hash)is str and re.fullmatch('[0-9a-f]{64}',map_hash) is not None,
      'exact image-build context map required')
 need(reason in ('NO_RETAINED_CONTEXT','CONTEXT_DATA_REFUSED'),'fixed image-build context absence reason')
 return dict(schema=1,status='UNKNOWN',domain='IMAGE_BUILD_STAGE',source_map_sha256=map_hash,
             reason=reason,evidence=None,values=None,native_acceptance='NOT_ADMITTED')


def image_build_context(value,map_hash,command_index,log,log_pin):
 """Copy one already captured context log; never resample the launcher or daemon."""
 result=unknown_image_build_context(map_hash)
 keys={'schema','status','mode','source_map_sha256','before','syscall','after','scope',
       'namespace_acceptance','native_acceptance'}
 need(type(value)is dict and set(value)==keys and type(value['schema'])is int and value['schema']==1
      and value['status']=='NAMESPACE_PREREQUISITE_DATA_ONLY'and value['mode']=='context'
      and value['source_map_sha256']==map_hash and value['syscall']is None
      and value['scope']=='OWN_BUILD_ACTOR_SELF_ONLY_NO_CHILD_OR_GLOBAL_MUTATION'
      and value['namespace_acceptance']=='NOT_ESTABLISHED'and value['native_acceptance']=='NOT_ADMITTED',
      'same-map captured image-build context only')
 context={'uid','euid','gid','egid','cwd','groups','group_count','groups_truncated','status_fields',
          'status_state','namespaces','maps','policy','lsm','mounts','bwrap'}
 need(type(value['before'])is dict and set(value['before'])==context and value['before']==value['after'],
      'complete unchanged captured image-build context required')
 need(type(command_index)is int and 0<=command_index<160 and type(log)is str
      and re.fullmatch(r'[0-9]{3}-namespace-[ab]-context\.log',log) is not None
      and log.startswith('%03d-'%command_index),'provided original context command/log role required')
 need(type(log_pin)is dict and set(log_pin)=={'bytes','sha256'}and type(log_pin['bytes'])is int
      and 0<log_pin['bytes']<=32768 and type(log_pin['sha256'])is str
      and re.fullmatch('[0-9a-f]{64}',log_pin['sha256']) is not None,'bounded original context log pin required')
 raw=json.dumps(value,sort_keys=True,allow_nan=False).encode()
 need(len(raw)<=32768,'captured image-build context32KiB cap')
 result.update(status='OBSERVED',reason=None,
               evidence=dict(command_index=command_index,log=log,log_pin=dict(log_pin)),
               values=json.loads(json.dumps(value['before'],sort_keys=True,allow_nan=False)))
 return result


NS_OBSERVATION_MODES=('context','user','mount','user_mount','user_net','user_mount_net')




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



def export(output,map_hash):
 """Bounded DATA export even when the original image-stage operation failed."""
 from common import verify_source
 verify_source(Path(__file__).resolve().parents[1],map_hash)
 output=Path(output).absolute();scope=STORE/'journey'/'first-login-enrollment-alpm-v1'
 need(os.getuid()==os.geteuid()!=0 and not os.path.lexists(output) and not any(p.is_symlink() for p in output.parents),'unprivileged fresh DATA export')
 raw=T.ordinary(scope/'result.json',4*1024**2);report=json.loads(raw)
 need(report.get('schema_version')==1 and report.get('operation')==T.OPERATION and report.get('source_map_sha256')==map_hash,'same-source lifecycle DATA identity')
 commands_raw=T.ordinary(scope/'commands.json',4*1024**2);commands=json.loads(commands_raw)
 need(type(commands) is list and len(commands)<=320 and commands==report['commands'],'finite standalone command index join')
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


def inside(source,map_hash):
 source=Path(source)
 need(os.getpid()>1 and os.getppid()==1 and os.getuid()==os.geteuid()==0 and
      os.uname().machine=='aarch64' and source==SOURCE and Path('/builder-packages.lock').is_file(),
      'owned disposable native image; direct Python child of Bash PID1 only')
 from common import verify_source
 verify_source(source,map_hash);need(not STORE.exists(),'fresh fixed evidence store')
 policy,base=T.source_policy(source)
 need(Path('/builder-packages.lock').read_bytes()==base,'original349 image inventory')
 scope=STORE/'journey'/T.OPERATION;scope.mkdir(parents=True)
 report=dict(schema_version=1,operation=T.OPERATION,status='FAIL',source_map_sha256=map_hash,
  contract=T.pin(source/'native/build-tools-contract-v2.json'),stages=[],inventory={},payloads={},builds={},
  comparisons={},signatures={},business={},commands=[],temporary_homes=[],first_failure=None,
  signature_policy=dict(SigLevel='Required',LocalFileSigLevel='Required'),
  native=dict(architecture=os.uname().machine,page_bytes=os.sysconf('SC_PAGE_SIZE'),execution='OWNED_IMAGE_BUILD_STAGE',physical_M2='NOT_RUN',release='NOT_ADMITTED'),
  process_layout=dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=os.getpid(),python_ppid=os.getppid(),status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD'),
  image_build_context=unknown_image_build_context(map_hash),
  cleanup=dict(homes_retired=False,no_sockets=False,private_directory_absent=False,failures=['INITIALIZATION_NOT_COMPLETED']))
 work=None;commands=None;primary=None;pacman=None;baseline=None;baseline_reasons=None;phase='initialize'
 save_result(scope,report)
 try:
  protected={**policy['dependency']['payload_files'],**{name:row for recipe in policy['recipes'].values() for name,row in recipe['payload_files'].items()}}
  need(all(not os.path.lexists('/'+name) for name in protected),'candidate/dependency payloads initially absent')
  work=Path(tempfile.mkdtemp(prefix='build-tools-test-',dir='/tmp'));work.chmod(0o700)
  signing,trust=work/'signing',work/'trust'
  for home in (signing,trust,work/'command-home'):home.mkdir(mode=0o700)
  report['temporary_homes']=[str(signing),str(trust)]
  alarm=pwd.getpwnam('alarm');W=T.load_workflow(source,policy)
  commands=W.Commands(scope,work/'command-home','/usr/bin:/bin',timeout=180,total=450,max_output=1024**2)
  report['commands']=commands.records
  def run(step,argv,expected=0,cwd=None):
   nonlocal phase
   phase=step;before=len(commands.records)
   need(len(commands.records)<320,'finite two-package command row cap')
   try:return commands.run(step,list(map(str,argv)),work if cwd is None else Path(cwd),expected)
   except BaseException as error:
    preserve_command_failure(commands,scope,report,step,argv,work if cwd is None else cwd,expected,error,before);raise
  def inventory(step,versions):
   actual=b''.join(sorted(run(step,['/usr/bin/pacman','-Q']).splitlines(keepends=True)))
   expected=T.inventory_expected(base,versions)
   need(actual==expected,'exact complete native package inventory: '+step)
   report['inventory'][step]=dict(**T.data_pin(actual),count=len(actual.splitlines()),versions=versions)
  def reasons(step):
   return {key:b''.join(sorted(run(step+'-'+key,['/usr/bin/pacman',flag]).splitlines(keepends=True)))
           for key,flag in (('explicit','-Qqe'),('dependencies','-Qqd'))}
  baseline=protected_state();inventory('baseline-inventory',{});baseline_reasons=reasons('baseline-reasons')
  report['install_reasons_before']={key:T.data_pin(raw) for key,raw in baseline_reasons.items()}
  recipes=PREFIX/'build-inputs';dependency=T.extract_recipes(source,recipes,policy)
  gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(signing),'--no-auto-key-retrieve','--pinentry-mode','loopback','--passphrase','']
  run('generate-test-key',gpg+['--quick-generate-key',TEST_UID,'ed25519','sign','1d'])
  listing=run('test-primary-fingerprint',gpg+['--with-colons','--list-keys']).decode()
  fingerprints=[line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
  need(len(fingerprints)==1 and re.fullmatch('[0-9A-F]{40}',fingerprints[0]),'one explicit TEST primary')
  fingerprint=fingerprints[0];report['fingerprint']=fingerprint
  public=work/'TEST-public.asc';public.write_bytes(run('export-only-test-public',gpg+['--armor','--export',fingerprint]))
  verifier=['/usr/bin/gpg','--batch','--no-options','--homedir',str(trust),'--no-auto-key-retrieve']
  run('sign-setup8',gpg+['--local-user',fingerprint,'--output',str(dependency)+'.sig','--detach-sign',str(dependency)])
  unknown=run('untrusted-signature-control',verifier+['--status-fd=1','--verify',str(dependency)+'.sig',str(dependency)],'nonzero')
  need(b'NO_PUBKEY' in unknown,'unknown TEST key refusal')
  run('import-only-test-public',verifier+['--import',str(public)])
  ownertrust=work/'ownertrust.txt';ownertrust.write_text(fingerprint+':6:\n')
  run('trust-only-test-primary',verifier+['--import-ownertrust',str(ownertrust)])
  status=run('verify-setup8',verifier+['--status-fd=1','--verify',str(dependency)+'.sig',str(dependency)]).decode()
  strict_signature(status,fingerprint)
  report['signatures']['setup8']=dict(signer=fingerprint,status=status,archive=T.pin(dependency),signature=T.pin(Path(str(dependency)+'.sig')))
  report['public_key']=dict(**T.pin(public),text=public.read_text('ascii'));report['stages'].append('signing')
  config=work/'pacman.conf';config.write_text(test_config(trust));pacman=['--config',str(config)]
  report['signature_config']=T.pin(config);run('required-signature-config',['/usr/bin/cat',str(config)])
  run('base-dependency-check',['/usr/bin/pacman',*pacman,'-T','python>=3.11','gnupg','pacman','coreutils','libarchive','bubblewrap'])
  run('install-setup8',['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-U',str(dependency)])
  dep_versions={'cachy-asahi-setup':'0.3.0-1'};inventory('dependency-inventory',dep_versions)
  report['payloads']['dependency']=T.check_payload(policy['dependency'],run,pacman,'setup8')
  report['stages'].append('dependency')
  archives={}
  for kind in T.KINDS:
   recipe=policy['recipes'][kind]
   run('declared-dependencies-'+kind,['/usr/bin/pacman',*pacman,'-T',*recipe['depends'],*recipe['makedepends'],*recipe['checkdepends']])
   archives[kind]=T.build_pair(run,source,recipes,kind,policy,alarm,report)
   report['comparisons'][kind]=T.compare_archives(run,archives[kind],kind,policy,map_hash)
   report['stages'].append(kind+'-compare')
  for kind in T.KINDS:
   report['signatures'][kind]={}
   for label in ('a','b'):
    archive=archives[kind][label];run('sign-'+kind+'-'+label,gpg+['--local-user',fingerprint,'--output',str(archive)+'.sig','--detach-sign',str(archive)])
    step='verify-'+kind+'-'+label
    status=run(step,verifier+['--status-fd=1','--verify',str(archive)+'.sig',str(archive)]).decode();strict_signature(status,fingerprint)
    report['signatures'][kind][label]=dict(signer=fingerprint,status=status,verify_step=step,archive=T.pin(archive),signature=T.pin(Path(str(archive)+'.sig')))
  first=archives['first-login']['a'];tampered=work/'tampered.pkg.tar.zst';tampered.write_bytes(first.read_bytes()+b'tamper')
  bad=run('tampered-signature-control',verifier+['--status-fd=1','--verify',str(first)+'.sig',str(tampered)],'nonzero')
  need(b'BADSIG' in bad or b'ERRSIG' in bad,'tampered signature refusal');report['stages'].append('sign-candidates')
  versions={**dep_versions,**{recipe['name']:recipe['version'] for recipe in policy['recipes'].values()}}
  for label,install,remove in (('a','install','remove'),('b','reinstall','remove-again')):
   run(install,['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-U',*[str(archives[kind][label]) for kind in T.KINDS]])
   inventory(install+'-inventory',versions)
   report['payloads'][install]={kind:T.check_payload(policy['recipes'][kind],run,pacman,install+'-'+kind) for kind in T.KINDS}
   report['stages'].append(install)
   report['business'][install]=T.business(run,source,policy,work,alarm,report,signing,fingerprint,install)
   report['stages'].append('commands' if label=='a' else 'commands-reinstalled')
   run(remove,['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-R',*[policy['recipes'][kind]['name'] for kind in T.KINDS]])
   inventory(remove+'-inventory',dep_versions)
   need(all(not os.path.lexists('/'+name) for recipe in policy['recipes'].values() for name in recipe['payload_files']),'all20+ candidate payload leaves removed')
   report['stages'].append(remove)
  run('remove-setup8',['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-R','cachy-asahi-setup'])
  inventory('final-inventory',{});need(all(not os.path.lexists('/'+name) for name in protected),'all candidate and dependency payload absent')
  report['stages'].append('dependency-remove')
  restored=reasons('restored-reasons');need(restored==baseline_reasons,'exact original install reasons restored')
  report['install_reasons_after']={key:T.data_pin(raw) for key,raw in restored.items()};report['stages'].append('restore')
 except BaseException as error:
  primary=error
  if report['first_failure'] is None:report['first_failure']=dict(phase=phase,type=type(error).__name__,message=str(error)[:1024],command_index=len(report['commands'])-1)
  report['failure']=dict(report['first_failure']);retain_first_failure(scope,report)
 finally:
  try:
   failures=[]
   if commands is not None and work is not None:
    cleanup_commands=W.Commands(scope,work/'command-home','/usr/bin:/bin',timeout=20,total=90,max_output=1024**2)
    cleanup_commands.records=commands.records
    def clean_run(step,argv,expected=0):
     before=len(cleanup_commands.records)
     try:return cleanup_commands.run(step,list(map(str,argv)),work,expected)
     except BaseException as error:
      retain_exception(cleanup_commands,scope,step,argv,work,expected,error,before);raise
    if primary is not None and pacman is not None:
     try:
      actual=b''.join(sorted(clean_run('cleanup-inventory',['/usr/bin/pacman','-Q']).splitlines(keepends=True)))
      names=[policy['recipes'][kind]['name'] for kind in T.KINDS]+['cachy-asahi-setup']
      installed=[name for name in names if any(line.startswith((name+' ').encode()) for line in actual.splitlines())]
      if installed:clean_run('cleanup-remove',['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-R',*installed])
      need(b''.join(sorted(clean_run('cleanup-restored-inventory',['/usr/bin/pacman','-Q']).splitlines(keepends=True)))==base,'failure cleanup restores349')
     except BaseException as error:failures.append('ALPM-restore:'+type(error).__name__)
    report['cleanup']=T.retire_private(clean_run,work,report['temporary_homes']);report['cleanup']['failures']+=failures
   elif work is not None:
    need(work.parent==Path('/tmp') and work.name.startswith('build-tools-test-'),'known unlaunched private directory')
    shutil.rmtree(work);report['cleanup']=dict(homes_retired=True,no_sockets=True,private_directory_absent=True,failures=[])
   if baseline is not None:
    after=protected_state();report['restore']={name:dict(before=value,after=after[name],unchanged=value==after[name]) for name,value in baseline.items()}
    need(all(value['unchanged'] for value in report['restore'].values()),'complete DB/home/trust/config/cache restoration')
   primary=primary_failure(primary,report['cleanup'])
   if primary is None:
    report['stages'].append('cleanup')
    need(report['stages']==list(T.STAGES),'complete ordered pair/lifecycle/journey/cleanup stages')
    report['status']=PASS
  except BaseException as later:
   report['status']='FAIL';report['cleanup'].setdefault('failures',[]).append('cleanup-unexpected:'+type(later).__name__)
   if primary is None:primary=later
  report['commands']=[] if commands is None else commands.records;report['phase']=phase
  if primary is not None:
   if report['first_failure'] is None:report['first_failure']=dict(phase=phase,type=type(primary).__name__,message=str(primary)[:1024],command_index=None)
   report['status']='FAIL';report['failure']=dict(report['first_failure']);retain_first_failure(scope,report)
  final_result(scope,report)
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
