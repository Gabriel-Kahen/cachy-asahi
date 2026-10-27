#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two unchanged clean builders, one inert split builder, one real removal actor."""
import argparse,fcntl,json,os,platform,re,shutil,signal,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def save(p,v):p.write_bytes(C.encoded(v))
def execute(source,base_dir,out,token):
 source,base_dir,out=map(C.safe,(source,base_dir,out));C.verify_source(source)
 C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and not any(k.startswith('DOCKER_') for k in os.environ),'ordinary local native ARM caller required')
 C.need(not out.exists() and out.parent.is_dir() and all(not out.is_relative_to(p) and not p.is_relative_to(out) for p in (source,base_dir)) and re.fullmatch('[0-9a-f]{32}',token),'fresh disjoint consumer output/token')
 original=C.read(base_dir/'report.json');image=(base_dir/'image-id').read_text().strip();lock=base_dir/'installed-packages.lock';C.need(original.get('status')=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and original['image']==image and re.fullmatch('sha256:[0-9a-f]{64}',image) and C.digest(lock)==C.BASE,'exact owned574 producer required')
 shared=C.load('orphans3_shared_build',source/'scripts/ci/welcome-native/run.py');shared.C=C
 candidate_builder=C.load('orphans03_candidate_build',source/C.LANE/'build_candidate.py')
 common=C.load('orphans3_logged',source/'scripts/virtual/common.py');checks=C.load('orphans3_package_checks',source/'scripts/checks/package_checks.py')
 sys.path[:0]=[str(source/'scripts/build'),str(source/'scripts/checks')];bind=C.load('orphans3_binding',source/'scripts/build/build.py');compare=C.load('orphans3_comparison',source/'scripts/build/compare.py')
 base=shared.inventory(lock.read_text());selected=C.read(source/'scripts/ci/maintained-desktop574-inputs.json');C.need(len(base)==574 and base=={r['name']:r['version'] for r in selected['packages']} and C.PRODUCT not in base,'exact574 inventory required')
 out.mkdir(mode=0o700);lease=os.open(out/'consumer.lock',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_CLOEXEC,0o600);fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB);(out/'home').mkdir(mode=0o700)
 owner=dict(schema_version=1,token=token,image=image,label=C.LABEL,containers=[]);save(out/'owner.json',owner)
 report=dict(status='FAIL',scope='PRIVATE_EXPLICIT_LIVE_CLI_FIXTURE_ONLY',base_image=image,base_count=574,base_lock_sha256=C.digest(lock),ownership_token=token,commands=[],hardware='NOT_RUN',release='NOT_ADMITTED',actual_source=None,actual_ref=None,actual_run=None)
 env=dict(shared.ENV,HOME=str(out/'home'));active=None
 class Owners(list):
  def append(self,name):
   C.need(len(self)<4 and name not in self and re.fullmatch(r'cachy-asahi-product-(?:lifecycle-)?[0-9a-f]{32}',name),'fixed four owned actors');super().append(name);owner['containers']=list(self);save(out/'owner.json',owner)
 containers=Owners();plain=shared.docker
 def docker(*args,**kw):return plain(*args,**kw)+['--label='+C.LABEL+'='+token]
 shared.docker=docker;candidate_builder.docker=docker
 def command(argv,log,seconds):
  nonlocal active
  row=dict(argv=list(map(str,argv)),log=str(log.relative_to(out)),exitcode=None);report['commands'].append(row);save(out/'report.json',report)
  primary=None
  try:
   with common.registered_spawn():
    active=common.LoggedProcess(argv,log,env=env,limit=16*1024**2,owner_signals_only=True)
   code=active.wait_owned(seconds);C.need(code==0,'native command failed: '+log.name)
  except BaseException as error:
   primary=error
   row.update(error_type=type(error).__name__,error=str(error)[:512])
   if active is None:
    row['retirement']=getattr(error,'owned_retirement',dict(ownership='NO_CHILD_HANDLE',leader_reaped=False,observed_returncode=None));row['exitcode']=row['retirement']['observed_returncode']
   raise
  finally:
   cleanup_error=None
   if active is not None:
    try:
     with common.registered_spawn():
      if not active.settled:active.wait_owned(0,cleanup_timeout=5)
    except BaseException as error:
     cleanup_error=error;row.update(cleanup_error_type=type(error).__name__,cleanup_error=str(error)[:512])
     if primary is not None:primary.add_note('owned command cleanup: '+type(error).__name__)
    finally:row.update(exitcode=active.observed_returncode,retirement=active.retirement)
   active=None
   try:save(out/'report.json',report)
   except BaseException as error:
    if primary is not None:primary.add_note('command report save: '+type(error).__name__)
    else:raise
   if cleanup_error is not None and primary is None:raise cleanup_error
 def capture(argv):
  r=subprocess.run(argv,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=30);C.need(r.returncode==0 and len(r.stdout)+len(r.stderr)<=1024**2,'native observer failed');return r.stdout.decode().strip()
 def interrupted(*a):raise TimeoutError('native consumer interrupted/deadline')
 old={s:signal.signal(s,interrupted) for s in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)};signal.setitimer(signal.ITIMER_REAL,1800)
 try:
  C.need(capture(['docker','context','show'])=='default' and json.loads(capture(['docker','context','inspect','default']))[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock' and capture(['docker','info','--format','{{.Architecture}}']) in ('aarch64','arm64') and capture(['docker','image','inspect','--format','{{.Os}}/{{.Architecture}}',image])=='linux/arm64','local native daemon/image required')
  pair=[candidate_builder.build(source,out,base,image,lock,C.PRODUCT,side,selected['source_date_epoch'],command,containers,checks,bind) for side in ('a','b')];comparison=compare.compare(*(r['directory'] for r in pair));C.pair_gate(comparison);save(out/'comparison.json',comparison)
  report['pair']=dict(comparison=comparison,builds=[dict(archive=r['archive'].name,sha256=C.digest(r['archive']),tests=r['tests']) for r in pair])
  directory=out/'fixtures';directory.mkdir();inputs=directory/'inputs';shutil.copytree(source/C.LANE/'fixture',inputs);artifacts=directory/'artifacts';artifacts.mkdir();shutil.copyfile(lock,directory/'expected-packages.lock')
  name='cachy-asahi-product-'+os.urandom(16).hex();containers.append(name)
  command(docker(image,name,artifacts)+['--env=CACHY_ASAHI_CONTAINER=1','--env=SOURCE_DATE_EPOCH='+str(selected['source_date_epoch']),'--mount',f'type=bind,src={inputs},dst=/inputs,readonly','--mount',f'type=bind,src={directory}/expected-packages.lock,dst=/expected-packages.lock,readonly','--mount',f'type=bind,src={source}/scripts/build/container-entry.sh,dst=/builder-entry.sh,readonly','--entrypoint=/bin/bash',image,'/builder-entry.sh'],directory/'build.log',240)
  C.need(shared.inventory((artifacts/'packages.lock').read_text())==base,'fixture builder574 differs');archives=sorted(artifacts.glob('*.pkg.tar.*'));C.need(len(archives)==8,'exact eight inert split archives required');fixtures={}
  for p in archives:
   package=checks.package(p);m=package['metadata']['.PKGINFO'];n=m['pkgname'][0];C.need(not package['errors'] and not package['elf'] and n in C.FIXTURES and n not in fixtures and m['pkgver']==['1-1'] and m['arch']==['any'],'fixed inert fixture identity')
   members={k:v for k,v in package['members'].items() if v['type']!='5' and k not in ('.PKGINFO','.BUILDINFO','.MTREE')}
   expected={'usr/share/orphans3-fixture/'+n+'.txt','usr/share/licenses/'+n+'/LICENSE'};C.need(set(members)==expected and all(r['type']=='0' and r['mode']==0o644 and r['uid']==r['gid']==0 for r in members.values()),'fixed ordinary inert payload only')
   C.need(members['usr/share/licenses/'+n+'/LICENSE']['sha256']==C.digest(inputs/'LICENSE'),'fixture license correspondence');fixtures[n]=dict(archive=p.name,sha256=C.digest(p))
  C.need(set(fixtures)==set(C.FIXTURES),'eight fixture identities required');save(directory/'fixture-packages.json',fixtures);report['fixtures']=fixtures
  context=out/'lifecycle-inputs';context.mkdir();candidate=pair[0]['archive'];shutil.copyfile(candidate,context/candidate.name)
  for p in archives:shutil.copyfile(p,context/p.name)
  signer_api=C.load('orphans3_TEST_signer',source/'scripts/ci/full-development-composition/run.py');signer=signer_api.sign(context,out,[context/candidate.name,*[context/r['archive'] for r in fixtures.values()]])
  key=out/'test-signing';s=key.stat();save(out/'authority.json',dict(directory='test-signing',dev=s.st_dev,ino=s.st_ino,uid=s.st_uid,mode=s.st_mode&0o777,signer=signer))
  subprocess.run(['gpgconf','--homedir',str(key),'--kill','all'],check=True,capture_output=True,timeout=20)
  save(context/'control.json',dict(signer=signer,candidate=dict(archive=candidate.name,sha256=C.digest(candidate)),fixtures=fixtures));save(context/'base.json',base)
  for p in (context,*context.rglob('*')):p.chmod(0o755 if p.is_dir() else 0o644)
  lifecycle_out=out/'lifecycle-output';lifecycle_out.mkdir(mode=0o700);name='cachy-asahi-product-lifecycle-'+os.urandom(16).hex();containers.append(name)
  command(docker(image,name,lifecycle_out,root=True)+['--env=CACHY_ASAHI_ORPHANS03_NATIVE=lifecycle','--mount',f'type=bind,src={context},dst=/inputs,readonly','--mount',f'type=bind,src={source},dst=/source,readonly','--entrypoint=/usr/bin/python3',image,'-I','-B','/source/'+C.LANE+'/lifecycle.py'],out/'lifecycle.log',600)
  life=C.read(lifecycle_out/'lifecycle.json');C.validate_lifecycle(life);report.update(status='PASS_NATIVE_ORPHANS03_PAIR_AND_REAL_PRIVATE_REMOVAL',lifecycle=life)
 except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:1024])
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);save(out/'report.json',report);os.close(lease)
  for s,h in old.items():signal.signal(s,h)
 return int(report['status']!='PASS_NATIVE_ORPHANS03_PAIR_AND_REAL_PRIVATE_REMOVAL')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','base-dir','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--consumer-token',required=True);a=p.parse_args();raise SystemExit(execute(a.source.absolute(),a.base_dir.absolute(),a.output.absolute(),a.consumer_token))
