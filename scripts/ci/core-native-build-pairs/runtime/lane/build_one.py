#!/usr/bin/env python3
"""Build only the explicit new core profile in one disposable native OCI container."""
import argparse,importlib.util,json,os,re,resource,shutil,subprocess,sys
from pathlib import Path
D=Path(__file__).resolve().parents[1]/'core'
PROFILE=D.parent/'effective-profile'
sys.path.insert(0,str(D))
import contract as C
sys.path.insert(0,str(Path(__file__).resolve().parent))
import effective_profile as E
import test_environment as T
import systemd_seccomp as S
ENC=lambda v:json.dumps(v,sort_keys=True,indent=2)+'\n'
def selection(path,profile,kind):
 s=json.loads(C.ordinary(path));cfg,row,m=C.source(profile,kind)
 keys={'schema','scope','image','profile','expected_packages','image_config_sha256','source_date_epoch','root_source_authorization'}
 if set(s)!=keys or s['schema']!=1 or s['scope']!='UNSELECTED_CORE_NATIVE_BUILD_ONLY':raise ValueError('explicit separate build selection required')
 if not isinstance(s['image'],str)or not re.fullmatch(r'(?:[A-Za-z0-9][A-Za-z0-9._:/-]*@)?sha256:[0-9a-f]{64}',s['image']):raise ValueError('genuine pinned native builder image required')
 if s['profile']!=C.pin(C.ordinary(profile/'profile.json')):raise ValueError('selected whole profile differs')
 if not isinstance(s['source_date_epoch'],int)or not 0<=s['source_date_epoch']<2**40:raise ValueError('explicit reproducible epoch required')
 if not isinstance(s['root_source_authorization'],dict)or set(s['root_source_authorization'])!={'path','pin'}:raise ValueError('Root reviewed new source authorization required')
 a=s['root_source_authorization'];raw=C.ordinary(Path(a['path']))
 if C.pin(raw)!=a['pin']:raise ValueError('source authorization pin differs')
 # Caller explicitly selects reviewed source authority; this is not a cryptographic
 # identity assertion or a grant for an old target transaction.
 lock=C.ordinary(Path(s['expected_packages']['path'])).decode()
 if C.pin(lock.encode())!=s['expected_packages']['pin']or not lock or lock!=''.join(sorted(lock.splitlines(keepends=True))):raise ValueError('exact sorted builder lock required')
 if not isinstance(s['image_config_sha256'],dict)or set(s['image_config_sha256'])!={'/etc/makepkg.conf','/etc/pacman.conf'}or any(not re.fullmatch('[0-9a-f]{64}',x)for x in s['image_config_sha256'].values()):raise ValueError('exact image configuration pins required')
 return s,row,m,lock
def safe_retire(name,image):
 """Never remove a foreign same-name object. No global Docker cleanup."""
 checked=subprocess.run(['docker','container','inspect',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 if checked.returncode:
  if 'No such'not in checked.stderr.decode(errors='replace'):raise ValueError('package ownership inspect failed')
  return dict(status='ALREADY_ABSENT',name=name,image=image)
 rows=json.loads(checked.stdout)
 if len(rows)!=1:raise ValueError('package ownership ambiguous')
 row=rows[0];labels=row['Config'].get('Labels')or{}
 if row['Name']!='/'+name or row['Image']!=image or labels.get('org.cachy-asahi.core.package')!=name:raise ValueError('foreign package container preserved')
 r=subprocess.run(['docker','rm','-f',name],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
 if r.returncode:raise ValueError('owned package removal failed')
 return dict(status='OWNED_REMOVED',name=name,image=image,cid=row['Id'],inspect=row,command=['docker','rm','-f',name],returncode=r.returncode,output=r.stdout.decode(errors='replace'))

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--recipe',choices=C.KINDS,required=True);p.add_argument('--selection',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--timeout',type=int,default=14400);p.add_argument('--plan-only',action='store_true');a=p.parse_args()
 out=a.output.resolve();name='cachy-asahi-new-core-'+os.urandom(8).hex();created=False;actor=False;exitcode=1;receipt={'native_build':'NOT_RUN','installation':'NOT_RUN','hardware':'NOT_RUN'}
 try:
  if not 1<=a.timeout<=14400:raise ValueError('build timeout must be 1..14400 seconds')
  E.authorize(D.parent)
  s,row,m,lock=selection(a.selection,PROFILE,a.recipe)
  if out.exists()or out.is_symlink()or (out.is_relative_to(D/'profile')or out.is_relative_to(PROFILE)):raise ValueError('fresh separate output required')
  if any(','in str(x)or'\n'in str(x)for x in(D,out)):raise ValueError('unsafe bind-mount path')
  capture=lambda cmd:subprocess.check_output(cmd,text=True,timeout=30).strip()
  # Plan-only is entirely passive and must not contact Docker.
  if a.plan_only:
   print(ENC(dict(status='REVIEWED_PLAN_ONLY_NO_ACTOR',selection=s,recipe=a.recipe,timeout=a.timeout,source_contract=row)));return 0
  if os.getuid()==0:raise ValueError('non-root host account required')
  image=json.loads(capture(['docker','image','inspect',s['image']]))[0]
  if image['Architecture']!='arm64'or image['Os']!='linux'or capture(['docker','info','--format','{{.Architecture}}'])not in('aarch64','arm64'):raise ValueError('native linux/arm64 Docker server/image required')
  if capture(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']):raise ValueError('package container name collision')
  out.mkdir(mode=0o700);created=True
  shutil.copytree(PROFILE,out/'profile')
  if C.closed(out/'profile')!=C.closed(PROFILE):raise ValueError('source snapshot changed')
  art=out/'artifacts';art.mkdir()
  seccomp=S.prepare(a.recipe,out,art)
  (out/'expected-packages.lock').write_text(lock)
  (out/'expected-config.sha256').write_text(''.join(v+'  '+k+'\n'for k,v in [(k,s['image_config_sha256'][k])for k in('/etc/makepkg.conf','/etc/pacman.conf')]))
  for f in('contract.py','build-deps.py','container-entry.sh'):shutil.copyfile(D/f,out/f)
  catalog=Path(__file__).with_name('docbook_catalog.py');spec=importlib.util.spec_from_file_location('source_owned_private_docbook',catalog);catalog_api=importlib.util.module_from_spec(spec);spec.loader.exec_module(catalog_api)
  (out/'container-entry.sh').write_bytes(catalog_api.entry(C.ordinary(out/'container-entry.sh')));shutil.copyfile(catalog,out/'docbook_catalog.py')
  (out/'container-entry.sh').write_bytes(T.entry(C.ordinary(out/'container-entry.sh')));shutil.copyfile(Path(__file__).with_name('test_environment.py'),out/'test_environment.py');shutil.copytree(Path(__file__).with_name('mechanism'),out/'mechanism')
  command=['docker','run','--rm','--name',name,'--label','org.cachy-asahi.core.package='+name,'--pull=never','--platform','linux/arm64','--user',f'{os.getuid()}:{os.getgid()}','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--pids-limit','2048','--memory','16g','--cpus','4','--network','none','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=16g','--env','CACHY_ASAHI_CORE_CONTAINER=1','--env','CORE_RECIPE='+a.recipe,'--env','CACHY_ASAHI_CORE_CATALOG_OWNER='+name,'--env','SOURCE_DATE_EPOCH='+str(s['source_date_epoch'])]
  command+=T.scratch_args(a.recipe,os.getuid(),os.getgid())
  command+=S.arguments(a.recipe,out/'systemd-seccomp.json')
  mounts=[(out/'profile','/profile',True),(art,'/out',False),(out/'expected-packages.lock','/expected-packages.lock',True),(out/'expected-config.sha256','/expected-config.sha256',True)]+[(out/f,'/'+f,True)for f in('contract.py','build-deps.py','container-entry.sh','docbook_catalog.py','test_environment.py')]+[(out/'mechanism','/mechanism',True)]
  for src,dst,ro in mounts:command+=['--mount',f'type=bind,src={src},dst={dst}'+(',readonly'if ro else'')]
  command+=['--entrypoint','/bin/bash',s['image'],'/container-entry.sh']
  receipt.update(status='BUILDING',systemd_seccomp=seccomp,selection=s,image_inspect=image,command=command,clean_container=name,log_bytes_ceiling=128*1024**2,source=C.closed(out/'profile'),entry={f:C.pin(C.ordinary(out/f))for f in('contract.py','build-deps.py','container-entry.sh','docbook_catalog.py','test_environment.py')},mechanism=C.closed(out/'mechanism'),effective_selection=C.pin(C.ordinary(D.parent/'lane/effective-source-authorization.json')))
  (out/'provenance.json').write_text(ENC(receipt));actor=True
  with(out/'build.log').open('wb')as log:r=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=a.timeout,preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024**2,128*1024**2)))
  S.verify(a.recipe,out)
  if r.returncode:raise ValueError('native makepkg failed; retained build.log: '+str(r.returncode))
  if(art/'packages.lock').read_text()!=lock:raise ValueError('final environment lock differs')
  C.bind_generated(m,C.ordinary(art/'generated.SRCINFO').decode())
  installed=C.installed_descriptions(C.ordinary(art/'installed-descriptions.txt').decode(),lock)
  paths=sorted(art.glob('*.pkg.tar.xz'));reports=[]
  for archive in paths:reports.append(C.inspect_archive(archive,m,row['recipe']['sha256'],lock,dict(buildinfo_installed=installed,install_pin=C.pin(C.ordinary(out/'profile'/a.recipe/'systemd.install'))if a.recipe=='systemd'else None)))
  if len(reports)!=len(m)-1 or{v['name']for v in reports}!=set(m)-{'@base'}:raise ValueError('exact finite output split set differs')
  (out/'validation.json').write_text(ENC(dict(status='NATIVE_BUILD_METADATA_AND_STRUCTURAL_ELF_ONLY',packages=reports,installation='NOT_RUN',Asahi_M2='NOT_RUN',reproducibility='NOT_RUN_SINGLE_BUILD')))
  receipt.update(status='NATIVE_BUILD_METADATA_AND_STRUCTURAL_ELF_ONLY',native_build='PASS',outputs=C.closed(art));exitcode=0
 except(Exception,KeyboardInterrupt)as e:
  receipt.update(status='FAILED',error=str(e));print(str(e),file=sys.stderr);exitcode=1
 finally:
  if actor:
   try:
    # Only this unique private builder may be retired; daemon errors prove nothing.
    receipt['retirement']=safe_retire(name,image['Id'])
    check=subprocess.run(['docker','container','inspect',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    receipt['container_absence']=check.returncode!=0 and ('No such'in check.stderr.decode(errors='replace'))
   except(subprocess.SubprocessError,OSError)as e:
    receipt['container_absence']=False;receipt['retirement_error']=str(e)
   if not receipt['container_absence']:receipt['status']='FAILED_RETIREMENT_UNPROVED'
  if created:(out/'provenance.json').write_text(ENC(receipt))
  if actor and not receipt['container_absence']:exitcode=1
 return exitcode
if __name__=='__main__':sys.exit(main())
