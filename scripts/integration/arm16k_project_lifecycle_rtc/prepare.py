#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Prepare a new exact three-package lifecycle fixture. Never launch a VM."""
import argparse,importlib.util,json,os,re,secrets,shutil,sys,time,traceback,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent


def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module



def output_path(path):
 """Check a fresh ordinary private leaf and its actual parent filesystem."""
 if not path.is_absolute()or '..'in path.parts or not re.fullmatch('[A-Za-z0-9_/.:-]+',str(path)):raise ValueError('ordinary absolute output path required')
 roots=(Path('/tmp'),Path('/dev/shm'))
 root=next((root for root in roots if root in path.parents),None)
 if root is None:raise ValueError('output must be below exact /tmp or /dev/shm root')
 if any(parent.is_symlink()for parent in (path,*path.parents)):raise ValueError('output and ancestors must not be symlinks')
 if path.exists():raise ValueError('fresh output leaf required')
 if not path.parent.is_dir():raise ValueError('existing output parent required')
 parent=path.parent
 while parent!=root:
  info=parent.stat()
  if info.st_uid!=os.getuid()or stat.S_IMODE(info.st_mode)&0o077:raise ValueError('nested output ancestors must be user-owned private directories')
  parent=parent.parent
 if shutil.disk_usage(path.parent).free<3*1024**3:raise ValueError('preparation cap plus2GiB reserve required on actual output filesystem')
 return path


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-prepare-project-lifecycle',action='store_true');p.add_argument('--materials',type=Path,required=True);p.add_argument('--rootfs',type=Path,required=True);p.add_argument('--fresh-signatures',type=Path,required=True);p.add_argument('--signing-receipt',type=Path,required=True);p.add_argument('--kernel-bundle',type=Path,required=True);p.add_argument('--authority',type=Path,required=True);p.add_argument('--authority-sha256',required=True);p.add_argument('--base',type=Path,required=True);p.add_argument('--base-first-boot-report',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 args=p.parse_args()
 if not(args.allow_prepare_project_lifecycle and __debug__ and sys.flags.isolated and os.geteuid()!=0):p.error('isolated ordinary user and explicit fixture preparation required')
 os.umask(0o077);I=load('arm16k_project_input_checks',HERE/'inputs.py');lock,reference,B=I.reference()
 K=load('arm16k_rtc_contracts',HERE/'contracts.py');approval=K.authority(args.authority,args.authority_sha256,HERE/'rtc_actor.py')
 assert approval.get('allow_prepare')is True,'Root preparation authority required'
 bundle=K.kernel(args.kernel_bundle,approval,args.base/'kernel.config');fresh=K.signing(args.signing_receipt,lock)
 out=output_path(args.output);out.mkdir(mode=0o700,parents=False,exist_ok=False)
 C=load('arm16k_project_command_runtime',reference/'frozen/command_runtime.py');runner=C.Runner(600,dict(os.environ),out);state=B.Cancellation();state.__enter__();scope=None
 report={'schema_version':1,'status':'HOLD','operation':'arm16k-rtc-project-lifecycle-ksm1','VM_boot':'NOT RUN','native16K':'NOT RUN','M2':'NOT RUN'}
 def cmd(label,argv,timeout=60):
  result=runner.run(argv,timeout=timeout,log=label+'.log');assert result.returncode==0,(label,result.returncode);return result.stdout
 try:
  security=json.loads(cmd('rootless-check',['docker','info','--format','{{json .SecurityOptions}}']));assert 'name=rootless'in security
  base=args.base.resolve(strict=True);original_materials=args.materials.resolve(strict=True);materials=out/'materials';materials.mkdir(mode=0o700)
  for name,ref in lock['materials'].items():
   origin=args.fresh_signatures/name if name in ('TEST-public.asc','cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz.sig')else original_materials/name
   I.checked(origin,ref);shutil.copyfile(origin,materials/name)
  I.checked(base/'prepared.json',lock['base_prepared'])
  original=json.loads((base/'prepared.json').read_text())
  for name,ref in lock['base_files'].items():I.checked(base/name,ref)
  I.checked(args.base_first_boot_report,lock['required_base_first_boot']);proof=json.loads(args.base_first_boot_report.read_text())
  assert proof['status']==lock['required_base_first_boot']['status']and proof['session']['ARCH']=='aarch64'and proof['session']['PAGESIZE']=='16384'and proof['normal_PAM_logout_observed']and proof['owned_container_absence_verified']
  # Verify an already consumed marker exists on the ORIGINAL; never copy/edit it.
  old_marker=base/'arm16k-first-boot-attempt.json';assert old_marker.is_file();report['original_consumed_marker']=I.pin(old_marker)
  for name,ref in lock['materials'].items():I.checked(materials/name,ref)
  closure=I.closure(materials,original);report['closure']={k:v for k,v in closure.items()if k!='packages'}
  tools=load('project_static_tool_namespace',HERE/'tool_namespace.py');report['static_tool_namespace']=tools.verify(args.rootfs,original,closure)
  gpg_home=out/'signature-home';gpg_home.mkdir(mode=0o700);statuses={}
  for name in ('archlinuxarm.gpg','TEST-public.asc'):cmd('dearmor-'+name,['gpg','--no-options','--batch','--homedir',str(gpg_home),'--dearmor','--output',str(out/(name+'.binary')),str(materials/name)])
  for name in lock['added_packages']:
   archive=next(materials.glob(name+'-*.pkg.tar.xz'));key='TEST-public.asc'if name=='cachy-asahi-ksmctl'else'archlinuxarm.gpg'
   raw=cmd('signature-'+name,['gpgv','--homedir',str(gpg_home),'--keyring',str(out/(key+'.binary')),'--status-fd','1',str(archive)+'.sig',str(archive)],60)
   lines=[line for line in raw.decode().splitlines()if line.startswith('[GNUPG:] VALIDSIG ')]
   expected=lock['project']['signer']if name=='cachy-asahi-ksmctl'else'68B3537F39A313B3E574D06777193F152BDBE6A6'
   assert len(lines)==1 and lines[0].split()[2]==expected;statuses[name]=lines[0]
  report['actual_signature_statuses']=statuses
  dates=I.signature_dates(statuses);report['diagnostic_signature_dates']=dates
  fixture=out/'fixture-data';fixture.mkdir(mode=0o700);baseline={x['name']:x['version']for x in original['base_packages']}
  (fixture/'signature-dates.lock').write_text(''.join(name+' '+str(row['created'])+' '+str(row['expires'])+'\n'for name,row in sorted(dates.items())))
  for name,packages in (('expected111.lock',baseline),('expected114.lock',{**baseline,**lock['added_packages']})):(fixture/name).write_text(''.join(n+' '+v+'\n'for n,v in sorted(packages.items())))
  (fixture/'materials.sha256').write_text(''.join(ref['sha256']+'  '+name+'\n'for name,ref in sorted(lock['materials'].items())))
  (fixture/'project-payload.sha256').write_text(''.join(row['sha256']+'  /'+name+'\n'for name,row in sorted(closure['project_payload'].items())))
  (fixture/'project-metadata.lock').write_text(''.join(format(row['mode'],'o')+':'+str(row['uid'])+':'+str(row['gid'])+' '+name+'\n'for name,row in sorted(closure['project_payload'].items())))
  (fixture/'pacman.conf').write_text('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nGPGDir = /var/lib/arm16k-project-lifecycle/trust\nCacheDir = /var/lib/arm16k-project-lifecycle/cache\n')
  image=json.loads(cmd('tool-image',['docker','image','inspect',lock['tool_image_id']]))[0];assert image['Id']==lock['tool_image_id']
  manifest={k:lock[k]for k in ('materials','base_files','base_prepared','required_base_first_boot','tool_image_id','project','added_packages')}
  manifest.update({'rtc_bundle':bundle,'rtc_authority':approval,'fresh_signing':fresh,'actual_signature_statuses':statuses,'baseline_proof_script':I.pin(reference/'guest-proof.sh'),'operation':'arm16k-rtc-project-lifecycle-ksm1','authority_pin':I.pin(args.authority),'source_pins':{path.name:I.pin(path)for path in HERE.iterdir()if path.is_file()}})
  (out/'input-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n');assembly=out/'assembly';assembly.mkdir(mode=0o700)
  assert shutil.disk_usage(out).free>=2*1024**3 and shutil.disk_usage('/home').free>512*1024**2,'capacity reserve'
  mounts=[('bind',str(base/'guest.raw'),'/base.raw',False),('bind',str(base/'prepared.json'),'/base-prepared.json',False),('bind',str(args.kernel_bundle.resolve()/'Image'),'/base-Image',False),('bind',str(args.kernel_bundle.resolve()/'config'),'/base-config',False),('bind',str(materials),'/materials',False),('bind',str(HERE),'/code',False),('bind',str(out),'/work',True)]
  container_name='cachy-arm16k-project-prepare-'+secrets.token_hex(12);labels=dict(image['Config'].get('Labels')or{});labels.update({'org.cachy-asahi.arm16k-project-owner':str(os.getuid()),'org.cachy-asahi.arm16k-project-operation':container_name})
  class Scope(B.OwnedContainer):
   def validate(self,row):
    assert row['Name']=='/'+container_name and row['Image']==image['Id']and row['Config']['Labels']==labels
    assert row['Config']['Entrypoint']==['/usr/bin/python3']and row['Config']['Cmd']==['-I','-B','/code/prepare_image.py']
    assert {(m['Type'],m['Source'],m['Destination'],m['RW'])for m in row['Mounts']}==set(mounts)and len(row['Mounts'])==7
    h=row['HostConfig'];assert h['NetworkMode']=='none'and h['ReadonlyRootfs']and h['CapDrop']==['ALL']and not h['CapAdd']and not h['Privileged']and not h['Devices']and h['Init']is True and h['SecurityOpt']==['no-new-privileges']
    assert h['Memory']==3*1024**3 and h['NanoCpus']==2_000_000_000 and h['PidsLimit']==256
  scope=Scope(container_name,out/'prepare.cid',image['Id'],labels,base,out);assert scope.listing(time.monotonic()+8)is None
  argv=['docker','create','--cidfile',str(scope.cidfile),'--name',container_name,'--init','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=64m']
  for key,value in labels.items():argv+=['--label',key+'='+value]
  for kind,source,destination,rw in mounts:argv+=['--mount','type='+kind+',source='+source+',target='+destination+(''if rw else',readonly')]
  argv+=['--env','CACHY_ARM16K_PROJECT_PREPARE=1','--entrypoint','/usr/bin/python3',image['Id'],'-I','-B','/code/prepare_image.py']
  scope.submitted=True;cmd('create-offline-fixture',argv);scope.recover(time.monotonic()+8);cmd('prepare-offline-fixture',['docker','start','-a',container_name],360)
  row=scope.recover(time.monotonic()+8);assert row['State']['ExitCode']==0 and not row['State']['OOMKilled']and not row['State']['Running']
  prepared=json.loads((assembly/'prepared.json').read_text());assert prepared['nonce']!=original['nonce']and prepared['operation']=='arm16k-rtc-project-lifecycle-ksm1'
  for name,ref in prepared['files'].items():I.checked(assembly/name,ref)
  assert not(assembly/'arm16k-first-boot-attempt.json').exists()and not(assembly/'arm16k-project-lifecycle-attempt.json').exists()
  for name,ref in lock['base_files'].items():I.checked(base/name,ref)
  assert I.pin(old_marker)==report['original_consumed_marker']
  allocated=sum(path.stat().st_blocks*512 for path in out.rglob('*')if path.is_file());assert allocated<=800*1024**2,'owned clone preparation disk cap'
  report.update({'status':'PREPARED_NOT_BOOTED','prepared':I.pin(assembly/'prepared.json'),'prepared_path':str(assembly),'allocated_output_bytes':allocated,'future_overlay_limit_bytes':256*1024**2})
 except BaseException as error:report['failure']={'category':type(error).__name__,'message':str(error)[:2048],'frames':[{'file':Path(row.filename).name,'line':row.lineno}for row in traceback.extract_tb(error.__traceback__)[-5:]]}
 finally:
  state.cleaning=True
  try:
   if scope is not None:scope.cleanup(report)
  finally:
   if state.pending:report['status']='HOLD_CANCELLED';report['cancelled_signals']=state.pending
   if report.get('cleanup_errors'):report['status']='HOLD_CLEANUP'
   try:(out/'preparation.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
   finally:state.__exit__()
 print(json.dumps({'status':report['status'],'report':str(out/'preparation.json'),'failure':report.get('failure'),'VM_boot':'NOT RUN'}))
 return 0 if report['status']=='PREPARED_NOT_BOOTED'else 1


if __name__=='__main__':raise SystemExit(main())
