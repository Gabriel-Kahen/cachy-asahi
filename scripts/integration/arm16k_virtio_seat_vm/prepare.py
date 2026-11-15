#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Root-only offline ARM seat fixture constructor; never launches a guest."""
import argparse,importlib.util,json,os,secrets,shutil,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def preflight(a):
 K=load('seat_contracts',HERE/'contracts.py');authority=K.authority(a.authority,a.authority_sha256,'prepare');kernel=K.kernel(a.kernel_bundle,authority);tool=K.tool_metadata(a.qemu_metadata,authority);base,marker=K.baseline(a.base,a.base_first_boot_report);additions,catalog,edges=K.additions(a.additions_manifest,a.materials,base,authority)
 return K,authority,kernel,tool,base,marker,additions,catalog,edges

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-prepare-arm16k-virtio-seat',action='store_true')
 for n in ('base','base-first-boot-report','materials','additions-manifest','kernel-bundle','qemu-metadata','authority','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--authority-sha256',required=True);a=p.parse_args()
 if not(a.allow_prepare_arm16k_virtio_seat and sys.flags.isolated and __debug__ and os.geteuid()!=0):p.error('isolated ordinary user and explicit Root preparation required')
 # All null/missing/hash/namespace/dependency/kernel/authority failures precede
 # output creation, sparse raw cloning and every daemon/process invocation.
 K,authority,kernel,tool,base,marker,adds,catalog,edges=preflight(a)
 out=K.output_path(a.output);os.umask(0o077);out.mkdir(mode=0o700)
 C=load('seat_runner',HERE/'frozen/command_runtime.py');B=load('seat_custody',HERE/'frozen/reference_controller.py');runner=C.Runner(600,dict(os.environ),out);state=B.Cancellation();scope=None;state.__enter__()
 report={'schema_version':1,'status':'HOLD','operation':K.OP,'VM_boot':'NOT RUN','native16K':'NOT RUN','M2':'NOT RUN'}
 def cmd(label,argv,timeout=60):
  r=runner.run(argv,timeout=timeout,log=label+'.log')
  if r.returncode:raise RuntimeError((label,r.returncode))
  return r.stdout
 try:
  assert 'name=rootless' in json.loads(cmd('rootless',['docker','info','--format','{{json .SecurityOptions}}']))
  image=json.loads(cmd('tool-image',['docker','image','inspect',K.IMAGE]))[0];assert image['Id']==K.IMAGE
  materials=out/'materials';materials.mkdir(mode=0o700);material_pins={}
  for row in adds['archives'].values():
   for filename,ref in ((row['filename'],row['archive']),(row['filename']+'.sig',row['signature'])):K.checked(a.materials/filename,ref);shutil.copyfile(a.materials/filename,materials/filename);material_pins[filename]=ref
  key=adds['keyring'];shutil.copyfile(K.checked(a.materials/key['filename'],key['pin']),materials/key['filename']);material_pins[key['filename']]=key['pin']
  # Verify original detached signatures under a NEW private public-only keyring.
  home=out/'public-signature-home';home.mkdir(mode=0o700);statuses={}
  for name,row in sorted(adds['archives'].items()):
   raw=cmd('signature-'+name,['gpgv','--homedir',str(home),'--keyring',str(materials/key['filename']),'--status-fd','1',str(materials/(row['filename']+'.sig')),str(materials/row['filename'])])
   valid=[x for x in raw.decode().splitlines() if x.startswith('[GNUPG:] VALIDSIG ')]
   assert len(valid)==1
   fields=valid[0].split();assert len(fields) in (11,12) and (fields[-1] if len(fields)==12 else fields[2])==row['expected_signer']
   assert int(fields[4])<=time.time() and (int(fields[5])==0 or time.time()<int(fields[5]));statuses[name]=valid[0]
  fixture=out/'fixture-data';fixture.mkdir(mode=0o700);baseline={r['name']:r['version'] for r in base['base_packages']};final={**baseline,**{n:r['version'] for n,r in adds['archives'].items()}}
  for name,rows in [('expected-before.lock',baseline),('expected-after.lock',final)]: (fixture/name).write_text(''.join(n+' '+v+'\n' for n,v in sorted(rows.items())))
  (fixture/'materials.sha256').write_text(''.join(r['sha256']+'  '+n+'\n' for n,r in sorted(material_pins.items())))
  (fixture/'archive-names.lock').write_text(''.join(r['filename']+'\n' for n,r in sorted(adds['archives'].items())))
  signers=sorted({r['expected_signer'] for r in adds['archives'].values()});(fixture/'ownertrust.lock').write_text(''.join(f+':6:\n' for f in signers))
  original={**adds['original_file_pins'],'/usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy':K.POLICY}
  (fixture/'original-files.sha256').write_text(''.join(h+'  '+p+'\n' for p,h in sorted(original.items())))
  required_paths=set(K.REQUIRED)|{'usr/lib/python3.14/site-packages/gi/__init__.py','usr/lib/girepository-1.0/Gio-2.0.typelib','usr/lib/girepository-1.0/GLib-2.0.typelib'}
  (fixture/'required-namespace.json').write_text(json.dumps({n:adds['required_namespace'][n] for n in sorted(required_paths)},sort_keys=True)+'\n')
  (fixture/'addition-manifest.sha256').write_text(K.pin(a.additions_manifest)['sha256']+'\n')
  (fixture/'pacman.conf').write_text('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nGPGDir = /var/lib/arm16k-virtio-seat/trust\nCacheDir = /var/lib/arm16k-virtio-seat/cache\n')
  foundation='frozen/arm16k_virtio_seat/';delivery=K.read_json(HERE/foundation/'delivery.lock.json');guest={}
  for name,row in delivery['guest_files'].items():
   if name in ('observer.py','input_seat.py'):source=name
   else:source=foundation+name
   guest[name]={**row,**K.pin(HERE/source),'source':source,'replace':name=='profile.fragment','uid':1000 if name=='profile.fragment' else 0,'gid':1000 if name=='profile.fragment' else 0}
  for name,path,mode in [('guest-install.sh','/usr/local/libexec/arm16k-seat-install','0755'),('bytes.sh','/var/lib/arm16k-virtio-seat/bytes.sh','0600'),('namespace-check.py','/var/lib/arm16k-virtio-seat/namespace-check.py','0600'),('frozen/rtc-clock.sh','/var/lib/arm16k-virtio-seat/rtc-clock.sh','0600'),('seat-install.service','/etc/systemd/system/arm16k-seat-install.service','0644'),('observer-install.conf','/etc/systemd/system/arm16k-virtio-seat-observer.service.d/10-install.conf','0644'),('getty-install.conf','/etc/systemd/system/getty@tty1.service.d/10-install.conf','0644')]:guest[name]={**K.pin(HERE/name),'source':name,'guest_path':path,'mode':mode}
  manifest={'schema_version':1,'operation':K.OP,'base_files':K.lock()['base_files'],'base_prepared':K.lock()['base_prepared'],'original_marker':marker,'kernel':kernel,'authority':authority,'additions':adds,'additions_pin':K.pin(a.additions_manifest),'actual_host_signatures':statuses,'tool_metadata':tool,'material_pins':material_pins,'guest_files':guest,'source_lock':K.source()}
  (out/'input-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n');assembly=out/'assembly';assembly.mkdir(mode=0o700)
  mounts=[('bind',str(a.base.resolve()/'guest.raw'),'/base.raw',False),('bind',str(a.base.resolve()/'prepared.json'),'/base-prepared.json',False),('bind',str(a.kernel_bundle.resolve()/'Image'),'/base-Image',False),('bind',str(a.kernel_bundle.resolve()/'config'),'/base-config',False),('bind',str(materials),'/materials',False),('bind',str(HERE),'/code',False),('bind',str(out),'/work',True)]
  if shutil.disk_usage(out).free<K.lock()['reserve_bytes'] or shutil.disk_usage('/home').free<512*1024**2:raise ValueError('capacity reserve before offline actor')
  name='cachy-arm16k-seat-prepare-'+secrets.token_hex(12);labels=dict(image['Config'].get('Labels') or {});labels.update({'org.cachy-asahi.arm-seat-owner':str(os.getuid()),'org.cachy-asahi.arm-seat-operation':name})
  class Scope(B.OwnedContainer):
   def validate(self,row):
    assert row['Name']=='/'+name and row['Image']==K.IMAGE and row['Config']['Labels']==labels
    assert row['Config']['Entrypoint']==['/usr/bin/python3'] and row['Config']['Cmd']==['-I','-B','/code/prepare_image.py']
    assert len(row['Mounts'])==7 and {(x['Type'],x['Source'],x['Destination'],x['RW']) for x in row['Mounts']}==set(mounts)
    h=row['HostConfig'];assert h['NetworkMode']=='none' and h['ReadonlyRootfs'] and h['CapDrop']==['ALL'] and not h['CapAdd'] and not h['Privileged'] and not h['Devices'] and h['Init'] is True and h['SecurityOpt']==['no-new-privileges'] and h['Memory']==3*1024**3 and h['NanoCpus']==2_000_000_000 and h['PidsLimit']==256
  scope=Scope(name,out/'prepare.cid',K.IMAGE,labels,a.base,out);assert scope.listing(time.monotonic()+8) is None
  argv=['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=64m']
  for k,v in labels.items():argv+=['--label',k+'='+v]
  for kind,src,dest,rw in mounts:argv+=['--mount','type='+kind+',source='+src+',target='+dest+('' if rw else ',readonly')]
  argv+=['--env','CACHY_ARM16K_SEAT_PREPARE=1','--entrypoint','/usr/bin/python3',K.IMAGE,'-I','-B','/code/prepare_image.py'];scope.submitted=True;cmd('create',argv);scope.recover(time.monotonic()+8);cmd('offline-assembly',['docker','start','-a',name],360)
  row=scope.recover(time.monotonic()+8);assert row['State']['ExitCode']==0 and not row['State']['OOMKilled'] and not row['State']['Running']
  prepared=K.read_json(assembly/'prepared.json');assert prepared['operation']==K.OP and prepared['nonce']!=base['nonce']
  for n,ref in prepared['files'].items():K.checked(assembly/n,ref)
  for n,ref in K.lock()['base_files'].items():K.checked(a.base/n,ref)
  assert K.pin(a.base/'arm16k-first-boot-attempt.json')==marker and not (assembly/'virtio-seat-attempt.json').exists()
  allocated=sum(p.stat().st_blocks*512 for p in out.rglob('*') if p.is_file());assert allocated<=K.lock()['prep_allocated_cap'] and shutil.disk_usage(out).free>=K.lock()['reserve_bytes']
  report.update(status='PREPARED_NOT_BOOTED',prepared=K.pin(assembly/'prepared.json'),allocated_output_bytes=allocated,overlay_limit=K.lock()['overlay_cap'])
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  state.cleaning=True
  try:
   if scope is not None:scope.cleanup(report)
  finally:
   if state.pending:report.update(status='HOLD_CANCELLED',cancelled_signals=state.pending)
   if report.get('cleanup_errors'):report['status']='HOLD_CLEANUP'
   try:(out/'preparation.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
   finally:state.__exit__()
 print(json.dumps({'status':report['status'],'report':str(out/'preparation.json')}));return 0 if report['status']=='PREPARED_NOT_BOOTED' else 1
if __name__=='__main__':raise SystemExit(main())
