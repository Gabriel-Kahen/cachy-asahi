#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Root-admitted offline ARM283 UI constructor; never launches a guest."""
import argparse,importlib.util,json,os,secrets,shutil,sys,tarfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('ARM_UI_upper_contracts',HERE/'contracts.py');K=importlib.util.module_from_spec(s);s.loader.exec_module(K)
def stage_inputs(out,args,c):
 materials=out/'materials';materials.mkdir(mode=0o700);m=c['manifest'];pins={};statuses={};home=out/'public-signature-home';home.mkdir(mode=0o700)
 for row in m['archives'].values():
  for filename,ref in [(row['filename'],row['archive']),(row['filename']+'.sig',row['signature'])]:shutil.copyfile(K.checked(args.materials/filename,ref),materials/filename);pins[filename]=ref
 for role,key in m['trust']['keyrings'].items():
  assert key['filename']==role+'-public.gpg';shutil.copyfile(K.checked(args.materials/key['filename'],key['pin']),materials/key['filename']);pins[key['filename']]=key['pin']
 for name,row in m['archives'].items():
  key=m['trust']['keyrings'][row['signer_role']];assert row['expected_signer']==key['primary'];assert time.time()<m['trust']['valid_until_utc']
  # Same strict status policy, with the explicitly admitted project identity.
  # No global trust/import/agent: gpgv keyring is finite and public-only.
  import subprocess
  result=subprocess.run(['/usr/bin/gpgv','--homedir',str(home),'--keyring',str(materials/key['filename']),'--status-fd','1',str(materials/(row['filename']+'.sig')),str(materials/row['filename'])],capture_output=True,text=True,timeout=5)
  assert len(result.stdout)+len(result.stderr)<=65536 and result.returncode==0
  lines=[v.split()[1:]for v in result.stdout.splitlines()if v.startswith('[GNUPG:] ')];valid=[v for v in lines if v[0]=='VALIDSIG'];assert len(valid)==1 and valid[0][1]==valid[0][-1]==row['expected_signer']and int(valid[0][3])<=time.time()and(int(valid[0][4])==0 or time.time()<int(valid[0][4]))and not any(v[0]in ['EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','FAILURE','ERROR','NODATA','BADARMOR']for v in lines);statuses[name]=valid[0]
 fixture=out/'fixture-data';fixture.mkdir(mode=0o700);seat=fixture/'seat';seat.mkdir();ui=fixture/'ui';ui.mkdir();(fixture/'UI-unrelated.txt').write_bytes(b'preserved ARM16K UI unrelated user settings\n')
 baseline={r['name']:r['version']for r in c['base']['base_packages']};final={**baseline,**{n:r['version']for n,r in m['archives'].items()}}
 for name,rows in [('expected-before.lock',baseline),('expected-after.lock',final)]:(seat/name).write_text(''.join(n+' '+v+'\n'for n,v in sorted(rows.items())))
 (seat/'materials.sha256').write_text(''.join(r['sha256']+'  '+n+'\n'for n,r in sorted(pins.items())));(seat/'archive-names.lock').write_text(''.join(r['filename']+'\n'for n,r in sorted(m['archives'].items())))
 primaries=sorted({r['primary']for r in m['trust']['keyrings'].values()});(seat/'ownertrust.lock').write_text(''.join(p+':6:\n'for p in primaries));(seat/'addition-manifest.sha256').write_text(K.pin(args.additions_manifest)['sha256']+'\n')
 originals=m['original_file_pins'];(seat/'baseline-files.sha256').write_text(''.join(h+'  '+p+'\n'for p,h in sorted(originals.items())));(seat/'original-files.sha256').write_text((seat/'baseline-files.sha256').read_text()+K.POLICY+'  /usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy\n')
 (seat/'pacman.conf').write_text('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nGPGDir = /var/lib/arm16k-virtio-seat/trust\nCacheDir = /var/lib/arm16k-virtio-seat/cache\n')
 templates=ui/'templates';templates.mkdir();allowed={'fish':'21f4ca0ab90c66b131673f2cb2c6caf85b72e2872777481d8118d9264b3d0c02','zsh':'0e88f366d93de023007a290678e38c37dda64d2c10036f763e4ee0c4de4cc9c0'}
 for component,ref in m['templates'].items():
  assert component in allowed and ref['pin']['sha256']==allowed[component];archive=K.checked(args.materials/ref['filename'],ref['pin'])
  with tarfile.open(archive,'r:*')as tree:
   prefix='usr/share/cachy-asahi/'+component+'/'
   for member in tree:
    if not member.name.startswith(prefix):continue
    dest=templates/component/member.name.removeprefix(prefix);assert '..'not in dest.parts
    if member.isdir():dest.mkdir(parents=True,exist_ok=True)
    else:assert member.isfile()and member.size<=1024**2;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(tree.extractfile(member).read())
 assert set(m['templates'])=={'fish','zsh'}and(templates/'fish/config.fish').is_file()and(templates/'zsh/config.zsh').is_file()
 O=K.load('ARM_UI_ownership_stage',HERE/'ownership.py');rows=[{'name':n,'version':r['version'],'filename':r['filename'],**r['archive']}for n,r in m['archives'].items()];ownership=O.build_index(materials,rows,ui/'ownership');payloads={path:row['sha256']for name in K.PROJECT for path,row in c['catalog'][name]['payload'].items()if row['type']=='0'and path.startswith('usr/')};assert len(payloads)==24
 profile={'baseline_versions':baseline,'archives':[{'name':n,'version':r['version'],'filename':r['filename'],'bytes':r['archive']['bytes'],'sha256':r['archive']['sha256'],'signature_bytes':r['signature']['bytes'],'signature_sha256':r['signature']['sha256']}for n,r in sorted(m['archives'].items())],'project_payloads':payloads,'ownership_metadata':ownership,'original_file_pins':originals,'NM_policy_sha256':K.POLICY,'unrelated_user_sha256':K.pin(fixture/'UI-unrelated.txt')['sha256'],'trusted_primaries':primaries};(ui/'inputs.json').write_text(json.dumps(profile,indent=2,sort_keys=True)+'\n')
 owned=c['refs']['owned_process'];shutil.copyfile(owned['path'],fixture/'owned_process.py');return pins,statuses

def guest_sources(c):
 records={};arm=c['arm'];foundation='frozen/arm16k_virtio_seat/';delivery=K.read(arm/foundation/'delivery.lock.json')
 def add(name,root,source,path,mode='0755',uid=0,gid=0,replace=False):
  prefix={'ui':HERE,'arm':arm,'x86':c['x86'],'fixture':Path(c['output'])/'fixture-data'}[root];records[name]={'source_root':root,'source':source,'pin':K.pin(prefix/source),'guest_path':path,'mode':mode,'uid':uid,'gid':gid,'replace':replace}
 for name,row in delivery['guest_files'].items():
  if name in ['observer.py','profile.fragment']:continue
  add(name,'arm',name if name=='input_seat.py'else foundation+name,row['guest_path'],row['mode'])
 for name,dest in [('observer.py','seat-observer.py'),('root_fixture.py','ui-root-fixture.py'),('receipts.py','ui-receipts.py'),('ownership.py','ui-ownership.py'),('result.py','ui-result.py'),('ui_observer.py','arm-ui-observer.py'),('arm_ui_gate.py','arm_ui_gate.py')]:add(name,'ui',name,'/usr/local/libexec/'+dest)
 for name,dest in [('client.py','ui-client.py'),('gui_probe.py','ui-gui-probe.py')]:add(name,'x86',name,'/usr/local/libexec/'+dest)
 add('owned','fixture','owned_process.py','/usr/local/libexec/ui-owned-process.py');add('profile','ui','profile.fragment','/home/builder/.bash_profile','0600',1000,1000,True)
 for name,root,source,dest in [('install','ui','guest-install.sh','/usr/local/libexec/arm16k-seat-install'),('bytes','arm','bytes.sh','/var/lib/arm16k-virtio-seat/bytes.sh'),('clock','arm','frozen/rtc-clock.sh','/var/lib/arm16k-virtio-seat/rtc-clock.sh')]:add(name,root,source,dest,'0755'if name=='install'else'0600')
 for name,root,source,dest in [('install-service','arm','seat-install.service','/etc/systemd/system/arm16k-seat-install.service'),('observer-order','arm','observer-install.conf','/etc/systemd/system/arm16k-virtio-seat-observer.service.d/10-install.conf'),('getty-order','arm','getty-install.conf','/etc/systemd/system/getty@tty1.service.d/10-install.conf'),('ui-fixture','ui','fixture.service','/etc/systemd/system/arm16k-ui-fixture.service'),('ui-observer','ui','ui-observer.service','/etc/systemd/system/arm16k-ui-observer.service')]:add(name,root,source,dest,'0644')
 return records

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-prepare-arm16k-ui',action='store_true')
 for n in ['base','base-first-boot-report','materials','additions-manifest','kernel-bundle','qemu-metadata','tool-qualification','minimal155-report','minimal155-prepared','authority','output']:p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--authority-sha256',required=True);a=p.parse_args()
 if not(a.allow_prepare_arm16k_ui and __debug__ and sys.flags.isolated and os.geteuid()!=0):p.error('explicit Root-admitted isolated ordinary-user preparation required')
 c=K.preflight(a);out=K.output_path(a.output);available=int(next(v.split()[1]for v in Path('/proc/meminfo').read_text().splitlines()if v.startswith('MemAvailable:')))*1024;assert available>=6*1024**3
 out.mkdir(mode=0o700);os.umask(0o077);c['output']=out;arm=c['arm'];C=K.load('UI_ARM_held_runner',arm/'frozen/command_runtime.py');B=K.load('UI_ARM_held_custody',arm/'frozen/reference_controller.py');runner=C.Runner(600,dict(os.environ),out);cancel=B.Cancellation();scope=None;report={'status':'HOLD','operation':K.OP,'VM_boot':'NOT RUN'};cancel.__enter__()
 def cmd(label,argv,timeout=60):
  r=runner.run(argv,timeout=timeout,log=label+'.log');assert r.returncode==0,(label,r.returncode);return r.stdout
 try:
  assert 'name=rootless'in json.loads(cmd('rootless',['docker','info','--format','{{json .SecurityOptions}}']));image_id=c['authority']['tool_image_id'];image=json.loads(cmd('tool-image',['docker','image','inspect',image_id]))[0];assert image['Id']==image_id
  pins,statuses=stage_inputs(out,a,c);manifest={'operation':K.OP,'base_files':c['lower'].lock()['base_files'],'base_prepared':c['lower'].lock()['base_prepared'],'original_marker':c['original_marker'],'kernel':c['kernel'],'authority':c['authority'],'additions':c['manifest'],'additions_pin':K.pin(a.additions_manifest),'actual_host_signatures':statuses,'tool_metadata':c['tool'],'tool_qualification':c['tool_qualification'],'material_pins':pins,'guest_files':guest_sources(c),'source_lock':K.source()};(out/'input-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n');(out/'assembly').mkdir(mode=0o700)
  mounts=[('bind',str(a.base.resolve()/'guest.raw'),'/base.raw',False),('bind',str(a.base.resolve()/'prepared.json'),'/base-prepared.json',False),('bind',str(a.kernel_bundle.resolve()/'Image'),'/base-Image',False),('bind',str(a.kernel_bundle.resolve()/'config'),'/base-config',False),('bind',str(out/'materials'),'/materials',False),('bind',str(HERE),'/code',False),('bind',str(arm),'/arm-source',False),('bind',str(c['x86']),'/x86-source',False),('bind',str(out),'/work',True)];name='cachy-arm16k-ui-prepare-'+secrets.token_hex(12);labels=dict(image['Config'].get('Labels')or{});labels.update({'org.cachy-asahi.arm-ui-owner':str(os.getuid()),'org.cachy-asahi.arm-ui-operation':name})
  class Scope(B.OwnedContainer):
   def validate(self,row):
    K.preparation_confinement(row,name,image_id,labels,mounts)
  scope=Scope(name,out/'prepare.cid',image_id,labels,a.base,out);assert scope.listing(time.monotonic()+8)is None;argv=['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init=false','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--memory-swap=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=64m']
  for k,v in labels.items():argv+=['--label',k+'='+v]
  for kind,src,dest,rw in mounts:argv+=['--mount','type='+kind+',source='+src+',target='+dest+(''if rw else',readonly')]
  argv+=['--env','CACHY_ARM16K_UI_PREPARE=1','--entrypoint','/usr/bin/python3',image_id,'-I','-B','/code/prepare_image.py'];scope.submitted=True;cmd('create',argv);scope.recover(time.monotonic()+8);cmd('offline-assembly',['docker','start','-a',name],360);terminal=scope.recover(time.monotonic()+8);assert terminal['State']['ExitCode']==0 and not terminal['State']['OOMKilled']and not terminal['State']['Running'];prepared=K.read(out/'assembly/prepared.json');assert prepared['operation']==K.OP and prepared['nonce']!=c['base']['nonce']
  for name,ref in prepared['files'].items():K.checked(out/'assembly'/name,ref)
  for name,ref in c['lower'].lock()['base_files'].items():K.checked(a.base/name,ref)
  assert K.pin(a.base/'arm16k-first-boot-attempt.json')==c['original_marker'];allocated=sum(p.stat().st_blocks*512 for p in out.rglob('*')if p.is_file());assert allocated<=3*1024**3 and shutil.disk_usage(out).free>=2*1024**3;report.update(status='PREPARED_NOT_BOOTED',prepared=K.pin(out/'assembly/prepared.json'),allocated_output_bytes=allocated)
 except BaseException as error:report['failure']={'category':type(error).__name__,'message':str(error)[:1024]}
 finally:
  cancel.cleaning=True
  try:
   if scope is not None:scope.cleanup(report)
  finally:
   if cancel.pending:report['status']='HOLD_CANCELLED'
   if report.get('cleanup_errors'):report['status']='HOLD_CLEANUP'
   try:(out/'preparation.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
   finally:cancel.__exit__()
 print(json.dumps({'status':report['status'],'report':str(out/'preparation.json')}));return 0 if report['status']=='PREPARED_NOT_BOOTED'else 1
if __name__=='__main__':raise SystemExit(main())
