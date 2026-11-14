#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit finite no-capability/private-system-bus NM software probe."""
import base64
import argparse,hashlib,importlib.util,json,os,secrets,shutil,subprocess,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2]
s=importlib.util.spec_from_file_location('nm_candidate_inputs',HERE.parent/'networkmanager_candidate/run.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
WRITABLE=['/run','/var/lib/NetworkManager','/etc/NetworkManager','/home/TEST','/tmp','/out']


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-owned-private-system-bus',action='store_true');p.add_argument('--archives',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not a.allow_owned_private_system_bus or not __debug__ or os.geteuid()==0:p.error('ordinary user, explicit opt-in and non-optimized Python required')
 refs=C.inputs(a.archives.resolve(strict=True));out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 tag='cachy-asahi-nm-private-bus:'+secrets.token_hex(8);name=tag.replace(':','-');created=False
 report={'schema_version':1,'status':'HOLD','base_image_id':C.BASE_ID,'scope':'x86 private SYSTEM bus/daemon; not native/M2/connectivity/release'}
 def call(label,argv,timeout=30):
  with (out/(label+'.log')).open('wb')as log:r=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
 try:
  base=json.loads(subprocess.check_output(['docker','image','inspect',C.BASE],text=True))[0];assert base['Id']==C.BASE_ID
  with tempfile.TemporaryDirectory(prefix='nm-private-bus-')as temp:
   context=Path(temp);data=context/'input';data.mkdir()
   sources=[HERE/'guest.py',HERE/'image_install.py',REPO/'scripts/virtual/owned_process.py',REPO/'scripts/integration/repository.py']
   for f in sources:shutil.copyfile(f,data/f.name)
   for ref in refs:shutil.copyfile(a.archives/ref['name'],data/ref['name'])
   contract={'archives':refs,'guest_source_pins':{f.name:C.sha(f)for f in sources},'host_launcher_sha256':C.sha(HERE/'run.py'),'archive_intake_sha256':C.sha(HERE.parent/'networkmanager_candidate/run.py')}
   (data/'contract.json').write_text(json.dumps(contract,indent=2)+'\n');report['input_contract']=contract
   (context/'Dockerfile').write_text('\n'.join(['FROM '+C.BASE,'USER 0:0','COPY input/ /opt/nm-private-bus/','RUN CACHY_ASAHI_PRIVATE_BUS_IMAGE_BUILD=1 python3 -I /opt/nm-private-bus/image_install.py --allow-private-image-install && find /opt/nm-private-bus -type f -exec chmod 0444 {} + && chmod 0555 /opt/nm-private-bus','ENV CACHY_ASAHI_PRIVATE_BUS_TEST=1','ENTRYPOINT ["/usr/bin/python3","-I","-B","/opt/nm-private-bus/guest.py","--allow-owned-private-system-bus"]','']))
   call('image-build',['docker','build','--network=none','--pull=false','--tag',tag,str(context)],180)
   after=json.loads(subprocess.check_output(['docker','image','inspect',C.BASE],text=True))[0];built=json.loads(subprocess.check_output(['docker','image','inspect',tag],text=True))[0]
   assert after['Id']==C.BASE_ID and built['RootFS']['Layers'][:len(base['RootFS']['Layers'])]==base['RootFS']['Layers']
  argv=['docker','create','--name',name,'--init','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=4g','--pids-limit=256']
  for path in WRITABLE:argv+=['--tmpfs',path+':rw,nosuid,nodev,noexec,mode=0700,size=32m']
  for var in ['DBUS_SYSTEM_BUS_ADDRESS','DBUS_SESSION_BUS_ADDRESS','DBUS_STARTER_ADDRESS','G_BUS_ADDRESS']:argv+=['--env',var+'=unix:path=/FORBIDDEN-CALLER-BUS']
  call('create',argv+[tag]);created=True
  config=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0];hc=config['HostConfig']
  assert not config['Mounts']and hc['ReadonlyRootfs']and hc['NetworkMode']=='none'and hc['CapDrop']==['ALL']and not hc['CapAdd']and not hc['Privileged']
  assert hc['PidMode']==''and hc['UTSMode']==''and hc['IpcMode']=='private'and hc['CgroupnsMode']=='private'
  assert hc['NanoCpus']==2_000_000_000 and hc['Memory']==4*1024**3 and hc['PidsLimit']==256
  report['runtime']={k:hc[k]for k in ['ReadonlyRootfs','NetworkMode','CapAdd','CapDrop','Privileged','Memory','NanoCpus','PidsLimit','Tmpfs','SecurityOpt','Devices','PidMode','UTSMode','IpcMode','CgroupnsMode']};report['image_id']=config['Image']
  call('start',['docker','start',name]);until=time.monotonic()+150;ready=False
  while time.monotonic()<until:
   r=subprocess.run(['docker','exec',name,'/usr/bin/test','-f','/out/READY'],capture_output=True,timeout=10)
   if r.returncode==0:ready=True;break
   state=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0]['State']
   if not state['Running']:break
   time.sleep(.1)
  call('console',['docker','logs',name]);assert ready,'guest never reached live-export boundary'
  export="import base64,json;from pathlib import Path;files=sorted(Path('/out').iterdir());assert len(files)<128;assert all(p.is_file()and not p.is_symlink()and p.stat().st_size<=2*1024**2 for p in files);assert sum(p.stat().st_size for p in files)<16*1024**2;print(json.dumps({p.name:base64.b64encode(p.read_bytes()).decode()for p in files}))"
  call('export-public-report',['docker','exec',name,'/usr/bin/python3','-I','-c',export])
  guest=out/'guest';guest.mkdir()
  exported=json.loads((out/'export-public-report.log').read_text());assert len(exported)<128
  for filename,data in exported.items():
   assert Path(filename).name==filename and(filename in {'READY','report.json'}or filename.endswith('.log'))
   decoded=base64.b64decode(data,validate=True);assert len(decoded)<=2*1024**2;(guest/filename).write_bytes(decoded)
  report['guest']=json.loads((guest/'report.json').read_text())
  call('allow-normal-entry-exit',['docker','exec',name,'/usr/bin/touch','/run/ALLOW_EXIT'])
  call('normal-container-wait',['docker','wait',name],15);state=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0]['State']
  assert state['ExitCode']==0 and not state['OOMKilled'],state
  assert report['guest']['status']=='PASS_X86_OWNED_PRIVATE_SYSTEM_BUS_ONLY'
  report['status']=report['guest']['status']
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  if created:
   r=subprocess.run(['docker','rm','--force',name],capture_output=True,timeout=30);report['owned_container_removed']=r.returncode==0
   if r.returncode:report['status']='HOLD_CLEANUP'
  r=subprocess.run(['docker','image','rm',tag],capture_output=True,timeout=30);report['owned_image_tag_removed']=r.returncode==0
  (out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'report':str(out/'report.json'),'failure':report.get('failure')}))
 return 0 if report['status']=='PASS_X86_OWNED_PRIVATE_SYSTEM_BUS_ONLY'else 1


if __name__=='__main__':raise SystemExit(main())
