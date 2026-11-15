#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite real UID1000/Polkit authorization rehearsal, never a host install."""
import argparse,base64,hashlib,importlib.util,json,os,secrets,shutil,subprocess,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2]

def mod(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
C=mod('auth_archive_intake',HERE.parent/'networkmanager_candidate/run.py')
O=mod('auth_bridge_owner',REPO/'scripts/virtual/owned_process.py')


def main():
 p=argparse.ArgumentParser();p.add_argument('--allow-owned-auth-agent',action='store_true');p.add_argument('--archives',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(__debug__ and a.allow_owned_auth_agent and os.geteuid()!=0):p.error('ordinary user, explicit opt-in and non-optimized Python required')
 refs=C.inputs(a.archives.resolve(strict=True));out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 tag='cachy-asahi-nm-auth-agent:'+secrets.token_hex(8);name=tag.replace(':','-');created=False;bridge=None;bridge_log=None
 report={'status':'HOLD','scope':'real UID1000 pkttyagent process-subject registration gate; no credentials or PAM claim','base_image_id':C.BASE_ID,'native_ARM':'NOT RUN','M2':'NOT RUN','real_connectivity':'NOT RUN','release':'HOLD','operations':[]}
 def cmd(label,argv,timeout=20):
  path=out/(label+'.log')
  with path.open('wb')as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
  return path
 def role(label,which,user='0:0'):
  path=cmd(label,['docker','exec','--user',user,name,'/usr/bin/python3','-I','-B','/opt/nm-private-bus/roles.py',which])
  return json.loads(path.read_text())
 def touch(file):cmd('signal-'+Path(file).name,['docker','exec',name,'touch',file])
 def marker(file,seconds=15):
  until=time.monotonic()+seconds
  while time.monotonic()<until:
   r=subprocess.run(['docker','exec',name,'test','-f',file],capture_output=True,timeout=5)
   if r.returncode==0:return
   time.sleep(.1)
  raise TimeoutError(file)
 def export():
  script="import base64,json;from pathlib import Path;files=[p for d in ['/out','/polkit']for p in Path(d).iterdir()if p.is_file()and not p.is_symlink()];assert len(files)<128 and all(p.stat().st_size<=2*1024**2 for p in files);assert sum(p.stat().st_size for p in files)<16*1024**2;print(json.dumps({p.parent.name+'-'+p.name:base64.b64encode(p.read_bytes()).decode()for p in files}))"
  path=cmd('public-live-export',['docker','exec',name,'python3','-I','-c',script]);data=json.loads(path.read_text());guest=out/'guest';guest.mkdir(exist_ok=True)
  for n,b in data.items():assert Path(n).name==n;(guest/n).write_bytes(base64.b64decode(b,validate=True))
 try:
  base=json.loads(subprocess.check_output(['docker','image','inspect',C.BASE],text=True))[0];assert base['Id']==C.BASE_ID
  with tempfile.TemporaryDirectory(prefix='nm-auth-agent-')as temp:
   context=Path(temp);data=context/'input';data.mkdir()
   sources={'fixture.py':HERE/'pam_fixture.py','roles.py':HERE.parent/'networkmanager_user_auth/roles.py','previous_guest.py':HERE.parent/'networkmanager_private_bus/guest.py','image_install.py':HERE.parent/'networkmanager_private_bus/image_install.py','owned_process.py':REPO/'scripts/virtual/owned_process.py','repository.py':REPO/'scripts/integration/repository.py','probe.py':HERE/'probe.py','bootstrap.py':HERE/'bootstrap.py','credential.py':HERE/'credential.py','authenticate.py':HERE/'authenticate.py','paths.py':HERE/'paths.py'}
   for n,s in sources.items():shutil.copyfile(s,data/n)
   for ref in refs:shutil.copyfile(a.archives/ref['name'],data/ref['name'])
   contract={'archives':refs,'source_pins':{n:C.sha(s)for n,s in sources.items()},'launcher_sha256':C.sha(HERE/'run.py')};report['input_contract']=contract
   (data/'contract.json').write_text(json.dumps(contract,indent=2)+'\n')
   (context/'Dockerfile').write_text('\n'.join(['FROM '+C.BASE,'USER 0:0','COPY input/ /opt/nm-private-bus/','RUN CACHY_ASAHI_PRIVATE_BUS_IMAGE_BUILD=1 python3 -I /opt/nm-private-bus/image_install.py --allow-private-image-install && find /opt/nm-private-bus -type f -exec chmod 0444 {} + && chmod 0555 /opt/nm-private-bus && cp /etc/shadow /opt/TEST-original-shadow && chmod 0600 /opt/TEST-original-shadow && rm /etc/shadow && ln -s /run/auth-credentials/shadow /etc/shadow','ENV CACHY_ASAHI_USER_AUTH_TEST=1 CACHY_ASAHI_PAM_ACTOR=1','ENTRYPOINT ["/usr/bin/python3","-I","-B","/opt/nm-private-bus/bootstrap.py"]','']))
   cmd('image-build',['docker','build','--network=none','--pull=false','--tag',tag,str(context)],180)
   after=json.loads(subprocess.check_output(['docker','image','inspect',C.BASE],text=True))[0];built=json.loads(subprocess.check_output(['docker','image','inspect',tag],text=True))[0]
   assert after['Id']==C.BASE_ID and built['RootFS']['Layers'][:len(base['RootFS']['Layers'])]==base['RootFS']['Layers']
  argv=['docker','create','--name',name,'--init','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=4g','--pids-limit=256']
  roots={'/run':'0755','/var/lib/NetworkManager':'0700','/etc/NetworkManager':'0700','/home/TEST':'0700','/tmp':'1777','/out':'0755','/polkit':'0755,uid=102,gid=102','/home/UID1000':'0755,uid=1000,gid=1000'}
  for path,mode in roots.items():argv+=['--tmpfs',path+':rw,nodev,nosuid,noexec,size=32m,mode='+mode]
  for k in ['DBUS_SYSTEM_BUS_ADDRESS','DBUS_SESSION_BUS_ADDRESS','DBUS_STARTER_ADDRESS','G_BUS_ADDRESS']:argv+=['--env',k+'=unix:path=/FORBIDDEN-CALLER-BUS']
  cmd('create',argv+[tag]);created=True
  observed=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0];hc=observed['HostConfig'];assert not observed['Mounts']and hc['ReadonlyRootfs']and hc['NetworkMode']=='none'and hc['CapDrop']==['ALL']and not hc['CapAdd']and not hc['Privileged']
  assert hc['NanoCpus']==2_000_000_000 and hc['Memory']==4*1024**3 and hc['PidsLimit']==256
  report['runtime']={k:hc[k]for k in ['ReadonlyRootfs','NetworkMode','CapDrop','CapAdd','Privileged','NanoCpus','Memory','PidsLimit','Tmpfs','SecurityOpt','Devices']};report['image_id']=observed['Image']
  cmd('start',['docker','start',name]);marker('/run/NEED_CREDENTIAL')
  password=secrets.token_urlsafe(32).encode()
  for user,label in [('0:0','private-shadow-provision'),('1000:1000','private-credential-handoff')]:
   result=subprocess.run(['docker','exec','--interactive','--user',user,name,'python3','-I','/opt/nm-private-bus/credential.py'],input=password,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
   assert result.returncode==0,(label,result.stderr.decode(errors='replace'))
   assert password not in result.stdout and password not in result.stderr
   (out/(label+'.log')).write_bytes(result.stdout)
  marker('/out/READY')
  O.prepare();bridge_log=(out/'real-polkit-owner.log').open('wb');bridge=subprocess.Popen(['docker','exec','--user','102:102',name,'/usr/bin/python3','-I','-B','/opt/nm-private-bus/roles.py','polkit'],stdout=bridge_log,stderr=subprocess.STDOUT,start_new_session=True)
  marker('/polkit/STARTED')
  until=time.monotonic()+12
  while True:
   r=subprocess.run(['docker','exec',name,'env','DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket','gdbus','call','--system','--dest','org.freedesktop.DBus','--object-path','/org/freedesktop/DBus','--method','org.freedesktop.DBus.NameHasOwner','org.freedesktop.PolicyKit1'],capture_output=True,timeout=5)
   if r.returncode==0 and b'true'in r.stdout:break
   if time.monotonic()>until:raise TimeoutError('real Polkit authority unavailable')
   time.sleep(.1)
  report['authority']=role('root-authority-credentials','authority')
  report['ordinary_identity']=role('ordinary-bus-credentials-and-policy','identity','1000:1000')
  before=role('before-auth-policy-and-config','snapshot')
  paths=json.loads(cmd('root-fixture-paths',['docker','exec',name,'python3','-I','/opt/nm-private-bus/paths.py']).read_text())
  authlog=(out/'real-agent-PAM.log').open('wb');O.prepare()
  auth=subprocess.Popen(['docker','exec','--user','1000:1000','--env','NM_AUTH_SYSTEM_PATH='+paths['system'],'--env','NM_AUTH_FOREIGN_PATH='+paths['foreign'],name,'python3','-I','-B','/opt/nm-private-bus/authenticate.py'],stdout=authlog,stderr=subprocess.STDOUT,start_new_session=True)
  marker('/home/UID1000/OWN_DONE',35)
  own=json.loads(cmd('own-PAM-result',['docker','exec',name,'cat','/home/UID1000/OWN_RESULT.json']).read_text());report['own_request']=own
  before_denials=role('before-denials-policy-and-config','snapshot')
  assert before['inventory']==before_denials['inventory']and before['policy_pins']==before_denials['policy_pins']
  touch('/run/auth-control/CONTINUE_DENIALS');marker('/home/UID1000/AUTH_DONE',50)
  auth_result=O.supervise(auth,cap=8,retirement=2,grace=.2);auth_result.pop('output');authlog.close();assert auth_result['passed'],auth_result
  report['agent_exec_retirement']=auth_result
  result=json.loads(cmd('ordinary-auth-result',['docker','exec',name,'cat','/home/UID1000/AUTH_REPORT.json']).read_text());report['authentication']=result
  after=role('after-auth-policy-and-config','snapshot');assert before_denials==after,'denied actions changed configuration, inventory or policy'
  report['denied_bytes_inventory_policy_unchanged']=True;report['upstream_policy_pins']=before['policy_pins']
  assert password not in (out/'real-agent-PAM.log').read_bytes()
  report['status']=result['status']
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  if created:
   try:
    touch('/run/auth-control/STOP_POLKIT')
    if bridge is not None:
     result=O.supervise(bridge,cap=12,retirement=2,grace=.2);result.pop('output');report['polkit_exec_bridge_retirement']=result;bridge=None
    touch('/run/auth-control/STOP_ROOT');marker('/out/DONE',20);export()
    for n,k in [('out-report.json','root_fixture_cleanup'),('polkit-report.json','polkit_owner')]:
     if (out/'guest'/n).exists():report[k]=json.loads((out/'guest'/n).read_text())
    touch('/run/auth-control/ALLOW_EXIT');cmd('normal-container-wait',['docker','wait',name],15)
    state=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0]['State'];assert state['ExitCode']==0 and not state['OOMKilled']
    assert report['root_fixture_cleanup']['status']=='PASS_ROOT_FIXTURE_CLEANUP_ONLY'
    assert report['polkit_owner']['retirement']['passed']and report['polkit_exec_bridge_retirement']['passed']
   except BaseException as e:report['status']='HOLD_CLEANUP_OR_AUTHORITY';report['cleanup_failure']=str(e)[:2048]
   r=subprocess.run(['docker','rm','--force',name],capture_output=True,timeout=30);report['owned_container_removed']=r.returncode==0
  if bridge is not None:
   result=O.supervise(bridge,cap=4,retirement=2,grace=.2);result.pop('output');report['failed_exec_bridge_retirement']=result
  if bridge_log is not None:bridge_log.close()
  r=subprocess.run(['docker','image','rm',tag],capture_output=True,timeout=30);report['owned_image_tag_removed']=r.returncode==0
  (out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'ordinary_write_scope':report.get('ordinary_write_scope'),'failure':report.get('failure'),'report':str(out/'report.json')}))
 return 0 if report['status']in {'HOLD_REAL_PAM_OR_AUTHORIZATION','PASS_AUTHENTICATED_OWN_WRITE_AND_DENIALS'}else 1


if __name__=='__main__':raise SystemExit(main())
