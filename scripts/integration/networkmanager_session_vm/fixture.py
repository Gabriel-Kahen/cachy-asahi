#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only root observer: seed files are offline; no authorization grants."""
import hashlib,json,os,socket,subprocess,time
from pathlib import Path
I=Path('/run/nm-session-fixture');H=Path('/home/builder');P=Path('/etc/NetworkManager/system-connections')
POLICY=['/usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy','/usr/share/polkit-1/rules.d/50-default.rules','/usr/lib/pam.d/polkit-1','/etc/pam.d/login','/etc/pam.d/system-login','/etc/passwd','/etc/group']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def snapshot():
 paths=list(P.glob('*'))+[Path(p)for p in POLICY]+[H/'user-config.txt']
 for directory in ['/usr/share/polkit-1/rules.d','/etc/polkit-1/rules.d']:
  paths.extend(p for p in Path(directory).glob('*')if p.is_file())
 paths=list(set(paths))
 assert all(p.is_file()and not p.is_symlink()for p in paths)
 return {'files':{str(p):{'sha256':sha(p),'bytes':p.stat().st_size,'uid':p.stat().st_uid,'mode':p.stat().st_mode&0o7777}for p in sorted(paths)},'packages':subprocess.check_output(['pacman','-Q'],timeout=10).decode()}
def write(name,data):
 p=I/(name+'.json');temp=I/(name+'.tmp');temp.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n');temp.chmod(0o644);temp.replace(p)
def wait(name,deadline):
 while time.monotonic()<deadline:
  p=H/name
  if p.exists():assert p.is_file()and not p.is_symlink()and p.stat().st_uid==1000;return
  time.sleep(.1)
 raise TimeoutError('VM user phase '+name)
def main():
 assert __debug__ and os.geteuid()==0 and Path('/proc/1/comm').read_text().strip()=='systemd'and not Path('/.dockerenv').exists()
 nonce=Path('/etc/tcg-reference-nonce').read_text().strip();assert 'tcg_reference_nonce='+nonce in Path('/proc/cmdline').read_text()
 import gi
 gi.require_version('NM','1.0')
 from gi.repository import NM
 I.mkdir(exist_ok=True);report={'status':'HOLD','scope':'root read-only profile/package observer in full isolated x86 guest'}
 try:
  client=NM.Client.new(None);assert client.get_nm_running()
  paths={}
  for k,u in {'system':'e3140000-0000-4000-8000-000000000021','foreign':'e3140000-0000-4000-8000-000000000022'}.items():
   c=client.get_connection_by_uuid(u);assert c;paths[k]=c.get_path()
  initial=snapshot();write('ready',{'nonce':nonce,'paths':paths,'initial':initial,'version':client.get_version()})
  address=os.environ['NOTIFY_SOCKET'];address='\0'+address[1:]if address.startswith('@')else address
  with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)as notify:notify.connect(address);notify.sendall(b'READY=1')
  deadline=time.monotonic()+240;wait('PERSISTENCE_READY',deadline)
  own=[]
  for p in P.glob('*'):
   data=p.read_text()
   if 'e3140000-0000-4000-8000-000000000023'in data:own.append((p,data))
  assert len(own)==1
  p,data=own[0]
  for value in ['id=TEST-session-own-edited','permissions=user:builder:','autoconnect=false','interface-name=cachy-absent0']:assert value in data,value
  assert p.stat().st_uid==0 and p.stat().st_mode&0o777==0o600
  persisted=snapshot();assert all(persisted['files'][k]==v for k,v in initial['files'].items());assert persisted['packages']==initial['packages']
  write('persisted',{'passed':True,'own_path':str(p),'own_sha256':sha(p),'snapshot':persisted})
  wait('DENIALS_DONE',deadline);denied=snapshot();assert denied==persisted,'denied writes changed configuration/inventory'
  write('denials',{'passed':True,'complete_profile_policy_package_snapshot_unchanged':True})
  wait('SESSION_DONE',deadline);final=snapshot();assert final==initial,'cleanup did not restore original profile inventory'
  report.update(status='PASS_X86_ROOT_OBSERVATION_ONLY',own_persisted=True,denied_state_unchanged=True,own_profile_cleanup=True,user_and_original_profiles_preserved=True,inventory_policy_PAM_unchanged=True,initial=initial,final=final)
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:write('final',report)
 return 0 if report['status']=='PASS_X86_ROOT_OBSERVATION_ONLY'else 1
if __name__=='__main__':raise SystemExit(main())
