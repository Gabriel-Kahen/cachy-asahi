#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare one fresh real-seat NM fixture; no VM/package/network execution."""
import argparse,hashlib,importlib.util,json,os,secrets,shutil,subprocess,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;INTEGRATION=HERE.parent
BASE='cachy-tcg-real-seat:196337a5c11df127';PIN='sha256:e34f4f1c8fa36c1bc7ffa03d707f8b9eeed933163a4b10800b8cd90103fac1e6'
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-prepare-nm-seat-reference',action='store_true');p.add_argument('--archives',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_prepare_nm_seat_reference and __debug__ and os.geteuid()!=0):p.error('explicit ordinary-user offline preparation required')
 references=json.loads((HERE/'references.json').read_text())
 for name,ref in references.items():assert sha(INTEGRATION/name)==ref['sha256'],'retained source drift: '+name
 s=importlib.util.spec_from_file_location('NM_seat_archive_intake',INTEGRATION/'networkmanager_candidate/run.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C);archives=C.inputs(a.archives.resolve(strict=True))
 assert 'name=rootless'in json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}']))
 base=json.loads(subprocess.check_output(['docker','image','inspect',BASE]))[0];assert base['Id']==PIN
 out=a.output.resolve();out.mkdir(parents=True,mode=0o700,exist_ok=False);before=shutil.disk_usage(out).free;assert before>=3*1024**3
 report={'schema_version':1,'status':'HOLD','VM_boot':'NOT RUN','scope':'fresh x86 full real-seat NM lifecycle preparation only','base':{'image':BASE,'id':PIN},'archives':archives,'reference_sources':references,'free_before':before};tag='cachy-nm-real-seat:'+secrets.token_hex(8);assembly_name='cachy-nm-seat-assembly-'+secrets.token_hex(16);created=False
 def call(label,args,timeout=60):
  with(out/(label+'.log')).open('wb')as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
 try:
  with tempfile.TemporaryDirectory(prefix='.context-',dir=out)as temp:
   context=Path(temp);mapping={'seat-assemble.py':HERE/'assemble.py','seat-observer.py':HERE/'observer.py','seat-user-proof.py':INTEGRATION/'systemd_tcg_seat_guest/user_proof.py','seat-observer.service':INTEGRATION/'systemd_tcg_seat_guest/observer.service','seat-keyboard.py':INTEGRATION/'systemd_tcg_seat_guest/keyboard.py','seat-input.py':INTEGRATION/'systemd_tcg_seat_guest/input_seat.py','vm_actor.py':INTEGRATION/'systemd_tcg_seat_guest/vm_actor.py','nm-seat-client.py':HERE/'client.py','nm-seat-result.py':HERE/'result.py','nm-session-fixture.py':INTEGRATION/'networkmanager_session_vm/fixture.py','nm-session-fixture.service':HERE/'fixture.service'}
   sources={name:sha(path)for name,path in mapping.items()}
   for name,path in mapping.items():shutil.copyfile(path,context/name)
   (context/'seat-inputs.json').write_text(json.dumps({'sources':sources},sort_keys=True)+'\n')
   dockerfile='\n'.join(['FROM '+BASE,'USER 0:0',*[f'COPY {n} /opt/{n}'for n in [*sources,'seat-inputs.json']],'RUN chmod 0444 /opt/seat-* /opt/nm-seat-* /opt/nm-session-fixture* /opt/vm_actor.py',''])
   (context/'Dockerfile').write_text(dockerfile);report['Dockerfile']=dockerfile;report['source_pins']={f.name:sha(f)for f in HERE.iterdir()if f.is_file()and f.suffix in {'.py','.service','.json'}}
   call('COPY-only-image',['docker','build','--network=none','--pull=false','--tag',tag,str(context)],120)
  image=json.loads(subprocess.check_output(['docker','image','inspect',tag]))[0];assert image['RootFS']['Layers'][:len(base['RootFS']['Layers'])]==base['RootFS']['Layers'];report.update(tool_image=tag,tool_image_id=image['Id'])
  memory=dict(line.split(':',1)for line in Path('/proc/meminfo').read_text().splitlines());available=int(memory['MemAvailable'].split()[0])*1024;assert available>=6*1024**3 and shutil.disk_usage(out).free>=3*1024**3,'aggregate memory/storage admission failed';report['aggregate_memory_admission']={'MemAvailable_bytes':available,'assembly_cap_bytes':3*1024**3,'additional_reserve_bytes':3*1024**3}
  prepared=out/'prepared';prepared.mkdir(mode=0o700)
  call('create',['docker','create','--name',assembly_name,'--init=false','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,size=1280m','--mount','type=bind,source='+str(prepared)+',target=/work','--entrypoint=/usr/bin/fakeroot',tag,'--','/usr/bin/python3','-I','-B','/opt/seat-assemble.py']);created=True
  call('assemble',['docker','start','--attach',assembly_name],300);state=json.loads(subprocess.check_output(['docker','inspect',assembly_name]))[0]['State'];assert state['ExitCode']==0 and not state['OOMKilled']
  report.update(prepared=json.loads((prepared/'prepared.json').read_text()),prepared_sha256=sha(prepared/'prepared.json'),free_after=shutil.disk_usage(out).free);report['global_free_delta']=before-report['free_after'];assert report['global_free_delta']<3*1024**3;report['status']='PREPARED_NOT_BOOTED'
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  if created:
   r=subprocess.run(['docker','rm','--force',assembly_name],capture_output=True,timeout=20);report['owned_assembly_removed']=r.returncode==0
   if r.returncode:report['status']='HOLD_CLEANUP'
  (out/'preparation.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'report':str(out/'preparation.json'),'failure':report.get('failure')}));return 0 if report['status']=='PREPARED_NOT_BOOTED'else 1
if __name__=='__main__':raise SystemExit(main())
