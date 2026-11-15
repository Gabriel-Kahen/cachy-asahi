#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""COPY-only real-seat reference preparation; never launches a VM."""
import argparse,hashlib,importlib.util,json,os,secrets,shutil,subprocess,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;BASE='cachy-nm-session-challenge:c4b31ba52acaa84e';PIN='sha256:214e6381db6706d05c53ebe96f2eb9b43d9243c41fa8103c253a63412d57f483'
def sha(p):
 with p.open('rb')as s:return hashlib.file_digest(s,'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-prepare-seat-reference',action='store_true');p.add_argument('--kernel',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_prepare_seat_reference and __debug__ and os.geteuid()!=0):p.error('explicit ordinary-user preparation required')
 spec=importlib.util.spec_from_file_location('seat_kernel_data',HERE/'kernel_probe.py');K=importlib.util.module_from_spec(spec);spec.loader.exec_module(K);kernel=K.inspect(a.kernel);assert kernel['kernel_sha256']=='b1e9eaf5700a53a31ed923edecd72b319a29da74be32c0885bff112d37ce325b'
 assert 'name=rootless'in json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}']))
 base=json.loads(subprocess.check_output(['docker','image','inspect',BASE]))[0];assert base['Id']==PIN
 out=a.output.resolve();out.mkdir(parents=True,mode=0o700,exist_ok=False);before=shutil.disk_usage(out).free;assert before>3*1024**3
 tag='cachy-tcg-real-seat:'+secrets.token_hex(8);name='cachy-tcg-seat-assembly-'+secrets.token_hex(16);created=False;report={'schema_version':1,'status':'HOLD','VM_boot':'NOT RUN','kernel_DATA_probe':kernel,'base':{'name':BASE,'id':PIN},'free_before':before}
 def call(label,args,timeout=60):
  with(out/(label+'.log')).open('wb')as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
 try:
  with tempfile.TemporaryDirectory(prefix='.context-',dir=out)as temp:
   context=Path(temp);mapping={'assemble.py':'seat-assemble.py','user_proof.py':'seat-user-proof.py','observer.py':'seat-observer.py','observer.service':'seat-observer.service','input_seat.py':'seat-input.py','keyboard.py':'seat-keyboard.py','vm_actor.py':'vm_actor.py'}
   sources={dest:sha(HERE/source)for source,dest in mapping.items()}
   for source,dest in mapping.items():shutil.copyfile(HERE/source,context/dest)
   (context/'seat-inputs.json').write_text(json.dumps({'sources':sources},sort_keys=True)+'\n')
   dockerfile='\n'.join(['FROM '+BASE,'USER 0:0',*[f'COPY {n} /opt/{n}'for n in [*sources,'seat-inputs.json']],'RUN chmod 0444 /opt/seat-* /opt/vm_actor.py',''])
   (context/'Dockerfile').write_text(dockerfile);report['Dockerfile']=dockerfile;report['source_pins']={f.name:sha(f)for f in HERE.iterdir()if f.is_file()and f.suffix in {'.py','.service'}}
   call('COPY-only-image',['docker','build','--network=none','--pull=false','--tag',tag,str(context)],120)
  image=json.loads(subprocess.check_output(['docker','image','inspect',tag]))[0];assert image['RootFS']['Layers'][:len(base['RootFS']['Layers'])]==base['RootFS']['Layers'];report.update(tool_image=tag,tool_image_id=image['Id'])
  memory=dict(line.split(':',1)for line in Path('/proc/meminfo').read_text().splitlines());available=int(memory['MemAvailable'].split()[0])*1024;report['aggregate_memory_admission']={'MemAvailable_bytes':available,'assembly_cap_bytes':3*1024**3,'reserved_additional_bytes':3*1024**3};assert available>=6*1024**3,'aggregate memory admission: need6GiB available before3GiB-capped assembly';assert shutil.disk_usage(out).free>=3*1024**3,'need3GiB tmp free before fresh assembly'
  prepared=out/'prepared';prepared.mkdir(mode=0o700)
  call('create',['docker','create','--name',name,'--init=false','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,size=1280m','--mount','type=bind,source='+str(prepared)+',target=/work','--entrypoint=/usr/bin/fakeroot',tag,'--','/usr/bin/python3','-I','-B','/opt/seat-assemble.py']);created=True
  call('assemble',['docker','start','--attach',name],300)
  state=json.loads(subprocess.check_output(['docker','inspect',name]))[0]['State'];assert state['ExitCode']==0 and not state['OOMKilled'];report.update(prepared=json.loads((prepared/'prepared.json').read_text()),prepared_sha256=sha(prepared/'prepared.json'),free_after=shutil.disk_usage(out).free);report['global_free_delta']=before-report['free_after'];assert report['global_free_delta']<3*1024**3;report['status']='PREPARED_NOT_BOOTED'
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  if created:
   r=subprocess.run(['docker','rm','--force',name],capture_output=True,timeout=20);report['owned_assembly_removed']=r.returncode==0
   if r.returncode:report['status']='HOLD_CLEANUP'
  (out/'preparation.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'report':str(out/'preparation.json'),'failure':report.get('failure')}));return 0 if report['status']=='PREPARED_NOT_BOOTED'else 1
if __name__=='__main__':raise SystemExit(main())
