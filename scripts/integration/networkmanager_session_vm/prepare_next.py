#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fresh raw/nonce/credential, reusing the exact previous verified payload image."""
import argparse,hashlib,json,os,secrets,shutil,subprocess,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;SUB=HERE.parent/'systemd_tcg_guest'
PROVIDER='cachy-nm-session-tools:659aeb311cbc49a6';PIN='sha256:064b5cbbbdabe0c51ad6dd72c3f5bf33642168714690a1468f552b7488b2096b'
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-prepare-challenge-vm',action='store_true');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_prepare_challenge_vm and __debug__ and os.geteuid()!=0):p.error('explicit ordinary-user preparation only')
 assert 'name=rootless'in json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}']))
 image=json.loads(subprocess.check_output(['docker','image','inspect',PROVIDER]))[0];assert image['Id']==PIN
 out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False);before=shutil.disk_usage(out).free;assert before>2*1024**3
 tag='cachy-nm-session-challenge:'+secrets.token_hex(8);name='cachy-nm-session-assemble-'+secrets.token_hex(16);created=False
 report={'schema_version':1,'status':'HOLD','VM_boot':'NOT RUN','previous_payload_image':{'name':PROVIDER,'id':PIN},'scope':'new x86 real-TTY credential experiment preparation; no old marker replay','free_before':before}
 def call(label,argv,timeout=60):
  with(out/(label+'.log')).open('wb')as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
 try:
  with tempfile.TemporaryDirectory(prefix='.context-',dir=out)as temporary:
   context=Path(temporary);mapping={'assemble.py':'nm-session-assemble.py','client.py':'nm-session-client.py','fixture.py':'nm-session-fixture.py','fixture.service':'nm-session-fixture.service'}
   sources={dest:HERE/source for source,dest in mapping.items()};sources['nm-session-session-proof.sh']=SUB/'guest-proof.sh'
   runtime={dest:sha(source)for dest,source in sources.items()}
   for dest,source in sources.items():shutil.copyfile(source,context/dest)
   (context/'nm-session-inputs.json').write_text(json.dumps({'runtime_sources':runtime},sort_keys=True)+'\n')
   dockerfile='\n'.join(['FROM '+PROVIDER,'USER 0:0',*[f'COPY {name} /opt/{name}'for name in [*sources,'nm-session-inputs.json']],'RUN chmod 0444 /opt/nm-session-*',''])
   (context/'Dockerfile').write_text(dockerfile);report['Dockerfile']=dockerfile;report['runtime_source_pins']=runtime;report['source_pins']={f.name:sha(f)for f in HERE.iterdir()if f.is_file()and f.suffix in {'.py','.service'}}
   call('copy-only-tool-image',['docker','build','--network=none','--pull=false','--tag',tag,str(context)],120)
  current=json.loads(subprocess.check_output(['docker','image','inspect',tag]))[0];assert current['RootFS']['Layers'][:len(image['RootFS']['Layers'])]==image['RootFS']['Layers'];report.update(tool_image=tag,tool_image_id=current['Id'])
  assembly=out/'prepared';assembly.mkdir(mode=0o700)
  call('create',['docker','create','--name',name,'--init=false','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,size=1280m','--mount','type=bind,source='+str(assembly)+',target=/work','--entrypoint=/usr/bin/fakeroot',tag,'--','/usr/bin/python3','-I','-B','/opt/nm-session-assemble.py']);created=True
  call('assemble',['docker','start','--attach',name],300)
  state=json.loads(subprocess.check_output(['docker','inspect',name]))[0]['State'];assert state['ExitCode']==0 and not state['OOMKilled']
  prepared=json.loads((assembly/'prepared.json').read_text());assert prepared['runtime_source_pins']==runtime
  report.update(prepared=prepared,prepared_sha256=sha(assembly/'prepared.json'),free_after=shutil.disk_usage(out).free);report['global_free_delta']=before-report['free_after'];assert report['global_free_delta']<3*1024**3
  report['status']='PREPARED_NOT_BOOTED'
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  if created:
   r=subprocess.run(['docker','rm','--force',name],capture_output=True,timeout=20);report['owned_assembly_container_removed']=r.returncode==0
   if r.returncode:report['status']='HOLD_CLEANUP'
  (out/'preparation.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'report':str(out/'preparation.json'),'failure':report.get('failure')}));return 0 if report['status']=='PREPARED_NOT_BOOTED'else 1
if __name__=='__main__':raise SystemExit(main())
