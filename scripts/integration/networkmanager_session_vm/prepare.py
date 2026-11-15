#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare the next offline x86 VM experiment. Never starts QEMU or guest code."""
import argparse,hashlib,importlib.util,json,os,secrets,shutil,subprocess,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2];SUB=HERE.parent/'systemd_tcg_guest'
TOOL='cachy-tcg-tools:reference-reviewed';TOOL_ID='sha256:c6bd2d0ed8c437a74b3e1713b7bfcb023b7446f1abe3c0d27a6a5b4fd734f925'
PROVIDER='cachy-asahi-nm-source-final:20261114';PROVIDER_ID='sha256:7052baf57a6eec068371ffdb2f9670ef69bd5ce11ee3ba67f705b724dc8a53d5'
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-prepare-session-vm',action='store_true');p.add_argument('--reference',type=Path,required=True);p.add_argument('--archives',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_prepare_session_vm and __debug__ and os.geteuid()!=0):p.error('explicit ordinary-user preparation required')
 C=load('nm_session_candidate_intake',HERE.parent/'networkmanager_candidate/run.py');refs=C.inputs(a.archives.resolve(strict=True))
 security=json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}']));assert 'name=rootless'in security
 for image,pin in [(TOOL,TOOL_ID),(PROVIDER,PROVIDER_ID)]:assert json.loads(subprocess.check_output(['docker','image','inspect',image]))[0]['Id']==pin
 reference=a.reference.resolve(strict=True);old=json.loads((reference/'prepared.json').read_text());assert old['files']['vmlinuz']['sha256']=='b1e9eaf5700a53a31ed923edecd72b319a29da74be32c0885bff112d37ce325b'and old['files']['initramfs.img']['sha256']=='9765fd579cee81a14092b10da1daa762e58c8e2112883a84f57a60550d1de8c9'
 for name in ['vmlinuz','initramfs.img']:assert sha(reference/name)==old['files'][name]['sha256']
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700);before=shutil.disk_usage(out).free;assert before>3*1024**3
 tag='cachy-nm-session-tools:'+secrets.token_hex(8);name='cachy-nm-session-assembly-'+secrets.token_hex(16);created=False;report={'schema_version':1,'status':'HOLD','VM_boot':'NOT RUN','scope':'fresh x86 full-system NM/session preparation only','provider':{'image':PROVIDER,'id':PROVIDER_ID},'fixed_substrate':{'image':TOOL,'id':TOOL_ID,'source_pins':{n:sha(SUB/n)for n in ['boot.py','vm_actor.py','guest-proof.sh']}},'archives':refs,'free_before':before}
 def call(label,argv,timeout=60):
  with(out/(label+'.log')).open('wb')as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
 try:
  with tempfile.TemporaryDirectory(prefix='.context-',dir=out)as temporary:
   context=Path(temporary);data=context/'input';data.mkdir()
   program="import json,tarfile;t=tarfile.open('/opt/guest-base.tar.zst');out={};\nfor m in t:\n if m.name.startswith('var/lib/pacman/local/')and m.name.endswith('/desc'):\n  s=t.extractfile(m).read().decode();out[s.split('%NAME%\\n')[1].split('\\n')[0]]=s.split('%VERSION%\\n')[1].split('\\n')[0]\nprint(json.dumps(out,sort_keys=True))"
   raw=subprocess.check_output(['docker','run','--rm','--init=false','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=512m','--pids-limit=64','--entrypoint=/usr/bin/python3',TOOL,'-I','-c',program],timeout=30)
   base=json.loads(raw);assert 100<len(base)<200;(data/'base-inventory.json').write_bytes(raw)
   runtime={'nm-session-assemble.py':sha(HERE/'assemble.py'),'nm-session-fixture.py':sha(HERE/'fixture.py'),'nm-session-client.py':sha(HERE/'client.py'),'nm-session-fixture.service':sha(HERE/'fixture.service'),'nm-session-session-proof.sh':sha(SUB/'guest-proof.sh')}
   (data/'contract.json').write_text(json.dumps({'archives':refs,'provider':report['provider'],'runtime_sources':runtime})+'\n')
   for ref in refs:shutil.copyfile(a.archives/ref['name'],data/ref['name'])
   for source in ['export_guest.py','assemble.py','fixture.py','client.py','fixture.service']:shutil.copyfile(HERE/source,data/source)
   shutil.copyfile(SUB/'guest-proof.sh',data/'guest-proof.sh')
   for source,dest in [('vmlinuz','reference-vmlinuz'),('initramfs.img','reference-initramfs.img')]:shutil.copyfile(reference/source,data/dest)
   dockerfile='\n'.join(['FROM '+PROVIDER+' AS provider','USER 0:0','COPY input/ /opt/nm-session-input/','RUN NM_SESSION_IMAGE_BUILD=1 python3 -I -B /opt/nm-session-input/export_guest.py','FROM '+TOOL,'COPY --from=provider /opt/nm-session-additions.tar.zst /opt/nm-session-export.json /opt/','COPY input/assemble.py /opt/nm-session-assemble.py','COPY input/fixture.py /opt/nm-session-fixture.py','COPY input/client.py /opt/nm-session-client.py','COPY input/fixture.service /opt/nm-session-fixture.service','COPY input/guest-proof.sh /opt/nm-session-session-proof.sh','COPY input/contract.json /opt/nm-session-inputs.json','COPY input/reference-vmlinuz input/reference-initramfs.img /opt/','RUN chmod 0444 /opt/nm-session-* /opt/reference-*',''])
   (context/'Dockerfile').write_text(dockerfile);report['Dockerfile']=dockerfile;report['source_pins']={f.name:sha(f)for f in HERE.iterdir()if f.is_file()and f.suffix in {'.py','.service'}}
   call('tool-image-build',['docker','build','--network=none','--pull=false','--tag',tag,str(context)],240)
  image=json.loads(subprocess.check_output(['docker','image','inspect',tag]))[0];report['tool_image']=tag;report['tool_image_id']=image['Id']
  assembly=out/'prepared';assembly.mkdir(mode=0o700)
  call('create',['docker','create','--name',name,'--init=false','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,size=1280m','--mount','type=bind,source='+str(assembly)+',target=/work','--entrypoint=/usr/bin/fakeroot',tag,'--','/usr/bin/python3','-I','-B','/opt/nm-session-assemble.py']);created=True
  call('assemble',['docker','start','--attach',name],300)
  observed=json.loads(subprocess.check_output(['docker','inspect',name]))[0];assert observed['State']['ExitCode']==0 and not observed['State']['OOMKilled']
  report['prepared']=json.loads((assembly/'prepared.json').read_text());report['prepared_sha256']=sha(assembly/'prepared.json');report['free_after']=shutil.disk_usage(out).free;report['global_free_delta']=before-report['free_after'];assert report['global_free_delta']<3*1024**3,'3GiB additional disk bound exceeded'
  report['status']='PREPARED_NOT_BOOTED'
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  if created:
   result=subprocess.run(['docker','rm','--force',name],capture_output=True,timeout=20);report['assembly_container_removed']=result.returncode==0
   if result.returncode:report['status']='HOLD_CLEANUP'
  (out/'preparation.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'report':str(out/'preparation.json'),'failure':report.get('failure')}));return 0 if report['status']=='PREPARED_NOT_BOOTED'else 1
if __name__=='__main__':raise SystemExit(main())
