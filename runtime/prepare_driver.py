#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One bounded five-cap preparer under an existing owned original574 producer."""
import argparse,json,os,re,shutil,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
import media_adapter as M
LABEL='org.cachy-asahi.ksm2-vm.prepare'
CAPS=('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP')

def ordinary(path):
 p=Path(path).absolute();C.need(not any(q.is_symlink()for q in(p,*p.parents))and ','not in str(p)and '\n'not in str(p),'ordinary fixed bind path');return p

def argv(image,nonce,source,work,inputs,disks):
 C.need(re.fullmatch('sha256:[a-f0-9]{64}',image)and re.fullmatch('[a-f0-9]{32}',nonce),'exact producer image and nonce')
 name='caa-ksm2-vm-'+nonce+'-prepare';cmd=['/usr/bin/docker','run','--name',name,'--label',LABEL+'='+nonce,'--pull=never','--platform=linux/arm64','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=256','--memory=2g','--cpus=2','--tmpfs=/tmp:rw,nosuid,nodev,size=512m']+['--cap-add='+v for v in CAPS]
 bindings={ '/inputs':inputs,'/out':work/'guest-out','/upgrade-code':source/'media-source','/upgrade-config.json':work/'upgrade-config.json','/persistent_scope.py':source/'media-source/scripts/ci/full-root-upgrade-caller/persistent_scope.py','/upgrade-signing':work/'signing','/workspace':work/'runner','/source':source}
 for dest,path in bindings.items():cmd+=['--mount','type=bind,src='+str(ordinary(path))+',dst='+dest+',readonly']
 cmd+=['--mount','type=bind,src='+str(ordinary(disks))+',dst=/measurement','--env=CAA_KSM2_VM_PREPARE='+nonce,'--entrypoint=/usr/bin/python3',image,'-I','-B','/workspace/media_adapter.py']
 return name,cmd

def run(a):
 source=C.HERE;s=C.decode(C.read(a.selection));C.native_gate(s,a.inputs);C.actual_identity(s);C.actual_environment(s);C.support();C.source_check();C.need(s.get('media')is None and s.get('producer_report')is not None,'bound original producer; media absent before preparation')
 K=C.load('_ksm_prepare_driver_kernel',source/'kernel_input.py');profile,_,_,_=K.imported(s,a.inputs);C.need(s['kernel']==profile,'fresh actual kernel profile before staging')
 producer=C.decode(C.checked(a.inputs,s['producer_report'],2*1024**2));owner=producer['ownership'];image=producer['image']
 C.need(producer['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION'and producer['packages']==574 and producer['native_build']=='PASS'and producer['build_returncode']==0 and producer['host_arch']in('aarch64','arm64')and producer['daemon_arch']in('aarch64','arm64')and owner['build_started']and owner['build_complete']and owner['probe_complete']and owner['image']==image and image not in owner['before_images']and re.fullmatch('[a-f0-9]{16}',owner['token']),'actual source-bound owned574 producer build/probe required')
 work=ordinary(a.work);disks=ordinary(a.media);C.need(not work.exists()and not disks.exists()and work.parent==disks.parent and work.parent.is_dir(),'fresh sibling preparation leases')
 work.mkdir(mode=0o700);disks.mkdir(mode=0o700);st=work.stat();C.save(work/'work-owner.json',dict(nonce=s['nonce'],source=s['VM_source'],identity=[st.st_dev,st.st_ino,st.st_uid]))
 for name in('runner','guest-out','signing','docker-config'): (work/name).mkdir(mode=0o700)
 for n,pin in s['runner_files'].items():C.need(C.row(source/n)==pin,'source-pinned flat runner');shutil.copyfile(source/n,work/'runner'/n)
 C.save(work/'runner/selection.json',s);C.save(work/'runner/input-map.json',{}) # Guest source/native gates independently check complete readonly roles.
 shutil.copyfile(source/'media-source/scripts/ci/expanded604-apps6-public-pair-updater/fixtures/normal-upgrade-config.json',work/'upgrade-config.json') # Whole held config; donor reads only original scale limits.
 R=C.load('_ksm_prepare_driver_supervisor',source/'borrowed/runtime.py');records=[];env=dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME=str(work),DOCKER_CONFIG=str(work/'docker-config'));name,cmd=argv(image,s['nonce'],source,work,a.inputs,disks)
 def command(values,seconds=30,allow=False):
  row,out,err,error=R.run_command(values,work,env,seconds,2*1024**2);records.append(row);number=str(len(records)).zfill(2);(work/('command-'+number+'.stdout')).write_bytes(out);(work/('command-'+number+'.stderr')).write_bytes(err);C.save(work/'commands.json',records);C.need(error is None and row['group_absence_verified']is True and (allow or row['exit_code']==0),'owned prepare command/group failure');return row,out,err
 def inspect():
  row,out,err=command(['/usr/bin/docker','container','inspect',name],allow=True)
  if row['exit_code']:
   C.need(row['exit_code']==1 and name.encode()in out+err and b'No such'in out+err,'unambiguous owned actor absence');return None
  values=C.decode(out);C.need(len(values)==1,'one actor');v=values[0];C.need(v['Name']=='/'+name and v['Image']==image and v['Config']['Labels'].get(LABEL)==s['nonce']and re.fullmatch('[a-f0-9]{64}',v['Id']),'exact owned actor identity');return v
 C.need(inspect()is None,'no existing actor may be borrowed')
 metadata=command(['/usr/bin/docker','image','inspect',image])[1];images=C.decode(metadata);C.need(len(images)==1 and images[0]['Id']==image and images[0]['Config']['Labels'].get('org.cachy-asahi.bootstrap574.job')==owner['token'],'exact original producer image label')
 error=None
 try:
  row,out,err=command(cmd,1900);(work/'prepare.stdout').write_bytes(out);(work/'prepare.stderr').write_bytes(err);C.need(inspect()is not None,'completed retained preparer identity')
 finally:
  # No producer removal here: original owner retains that obligation after all consumers.
  v=inspect()
  if v is not None:command(['/usr/bin/docker','rm','-f',v['Id']])
  C.need(inspect()is None,'preparer actor absent before returning media')
 lease=C.decode(C.read(disks/'ksm2-media.json'));C.need(lease['nonce']==s['nonce'],'actual prepared nonce');result=dict(status='PASS_PREPARED_MEDIA_AND_OWNED_ACTOR_RETIRED_NOT_VM',nonce=s['nonce'],actor=name,actor_absent=True,producer_image=image,producer_cleanup='REQUIRED_FROM_ORIGINAL_OWNER_AFTER_ALL_CONSUMERS',prepared=C.row(disks/'ksm2-media.json'),records=records);C.save(work/'preparation-result.json',result);return result

def retire_work(work,s,qemu,output):
 # Called only after successful same-process host protocol and direct QEMU wait.
 C.need(qemu['group_absence_verified']is True,'retain work while QEMU group absent unknown');work=ordinary(work);held=C.decode(C.read(work/'work-owner.json'));st=work.lstat();C.need(held==dict(nonce=s['nonce'],source=s['VM_source'],identity=[st.st_dev,st.st_ino,st.st_uid])and st.st_uid==os.getuid()and stat.S_IMODE(st.st_mode)==0o700,'same fresh private work lease')
 proof=C.decode(C.read(work/'preparation-result.json'));C.need(proof['nonce']==s['nonce']and proof['actor_absent']is True,'actual preparer absence before work retirement')
 records=C.decode(C.read(work/'commands.json'));C.need(records and all(r['group_absence_verified']is True for r in records),'all original preparation command groups retired')
 total=0;count=0
 for directory,dirs,files in os.walk(work,followlinks=False):
  for name in dirs+files:
   p=Path(directory)/name;v=p.lstat();count+=1;C.need(count<=2048 and v.st_uid==os.getuid()and v.st_dev==st.st_dev and(stat.S_ISDIR(v.st_mode)or stat.S_ISREG(v.st_mode)and v.st_nlink==1),'only caller-owned same-device ordinary scratch tree')
   if stat.S_ISREG(v.st_mode):total+=v.st_size;C.need(total<=32*1024**2,'bounded scratch retention')
 C.save(Path(output)/'preparation-retirement.json',dict(status='PASS_EXACT_OWNED_PREPARATION_WORK_RETIRED',nonce=s['nonce'],identity=held['identity'],preparation=proof,commands=records))
 C.need(shutil.rmtree.avoids_symlink_attacks,'descriptor-safe scratch removal');shutil.rmtree(work);C.need(not work.exists(),'scratch work remains');return 'PASS_EXACT_OWNED_PREPARATION_WORK_REMOVED'

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in('selection','inputs','work','media'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();print(json.dumps(run(a),sort_keys=True))
