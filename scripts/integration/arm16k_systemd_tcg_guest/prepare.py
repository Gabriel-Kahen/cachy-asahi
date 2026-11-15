#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Prepare one separate ARM16K systemd guest; never boot or execute guest code."""
import argparse,base64,hashlib,importlib.util,json,os,re,secrets,shutil,sys,tarfile,time,traceback
from pathlib import Path

HERE=Path(__file__).resolve().parent
PARENT='sha256:c6bd2d0ed8c437a74b3e1713b7bfcb023b7446f1abe3c0d27a6a5b4fd734f925'
CATALOGS={'core.db':'aec62efbfb59d300204f936a633a59d3c89d6a7e7f94852b8f621b61a253afae','extra.db':'1b4caf18e4a57ba10f201c7b19892bb55a37283c2b0369b39cc6c4f6b654151d'}
SIG={'bytes':566,'sha256':'0157d8cd6261c85205931c766b754d6d56112b28800666fb64add1de192ebe11'}
KEY={'bytes':3098,'sha256':'6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f'}
SIGNER='68B3537F39A313B3E574D06777193F152BDBE6A6'
LIMIT=3*1024**3


def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def sha(path):
 with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()


def allocated(path):
 return sum(p.lstat().st_blocks*512 for p in (path,*path.rglob('*'))if not p.is_symlink())


def catalogs(directory):
 rows={}
 for name,digest in CATALOGS.items():
  path=directory/name;assert path.is_file()and not path.is_symlink()and sha(path)==digest
  with tarfile.open(path)as archive:
   for item in archive:
    if item.name.endswith('/desc'):
     assert item.isfile()and item.size<131072
     row={p.splitlines()[0].strip('%'):p.splitlines()[1:]for p in archive.extractfile(item).read().decode().split('\n\n')if p.startswith('%')}
     name=row['NAME'][0];assert name not in rows;row['repository']=[path.stem];rows[name]=row
 return rows


def assert_budget(inputs,output,parent_size,tool_size=0,scratch=0,prior=()):
 # Include the existing acquired archive and this NEW checkout, not unrelated /tmp users.
 # Conservatively count both the committed delta and the still-owned install RW layer.
 value=allocated(inputs)+allocated(output)+allocated(HERE.parents[2])+2*max(0,tool_size-parent_size)+scratch+sum(allocated(path)for path in prior)
 assert value<=LIMIT,('owned additional disk cap',value,LIMIT)
 assert shutil.disk_usage(output).free>=512*1024**2+scratch,'/tmp safety reserve'
 assert shutil.disk_usage('/home').free>=512*1024**2,'/home safety reserve'
 return value


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--allow-prepare-arm16k',action='store_true');p.add_argument('--inputs',type=Path,required=True)
 p.add_argument('--kernel-data',type=Path,required=True);p.add_argument('--catalogs',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--prior-output',type=Path,action='append',default=[],help='include retained outputs from earlier owned attempts in the3GiB cap')
 a=p.parse_args()
 if not(a.allow_prepare_arm16k and __debug__ and sys.flags.isolated and os.geteuid()!=0):p.error('isolated ordinary-user invocation and explicit prepare opt-in required')
 os.umask(0o077);inputs=a.inputs.resolve(strict=True);out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 assert str(inputs).startswith('/tmp/')and str(out).startswith('/tmp/'),'preparation is confined to owned /tmp storage'
 for directory in (inputs,out):assert directory.stat().st_uid==os.getuid()and not directory.stat().st_mode&0o077
 prior=[path.resolve(strict=True)for path in a.prior_output]
 assert len(set(prior))==len(prior)and all(str(path).startswith('/tmp/')and path.stat().st_uid==os.getuid()and path not in (inputs,out)for path in prior)
 origins=json.loads((HERE/'frozen/origin.json').read_text())
 for name,ref in origins.items():
  path=HERE/'frozen'/name;assert path.stat().st_size==ref['bytes']and sha(path)==ref['sha256']
 B=load('arm16k_reference_primitives',HERE/'frozen/reference_controller.py')
 C=load('arm16k_command_runtime',HERE/'frozen/command_runtime.py')
 D=load('arm16k_inspection',HERE/'inspect_inputs.py');S=load('arm16k_selection',HERE/'select_guest.py')
 runner=C.Runner(1800,dict(os.environ),out)
 state=B.Cancellation();state.__enter__();scopes=[];tool=None
 report={'schema_version':1,'status':'HOLD','scope':'emulated ARM16K input preparation only','VM_boot':'NOT RUN','native16K':'NOT RUN','M2':'NOT RUN','parent_tool_image_id':PARENT,'catalogs':CATALOGS,'additional_disk_limit':LIMIT}
 def cmd(label,argv,timeout=120):
  result=runner.run(argv,timeout=timeout,log=label+'.log');assert result.returncode==0,(label,result.returncode);return result.stdout
 def image(name):return json.loads(cmd('inspect-'+secrets.token_hex(4),['docker','image','inspect',name]))[0]
 class Scope(B.OwnedContainer):
  def validate(self,row):
   assert re.fullmatch('[0-9a-f]{64}',row.get('Id',''))and row['Name']=='/'+self.name
   assert row['Image']==self.image and row['Config']['Labels']==self.labels
   assert row['Config']['Entrypoint']==self.entrypoint and row['Config']['Cmd']==self.args
   assert {(m['Type'],m['Source'],m['Destination'],m['RW'])for m in row['Mounts']}==set(self.mounts)and len(row['Mounts'])==len(self.mounts)
   h=row['HostConfig'];assert h['NetworkMode']=='none'and h['CapDrop']==['ALL']and not h['CapAdd']and not h['Privileged']and not h['Devices']and h.get('Init')is True
   assert h['ReadonlyRootfs']==self.readonly and h['Memory']==3*1024**3 and h['NanoCpus']==2_000_000_000 and h['PidsLimit']==256
   assert h['SecurityOpt']==['no-new-privileges']
 def container(label,tool_id,entry,args,mounts,readonly=True,tmpfs='64m',timeout=240):
  name='cachy-arm16k-prepare-'+secrets.token_hex(12);labels=dict(image(tool_id).get('Config',{}).get('Labels')or{})
  labels.update({'org.cachy-asahi.arm16k-prepare-owner':str(os.getuid()),'org.cachy-asahi.arm16k-prepare-operation':name})
  scope=Scope(name,out/(label+'.cid'),tool_id,labels,inputs,out);scope.entrypoint=[entry];scope.args=args;scope.mounts=mounts;scope.readonly=readonly;scopes.append(scope)
  argv=['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init',*[x for k,v in labels.items()for x in ('--label',k+'='+v)],'--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size='+tmpfs]
  if readonly:argv+=['--read-only']
  for kind,source,destination,rw in mounts:argv+=['--mount','type='+kind+',source='+source+',target='+destination+(''if rw else',readonly')]
  argv+=['--env','CACHY_ALLOW_ARM16K_PREPARE=1','--entrypoint',entry,tool_id,*args]
  assert scope.listing(time.monotonic()+8)is None;scope.submitted=True;cmd(label+'-create',argv)
  scope.recover(time.monotonic()+8);cmd(label+'-run',['docker','start','-a',name],timeout)
  row=scope.recover(time.monotonic()+8);assert not row['State']['Running']and row['State']['ExitCode']==0 and not row['State']['OOMKilled']
  return scope
 try:
  security=json.loads(cmd('docker-security',['docker','info','--format','{{json .SecurityOptions}}']));assert 'name=rootless'in security
  parent=image(PARENT);assert parent['Id']==PARENT;parent_size=parent['Size'];report['parent_tool_image_bytes']=parent_size
  assert_budget(inputs,out,parent_size,prior=prior)
  kernel=D.kernel(a.kernel_data/'Image',a.kernel_data/'config');descriptor=a.kernel_data/'kernel-input.json'
  assert D.pin(descriptor)=={'bytes':1138,'sha256':'4194ad7212e07a5b96c8bd6c95fc23482524bdd6ba340d12a77fc193a9ee3db1'}
  assert D.pin(inputs/'rootfs.tar.gz')=={'bytes':D.ROOTFS_BYTES,'sha256':D.ROOTFS_SHA}
  assert D.pin(inputs/'rootfs.tar.gz.sig')==SIG and D.pin(inputs/'archlinuxarm.gpg')==KEY
  home=out/'signature-home';home.mkdir(mode=0o700)
  cmd('dearmor',['gpg','--no-options','--homedir',str(home),'--batch','--dearmor','--output',str(out/'alarm.binary.gpg'),str(inputs/'archlinuxarm.gpg')])
  status=cmd('rootfs-signature',['gpgv','--homedir',str(home),'--keyring',str(out/'alarm.binary.gpg'),'--status-fd','1',str(inputs/'rootfs.tar.gz.sig'),str(inputs/'rootfs.tar.gz')],180)
  valid=[line for line in status.decode().splitlines()if line.startswith('[GNUPG:] VALIDSIG ')]
  assert len(valid)==1 and valid[0].split()[2]==SIGNER
  # Recompute the selected whole-package graph from the pinned archive, not caller-supplied metadata.
  index=D.rootfs(inputs/'rootfs.tar.gz');selection=S.select(index)
  selection_path=inputs/'verified-selection.json';selection_path.write_text(json.dumps(selection,sort_keys=True,indent=2)+'\n')
  report['kernel']=kernel;report['rootfs_signature']=valid[0];report['selected_packages']=len(selection['packages'])
  report['selected_logical_file_bytes']=selection['logical_file_bytes'];report['package_registration']=selection['package_registration']
  rows=catalogs(a.catalogs.resolve(strict=True));setup=out/'setup';setup.mkdir(mode=0o700);db=setup/'db';db.mkdir()
  for name in CATALOGS:shutil.copyfile(a.catalogs/name,db/name)
  config='[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n'
  for repo in ('core','extra'):config+='['+repo+']\nServer = https://archive.archlinux.org/repos/2026/11/09/$repo/os/$arch\n'
  (setup/'resolve.conf').write_text(config)
  scope=container('resolve',PARENT,'/usr/bin/pacman',['--config','/setup/resolve.conf','-Sp','--noconfirm','--print-format','PKG|%n|%v|%l|%s','qemu-system-aarch64=11.1.3-1'],[('bind',str(setup),'/setup',False),('bind',str(db),'/var/lib/pacman/sync',False)])
  selected=[]
  for line in (out/'resolve-run.log').read_text().splitlines():
   if line.startswith('PKG|'):
    _,name,version,url,size=line.split('|');row=rows[name]
    assert version==row['VERSION'][0]and int(size)==int(row['CSIZE'][0])and url=='https://archive.archlinux.org/repos/2026/11/09/'+row['repository'][0]+'/os/x86_64/'+row['FILENAME'][0]
    selected.append(row)
  assert any(row['NAME']==['qemu-system-aarch64']for row in selected)and len(selected)==len({r['NAME'][0]for r in selected})
  assert sum(int(r['CSIZE'][0])for r in selected)<=64*1024**2 and sum(int(r['ISIZE'][0])for r in selected)<=256*1024**2,'bounded QEMU tool transaction exceeds allowance'
  cache=out/'packages';cache.mkdir(mode=0o700);refs=[];end=time.monotonic()+360
  for row in selected:
   filename=row['FILENAME'][0];assert re.fullmatch(r'[A-Za-z0-9@._+:-]+\.pkg\.tar\.zst',filename)
   url='https://archive.archlinux.org/repos/2026/11/09/'+row['repository'][0]+'/os/x86_64/'+filename;dst=cache/filename
   assert time.monotonic()<end
   cmd('fetch-'+row['NAME'][0],['curl','--fail','--location','--silent','--show-error','--proto','=https','--max-time',str(min(120,max(1,int(end-time.monotonic())))),'--max-filesize',row['CSIZE'][0],'--output',str(dst),url],130)
   assert dst.stat().st_size==int(row['CSIZE'][0])and sha(dst)==row['SHA256SUM'][0]
   sig=base64.b64decode(row['PGPSIG'][0],validate=True);assert 32<len(sig)<16384;Path(str(dst)+'.sig').write_bytes(sig)
   refs.append({'name':row['NAME'][0],'version':row['VERSION'][0],'filename':filename,'bytes':dst.stat().st_size,'sha256':sha(dst),'signature_sha256':sha(Path(str(dst)+'.sig')),'signature_origin':'exact frozen official repository PGPSIG','url':url,'license':row.get('LICENSE',[])})
  report['new_host_packages']=refs
  (setup/'package-refs.json').write_text(json.dumps(refs,indent=2)+'\n');(setup/'install.conf').write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
  shutil.copytree(HERE,setup/'source',ignore=shutil.ignore_patterns('__pycache__'))
  scope=container('tool-install',PARENT,'/usr/bin/bash',['/setup/source/tool_install.sh'],[('bind',str(setup),'/setup',False),('bind',str(cache),'/packages',False)],readonly=False,timeout=240)
  tool='cachy-arm16k-systemd-tools:'+secrets.token_hex(12)
  cmd('commit-tools',['docker','commit',scope.cid,tool],120);tool_row=image(tool);report['tool_image']=tool;report['tool_image_id']=tool_row['Id'];report['tool_image_bytes']=tool_row['Size']
  assert tool_row['RootFS']['Layers'][:len(parent['RootFS']['Layers'])]==parent['RootFS']['Layers']
  assert tool_row['Size']-parent_size<=256*1024**2,'new host image exceeds allowance'
  assert_budget(inputs,out,parent_size,tool_row['Size'],selection['logical_file_bytes']+64*1024**2,prior)
  container('tool-provenance',tool_row['Id'],'/usr/bin/cat',['/opt/tool-provenance.json'],[])
  tool_facts=json.loads((out/'tool-provenance-run.log').read_text());assert len(tool_facts['packages'])==len(refs)
  for ref,fact in zip(refs,tool_facts['packages']):
   assert all(fact[k]==v for k,v in ref.items())and fact['VALIDSIG'].startswith('[GNUPG:] VALIDSIG ')
  report['tool_signature_provenance']=tool_facts
  container('qemu-version-only',tool_row['Id'],'/usr/bin/qemu-system-aarch64',['--version'],[])
  shutil.copyfile(a.kernel_data/'Image',inputs/'Image');shutil.copyfile(a.kernel_data/'config',inputs/'kernel.config');shutil.copyfile(descriptor,inputs/'kernel-input.json')
  shutil.copyfile(selection_path,inputs/'selection.json')
  materials={name:D.pin(inputs/name)for name in ('rootfs.tar.gz','rootfs.tar.gz.sig','archlinuxarm.gpg','Image','kernel.config','kernel-input.json','selection.json')}
  manifest={'schema_version':1,'material_files':materials,'rootfs_signature':valid[0],'rootfs_url':'https://ca.us.mirror.archlinuxarm.org/os/multi/ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz','kernel':kernel,'kernel_build_descriptor':json.loads(descriptor.read_text()),'tool_image_id':tool_row['Id'],'new_host_packages':refs,'tool_signature_provenance':tool_facts,'tool_parent_id':PARENT,'frozen_catalogs':CATALOGS,'source_pins':{str(path.relative_to(HERE)):sha(path)for path in HERE.rglob('*')if path.is_file()and '__pycache__'not in path.parts},'holds':['not frozen349/current supported composition','rootfs whole-archive signature; per-package validation inherited DATA','kernel build-only provenance; systemd login compatibility NOT RUN','source/legal/compiler correspondence incomplete','native16K/M2/performance/release NOT RUN']}
  (inputs/'input-manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
  assembly=out/'assembly';assembly.mkdir(mode=0o700)
  container('assembly',tool_row['Id'],'/usr/bin/fakeroot',['--','/usr/bin/python3','-I','-B','/opt/arm16k/assemble.py'],[('bind',str(inputs),'/inputs',False),('bind',str(assembly),'/work',True)],tmpfs='1g',timeout=420)
  report['prepared']=D.pin(assembly/'prepared.json');report['prepared_path']=str(assembly)
  report['owned_allocation_with_peak_scratch_bytes']=assert_budget(inputs,out,parent_size,tool_row['Size'],selection['logical_file_bytes']+64*1024**2,prior)
  assert not(assembly/'arm16k-first-boot-attempt.json').exists()
  report['status']='PREPARED_NOT_BOOTED'
 except BaseException as error:report['failure']={'category':type(error).__name__,'message':str(error)[:2048],'frames':[{'file':Path(row.filename).name,'line':row.lineno,'function':row.name}for row in traceback.extract_tb(error.__traceback__)[-6:]]}
 finally:
  state.cleaning=True
  report['owned_container_cleanup']=[]
  for scope in reversed(scopes):
   result={'name':scope.name};scope.cleanup(result);report['owned_container_cleanup'].append(result)
   report.setdefault('cleanup_errors',[]).extend(result.get('cleanup_errors',[]))
  if state.pending:report['status']='HOLD_CANCELLED';report['cancelled_signals']=state.pending
  if report.get('cleanup_errors'):report['status']='HOLD_CLEANUP'
  if tool and report['status']!='PREPARED_NOT_BOOTED':
   try:
    clean=C.Runner(60,dict(os.environ),out/'image-cleanup')
    result=clean.run(['docker','image','inspect',tool],timeout=15,log='inspect.log')
    if result.returncode==0:
     rows=json.loads(result.stdout);assert len(rows)==1;row=rows[0]
     assert row['Config']['Labels']['org.cachy-asahi.arm16k-prepare-owner']==str(os.getuid())and row['Config']['Labels']['org.cachy-asahi.arm16k-prepare-operation']in{scope.name for scope in scopes}
     assert row['RootFS']['Layers'][:len(parent['RootFS']['Layers'])]==parent['RootFS']['Layers']
     result=clean.run(['docker','image','rm',tool],timeout=30,log='remove.log');assert result.returncode==0
     report['failed_owned_tool_image_removed']=row['Id']
    else:report['failed_owned_tool_image_absent']=True
   except BaseException as error:
    report.setdefault('cleanup_errors',[]).append({'step':'owned-tool-image-cleanup','category':type(error).__name__,'message':str(error)[:1024]});report['status']='HOLD_CLEANUP'
  report['output_allocated_bytes']=allocated(out)
  (out/'preparation.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');state.__exit__()
 print(json.dumps({'status':report['status'],'failure':report.get('failure'),'report':str(out/'preparation.json'),'VM_boot':'NOT RUN'}))
 return 0 if report['status']=='PREPARED_NOT_BOOTED'else 1


if __name__=='__main__':raise SystemExit(main())
