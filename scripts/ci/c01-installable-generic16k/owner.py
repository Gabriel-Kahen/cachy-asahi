#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite actual generic16K installed package owner; actors need explicit CI binding."""
import argparse,base64,hashlib,importlib.util,json,os,platform,re,secrets,shutil,signal,stat,subprocess,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
LANE='scripts/ci/c01-installable-generic16k'
OLD='scripts/ci/arm-c01-installable-native'
KERNEL_SOURCE='1c6a2e7a7c6709eb1462cdcb0b449c98fe33d845'
CAPS=('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP')
VM_SECONDS=1800
UART_CAP=4*1024**2

def need(ok,why):
 if not ok:raise ValueError(why)
def read(path,cap=16*1024**2):
 path=Path(path);info=path.lstat()
 need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap and not any(p.is_symlink() for p in path.parents),'bounded ordinary input')
 return path.read_bytes()
def sha(data):return hashlib.sha256(data).hexdigest()
def pin(data):return dict(bytes=len(data),sha256=sha(data))
def save(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def load_module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
O=load_module('_c01_original341_owner',ROOT/OLD/'owner.py')
K=load_module('_c01_kernel_data',HERE/'kernel_data.py')
V=load_module('_c01_vm_support',HERE/'vm_support.py')
G=load_module('_c01_generic_fixture',ROOT/'scripts/virtual/generic16k/fixture.py')

def accepted():return json.loads(read(HERE/'accepted-inputs.json'))
def carrier(directory):
 directory=O.safe_path(directory);expected=accepted()
 names=set(expected['packages'])|{'package_variants.py','packages.lock','accepted-receipt.json','accepted-package-result.json','carrier.json'}
 need(directory.is_dir() and {p.name for p in directory.iterdir() if p.name!='.git'}==names,'closed exact accepted package carrier')
 need(json.loads(read(directory/'carrier.json'))==expected,'accepted origin/complete carrier manifest')
 for name,row in {**expected['packages'],'package_variants.py':expected['helper'],'packages.lock':expected['inventory'],
                  'accepted-receipt.json':expected['receipt'],'accepted-package-result.json':expected['result']}.items():
  need(pin(read(directory/name))==row,'accepted input drift: '+name)
 helper=load_module('_c01_accepted_helper',directory/'package_variants.py')
 result=json.loads(read(directory/'accepted-package-result.json'))
 need(result['status']==result['native_build']==result['installed_behavior']=='PASS'
      and result['base_commit']==expected['accepted_origin']['source'] and len(result['rebuilds'])==6 and len(result['phases'])==8,'accepted package result identity/scope')
 for v in ('baseline','lto'):
  for rel,attempt in ((1,1),(1,2),(2,1)):helper.package_members(read(directory/f'{v}-r{rel}-{attempt}.pkg.tar.xz'),v)
  need(read(directory/f'{v}-r1-1.pkg.tar.xz')==read(directory/f'{v}-r1-2.pkg.tar.xz'),'accepted clean pair bytes')
 receipt=json.loads(read(directory/'accepted-receipt.json'))
 need(receipt['status'].startswith('PASS') and receipt['identity']['source_sha']==expected['accepted_origin']['source']
      and int(receipt['identity']['run_id'])==expected['accepted_origin']['run'],'accepted origin receipt')
 return expected,result

def kernel_data(directory):
 need(subprocess.check_output(['git','-C',str(directory),'rev-parse','HEAD'],text=True,timeout=10).strip()==KERNEL_SOURCE,'exact kernel DATA source')
 names={'Image','config','kernel-input.json'}
 need(set(subprocess.check_output(['git','-C',str(directory),'ls-tree','-r','--name-only','HEAD'],text=True,timeout=10).splitlines())==names,'exact root kernel DATA3 tree')
 with tempfile.TemporaryDirectory(prefix='c01-kernel-export-',dir=directory.parent) as td:
  for name in names:Path(td,name).write_bytes(read(directory/name))
  selected,image,config=K.verify(Path(td),K.expected_descriptor())
 return selected,image,config

def command_line(nonce):
 need(re.fullmatch('[0-9a-f]{32}',nonce or ''),'exact fresh nonce')
 original=G.boot_arguments(False);need(original.count('rdinit=/init')==1,'one original generic boot anchor')
 return original.replace('rdinit=/init','root=/dev/vda rw rootwait init=/c01/init')+' c01install16k='+nonce+' arm64.nomops'

def qemu(image,disk,nonce):
 return ['/usr/bin/qemu-system-aarch64','-nodefaults','-machine','virt','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','4096',
         '-kernel',str(image),'-append',command_line(nonce),'-drive','if=none,id=c01root,format=raw,file='+str(disk),
         '-device','virtio-blk-pci,drive=c01root','-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot']

def record_plan(selection):
 helper=load_module('_c01_plan_helper',ROOT/'scripts/experiments/package_variants.py')
 base={line.split()[0]:line.split()[1] for line in read(ROOT/OLD/'expected-packages.lock').decode().splitlines()}
 corpus=[b'',b'x',b'cachy-asahi public workload\n'*4096,bytes(range(256))*1024]
 corpus += [bytes((i*13+i//257)&255 for i in range(n)) for n in (16383,16384,16385)]
 plan=[]
 def add(label,argv,exit=0,output=None):plan.append(dict(label=label,argv=list(map(str,argv)),exit=exit,output=output))
 def inv(label,versions):
  values={**base,**{helper.name(v):'1.3.2-'+str(r) for v,r in versions.items()}}
  output=''.join(k+' '+v+'\n' for k,v in sorted(values.items())).encode();add(label,['pacman','-Q'],output=pin(output))
 inv('initial-inventory',{})
 artifacts={(v,r):f'/c01/packages/{v}-r{r}-{2 if r==1 else 1}.pkg.tar.xz' for v in helper.VARIANTS for r in (1,2)}
 transactions=[['-U',artifacts[('baseline',1)]],['-U',artifacts[('lto',1)]],
               ['-U',*[artifacts[(v,2)] for v in helper.VARIANTS]],['-U',*[artifacts[(v,2)] for v in helper.VARIANTS]],
               ['-R',helper.name('baseline')],['-R',helper.name('lto')],
               ['-U',*[artifacts[(v,2)] for v in helper.VARIANTS]],['-R',*[helper.name(v) for v in helper.VARIANTS]]]
 for (phase,versions),transaction in zip(O.PHASES,transactions):
  add('pacman-'+phase,['pacman','--config','/c01/output/pacman-local.conf','--noconfirm','--noscriptlet',*transaction]);inv(phase+'-inventory',versions)
  for variant in versions:add(phase+'-probe-'+variant,[helper.prefix(variant)/'bin/probe','--installed-check'])
  for producer in versions:
   for i,original in enumerate(corpus):
    for level in (1,6,9):
     label=f'{phase}-{producer}-{i}-{level}'
     add(label+'-encode',[helper.prefix(producer)/'bin/minigzip','-'+str(level)])
     for consumer in versions:add(label+'-decode-'+consumer,[helper.prefix(consumer)/'bin/strict-gzip'],output=pin(original))
  for variant in versions:
   for i in range(3):add(phase+'-reject-'+variant+'-'+str(i),[helper.prefix(variant)/'bin/strict-gzip'],exit=2)
 need(len(plan)==645,'closed original lifecycle command graph')
 return plan,[pin(data) for data in corpus]

def validate_records(result,selection):
 plan,corpus=record_plan(selection)
 need(len(result['commands'])==len(plan),'complete645 command records')
 for i,(actual,expected) in enumerate(zip(result['commands'],plan)):
  need(actual['label']==expected['label'] and actual['argv']==expected['argv'] and actual['exit']==expected['exit']
       and actual['status']=='PASS' and actual['group_absent'] is True and actual['leader_held_until_group_inspection'] is True
       and actual['log']==f'{i:04d}-'+expected['label']+'.log','exact ordered argv/exit/group/log graph')
  need(type(actual['stdout_bytes']) is int and 0<=actual['stdout_bytes']<=1024**2
       and re.fullmatch('[0-9a-f]{64}',actual['stdout_sha256']) and type(actual['elapsed_seconds']) in (int,float)
       and 0<=actual['elapsed_seconds']<=75,'bounded actual command observations')
  if expected['output'] is not None:need(dict(bytes=actual['stdout_bytes'],sha256=actual['stdout_sha256'])==expected['output'],'exact inventory/decoded output bytes/hash')
 for phase in result['phases']:
  if phase['versions']:need(phase['workload']['inputs']==corpus,'exact seven public workload inputs')
 return True

def observed(raw,code,selection):
 need(code==0 and len(raw)<=UART_CAP and not any(x in raw for x in (b'C01_INSTALL16K_FAIL',b'Kernel panic',b'Attempted to kill init')),'natural successful bounded VM')
 lines=raw.replace(b'\r',b'').splitlines();nonce=selection['nonce']
 markers=[f'UNAME16K aarch64 {K.RELEASE}'.encode(),b'GETCONF16K 16384',b'SMOKE16K: mmap,mprotect,file-offset PASS',f'C01_INSTALL16K_DONE {nonce}'.encode()]
 need(all(lines.count(m)==1 for m in markers),'separate actual uname/getconf/static probe/done markers')
 positions=[lines.index(m) for m in markers];need(positions==sorted(positions),'actual guest marker ordering')
 kernel_lines=[line.split(b'Kernel command line: ',1)[1].decode() for line in lines if b'Kernel command line: ' in line]
 need(kernel_lines==[command_line(nonce)] and sum(bool(re.search(rb'ID_AA64ISAR2_EL1\[19:16\]: forced to 0\b',line)) for line in lines)==1
      and not any(b'CPU features: detected: Memory Copy and Memory Set instructions' in line for line in lines),'actual NOMOPS command/readback')
 frames=[(i,line) for i,line in enumerate(lines) if line.startswith(b'C01_INSTALL16K ')];prefix=('C01_INSTALL16K '+nonce+' ').encode()
 need(len(frames)==1 and frames[0][1].startswith(prefix) and positions[2]<frames[0][0]<positions[3],'one nonce-bound complete guest frame')
 data=base64.b64decode(frames[0][1][len(prefix):],validate=True);need(len(data)<=2*1024**2,'bounded guest report')
 result=json.loads(data)
 need(result['status']=='PASS_C01_INSTALLABLE_GENERIC16K_LIFECYCLE_ONLY' and result['nonce']==nonce
      and result['source_commit']==selection['source_commit'] and result['accepted_origin']==selection['accepted_origin'],'guest exact source/origin join')
 facts=result['guest']
 need(facts['page_size']==facts['auxv_page_size']==16384 and facts['kernel']==K.RELEASE
      and facts['machine']=='aarch64' and facts['uid']==facts['euid']==0 and facts['sysname']=='Linux'
      and facts['network']==['lo'] and [x for x in facts['cmdline'] if x.startswith('c01install16k')]==['c01install16k='+nonce]
      and result['host_page_size']==4096,'actual guest16K separate host4K')
 need([(p['phase'],p['versions']) for p in result['phases']]==O.PHASES,'all eight original installed lifecycle phases')
 for phase in result['phases']:
  active=phase['versions']
  if active:
   workload=phase['workload'];n=len(active)
   need(workload['encodes']==21*n and workload['cross_decodes']==21*n*n and workload['strict_rejections']==3*n
        and set(workload['probe'])==set(active),'complete original codec counts')
   for variant,probe in workload['probe'].items():need(probe['status']=='PASS' and probe['variant']==variant and probe['roundtrips']==21 and probe['negative_checks']==42,'all installed probes')
 need(all(p['inventory_preserved'] and p['system_sentinels_preserved'] for p in result['phases'])
      and result['system_sentinels_preserved'] and result['system_sentinels']==selection['base_sentinels']
      and result['inventory_sha256']==O.PACKAGES and result['original_packages_preserved']
      and result['packages']==selection['packages'] and len(result['commands'])==645
      and all(r['status']=='PASS' and r['group_absent'] is True for r in result['commands']),'complete commands/payload/base preservation')
 need(result['hardware_validation']=='NOT RUN' and result['performance_acceptance']=='NOT RUN' and result['release_admission'] is False,'finite compatibility scope')
 validate_records(result,selection)
 return result

def capture_argv(args,own,image,inputs,output):
 return [*O.DOCKER,'run','--pull=never','--name',own['consumer']+'-16k-root','--label',O.LABEL+'='+own['token'],
         '--label',O.LABEL+'.source='+args.source_sha,'--label',O.LABEL+'.run='+own['run_id'],
         '--platform=linux/arm64','--user=0:0','--read-only','--network=none','--ipc=private','--cgroupns=private',
         '--cpus=2','--memory=8g','--memory-swap=8g','--pids-limit=256','--security-opt=no-new-privileges','--cap-drop=ALL',
         *['--cap-add='+cap for cap in CAPS],'--tmpfs=/tmp:rw,exec,nosuid,nodev,size=6g,mode=1777',
         '--mount','type=bind,src='+str(inputs)+',dst=/inputs,readonly','--mount','type=bind,src='+str(output)+',dst=/out',
         '--env=CACHY_ASAHI_C01_CAPTURE16K=1','--entrypoint=/usr/bin/python3',image,
         '-I','-B','/inputs/capture.py',str(os.getuid()),str(os.getgid())]

def check_capture(row,own,image,inputs,output):
 need(row['Image']==image and row['Config']['Labels'].get(O.LABEL)==own['token'] and row['State']['Status']=='exited'
      and row['State']['ExitCode']==0 and not row['State']['OOMKilled']
      and row['Config']['Labels'].get(O.LABEL+'.source')==own['source_sha']
      and row['Config']['Labels'].get(O.LABEL+'.run')==own['run_id']
      and row['Config']['User']=='0:0' and row['Config']['Entrypoint']==['/usr/bin/python3']
      and row['Config']['Cmd']==['-I','-B','/inputs/capture.py',str(os.getuid()),str(os.getgid())]
      and [e for e in row['Config']['Env'] if not e.startswith('PATH=')]==['CACHY_ASAHI_C01_CAPTURE16K=1'],'owned natural capture exit')
 h=row['HostConfig'];caps={c.removeprefix('CAP_') for c in h['CapAdd']}
 need(h['NetworkMode']=='none' and h['ReadonlyRootfs'] is True and not h['Privileged']
      and h['Memory']==h['MemorySwap']==8*1024**3 and h['NanoCpus']==2*10**9 and h['PidsLimit']==256
      and caps==set(CAPS) and h['CapDrop']==['ALL'] and not h['Devices'] and not h['DeviceRequests']
      and h['IpcMode']==h['CgroupnsMode']=='private' and h['SecurityOpt']==['no-new-privileges'],'exact capture resource/authority boundary')
 check_capture_mounts(row,inputs,output)

def check_capture_mounts(row,inputs,output):
 h=row['HostConfig'];rows=row['Mounts']
 need(type(rows) is list and len(rows) in (2,3) and all(type(m) is dict and type(m.get('Destination')) is str for m in rows),'finite capture mount records')
 mounts={m['Destination']:m for m in rows}
 need(len(mounts)==len(rows) and set(mounts) in ({'/inputs','/out'},{'/inputs','/out','/tmp'}),'unique closed capture mount destinations')
 need(h.get('Tmpfs')=={'/tmp':'rw,exec,nosuid,nodev,size=6g,mode=1777'} and not h.get('Binds') and not h.get('VolumesFrom'),'exact configured private tmpfs and no inherited binds')
 for name,path,writable,mode in (('/inputs',inputs,False,'ro'),('/out',output,True,'rw')):
  m=mounts[name]
  need(m.get('Type')=='bind' and m.get('Source')==str(path) and m.get('RW') is writable
       and m.get('Propagation','') in ('','private','rprivate') and m.get('Mode','') in ('',mode),'exact private capture bind role')
 if '/tmp' in mounts:
  m=mounts['/tmp']
  need(m.get('Type')=='tmpfs' and m.get('Source','')=='' and m.get('RW',True) is True
       and m.get('Name','')==m.get('Driver','')==m.get('Propagation','')=='' and m.get('Mode','') in ('','rw'),'private tmpfs mount record without host source')
 # Docker --tmpfs may be represented only in HostConfig.Tmpfs; require it always.
 configured=h.get('Mounts')
 if configured is not None:
  need(type(configured) is list and len(configured)==2 and all(type(m) is dict and type(m.get('Target')) is str for m in configured),'two configured capture binds')
  declared={m.get('Target'):m for m in configured}
  need(len(declared)==2 and set(declared)=={'/inputs','/out'},'closed configured bind destinations')
  for name,path,readonly in (('/inputs',inputs,True),('/out',output,False)):
   m=declared[name];options=m.get('BindOptions')
   need(m.get('Type')=='bind' and m.get('Source')==str(path) and m.get('ReadOnly',False) is readonly
        and not m.get('VolumeOptions') and not m.get('TmpfsOptions'),'exact configured capture bind role')
   if options is not None:
    need(type(options) is dict and set(options)<=set(('Propagation','NonRecursive','CreateMountpoint','ReadOnlyNonRecursive','ReadOnlyForceRecursive'))
         and options.get('Propagation','') in ('','private','rprivate') and all(v is False for k,v in options.items() if k!='Propagation'),'no extra configured bind authority')

def record_capture(row,own,image,inputs,output,path):
 # Preserve all predicate-relevant daemon fields even when the predicate refuses.
 projected={key:row.get(key) for key in ('Id','Name','Image','RestartCount','Config','State','HostConfig','Mounts')}
 raw=(json.dumps(projected,sort_keys=True,indent=2)+'\n').encode()
 need(len(raw)<=64*1024,'bounded capture inspect projection')
 Path(path).write_bytes(raw)
 check_capture(row,own,image,inputs,output)

def cleanup_safe(args):
 path=args.work/'guest16k-owner.json'
 if not path.is_file():return not any((args.work/n).exists() for n in ('guest16k-actors','guest16k-private','guest16k-public'))
 r=json.loads(read(path))
 return r.get('source_sha')==args.source_sha and r.get('capture_absent') is True and r.get('vm_retired') is True and r.get('private_removed') is True

def trial(args):
 _,own=O.admitted(args)
 need(platform.machine()=='aarch64' and os.sysconf('SC_PAGE_SIZE')==4096,'observed native ARM4K host required')
 need(args.kernel_data==Path(os.environ['RUNNER_TEMP'])/'c01-kernel-data'
      and args.package_data==Path(os.environ['RUNNER_TEMP'])/'c01-package-data','fixed external DATA paths')
 need(re.fullmatch('[0-9a-f]{40}',args.package_source or ''),'explicit Root-published carrier source required')
 need(subprocess.check_output(['git','-C',str(args.package_data),'rev-parse','HEAD'],text=True,timeout=10).strip()==args.package_source,'exact selected public carrier source')
 expected,accepted_result=carrier(args.package_data);kernel,image,_=kernel_data(args.kernel_data)
 bootstrap=json.loads(read(args.work/'bootstrap-owner.json'))
 need(bootstrap['status']=='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP' and bootstrap['identity']==own
      and bootstrap['packages_sha256']==O.PACKAGES,'same-job signed original341 producer')
 actor=O.Actors(args.work/'guest16k-actors',1100)
 row=json.loads(actor.docker('image','inspect',bootstrap['image']))[0];O.require_image(row,own)
 private=O.fresh(args.work/'guest16k-private');private.chmod(0o700)
 inputs=O.fresh(private/'inputs');capture=O.fresh(private/'capture');output=O.fresh(args.work/'guest16k-public')
 report=dict(status='FAIL',source_sha=args.source_sha,identity=own,accepted_origin=expected['accepted_origin'],
             host_page_size=os.sysconf('SC_PAGE_SIZE'),host_architecture=platform.machine(),host_kernel=platform.release(),kernel_data_source=KERNEL_SOURCE,hardware_validation='NOT RUN',
             performance_acceptance='NOT RUN',selected_for_release=False,capture_absent=False,vm_retired=False,private_removed=False)
 started=False;vm_started=False;vm_actor=None
 try:
  nonce=secrets.token_hex(16)
  report['host_qemu_version']=actor.run(['/usr/bin/qemu-system-aarch64','--version'],log=output/'qemu-version.log',timeout=10)
  selection=dict(schema=1,nonce=nonce,source_commit=args.source_sha,accepted_origin=expected['accepted_origin'],
                 host_page_size=report['host_page_size'],helper_sha256=expected['helper']['sha256'],
                 inventory_sha256=O.PACKAGES,packages=expected['packages'],base_sentinels=accepted_result['system_sentinels'])
  save(inputs/'selection.json',selection);save(output/'selection.json',selection)
  for src,dst in [(HERE/'capture.py',inputs/'capture.py'),(HERE/'guest.py',inputs/'guest.py'),
                  (args.package_data/'package_variants.py',inputs/'package_variants.py'),
                  (args.package_data/'packages.lock',inputs/'packages.lock'),
                  (ROOT/'scripts/virtual/generic16k/smoke.c',inputs/'smoke.c')]:shutil.copyfile(src,dst)
  (inputs/'packages').mkdir()
  for name in expected['packages']:shutil.copyfile(args.package_data/name,inputs/'packages'/name)
  (private/'Image').write_bytes(image)
  command=capture_argv(args,own,bootstrap['image'],inputs,capture);save(output/'capture-command.json',dict(argv=command))
  started=True;actor.run(command,log=output/'capture.log',timeout=1000)
  rows=json.loads(actor.docker('inspect',own['consumer']+'-16k-root'));need(len(rows)==1,'one capture consumer')
  record_capture(rows[0],own,bootstrap['image'],inputs,capture,output/'capture-inspect.json')
  actor.docker('rm',own['consumer']+'-16k-root')
  need(not actor.docker('ps','-aq','--filter','name=^/'+own['consumer']+'-16k-root$'),'capture retired before VM')
  report['capture_absent']=True
  captured=json.loads(read(capture/'capture.json'));need(captured['nonce']==nonce and captured['capture_workspace_absent']
       and captured['host_page_size']==4096 and captured['base_inventory_sha256']==O.PACKAGES,'complete original341 capture')
  save(output/'capture.json',captured)
  vm_started=True
  code,raw,vm_actor=V.supervise(qemu(private/'Image',capture/'root.raw',nonce),output/'uart.log',VM_SECONDS,cap=UART_CAP)
  report['vm_retired']=vm_actor['natural_exit'] and vm_actor['group_absent']
  guest=observed(raw,code,selection);save(output/'guest.json',guest)
  report.update(status='PASS_GUEST16K_AWAITING_OUTER_PRODUCER_RETIREMENT',guest=guest,vm_actor=vm_actor,
                capture=captured,nonce=nonce,kernel=kernel)
 except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:2048])
 finally:
  if started and not report['capture_absent']:
   try:
    names=actor.docker('ps','-aq','--filter','name=^/'+own['consumer']+'-16k-root$').split()
    if names:
     inspected=json.loads(actor.docker('inspect',own['consumer']+'-16k-root'))[0]
     need(inspected['Config']['Labels'].get(O.LABEL)==own['token'] and inspected['Image']==bootstrap['image'],'exact failed capture ownership')
     actor.docker('rm','-f',own['consumer']+'-16k-root')
    report['capture_absent']=not actor.docker('ps','-aq','--filter','name=^/'+own['consumer']+'-16k-root$')
   except BaseException:report['capture_absent']=False
  if not vm_started:report['vm_retired']=True
  if report['capture_absent'] and report['vm_retired']:
   shutil.rmtree(private);report['private_removed']=not private.exists()
  if not report['private_removed']:report['status']='FAIL'
  save(args.work/'guest16k-owner.json',report)
 return report

def retain(args):
 _,own=O.binding(args);out=O.fresh(args.public)
 report=dict(status='FAIL',source_sha=args.source_sha,identity=own,hardware_validation='NOT RUN',performance_acceptance='NOT RUN',selected_for_release=False)
 try:
  guest=json.loads(read(args.work/'guest16k-owner.json'));cleanup=json.loads(read(args.work/'cleanup-owner.json'))
  need(guest['status']=='PASS_GUEST16K_AWAITING_OUTER_PRODUCER_RETIREMENT' and cleanup_safe(args)
       and cleanup['identity']==own and cleanup['consumer_absence_verified'] and cleanup['image_absence_verified'],'ordered VM/workspace/container/image retirement')
  report.update(status='PASS_FINITE_ORIGINAL341_GENERIC16K_INSTALLED_LIFECYCLE_AND_ORDERED_RETIREMENT',
                accepted_origin=accepted()['accepted_origin'],guest_page_size=16384,host_page_size=4096,
                kernel_data_source=KERNEL_SOURCE,source_files=len(O.source(ROOT,args.manifest_sha256)['files'])+3)
 except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:2048])
 try:
  # Explicit failure/success allowlist; never disks, cache, keys, HOME or root trees.
  selected={n:args.work/'guest16k-public'/n for n in ('capture-command.json','capture.log','capture-inspect.json','capture.json','selection.json','uart.log','guest.json','qemu-version.log')}
  selected.update({n:args.work/n for n in ('bootstrap-owner.json','cleanup-owner.json','guest16k-owner.json')})
  selected.update({'bootstrap-'+n:args.work/'bootstrap'/n for n in ('inputs.lock.json','acquisition.json','signatures.json','packages.lock','rootfs-inventory.json','bootstrap.json','bootstrap.log','runner.json')})
  for name,source in selected.items():
   if source.exists():(out/name).write_bytes(read(source,UART_CAP))
  files={p.name:pin(read(p,UART_CAP)) for p in out.iterdir() if p.is_file()}
  need(sum(r['bytes'] for r in files.values())<=16*1024**2,'metadata/UART retention aggregate budget');report['files']=files
 except BaseException as error:report.update(status='FAIL',retention_error_type=type(error).__name__,retention_error=str(error)[:2048])
 save(out/'receipt.json',report);return report

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('trial','cleanup-safe','retain'))
 for arg in ('source-root','proof','work','cache','public','kernel-data','package-data'):parser.add_argument('--'+arg,type=Path,required=True)
 for arg in ('source-sha','manifest-sha256','package-source'):parser.add_argument('--'+arg,required=True)
 parser.add_argument('--execute',action='store_true');args=parser.parse_args()
 if args.mode=='cleanup-safe':
  O.binding(args)
  return 0 if cleanup_safe(args) else 1
 result=trial(args) if args.mode=='trial' else retain(args)
 print(json.dumps({k:result.get(k) for k in ('status','error_type','error')}));return 0 if result['status'].startswith('PASS') else 1
if __name__=='__main__':
 def cancel(*_):raise KeyboardInterrupt('owned generic16K interrupted')
 signal.signal(signal.SIGTERM,cancel);signal.signal(signal.SIGINT,cancel)
 raise SystemExit(main())
