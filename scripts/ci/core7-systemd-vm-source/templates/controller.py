# SPDX-License-Identifier: MIT
"""Original800 snapshot/signing plus separately owned two-boot VM consumer."""
import ast,json,os,shutil,stat,sys,time,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,adapter,host

TAIL="""   report['active_phase']='CORE_LIFECYCLE'
   result=command([sys.executable,'-I','-B',str(HERE/'run.py'),'--inputs',str(args.output/'inputs'),'--input-sha256',sha(args.output/'inputs/lifecycle-input.json'),'--source-root',str(args.workspace),'--held-root',str(args.output/'data/original574'),'--output',str(args.output/'inner'),'--apparmor-state',str(args.output/'apparmor')],False,3800)
   inner=read(args.output/'inner/owner.json');need(result['code']==0 and inner['status']=='PASS_CORE7_INSTALLED_AND_TEARDOWN','all installed Core7 cases and inner teardown');child=read(args.output/'inner/public/result.json',2*1024**2);C.validate_child(index,child);report['status']='PASS_CORE7_PENDING_ORDERED_PRODUCER_CLEANUP'
"""

def derive_owner(root):
 root=Path(root)
 original=root/'scripts/ci/core-native-lifecycle/owner.py';raw=C.read(original,256*1024).decode();tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='execute');body='\n'.join(raw.splitlines()[node.lineno-1:node.end_lineno])+'\n'
 C.need(body.count(TAIL)==1 and body.count('deadline=time.monotonic()+4800')==1,'whole original800 consumer and parent clock anchors')
 changed=body.replace('deadline=time.monotonic()+4800','deadline=time.monotonic()+14400').replace(TAIL,"   report['active_phase']='REAL_SYSTEMD_VM'\n   NEW_VM(args,report,command,index,deadline)\n   report['status']='PASS_CORE7_PENDING_ORDERED_PRODUCER_CLEANUP'\n")
 C.need(changed.replace('deadline=time.monotonic()+14400','deadline=time.monotonic()+4800').replace("   report['active_phase']='REAL_SYSTEMD_VM'\n   NEW_VM(args,report,command,index,deadline)\n   report['status']='PASS_CORE7_PENDING_ORDERED_PRODUCER_CLEANUP'\n",TAIL)==body,'complete original owner inverse')
 return changed

def execute(args):
 """Genuine entry binding precedes the whole original owner body."""
 C.selection(args.selected);C.need(os.uname().machine=='aarch64'and args.selected['actual']['source']==os.environ.get('SOURCE_SHA')==os.environ.get('GITHUB_SHA')and str(args.selected['actual']['run'])==os.environ.get('GITHUB_RUN_ID'),'genuine native case binding before original actors')
 changed=derive_owner(args.core_source);adapter.core(args.core_source);O=C.load('_core800_original_owner',args.core_source/'scripts/ci/core-native-lifecycle/owner.py');namespace=dict(vars(O),NEW_VM=vm);exec(compile(changed,'whole-original800-owner-with-explicit-vm-tail','exec'),namespace);return namespace['execute'](args)

def materialize(root,rows,target):
 C.need(not target.exists(),'fresh own source role');target.mkdir(mode=0o700)
 for n,pin in rows.items():
  p=root/n;raw=C.read(p,32*1024**2);C.need(C.pin(raw)==pin,'whole source bytes before staging');q=target/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(raw)

def actor(args,command,work,media,role):
 """Same original five-cap offline preparer; fixed new source-owned role."""
 C.need(role in('prepare','scrub','export'),'finite media role')
 nonce=args.selected['nonce'];name='caa-core7-vm-'+nonce+'-'+role;label='org.cachy-asahi.core7-systemd-vm';image=C.decode(C.read(args.base/'report.json'))['image'];image_value=command(['/usr/bin/docker','image','inspect',image])
 images=C.decode(image_value['out']);base=C.decode(C.read(args.base/'report.json'));C.need(len(images)==1 and images[0]['Id']==image and images[0]['Architecture']=='arm64'and images[0]['Os']=='linux'and images[0]['Config']['Labels'].get('org.cachy-asahi.bootstrap574.job')==base['ownership']['token'],'exact fresh original574 native image/label')
 # Original owner.command returns complete stdout via its explicit data row.
 O=C.load('_core800_actor_owner',args.core_source/'scripts/ci/core-native-lifecycle/owner.py')
 def inspect():
  v=command(['/usr/bin/docker','container','inspect',name],False);raw=v['out']
  if v['code']:
   C.need(v['code']==1 and name.encode()in raw+v['err']and b'No such'in raw+v['err'],'unambiguous exact owned VM preparer absence');return None
  rows=json.loads(raw);C.need(len(rows)==1,'one owned preparer');r=rows[0];C.need(r['Name']=='/'+name and r['Image']==image and r['Config']['Labels'].get(label)==nonce and len(r['Id'])==64,'owned preparer ID/image/nonce');h=r['HostConfig'];C.need(h['NetworkMode']=='none'and h['ReadonlyRootfs']is True and h['CapDrop']==['ALL']and set(h['CapAdd'])=={'CAP_CHOWN','CAP_DAC_OVERRIDE','CAP_FOWNER','CAP_FSETID','CAP_SETFCAP'}and'no-new-privileges'in h['SecurityOpt'],'actual original five-cap read-only no-network NNP preparer config');return r
 C.need(inspect()is None,'never borrow existing preparer')
 cmd=['/usr/bin/docker','run','--name',name,'--label',label+'='+nonce,'--pull=never','--platform=linux/arm64','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=256','--memory=2g','--cpus=2','--tmpfs=/tmp:rw,nosuid,nodev,size=512m']+['--cap-add='+n for n in('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP')]
 bindings={'/inputs':args.output/'inputs','/out':work/'guest-out','/upgrade-code':args.vm_source/'runtime/media-source','/upgrade-config.json':work/'upgrade-config.json','/persistent_scope.py':args.vm_source/'runtime/media-source/scripts/ci/full-root-upgrade-caller/persistent_scope.py','/upgrade-signing':work/'signing','/workspace':work/'runner','/source':args.vm_source/'runtime','/measurement-source':args.kernel_inputs}
 for dest,path in bindings.items():
  C.need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents))and ','not in str(path),'ordinary finite media bind source');cmd+=['--mount','type=bind,src='+str(path)+',dst='+dest+',readonly']
 cmd+=['--mount','type=bind,src='+str(media)+',dst=/measurement','--env=CAA_CORE7_PREPARE='+nonce,'--entrypoint=/usr/bin/python3',image,'-I','-B','/workspace/media.py',role]
 result=None;run_row=None
 try:
  result=command(cmd,False,1900 if role=='prepare'else 120);run_row=args._owner_report['commands'][-1]
 finally:
  row=inspect()
  if row is not None:command(['/usr/bin/docker','rm','-f',row['Id']])
  C.need(inspect()is None,'owned media preparer absent before QEMU')
 C.need(row['State']['Running']is False and row['State']['Pid']==0 and row['State']['ExitCode']==0 and result['code']==0,'source-owned '+role+' media operation succeeded');return dict(name=name,role=role,actor_absent=True,command=run_row)

def prepare_work(args,work):
 for n in('guest-out','signing'):(work/n).mkdir(mode=0o700)
 own_rows=adapter.source_rows(C.HERE);materialize(C.HERE,own_rows,work/'runner');materialize(args.core_source,args.selected['source_profiles']['core800']['files'],work/'runner/core-source')
 runner=adapter.source_rows(work/'runner');(work/'runner/runner-files.json').write_bytes(C.encoded(runner));(work/'runner/selection.json').write_bytes(C.encoded(args.selected));(work/'runner/input-map.json').write_bytes(b'{}\n')
 # These three source-owned generated files are copied under the existing closed
 # /workspace mount; the media selection itself stays preparer-only.
 source_files={n[len('runtime/'):]:p for n,p in args.selected['source_profiles']['ksm637']['files'].items()if n.startswith('runtime/')};C.need(len(source_files)==610,'whole held runtime610')
 ms=dict(nonce=args.selected['nonce'],uid=os.getuid(),gid=os.getgid(),bindings=list(__import__('boot').ROLES[:6]),runner_files=runner,source_files=source_files)
 (work/'runner/media-selection.json').write_bytes(C.encoded(ms));shutil.copyfile(args.vm_source/'runtime/media-source/scripts/ci/expanded604-apps6-public-pair-updater/fixtures/normal-upgrade-config.json',work/'upgrade-config.json')
 (args.output/'vm-work-map.json').write_bytes(C.encoded(adapter.source_rows(work)))
 return ms

def vm(args,report,command,index,deadline):
 C.selection(args.selected);args._owner_report=report;work=args.output/'vm-work';media=args.output/'media';work.mkdir(mode=0o700);media.mkdir(mode=0o700)
 (args.output/'vm-owner.json').write_bytes(C.encoded(dict(nonce=args.selected['nonce'],image=report['image'],work=[work.stat().st_dev,work.stat().st_ino],media=[media.stat().st_dev,media.stat().st_ino])))
 prepare_work(args,work)
 prep=actor(args,command,work,media,'prepare');report['vm_preparation']=prep
 (args.output/'media-metadata').mkdir(mode=0o700)
 for n in('prepared.json','core-media.json','stage-owner.json'):shutil.copyfile(media/n,args.output/'media-metadata'/n)
 (args.output/'vm-media-lease.json').write_bytes(C.encoded(dict(nonce=args.selected['nonce'],identities=C.decode(C.read(media/'core-media.json'))['identities'],metadata={n:C.pin(C.read(media/n))for n in('prepared.json','core-media.json','stage-owner.json')})))
 # Kernel DATA gate is the entire unchanged imported() body, independent of KSM
 # package/positive predicates and with all original kernel source/profile checks.
 sys.path.insert(0,str(args.vm_source/'runtime'));prior=sys.modules.pop('contract',None)
 try:K=C.load('_core_full_kernel_import',args.vm_source/'runtime/kernel_input.py');kernel,receipt,image,config=K.imported(args.selected['kernel'],args.kernel_inputs,args.vm_source/'runtime')
 finally:
  if prior is not None:sys.modules['contract']=prior
 old=adapter.core(args.core_source);expected=C.decode(C.read(args.case_source/'pid1-expected.json'));expected.update(kernel=args.selected['kernel']['profile']['release'],nonce=args.selected['nonce'],serial='core7-'+args.selected['nonce'])
 try:
  result=host.two_boots(args.selected,media,image,args.output/'boots',old.api['runtime'],expected);report['vm_result']=result
 finally:
  # Keep original failed progress/command bytes too; opaque transport does not
  # invent success or require a successful final UART frame to retain DATA.
  report['vm_export']=actor(args,command,work,media,'export')
  C.need(not(args.output/'guest').exists(),'fresh guest evidence role');(media/'guest-export').rename(args.output/'guest');(media/'guest-export.json').rename(args.output/'guest-export.json')
 held_contract=sys.modules.get('contract');sys.modules['contract']=K.C
 try:
  refreshed=K.imported(args.selected['kernel'],args.kernel_inputs,args.vm_source/'runtime');C.need(refreshed[0]==kernel and refreshed[1]==receipt,'whole immutable kernel/source/provenance recheck after both QEMU groups')
 finally:
  if held_contract is not None:sys.modules['contract']=held_contract
 result.update(kernel_profile=kernel,kernel_import=receipt);C.need(time.monotonic()<deadline,'new owner14400 held');(args.output/'vm-result.json').write_bytes(C.encoded(result))
 return result
