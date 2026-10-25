# SPDX-License-Identifier: MIT
"""Exact owned media/work retirement; complete upload-safe public failure DATA."""
import json,os,shutil,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,adapter,controller,validate

def cleanup(a):
 profile,body= C.decode(C.read(a.case_source/'profile.json',4*1024**2)),adapter.core(a.core_source);O=C.load('_original800_cleanup',a.core_source/'scripts/ci/core-native-lifecycle/owner.py');result=dict(status='FAIL',vm='NOT_STARTED');end=time.monotonic()+60
 try:
  if(a.output/'vm-owner.json').exists():
   lease=C.decode(C.read(a.output/'vm-owner.json'));C.need(lease['nonce']==a.selected['nonce'],'same actual VM lease');report=C.decode(C.read(a.output/'owner.json',16*1024**2));a._owner_report=report
   command=O.command_api(a.workspace,a.output,report)
   work=a.output/'vm-work';media=a.output/'media'
   C.need([work.stat().st_dev,work.stat().st_ino]==lease['work']and[media.stat().st_dev,media.stat().st_ino]==lease['media'],'same exclusive owned work/media directories')
   for row in (a.output/'boots').glob('boot-*.json'):
    v=C.decode(C.read(row));C.need(v['group_absence_verified']is True,'retain all media until every started QEMU group is absent')
   if(media/'stage').exists():controller.actor(a,lambda argv,required=True,seconds=30:command(argv,required,min(seconds,max(.001,end-time.monotonic()))),work,media,'scrub')
   # Export successful or failed raw bytes before deleting media. Every image
   # must keep its known initial inode; sizes may never change across a guest.
   for n,size in(('boot.raw',16*1024**3),('data.raw',24*1024**3)):
    p=media/n
    if p.exists():
     st=p.lstat();held=C.decode(C.read(media/'core-media.json'))['identities'][n];C.need([st.st_dev,st.st_ino,st.st_uid,st.st_size]==held,'exact prepared disk identity');C.need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==os.getuid()and st.st_size==size,'only finite ordinary owned image may retire');p.unlink()
   # Preserve exported files through retainer, then remove only ordinary exact
   # preparation metadata and source copies under their recorded parent lease.
   metadata=C.decode(C.read(a.output/'vm-media-lease.json'))['metadata'];C.need(set(p.name for p in media.iterdir())==set(metadata),'only fixed preparation metadata remains after disk retirement')
   for n,pin in metadata.items():C.need(C.pin(C.read(media/n))==pin,'whole original prepared metadata');(media/n).unlink()
   media.rmdir();C.need(not media.exists(),'all owned media retired')
   a.output.joinpath('vm-retirement.json').write_bytes(C.encoded(dict(status='PASS_MEDIA_REMOVED_AFTER_QEMU_GROUP_ABSENCE',nonce=a.selected['nonce'],work_source_files=adapter.source_rows(work/'runner'))))
   C.need(adapter.source_rows(work)==C.decode(C.read(a.output/'vm-work-map.json',4*1024**2)),'whole exact unchanged preparation work files');count=0;total=0
   for p in work.rglob('*'):
    st=p.lstat();count+=1;C.need(count<=2048 and st.st_dev==work.stat().st_dev and st.st_uid==os.getuid()and not p.is_symlink()and(stat.S_ISDIR(st.st_mode)or stat.S_ISREG(st.st_mode)and st.st_nlink==1),'only caller-owned exact preparation work')
    if p.is_file():total+=st.st_size;C.need(total<=32*1024**2,'original bounded preparation source work')
   C.need(shutil.rmtree.avoids_symlink_attacks and time.monotonic()<end,'bounded descriptor-safe VM retirement');shutil.rmtree(work);result['vm']='PASS_OWNED_MEDIA_AND_PREPARATION_RETIRED'
  result['original_cleanup']=O.cleanup(a);C.need(result['original_cleanup']==0,'whole original ordered actor/snapshot/producer cleanup');result['status']='PASS_ALL_VM_THEN_ORIGINAL800_CONSUMER_PRODUCER_RETIREMENT'
 except BaseException as error:result.update(error_type=type(error).__name__,error=str(error)[:512])
 # Keep the original cleanup receipt intact as its own source-owned record.
 original=a.receipt
 if original.exists():original.replace(original.with_name('original800-'+original.name))
 a.receipt.write_bytes(C.encoded(result));return int(result['status']!='PASS_ALL_VM_THEN_ORIGINAL800_CONSUMER_PRODUCER_RETIREMENT')

def retain(a):
 C.need(not a.public.exists(),'fresh complete public evidence');a.public.mkdir(mode=0o700);result=dict(schema=1,status='FAIL_OR_INCOMPLETE',files={},errors=[],bytes=0,hardware='NOT_RUN',Asahi='NOT_RUN',release='NOT_ADMITTED')
 def copy(source,name,cap=64*1024**2):
  try:
   raw=C.read(source,cap);C.need(result['bytes']+len(raw)<=768*1024**2,'original full evidence transport cap');p=a.public/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);result['files'][name]=C.pin(raw);result['bytes']+=len(raw)
  except BaseException as error:result['errors'].append(dict(file=name,error=str(error)[:256]))
 copy(a.proof,'source-proof.json',4*1024**2);copy(a.receipt,'ordered-cleanup.json');copy(a.receipt.with_name('original800-'+a.receipt.name),'original800-ordered-cleanup.json');copy(a.output/'owner.json','owner.json',16*1024**2)
 copy(a.proof.parent/'legacy-prefill.json','retained/legacy-prefill.json');copy(a.proof.parent/'retained-custody.json','retained/retained-custody.json')
 for p in sorted((a.output/'apparmor').glob('*')):
  if p.name in('state.json','trial.profile'):copy(p,'apparmor/'+p.name,128*1024)
 for source,prefix in((a.output/'media-metadata','media-metadata'),(a.kernel_inputs/'kernel','kernel'),(a.output/'inputs','inputs'),(a.output/'snapshot-public','snapshot'),(a.output/'boots','boots'),(a.output/'guest','guest')):
  if source.exists():
   for p in sorted(source.rglob('*')):
    if p.is_symlink():C.need(prefix=='inputs'and p.name in('core7-test.db','core7-test.db.sig','core7-test.files','core7-test.files.sig'),'only exact original repository aliases');continue
    if p.is_file():copy(p,prefix+'/'+p.relative_to(source).as_posix(),128*1024**2 if prefix=='inputs'else 64*1024**2)
 for n in('vm-result.json','vm-owner.json','vm-retirement.json','vm-media-lease.json','guest-export.json'):copy(a.output/n,n,16*1024**2)
 for p in sorted(a.output.glob('command-*.std*')):copy(p,'owner-commands/'+p.name,1024**2)
 for p in sorted(a.base.glob('*')):
  if p.name in('report.json','seed-report.json','installed-packages.lock','build.log'):copy(p,'producer/'+p.name,64*1024**2)
 try:
  boots=C.decode(C.read(a.output/'boots/boots.json',32*1024**2));proof=validate.validate(a.public/'guest',a.core_source,a.selected,boots);C.need(not result['errors'],'no omitted original public file')
  cleanup=C.decode(C.read(a.receipt));C.need(cleanup['status']=='PASS_ALL_VM_THEN_ORIGINAL800_CONSUMER_PRODUCER_RETIREMENT','all ordered original and new media retirement');result.update(status='PASS_CLOSED_CORE7_AUTOMATIC_HOOKS_AND_ACTUAL_PID1_GENERIC16K',validation=proof)
 except BaseException as error:result['errors'].append(dict(file='acceptance',error=str(error)[:512]))
 (a.public/'export.json').write_bytes(C.encoded(result));return int(result['status']!='PASS_CLOSED_CORE7_AUTOMATIC_HOOKS_AND_ACTUAL_PID1_GENERIC16K')
