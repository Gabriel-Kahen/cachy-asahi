"""Counted original native owner adapter; NULL inputs refuse before actors."""
import argparse,ast,hashlib,json,os,re,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import inputs,factory,disk_adapter,runtime_policy,prerequisites
P,C,_,_=inputs.broker()
PASS='PASS_NEW_IMMUTABLE_GNU_RUNTIME_PENDING_ROOT_ACCEPTANCE'
def kernel_input(args,value):
 # Acquisition is deliberately separate: only exact already-retained Actions
 # artifact data, byte-selected by Root in source, may populate this directory.
 P.need(args.kernel_receipt==args.kernel_work/'Root-artifact-replay.json','one exact retained kernel receipt operand')
 selected=P.decode((inputs.D/'qualification-pins.json').read_bytes())['kernel_artifact'];P.need(type(selected)is dict and set(selected)=={'source','run','artifact_id','artifact_name','archive','Image','config','descriptor'},'genuine Actions kernel artifact descriptor UNSUPPLIED')
 P.need(re.fullmatch('[a-f0-9]{40}',selected['source'])and str(selected['run']).isdecimal()and type(selected['artifact_id'])is int and selected['artifact_id']>0 and type(selected['artifact_name'])is str and 0<len(selected['artifact_name'])<=128,'exact original Actions artifact identity')
 # Whole archive custody must remain locally available for Root's transport
 # replay; this code neither fetches nor reconstructs original API/log bytes.
 for name in('archive','Image','config','descriptor'):
  raw=runtime_policy.read(args.kernel_work/({'archive':'artifact.zip','descriptor':'Root-artifact-replay.json'}.get(name,name)),256*1024**2 if name=='Image'else 512*1024**2 if name=='archive'else 4*1024**2);P.need(P.pin(raw)==selected[name],'exact retained kernel artifact operand '+name)
 receipt=P.decode(runtime_policy.read(args.kernel_work/'Root-artifact-replay.json',4*1024**2));P.need(receipt==dict(purpose='EXISTING_ACTIONS_KERNEL_ARTIFACT_INPUT_ONLY',source=selected['source'],run=selected['run'],artifact_id=selected['artifact_id'],artifact_name=selected['artifact_name'],archive=selected['archive'],Image=selected['Image'],config=selected['config'],kernel_build_decision=value['kernel_build_decision'],scope='BUILD_ONLY_NOT_BOOT_OR_MAPPING_OR_LIFECYCLE'),'finite Root-selected artifact replay context')
 profile=dict(value['bootstrap']['kernel'],Image=selected['Image']);return profile,args.kernel_work/'Image',args.kernel_work/'config'
def protocol(raw,selection):
 P.need(len(raw)<=16*1024**2,'original UART cap');lines=[r for r in raw.splitlines()if r.startswith(b'{')];P.need(len(lines)==1,'one NEW purpose owner result, never old3-record credit');v=P.decode(lines[0]);P.need(v['purpose']=='GNU_IMMUTABLE_RUNTIME_V1'and v['nonce']==selection['nonce']and v['status']=='FULL_LIFECYCLE_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED'and v['page_size']==16384 and v['kernel']==selection['kernel']['release'],'actual new-purpose lifecycle/16K/nonce result')
 nofile=v['observer_nofile'];P.need(nofile['after']==[8192,8192]and nofile['scope']=='NATIVE_TRIAL_8192_BOTH_INHERITED_BY_LIFECYCLE_CHILD','same inherited original descriptor budget')
 w=v['worker'];files=w['files'];P.need(w['status']=='SOURCE_ENFORCED_FULL_LIFECYCLE_AWAITING_PID1_RETIREMENT'and w['nonce']==selection['nonce']and w['worker_mask']==P.WORKER_MASK and w['source_nodes_sha256']==selection['source_nodes_sha256']and w['capabilities']['status']=='EXACT_SOURCE_MAP_PRESERVED'and w['capabilities']['cases']==2 and w['capabilities']['stages']==8,'whole actual source/lifecycle/capability guards')
 P.need(type(files)is dict and len(files)<=256 and 'result.json'in files and sum(n.endswith('-root.json.gz')for n in files)==16 and sum(r['bytes']for r in files.values())==w['bytes']<=512*1024**2,'complete original16 root snapshots and aggregate export')
 for n,row in files.items():P.need(re.fullmatch(r'(result\.json|isolation\.json|command-[0-9]{3}\.(stdout|stderr)|(pristine|modified)-[a-z0-9-]+(-root\.json\.gz|\.log))',n)and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<=row['bytes']<=64*1024**2 and re.fullmatch('[a-f0-9]{64}',row['sha256']),'whole original closed export row')
 P.need(v['supervisor']['group_absence_verified']is True and v['leases']['leases']==9 and v['cleanup']['status']=='WORKER_GROUP_LEASES_MOUNTS_AND_OWNED_DM_RETIRED'and v['source_map_join']['status']=='COMPLETE_LOGICAL_CAPABILITY_MAP_JOIN_PHYSICAL_REANCHORED','actual worker/group/mount/DM/map retirement')
 return dict(v,files=files,bytes=w['bytes'])
def derive(raw):
 text=raw.decode();tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='execute');old=ast.get_source_segment(text,node);new=old
 start=old.index("    helper=C.load('kernel_helper'");end=old.index('    text,derivation=adapter.derive(source)',start)
 kernel=old[start:end];replacement="    profile,image,config=runtime_kernel(args,runtime_value)\n    receipt=dict(scope='EXACT_EXISTING_ACTIONS_ARTIFACT_ROOT_REPLAY',Image=profile['Image'])\n"
 changes=((kernel,replacement),("    source=args.workspace;", "    runtime_need(args)\n    source=args.workspace;"),("        mounts=[", "        mounts=[(args.runtime_bundle,'/immutable-bundle',True),(args.runtime_inputs,'/runtime-selection',True),"),("'-I','-B','/debian-maintained-installed16k/'+script]", "'-I','-B',('/immutable-bundle/immutable/native_prepare.py' if role=='prepare' else '/debian-maintained-installed16k/'+script)]"),("        report['guest']=protocol(uart,selection);", "        report['guest']=runtime_protocol(uart,selection);"),("qemu(out/'Image',disks/'boot.raw',disks/'volume.raw')", "runtime_qemu(qemu,out/'Image',disks/'boot.raw',disks/'volume.raw',disks/'immutable-media/source.raw',disks/'immutable-media/source.hash')"),("        for name in ('boot','volume'):C.need", "        for name in ('boot','volume'):C.need"),("            for path in (disks/'boot.raw',disks/'volume.raw',out/'Image'):", "            for path in (disks/'immutable-media/source.raw',disks/'immutable-media/source.hash',disks/'boot.raw',disks/'volume.raw',out/'Image'):"),("report['status']=C.PASS", "report['status']=runtime_PASS"),("report['status']!=C.PASS", "report['status']!=runtime_PASS"))
 changes=tuple((a,b)for a,b in changes if a!=b)
 for a,b in changes:P.need(new.count(a)==1,'one original native owner seam: '+a[:70]);new=new.replace(a,b)
 restored=new
 for a,b in reversed(changes):restored=restored.replace(b,a)
 P.need(restored==old,'whole original native execute inverse');return text.replace(old,new),dict(changed=['execute'],seams=len(changes),held='ORIGINAL_NATIVE_GATE_LEASE_ACTOR_BOUNDS_GROUP_ABSENCE_EXPORT_AND_REVERSE_RETIREMENT')
def ready(args,value):
 runtime_policy.gate(value,preparing=True);P.need(os.environ.get('SOURCE_SHA')==os.environ.get('WORKFLOW_SHA')==value['actual_source']and os.environ.get('GITHUB_RUN_ID')==value['actual_run']and os.environ.get('GITHUB_REF_NAME')==value['actual_ref'],'actual native workflow source/ref/run join');factory.check(args.runtime_bundle)
 P.need(args.runtime_inputs.is_absolute()and not any(p.is_symlink()for p in(args.runtime_inputs,*args.runtime_inputs.parents)),'ordinary exact private runtime inputs')
 raw=runtime_policy.read(args.runtime_inputs/'policy.json',1024**2);P.need(P.decode(raw)==value,'same source-selected Root private policy')
 for n in('kernel_build_decision','kernel_boot_decision','source_decision','producer_retirement'):
  r=runtime_policy.read(args.runtime_inputs/'immutable-inputs'/(n+'.json'),4*1024**2);P.need(P.pin(r)==value[n],'exact genuine prerequisite '+n)
 prerequisites.boot(P.decode(runtime_policy.read(args.runtime_inputs/'immutable-inputs/kernel_boot_decision.json',4*1024**2)),value['kernel_build_decision'])
def execute(args,value):
 # Strict new prerequisites BEFORE the original execute can create outputs,
 # read credentials, or start native actors; original C.gate remains inside.
 ready(args,value);original=inputs.original('_immutable_original_native_owner','scripts/ci/glibc-debian-maintained-installed16k/run.py');text,proof=derive(Path(original.__file__).read_bytes());space=dict(vars(original),runtime_value=value,runtime_kernel=kernel_input,runtime_need=lambda a:ready(a,value),runtime_protocol=protocol,runtime_qemu=disk_adapter.qemu,runtime_PASS=PASS);exec(compile(text,original.__file__,'exec'),space);return space['execute'](args)
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in('workspace','acceptances','owner','base','kernel-work','kernel-receipt','output','runtime-bundle','runtime-inputs'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();value=P.decode(runtime_policy.read(a.runtime_inputs/'policy.json',1024**2));return execute(a,value)
if __name__=='__main__':raise SystemExit(main())
