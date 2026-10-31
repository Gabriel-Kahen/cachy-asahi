#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Manual callback over the original verified tools16K payload/kernel/VM helpers."""
import argparse,base64,hashlib,importlib.util,json,os,secrets,shutil,signal,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import prepare as P
import runtime as R
HERE=Path(__file__).resolve().parent

def load(root,name):
 path=root/name;spec=importlib.util.spec_from_file_location('arm16k_'+path.stem,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def dependencies(root):
 pins=json.loads(P.read(HERE/'source-pins.json',65536))
 for name,row in pins['files'].items():P.need(P.pin(P.read(root/P.relative(name),16*1024**2))==row,'source-owned runtime helper changed: '+name)
 sys.path.insert(0,str(root/'scripts/ci/tools-generic16k'))
 tools=load(root,'scripts/ci/tools-generic16k/run.py');tools.s.check_source(root)
 return tools,load(root,'scripts/virtual/generic16k/fixture.py')

def augment(root,input_root,experiment,files,generic):
 extra,selection=P.select(input_root,experiment,generic);P.closure(files,selection)
 P.need(not set(files)&set(extra) and not any(n.startswith('arm/') or n=='arm-inputs.json' for n in files),'fresh exact experiment namespace')
 files.update(extra)
 for name in ('runtime.py','guest.py'):files['arm/'+name]=(stat.S_IFREG|0o444,P.read(HERE/name,65536))
 files['arm/runner.py']=(stat.S_IFREG|0o444,P.read(root/'scripts/ci/glibc-owned-runtime/runner.py',65536))
 files['arm-inputs.json']=(stat.S_IFREG|0o444,(json.dumps(selection,sort_keys=True)+'\n').encode())
 return files,selection

def assemble(root,input_root,experiment,archive,receipt,nonce,release,page_probe=None):
 P.need(type(page_probe) is bytes,'manual raw capture requires validated source-owned page probe input before assembly')
 tools,generic=dependencies(root);files=tools.payload(archive,receipt,generic);files,selection=augment(root,input_root,experiment,files,generic)
 interpreter,needed,loads=generic.elf(page_probe);P.need(interpreter is None and not needed and loads and all(a>=16384 and (v-o)%16384==0 for v,o,_,a in loads),'static aligned source-owned page probe')
 files.update({'smoke':(stat.S_IFREG|0o755,page_probe),'page-data':(stat.S_IFREG|0o444,b'A'*16384+b'B'*16384)})
 original=tools.init(nonce,release);before=b"/usr/bin/python3 -I -B /guest.py";P.need(original.count(before)==1,'one original guest entry anchor');init=original.replace(before,b'/usr/bin/python3 -I -B /arm/guest.py')
 files.update({'init':(stat.S_IFREG|0o755,init),'proc':(stat.S_IFDIR|0o555,b''),'dev':(stat.S_IFDIR|0o755,b''),'tmp':(stat.S_IFDIR|0o1777,b'')})
 ramfs=generic.cpio(files);P.need(len(ramfs)<=300*1024**2,'unchanged bounded diskless cpio')
 return ramfs,selection

def observed(raw,code,nonce,release,selection):
 P.need(code==0 and len(raw)<=1024**2 and b'SMOKE16K: mmap,mprotect,file-offset PASS' in raw,'natural zero VM/actual static page probe');lines=[l.rstrip(b'\r') for l in raw.splitlines() if l.startswith(b'ARM_EXPERIMENTS16K ')];prefix=('ARM_EXPERIMENTS16K '+nonce+' ').encode();P.need(len(lines)==1 and lines[0].startswith(prefix) and ('TOOLS16K PASS '+nonce).encode() in raw.splitlines(),'one exact nonce result followed by original poweroff path');data=base64.b64decode(lines[0][len(prefix):],validate=True);P.need(len(data)<=512*1024,'bounded original guest report');value=json.loads(data)
 P.need(value['status']=='PASS_RETAINED_ARM_EXPERIMENT_GENERIC16K_CORRECTNESS' and value['experiment']==selection['experiment'] and value['original_run']==selection['original_run'] and value['page_size']==16384 and value['kernel']==release and value['uid']==23001 and value['groups']==[] and value['caps']=='ALL_ZERO' and value['no_new_privs']==1 and value['original_inputs_preserved'] is True and len(value['commands'])==468,'actual exact input/16K/complete correctness/identity')
 P.need(all(c['supervisor']['group_absence_verified'] is True and c['supervisor']['exit_code'] in c['allowed'] for c in value['commands']),'every actual owned command retired')
 R.validate_records(selection,value['commands'])
 return value

def trial(args):
 policy=json.loads(P.read(HERE/'policy.json',65536));P.need(policy['status']=='BOUND_BY_ROOT','UNBOUND runtime input/kernel selection; no actors');P.need(args.execute is True,'explicit future CI execution required')
 P.need(getattr(args,'page_probe',None) is not None and getattr(args,'page_probe_receipt',None) is not None,'manual raw capture path incomplete: source-owned probe stage inputs required before actors')
 probe=P.read(args.page_probe,1024**2);proof=P.read(args.page_probe_receipt,65536);P.need(P.pin(probe)==policy.get('page_probe') and P.pin(proof)==policy.get('page_probe_receipt'),'explicit Root-bound source-owned probe inputs')
 compiled=json.loads(proof);P.need(compiled['status']=='SOURCE_OWNED_PAGE_PROBE_COMPILE_PASS' and compiled['source_commit']==args.source_commit and compiled['source']==P.pin(P.read(args.source_root/'scripts/virtual/generic16k/smoke.c',65536)) and compiled['binary']==P.pin(probe) and compiled['command']['exit']==0 and compiled['command']['natural_exit'] is True and compiled['command']['group_absent'] is True,'source-owned original probe compile/retirement proof')
 for key,path,cap in [('bootstrap_archive',args.bootstrap_dir/'payload.tar',270*1024**2),('bootstrap_receipt',args.bootstrap_dir/'capture.json',2*1024**2),('kernel_receipt',args.kernel_receipt,65536)]:P.need(P.pin(P.read(path,cap))==policy[key],'actual Root-bound input changed: '+key)
 tools,generic=dependencies(args.source_root);image,owner=tools.preflight(args);receipt=json.loads(P.read(args.bootstrap_dir/'capture.json',2*1024**2));P.need(receipt['image_id']==image and receipt['source_commit']==args.source_commit,'same owned producer/capture source')
 for path in (args.private,args.output):
  P.need(path.is_absolute() and not path.exists() and not any(p.is_symlink() for p in path.parents) and all(not path.is_relative_to(p) and not p.is_relative_to(path) for p in (args.source_root,args.base_dir,args.input_root,args.bootstrap_dir)),'fresh scoped actor paths')
 P.need(not args.private.is_relative_to(args.output) and not args.output.is_relative_to(args.private),'separate private/public paths');args.private.mkdir(mode=0o700);args.output.mkdir(mode=0o700)
 report=dict(status='FAIL',experiment=args.experiment,installation='NOT_RUN',hardware='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED',cleanup='NOT_RUN');raw=b'';vm_started=False;actor=None
 try:
  kernel_receipt=json.loads(P.read(args.kernel_receipt,65536));kernel=tools.kernel(kernel_receipt,args.source_root);nonce=secrets.token_hex(16);release=kernel_receipt['kernel_release'];ramfs,selection=assemble(args.source_root,args.input_root,args.experiment,args.bootstrap_dir/'payload.tar',receipt,nonce,release,probe);initrd=args.private/'initramfs.cpio';initrd.write_bytes(ramfs);image_copy=args.private/'Image';shutil.copyfile(kernel,image_copy);P.need(P.pin(P.read(image_copy,256*1024**2))=={k:kernel_receipt['image'][k] for k in ('bytes','sha256')},'exact copied kernel')
  qemu=shutil.which('qemu-system-aarch64');P.need(qemu,'accepted QEMU available');argv=[qemu,'-nodefaults','-machine','virt','-accel','tcg','-cpu','max','-smp','1','-m','1024','-kernel',str(image_copy),'-initrd',str(initrd),'-append',generic.boot_arguments(True)+' armexperiments16k=1','-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot'];vm_started=True;code,raw,actor=tools.supervise(argv,args.output/'uart.log',900);report.update(actor=actor,result=observed(raw,code,nonce,release,selection),status='PASS_GENERIC16K_CORRECTNESS_AWAITING_OUTER_PRODUCER_CLEANUP',selection=selection,kernel=kernel_receipt)
 except BaseException as error:report.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:512])
 finally:
  if vm_started and actor is None:
   report['cleanup']='UNKNOWN_VM_RETIREMENT_RETAIN_PRIVATE_FILES'
  else:
   for name in ('initramfs.cpio','Image'):
    path=args.private/name
    if path.exists():P.need(path.is_file() and not path.is_symlink(),'exact owned private file');path.unlink()
   P.need(not any(args.private.iterdir()),'owned private workspace empty');args.private.rmdir();report['cleanup']='PASS_SCOPED_VM_GROUP_AND_PRIVATE_FILES_RETIRED'
  report['producer_cleanup']='BORROWED_NOT_ATTEMPTED'
  encoded=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode();P.need(len(encoded)<=2*1024**2,'bounded metadata-only host receipt');(args.output/'runtime.json').write_bytes(encoded)
 return report

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute',action='store_true');p.add_argument('--experiment',choices=P.BUNDLES,required=True)
 for key in ('source-root','input-root','base-dir','bootstrap-dir','kernel-receipt','private','output'):p.add_argument('--'+key,type=Path,required=True)
 for key in ('page-probe','page-probe-receipt'):p.add_argument('--'+key,type=Path)
 for key in ('source-commit','job-token'):p.add_argument('--'+key,required=True)
 def interrupted(*_):raise KeyboardInterrupt('owned ARM16K controller interrupted')
 signal.signal(signal.SIGTERM,interrupted)
 a=p.parse_args();raise SystemExit(trial(a)['status']!='PASS_GENERIC16K_CORRECTNESS_AWAITING_OUTER_PRODUCER_CLEANUP')
