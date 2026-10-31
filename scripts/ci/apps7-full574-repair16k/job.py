#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Borrow original owner/case/cleanup bodies; route only its lifecycle execution."""
import argparse,contextlib,io,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
import vm

def actor_body(raw):
 anchor=' result=command(argv,False,';C.need(raw.count(anchor)==1,'one original actor command seam');return raw.replace(anchor,' result=_repair16k_dispatch(command,role,root,output,report,api,argv,False,')
def cleanup_gate(output):
 state=output/'repair16k-state.json';work=output/'repair16k';media=output/'repair16k-media'
 if state.exists():C.need(C.decode(C.read(state))['status']=='PASS_VM_GROUP_AND_PRIVATE_MEDIA_RETIRED' and not work.exists() and not media.exists(),'VM absence unknown: preserve backing source/data, no original scrub')
 else:C.need(not work.exists() and not media.exists(),'anonymous VM state preserved')
def retain(args,native):
 path=args.public/'retention.json';result=C.decode(C.read(path));C.need(result['status']==native.STATUS and not result['errors'],'original case/transaction/source/ordered cleanup gates required');cleanup_gate(args.output);v=C.decode(C.read(args.public/'lifecycle-public/repair16k-result.json'));C.need(v['status']==C.PASS and v['case']==args.case and v['natural_qemu']['exit_code']==0 and v['natural_qemu']['group_absence_verified'] is True and v['shared_lifecycle_seconds']==3000 and v['elapsed_seconds']<=3000,'actual complete bounded case VM and private media retirement')
 life=C.decode(C.read(args.public/'lifecycle-public/lifecycle.json'));native.result(life);C.need(life['case']==args.case and set(life['repairs'])==set(life['preparations'])=={args.case},'one original genuine repair case only')
 for file in [args.output/'repair16k-state.json',*sorted(C.HERE.iterdir())]:
  if file.is_dir():continue
  C.need(file.is_file() and not file.is_symlink(),'ordinary own evidence');raw=C.read(file,2*1024**2);name='repair16k/'+file.name;C.need(name not in result['files'] and result['bytes']+len(raw)<=192*1024**2,'unchanged192MiB closed evidence cap');target=args.public/name;target.parent.mkdir(exist_ok=True);target.write_bytes(raw);result['files'][name]=dict(bytes=len(raw),sha256=C.sha(raw));result['bytes']+=len(raw)
 result.update(status=C.PASS+'_AND_ORDERED_TEARDOWN',scope='GENERIC16K_VM_ORIGINAL574_SIGNED_REPAIR_CASE',case=args.case,native_host_acceptance=False,aggregate='BOTH_DISTINCT_SAME_SOURCE_16K_CASE_ROOT_DECISIONS_REQUIRED',hardware='NOT_RUN',release_admission=False);C.save(path,result);return result

@contextlib.contextmanager
def contract_context(native):
 prior=sys.modules.get('contract');sys.modules['contract']=native
 try:yield
 finally:
  if prior is None:sys.modules.pop('contract',None)
  else:sys.modules['contract']=prior

def native_job(root,native):
 with contract_context(native):J=C.load('native_job',root/C.NATIVE/'job.py')
 C.need(J.C is native and J.H.C is native,'isolated native job/helper contract identity');return J

def main(argv=None):
 values=list(sys.argv[1:] if argv is None else argv);p=argparse.ArgumentParser(description=__doc__,epilog='All original native case operands are forwarded; run additionally requires exact native decisions and owned accepted kernel files.')
 p.add_argument('mode',choices=('proof','check','run','cleanup','retain'));p.add_argument('--source',type=Path,required=True);p.add_argument('--case',choices=C.CASES,required=True)
 for name in ('kernel-work','kernel-receipt','kernel-authority','native-decisions'):p.add_argument('--'+name,type=Path)
 args,rest=p.parse_known_args(values);args.source=args.source.absolute();native,b=C.gate(args.source,args.case);C.need(os.environ.get('REPAIR_CASE')==args.case,'same explicit workflow case')
 if args.mode=='run':C.need(all(getattr(args,n) is not None for n in ('kernel_work','kernel_receipt','kernel_authority','native_decisions')),'exact native decisions/kernel paths required before outputs');C.authorize(args)
 for flag in ('output','public'):
  name='--'+flag
  if name in rest:setattr(args,flag,Path(rest[rest.index(name)+1]).absolute())
 if args.mode=='cleanup':cleanup_gate(args.output)
 J=native_job(args.source,native);original=J.derived
 def derived(raw):
  parts=original(raw);C.need('actor' in parts,'original finitecase actor derivative');parts['actor']=actor_body(parts['actor']);return parts
 J.derived=derived;J.H._repair16k_dispatch=lambda command,role,root,output,report,api,argv,required,seconds:vm.selected_command(args,native,role,root,output,report,api,argv,required,seconds,command)
 prior=sys.argv;sys.argv=[str(args.source/C.NATIVE/'job.py'),args.mode,'--source',str(args.source),'--case',args.case,*rest]
 try:
  capture=io.StringIO()
  with contract_context(native),contextlib.redirect_stdout(capture):code=J.main()
 finally:sys.argv=prior
 status=C.decode(capture.getvalue())['status']
 if code==0 and args.mode=='retain':status=retain(args,native)['status']
 print(C.encoded(dict(status=status,case=args.case,execution_scope='GENERIC16K_VM_ONLY',native_host_acceptance=False)).decode(),end='');return code
if __name__=='__main__':raise SystemExit(main())
