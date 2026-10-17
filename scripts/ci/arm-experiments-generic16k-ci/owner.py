#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One-case source-authorized callbacks over unchanged tools574 owner stages."""
import argparse,ast,gzip,hashlib,importlib.util,json,os,re,signal,sys
from pathlib import Path
from types import SimpleNamespace
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/arm-experiments-generic16k'
SCOPE='GENERIC16K_RETAINED_ARM_COMPILER_EXPERIMENT_CORRECTNESS_ONLY'

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path,cap=2*1024**2):
 need(path.is_file() and not any(p.is_symlink() for p in (path,*path.parents)) and path.stat().st_size<=cap,'bounded ordinary owner input');raw=path.read_bytes();need(len(raw)<=cap,'owner input byte bound');return raw
def save(path,value):
 raw=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode();need(len(raw)<=2*1024**2,'bounded owner metadata');path.write_bytes(raw)
def authorize(args):
 raw=read(HERE/'integration-manifest.json',65536);need(re.fullmatch('[a-f0-9]{64}',args.manifest_sha256 or '') and pin(raw)['sha256']==args.manifest_sha256,'Root exact CI source closure operand');value=json.loads(raw)
 for name,row in value['files'].items():
  need(not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'closed owner source path');need(pin(read(args.source_root/name,16*1024**2))==row,'owner source pin differs: '+name)
 policy=json.loads(read(HERE/'policy.json',65536));need(policy['status']=='ROOT_SOURCE_AUTHORIZED_ONE_CASE_PER_JOB_NOT_RUNTIME_ACCEPTANCE' and policy['runtime_acceptance']=='UNBOUND' and args.experiment in policy['cases'] and len(policy['cases'])==4,'explicit source-only one-case authorization')
 need(os.environ.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi' and os.environ.get('GITHUB_WORKFLOW_SHA')==args.source_commit and re.fullmatch('[a-f0-9]{40}',args.source_commit) and os.environ.get('GITHUB_RUN_ATTEMPT')=='1','one exact source/attempt only');run=os.environ.get('GITHUB_RUN_ID','');need(re.fullmatch('[1-9][0-9]*',run),'actual current run id')
 token=hashlib.sha256(('armexperiments16k:'+run+':1:'+args.source_commit+':'+args.experiment).encode()).hexdigest()[:16];need(args.job_token==token,'one-source/run/case actor token');return dict(status='SOURCE_AUTHORIZATION_ONLY_NOT_RUNTIME_ACCEPTANCE',manifest_sha256=args.manifest_sha256,source=args.source_commit,run=int(run),attempt=1,experiment=args.experiment,job_token=token)

def namespace(args):
 authorization=authorize(args);sys.path.insert(0,str(args.source_root/LANE));import adapter as A
 tools,generic=A.dependencies(args.source_root);path=args.source_root/'scripts/ci/tools-generic16k/run.py';raw=read(path).decode();before="+' tools16k=1'";after="+' tools16k=1 armexperiments16k=1'";need(raw.count(before)==1,'one fixed inherited boot marker anchor');adapted=raw.replace(before,after);value=dict(__file__=str(path),__name__='source_owned_arm16k_tools_owner');exec(compile(adapted,str(path),'exec'),value)
 source=lambda text:{n.name:ast.dump(n,include_attributes=False) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
 original_functions,changed_functions=source(raw),source(adapted);need([n for n in original_functions if original_functions[n]!=changed_functions[n]]==['trial'],'one counted trial marker edit only')
 derivation=dict(status='SOURCE_ONLY_COUNTED_OWNER_ADAPTER',counted_edits=1,before_sha256=pin(raw.encode())['sha256'],after_sha256=pin(adapted.encode())['sha256'],unchanged_bodies=[n for n in original_functions if original_functions[n]==changed_functions[n]],callbacks=['preflight','payload','kernel','init','supervise','guest_report'],capture_entry=dict(path='scripts/ci/arm-experiments-generic16k-ci/capture_entry.py',**pin(read(args.source_root/'scripts/ci/arm-experiments-generic16k-ci/capture_entry.py',65536))),source_authorization=authorization)
 original={k:value[k] for k in derivation['callbacks']};state={};proxy=SimpleNamespace(**vars(value['s']));proxy.SCOPE=SCOPE;value['s']=proxy
 original_capture=value['capture_command']
 def capture_command(a,image,name,capture):
  argv=original_capture(a,image,name,capture);need(argv.count('/source/capture.py')==1,'one fixed original capture entry');argv[argv.index('/source/capture.py')]='/repo/'+derivation['capture_entry']['path'];return argv
 def preflight(a):
  image,owner=original['preflight'](a);state.update(image=image);return image,owner
 def payload(archive,receipt,g):
  files=original['payload'](archive,receipt,g);need(receipt['image_id']==state['image'] and receipt['source_commit']==args.source_commit,'same-job verified capture identity');files,selection=A.augment(args.source_root,args.input_root,args.experiment,files,g);state.update(selection=selection,archive=pin(read(archive,270*1024**2)),capture=pin(read(archive.with_name('capture.json'))));return files
 def kernel(receipt,root):
  result=original['kernel'](receipt,root);need('capture' in state,'capture checks precede runtime binding');binding=dict(status='SOURCE_AUTHORIZED_SAME_JOB_CAPTURE_KERNEL_CHECKS_NOT_RUNTIME_ACCEPTANCE',authorization=authorization,image_id=state['image'],bootstrap_archive=state['archive'],bootstrap_receipt=state['capture'],kernel_receipt=pin(read(args.kernel_receipt,65536)),original_artifact_inputs=state['selection']['bundle'],page_probe='PENDING_ORIGINAL_NEXT_COMPILE_STAGE');save(args.output/'binding.json',binding);state['binding']=binding
  acquisition=Path(os.environ['RUNNER_TEMP'])/'tools16k-kernel/kernel-input.json'
  if acquisition.is_file():save(args.output/'kernel-acquisition.json',json.loads(read(acquisition,16384)))
  return result
 def init(nonce,release):
  data=original['init'](nonce,release);before=b'/usr/bin/python3 -I -B /guest.py';need(data.count(before)==1,'one source-owned init entry');return data.replace(before,b'/usr/bin/python3 -I -B /arm/guest.py')
 def supervise(argv,log,seconds,**kwargs):
  code,data,actor=original['supervise'](argv,log,seconds,**kwargs)
  if log.name=='compile.log':
   binary=read(args.private/'smoke',1024**2);proof=dict(status='SOURCE_OWNED_PAGE_PROBE_COMPILE_PASS',source_commit=args.source_commit,source=pin(read(args.source_root/'scripts/virtual/generic16k/smoke.c',65536)),binary=pin(binary),command=actor);need(code==0 and actor['natural_exit'] is True and actor['group_absent'] is True,'original page probe compile/retirement');save(args.output/'page-probe-proof.json',proof);state['binding']['page_probe']=proof;save(args.output/'binding.json',state['binding'])
  if log.name=='uart.log':need(len(data)<=1024**2,'original UART cap');(args.output/'uart.log.gz').write_bytes(gzip.compress(data,mtime=0))
  return code,data,actor
 def guest_report(uart,code,nonce,release,capture):
  need(state.get('binding',{}).get('page_probe')!='PENDING_ORIGINAL_NEXT_COMPILE_STAGE','original probe stage required before VM result');return A.observed(uart,code,nonce,release,state['selection'])
 value.update(preflight=preflight,payload=payload,kernel=kernel,init=init,supervise=supervise,guest_report=guest_report,capture_command=capture_command);return value,derivation

def cleanup_safe(args):
 path=args.output/'runtime.json'
 if not path.is_file():return False
 report=json.loads(read(path));actors=report.get('actors',[]);consumer=report.get('consumer_cleanup',{})
 return report.get('job_token')==args.job_token and len(actors)==3 and all(a.get('group_absent') is True and a.get('natural_exit') is True for a in actors) and consumer.get('capture_absent') is True and consumer.get('private_removed') is True and consumer.get('producer')=='BORROWED_PRESERVED'

def finalize(args):
 value,derivation=namespace(args);need(cleanup_safe(args),'all owned consumers absent before producer/finalization');report=value['finalize'](args)
 if report['status']=='PASS_GENERIC_16K_MAPPED_TOOLS_PTY_CLI_ONLY':report.update(status='PASS_RETAINED_ARM_EXPERIMENT_GENERIC16K_AND_ORDERED_CLEANUP',scope=SCOPE,tools_correctness='NOT_RUN_CAPTURE_ONLY',performance='NOT_MEASURED',hardware='NOT_RUN',installation='NOT_RUN',release_admission=False)
 save(args.output/'runtime.json',report);return report

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('trial','cleanup-safe','finalize'));p.add_argument('--experiment',choices=('ARM-C01','ARM-C02','ARM-C03','ARM-C04'),required=True)
 for key in ('source-root','base-dir','input-root','private','output','kernel-receipt','kernel-work'):p.add_argument('--'+key,type=Path,required=True)
 for key in ('source-commit','job-token','manifest-sha256'):p.add_argument('--'+key,required=True)
 p.add_argument('--execute',action='store_true');a=p.parse_args()
 def interrupted(*_):raise KeyboardInterrupt('owned ARM16K CI owner interrupted')
 signal.signal(signal.SIGTERM,interrupted)
 if a.mode=='cleanup-safe':raise SystemExit(0 if cleanup_safe(a) else 1)
 if a.mode=='trial':
  value,derivation=namespace(a);report=value['trial'](a)
  if a.output.exists():save(a.output/'derivation.json',derivation)
 else:report=finalize(a)
 print(json.dumps(dict(status=report['status'],scope=SCOPE)));raise SystemExit(report['status']=='FAIL')
