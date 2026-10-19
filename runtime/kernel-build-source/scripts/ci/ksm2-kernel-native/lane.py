#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private build/config/header evidence only. Never boot or install a kernel."""
import argparse,hashlib,importlib.util,json,os,platform,re,shutil,stat,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
import ksm_profile as KP
import runtime as R
LANE='scripts/ci/ksm2-kernel-native'
CAP=384*1024**2

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def decode(raw):
 def pairs(rows):
  v={}
  for k,x in rows:need(k not in v,'duplicate JSON key');v[k]=x
  return v
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def read(p,cap=262144):
 p=Path(p);need(p.is_absolute()and not any(v.is_symlink()for v in(p,*p.parents)),'ordinary absolute file')
 a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded ordinary singlelink file')
 raw=p.read_bytes();b=p.lstat();need(len(raw)==a.st_size and(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'file identity drift');return raw
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(p):
 s=p.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700 and not any(x.is_symlink()for x in(p,*p.parents)),'owned0700 ordinary directory')
 return [s.st_dev,s.st_ino,s.st_uid]
def fresh(p):
 need(p.is_absolute()and not p.exists()and not p.is_symlink()and p.parent.is_dir()and not any(x.is_symlink()for x in p.parents),'fresh ordinary sibling output');p.mkdir(mode=0o700);return identity(p)
def load(name,p):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def preflight(root):
 root=Path(root).absolute();mf=decode(read(root/LANE/'source-manifest.json',1024**2));need(set(mf)=={'schema_version','purpose','files'}and mf['schema_version']==1 and mf['purpose']=='KSM_DIAGNOSTIC16K_BUILD_ONLY','exact build-only manifest')
 expected=set(mf['files'])|{LANE+'/source-manifest.json','.github/workflows/native-arm-ksm2-kernel.yml','.github/workflows/native-arm-build.yml'}
 actual={p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()and p.relative_to(root).parts[0]!='.git'}
 need(actual==expected,'exact closed build-only source; top-level Git metadata only ignored')
 for n,v in mf['files'].items():need(pin(read(root/n,1024**2))==v,'source pin differs: '+n)
 need(read(root/'.github/workflows/native-arm-build.yml')==read(root/'.github/workflows/native-arm-ksm2-kernel.yml'),'identical registered workflow required')
 for n in KP.PINS:KP.held(root,n)
 policy=decode(read(root/LANE/'input-policy.json'));need(policy['profile']==KP.PROFILE and all(policy[k]is None for k in('actual_source','actual_ref','actual_run','native_package_decision')),'source-only NULL authority')
 need(policy['bounds']==dict(build_seconds=3600,controller_seconds=3700,baseline_config_seconds=300,aggregate_workspace_bytes=16*1024**3,per_file_bytes=2*1024**3,output_bytes=CAP),'exact bounded build-only profile')
 return dict(status='PASS_SOURCE_ONLY_NO_BUILD_OR_BOOT',source_files=len(expected),profile=KP.PROFILE,actual_source=None,actual_run=None)

def source_proof(root):
 preflight(root)
 source=os.environ.get('SOURCE_SHA');run=os.environ.get('GITHUB_RUN_ID');attempt=os.environ.get('GITHUB_RUN_ATTEMPT')
 need(re.fullmatch('[a-f0-9]{40}',source or'')and source==os.environ.get('GITHUB_SHA')and re.fullmatch('[1-9][0-9]{0,19}',run or'')and attempt=='1'and os.environ.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','exact genuine source/workflow/run/first attempt environment')
 return dict(status='SOURCE_PROOF_PASS_BUILD_ONLY',source_sha=source,workflow_sha=source,ref=os.environ.get('GITHUB_REF_NAME'),run_id=run,run_attempt=attempt,manifest=pin(read(root/LANE/'source-manifest.json',1024**2)),profile=KP.PROFILE)

def config_values(raw):
 values={}
 for line in raw.decode().splitlines():
  m=re.fullmatch(r'(CONFIG_[A-Z0-9_]+)=(.*)',line)
  n=re.fullmatch(r'# (CONFIG_[A-Z0-9_]+) is not set',line)
  if m or n:
   k,v=(m.group(1),m.group(2))if m else(n.group(1),'n');need(k not in values,'duplicate config symbol');values[k]=v
 return values
def delta(before,after):
 a,b=config_values(before),config_values(after);need(set(a)^set(b)<= {'CONFIG_XXHASH'},'same kernel configuration domain except newly selected hidden XXHASH')
 result={k:dict(before=a.get(k,'n'),proposed=b.get(k,'n'))for k in sorted(set(a)|set(b))if a.get(k,'n')!=b.get(k,'n')}
 need(result=={'CONFIG_KSM':dict(before='n',proposed='y'),'CONFIG_XXHASH':dict(before='n',proposed='y')},'only KSM and Kconfig-selected XXHASH configuration delta')
 return dict(status='PASS_ACTUAL_SAME_BUILD_ENV_BASELINE_CONFIG_DELTA',before=pin(before),proposed=pin(after),changed=result,boot='NOT_RUN')

def remove_owned(path,owner,allowed):
 need(identity(path)==owner and {x.name for x in path.iterdir()}<=set(allowed),'owned workspace identity/top-level closure')
 for directory,dirs,files in os.walk(path,followlinks=False):
  for name in dirs+files:
   p=Path(directory)/name;s=p.lstat();need(s.st_dev==owner[0]and s.st_uid==os.getuid()and(stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode)or stat.S_ISLNK(s.st_mode)),'same-device owned ordinary build tree')
 shutil.rmtree(path);need(not path.exists(),'owned workspace remains')
 return dict(status='PASS_OWNED_BUILD_WORK_REMOVED',identity=owner,absence_verified=True)

def build(root,work,out,archive=None):
 root=root.absolute();proof=source_proof(root)
 need(platform.system()=='Linux'and platform.machine()=='aarch64'and os.getuid()==os.geteuid()>0,'ordinary native aarch64 CI build only')
 need(work!=out and work.parent==out.parent and not(work.is_relative_to(root)or out.is_relative_to(root)),'separate sibling runner-owned work/export outside source')
 owner=fresh(work);fresh(out);(work/'owner.json').write_bytes(encoded(dict(source=proof,identity=owner)))
 files={};total=0
 def emit(name,raw):
  nonlocal total
  need(re.fullmatch('[A-Za-z0-9_.-]+',name)and name not in files and total+len(raw)<=CAP,'closed bounded output')
  (out/name).write_bytes(raw);files[name]=pin(raw);total+=len(raw)
 try:
  emit('source-proof.json',encoded(proof));emit('source-manifest.json',read(root/LANE/'source-manifest.json',1024**2))
  inputs=work/'inputs';inputs.mkdir(mode=0o700)
  fetch=load('_ksm_build_fetch',root/'scripts/virtual/generic16k/fetch_inputs.py');acquire=load('_ksm_build_acquire',root/'scripts/ci/tools-generic16k/acquire_kernel.py')
  manifest,msha=fetch.load_manifest(root/'scripts/virtual/generic16k/inputs.json')
  acquire.acquire(fetch,manifest['inputs'][0],inputs,msha,work/'acquisition.json',retained_archive=archive)
  emit('acquisition.json',read(work/'acquisition.json'));kernel_archive=inputs/'kernel.tar.gz'
  with kernel_archive.open('rb')as f:emit('archive-header.bin',f.read(64))
  started=time.monotonic();deadline=started+3700;commands=[]
  def command(directory,configure):
   limit=min(300 if configure else 3700,int(deadline-time.monotonic()));need(limit>0,'shared original3700 controller deadline')
   argv=['/usr/bin/python3','-I','-B',str(directory/'build_kernel.py'),'--archive',str(kernel_archive),'--output',str(directory/'built'),'--configure-only'if configure else'--build','--boot-diagnostics']
   row,stdout,stderr,error=R.run_command(argv,work,dict(PATH='/usr/bin:/bin',HOME=str(work),TMPDIR=str(work),LC_ALL='C',TZ='UTC'),limit,16*1024**2)
   commands.append(row);emit(('baseline'if configure else'candidate')+'-controller.json',encoded(row));emit(('baseline'if configure else'candidate')+'-controller.stdout',stdout);emit(('baseline'if configure else'candidate')+'-controller.stderr',stderr)
   need(error is None and row['exit_code']==0 and row['group_absence_verified']is True,'natural exact kernel helper exit/group absence')
   return decode(read(directory/'built/build-receipt.json',65536))
  baseline=work/'baseline';baseline.mkdir(mode=0o700)
  for n in('build_kernel.py','kernel.fragment'):(baseline/n).write_bytes(KP.held(root,n))
  receipt0=command(baseline,True);need(receipt0['status']=='CONFIGURED_ONLY'and receipt0['kernel_build']=='NOT RUN','original baseline configured-only receipt')
  baseline_config=read(baseline/'built/build/.config');emit('baseline.config',baseline_config);emit('baseline-build-receipt.json',encoded(receipt0))
  # Retire the temporary baseline before candidate build: one16GiB work allocation.
  bowner=identity(baseline);remove_owned(baseline,bowner,{'build_kernel.py','kernel.fragment','built'})
  helper=work/'helper';helper.mkdir(mode=0o700)
  for n in('build_kernel.py','kernel.fragment'):(helper/n).write_bytes(KP.held(root,n))
  KP.prepare_kernel(root,helper);receipt=command(helper,False)
  H=KP.helper(root);H.HERE=helper;K=KP.contract(root);fragment=read(helper/'kernel.fragment')
  profile,image,config=K.from_receipt(receipt,H,fragment,KP.sha(read(helper/'build_kernel.py')),KP.sha(fragment));KP.check_config(config)
  need(KP.sha(read(helper/'build_kernel.py'))==profile['helper_sha256']and KP.sha(fragment)==profile['fragment_sha256'],'actual copied derived helper/fragment join')
  emit('configuration-delta.json',encoded(delta(baseline_config,read(config))))
  emit('Image',read(image,256*1024**2));emit('Image.header',read(image,256*1024**2)[:64]);emit('config',read(config));emit('kernel-profile.json',encoded(profile));emit('build-receipt.json',encoded(receipt))
  emit('build_kernel.py',read(helper/'build_kernel.py'));emit('kernel.fragment',fragment);emit('diagnostic.fragment',read(helper/'built/diagnostic.fragment'))
  for n in('configure.log','build.log'):emit(n,read(helper/'built'/n,16*1024**2))
  need(time.monotonic()<=deadline and receipt['build_environment']['build_seconds']==3600,'original finite kernel build/controller envelope')
  emit('controller.json',encoded(dict(status='PASS_NATURAL_KERNEL_HELPERS',commands=commands,seconds=round(time.monotonic()-started,6),controller_seconds=3700,baseline_retired_before_candidate=True)))
  cleanup=remove_owned(work,owner,{'owner.json','inputs','acquisition.json','helper'});emit('ordered-cleanup.json',encoded(cleanup))
  result=dict(schema_version=1,status='BUILT_ONLY_KSM_DIAGNOSTIC16K_NOT_BOOTED',profile=profile,source=proof,archive=dict(bytes=acquire.SIZE,sha256=acquire.SHA,source_revision=acquire.REVISION,retained='HEADER_ONLY_ARCHIVE_REACQUIRE_REQUIRES_FULL_ORIGINAL_HASH'),files=files,total_bytes=total,cleanup=cleanup,receipt_paths='ORIGINAL_BUILD_PROVENANCE_NOT_VALID_AT_IMPORT',native_package_acceptance='NOT_REQUIRED_NOT_GRANTED',boot='NOT_RUN',VM='NOT_RUN',live_kernel_write='NOT_RUN',hardware='NOT_RUN',performance='NOT_RUN',release='NOT_ADMITTED')
  (out/'kernel-artifacts.json').write_bytes(encoded(result));return result
 except BaseException as e:
  (out/'failure.json').write_bytes(encoded(dict(status='FAIL_BUILD_ONLY_NO_BOOT_AUTHORITY',error_type=type(e).__name__,error=str(e)[:512],source=proof,retained=files,cleanup='UNKNOWN_WORK_RETAINED_NO_SUCCESSFUL_COMPLETE_RECEIPT_AUTHORITY')));raise

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['preflight','build']);p.add_argument('--source',type=Path,default=ROOT);p.add_argument('--work',type=Path);p.add_argument('--output',type=Path);p.add_argument('--archive',type=Path);a=p.parse_args()
 v=preflight(a.source)if a.action=='preflight'else build(a.source,a.work.absolute(),a.output.absolute(),a.archive);print(json.dumps(v,sort_keys=True))
