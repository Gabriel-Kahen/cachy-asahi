# SPDX-License-Identifier: MIT
"""Finite KSM hosted source/selection custody; no actors or output on NULL."""
import hashlib,json,os,re,stat,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/ksm2-generic16k-vm-hosted';ROOT=HERE.parents[2]
BOUNDS=dict(owner_seconds=6600,producer_seconds=2300,seed_seconds=120,prepare_seconds=1900,VM_seconds=3000,QEMU_output_bytes=16*1024**2,public_output_bytes=192*1024**2)
CHECKOUT='3d3c42e5aac5ba805825da76410c181273ba90b1';UPLOAD='cf430e030ddbb5b0abf93d22962f4752f3646cd9'
SEED_SOURCE='04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd';SEED_PINS={'seed.py':'a7857658af224984065e575f6ffed8308ea85027d46eace8bda146d9033e93b3','index.json':'a388c8c8ba8e06cb92fd2be598b86e433c4e403b6e71a0f15b1eaec381bb7300'}

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(rows):
  d={}
  for n,v in rows:need(n not in d,'duplicate JSON');d[n]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON'))
def relative(n):need(type(n)is str and n and not n.startswith('/')and '\\'not in n and '\0'not in n and all(v not in('','.','..')for v in n.split('/')),'finite relative path');return n
def read(p,cap=16*1024**2):
 p=Path(p);need(not any(x.is_symlink()for x in(p,*p.parents)),'ordinary source/data');a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded regular source/data');raw=p.read_bytes();b=p.lstat();need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)and len(raw)==a.st_size,'source/data drift');return raw
def defaults():
 return dict(schema_version=1,purpose='KSM2_GENERIC16K_OWNED_SYSFS_TEST_ONLY',bounds=dict(BOUNDS),known_native_source='72ea5a1e81268f08da9b9cc04cdc7e23a1a9ff8a',known_native_run=39139213293,known_kernel_source='7b382cd8087407cebb33327180c8a76e7be5a79c',**{k:None for k in('native_carrier','kernel_carrier','native_decision','native_inputs','kernel_authority','kernel_transport','kernel_build','kernel_run','actual_source','actual_ref','actual_run')})

def policy(root):
 v=decode(read(Path(root)/LANE/'input-policy.json'));need(set(v)==set(defaults()),'exact source policy fields');need(v['schema_version']==1 and v['purpose']=='KSM2_GENERIC16K_OWNED_SYSFS_TEST_ONLY'and v['bounds']==BOUNDS,'exact owned VM policy/bounds');need(v['known_native_source']=='72ea5a1e81268f08da9b9cc04cdc7e23a1a9ff8a'and v['known_native_run']==39139213293 and v['known_kernel_source']=='7b382cd8087407cebb33327180c8a76e7be5a79c','exact retained native and corrected kernel sources');return v

def selected(v):
 # This gate is evaluated before component checkout, secret seeding or actors.
 keys=('native_carrier','kernel_carrier','native_decision','native_inputs','kernel_authority','kernel_transport','kernel_build','kernel_run')
 need(all(v.get(k)is not None for k in keys),'UNBOUND native/kernel carriers and Root decisions: no acquisition or actors')
 for k in('native_carrier','kernel_carrier'):need(re.fullmatch('[a-f0-9]{40}',v[k]or''),'immutable component carrier commit')
 need(type(v['kernel_run'])is int and v['kernel_run']>0,'genuine accepted kernel run')
 for k in('native_decision','native_inputs','kernel_authority','kernel_transport','kernel_build'):
  r=v[k];need(type(r)is dict and set(r)=={'path','bytes','sha256'}and type(r['bytes'])is int and 0<r['bytes']<=2*1024**2 and re.fullmatch('[a-f0-9]{64}',r['sha256']or''),'exact Root selected descriptor ref');relative(r['path'])
 need(v['native_inputs']['path']=='index.json'and v['native_decision']['path']=='Root-acceptance.json'and all(v[k]['path'].startswith('kernel/')for k in('kernel_authority','kernel_transport','kernel_build')),'fixed native original-root and separate kernel DATA namespace')
 need(all(v[k]is None for k in('actual_source','actual_ref','actual_run')),'source policy actual identity remains NULL; source proof supplies actuals')
 return v

def files(root):
 root=Path(root);mf=decode(read(root/LANE/'source-manifest.json',2*1024**2));need(set(mf)=={'schema_version','purpose','files'}and mf['schema_version']==1 and mf['purpose']=='KSM2_GENERIC16K_HOSTED_TEST_ONLY','closed source manifest')
 expected=set(mf['files'])|{LANE+'/source-manifest.json','.github/workflows/native-arm-ksm2-generic16k.yml','.github/workflows/native-arm-build.yml'}
 actual={p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()and p.relative_to(root).parts[0]not in('.git','.ci-inputs')};need(actual==expected,'exact closed hosted source, only top-level Git/component checkouts excluded')
 for name,row in mf['files'].items():need(pin(read(root/relative(name)))==row,'closed source pin: '+name)
 expected_workflow=workflow(root)
 need(read(root/'.github/workflows/native-arm-build.yml')==read(root/'.github/workflows/native-arm-ksm2-generic16k.yml')==expected_workflow,'registered trial alias and exact source-owned workflow stamp identity')
 return expected

def git(root,*argv,cap=8*1024**2):
 p=subprocess.run(['/usr/bin/git','-C',str(root),*argv],stdin=subprocess.DEVNULL,capture_output=True,timeout=30,env=dict(PATH='/usr/bin:/bin',HOME='/tmp',LC_ALL='C',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0'));need(p.returncode==0 and len(p.stdout)+len(p.stderr)<=cap,'bounded genuine Git read refused');return p.stdout

def prove(root,environment):
 root=Path(root).absolute();expected=files(root);source=environment.get('SOURCE_SHA');run=environment.get('GITHUB_RUN_ID');ref=environment.get('GITHUB_REF_NAME')
 need(re.fullmatch('[a-f0-9]{40}',source or'')and all(environment.get(k)==source for k in('GITHUB_SHA','GITHUB_WORKFLOW_SHA'))and re.fullmatch('[1-9][0-9]{0,19}',run or'')and environment.get('GITHUB_RUN_ATTEMPT')=='1'and re.fullmatch('codex/[a-z0-9-]+',ref or'')and environment.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and environment.get('GITHUB_EVENT_NAME')=='workflow_dispatch','exact actual source/workflow/first attempt')
 need(git(root,'rev-parse','HEAD').decode().strip()==source,'checkout HEAD actual source')
 rows={}
 for line in git(root,'ls-tree','-rz','--full-tree',source).split(b'\0'):
  if not line:continue
  meta,name=line.split(b'\t',1);mode,kind,oid=meta.split();n=name.decode();need(mode in(b'100644',b'100755')and kind==b'blob','ordinary Git source blobs only');rows[n]=oid.decode()
 need(set(rows)==expected,'complete committed source custody')
 for n in sorted(rows):need(git(root,'cat-file','blob',source+':'+n,cap=16*1024**2)==read(root/n),'actual source file differs from committed blob: '+n)
 job=hashlib.sha256(('ksm2-vm574:'+source+':'+run+':1').encode()).hexdigest()[:16]
 return dict(status='PASS_GENUINE_SOURCE_NOT_VM_ACCEPTANCE',source=source,run=int(run),ref=ref,attempt=1,job_token=job,manifest=pin(read(root/LANE/'source-manifest.json')),runtime_manifest=pin(read(root/'runtime/source-files.json')),files=len(rows))

def load(name,path):
 import importlib.util
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def carrier_files(checkout,source):
 checkout=Path(checkout);need(git(checkout,'rev-parse','HEAD').decode().strip()==source,'exact selected carrier checkout')
 result={}
 for entry in git(checkout,'ls-tree','-rz','--full-tree',source).split(b'\0'):
  if not entry:continue
  meta,name=entry.split(b'\t',1);mode,kind,oid=meta.split();n=name.decode();relative(n);need(mode in(b'100644',b'100755')and kind==b'blob','ordinary carrier DATA blobs')
  if not n.startswith('payload/'):continue
  raw=read(checkout/n,384*1024**2);need(git(checkout,'cat-file','blob',source+':'+n,cap=384*1024**2)==raw,'carrier file differs from immutable Git object');result[n.removeprefix('payload/')]=raw
 need(1<=len(result)<=64 and sum(map(len,result.values()))<=400*1024**2,'closed bounded native/kernel payload');return result

def binding(v,proof):
 selected(v)
 return dict(native_source=v['known_native_source'],native_run=v['known_native_run'],native_decision=v['native_decision'],native_inputs=v['native_inputs'],kernel_source=v['known_kernel_source'],kernel_run=v['kernel_run'],kernel_authority=v['kernel_authority'],kernel_transport=v['kernel_transport'],kernel_build=v['kernel_build'],producer_report=None,media=None,VM_source=proof['source'],VM_ref=proof['ref'],VM_run=proof['run'])

def components(root,v,proof,native,kernel,destination):
 # Validate each original DATA role in its checkout before creating staging.
 selected(v);root=Path(root);runtime=root/'runtime';sys.path.insert(0,str(runtime));import contract as C
 C.source_check(runtime);C.support(runtime);s=binding(v,proof)
 native_rows=carrier_files(native,v['native_carrier']);kernel_rows=carrier_files(kernel,v['kernel_carrier'])
 need({n:pin(r)for n,r in native_rows.items()}==C.RENEWAL_FILES and v['native_carrier']=='fe67aaaae7ef4ea94dfc8a42cd2c806cc5436fc7','exact genuine32 renewal carrier role before any staging or actors')
 C.native_gate(s,Path(native)/'payload',runtime)
 K=load('_ksm_hosted_kernel_input',runtime/'kernel_input.py');projected=dict(s)
 for n in('kernel_authority','kernel_transport','kernel_build'):projected[n]=dict(s[n],path=s[n]['path'].removeprefix('kernel/'))
 K.imported(projected,Path(kernel)/'payload',runtime)
 custody=dict(status='PASS_GENUINE_COMPONENT_DATA_CUSTODY_NO_BOOT',native_carrier=v['native_carrier'],kernel_carrier=v['kernel_carrier'],native_files={n:pin(r)for n,r in native_rows.items()},kernel_files={n:pin(r)for n,r in kernel_rows.items()},selection_actuals=dict(source=proof['source'],run=proof['run']),kernel_input_path_projection='FIXED_KERNEL_PREFIX_ONLY_NO_RECORD_CHANGE')
 if destination is None:return s,custody
 destination=Path(destination);need(destination.is_absolute()and not destination.exists()and not destination.is_symlink()and destination.parent.is_dir(),'fresh component DATA staging')
 destination.mkdir(mode=0o700)
 for prefix,rows in(('',native_rows),('kernel/',kernel_rows)):
  for name,raw in rows.items():
   p=destination/relative(prefix+name);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);need(not p.exists(),'unique carrier DATA destination');p.write_bytes(raw);p.chmod(0o600)
 C.native_gate(s,destination,runtime);K.imported(s,destination,runtime)
 return s,custody

def workflow(root):
 root=Path(root);text=read(root/LANE/'workflow.yml.in').decode();need(text.count('@ENTRY_SHA@')==1 and text.count('@MANIFEST_SHA@')==1 and text.count('@HOSTED_SHA@')==1,'exact three workflow proof stamps');return text.replace('@ENTRY_SHA@',pin(read(root/LANE/'entry.py'))['sha256']).replace('@MANIFEST_SHA@',pin(read(root/LANE/'source-manifest.json'))['sha256']).replace('@HOSTED_SHA@',pin(read(root/LANE/'hosted.py'))['sha256']).encode()
