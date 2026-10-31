#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Finite maintained interruption composition from two separately closed sources."""
import argparse,ast,hashlib,importlib.util,json,os,re,shutil,stat,subprocess,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROUTE='scripts/ci/glibc-debian-maintained-installed16k-interruption-source'
LANE='scripts/ci/glibc-debian-maintained-installed16k-interruption'
NATIVE='scripts/ci/glibc-debian-maintained-public-provider-interruption'
NORMAL='scripts/ci/glibc-gnu-provider-installed16k'
NATIVE_ROUTE='scripts/ci/glibc-debian-maintained-public-interruption'
KINDS=('native_interruption','normal_installed16k')
WF='.github/workflows/native-arm-glibc-debian-maintained-installed16k-interruption.yml'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  v={}
  for k,x in rows:need(k not in v,'duplicate JSON key');v[k]=x
  return v
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def relative(n):
 need(type(n)is str and re.fullmatch(r'[A-Za-z0-9_.\-/]{1,240}',n) and not n.startswith('/')and all(p not in('','.','..')for p in n.split('/')),'safe relative source/decision path');return n
def read(path,cap=2*1024**2):
 path=Path(path);need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary source/data path');s=path.stat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=cap,'bounded ordinary single-link source/data');raw=path.read_bytes();a=path.stat();need(len(raw)==s.st_size and(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns),'source/data changed');return raw
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
def source(root):
 rows=decode(read(HERE/'source-manifest.json'))['files']
 for n,row in rows.items():need(pin(read(root/relative(n)))==row,'exact maintained template source: '+n)
 return rows

def snapshots(normal,native):
 v=decode(read(HERE/'source-inputs.json'));need(len(v['normal']['files'])==157 and len(v['native']['files'])==165,'exact separate157/165 published roles')
 for kind,root in(('normal',normal),('native',native)):
  files=v[kind]['files'];actual=set();nodes=0
  for folder,dirs,leaves in os.walk(root,followlinks=False):
   if Path(folder)==root and '.git'in dirs:dirs.remove('.git')
   nodes+=len(dirs)+len(leaves);need(nodes<=512,'finite source tree nodes')
   for n in dirs+leaves:need(not(Path(folder)/n).is_symlink(),'no source aliases')
   for n in leaves:actual.add((Path(folder)/n).relative_to(root).as_posix())
  need(actual==set(files),'whole closed '+kind+' source snapshot')
  for n,row in files.items():need(pin(read(root/relative(n)))==row,'published '+kind+' source differs: '+n)
 shared=set(v['normal']['files'])&set(v['native']['files']);need(len(shared)==102,'finite two-source overlap')
 need([n for n in sorted(shared)if v['normal']['files'][n]!=v['native']['files'][n]]==['.github/workflows/native-arm-build.yml'],'only registered alias differs; never rewrite historical manifests')
 return v

def one(text,before,after,count=1):
 need(text.count(before)==count,'counted maintained interruption anchor: '+before[:90]);return text.replace(before,after)
def maintained(raw,name,G):
 raw,count=G.adapt(raw,name);text=raw.decode();edits=[]
 rules=[('caa_gnu_interrupted16k=1','caa_debian_maintained_interrupted16k=1'),('GNU_INTERRUPTED16K','DEBIAN_MAINTAINED_INTERRUPTED16K'),('CAA_INTERRUPTED16K_PREPARE','CAA_DEBIAN_MAINTAINED_INTERRUPTED16K_PREPARE'),('/installed16k-interruption','/debian-maintained-installed16k-interruption'),("'installed16k-interruption", "'debian-maintained-installed16k-interruption"),('init-interrupted16k','init-debian-maintained-interrupted16k'),('caa-gnu-interrupted16k-','caa-debian-maintained-interrupted16k-')]
 for a,b in rules:
  n=text.count(a)
  if n:text=one(text,a,b,n);edits.append(dict(before=a,after=b,count=n))
 if name=='contract.py':
  text=one(text,G.NEW,LANE);text=one(text,"NATIVE='scripts/ci/glibc-gnu-provider-interruption'","NATIVE='"+NATIVE+"'");text=one(text,'org.cachy-asahi.gnu-interrupted16k','org.cachy-asahi.debian-maintained-interrupted16k');text=one(text,'PASS_GENERIC16K_ALPM_PROVIDER_INTERRUPTED_REPLACEMENT_AND_RECOVERY','PASS_DEBIAN_MAINTAINED_GENERIC16K_ALPM_PROVIDER_INTERRUPTED_REPLACEMENT_AND_RECOVERY')
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='gate');body=ast.get_source_segment(text,node);text=one(text,body,"def gate(acceptances):\n    return load('maintained_interruption_phase',HERE/'phase_gate.py').validate(sys.modules[__name__],acceptances)")
 if name=='prepare.py':text=one(text,'b852e3fc647d63699c5f42003a748cbd2268991dc2615a494dc3cdda4d757d12','a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9')
 if name=='run.py':text=one(text,'caa_debian_maintained_interrupted16k=1','caa_debian_maintained_interrupted16k=1 arm64.nomops')
 ast.parse(text);return text.encode(),dict(original_interruption_edits=count,maintained_identity_edits=edits)

def derive(root,normal,native,output):
 source(root);v=snapshots(normal,native);need(not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary source-only output')
 G=load('whole_original_interruption_generator',HERE/'original_generator.py');P=load('exact_maintained_native_interruption_source',native/NATIVE_ROUTE/'prepare.py')
 with tempfile.TemporaryDirectory()as td:
  # Invoke the exact73da native emitter on an ordinary source-only clone. Its
  # existing whole b07 decision is a prerequisite, never new interruption credit.
  clone=Path(td)/'native';shutil.copytree(native,clone,ignore=shutil.ignore_patterns('.git'));normal_root=Path(td)/'normal/payload';normal_root.mkdir(parents=True)
  (normal_root/'native-lifecycle.json').write_bytes(read(native/NATIVE_ROUTE/'known-native-normal.json'))
  P=load('source_only_native_emitter_clone',clone/NATIVE_ROUTE/'prepare.py');native_out=clone/'runtime';P.emit(clone,native_out,normal_root.parent)
  output.mkdir(mode=0o700)
  for p in native_out.rglob('*'):
   if p.is_file()and p.relative_to(native_out).as_posix()!='adaptation.json':q=output/p.relative_to(native_out);q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(read(p))
 # Add normal helpers; the only conflicting published dispatch alias is omitted.
 for n in v['normal']['files']:
  if n=='.github/workflows/native-arm-build.yml':continue
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True)
  if q.exists():need(read(q)==read(normal/n),'whole helper overlap differs: '+n)
  else:q.write_bytes(read(normal/n))
 deps={p.relative_to(output).as_posix():pin(read(p))for p in output.rglob('*')if p.is_file()}
 target=output/LANE;target.mkdir(parents=True,mode=0o700);changes={}
 for name in G.MODULES:
  raw,receipt=maintained(read(normal/NORMAL/name),name,G);(target/name).write_bytes(raw);changes[name]=receipt
 G.OWNER=NATIVE+'-owner/job.py';recovery=G.recovery(output);(target/'recovery.py').write_bytes(recovery)
 (target/'phase_gate.py').write_bytes(read(HERE/'phase_gate.py'))
 (target/'input-policy.json').write_bytes(encoded(dict(schema_version=1,status='UNBOUND_DO_NOT_EXECUTE',binding=dict.fromkeys(KINDS),authority='PRIVATE_TEST_ONLY_NO_RELEASE_ADMISSION')))
 (target/'dependencies.json').write_bytes(encoded(dict(schema_version=1,files=deps)))
 own={p.relative_to(output).as_posix():pin(read(p))for p in target.iterdir()if p.is_file()};(target/'source-manifest.json').write_bytes(encoded(dict(schema_version=1,files=own)))
 C=load('derived_maintained_interrupted16k_contract',target/'contract.py');C.check_source(output)
 result=dict(status='SOURCE_ONLY_MAINTAINED_INTERRUPTED16K_UNBOUND',normal_input=v['normal']['source'],native_input=v['native']['source'],input_files=dict(normal=157,native=165),source_files=len(deps),derived_files=len(own)+1,bundle_files=len(deps)+len(own)+2,changes=changes,recovery_owner_validator_edits=2,root_maps=20,normal_runtime_observations=10,copy600='HELD',worker10500='HELD',QEMU10800='HELD',arm64_nomops='REQUIRED',hardware='NOT_RUN',release='NOT_ADMITTED')
 (output/'adaptation.json').write_bytes(encoded(result));actual={p.relative_to(output).as_posix()for p in output.rglob('*')if p.is_file()};closed=set(deps)|set(own)|{LANE+'/source-manifest.json','adaptation.json'};need(actual==closed and len(actual)==236,'closed219+16+ledger source bundle');return result

def descriptor(v):
 need(type(v)is dict and set(v)=={'ref','path','bytes','sha256'},'UNBOUND exact future Root decision descriptor required');relative(v['path']);need(type(v['ref'])is str and re.fullmatch('[0-9a-f]{40}',v['ref'])and type(v['bytes'])is int and 0<v['bytes']<=128*1024 and type(v['sha256'])is str and re.fullmatch('[0-9a-f]{64}',v['sha256']),'finite immutable Root decision descriptor');return v

def selection(inputs):
 p=decode(read(HERE/'policy.json',65536));need(p['schema_version']==1 and p['status']=='BOUND_BY_ROOT'and type(p['binding'])is dict and set(p['binding'])==set(inputs)==set(KINDS)and all(type(p['binding'][k])is dict for k in KINDS),'UNBOUND BOTH actual maintained native-interruption/full-normal16K decisions required before outputs/actors')
 for k in KINDS:need(descriptor(p['binding'][k])==descriptor(inputs[k]),'dispatch decision differs from Root selected source')
 return p['binding']

def head(root):
 r=subprocess.run(['/usr/bin/git','--no-replace-objects','-C',str(root),'rev-parse','HEAD'],capture_output=True,text=True,timeout=10);need(r.returncode==0 and len(r.stdout)<=128,'bounded source identity');return r.stdout.strip()
def preflight(root,inputs,env):
 selected=selection(inputs);source(root);sha=env.get('SOURCE_SHA');need(type(sha)is str and re.fullmatch('[0-9a-f]{40}',sha)and sha==env.get('WORKFLOW_SHA')==env.get('GITHUB_SHA')==head(root),'one exact source/workflow checkout');need(env.get('RUNNER_ARCH')=='ARM64'and env.get('RUNNER_OS')=='Linux','native ARM disposable CI only');return selected

def assemble(root,normal,native,output,decision_roots,inputs,env,public):
 selected=preflight(root,inputs,env);v=snapshots(normal,native);need(head(normal)==v['normal']['source']and head(native)==v['native']['source'],'two whole exact published component checkouts')
 phase=load('future_exact_maintained_decision_schema',HERE/'phase_gate.py');raws={}
 for k,row in selected.items():
  need(head(decision_roots[k])==row['ref'],'exact Root decision carrier checkout');raw=read(decision_roots[k]/relative(row['path']),128*1024);need(pin(raw)=={x:row[x]for x in('bytes','sha256')},'whole future Root decision pin');phase.fields(decode(raw),k,phase.EXPECTED,phase.PROVIDER);raws[k]=raw
 need(not public.exists()and public.parent.is_dir()and not any(p.is_symlink()for p in(public,*public.parents)),'fresh wiring public output')
 receipt=derive(root,normal,native,output);target=output/LANE;prereqs=target/'prerequisites';prereqs.mkdir(mode=0o700);p=decode(read(target/'input-policy.json'));p.update(status='BOUND_BY_ROOT',binding={k:dict(path=k+'.json',**pin(raw))for k,raw in raws.items()})
 for k,raw in raws.items():(prereqs/(k+'.json')).write_bytes(raw)
 (target/'input-policy.json').write_bytes(encoded(p));m=decode(read(target/'source-manifest.json'));m['files'][LANE+'/input-policy.json']=pin(read(target/'input-policy.json'))
 for k,raw in raws.items():m['files'][LANE+'/prerequisites/'+k+'.json']=pin(raw)
 (target/'source-manifest.json').write_bytes(encoded(m));C=load('bound_maintained_interruption_contract',target/'contract.py');C.check_source(output);C.gate(prereqs)
 actual={p.relative_to(output).as_posix()for p in output.rglob('*')if p.is_file()};closed=set(decode(read(target/'dependencies.json'))['files'])|set(m['files'])|{LANE+'/source-manifest.json','adaptation.json'};need(actual==closed and len(actual)==238,'closed219+16+ledger+two actual decisions')
 public.mkdir(mode=0o700)
 for n,raw in {'wiring.json':encoded(dict(status='BOUND_SOURCE_ONLY_NO_RUNTIME_CREDIT',decisions=selected,normal_input=v['normal']['source'],native_input=v['native']['source'])),'adaptation.json':read(output/'adaptation.json'),'input-policy.json':read(target/'input-policy.json'),'source-manifest.json':read(target/'source-manifest.json'),**{k+'.json':raw for k,raw in raws.items()}}.items():(public/n).write_bytes(raw)
 rows={p.name:pin(read(p,128*1024))for p in public.iterdir()};need(len(rows)==6 and sum(r['bytes']for r in rows.values())<=512*1024,'six bounded wiring metadata files');(public/'retention.json').write_bytes(encoded(dict(schema_version=1,status='BOUNDED_WIRING_METADATA_ONLY',files=rows,bytes=sum(r['bytes']for r in rows.values()))));return receipt

def public_check(public):
 value=decode(read(public/'retention.json',65536));need(value['status']=='BOUNDED_WIRING_METADATA_ONLY'and len(value['files'])==6 and value['bytes']==sum(v['bytes']for v in value['files'].values())<=512*1024,'bounded wiring metadata only')
 need({p.name for p in public.iterdir()}==set(value['files'])|{'retention.json'},'closed wiring metadata')
 for n,row in value['files'].items():need('/'not in relative(n)and pin(read(public/n,128*1024))==row,'wiring metadata changed')
 return dict(status='PASS_BOUNDED_WIRING_METADATA_ONLY')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('derive','preflight','assemble','export'));p.add_argument('--workspace',type=Path,required=True);p.add_argument('--normal-source',type=Path);p.add_argument('--native-source',type=Path);p.add_argument('--native-decision-root',type=Path);p.add_argument('--normal-decision-root',type=Path);p.add_argument('--output',type=Path);p.add_argument('--public',type=Path);a=p.parse_args();inputs={k:decode(os.environ.get(k.upper()+'_DECISION','null'))for k in KINDS}
 if a.action=='export':result=public_check(a.public)
 elif a.action=='derive':result=derive(a.workspace,a.normal_source,a.native_source,a.output)
 elif a.action=='preflight':
  result=preflight(a.workspace,inputs,os.environ)
  with open(os.environ['GITHUB_OUTPUT'],'a')as f:
   for k,r in result.items():f.write(k+'_ref='+r['ref']+'\n')
 else:result=assemble(a.workspace,a.normal_source,a.native_source,a.output,dict(native_interruption=a.native_decision_root,normal_installed16k=a.normal_decision_root),inputs,os.environ,a.public)
 print(json.dumps(result,sort_keys=True))
