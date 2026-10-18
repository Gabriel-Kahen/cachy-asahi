#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Explicit public compile-native component of the existing full ALPM16K lane."""
import argparse,ast,hashlib,importlib.util,json,os,re,shutil,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROUTE='scripts/ci/glibc-debian-maintained-public-installed16k'
LANE='scripts/ci/glibc-debian-maintained-installed16k'
CI='scripts/ci/glibc-debian-maintained-installed16k-ci'
NATIVE='scripts/ci/glibc-debian-maintained-public-provider-lifecycle'
PRIOR='scripts/ci/glibc-debian-maintained-provider-lifecycle'
COMPONENT='9aef8b7429fb8dd9f9d8412f4e878c5e0324c58d'
ROOT_STATUS='ROOT_ACCEPTED_CAA3_PUBLIC_COMPILE_INPUT_NATIVE_LIFECYCLE'
KINDS=('native_lifecycle','system16k')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
def read(p,cap=16*1024**2):
 need(not any(x.is_symlink() for x in (p,*p.parents)),'ordinary unaliased source');s=p.stat();need(p.is_file() and s.st_nlink==1 and 0<s.st_size<=cap,'bounded single-link source');raw=p.read_bytes();need(len(raw)==s.st_size,'source changed');return raw
def rows():
 v=json.loads(read(HERE/'source-pins.json'));need(v['schema_version']==1 and v['native_source']==COMPONENT and len(v['implementation'])==149 and len(v['native_component'])==159,'finite explicit149/159 source roles');return v
def verify(root,files):
 for n,row in files.items():need(pin(read(root/n))==row,'exact source differs: '+n)
def source(root):
 v=rows();verify(root,v['implementation']);return v

def native(root):
 v=rows();verify(root,v['native_component']);actual=set();nodes=0
 for directory,dirs,files in os.walk(root,followlinks=False):
  if Path(directory)==root and '.git' in dirs:dirs.remove('.git')
  for name in dirs+files:
   p=Path(directory)/name;nodes+=1;need(nodes<=512 and not p.is_symlink(),'bounded ordinary native component tree')
   if name in files:need(p.is_file(),'ordinary component leaf');actual.add(p.relative_to(root).as_posix())
 need(actual==set(v['native_component']),'closed159 public-native component only');return v['native_component']

def binding(inputs):
 policy=json.loads(read(HERE/'policy.json'));need(policy['status']=='BOUND_BY_ROOT' and policy['schema_version']==1,'UNBOUND public ALPM16K: future actual Root native ALPM decision required before output/secrets/actors')
 need(policy['native_source']==COMPONENT and policy['packet']==dict(ref='132aec86c0946f6c7b7a79c46e1a9ccaf91021e3',directory='payload',index_sha256='a8e3317cabb3fe914a6b3898b2bfbc900905c3823495f15166c419564f7e4956'),'exact independently pinned public inputs/native source')
 need(set(policy['binding'])==set(inputs)==set(KINDS),'two actual prerequisite roles')
 W=load('public_installed_original_descriptor',HERE.parents[2]/'scripts/ci/glibc-gnu-provider-installed16k-interruption/ci/wiring.py')
 for k in KINDS:need(W.descriptor(policy['binding'][k])==W.descriptor(inputs[k]),'exact Root dispatch descriptor')
 return policy

def preflight(root,inputs,env):
 policy=binding(inputs);source(root)
 W=load('public_installed_git_identity',root/'scripts/ci/glibc-gnu-provider-installed16k-interruption/ci/wiring.py')
 sha=env.get('SOURCE_SHA');need(type(sha) is str and re.fullmatch('[0-9a-f]{40}',sha) and sha==env.get('WORKFLOW_SHA')==env.get('GITHUB_SHA')==W.head(root),'one frozen implementation/workflow checkout')
 need(env.get('RUNNER_ARCH')=='ARM64' and env.get('RUNNER_OS')=='Linux','native ARM disposable CI only');return policy

def phase(raw):
 text=raw.decode();a="native_lifecycle='ROOT_ACCEPTED_DEBIAN_MAINTAINED_PROVIDER_NORMAL_LIFECYCLE'";need(text.count(a)==1,'one old native phase');text=text.replace(a,"native_lifecycle='"+ROOT_STATUS+"'")
 a="  if kind=='native_lifecycle':C.need(";need(text.count(a)==1,'one native phase qualification');text=text.replace(a,"  if kind=='native_lifecycle':C.need(row['source_sha']=='"+COMPONENT+"' and row.get('input_phase')=='NATIVE_COMPILE_INPUTS' and ",1);ast.parse(text);return text.encode()

def copy_component(held,component,output):
 # The native input is independently validated in full before this source copy.
 # Only the shared nonruntime inventory belongs to the current implementation.
 for n in held['native_component']:
  if n=='adaptation.json':continue  # Native component's root ledger is not a VM runtime operand.
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True)
  if n=='manifests/packages.toml':
   need(n in held['implementation'] and q.is_file() and pin(read(q))==held['implementation'][n],'exact current implementation inventory required')
  elif q.exists():need(read(q)==read(component/n),'separate component source conflict: '+n)
  else:q.write_bytes(read(component/n))

def derive(root,component,output):
 held=source(root);native(component);need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary output')
 G=load('public_installed_original_generator',root/LANE/'generator.py');receipt=G.emit(root,output)
 # Original VM modules plus bounded progress helper and all native transaction bodies are generated first.
 for n in held['implementation']:
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(read(root/n))
 copy_component(held,component,output)
 target=output/LANE
 # Restore the generated modules overwritten by implementation source operands.
 for name in G.MODULES:(target/name).write_bytes(G.adapt(read(root/G.OLD/name),name)[0])
 for name in ('candidate_gate.py',):shutil.copyfile(root/G.MAINTAINED/name,target/name)
 contract=read(target/'contract.py').decode();a="NATIVE='"+PRIOR+"'";need(contract.count(a)==1,'one normal source role');(target/'contract.py').write_text(contract.replace(a,"NATIVE='"+NATIVE+"'"))
 (target/'phase_gate.py').write_bytes(phase(read(root/LANE/'phase_gate.py')))
 # The original gate policy remains NULL; no source authorization is an ALPM decision.
 policy=dict(schema_version=1,status='UNBOUND_DO_NOT_EXECUTE',binding=dict.fromkeys(KINDS),candidate=receipt['candidate'],native_pair=receipt['native_pair'],authority='PRIVATE_TEST_ONLY_NO_RELEASE_ADMISSION',interruption='SEPARATE_NOT_A_PREREQUISITE')
 (target/'input-policy.json').write_bytes(encoded(policy))
 deps=held['implementation']|held['native_component']
 inventory='manifests/packages.toml'
 need(inventory in held['implementation'] and inventory in held['native_component'] and pin(read(output/inventory))==held['implementation'][inventory],'exact assembled implementation inventory required')
 deps[inventory]=held['implementation'][inventory]  # No other role has priority over an unequal overlap.
 # Runtime generated leaves have their own independent source manifest.
 deps={n:v for n,v in deps.items() if n!='adaptation.json' and not n.startswith(LANE+'/')}
 (target/'dependencies.json').write_bytes(encoded(dict(schema_version=1,files=deps)))
 own={p.relative_to(output).as_posix():pin(read(p)) for p in target.iterdir() if p.is_file() and p.name!='source-manifest.json'}
 (target/'source-manifest.json').write_bytes(encoded(dict(schema_version=1,files=own)))
 C=load('public_installed_contract',target/'contract.py');C.check_source(output)
 result=dict(status='SOURCE_ONLY_PUBLIC_COMPILE_NATIVE_INSTALLED16K_UNBOUND',native_component=COMPONENT,native_phase=ROOT_STATUS,original_derivation=receipt,ALPM_installation='NOT_RUN',generic16k='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',files={p.relative_to(output).as_posix():pin(read(p)) for p in output.rglob('*') if p.is_file() and p.name!='adaptation.json'})
 (output/'adaptation.json').write_bytes(encoded(result));return result

def assemble(root,component,output,decision_roots,inputs,env,public):
 policy=preflight(root,inputs,env);native(component);W=load('public_installed_decision_reader',root/'scripts/ci/glibc-gnu-provider-installed16k-interruption/ci/wiring.py');raws={}
 for k in KINDS:
  row=policy['binding'][k];need(W.head(decision_roots[k])==row['ref'],'decision Git source differs');raw=read(decision_roots[k]/W.relative(row['path']),128*1024);need(pin(raw)=={f:row[f] for f in ('bytes','sha256')},'Root decision bytes differ');raws[k]=raw
 need(not public.exists(),'fresh public metadata');receipt=derive(root,component,output);target=output/LANE;p=target/'prerequisites';p.mkdir(mode=0o700);v=json.loads(read(target/'input-policy.json'));v['status']='BOUND_BY_ROOT';v['binding']={k:dict(path=k+'.json',**pin(raw)) for k,raw in raws.items()}
 for k,raw in raws.items():(p/(k+'.json')).write_bytes(raw)
 (target/'input-policy.json').write_bytes(encoded(v));m=json.loads(read(target/'source-manifest.json'));m['files'][LANE+'/input-policy.json']=pin(read(target/'input-policy.json'))
 for k,raw in raws.items():m['files'][LANE+'/prerequisites/'+k+'.json']=pin(raw)
 (target/'source-manifest.json').write_bytes(encoded(m));C=load('public_installed_bound_contract',target/'contract.py');C.gate(p);C.check_source(output)
 public.mkdir(mode=0o700)
 for n,raw in {'wiring.json':encoded(dict(status='BOUND_SOURCE_ONLY_NO_RUNTIME_CREDIT',native_component=COMPONENT,decisions=policy['binding'])),'adaptation.json':read(output/'adaptation.json'),'input-policy.json':read(target/'input-policy.json'),'source-manifest.json':read(target/'source-manifest.json'),**{k+'.json':raw for k,raw in raws.items()}}.items():(public/n).write_bytes(raw)
 v={p.name:pin(read(p,128*1024)) for p in public.iterdir()};need(len(v)==6 and sum(r['bytes'] for r in v.values())<=512*1024,'original bounded wiring metadata');(public/'retention.json').write_bytes(encoded(dict(schema_version=1,status='BOUNDED_WIRING_METADATA_ONLY',files=v,bytes=sum(r['bytes'] for r in v.values()))));return receipt

def native_source(root,component,output,inputs,env):
 preflight(root,inputs,env);native(component);need(output.parent==root and not output.exists(),'fresh checkout-child native source');shutil.copytree(component,output,ignore=shutil.ignore_patterns('.git'));return dict(status='SOURCE_COMPONENT_COPIED_NO_RUNTIME_CREDIT',source=COMPONENT,files=len(rows()['native_component']))

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('derive','preflight','assemble','native-source','export'));p.add_argument('--workspace',type=Path,required=True);p.add_argument('--component',type=Path);p.add_argument('--output',type=Path);p.add_argument('--public',type=Path);p.add_argument('--native-decision-root',type=Path);p.add_argument('--normal-decision-root',type=Path);a=p.parse_args();inputs={k:json.loads(os.environ.get(k.upper()+'_DECISION','null')) for k in KINDS}
 if a.action=='derive':v=derive(a.workspace,a.component,a.output)
 elif a.action=='preflight':
  v=preflight(a.workspace,inputs,os.environ)
  with open(os.environ['GITHUB_OUTPUT'],'a') as f:
   for k,r in v['binding'].items():f.write(k+'_ref='+r['ref']+'\n')
   f.write('native_component_ref='+COMPONENT+'\n')
 elif a.action=='assemble':v=assemble(a.workspace,a.component,a.output,dict(native_lifecycle=a.native_decision_root,system16k=a.normal_decision_root),inputs,os.environ,a.public)
 elif a.action=='native-source':v=native_source(a.workspace,a.component,a.output,inputs,os.environ)
 else:
  W=load('public_installed_export',a.workspace/'scripts/ci/glibc-gnu-provider-installed16k-interruption/ci/wiring.py');v=W.public_check(a.public)
 print(json.dumps(v,sort_keys=True))
