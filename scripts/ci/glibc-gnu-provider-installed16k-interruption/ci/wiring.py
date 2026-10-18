#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite, actor-free workflow source assembly. Default policy refuses execution."""
import argparse,hashlib,importlib.util,json,os,re,stat,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/glibc-gnu-provider-installed16k-interruption'
KINDS=('native_interruption','normal_installed16k')
LIMIT=128*1024

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  value={}
  for k,v in rows:need(k not in value,'duplicate JSON key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def relative(name):
 need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.\-/]{1,240}',name) and all(p not in ('','.','..') for p in name.split('/')),'ordinary relative decision path');return name
def read(path,cap=2*1024**2):
 path=Path(path);need(not any(p.is_symlink() for p in (path,*path.parents)),'no symbolic path');s=path.stat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=cap,'bounded ordinary file');raw=path.read_bytes();need(len(raw)==s.st_size,'file changed');return raw
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
def descriptor(value):
 need(type(value) is dict and set(value)=={'ref','path','bytes','sha256'},'closed Root decision descriptor')
 need(type(value['ref']) is str and re.fullmatch('[0-9a-f]{40}',value['ref']),'immutable decision Git object')
 relative(value['path']);need(type(value['bytes']) is int and 0<value['bytes']<=LIMIT and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),'bounded pinned decision');return value
def selection(policy,inputs):
 need(policy['schema_version']==1 and policy['status']=='BOUND_BY_ROOT','UNBOUND: both actual Root decisions required before credentials, outputs or actors')
 need(type(policy['binding']) is dict and set(policy['binding'])==set(KINDS) and set(inputs)==set(KINDS),'exactly two distinct prerequisite roles')
 for k in KINDS:need(descriptor(policy['binding'][k])==descriptor(inputs[k]),'dispatch decision differs from Root-bound policy')
 return policy['binding']
def check_source(root):
 files=decode(read(HERE/'integration-manifest.json'))['files']
 need(type(files) is dict and len(files)==115,'finite original106 plus adapter5 plus CI4 source closure')
 for name,row in files.items():need(pin(read(root/relative(name)))==row,'exact workflow source: '+name)
 return files
def head(root):
 result=subprocess.run(['git','-C',str(root),'rev-parse','HEAD'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
 need(len(result.stdout)<=128,'bounded Git identity');return result.stdout.decode().strip()
def preflight(root,inputs,env):
 bound=selection(decode(read(HERE/'policy.json',65536)),inputs)
 source=env.get('SOURCE_SHA','');need(re.fullmatch('[0-9a-f]{40}',source) and source==env.get('WORKFLOW_SHA')==env.get('GITHUB_SHA'),'source and workflow must be exactly frozen together')
 need(env.get('RUNNER_ARCH')=='ARM64' and env.get('RUNNER_OS')=='Linux','native ARM disposable CI only')
 check_source(root);need(head(root)==source,'checkout source differs');return bound

def assemble(root,output,decision_roots,inputs,env,public):
 bound=preflight(root,inputs,env);need(set(decision_roots)==set(KINDS),'two decision checkout roots');raws={}
 for kind in KINDS:
  row=bound[kind];need(head(decision_roots[kind])==row['ref'],'decision checkout differs');raw=read(decision_roots[kind]/relative(row['path']),LIMIT)
  need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'decision bytes differ');raws[kind]=raw
 need(not output.exists() and not public.exists() and not any(p.is_symlink() for p in (output,public,*output.parents,*public.parents)),'fresh ordinary source and metadata outputs')
 generator=load('interrupted16k_generator',root/LANE/'generator.py');held=generator.source(root);original=generator.emit(root,output)
 for name,row in held['files'].items():
  target=output/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);target.write_bytes(read(root/name));need(pin(read(target))==row,'copied source changed')
 lane=output/LANE;prereqs=lane/'prerequisites';prereqs.mkdir(mode=0o700);binding={}
 for kind in KINDS:
  path=prereqs/(kind+'.json');path.write_bytes(raws[kind]);binding[kind]=dict(path=path.name,**pin(raws[kind]))
 policy=decode(read(lane/'input-policy.json'));policy['status']='BOUND_BY_ROOT';policy['binding']=binding;(lane/'input-policy.json').write_bytes(encoded(policy))
 manifest=decode(read(lane/'source-manifest.json'));manifest['files'][LANE+'/input-policy.json']=pin(read(lane/'input-policy.json'))
 for kind in KINDS:manifest['files'][LANE+'/prerequisites/'+kind+'.json']=pin(raws[kind])
 (lane/'source-manifest.json').write_bytes(encoded(manifest))
 contract=load('interrupted16k_contract',lane/'contract.py');decisions=contract.gate(prereqs);contract.check_source(output)
 closed=set(held['files'])|set(original['files'])|{'adaptation.json'}|{LANE+'/prerequisites/'+k+'.json' for k in KINDS}
 actual={p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()};need(actual==closed and len(actual)==124,'closed106+15+adaptation+2 source bundle')
 receipt=dict(schema_version=1,status='BOUND_SOURCE_ONLY_NO_RUNTIME_CREDIT',source_sha=env['SOURCE_SHA'],source_files=106,derived_files=15,bundle_files=124,decisions=bound,decision_results={k:dict(status=v['status'],source_sha=v['source_sha'],run_id=v['run_id']) for k,v in decisions.items()},effective_input_policy=pin(read(lane/'input-policy.json')),effective_source_manifest=pin(read(lane/'source-manifest.json')),authority='PRIVATE_TEST_ONLY_NO_RELEASE_ADMISSION',hardware='NOT_RUN',runtime='NOT_RUN')
 public.mkdir(mode=0o700)
 for name,raw in {'wiring.json':encoded(receipt),'adaptation.json':read(output/'adaptation.json'),'input-policy.json':read(lane/'input-policy.json'),'source-manifest.json':read(lane/'source-manifest.json'),**{k+'.json':raws[k] for k in KINDS}}.items():(public/name).write_bytes(raw)
 rows={p.name:pin(read(p,LIMIT)) for p in public.iterdir()};need(len(rows)==6 and sum(v['bytes'] for v in rows.values())<=512*1024,'six-file bounded public metadata only');(public/'retention.json').write_bytes(encoded(dict(schema_version=1,status='BOUNDED_WIRING_METADATA_ONLY',files=rows,bytes=sum(v['bytes'] for v in rows.values()))));return receipt

def public_check(public):
 value=decode(read(public/'retention.json',65536));need(value['status']=='BOUNDED_WIRING_METADATA_ONLY' and len(value['files'])==6 and value['bytes']==sum(v['bytes'] for v in value['files'].values())<=512*1024,'bounded wiring metadata only')
 need({p.name for p in public.iterdir()}==set(value['files'])|{'retention.json'},'closed wiring metadata export')
 for name,row in value['files'].items():need('/' not in relative(name) and pin(read(public/name,LIMIT))==row,'metadata export changed')

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('preflight','assemble','export'));parser.add_argument('--workspace',type=Path,required=True);parser.add_argument('--output',type=Path);parser.add_argument('--public',type=Path);parser.add_argument('--native-decision-root',type=Path);parser.add_argument('--normal-decision-root',type=Path);args=parser.parse_args()
 if args.action=='export':public_check(args.public)
 else:
  inputs={k:decode(os.environ.get(k.upper()+'_DECISION','null')) for k in KINDS}
  if args.action=='preflight':
   bound=preflight(args.workspace,inputs,os.environ)
   with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
    for k,row in bound.items():stream.write(k+'_ref='+row['ref']+'\n')
  else:print(json.dumps(assemble(args.workspace,args.output,dict(native_interruption=args.native_decision_root,normal_installed16k=args.normal_decision_root),inputs,os.environ,args.public),sort_keys=True))
