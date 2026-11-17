# SPDX-License-Identifier: MIT
"""Compose qualification and privacy contracts; no process or authority creation."""
import hashlib,importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
EVIDENCE=('baseline_certificate','runtime_certificate','resource_certificate','Root_decision','installed_Reader','installed_component_decision')
ROLES=('document','scan','empty_proof','empty_closure','scan_certificate','qualification_case')+tuple('qualification_'+n for n in EVIDENCE)
def module(name,root=HERE):
 s=importlib.util.spec_from_file_location('initialized_lifecycle_'+name,root/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def initialized(name):return module(name,HERE/'_initialized')
def refs(materials):
 K=module('contracts');p=K.ordinary(materials);p=(p if p.is_dir()else p.parent)/'initialized-inputs.json';v=K.load(p);K.keys(v,ROLES,'explicit fresh initialized qualification references')
 for row in v.values():
  K.keys(row,('path','bytes','sha256'),'closed selected qualification descriptor');K.need(K.pin(K.ordinary(row['path']))=={k:row[k]for k in('bytes','sha256')},'external exact qualification input pin')
 return v
def empty_closure(K,path,cap=4*1024**2):
 """Decode only the four observational seconds in the actual r74 closure."""
 p=K.ordinary(path);before=K.pin(p,cap)
 def unique(rows):
  result={}
  for k,v in rows:K.need(k not in result,'duplicate JSON field');result[k]=v
  return result
 def invalid(value):raise ValueError('nonfinite JSON: '+value)
 raw=p.read_bytes();K.need(len(raw)<=cap and dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==before,'stable bounded JSON read')
 value=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)
 timings={('external','seconds')}|{('owned_absence_independently_verified',i,'retirement','seconds')for i in range(3)}
 def check(v,path=()):
  if path in timings:K.need(type(v)in(int,float)and 0<=v<float('inf'),'finite nonnegative observational seconds')
  elif type(v)is float:raise ValueError('noninteger JSON outside empty-closure observational seconds')
  if type(v)is dict:
   for k,w in v.items():check(w,path+(k,))
  elif type(v)is list:
   for i,w in enumerate(v):check(w,path+(i,))
 check(value);K.need(type(value)is dict and raw==K.canonical(value),'canonical JSON object required');return value
def input_value(K,role,path):
 return empty_closure(K,path)if role=='empty_closure'else K.load(path,128*1024**2 if role=='scan'else 4*1024**2)
def qualify(case,observed,cert,bindings,source):
 K=module('contracts');Q=initialized('qualification');K.keys(bindings,ROLES,'complete new initialized evidence tuple');v={}
 for n,row in bindings.items():
  K.keys(row,('path','bytes','sha256'),'exact initialized input descriptor');p=K.ordinary(row['path']);K.need(K.pin(p)=={k:row[k]for k in('bytes','sha256')},'exact initialized qualification input');v[n]=input_value(K,n,p)
 prior={n:v['qualification_'+n]for n in EVIDENCE};prior_case=v['qualification_case'];prior_observed=dict(observed,**{n:K.json_pin(prior[n])for n in EVIDENCE})
 result=Q.qualify(v['document'],v['scan'],v['empty_proof'],v['empty_closure'],prior_case,prior_observed,prior,v['scan_certificate'])
 lifecycle_join(K,Q,case,cert,prior_case,prior,source)
 return dict(state=initialized('policy').snapshot(v['scan']),proof=v['empty_proof'],closure=v['empty_closure'],validation=result,bindings=bindings)
def lifecycle_join(K,Q,case,cert,prior_case,prior,source):
 K.need({k:v for k,v in case.items()if k!='evidence'}=={k:v for k,v in prior_case.items()if k!='evidence'},'same qualified case/package/native/trust; only fresh evidence tuple differs')
 for n in EVIDENCE:
  if n not in('resource_certificate','Root_decision'):K.need(cert[n]==prior[n],'same qualified lifecycle '+n)
 a=cert['resource_certificate'];b=prior['resource_certificate']
 K.need(all(a[n]==v for n,v in Q.FIXED_RESOURCES.items())and a['baseline_allocated_bytes']==634167296,'same frozen lifecycle bounds and warmed allocation')
 live={'physical_free_bytes','host_MemAvailable_bytes','quota_guard'}
 K.need({k:v for k,v in a.items()if k not in live}=={k:v for k,v in b.items()if k not in live},'same qualified geometry and lifecycle resource contract')
 aq,bq=a['quota_guard'],b['quota_guard'];fresh={'source_lock','outputs','created_utc','expires_utc'}
 K.need({k:v for k,v in aq.items()if k not in fresh}=={k:v for k,v in bq.items()if k not in fresh}and aq['source_lock']==source,'new lifecycle Source/output/time binding; unchanged quota/capacity semantics')
def fixture(cert,qualified):
 cert['_initialized_state']=qualified['state'];return cert
def verify_packet(case,observed,cert,packet):
 K=module('contracts');q=qualify(case,observed,cert,packet['initialized_inputs'],packet['Source_lock']);K.need(K.json_pin(q['state'])==packet['initialized_state'],'packet genuine initialized qualification and exact state');return q
def guard_empty(K,reader):
 E=initialized('ssh_empty');privacy=module('ssh_privacy',HERE/'_legacy');budget=[0]
 entries=privacy._directory(K,reader,2,2,budget);root=entries.get(b'root');K.need(root is not None and root[1]==2 and root[0]!=2 and sum(v[0]==root[0]for v in entries.values())==1,'literal initialized root without aliases')
 entries=privacy._directory(K,reader,root[0],2,budget);target=entries.get(b'.ssh');K.need(target is not None and target[1]==2 and target[0]not in(2,root[0])and sum(v[0]==target[0]for v in entries.values())==1,'literal existing selected SSH without aliases')
 reader._ssh_inode=target[0];reader._verified_blocks=[];proof=E.aggregate(reader,target[0],root[0]);E.require_empty(proof)
 expected=K.load(Path('/packet/initialized-empty-proof.json'))['root_ssh_emptiness'];K.need(proof==expected,'fresh same-inode initialized empty SSH proof before inventory');reader._empty=proof;reader._metadata_only=False;return proof
