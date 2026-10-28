#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact failure-retaining563 from immutable555; source-only fresh graph trial."""
import argparse,base64,hashlib,json,shutil,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 2500, 'sha256': '79b591ef6a4ce76c1b1695e095e4cef6de869b4a669afce31e63e94a12e30f88'}
I='latest/implementation/';MANIFEST='latest/source-manifest.json';GUARD=I+'latest_guard.py'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def ordinary(path):
 path=Path(path).absolute();need('..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary explicit source/output ancestry');return path
def read(path):
 path=ordinary(path);s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=16*1024**2,'bounded singlelink whole source');raw=path.read_bytes();identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns);need(len(raw)==s.st_size and identity(path.lstat())==identity(s),'whole stable atime-independent source read');return raw
def files(root):
 root=ordinary(root);need(root.is_dir(),'original whole source directory');out={}
 for p in sorted(root.rglob('*')):
  n=p.relative_to(root)
  if n.parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_dir()or p.is_file()),'ordinary closed source nodes')
  if p.is_file():out[n.as_posix()]=pin(read(p))
 return out

def inputs():
 raw=read(HERE/'profile.json');need(pin(raw)==PROFILE,'whole fixed source-only profile');profile=json.loads(raw);bodies={}
 for name,want in profile['support'].items():
  body=read(HERE/name);need(pin(body)==want,'exact profile support body '+name);bodies[name]=body
 p=json.loads(bodies['lifecycle-successor.json']);expected=json.loads(bodies['source559.json']);final=json.loads(bodies['source561.json']);q=json.loads(bodies['prefill-path-successor.json']);need(len(p['before'])==555 and len(expected)==559 and len(final)==561 and q['before']==expected and p['publication']['source']==profile['source_before']and set(p['added'])=={I+n for n in('latest_descriptor.py','latest_graph_timing.py','lifecycle_successor.py','lifecycle-successor.json')},'one exact555 to559 profile, no generic source input');r=json.loads(bodies['failure-retention-successor.json']);last=json.loads(bodies['source563.json']);need(r['before']==final and len(last)==563,'whole fixed561-to563 failure-data profile');return profile,p,expected,final,q,r,last,bodies

def emit(source,output,profile='fresh_descriptor563'):
 need(profile in('fresh_descriptor563','fresh_ancestry566','correctness2400','layered4200'),'explicit corrected finite graph profile');_,p,expected,final,q,r,last,bodies=inputs()
 if profile in('fresh_ancestry566','correctness2400','layered4200'):ancestry_inputs()
 if profile=='correctness2400':correctness_inputs()
 if profile=='layered4200':layered_inputs()
 source=ordinary(source);output=ordinary(output);need(files(source)==p['before'],'entire original555 source before any output');need(not output.exists()and output.parent.is_dir()and not output.is_relative_to(source)and not source.is_relative_to(output),'fresh separate source-only output');shutil.copytree(source,output,ignore=shutil.ignore_patterns('.git'));need(files(output)==p['before'],'whole original555 copied without drift')
 for name,edits in p['edits'].items():
  text=read(output/name).decode()
  for old,new in edits:need(text.count(old)==1,'one exact source-owned query/timing/reporting seam');text=text.replace(old,new,1)
  inverse=text
  for old,new in reversed(edits):need(inverse.count(new)==1,'one exact inverse seam');inverse=inverse.replace(new,old,1)
  need(inverse.encode()==read(source/name),'whole original runtime/test body inverse');(output/name).write_text(text)
 for name in p['added']:(output/name).write_bytes(bodies[Path(name).name])
 proof_pin=pin(bodies['lifecycle-successor.json']);text=read(output/GUARD).decode()+'\n# BEGIN_FINITE_LIFECYCLE_DESCRIPTOR_SUCCESSOR\ndef verify():\n import lifecycle_successor\n return lifecycle_successor.verify(ROOT, '+repr(I+'lifecycle-successor.json')+', '+repr(proof_pin)+')\n';(output/GUARD).write_text(text)
 value=json.loads(read(output/MANIFEST));value['files']={n:v for n,v in files(output).items()if n not in{MANIFEST,*p['workflows']}};(output/MANIFEST).write_bytes(encoded(value));manifest=pin(read(output/MANIFEST))
 for name in p['workflows']:
  raw=read(output/name);old=p['before'][MANIFEST]['sha256'].encode();need(raw.count(old)==1,'one exact source stamp, original workflow/clocks held');(output/name).write_bytes(raw.replace(old,manifest['sha256'].encode(),1))
 actual=files(output);need(actual==expected,'entire intermediate559 exact; never returned as runnable source')
 for name,edits in q['edits'].items():
  text=read(output/name).decode()
  for old,new in edits:need(text.count(old)==1,'one exact actual-failed prefill argv/count seam');text=text.replace(old,new,1)
  (output/name).write_text(text)
 for name in q['added']:(output/name).write_bytes(bodies[Path(name).name])
 proof_pin=pin(bodies['prefill-path-successor.json']);text=read(output/GUARD).decode()+'\n# BEGIN_EXACT_PREFILL_PATH_SUCCESSOR\ndef verify():\n import prefill_path_successor\n return prefill_path_successor.verify(ROOT, '+repr(I+'prefill-path-successor.json')+', '+repr(proof_pin)+')\n';(output/GUARD).write_text(text)
 value=json.loads(read(output/MANIFEST));value['files']={n:v for n,v in files(output).items()if n not in{MANIFEST,*q['workflows']}};(output/MANIFEST).write_bytes(encoded(value));manifest=pin(read(output/MANIFEST))
 for name in q['workflows']:
  raw=read(output/name);old=q['before'][MANIFEST]['sha256'].encode();need(raw.count(old)==1,'one exact corrected source stamp');(output/name).write_bytes(raw.replace(old,manifest['sha256'].encode(),1))
 actual=files(output);need(actual==final,'entire corrected561 exact intermediate; never returned as output')
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_failed_public_data',HERE/'failure_retention.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
 (output/r['transport']).write_text(F.derive_transport(read(output/r['transport']).decode()))
 for name,edits in r['edits'].items():
  text=read(output/name).decode()
  for old,new in edits:need(text.count(old)==1,'one exact failure-data source seam');text=text.replace(old,new,1)
  (output/name).write_text(text)
 for name in r['added']:(output/name).write_bytes(bodies[Path(name).name])
 proof_pin=pin(bodies['failure-retention-successor.json']);text=read(output/GUARD).decode()+'\n# BEGIN_BOUNDED_FAILURE_RETENTION_SUCCESSOR\ndef verify():\n import failure_retention\n return failure_retention.verify(ROOT, '+repr(I+'failure-retention-successor.json')+', '+repr(proof_pin)+')\n';(output/GUARD).write_text(text)
 value=json.loads(read(output/MANIFEST));value['files']={n:v for n,v in files(output).items()if n not in{MANIFEST,*r['workflows']}};(output/MANIFEST).write_bytes(encoded(value));manifest=pin(read(output/MANIFEST))
 for name in r['workflows']:
  raw=read(output/name);old=r['before'][MANIFEST]['sha256'].encode();need(raw.count(old)==1,'one failure-data source stamp, workflow/clocks held');(output/name).write_bytes(raw.replace(old,manifest['sha256'].encode(),1))
 actual=files(output);need(actual==last,'whole exact published563 failure-data source')
 if profile in('fresh_ancestry566','correctness2400','layered4200'):
  value=ancestry(output,last)
  return layered(output,value['files'])if profile=='layered4200'else correctness(output,value['files'])if profile=='correctness2400'else value
 return dict(status='SOURCE_ONLY_EXACT563_FAILED_PUBLIC_DATA_CAPTURE_UNQUALIFIED',files=actual,consumer_seconds=1800,owner_seconds=6600,actual=None,native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

ANCESTRY_PROFILE={'bytes': 1327, 'sha256': 'f4a265501c26adc5577affd624deb593c1121b4f4ba3c5e3846e51b0c6bc97f0'}

def ancestry_inputs():
 raw=read(HERE/'ancestry-profile.json');need(pin(raw)==ANCESTRY_PROFILE,'whole explicit ancestry profile');v=json.loads(raw);need(v['profile']=='fresh_ancestry566'and v['default']is False,'explicit opt-in only');bodies={}
 for n,w in v['support'].items():
  body=read(HERE/n);need(pin(body)==w,'whole ancestry emission support '+n);bodies[n]=body
 p=json.loads(bodies['ancestry/lifecycle-cost-successor.json']);expected=json.loads(bodies['ancestry/source566.json']);need(len(p['before'])==563 and len(expected)==566,'complete fixed563/566 profile');return p,expected,bodies

def ancestry(output,before):
 p,expected,bodies=ancestry_inputs();need(p['before']==before and files(output)==before,'complete original563 before optional566')
 for n,edits in p['edits'].items():
  text=read(output/n).decode()
  for a,b in edits:need(text.count(a)==1,'one exact optional ancestry/timing/count seam');text=text.replace(a,b,1)
  (output/n).write_text(text)
 for n in p['added']:(output/n).write_bytes(bodies['ancestry/'+Path(n).name])
 proof_pin=pin(bodies['ancestry/lifecycle-cost-successor.json']);text=read(output/GUARD).decode()+'\n# BEGIN_FRESH_ANCESTRY_COST_SUCCESSOR\ndef verify():\n import lifecycle_cost_successor\n return lifecycle_cost_successor.verify(ROOT, '+repr(I+'lifecycle-cost-successor.json')+', '+repr(proof_pin)+')\n';(output/GUARD).write_text(text)
 value=json.loads(read(output/MANIFEST));value['files']={n:w for n,w in files(output).items()if n not in{MANIFEST,*p['workflows']}};(output/MANIFEST).write_bytes(encoded(value));manifest=pin(read(output/MANIFEST))
 for n in p['workflows']:
  raw=read(output/n);old=before[MANIFEST]['sha256'].encode();need(raw.count(old)==1,'one optional source stamp; original workflow/clocks held');(output/n).write_bytes(raw.replace(old,manifest['sha256'].encode(),1))
 need(files(output)==expected,'entire public566 exact output');return dict(status='SOURCE_ONLY_EXACT566_FRESH_ANCESTRY_NATIVE_FIT_UNKNOWN',files=expected,consumer_seconds=1800,owner_seconds=6600,actual=None,native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')


CORRECTNESS_PROFILE={'bytes': 707, 'sha256': '045fc3eb5fbf788f3fbb7f54f811712e1ed68af5b21d40c3a9718332c5e6f18a'}
def correctness_inputs():
 raw=read(HERE/'correctness2400-profile.json');need(pin(raw)==CORRECTNESS_PROFILE,'whole explicit correctness profile');v=json.loads(raw)
 need(v['profile']=='correctness2400'and v['default']is False and v['original1800_fit']=='FAILED_NOT_RECLASSIFIED','separate correctness profile; original failed budget not reclassified')
 bodies={n:read(HERE/n)for n in v['support']}
 need(all(pin(bodies[n])==row for n,row in v['support'].items()),'whole correctness support before output')
 p=json.loads(bodies['correctness2400/correctness2400-successor.json']);expected=json.loads(bodies['correctness2400/source568.json'])
 need(len(p['before'])==566 and len(expected)==568 and p['budgets']==dict(consumer=2400,owner=6600,transaction=90,fixture=100,cleanup=60),'exact new full correctness bounds')
 return p,expected,bodies

def correctness(output,before):
 p,expected,bodies=correctness_inputs();need(p['before']==before and files(output)==before,'entire original566 before correctness2400')
 for n,edits in p['edits'].items():
  text=read(output/n).decode()
  for old,new in edits:need(text.count(old)==1,'one exact explicit budget/source test seam');text=text.replace(old,new,1)
  (output/n).write_text(text)
 for n in p['added']:(output/n).write_bytes(bodies['correctness2400/'+Path(n).name])
 raw=bodies['correctness2400/correctness2400-successor.json'];text=read(output/GUARD).decode()+'\n# BEGIN_CORRECTNESS2400_PROFILE\ndef verify():\n import budget_successor\n return budget_successor.verify(ROOT, '+repr(I+'correctness2400-successor.json')+', '+repr(pin(raw))+')\n';(output/GUARD).write_text(text)
 value=json.loads(read(output/MANIFEST));value['files']={n:row for n,row in files(output).items()if n not in{MANIFEST,*p['workflows']}};(output/MANIFEST).write_bytes(encoded(value));manifest=pin(read(output/MANIFEST))
 for n in p['workflows']:
  raw=read(output/n);old=before[MANIFEST]['sha256'].encode();need(raw.count(old)==1,'one explicit profile source stamp; all outer clocks held');(output/n).write_bytes(raw.replace(old,manifest['sha256'].encode(),1))
 need(files(output)==expected,'whole exact published568 correctness output')
 return dict(status='SOURCE_ONLY_EXACT568_CORRECTNESS2400_UNQUALIFIED',files=expected,consumer_seconds=2400,owner_seconds=6600,original1800_fit='FAILED_NOT_RECLASSIFIED',performance='NOT_CLAIMED',actual=None,native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')


LAYERED_PROFILE={'bytes': 736, 'sha256': 'be4af3c23667735fc81660bbf8ce28ea00aaefc914edd56a297f78bebd88ef62'}
def layered_inputs():
 raw=read(HERE/'layered4200-profile.json');need(pin(raw)==LAYERED_PROFILE,'whole explicit layered4200 profile');v=json.loads(raw)
 need(v['profile']=='layered4200'and v['default']is False and v['actual']is None and v['original1800_fit']==v['original2400_fit']=='FAILED_NOT_RECLASSIFIED','separate layered correctness; earlier fits remain failed')
 bodies={n:read(HERE/n)for n in v['support']};need(all(pin(bodies[n])==row for n,row in v['support'].items()),'whole layered4200 support before output')
 p=json.loads(bodies['layered4200/layered4200-successor.json']);expected=json.loads(bodies['layered4200/source568.json'])
 need(len(p['before'])==566 and len(expected)==568 and p['budgets']==dict(consumer=4200,component=2400,owner=6600,transaction=90,fixture=100,cleanup=60),'exact additive4200/2400/6600 bounds')
 return p,expected,bodies

def layered(output,before):
 p,expected,bodies=layered_inputs();need(p['before']==before and files(output)==before,'entire exact566 before layered4200')
 for n,edits in p['edits'].items():
  text=read(output/n).decode()
  for old,new in edits:need(text.count(old)==1,'one exact layered budget/source seam');text=text.replace(old,new,1)
  back=text
  for old,new in reversed(edits):need(back.count(new)==1,'one full layered inverse');back=back.replace(new,old,1)
  need(pin(back.encode())==before[n],'whole original566 actor/test inverse');(output/n).write_text(text)
 for n in p['added']:(output/n).write_bytes(bodies['layered4200/'+Path(n).name])
 proof=bodies['layered4200/layered4200-successor.json'];text=read(output/GUARD).decode()+'\n# BEGIN_LAYERED4200_PROFILE\ndef verify():\n import budget_successor\n return budget_successor.verify(ROOT, '+repr(I+'layered4200-successor.json')+', '+repr(pin(proof))+')\n';(output/GUARD).write_text(text)
 value=json.loads(read(output/MANIFEST));value['files']={n:r for n,r in files(output).items()if n not in{MANIFEST,*p['workflows']}};(output/MANIFEST).write_bytes(encoded(value));manifest=pin(read(output/MANIFEST))
 for n in p['workflows']:
  raw=read(output/n);old=before[MANIFEST]['sha256'].encode();need(raw.count(old)==1,'one layered stamp with all outer workflow clocks held');(output/n).write_bytes(raw.replace(old,manifest['sha256'].encode(),1))
 need(files(output)==expected,'whole exact public568 layered4200 output')
 return dict(status='SOURCE_ONLY_EXACT568_LAYERED4200_UNQUALIFIED',files=expected,consumer_seconds=4200,component_seconds=2400,owner_seconds=6600,original1800_fit='FAILED_NOT_RECLASSIFIED',original2400_fit='FAILED_NOT_RECLASSIFIED',performance='NOT_CLAIMED',actual=None,native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

SIXCAP_PROFILE={'bytes': 942, 'sha256': '07e025a98cd46fb6f31a334c1aee62f4ca2f382cd46ea807381d4c574c3e79db'}

def sixcap_inputs():
 raw=read(HERE/'sixcap840-profile.json');need(pin(raw)==SIXCAP_PROFILE,'whole explicit sixcap840 profile');v=json.loads(raw)
 need(v['profile']=='sixcap840' and v['default']is False and v['actual']is None,'source-only opt-in sixcap profile')
 bodies={n:read(HERE/n)for n in v['support']};need(all(pin(bodies[n])==w for n,w in v['support'].items()),'whole sixcap support before output')
 p=json.loads(bodies['sixcap840/sixcap-successor.json']);expected=json.loads(bodies['sixcap840/source840.json'])
 need(len(p['before'])==838 and len(expected)==840 and p['publication']['source']==v['source_before'] and len(p['before_bodies'])==5 and len(p['added'])==2,'exact genuine838 to840 inverse')
 return v,p,expected,bodies

def emit_sixcap(source,output):
 v,p,expected,support=sixcap_inputs();source=ordinary(source);output=ordinary(output)
 need(files(source)==p['before'],'entire genuine838 before any output');need(not output.exists()and output.parent.is_dir()and not output.is_relative_to(source)and not source.is_relative_to(output),'fresh separate source-only output')
 bodies={n:read(source/n)for n in p['before']}
 for n,b64 in p['before_bodies'].items():need(base64.b64decode(b64,validate=True)==bodies[n],'whole exact original body')
 # Exact source-owned constants, parsed as literals without executing carrier code.
 tree=__import__('ast').parse(support['sixcap840/sixcap_successor.py']);constants={n.targets[0].id:__import__('ast').literal_eval(n.value)for n in tree.body if isinstance(n,__import__('ast').Assign)and len(n.targets)==1 and isinstance(n.targets[0],__import__('ast').Name)and n.targets[0].id in('MARKER','COMPONENT','OLD','NEW')}
 name=constants['COMPONENT'];raw=bodies[name];need(raw.count(constants['OLD'].encode())==1,'one exact existing native API binding');bodies[name]=raw.replace(constants['OLD'].encode(),constants['NEW'].encode(),1)
 for n in p['added']:bodies[n]=support['sixcap840/'+Path(n).name]
 proof=I+'sixcap-successor.json';footer='def verify():\n import sixcap_successor\n return sixcap_successor.verify(ROOT, '+repr(proof)+', '+repr(pin(bodies[proof]))+')\n';bodies[GUARD]+=constants['MARKER'].encode()+footer.encode()
 mf=json.loads(bodies[MANIFEST]);mf['files']={n:pin(b)for n,b in bodies.items()if n not in{MANIFEST,*p['workflows']}};bodies[MANIFEST]=encoded(mf)
 for n in p['workflows']:
  old=p['before'][MANIFEST]['sha256'].encode();need(bodies[n].count(old)==1,'one source stamp; all clocks held');bodies[n]=bodies[n].replace(old,pin(bodies[MANIFEST])['sha256'].encode(),1)
 need({n:pin(b)for n,b in bodies.items()}==expected and files(source)==p['before'],'entire exact840 validated before first write')
 output.mkdir()
 for n,b in bodies.items():q=output/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
 need(files(output)==expected,'whole published840 output')
 return dict(status='SOURCE_ONLY_EXACT840_EXISTING_SIXCAP_API_UNQUALIFIED',files=expected,source=v['source_after'],ref=v['ref_after'],actual=None,native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--profile',choices=('fresh_descriptor563','fresh_ancestry566','correctness2400','layered4200','sixcap840','installed_codec842','apps16_849','apps16_849_unbound','apps16_vmtest3600','apps16_vmtest3600_unbound'),default='fresh_descriptor563');parser.add_argument('--authorization',type=Path,required=True);parser.add_argument('--apps16-carrier',type=Path);parser.add_argument('--apps16-record',type=Path);parser.add_argument('--apps16-current606-record',type=Path);a=parser.parse_args();authorization=ordinary(a.authorization);need(not authorization.exists()and authorization.parent.is_dir(),'fresh output authorization');
 if a.profile in('apps16_vmtest3600','apps16_vmtest3600_unbound'):
  import importlib.util
  spec=importlib.util.spec_from_file_location('_maintained_apps16_vmtest3600',HERE/'apps16_vmtest3600.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);result=module.emit(a.source,a.output,authorization,a.profile.endswith('_unbound'))
 elif a.profile in('apps16_849','apps16_849_unbound'):
  import importlib.util
  spec=importlib.util.spec_from_file_location('_maintained_apps16_849',HERE/'apps16_849.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);result=module.emit(a.source,a.output,authorization,a.apps16_carrier,a.apps16_record,a.apps16_current606_record,a.profile.endswith('_unbound'))
 elif a.profile=='installed_codec842':
  import importlib.util
  spec=importlib.util.spec_from_file_location('_maintained_installed_codec842',HERE/'installed_codec842.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);result=module.emit(a.source,a.output,authorization=authorization)
 else:result=emit_sixcap(a.source,a.output)if a.profile=='sixcap840'else emit(a.source,a.output,a.profile)
 with authorization.open('xb')as stream:stream.write(encoded(result))
