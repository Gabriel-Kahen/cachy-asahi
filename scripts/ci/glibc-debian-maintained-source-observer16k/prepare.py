#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Closed public maintained source-only16K route; no lifecycle result credit."""
import argparse,ast,hashlib,importlib.util,json,os,shutil,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROUTE='scripts/ci/glibc-debian-maintained-source-observer16k'
PARENT='scripts/ci/glibc-debian-maintained-public-installed16k'
NORMAL='scripts/ci/glibc-debian-maintained-installed16k'
NS='/debian-maintained-source-observer16k'
DONE='SOURCE_OBSERVATION_ONLY_DIAGNOSTIC_COMPLETED_NO_ACCEPTANCE'
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(p):
 need(p.is_file() and p.stat().st_nlink==1 and not any(q.is_symlink() for q in (p,*p.parents)) and p.stat().st_size<=16*1024**2,'ordinary finite source');return p.read_bytes()
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def source(root):
 v=json.loads(read(HERE/'source-pins.json'))
 for name,row in v['files'].items():need(pin(read(root/name))==row,'exact diagnostic source differs: '+name)
 return v

def one(text,before,after):
 need(text.count(before)==1,'one diagnostic adaptation anchor: '+before[:80]);return text.replace(before,after)
def replace_function(text,name,replacement):
 node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name);return one(text,ast.get_source_segment(text,node),replacement)
def parent(root):return load('source_diagnostic_parent',root/PARENT/'prepare.py')
def preflight(root,inputs,env):source(root);return parent(root).preflight(root,inputs,env)

def adapt(output):
 target=output/ROUTE;need(not target.exists(),'fresh separate diagnostic lane');shutil.copytree(output/NORMAL,target)
 for name in ('contract.py','prepare.py','guest.py','run.py','export.py','sandbox.py','scrub.py','support.py'):
  text=read(target/name).decode().replace('/debian-maintained-installed16k',NS).replace('init-debian-maintained-installed16k','init-debian-maintained-source-observer16k')
  if name=='contract.py':
   text=text.replace("LANE='"+NORMAL+"'","LANE='"+ROUTE+"'").replace('org.cachy-asahi.debian-maintained-installed16k','org.cachy-asahi.debian-maintained-source-observer16k').replace('PASS_DEBIAN_MAINTAINED_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY',DONE)
  if name=='prepare.py':
   text=one(text,"'debian-maintained-installed16k'","'debian-maintained-source-observer16k'") if text.count("'debian-maintained-installed16k'")==1 else text.replace("'debian-maintained-installed16k'","'debian-maintained-source-observer16k'")
   text=text.replace("'debian-maintained-installed16k/","'debian-maintained-source-observer16k/")
   text=one(text,NS+'/guest.py',NS+'/diagnostic_boot.py')
   text=one(text,"('guest.py','contract.py','sandbox.py')","('guest.py','contract.py','sandbox.py','observer_progress.py','source_diagnostic.py','diagnostic_boot.py','protocol.py')")
  if name=='run.py':
   text=one(text,'caa_debian_maintained_installed16k=1','caa_debian_maintained_installed16k=1 caa_gnu_source_observer_only=1')
   text=replace_function(text,'protocol',"def protocol(raw,selection):\n    return C.load('source_only_protocol',C.HERE/'protocol.py').protocol(C,raw,selection)")
   text=one(text,"selection=dict(source_sha=owner['source_sha'],","selection=dict(diagnostic_route='SOURCE_OBSERVATION_ONLY_600S_NO_ACCEPTANCE',source_sha=owner['source_sha'],")
   text=one(text,'seconds=10800,cap=16*1024**2','seconds=900,cap=16*1024**2')
   text=text.replace('caa-debian-maintained-installed16k-','caa-debian-maintained-source-observer16k-')
   text=one(text,"report=dict(status='FAIL',source_sha=","report=dict(status='FAIL',diagnostic_route='SOURCE_OBSERVATION_ONLY_600S_NO_ACCEPTANCE',ALPM_installation='NOT_RUN',normal_lifecycle='NOT_RUN',QEMU_seconds=900,subject_seconds=600,source_sha=")
  if name=='export.py':
   text=one(text,"row['time_limit']==10800","row['time_limit']==900")
   text=one(text,"if name=='result.json':entry['projection']=diagnostic_projection(raw)","if name=='result.json':\n                protocol=C.load('source_only_failure_protocol',C.HERE/'protocol.py');value=protocol.subject(C.decode(raw),selection);entry['projection']={k:value[k] for k in ('status','acceptance','complete','nodes','source_nodes_sha256','capabilities_sha256','ALPM','normal_lifecycle','hardware','release')}")
   text=one(text,"C.need(len(files)<=256 and sum(r['bytes'] for r in files.values())<=512*1024**2,'bounded export manifest')","C.need(set(files)=={'result.json','isolation.json','pristine-guest-progress.log'} and sum(r['bytes'] for r in files.values())<=3*65536 and all(type(r['bytes']) is int and 0<r['bytes']<=65536 for r in files.values()),'fixed bounded diagnostic export manifest')")
   old="C.need(re.fullmatch(r'(result\\.json|isolation\\.json|command-[0-9]{3}\\.(stdout|stderr)|(pristine|modified)-[a-z0-9-]+(-root\\.json\\.gz|\\.log))',name),'closed debugfs filename')"
   text=one(text,old,"C.need(name in ('result.json','isolation.json','pristine-guest-progress.log'),'fixed diagnostic debugfs filename')")
  ast.parse(text);(target/name).write_text(text)
 # Logger extension is exactly the frozen observer packet, with namespace identity only.
 text=read(HERE/'logger_guest.py').decode().replace('/installed16k',NS).replace('caa_gnu_installed16k=1','caa_debian_maintained_installed16k=1').replace('GNU_INSTALLED16K','DEBIAN_MAINTAINED_SOURCE_OBSERVER16K')
 (target/'guest.py').write_text(text)
 for name in ('observer_progress.py','source_diagnostic.py','diagnostic_boot.py','protocol.py'):
  text=read(HERE/name).decode()
  if name=='source_diagnostic.py':text=text.replace('/installed16k',NS).replace('caa_gnu_installed16k=1','caa_debian_maintained_installed16k=1').replace('GNU_INSTALLED16K_PROGRESS','DEBIAN_MAINTAINED_SOURCE_OBSERVER16K_PROGRESS')
  ast.parse(text);(target/name).write_text(text)
 # Original normal lane remains byte-exact and present in the generated source.
 deps=json.loads(read(target/'dependencies.json'));own={p.relative_to(output).as_posix():pin(read(p)) for p in target.iterdir() if p.is_file() and p.name!='source-manifest.json'}
 (target/'source-manifest.json').write_bytes(encoded(dict(schema_version=1,files=own)))
 sys.path.insert(0,str(target));C=load('source_diagnostic_generated_contract',target/'contract.py');C.check_source(output);C.gate(target/'prerequisites')
 return dict(status='BOUND_SOURCE_ONLY_DIAGNOSTIC_ROUTE_NOT_EXECUTED',scope='COMPLETE_ORIGINAL574_SOURCE_OBSERVATION_ONLY',QEMU_seconds=900,child_seconds=600,ALPM='NOT_RUN',normal_lifecycle='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',files={p.relative_to(output).as_posix():pin(read(p)) for p in output.rglob('*') if p.is_file()})

def assemble(root,component,output,decision_roots,inputs,env,public):
 preflight(root,inputs,env);parent(root).assemble(root,component,output,decision_roots,inputs,env,public)
 result=adapt(output);(public/'diagnostic-adaptation.json').write_bytes(encoded(result));v={p.name:pin(read(p)) for p in public.iterdir() if p.name!='retention.json'}
 need(len(v)==7 and sum(r['bytes'] for r in v.values())<=512*1024,'bounded diagnostic wiring metadata');(public/'retention.json').write_bytes(encoded(dict(schema_version=1,status='BOUNDED_WIRING_METADATA_ONLY',files=v,bytes=sum(r['bytes'] for r in v.values()))));return result
def public_check(public):
 v=json.loads(read(public/'retention.json'));need(v['status']=='BOUNDED_WIRING_METADATA_ONLY' and len(v['files'])==7 and v['bytes']==sum(r['bytes'] for r in v['files'].values())<=512*1024,'bounded seven diagnostic wiring metadata')
 need({p.name for p in public.iterdir()}==set(v['files'])|{'retention.json'},'closed diagnostic wiring export')
 for name,row in v['files'].items():need('/' not in name and name not in ('.','..') and pin(read(public/name))==row,'exact diagnostic wiring bytes')
 return v
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('preflight','assemble','native-source','export'));p.add_argument('--workspace',type=Path,required=True);p.add_argument('--component',type=Path);p.add_argument('--output',type=Path);p.add_argument('--public',type=Path);p.add_argument('--native-decision-root',type=Path);p.add_argument('--normal-decision-root',type=Path);a=p.parse_args();inputs={k:json.loads(os.environ.get(k.upper()+'_DECISION','null')) for k in ('native_lifecycle','system16k')}
 if a.action=='preflight':
  v=preflight(a.workspace,inputs,os.environ)
  with open(os.environ['GITHUB_OUTPUT'],'a') as f:
   for k,r in v['binding'].items():f.write(k+'_ref='+r['ref']+'\n')
   f.write('native_component_ref='+parent(a.workspace).COMPONENT+'\n')
 elif a.action=='assemble':v=assemble(a.workspace,a.component,a.output,dict(native_lifecycle=a.native_decision_root,system16k=a.normal_decision_root),inputs,os.environ,a.public)
 elif a.action=='native-source':source(a.workspace);v=parent(a.workspace).native_source(a.workspace,a.component,a.output,inputs,os.environ)
 else:
  source(a.workspace);v=public_check(a.public)
 print(json.dumps(v,sort_keys=True))
