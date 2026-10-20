#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Distinct native compile-input route over public132aec; no existing gate changes."""
import argparse,ast,hashlib,importlib.util,json,shutil,sys,tempfile,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROUTE='scripts/ci/glibc-debian-maintained-public-lifecycle'
PRIOR='scripts/ci/glibc-debian-maintained-provider-lifecycle'
NEW='scripts/ci/glibc-debian-maintained-public-provider-lifecycle'
EMITTER='scripts/ci/glibc-debian-maintained-lifecycle/adapter.py'
STAGE='scripts/ci/glibc-debian-maintained-staged-packet/prepare.py'
PACKET='132aec86c0946f6c7b7a79c46e1a9ccaf91021e3'
WF='.github/workflows/native-arm-glibc-debian-maintained-public-provider-lifecycle.yml'
INDEX=dict(bytes=5662,sha256='a8e3317cabb3fe914a6b3898b2bfbc900905c3823495f15166c419564f7e4956')
AUTH=dict(status='ROOT_AUTHORIZED_CAA3_PUBLIC_COMPILE_INPUTS_NATIVE_TRIAL',packet_source=PACKET,archive_sha256='a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9',scope='NATIVE_COMPILE_INPUTS_ONLY_NO_INSTALLATION_OR16K_ACCEPTANCE')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m

def source(repo):
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];need(len(rows)<=128,'finite protected source closure')
 for n,row in rows.items():
  p=repo/n;need(not any(q.is_symlink() for q in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<=2*1024**2 and pin(p.read_bytes())==row,'pinned source differs: '+n)
 return rows

def validate_packet(repo,root):
 source(repo);P=load('public_native_stage',repo/STAGE);pure,pins=P.helpers(repo);raw=P.read(root/'packet.json');need(pin(raw)==INDEX,'only public132aec index');value=P.obj(raw);need(len(value['files'])==21 and {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}==set(value['files'])|{'packet.json'},'exact public21+index closure')
 for n,row in value['files'].items():P.exact(row,P.read(root/P.safe(n),256*1024**2))
 owner=pure(repo,P.OWNER)
 def ref(base,row,cap=256*1024**2):
  need(value['files'].get(row['path'])=={k:row[k] for k in ('bytes','sha256')},'public reference closure');return owner.ref(base,row,cap)
 C=types.SimpleNamespace(SOURCE=repo,load=pure,read=P.read,ref=ref)
 receipt=pure(repo,P.PHASE).validate(C,root,value)
 normal=P.obj(P.read(ref(root,value['probe_receipt'])));compiles={side:P.obj(P.read(ref(root,row))) for side,row in normal['compile_receipts'].items()}
 P.normal_checks(repo,pure,root,value['probes'],compiles)
 return dict(status='VALIDATED_PUBLIC_COMPILE_INPUTS_ONLY_NOT_ALPM_OR16K',files=21,index=INDEX,compile_pair=receipt,normal_compiler_receipts='PASS_ORIGINAL_BOTH13_COMMAND_CHECKS')

def one(text,a,b):need(text.count(a)==1,'one public native input seam: '+a[:70]);return text.replace(a,b)
def derive_common(raw):
 text=raw.decode();tree=ast.parse(text);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='configuration')
 first=next(n for n in fn.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='private' for t in n.targets));last=next(n for n in fn.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='receipt' for t in n.targets))
 lines=text.splitlines(True);need(last.lineno-first.lineno==4,'exact four-line old private16K input gate');removed=''.join(lines[first.lineno-1:last.lineno-1]);text=one(text,removed,'')
 text=one(text,"value['status']=='ROOT_BOUND_UNSELECTED_PROVIDER_LIFECYCLE'","value['status']=='ROOT_BOUND_CAA3_PUBLIC_COMPILE_NATIVE_LIFECYCLE'")
 text=one(text,'UNBOUND provider lifecycle: Root must bind accepted private16K/new native pair first','UNBOUND public compile-input lifecycle: explicit Root source authorization required')
 text=one(text,"HERE/'candidate_gate.py').validate(sys.modules[__name__],root,value,candidate)","HERE/'public_gate.py').validate(sys.modules[__name__],root,value,candidate)")
 return text.encode(),dict(removed_private_gate=pin(removed.encode()),changed_functions=['configuration','validate_candidate_inputs'],other_functions='BYTE_IDENTICAL')

def derive_owner(raw):
 text=raw.decode();text=one(text,"LANE='"+PRIOR+"'","LANE='"+NEW+"'")
 text=one(text,"value['status']=='ROOT_ACCEPTED_PROVIDER_LIFECYCLE_INPUTS'","value['status']=='ROOT_ACCEPTED_PROVIDER_STAGED16K_INPUTS'")
 text=one(text,"for field in ('private16k','provider_pair','probe_receipt','held'):","for field in ('provider_pair','probe_receipt','held'):")
 text=one(text,"private=read(reference(directory,value['private16k']));native=","native=")
 text=one(text,"    need(private['status']=='ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME' and private['page_size']==16384 and private['cases']==8 and private['ordered_cleanup']=='PASS','Rootaccepted private actual16K before any base actor')\n",'')
 text=one(text,"private16k=packet_value['private16k'],provider_pair=","public_input_index=ref(inputs,inputs/'packet.json'),provider_pair=")
 text=one(text,"private16k_archive_sha256=read(reference(inputs,packet_value['private16k']))['candidate_package_sha256'],provider_pair_archive_sha256=","provider_pair_archive_sha256=")
 text=one(text,"status='ROOT_BOUND_UNSELECTED_PROVIDER_LIFECYCLE'","status='ROOT_BOUND_CAA3_PUBLIC_COMPILE_NATIVE_LIFECYCLE'")
 anchor="    for name,source in [('base.lock',base/'installed-packages.lock'),('producer.json',base/'report.json')]:"
 text=one(text,anchor,"    shutil.copyfile(packet_root/'packet.json',inputs/'packet.json')\n"+anchor)
 anchor="\nif __name__=='__main__':";text=one(text,anchor,"\n_packet_public_original=packet\ndef packet(workspace,root):\n    directory,value=_packet_public_original(workspace,root)\n    load('public_compile_source_route',workspace/'"+ROUTE+"/prepare.py').validate_packet(workspace,directory)\n    return directory,value\n"+anchor)
 return text.encode()

def derive(repo,output):
 rows=source(repo);need(not output.exists() and output.parent.is_dir(),'fresh output');A=load('public_native_original_emitter',repo/EMITTER)
 with tempfile.TemporaryDirectory() as td:
  original=Path(td)/'original';receipt=A.emit(repo,original);output.mkdir(mode=0o700)
  for n,row in rows.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((repo/n).read_bytes())
  for p in original.rglob('*'):
   if p.is_file():q=output/p.relative_to(original);q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(p.read_bytes())
  for folder in (PRIOR,PRIOR+'-owner'):shutil.copytree(output/folder,output/folder.replace(PRIOR,NEW))
 for p in HERE.iterdir():
  if p.is_file() and p.name in ('prepare.py','public_gate.py','policy.json','source-pins.json','test_route.py','README.md','input-interface.json'):q=output/ROUTE/p.name;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(p.read_bytes())
 workflow=HERE.parents[2]/WF
 if workflow.is_file():q=output/WF;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(workflow.read_bytes())
 lane=output/NEW;owner=output/(NEW+'-owner');common,changes=derive_common((lane/'common.py').read_bytes());(lane/'common.py').write_bytes(common);(lane/'public_gate.py').write_bytes((HERE/'public_gate.py').read_bytes());(owner/'job.py').write_bytes(derive_owner((owner/'job.py').read_bytes()))
 normal=json.loads((lane/'source-manifest.json').read_bytes());normal['files']['common.py']=pin(common);normal['files']['public_gate.py']=pin((lane/'public_gate.py').read_bytes());(lane/'source-manifest.json').write_bytes(encoded(normal))
 policy=json.loads((owner/'policy.json').read_bytes());policy['needed']='UNBOUND: explicit Root source authorization for public compile inputs; no native ALPM acceptance yet';(owner/'policy.json').write_bytes(encoded(policy))
 manifest=json.loads((owner/'integration-manifest.json').read_bytes())
 for n in rows:manifest['files'][n]=pin((output/n).read_bytes())
 for folder in (output/ROUTE,lane,owner):
  for p in folder.iterdir():
   if p.is_file() and p.name!='integration-manifest.json':manifest['files'][p.relative_to(output).as_posix()]=pin(p.read_bytes())
 if (output/WF).is_file():manifest['files'][WF]=pin((output/WF).read_bytes())
 (owner/'integration-manifest.json').write_bytes(encoded(manifest))
 for p in output.rglob('*.py'):ast.parse(p.read_bytes())
 return dict(status='DERIVED_DISTINCT_CAA3_NATIVE_PUBLIC_COMPILE_SOURCE_ONLY_UNBOUND',original_emitter_files=len(receipt['files']),source_helpers=len(rows),common=changes,output_lane=NEW,owner=NEW+'-owner',native_ALPM='NOT_RUN',private16k='NOT_REQUIRED_OR_CLAIMED',release='NOT_ADMITTED')

def emit(repo,output):
 policy=json.loads((HERE/'policy.json').read_bytes());need(policy['status']=='ROOT_BOUND_CAA3_PUBLIC_COMPILE_INPUTS_NATIVE_SOURCE' and policy['authorization']==AUTH and policy['packet']==dict(ref=PACKET,directory='payload',index_sha256=INDEX['sha256']),'UNBOUND public compile native route; Root source authorization required before output/secrets/actors')
 need(output.parent==repo and (HERE.parents[2]/WF).is_file(),'bound source must be a direct checkout child with dedicated workflow')
 value=derive(repo,output);owner=output/(NEW+'-owner');p=owner/'policy.json';v=json.loads(p.read_bytes());v.update(status='ROOT_BOUND_IMMUTABLE_PROVIDER_PACKET',packet=policy['packet']);p.write_bytes(encoded(v));m=owner/'integration-manifest.json';v=json.loads(m.read_bytes());v['files'][NEW+'-owner/policy.json']=pin(p.read_bytes());m.write_bytes(encoded(v));value['status']='ROOT_SOURCE_AUTHORIZED_CAA3_PUBLIC_COMPILE_NATIVE_TRIAL_NOT_ACCEPTANCE';return value
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('derive','emit','check-packet'));p.add_argument('--repo',type=Path,required=True);p.add_argument('--output',type=Path);p.add_argument('--packet',type=Path);a=p.parse_args()
 try:v=validate_packet(a.repo,a.packet) if a.action=='check-packet' else (emit(a.repo,a.output) if a.action=='emit' else derive(a.repo,a.output));code=0
 except Exception as e:v=dict(status='REFUSED_NO_ACTORS_OR_ACCEPTANCE',error_type=type(e).__name__,error=str(e)[:1024]);code=1
 print(json.dumps(v,sort_keys=True));raise SystemExit(code)
