#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite caa3 next-phase packet conversion and source-only native CI wiring."""
import argparse,hashlib,importlib.util,json,os,re,shutil,sys,tempfile,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
STAGE='scripts/ci/glibc-debian-maintained-staged-packet/prepare.py'
EMITTER='scripts/ci/glibc-debian-maintained-lifecycle/adapter.py'
NATIVE='scripts/ci/glibc-debian-maintained-provider-lifecycle'
PACKET_REF='132aec86c0946f6c7b7a79c46e1a9ccaf91021e3'
INDEX=dict(bytes=5662,sha256='a8e3317cabb3fe914a6b3898b2bfbc900905c3823495f15166c419564f7e4956')
ARCHIVE='a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9'
MiB=1024**2

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod;spec.loader.exec_module(mod);return mod

def source(repo):
 # All imports below are pinned trusted canonical pure/emission helpers.
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files']
 for name,row in rows.items():
  p=repo/name;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<=2*MiB and pin(p.read_bytes())==row,'exact next-phase helper: '+name)
 return rows

def helpers(repo):
 rows=source(repo);P=load('next_stage_packet',repo/STAGE);pure,pins=P.helpers(repo);return P,pure,pins,rows

def private(value,G):
 G.identity(value.get('candidate'))
 need(value['status']=='ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME' and value['native_source']=='78dfd3bbd85a61a84dda2dfc601796ee89edfd5f' and value['candidate_package_sha256']==ARCHIVE and value['page_size']==16384 and value['cases']==8 and value['runtime_records']==12 and value['actual_parent_child_providers']=='PASS' and value['ordered_cleanup']=='PASS' and value['hardware']=='NOT_RUN','UNBOUND: actual Root current-candidate16384/8cases/12records/providers/cleanup decision required')
 need(type(value['source_sha']) is str and re.fullmatch('[0-9a-f]{40}',value['source_sha']) and value['source_sha'] not in (value['native_source'],G.EXPECTED['source_packet_ref'],PACKET_REF) and type(value['run_id']) in (int,str) and re.fullmatch('[1-9][0-9]{0,19}',str(value['run_id'])) and str(value['run_id'])!='38994309021','actual independent runtime source/run, not package build or source carrier')
 return value

def convert(a):
 # Missing actual Root decision refuses before helper imports, large reads or outputs.
 need(a.private_decision is not None and re.fullmatch('[0-9a-f]{64}',a.private_sha256 or ''),'UNBOUND: Root private16K decision and explicit digest required')
 repo=a.repo.absolute();output=a.output.absolute();P,pure,pins,rows=helpers(repo);decision=P.read(a.private_decision,128*1024);need(pin(decision)['sha256']==a.private_sha256,'Root runtime decision digest differs');value=P.obj(decision);G=pure(repo,P.GATE);private(value,G)
 need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary packet output')
 index_raw=P.read(a.packet/'packet.json');need(pin(index_raw)==INDEX,'exact published first-stage packet index');index=P.obj(index_raw);need(index['status']=='ROOT_ACCEPTED_PROVIDER_STAGED16K_INPUTS' and len(index['files'])==21 and not {'private16k','private16k_archive_sha256'}&index.keys(),'closed first-stage-only input packet')
 actual={p.relative_to(a.packet).as_posix() for p in a.packet.rglob('*') if p.is_file()};need(actual==set(index['files'])|{'packet.json'},'exact original21+index packet closure');files={}
 for n,row in index['files'].items():data=P.read(a.packet/P.safe(n),256*MiB);P.exact(row,data);files[n]=data
 need(sum(map(len,files.values()))==47420206,'exact original first-stage payload bytes')
 owner=pure(repo,P.OWNER)
 def ref(root,row,cap=256*MiB):return owner.ref(root,row,cap)
 C=types.SimpleNamespace(SOURCE=repo,load=pure,read=P.read,ref=ref,archive=owner.archive)
 pure(repo,P.PHASE).validate(C,a.packet,index)
 normal=P.obj(files[index['probe_receipt']['path']]);receipts={side:P.obj(files[row['path']]) for side,row in normal['compile_receipts'].items()};P.normal_checks(repo,pure,a.packet,index['probes'],receipts)
 # Preserve every original payload byte/ref, including the original source-map.
 original_files=dict(index['files']);index=dict(index,status='ROOT_ACCEPTED_PROVIDER_LIFECYCLE_INPUTS',files=dict(original_files));name='acceptance/private16k.json';need(name not in files and 'lifecycle-source-map.json' not in files,'new names reserved');files[name]=decision;index['private16k']=P.reference(name,decision);index['files'][name]=pin(decision)
 mapping=encoded(dict(schema_version=1,status='CONVERTED_EXPLICIT_ROOT_CURRENT_PRIVATE16K_INPUTS_ONLY',original_packet=dict(ref=PACKET_REF,index=INDEX,files=original_files),original_source_map=P.reference('source-map.json',files['source-map.json']),private16k=index['private16k'],runtime_source=value['source_sha'],runtime_run=value['run_id'],pure_helpers=pins,scope='NATIVE_NORMAL_ALPM_LIFECYCLE_INPUTS_NOT_EXECUTED',hardware='NOT_RUN',release='NOT_ADMITTED'))
 files['lifecycle-source-map.json']=mapping;index['files']['lifecycle-source-map.json']=pin(mapping);need(len(files)==23 and sum(map(len,files.values()))<=512*MiB,'unchanged256file/512MiB packet bound')
 temporary=Path(tempfile.mkdtemp(prefix='.'+output.name+'-',dir=output.parent))
 try:
  for n,data in files.items():
   p=temporary/P.safe(n);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o755 if '/normal-clients/bin/' in n else 0o600)
  receipt=G.validate(C,temporary,index)
  P.normal_checks(repo,pure,temporary,index['probes'],receipts)
  for n,row in original_files.items():P.exact(row,P.read(temporary/n,256*MiB))
  (temporary/'packet.json').write_bytes(encoded(index));output.mkdir(mode=0o700);reservation=output.stat()
  try:os.rename(temporary,output)
  except BaseException:
   if output.exists() and output.stat().st_ino==reservation.st_ino and not any(output.iterdir()):output.rmdir()
   raise
 except BaseException:
  if temporary.exists():shutil.rmtree(temporary)
  raise
 return dict(status='CONVERTED_ROOT_ACCEPTED_CURRENT_PRIVATE16K_PACKET_INPUTS_ONLY',packet=pin(encoded(index)),files=23,original_files_preserved=21,bytes=sum(map(len,files.values())),candidate=receipt['candidate'],native='NOT_RUN',installation='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

def binding(policy,G):
 need(policy['schema_version']==1 and policy['status']=='ROOT_BOUND_IMMUTABLE_PROVIDER_PACKET','UNBOUND: future converted immutable native packet required before source output, credentials or actors');G.identity(policy.get('candidate'));p=policy['packet'];need(type(p) is dict and set(p)=={'ref','directory','index_sha256'} and re.fullmatch('[0-9a-f]{40}',p['ref']) and p['ref']!=PACKET_REF and p['directory']=='payload' and re.fullmatch('[0-9a-f]{64}',p['index_sha256']),'exact future converted packet carrier, not first-stage packet');return p

def emit(a):
 repo=a.repo.absolute();P,pure,pins,rows=helpers(repo);G=pure(repo,P.GATE);policy=P.obj(P.read(HERE/'policy.json',65536));packet=binding(policy,G);output=a.output.absolute();need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary in-checkout source output')
 need(output.parent==repo,'derived source must be a direct fresh checkout child for original Git/source proof')
 result=load('next_native_emitter',repo/EMITTER).emit(repo,output)
 for name,row in rows.items():
  p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(P.read(repo/name,2*MiB));P.exact(row,P.read(p))
 owner=output/(NATIVE+'-owner');held=P.obj(P.read(owner/'policy.json'));need(held['status']=='UNBOUND_CAA3_ACTUAL_NATIVE_PAIR_AND_PACKET' and held['packet'] is None,'emitted owner remains initially UNBOUND');before=pin(P.read(owner/'integration-manifest.json'));held.update(status='ROOT_BOUND_IMMUTABLE_PROVIDER_PACKET',packet=packet);(owner/'policy.json').write_bytes(encoded(held));manifest=P.obj(P.read(owner/'integration-manifest.json'));manifest['files'][NATIVE+'-owner/policy.json']=pin(P.read(owner/'policy.json'));(owner/'integration-manifest.json').write_bytes(encoded(manifest))
 for name,row in manifest['files'].items():P.exact(row,P.read(output/P.safe(name),16*MiB))
 receipt=dict(schema_version=1,status='DERIVED_NATIVE_SOURCE_ONLY_PACKET_ROOT_BOUND_NO_RUNTIME_CREDIT',candidate=G.EXPECTED,packet=packet,source_files=len(rows),derived_files=len(result['files']),changed_normal_owner_files=['policy.json','integration-manifest.json'],before_manifest=before,after_manifest=pin(P.read(owner/'integration-manifest.json')),owner_job=pin(P.read(owner/'job.py')),interruption_policy='UNBOUND_UNCHANGED',hardware='NOT_RUN',native='NOT_RUN',release='NOT_ADMITTED');(output/'wiring.json').write_bytes(encoded(receipt));return receipt

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('convert','emit'));p.add_argument('--repo',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--packet',type=Path);p.add_argument('--private-decision',type=Path);p.add_argument('--private-sha256');a=p.parse_args()
 try:value=convert(a) if a.action=='convert' else emit(a);code=0
 except Exception as error:value=dict(status='UNBOUND_OR_REFUSED_NO_RUNTIME_CREDIT',error=str(error)[:1024]);code=1
 print(json.dumps(value,sort_keys=True));raise SystemExit(code)
