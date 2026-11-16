# SPDX-License-Identifier: MIT
"""Finite same-run qualified-image/material handoff; no import-time role."""
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import ssl
import stat
import time
from urllib.parse import urljoin, urlsplit
import zipfile

MIB=1024**2;GIB=1024**3
IMAGE_CAP=12*GIB;ARTIFACT_CAP=16*GIB;DATA_CAP=4*GIB
EXPORT_SECONDS=900;IMPORT_SECONDS=1800;REQUEST_CAP=7
REPOSITORY='Gabriel-Kahen/cachy-asahi'
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
LABEL='cachy-asahi.rust199-bootstrap'
TAG='__rust_phase_file__'


def need(v,s):
 if not v:raise ValueError(s)

def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def dispatch_bytes(v):return(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def same(a,b):return encode(a)==encode(b)
def sha(v):return type(v)is str and re.fullmatch('[0-9a-f]{64}',v)is not None
def numeric(v):return type(v)is str and re.fullmatch('[1-9][0-9]{0,19}',v)is not None

def decode(raw):
 need(type(raw)is bytes and len(raw)<=4*MIB,'finite transfer JSON')
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate transfer JSON key');out[k]=v
  return out
 def invalid(_):raise ValueError('noninteger/nonfinite transfer JSON')
 value=json.loads(raw,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)
 need(type(value)is dict,'transfer JSON object');return value

def ordinary(path):
 path=Path(path);need(path.is_absolute() and '..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute transfer path');return path

def relative(name):
 need(type(name)is str and len(name)<=1024 and '\\'not in name and '\x00'not in name,'ordinary transfer member')
 path=PurePosixPath(name);need(not path.is_absolute() and all(p not in('','.','..')for p in name.split('/')),'relative transfer member without aliases');return path

def filepin(path,cap,expected=None,allow_empty=False):
 path=ordinary(path)
 with path.open('rb')as stream:
  before=os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and (0 if allow_empty else 1)<=before.st_size<=cap,'bounded ordinary single-link transfer file')
  result=dict(bytes=before.st_size,sha256=hashlib.file_digest(stream,'sha256').hexdigest(),mode=stat.S_IMODE(before.st_mode))
  key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  need(key(before)==key(os.fstat(stream.fileno()))==key(path.lstat()),'transfer input changed')
 if expected is not None:need({k:result[k]for k in('bytes','sha256')}=={k:expected[k]for k in('bytes','sha256')},'whole transfer file bytes/SHA differs')
 return result

def raw(path,cap=4*MIB):
 filepin(path,cap);return Path(path).read_bytes()

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def provider_check(dispatch,provider,phase):
 need(type(provider)is dict and type(provider.get('schema'))is int and provider['schema']==4 and provider.get('status')=='ACTUAL_PROVIDER_BINDING_ONLY' and provider.get('phase')==phase and type(provider.get('run_attempt'))is int and provider['run_attempt']==1 and provider.get('manual_dispatch')is True and provider.get('readback_required')is True and provider.get('native_acceptance')is False,'actual manual attempt1 provider binding for this phase')
 source=provider['source'];need(set(source)=={'sha','ref','run','job','map_sha256','approval'} and re.fullmatch('[0-9a-f]{40}',source['sha']) and all(numeric(source[k])for k in('run','job'))and all(sha(source[k])for k in('map_sha256','approval')),'actual finite provider selectors')
 need(all(source[k]==dispatch['source'][k]for k in('sha','ref','map_sha256','approval'))and provider['dispatch_sha256']==hashlib.sha256(dispatch_bytes(dispatch)).hexdigest(),'same exact Source/ref/map/approval/raw dispatch')
 return source

def image_owner(provider):
 s=provider['source'];binding=dict(source=s['sha'],ref=s['ref'],run=s['run'],job=s['job'],source_map_sha256=s['map_sha256'],approval=s['approval'])
 token=hashlib.sha256(encode(binding)).hexdigest()[:24]
 return dict(source=s['sha'],run=s['run'],job=s['job'],token=token,base_tag='rust199-base:'+token,tag='rust199-qualified:'+token)

def inspect_image(item,image,owner,tag=False):
 need(item['Id']==image and item['Os']=='linux' and item['Architecture']=='arm64'and not item['Config'].get('Volumes')and item['Config']['Labels'].get(LABEL)==owner['token']and item['Config']['Labels'].get(LABEL+'.source')==owner['source'],'exact immutable qualified image ID/Source/token/no anonymous volumes')
 if tag:need(owner['tag']in(item.get('RepoTags')or []),'exact owned normal-image tag')

def context(root,dispatch,provider,boot,qual):
 provider_check(dispatch,provider,'bootstrap');owner=image_owner(provider)
 need(boot['status']=='PASS_NORMAL_SIGNED_LLVM_IMAGE_DATA'and not boot.get('errors')and same(boot['owner'],owner)and same(boot.get('provider_binding'),provider),'actual PASS normal-image provenance')
 need(re.fullmatch('sha256:[0-9a-f]{64}',boot['image'])and sha(boot['rootfs_tree_sha256'])and boot.get('native_acceptance')is False,'actual immutable image/rootfs qualification with held acceptance')
 qualifier=load('rust_transfer_qualification_checks',root/'hosted/qualification.py');qualifier.validate_result(qual,provider,boot)
 return owner


class Budget:
 def __init__(self,command,seconds):self.command=command;self.deadline=min(time.monotonic()+seconds,command.deadline);self.requests=[];self.save=lambda:None
 def tick(self):
  need(not self.command.cancelled[0]and time.monotonic()<self.deadline,'transfer cancellation/deadline')
  callback=getattr(self.command,'on_tick',None)
  if callback is not None:callback()
 def remaining(self,cap):self.tick();return min(cap,self.deadline-time.monotonic())


def natural(row):return row.get('natural_exit')is True and row.get('forced_cleanup')is False and row.get('retirement')=='REAPED'and row.get('group_absent')is True and row.get('ownership_lost')is False and row.get('leader_held_until_group_inspection')is True and row.get('exit_observed_via_waitpid')is True

def call(command,argv,timeout,check=True):
 before=len(command.rows);result=command(argv,timeout=timeout,check=check)
 need(len(command.rows)==before+1 and natural(command.rows[-1]['lifecycle'])and command.rows[-1]['lifecycle'].get('exit')==result.returncode,'naturally retired owned transfer command')
 if check:need(result.returncode==0,'owned transfer command failed')
 return result

def one(command,argv,budget):
 value=decode_or_list(call(command,argv,budget.remaining(30)).stdout);need(type(value)is list and len(value)==1,'one actual daemon image');return value[0]

def decode_or_list(raw):
 need(type(raw)is bytes and len(raw)<=4*MIB,'bounded daemon metadata')
 return json.loads(raw)

def size_limit(previous,cap):
 need(min([cap]+[v for v in previous if v!=resource.RLIM_INFINITY])==cap,'inherited transfer file-size limit cannot be relaxed');return cap


def descriptors(value):
 if type(value)is dict:
  if {'bytes','sha256'}<=set(value)and('local_path'in value or 'path'in value):yield value
  else:
   for item in value.values():yield from descriptors(item)
 elif type(value)is list:
  for item in value:yield from descriptors(item)


def collect(delivered,boot,qual):
 selected={}
 for value in (delivered['materials'],delivered['files'],boot['files'],qual['files']):
  for row in descriptors(value):
   path=row.get('local_path',row.get('path'));path=str(ordinary(path));need(type(row['bytes'])is int and sha(row['sha256']),'actual typed selected file pin')
   item={k:row[k]for k in('bytes','sha256')}
   need(path not in selected or selected[path]==item,'consistent duplicate file pins');selected[path]=item
 need(1<=len(selected)<=200 and sum(r['bytes']for r in selected.values())<=DATA_CAP,'finite selected material/proof namespace')
 return selected


def rewrite(value,table,inverse=False):
 if type(value)is str:
  if not inverse and value in table:return {TAG:table[value]}
  return value
 if type(value)is dict:
  if inverse and set(value)=={TAG}:need(value[TAG]in table,'manifest file reference must be declared');return str(table[value[TAG]])
  need(inverse or set(value)!={TAG},'reserved transfer reference marker')
  return {k:rewrite(v,table,inverse)for k,v in value.items()}
 if type(value)is list:return [rewrite(v,table,inverse)for v in value]
 return value


def copy_file(source,target,row,budget):
 source=ordinary(source);target=ordinary(target);need(not target.exists(),'fresh transfer copy')
 before=filepin(source,DATA_CAP,row,allow_empty=True);h=hashlib.sha256();count=0
 with source.open('rb')as src,target.open('xb')as dst:
  while block:=src.read(MIB):budget.tick();count+=len(block);dst.write(block);h.update(block)
  dst.flush();os.fsync(dst.fileno());os.fchmod(dst.fileno(),0o444)
 need(dict(bytes=count,sha256=h.hexdigest())==row and filepin(source,DATA_CAP,row,allow_empty=True)==before,'exact readonly copied input remains stable')
 return filepin(target,DATA_CAP,row,allow_empty=True)


def export(root,work,dispatch,provider,delivered,boot,qual,command):
 root,work=ordinary(root),ordinary(work);owner=context(root,dispatch,provider,boot,qual);budget=Budget(command,EXPORT_SECONDS)
 out=work/'phase-transfer';need(not out.exists(),'fresh one-shot export');out.mkdir(mode=0o700);bundle=out/'bundle';bundle.mkdir(mode=0o700);(bundle/'inputs').mkdir(mode=0o700)
 selected=collect(delivered,boot,qual);paths={};rows={}
 for index,(path,row)in enumerate(sorted(selected.items())):
  leaf=re.sub('[^A-Za-z0-9._+-]','_',Path(path).name)[:120];name=f'inputs/{index:03d}-'+leaf
  rows[name]=copy_file(Path(path),bundle/name,row,budget);paths[path]=name
 actual=one(command,DOCKER+['image','inspect',boot['image']],budget);inspect_image(actual,boot['image'],owner,tag=True)
 image=bundle/'image.tar';previous=resource.getrlimit(resource.RLIMIT_FSIZE);cap=size_limit(previous,IMAGE_CAP)
 try:
  resource.setrlimit(resource.RLIMIT_FSIZE,(cap,previous[1]));call(command,DOCKER+['image','save','--output',str(image),boot['image']],budget.remaining(900))
 finally:resource.setrlimit(resource.RLIMIT_FSIZE,previous)
 image.chmod(0o444);rows['image.tar']=filepin(image,IMAGE_CAP)
 # Raw JSON proof bytes are copied above. Only the separate metadata envelope is relocated.
 metadata=dict(delivered=copy.deepcopy(delivered),boot=copy.deepcopy(boot),qual=copy.deepcopy(qual))
 metadata['delivered']['bootstrap']=None
 if type(metadata['delivered'].get('receipts'))is dict:metadata['delivered']['receipts']['path']=None
 manifest=dict(schema=4,status='QUALIFIED_BOOTSTRAP_PHASE_TRANSFER_DATA_ONLY',source=provider['source'],bootstrap_provider=provider,dispatch_sha256=provider['dispatch_sha256'],dispatch_raw=dispatch_bytes(dispatch).decode(),image_id=boot['image'],owner=owner,files=rows,metadata=rewrite(metadata,paths),native_acceptance=False,holds_preserved=True)
 raw_manifest=encode(manifest);need(len(raw_manifest)<=4*MIB and sum(r['bytes']for r in rows.values())+len(raw_manifest)<=ARTIFACT_CAP,'finite complete transfer manifest/logical size')
 target=bundle/'manifest.json';target.write_bytes(raw_manifest);target.chmod(0o444);manifest_sha=hashlib.sha256(raw_manifest).hexdigest();budget.tick()
 if os.environ.get('GITHUB_OUTPUT'):
  with ordinary(Path(os.environ['GITHUB_OUTPUT'])).open('a')as output:output.write('manifest_sha256='+manifest_sha+'\nbootstrap_job_id='+provider['source']['job']+'\n')
 return dict(directory=str(bundle),manifest_sha256=manifest_sha,bootstrap_job_id=provider['source']['job'],image_id=boot['image'])


def hosts(dispatch):
 value=dispatch['bootstrap']['transfer_redirect_hosts'];need(type(value)is list and 1<=len(value)<=3 and len(value)==len(set(value))and all(type(h)is str and re.fullmatch(r'[a-z0-9-]+\.blob\.core\.windows\.net',h)for h in value),'exact pregranted phase-transfer blob hosts');return set(value)

def _connection(host,timeout):return http.client.HTTPSConnection(host,timeout=timeout,context=ssl.create_default_context())

def fetch(url,target,budget,allowed,token=None,expected=None,cap=2*MIB,redirects=0):
 need(0<cap<=ARTIFACT_CAP,'phase-specific finite body cap');visited=set()
 for index in range(redirects+1):
  budget.tick();part=urlsplit(url);need(len(url)<=16384 and part.scheme=='https'and part.hostname in allowed and part.port in(None,443)and not part.username and not part.password and not part.fragment and url not in visited,'exact phase HTTPS host/no redirect loop');visited.add(url)
  need(len(budget.requests)<REQUEST_CAP,'seven-request transfer bound');row=dict(host=part.hostname,path=part.path,status=None,bytes=0);budget.requests.append(row);budget.save()
  connection=_connection(part.hostname,budget.remaining(30))
  try:
   header={'Accept-Encoding':'identity'}
   if index==0 and part.hostname=='api.github.com':need(type(token)is str and 0<len(token)<=4096 and not any(x.isspace()for x in token),'existing scoped token');header['Authorization']='Bearer '+token
   connection.request('GET',part.path+('?' + part.query if part.query else ''),headers=header);response=connection.getresponse();row['status']=response.status
   if response.status in(301,302,303,307,308):
    location=response.getheader('Location');need(location and index<redirects,'finite transfer redirect');url=urljoin(url,location);continue
   need(response.status==200 and response.getheader('Content-Encoding')in(None,'identity'),'successful identity transfer response')
   declared=response.getheader('Content-Length');need(declared is None or re.fullmatch('[0-9]+',declared)and 0<int(declared)<=cap and(expected is None or int(declared)==expected['bytes']),'exact transfer content length')
   h=hashlib.sha256();total=0
   with target.open('xb')as output:
    while block:=response.read1(min(MIB,cap+1-total)):
     budget.tick();total+=len(block);need(total<=cap,'transfer response body cap');output.write(block);h.update(block);row['bytes']=total;budget.save()
    output.flush();os.fsync(output.fileno());os.fchmod(output.fileno(),0o444)
   result=dict(bytes=total,sha256=h.hexdigest());need(total>0 and(expected is None or result=={k:expected[k]for k in('bytes','sha256')}),'whole transfer response bytes/SHA');return result
  finally:connection.close();budget.save()
 raise ValueError('transfer redirect exhaustion')


def extract(archive,out,manifest_sha,budget,materials):
 materials.zip_directory_bound(archive);headers=[];seen=set();logical=0
 with zipfile.ZipFile(archive)as z:
  infos=z.infolist();need(0<len(infos)<=256,'at most256 transfer ZIP entries')
  for info in infos:
   name=info.filename.rstrip('/')if info.is_dir()else info.filename;relative(name);need(name not in seen,'unique normalized phase member');seen.add(name)
   mode=info.external_attr>>16;kind=stat.S_IFMT(mode)
   need(not info.flag_bits&1 and info.compress_type in(zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)and kind in(0,stat.S_IFDIR,stat.S_IFREG)and(kind==0 or info.is_dir()is(kind==stat.S_IFDIR)),'ordinary unencrypted phase ZIP entries')
   logical+=info.file_size;need(0<=info.file_size<=IMAGE_CAP and logical<=ARTIFACT_CAP,'phase ZIP logical size')
   if not info.is_dir():headers.append(info)
  need('manifest.json'in seen and z.getinfo('manifest.json').file_size<=4*MIB,'one bounded manifest')
  raw_manifest=z.read('manifest.json');need(hashlib.sha256(raw_manifest).hexdigest()==manifest_sha,'needs-provided whole manifest SHA');manifest=decode(raw_manifest)
  rows=manifest['files'];need(type(rows)is dict and 1<=len(rows)<=201 and set(i.filename for i in headers)==set(rows)|{'manifest.json'},'exact complete transfer file membership')
  expected_dirs={str(p)for name in [*rows,'manifest.json']for p in relative(name).parents if str(p)!='.'}
  need({i.filename.rstrip('/')for i in infos if i.is_dir()}<=expected_dirs,'no extra transfer directory')
  need(set(rows)=={'image.tar'}|{name for name in rows if re.fullmatch(r'inputs/[0-9]{3}-[A-Za-z0-9._+-]{1,120}',name)},'only image and numbered immutable inputs')
  for name,row in rows.items():
   need(type(row)is dict and set(row)=={'bytes','sha256','mode'}and type(row['bytes'])is int and (1 if name=='image.tar'else 0)<=row['bytes']<=(IMAGE_CAP if name=='image.tar'else DATA_CAP)and type(row['mode'])is int and row['mode']==0o444 and sha(row['sha256'])and z.getinfo(name).file_size==row['bytes'],'each typed exact transfer leaf')
  need(sum(r['bytes']for n,r in rows.items()if n!='image.tar')<=DATA_CAP,'selected input aggregate cap')
  out.mkdir(mode=0o700);(out/'inputs').mkdir(mode=0o700)
  for name,row in rows.items():
   h=hashlib.sha256();total=0
   with z.open(name)as stream,(out/name).open('xb')as output:
    while block:=stream.read(MIB):budget.tick();total+=len(block);need(total<=row['bytes'],'bounded selected phase leaf');h.update(block);output.write(block)
    output.flush();os.fsync(output.fileno());os.fchmod(output.fileno(),0o444)
   need(total==row['bytes']and h.hexdigest()==row['sha256'],'complete phase leaf SHA')
  (out/'manifest.json').write_bytes(raw_manifest);(out/'manifest.json').chmod(0o444)
 return manifest


def absent(command,selector,budget):
 result=call(command,DOCKER+['image','inspect',selector],budget.remaining(30),check=False)
 need(result.returncode==1 and result.stderr.decode().strip()=='Error response from daemon: No such image: '+selector,'fresh absent immutable image/tag required before load')


def import_phase(root,work,dispatch,provider,args,command):
 root,work=ordinary(root),ordinary(work);current=provider_check(dispatch,provider,'build');budget=Budget(command,IMPORT_SECONDS);allowed={'api.github.com',*hosts(dispatch)}
 artifact_id=args.bootstrap_artifact_id;job_id=args.bootstrap_job_id;digest=args.bootstrap_artifact_sha256
 if type(digest)is str and digest.startswith('sha256:'):digest=digest[len('sha256:'):]
 need(numeric(artifact_id)and numeric(job_id)and job_id!=current['job']and sha(digest)and sha(args.bootstrap_manifest_sha256),'actual needs-provided distinct bootstrap selectors')
 out=work/'phase-import';need(not out.exists(),'fresh phase import');out.mkdir(mode=0o700);budget.save=lambda:(out/'acquisition.json').write_bytes(encode(dict(schema=4,status='FINITE_PHASE_TRANSFER_GET_DATA_ONLY',requests=budget.requests,native_acceptance=False)));budget.save();token=os.environ.get('GH_TOKEN','');base='https://api.github.com/repos/'+REPOSITORY+'/actions/'
 fetch(base+'artifacts/'+artifact_id,out/'artifact.json',budget,{'api.github.com'},token)
 artifact=decode(raw(out/'artifact.json'));need(type(artifact.get('id'))is int and str(artifact['id'])==artifact_id and artifact.get('expired')is False and type(artifact.get('size_in_bytes'))is int and 0<artifact['size_in_bytes']<=ARTIFACT_CAP,'actual unexpired bounded phase artifact')
 workflow=artifact.get('workflow_run',{});need(str(workflow.get('id'))==current['run']and workflow.get('head_sha')==current['sha']and artifact.get('name')=='rust199-qualified-transfer-v4-'+current['run']+'-1','same-run/source exact phase artifact name')
 if artifact.get('digest')is not None:need(artifact['digest']=='sha256:'+digest,'actual provider artifact digest')
 fetch(base+'jobs/'+job_id,out/'bootstrap-job.json',budget,{'api.github.com'},token)
 job=decode(raw(out/'bootstrap-job.json'));need(str(job.get('id'))==job_id and str(job.get('run_id'))==current['run']and job.get('head_sha')==current['sha']and job.get('status')=='completed'and job.get('conclusion')=='success'and job.get('name')=='rust199-bootstrap-v4','actual successful bootstrap job in same Source/run')
 fetch(base+'artifacts/'+artifact_id+'/zip',out/'artifact.zip',budget,allowed,token,dict(bytes=artifact['size_in_bytes'],sha256=digest),cap=ARTIFACT_CAP,redirects=3)
 materials=load('rust_transfer_material_helpers',root/'hosted/materials.py');bundle=out/'bundle';manifest=extract(out/'artifact.zip',bundle,args.bootstrap_manifest_sha256,budget,materials)
 need(type(manifest['schema'])is int and manifest['schema']==4 and manifest['status']=='QUALIFIED_BOOTSTRAP_PHASE_TRANSFER_DATA_ONLY'and manifest['native_acceptance']is False and manifest['holds_preserved']is True,'qualified DATA transfer scope only')
 bootstrap_provider=manifest['bootstrap_provider'];source=provider_check(dispatch,bootstrap_provider,'bootstrap')
 need(source['job']==job_id and source['run']==current['run']and manifest['source']==source and manifest['dispatch_sha256']==provider['dispatch_sha256']and manifest['dispatch_raw'].encode()==dispatch_bytes(dispatch),'bootstrap/build same exact raw Root dispatch and observed provider chain')
 table={name:bundle/name for name in manifest['files']};meta=rewrite(manifest['metadata'],table,inverse=True);delivered,boot,qual=(meta[k]for k in('delivered','boot','qual'));owner=context(root,dispatch,bootstrap_provider,boot,qual)
 need(manifest['image_id']==boot['image']and same(manifest['owner'],owner),'same qualified transferred immutable image')
 # Recheck every restored descriptor, still before the first Docker load.
 selected=collect(delivered,boot,qual)
 need(set(selected)=={str(p)for name,p in table.items()if name!='image.tar'},'all selected proof/material references exactly match copied inputs')
 for path,row in selected.items():need(filepin(Path(path),DATA_CAP,row,allow_empty=True)['mode']==0o444,'all restored input bytes/modes checked before load')
 report=dict(schema=4,status='FAIL',source=current,bootstrap_provider=bootstrap_provider,image=boot['image'],load_intent=False,image_retired_after_failure=False,requests=budget.requests)
 path=out/'import.json'
 def save():path.write_bytes(encode(report))
 save()
 try:
  absent(command,boot['image'],budget);absent(command,owner['tag'],budget)
  report['load_intent']=True;save();call(command,DOCKER+['image','load','--input',str(bundle/'image.tar')],budget.remaining(600))
  observed=one(command,DOCKER+['image','inspect',boot['image']],budget);inspect_image(observed,boot['image'],owner)
  if owner['tag']not in(observed.get('RepoTags')or []):
   # Deterministic restoration of the absent exact owned tag; never overwrite.
   absent(command,owner['tag'],budget);call(command,DOCKER+['image','tag',boot['image'],owner['tag']],budget.remaining(30))
  observed=one(command,DOCKER+['image','inspect',owner['tag']],budget);inspect_image(observed,boot['image'],owner,tag=True)
  boot['base_image']=None;boot['imported_from_bootstrap']=True;report['status']='PASS_IMPORTED_VERIFIED_BOOTSTRAP_PHASE_DATA';save()
  return dict(delivered=delivered,boot=boot,qual=qual,bootstrap_provider=bootstrap_provider)
 except BaseException:
  # Import owns recovery if load may have succeeded before the caller received boot.
  if report['load_intent']:
   previous=(command.deadline,command.cleaning,command.on_tick);command.deadline=time.monotonic()+300;command.cleaning=True;command.on_tick=None
   try:
    result=call(command,DOCKER+['image','inspect',boot['image']],30,check=False)
    if result.returncode==0:
     values=decode_or_list(result.stdout);need(type(values)is list and len(values)==1,'one exact recovery image');inspect_image(values[0],boot['image'],owner)
     call(command,DOCKER+['image','rm',boot['image']],60);missing=call(command,DOCKER+['image','inspect',boot['image']],30,check=False)
     need(missing.returncode==1 and missing.stderr.decode().strip()=='Error response from daemon: No such image: '+boot['image'],'recovered imported image absence')
    else:need(result.returncode==1 and result.stderr.decode().strip()=='Error response from daemon: No such image: '+boot['image'],'known image absence after load failure')
    report['image_retired_after_failure']=True
   except BaseException as error:report['cleanup_error']=type(error).__name__+': '+str(error)[:1024]
   finally:command.deadline,command.cleaning,command.on_tick=previous
  save();raise
