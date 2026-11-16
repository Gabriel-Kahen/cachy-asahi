# SPDX-License-Identifier: MIT
"""Finite Root-selected Rust/LLVM material DATA delivery; imports perform no role."""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import time
from urllib.parse import urljoin, urlsplit
import zipfile

MIB=1024**2;GIB=1024**3
REPOSITORY='Gabriel-Kahen/cachy-asahi'
SECONDS=1800;REQUESTS=24;RETAINED_SECONDS=500
ARTIFACT_CAPS={'llvm_original':8*GIB,'stage0_carrier':128*MIB,'root_proof_carrier':32*MIB}
PACKAGE='cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst'
STAGE0={
 'cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz':(11116188,'5784379d73ac881d15a9e67eed2882cd58c747c276221c23cdf9aff37e015ff6'),
 'rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz':(30768752,'a36f7ac98af20ef0ba6368aace0345efabbebaef7962eba99f47190fd256162d'),
 'rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz':(66413136,'00590657f2356d7163ca5ef295283523974c340fa21bb94b420ce794f29b358c')}
SOURCES={
 'rustc-1.99.0-src.tar.xz':dict(bytes=265258564,sha256='cc41916a8c84f5d9ec4f55561b44e39f43b647b133f8a6f51be9ea13c83f7036',url='https://static.rust-lang.org/dist/rustc-1.99.0-src.tar.xz'),
 'llvm-project-23.1.1.src.tar.xz':dict(bytes=179168672,sha256='ebe9be46fe8756d58c5b198ffad0fa2a766257add81a4dc52179bfacc7888ee6',url='https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.1/llvm-project-23.1.1.src.tar.xz')}
PROOFS={'llvm_signature','public_test_key','root_decision','verification_proof','reader_binding','reader_result','source_audit'}
RETAINED_PROFILE='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'


def need(value,message):
 if not value:raise ValueError(message)

def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def same(a,b):return encode(a)==encode(b)
def digest(path):
 with path.open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def pin(value):return dict(bytes=len(value),sha256=hashlib.sha256(value).hexdigest())
def sha(value):return type(value)is str and re.fullmatch('[0-9a-f]{64}',value)is not None
def number(value):return type(value)is str and re.fullmatch('[1-9][0-9]{0,19}',value)is not None

def decode(raw):
 need(type(raw)is bytes and len(raw)<=2*MIB,'bounded metadata JSON')
 def pairs(rows):
  out={}
  for key,value in rows:need(key not in out,'duplicate metadata key');out[key]=value
  return out
 def invalid(_):raise ValueError('noninteger/nonfinite metadata')
 result=json.loads(raw,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)
 need(type(result)is dict,'metadata object required');return result

def ordinary(path):
 path=Path(path);need(path.is_absolute() and '..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute material path');return path

def member(value):
 need(type(value)is str and len(value)<=1024 and '\\'not in value and '\x00'not in value,'literal archive member')
 path=PurePosixPath(value);need(not path.is_absolute() and all(x not in ('','.','..')for x in value.split('/')),'relative archive member without traversal');return path

def file_pin(row,cap):
 need(type(row)is dict and type(row.get('bytes'))is int and 0<row['bytes']<=cap and sha(row.get('sha256')),'positive bounded material bytes and whole SHA')

def validate(plan):
 need(type(plan)is dict and set(plan)=={'schema','status','holds_preserved','llvm_original','stage0_carrier','root_proof_carrier','sources'} and type(plan['schema'])is int and plan['schema']==1 and plan['status']=='ROOT_ADMITTED_FINITE_RUST_MATERIAL_DELIVERY' and plan['holds_preserved']is True and plan['sources']=='PINNED_HTTPS','complete separately admitted finite delivery plan')
 names=set();roles=set()
 for kind,cap in ARTIFACT_CAPS.items():
  row=plan[kind]
  need(type(row)is dict and set(row)=={'repository','id','run','job','source','bytes','sha256','metadata_sha256','job_metadata_sha256','redirect_hosts','members','accepted_by_root'},'complete exact artifact selectors')
  file_pin(row,cap);need(row['repository']==REPOSITORY and all(number(row[k])for k in('id','run','job')) and type(row['source'])is str and re.fullmatch('[0-9a-f]{40}',row['source']) and sha(row['metadata_sha256']) and sha(row['job_metadata_sha256']) and row['accepted_by_root']is True,'preselected same-repository artifact and Root selection required')
  hosts=row['redirect_hosts'];need(type(hosts)is list and 1<=len(hosts)<=3 and len(set(hosts))==len(hosts) and all(type(h)is str and re.fullmatch('[a-z0-9-]+\\.blob\\.core\\.windows\\.net',h)for h in hosts),'finite exact Root-selected Actions blob hosts')
  need(type(row['members'])is list and 1<=len(row['members'])<=32,'finite explicit extracted leaves')
  localroles=set();selections=set()
  for item in row['members']:
   need(type(item)is dict and set(item)=={'member','role','name','bytes','sha256','container','outer_member'},'complete member selection')
   member(item['member']);need(type(item['name'])is str and re.fullmatch('[A-Za-z0-9._+-]{1,255}',item['name']) and item['name']not in names and item['name']not in('.','..'),'unique output basename')
   names.add(item['name']);role=item['role'];need(type(role)is str and role not in roles,'unique material role');roles.add(role);localroles.add(role)
   file_pin(item,2*GIB if kind=='llvm_original' else 8*MIB if kind=='root_proof_carrier' else 128*MIB)
   need(item['container']in('ZIP','EXPORT_TAR'),'explicit zip or export-tar leaf')
   if item['container']=='ZIP':need(item['outer_member']is None,'no hidden nested container')
   else:
    outer=item['outer_member'];need(type(outer)is dict and set(outer)=={'member','bytes','sha256'},'whole nested export pin');member(outer['member']);file_pin(outer,4*GIB)
   selection=(item['container'],item['outer_member']['member']if item['outer_member']is not None else None,item['member']);need(selection not in selections,'duplicate selected archive member');selections.add(selection)
   if kind=='llvm_original':need(role=='llvm_archive' and item['name']==PACKAGE,'only exact private LLVM package from Original')
   elif kind=='stage0_carrier':
    need(item['name']in STAGE0 and role=='stage0:'+item['name'] and (item['bytes'],item['sha256'])==STAGE0[item['name']] and item['container']=='ZIP','exact retained stage0 whole-archive pins')
   else:need(role in PROOFS and item['container']=='ZIP','only explicit Root proof/signature/key leaves')
  wanted={'llvm_archive'}if kind=='llvm_original'else {'stage0:'+n for n in STAGE0}if kind=='stage0_carrier'else PROOFS
  need(localroles==wanted,'complete exact role set for '+kind)
 return plan


validate_plan=validate


class Budget:
 def __init__(self,command):self.command=command;self.deadline=time.monotonic()+SECONDS;self.requests=[];self.body_bytes=0
 def tick(self):
  need(time.monotonic()<self.deadline and not self.command.cancelled[0],'finite delivery deadline/cancellation')
  callback=getattr(self.command,'on_tick',None)
  if callback is not None:callback()
 def request(self,url,authorized):
  self.tick();need(len(self.requests)<REQUESTS,'aggregate request cap');row=dict(url=url.split('?',1)[0],authorized=authorized,status=None,bytes=0);self.requests.append(row);return row


def url_parts(url,hosts):
 need(type(url)is str and len(url)<=16384,'bounded URL');part=urlsplit(url)
 need(part.scheme=='https' and part.hostname in hosts and part.port in(None,443) and not part.username and not part.password and not part.fragment,'pinned HTTPS endpoint/host only');return part

def _connection(host,timeout):return http.client.HTTPSConnection(host,timeout=timeout,context=ssl.create_default_context())

def fetch(url,target,expected,budget,hosts,token=None,redirects=0,cap=None):
 """One logical GET, no retry. Credentials never follow an API redirect."""
 target=ordinary(target);need(not target.exists(),'fresh material output')
 maximum=expected['bytes']if expected else cap;need(type(maximum)is int and 0<maximum<=8*GIB,'finite body cap')
 start=url;response=None;connection=None;visited=set()
 for index in range(redirects+1):
  part=url_parts(url,hosts);need(url not in visited,'redirect loop/no retry');visited.add(url);authorized=token is not None and index==0 and part.hostname=='api.github.com'
  row=budget.request(url,authorized);connection=_connection(part.hostname,min(30,max(.1,budget.deadline-time.monotonic())))
  try:
   headers={'User-Agent':'cachy-asahi/rust199-source-reference-v9','Accept-Encoding':'identity','Accept':'application/vnd.github+json'if part.hostname=='api.github.com'else 'application/octet-stream'}
   if authorized:need(type(token)is str and 0<len(token)<=4096 and not any(c.isspace()for c in token),'bounded existing token');headers['Authorization']='Bearer '+token
   connection.request('GET',part.path+('?' + part.query if part.query else ''),headers=headers);response=connection.getresponse();row['status']=response.status
   if response.status in(301,302,303,307,308):
    location=response.getheader('Location');need(location and index<redirects,'redirect bound/no missing location');url=urljoin(url,location);url_parts(url,hosts);continue
   need(response.status==200 and response.getheader('Content-Encoding')in(None,'identity'),'exact successful unencoded material body')
   length=response.getheader('Content-Length');need(length is None or re.fullmatch('[0-9]+',length) and int(length)<=maximum and (expected is None or int(length)==maximum),'declared material body size')
   partial=target.with_name(target.name+'.partial');total=0;h=hashlib.sha256()
   with partial.open('xb')as stream:
    while True:
     budget.tick();block=response.read1(min(MIB,maximum+1-total))
     if not block:break
     total+=len(block);need(total<=maximum,'material body cap');stream.write(block);h.update(block);row['bytes']=total;budget.body_bytes+=len(block)
    stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o444)
   actual=dict(bytes=total,sha256=h.hexdigest());need(total>0 and (expected is None or actual=={k:expected[k]for k in('bytes','sha256')}),'whole body bytes/SHA differs')
   os.link(partial,target);partial.unlink();return actual
  finally:connection.close()
 raise ValueError('redirect exhaustion')


def artifact_metadata(row,budget,token,out):
 base='https://api.github.com/repos/'+REPOSITORY+'/actions/'
 path=out/'artifact.json';fetch(base+'artifacts/'+row['id'],path,None,budget,{'api.github.com'},token,cap=2*MIB)
 raw=path.read_bytes();need(hashlib.sha256(raw).hexdigest()==row['metadata_sha256'],'whole selected artifact metadata pin');value=decode(raw)
 workflow=value.get('workflow_run',{});need(type(value.get('id'))is int and str(value['id'])==row['id'] and value.get('expired')is False and value.get('size_in_bytes')==row['bytes'] and str(workflow.get('id'))==row['run'] and workflow.get('head_sha')==row['source'],'actual unexpired artifact/source/run/size joins')
 path=out/'job.json';fetch(base+'jobs/'+row['job'],path,None,budget,{'api.github.com'},token,cap=2*MIB)
 raw=path.read_bytes();need(hashlib.sha256(raw).hexdigest()==row['job_metadata_sha256'],'whole selected job metadata pin');job=decode(raw)
 need(type(job.get('id'))is int and type(job.get('run_id'))is int and str(job.get('id'))==row['job'] and str(job.get('run_id'))==row['run'] and job.get('head_sha')==row['source'] and job.get('status')=='completed' and job.get('conclusion')=='success','actual terminal successful selected job/source/run')


def copy_member(stream,target,row,budget):
 target=ordinary(target);need(not target.exists(),'fresh extracted leaf');h=hashlib.sha256();total=0
 with target.open('xb')as output:
  while block:=stream.read(min(MIB,row['bytes']+1-total)):
   budget.tick();total+=len(block);need(total<=row['bytes'],'extracted leaf size cap');output.write(block);h.update(block)
  output.flush();os.fsync(output.fileno());os.fchmod(output.fileno(),0o444)
 need(dict(bytes=total,sha256=h.hexdigest())=={k:row[k]for k in('bytes','sha256')},'whole extracted member bytes/SHA')
 return dict(path=str(target),local_path=str(target),name=target.name,bytes=total,sha256=h.hexdigest())


def zip_directory_bound(archive):
 # Bound the central directory before ZipFile allocates its entry table.
 size=archive.stat().st_size
 with archive.open('rb')as stream:
  stream.seek(max(0,size-65557));tail=stream.read(65557);index=tail.rfind(b'PK\x05\x06')
  need(index>=0 and index+22<=len(tail),'complete ZIP end record')
  disk,start,entries_disk,entries,cd_size,offset,comment=struct.unpack('<4H2LH',tail[index+4:index+22])
  need(disk==start==0 and index+22+comment==len(tail),'single-disk exact ZIP ending')
  if entries==65535 or cd_size==0xffffffff or offset==0xffffffff:
   absolute=size-len(tail)+index;need(absolute>=20,'ZIP64 locator');stream.seek(absolute-20);locator=stream.read(20)
   need(locator[:4]==b'PK\x06\x07','exact ZIP64 locator');disk,position,disks=struct.unpack('<LQL',locator[4:]);need(disk==0 and disks==1 and position+56<=absolute-20,'single ZIP64 record')
   stream.seek(position);record=stream.read(56);need(record[:4]==b'PK\x06\x06','ZIP64 end record')
   record_size,version_made,version_needed,disk,start,entries_disk,entries,cd_size,offset=struct.unpack('<Q2H2L4Q',record[4:])
   need(44<=record_size<=65536 and position+12+record_size==absolute-20 and disk==start==0,'bounded ZIP64 metadata')
  need(entries==entries_disk and 0<entries<=4096 and 0<cd_size<=4*MIB and offset+cd_size<=size,'finite ZIP central directory')


def extract_zip(archive,rows,target,budget):
 selected={row['member']:row for row in rows if row['container']=='ZIP'};outers={}
 for row in rows:
  if row['container']=='EXPORT_TAR':
   outer=row['outer_member'];need(outer['member']not in selected,'zip leaf/container collision')
   need(outer['member']not in outers or outers[outer['member']]==outer,'consistent nested export pin');outers[outer['member']]=outer
 result={};seen=set();logical=0;zip_directory_bound(archive)
 with zipfile.ZipFile(archive)as z:
  infos=z.infolist();need(0<len(infos)<=4096,'finite zip header count')
  for info in infos:
   budget.tick();name=info.filename.rstrip('/')if info.is_dir()else info.filename;member(name);need(name not in seen,'duplicate zip member');seen.add(name)
   mode=info.external_attr>>16;kind=stat.S_IFMT(mode)
   need(not info.flag_bits&1 and info.compress_type in(zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED) and kind in(0,stat.S_IFREG,stat.S_IFDIR) and (kind==0 or info.is_dir()is(kind==stat.S_IFDIR)),'zip encryption/compression/special-node refusal')
   need(info.file_size>=0 and info.compress_size>=0 and info.file_size<=8*GIB and info.file_size<=max(1,info.compress_size)*1000,'zip logical/ratio cap');logical+=info.file_size;need(logical<=12*GIB,'zip aggregate logical cap')
  for name,row in selected.items():
   need(name in seen and not z.getinfo(name).is_dir() and z.getinfo(name).file_size==row['bytes'],'selected exact zip leaf')
   with z.open(name)as stream:result[row['role']]=copy_member(stream,target/row['name'],row,budget)
  for index,(name,row)in enumerate(outers.items()):
   need(name in seen and z.getinfo(name).file_size==row['bytes'],'selected exact export container');tarpath=target/('export-'+str(index)+'.tar')
   with z.open(name)as stream:copy_member(stream,tarpath,row,budget)
   result.update(extract_tar(tarpath,[r for r in rows if r['container']=='EXPORT_TAR'and r['outer_member']==row],target,budget))
 return result


def bounded_tar_info():
 state={'headers':0,'ended':False}
 class Info(tarfile.TarInfo):
  @classmethod
  def fromtarfile(cls,archive):return cls._fromtarfile(archive)
  @classmethod
  def _fromtarfile(cls,archive,*,dircheck=True):
   block=archive.fileobj.read(512)
   if block==bytes(512):state['ended']=True
   else:state['headers']+=1;need(state['headers']<=4096,'raw tar header bound')
   item=cls._frombuf(block,archive.encoding,archive.errors,dircheck=dircheck)if hasattr(cls,'_frombuf')else cls.frombuf(block,archive.encoding,archive.errors)
   item.offset=archive.fileobj.tell()-512;return item._proc_member(archive)
  def _proc_pax(self,archive):need(0<=self.size<=65536,'bounded PAX metadata');return super()._proc_pax(archive)
  def _proc_gnulong(self,archive):need(0<=self.size<=65536,'bounded long-name metadata');return super()._proc_gnulong(archive)
  def _proc_sparse(self,*args):raise ValueError('sparse tar refused')
  _proc_gnusparse_00=_proc_sparse;_proc_gnusparse_01=_proc_sparse;_proc_gnusparse_10=_proc_sparse
 return Info,state


def extract_tar(archive,rows,target,budget):
 wanted={row['member']:row for row in rows};seen=set();result={};logical=0
 info,state=bounded_tar_info()
 with tarfile.open(archive,mode='r|',tarinfo=info)as t:
  for item in t:
   budget.tick();name=item.name.rstrip('/')if item.isdir()else item.name;member(name);need(name not in seen and len(seen)<4096,'finite unique export members');seen.add(name)
   need(item.isfile()or item.isdir(),'ordinary export files/directories only');logical+=item.size;need(0<=item.size<=2*GIB and logical<=4*GIB,'finite export logical bytes')
   if name in wanted:
    row=wanted[name];need(item.isfile()and item.size==row['bytes'],'selected export member size/type')
    with t.extractfile(item)as stream:result[row['role']]=copy_member(stream,target/row['name'],row,budget)
   t.members.clear()
  tail=0
  while block:=t.fileobj.read(65536):
   budget.tick();tail+=len(block);need(not any(block)and tail<=16*MIB,'bounded zero-only tar tail')
  need(state['ended']and tail>=512 and t.fileobj.tell()%512==0,'complete export tar termination')
 need(set(result)=={r['role']for r in rows},'complete selected export namespace');return result


def acquire(root,work,plan,command,token):
 """Caller validates Root source/resource/material authority before this API."""
 validate(plan);root=ordinary(root);work=ordinary(work);out=work/'material-delivery';need(not out.exists(),'one fresh delivery attempt');out.mkdir(mode=0o700)
 budget=Budget(command);receipt=dict(status='STARTED_NO_ACCEPTANCE',requests=budget.requests,files={},holds_preserved=True)
 def save():(out/'acquisition.json').write_bytes(encode(dict(receipt,body_bytes=budget.body_bytes)))
 save();files={}
 try:
  for role in ARTIFACT_CAPS:
   row=plan[role];folder=out/role;folder.mkdir(mode=0o700);artifact_metadata(row,budget,token,folder)
   path=folder/'artifact.zip';url='https://api.github.com/repos/'+REPOSITORY+'/actions/artifacts/'+row['id']+'/zip'
   fetch(url,path,row,budget,{'api.github.com',*row['redirect_hosts']},token,redirects=3)
   files.update(extract_zip(path,row['members'],folder,budget));save()
  material=[]
  for name,(size,checksum)in STAGE0.items():
   row=files['stage0:'+name];material.append(dict(name=name,local_path=row['local_path'],bytes=size,sha256=checksum,url='https://static.rust-lang.org/dist/2026-08-20/'+name,transport='LOCAL_READONLY'))
  for name,row in SOURCES.items():
   hosts={'static.rust-lang.org'}if name.startswith('rustc-')else {'github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'}
   path=out/name;fetch(row['url'],path,row,budget,hosts,redirects=2)
   material.append(dict(name=name,local_path=str(path),**row,transport='LOCAL_READONLY'))
  receipt.update(status='ACQUIRED_PINNED_MATERIAL_DATA_ONLY',files=files);save()
  llvm={key:files[role]for key,role in [('archive','llvm_archive'),('signature','llvm_signature'),('public_test_key','public_test_key'),('root_decision','root_decision'),('verification_proof','verification_proof'),('source_audit','source_audit')]}
  llvm['reader']={key:files['reader_'+key]for key in('binding','result')}
  return dict(status=receipt['status'],materials=material,files=files,llvm=llvm,receipts=dict(path=str(out/'acquisition.json'),sha256=digest(out/'acquisition.json'),requests=len(budget.requests),body_bytes=budget.body_bytes),holds_preserved=True)
 except BaseException as error:
  receipt.update(status='FAIL_NO_RETRY_NO_ACCEPTANCE',error=type(error).__name__+': '+str(error)[:1024]);save();raise


def retained(root,work,command):
 """Owned original200 retained transport, after separately seeded private/public cache."""
 root=ordinary(root);work=ordinary(work);temp=ordinary(Path(os.environ['RUNNER_TEMP']));original=root/'original'
 profile=original/'bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json';raw=profile.read_bytes();need(hashlib.sha256(raw).hexdigest()==RETAINED_PROFILE,'whole original carrier profile')
 before_path=sys.path.copy();before_modules=sys.modules.copy();previous_run=subprocess.run;primitive=None;previous_primitive=None
 deadline=min(time.monotonic()+RETAINED_SECONDS,getattr(command,'deadline',float('inf')))
 def load(name,path):
  spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
 try:
  sys.modules.pop('common',None);sys.path[:0]=[str(original/'native')]
  transport=load('rust_original_retained_transport',original/'native/retained_transport.py')
  owner=load('rust_original_retained_owner',original/'bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py')
  primitive=owner.owned_child();previous_primitive=primitive.run
  def supervised(argv,**kwargs):
   prior=kwargs.get('on_tick')
   def tick():
    if prior is not None:prior()
    need(not command.cancelled[0]and time.monotonic()<deadline,'retained delivery cancellation/deadline')
    callback=getattr(command,'on_tick',None)
    if callback is not None:callback()
   tick();return previous_primitive(argv,**dict(kwargs,on_tick=tick))
  primitive.run=supervised;subprocess.run=owner.owned_subprocess_run
  need(not command.cancelled[0],'Root cancellation before retained DATA transport')
  result=transport.deliver(original,temp/'pgo-hosted-retained',work/'retained-transport',raw,RETAINED_PROFILE)
  need(result['status']=='PASS_EXACT_RETAINED_GIT_DATA_ONLY'and not command.cancelled[0],'exact original retained transport completed')
  (work/'retained-transport.json').write_bytes(encode(result));return dict(cache=str(temp/'alarm-cache'),carrier=str(temp/'pgo-hosted-retained'),receipt=result)
 finally:
  if primitive is not None:primitive.run=previous_primitive
  subprocess.run=previous_run;sys.path[:]=before_path
  for name,module in list(sys.modules.items()):
   path=getattr(module,'__file__',None)
   if name.startswith('rust_original_retained_')or path and Path(path).is_relative_to(original):
    if name in before_modules:sys.modules[name]=before_modules[name]
    else:sys.modules.pop(name,None)
  if 'common'in before_modules:sys.modules['common']=before_modules['common']
  else:sys.modules.pop('common',None)
