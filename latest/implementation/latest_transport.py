#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Durable original framed bytes; transport completeness never grants acceptance."""
import argparse,base64,gzip,hashlib,io,json,os,re,stat,sys,tarfile,time,types,zipfile
from pathlib import Path
M=1024**2;PACKET=4*M;FILE=32*M;TOTAL=65*M;STEP_CAP=100*M;MAX_FILES=1100
ENCODER=dict(bytes=1708,sha256='a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5')
RECONSTRUCTION='concatenate each file chunks in listed order and verify full bytes and sha256'
SCOPE='accepted public pairs and native604 metadata lifecycle; hardware NOT_RUN'
PURPOSE='SOURCE_OWNED_NATIVE_FRAMED_TRANSPORT_V1'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def obj(raw):
 def pairs(rows):
  value={}
  for key,val in rows:need(key not in value,'duplicate JSON key');value[key]=val
  return value
 value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'));need(type(value)is dict,'JSON object');return value
def safe(name):
 need(type(name)is str and name and not name.startswith('/')and '\\'not in name and all(32<=ord(c)<127 for c in name)and all(p not in('','.','..')for p in name.split('/')),'safe relative name');return name
def read(path,cap):
 path=Path(path).absolute();need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary noalias path');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink ordinary input');raw=bytearray()
  while len(raw)<a.st_size:
   chunk=os.read(fd,min(M,a.st_size-len(raw)));need(bool(chunk),'complete input read');raw.extend(chunk)
  ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(ident(a)==ident(os.fstat(fd))==ident(path.lstat()),'stable input identity');return bytes(raw)
 finally:os.close(fd)
def write(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
def policy(value):
 need(set(value)=={'purpose','repository','workflow_name','workflow_path','job','step_id','step_name','nonce_path','nonce_field'}and value['purpose']==PURPOSE,'finite source-owned policy')
 need(value['repository']=='Gabriel-Kahen/cachy-asahi'and value['workflow_path']=='.github/workflows/native-arm-build.yml'and value['job']=='native'and re.fullmatch('[a-z0-9_-]{1,64}',value['step_id'])and re.fullmatch('[A-Za-z0-9 -]{1,160}',value['step_name'])and re.fullmatch('[a-z0-9-]{1,128}',value['workflow_name']),'fixed repository/workflow/job/step')
 safe(value['nonce_path']);need(value['nonce_path']=='plan/bridge-selection.json'and value['nonce_field']=='nonce','exact indexed original owner nonce operand');return value
def context(p,env):
 p=policy(p);source=env.get('GITHUB_SHA');run=env.get('GITHUB_RUN_ID');attempt=env.get('GITHUB_RUN_ATTEMPT')
 need(env.get('GITHUB_ACTIONS')=='true'and env.get('GITHUB_REPOSITORY')==p['repository']and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and env.get('GITHUB_JOB')==p['job']and env.get('GITHUB_WORKFLOW')==p['workflow_name']and env.get('RUNNER_ARCH')=='ARM64','genuine native workflow context required')
 need(re.fullmatch('[a-f0-9]{40}',source or'')and source==env.get('CAA_EVIDENCE_SOURCE_SHA')==env.get('CAA_EVIDENCE_WORKFLOW_SHA')and re.fullmatch('[1-9][0-9]{0,19}',run or'')and attempt=='1','exact head/workflow/source and first attempt')
 return dict(repository=p['repository'],run_id=int(run),attempt=1,head_sha=source,workflow_path=p['workflow_path'],workflow_name=p['workflow_name'],job=p['job'],step_id=p['step_id'],step_name=p['step_name'])
def decode_frame(label,raw):
 need(re.fullmatch('part-[0-9]{4}',label)and 0<len(raw)<=8*M,'finite compressed original frame')
 with gzip.GzipFile(fileobj=io.BytesIO(raw))as stream:tarraw=stream.read(16*M+1)
 need(len(tarraw)<=16*M,'original inflation cap');values={}
 with tarfile.open(fileobj=io.BytesIO(tarraw),mode='r:')as archive:
  for row in archive:
   prefix=label+'/';need(row.name.startswith(prefix)and row.isfile()and not row.sparse and row.size<=PACKET and len(values)<MAX_FILES,'ordinary bounded original tar member')
   name=safe(row.name[len(prefix):]);need('/'not in name and name not in values and(name=='retention.json'if label=='part-0000'else re.fullmatch(r'chunk-[0-9]{4}\.bin',name)),'closed original frame member');value=archive.extractfile(row).read(PACKET+1);need(len(value)==row.size,'complete original tar member');values[name]=value
 need(values and sum(map(len,values.values()))<=PACKET,'original packet raw cap');return values
def decode_step(raw):
 need(0<len(raw)<=STEP_CAP,'complete bounded original framed stdout');lines=raw.decode('ascii','strict').splitlines();packets={};frames={};at=0;decoded_bytes=0
 while at<len(lines):
  match=re.fullmatch(r'CACHY_ASAHI_EVIDENCE_BEGIN (part-[0-9]{4}) sha256=([a-f0-9]{64}) bytes=([0-9]+)',lines[at]);need(match is not None,'exact unprefixed original frame header');label,digest,size=match.groups();size=int(size);need(label not in packets and len(packets)<36 and 0<size<=8*M,'original frame uniqueness/count/cap');at+=1;body=[];chars=0
  while at<len(lines)and not lines[at].startswith('CACHY_ASAHI_EVIDENCE_END'):
   line=lines[at];need(0<len(line)<=76 and re.fullmatch('[A-Za-z0-9+/=]+',line),'original base64 line');body.append(line);chars+=len(line);need(chars<=((size+2)//3)*4,'base64 declared cap');at+=1
  need(at<len(lines)and lines[at]=='CACHY_ASAHI_EVIDENCE_END '+label,'complete matching original frame end');at+=1;compressed=base64.b64decode(''.join(body),validate=True);need(pin(compressed)==dict(bytes=size,sha256=digest),'whole original compressed frame identity');packets[label]=decode_frame(label,compressed);decoded_bytes+=sum(map(len,packets[label].values()));need(decoded_bytes<=TOTAL+PACKET,'bounded complete original decoded frame aggregate');frames[label]=pin(compressed)
 need('part-0000'in packets,'original index frame present');return packets,frames

def reconstruct(packets):
 need(set(packets['part-0000'])=={'retention.json'},'exact original index frame');raw=packets['part-0000']['retention.json'];index=obj(raw)
 need(set(index)=={'files','bytes','cap','packet_raw_cap','packet_count','reconstruction','scope'}and index['cap']==TOTAL and index['packet_raw_cap']==PACKET and index['reconstruction']==RECONSTRUCTION and index['scope']==SCOPE,'whole original retention schema/bounds')
 count=index['packet_count'];need(type(count)is int and 0<=count<=35 and set(packets)=={'part-%04d'%n for n in range(count+1)},'complete original contiguous frame closure');files=index['files'];need(type(files)is dict and len(files)<=MAX_FILES and type(index['bytes'])is int and 0<=index['bytes']<=TOTAL,'original file count/aggregate');values={};used=set();ids=set();total=0
 for name,row in files.items():
  safe(name);need(type(row)is dict and set(row)=={'bytes','sha256','chunks'}and type(row['bytes'])is int and 0<=row['bytes']<=FILE and re.fullmatch('[a-f0-9]{64}',row['sha256'])and type(row['chunks'])is list and len(row['chunks'])<=8,'whole original file reference');data=bytearray()
  for number,ref in enumerate(row['chunks']):
   need(set(ref)=={'packet','path','bytes','sha256'}and ref['packet']in packets and ref['packet']!='part-0000'and re.fullmatch(r'chunk-[0-9]{4}\.bin',ref['path']),'exact original chunk reference');key=(ref['packet'],ref['path']);need(key not in used and ref['path']in packets[ref['packet']],'original chunk unique/existing');chunk=packets[ref['packet']][ref['path']];need(type(ref['bytes'])is int and 0<len(chunk)<=PACKET and pin(chunk)=={k:ref[k]for k in('bytes','sha256')}and(number==len(row['chunks'])-1 or len(chunk)==PACKET),'whole original chunk bytes and position');used.add(key);ident=int(ref['path'][6:10]);need(ident not in ids,'unique global chunk number');ids.add(ident);data.extend(chunk);need(len(data)<=row['bytes'],'original fullfile cap')
  value=bytes(data);need(pin(value)=={k:row[k]for k in('bytes','sha256')},'whole reassembled original file');values[name]=value;total+=len(value);need(total<=TOTAL,'original aggregate cap')
 expected={(label,name)for label,group in packets.items()if label!='part-0000'for name in group};need(used==expected and ids==set(range(1,len(ids)+1))and total==index['bytes'],'all original chunks used, total exact')
 need(total-len(values.get('report.json',b''))<=64*M,'original public64MiB cap')
 report=obj(values['report.json'])if 'report.json'in values else {}
 if 'public_files'in report:
  refs=report['public_files'];need(type(refs)is dict and set(values)==set(refs)|{'report.json'}and all(pin(values[n])==row for n,row in refs.items()),'original producer advertised complete public closure');retention=report['retention'];need(retention['files']==len(refs)and retention['bytes']==total-len(values['report.json'])and retention['cap']==64*M,'original producer retention receipt')
 if 'input-summary.json'in values:
  refs=obj(values['input-summary.json'])['retention'];need(type(refs)is list and len(refs)<=1024,'original input reference count')
  for ref in refs:
   name='inputs/'+safe(ref['root'])+'/'+safe(ref['ref']['path']);need(name in values and pin(values[name])=={k:ref['ref'][k]for k in('bytes','sha256')},'whole original retained input closure')
 return raw,values

def capture(packet_root,output,encoder_path,p,env):
 started=time.monotonic();ctx=context(p,env);packet_root=Path(packet_root).absolute();output=Path(output).absolute();need(packet_root.is_dir()and not any(q.is_symlink()for q in(packet_root,*packet_root.parents))and not output.exists()and not any(q.is_symlink()for q in(output,*output.parents))and output.parent.is_dir()and not output.is_relative_to(packet_root)and not packet_root.is_relative_to(output),'fresh separate source-owned output')
 parent=output.parent.stat();need(parent.st_uid==os.getuid()and not(parent.st_mode&0o022),'caller-owned output parent without foreign write access');raw=read(encoder_path,65536);need(pin(raw)==ENCODER,'exact whole original source encoder');encoder=types.ModuleType('_original_native_evidence_encoder');encoder.__file__=str(encoder_path);exec(compile(raw,str(encoder_path),'exec'),vars(encoder))
 roots=sorted(packet_root.iterdir());need(0<len(roots)<=36 and all(q.is_dir()and not q.is_symlink()and re.fullmatch('part-[0-9]{4}',q.name)for q in roots),'finite ordinary original packet roots');step=bytearray()
 for root in roots:
  need(time.monotonic()-started<=90,'bounded source transport capture');children=list(root.iterdir());need(children and all(q.is_file()and not q.is_symlink()and q.stat().st_nlink==1 for q in children),'flat ordinary original packet children')
  # Encoder is invoked exactly once; these exact bytes go to artifact AND stdout.
  directory=root.stat();identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_mtime_ns,v.st_ctime_ns);before={q.name:pin(read(q,PACKET))for q in children};data=encoder.bundle(root);need(identity(root.stat())==identity(directory),'original packet directory identity held');need({q.name:pin(read(q,PACKET))for q in root.iterdir()}==before,'original packet contents held through encoder');step.extend(('CACHY_ASAHI_EVIDENCE_BEGIN '+root.name+' sha256='+pin(data)['sha256']+' bytes='+str(len(data))+'\n').encode());step.extend(base64.encodebytes(data));step.extend(('CACHY_ASAHI_EVIDENCE_END '+root.name+'\n').encode());need(len(step)<=STEP_CAP,'bounded complete emitted stdout')
 step=bytes(step);packets,frames=decode_step(step);index,files=reconstruct(packets);nonce_raw=files.get(p['nonce_path']);need(nonce_raw is not None and len(nonce_raw)<=65536,'original indexed nonce document required');nonce=obj(nonce_raw).get(p['nonce_field']);need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce),'actual original owner nonce required')
 receipt=dict(purpose=PURPOSE,status='COMPLETE_ORIGINAL_FRAMED_TRANSPORT_ONLY',context=dict(ctx,nonce=nonce),capture_source=pin(read(Path(__file__),M)),policy=pin(encoded(p)),encoder=ENCODER,frames=frames,retention_index=pin(index),nonce_reference=dict(path=p['nonce_path'],field=p['nonce_field'],**pin(nonce_raw)),stdout=pin(step),clock=dict(seconds=time.monotonic()-started,time_limit=90),acceptance='NOT_GRANTED',hardware='NOT_RUN',release='NOT_ADMITTED')
 need(receipt['clock']['seconds']<=90,'original capture deadline');output.mkdir(mode=0o700);write(output/'retention-step.txt',step);write(output/'transport.json',encoded(receipt));return step,receipt

def verify_zip(archive_path,expected,run,jobs,artifact,p):
 p=policy(p);archive_path=Path(archive_path);raw=read(archive_path,192*M);need(artifact['size_in_bytes']==len(raw)and artifact['digest']=='sha256:'+pin(raw)['sha256']and not artifact['expired']and type(artifact['id'])is int and artifact['id']>0,'original artifact API identity/digest/expiry')
 need(type(expected)is dict and set(expected)=={'repository','run_id','attempt','head_sha','workflow_path','workflow_name','job','step_id','step_name','nonce'}and expected['attempt']==1 and re.fullmatch('[a-f0-9]{32}',expected['nonce'])and re.fullmatch('[a-f0-9]{40}',expected['head_sha']),'independent complete Root transport binding')
 need(type(expected['run_id'])is int and expected['run_id']>0 and all(expected[k]==p[k]for k in('repository','workflow_path','workflow_name','job','step_id','step_name')),'exact Root source-owned policy context')
 need(run['id']==expected['run_id']and run['run_attempt']==1 and run['head_sha']==expected['head_sha']and run['repository']['full_name']==p['repository']==expected['repository']and run['path']==p['workflow_path']==expected['workflow_path']and run['name']==p['workflow_name']==expected['workflow_name']and run['event']=='workflow_dispatch'and run['status']=='completed','exact genuine original terminal run metadata')
 need(artifact['name']=='native-framed-evidence-'+str(expected['run_id'])+'-1-'+p['job']and artifact['workflow_run']['id']==expected['run_id']and artifact['workflow_run']['head_sha']==expected['head_sha'],'exact original named artifact role/run/head')
 need(jobs['total_count']==len(jobs['jobs'])==1,'complete single-job original workflow metadata')
 matches=[j for j in jobs['jobs']if j['name']==p['job']and j['run_id']==expected['run_id']];need(len(matches)==1,'one exact original native job');job=matches[0];need(job['status']=='completed'and job['head_sha']==expected['head_sha']and job['run_attempt']==1,'original native job identity')
 steps=[s for s in job['steps']if s['name']==p['step_name']];need(len(steps)==1 and steps[0]['status']=='completed'and steps[0]['conclusion']=='success'and type(steps[0]['number'])is int and steps[0]['number']>0,'exact original successful retention step; not aggregate-log inference')
 with zipfile.ZipFile(io.BytesIO(raw))as archive:
  infos=archive.infolist();need(len(infos)==2 and {r.filename for r in infos}=={'transport.json','retention-step.txt'}and all(not r.flag_bits&1 and stat.S_IFMT(r.external_attr>>16)in(0,stat.S_IFREG)and not r.is_dir()and r.file_size<=(M if r.filename=='transport.json'else STEP_CAP)for r in infos)and sum(r.file_size for r in infos)<=STEP_CAP+M,'closed ordinary bounded original artifact members');need(archive.testzip()is None,'original artifact CRC');receipt=obj(archive.read('transport.json'));step=archive.read('retention-step.txt')
 need(set(receipt)=={'purpose','status','context','capture_source','policy','encoder','frames','retention_index','nonce_reference','stdout','clock','acceptance','hardware','release'}and receipt['purpose']==PURPOSE and receipt['status']=='COMPLETE_ORIGINAL_FRAMED_TRANSPORT_ONLY'and receipt['context']==expected and receipt['capture_source']==pin(read(Path(__file__),M))and receipt['policy']==pin(encoded(p))and receipt['encoder']==ENCODER and receipt['stdout']==pin(step)and receipt['acceptance']=='NOT_GRANTED'and receipt['hardware']=='NOT_RUN'and receipt['release']=='NOT_ADMITTED','whole source-owned capture receipt/context')
 clock=receipt['clock'];need(set(clock)=={'seconds','time_limit'}and clock['time_limit']==90 and type(clock['seconds'])in(int,float)and 0<=clock['seconds']<=90,'original source capture clock cap');packets,frames=decode_step(step);index,files=reconstruct(packets);nonce_raw=files[p['nonce_path']];need(receipt['frames']==frames and receipt['retention_index']==pin(index)and receipt['nonce_reference']==dict(path=p['nonce_path'],field=p['nonce_field'],**pin(nonce_raw))and obj(nonce_raw)[p['nonce_field']]==expected['nonce'],'whole frame/index/original owner nonce joins')
 # Run/job failure remains failure. No source/lifecycle/security predicate is waived.
 return dict(status='VERIFIED_ORIGINAL_FRAMED_TRANSPORT_ONLY',context=expected,artifact=pin(raw),job_id=job['id'],step_number=steps[0]['number'],original_conclusion=run['conclusion'],files=len(files),bytes=sum(map(len,files.values())),acceptance='NOT_GRANTED'),files

LATEST607_POLICY={'job': 'native', 'nonce_field': 'nonce', 'nonce_path': 'latest607-selection.json', 'purpose': 'SOURCE_OWNED_NATIVE_FRAMED_TRANSPORT_V1', 'repository': 'Gabriel-Kahen/cachy-asahi', 'step_id': 'native_public_retention', 'step_name': 'Retain the separate bounded604 public closure and lifecycle', 'workflow_name': 'native-arm-current607-latest-tools', 'workflow_path': '.github/workflows/native-arm-build.yml'}
# Finite latest-five successor; original complete transport functions byte-held.
_prior_policy=policy
def policy(value):
 need(value==LATEST607_POLICY,'exact complete latest607 transport policy required')
 _prior_policy(dict(value,nonce_path='plan/bridge-selection.json'))
 return value

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--policy',type=Path,required=True);p.add_argument('--packets',type=Path,required=True);p.add_argument('--encoder',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();step,_=capture(a.packets,a.output,a.encoder,policy(obj(read(a.policy,65536))),os.environ);sys.stdout.buffer.write(step)
if __name__=='__main__':main()
