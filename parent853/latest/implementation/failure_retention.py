# SPDX-License-Identifier: MIT
"""Bounded failed public frames are DATA; every positive closure gate remains."""
import base64,hashlib,json,os,re,sys,time,types
from pathlib import Path
BEFORE=dict(bytes=18291,sha256='1359edd6565231587419abeb7e6cb32b7385c569e549f11351f79946055e2956')
SEAM="step=bytes(step);packets,frames=decode_step(step);index,files=reconstruct(packets);nonce_raw=files.get(p['nonce_path']);need(nonce_raw is not None and len(nonce_raw)<=65536,'original indexed nonce document required');nonce=obj(nonce_raw).get(p['nonce_field']);need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce),'actual original owner nonce required')"
REPLACEMENT="""step=bytes(step);packets,frames=decode_step(step)
 try:
  index,files=reconstruct(packets)
  nonce_raw=files.get(p['nonce_path']);need(nonce_raw is not None and len(nonce_raw)<=65536,'original indexed nonce document required');nonce=obj(nonce_raw).get(p['nonce_field']);need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce),'actual original owner nonce required')
 except (ValueError,KeyError,TypeError) as error:
  return _failure_retention.capture_failure(globals(),started,ctx,p,output,step,packets,frames,error)"""
IMPORT="sys.path.insert(0,str(Path(__file__).resolve().parent))\nimport failure_retention as _failure_retention\n"
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def derive_transport(raw):
 import ast
 need(pin(raw.encode())==BEFORE,'whole original561 transport source')
 tree=ast.parse(raw);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='reconstruct');text=ast.get_source_segment(raw,fn);anchor=" report=obj(values['report.json'])if 'report.json'in values else {}";need(text.count(anchor)==1,'one semantic boundary after complete original structural reconstruction')
 structural=text.split(anchor)[0].replace('def reconstruct(packets):','def reconstruct_bytes(packets):',1)+' return raw,values\n'
 need(raw.count(SEAM)==1 and raw.count('from pathlib import Path\n')==1 and raw.count('def capture(')==1,'exact capture/source import seams')
 original_verify=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='verify_zip');verify=ast.get_source_segment(raw,original_verify);stop=' need(set(receipt)=='
 need(verify.count(stop)==1,'one original complete receipt gate after exact API/ZIP validation')
 prefix=verify.split(stop)[0].replace('def verify_zip(', 'def verify_failure_zip(',1)
 before="re.fullmatch('[a-f0-9]{32}',expected['nonce'])";after="(expected['nonce']is None or re.fullmatch('[a-f0-9]{32}',expected['nonce']))";need(prefix.count(before)==1,'one failure-only nullable nonce DATA seam');prefix=prefix.replace(before,after,1)
 failure_verify=prefix+" return _failure_retention.verify_failure(globals(),receipt,step,expected,run,job,steps,raw)\n"
 changed=raw.replace('from pathlib import Path\n','from pathlib import Path\n'+IMPORT,1).replace('def capture(',structural+'\ndef capture(',1).replace(SEAM,REPLACEMENT,1)
 anchor='LATEST607_POLICY=';need(changed.count(anchor)==1,'one exact selected transport declaration');changed=changed.replace(anchor,failure_verify+'\n'+anchor,1)
 need(changed.replace('from pathlib import Path\n'+IMPORT,'from pathlib import Path\n',1).replace(structural+'\n','',1).replace(failure_verify+'\n','',1).replace(REPLACEMENT,SEAM,1)==raw,'whole original transport inverse')
 ast.parse(changed);return changed

def nonce_data(T,files,p,ctx):
 raw=files.get(p['nonce_path']);origin='ORIGINAL_INDEXED_PUBLIC_FILE';reference=dict(path=p['nonce_path'])
 if raw is None:
  path=Path('/tmp')/('cachy-asahi-expanded604-'+str(ctx['run_id'])+'-'+str(ctx['attempt']))/p['nonce_path'];origin='ORIGINAL_OWNER_PUBLIC_NONCE_FILE';reference=dict(path=str(path))
  try:
   raw=T.read(path,65536);info=path.stat();T.need(info.st_uid==os.getuid()and info.st_mode&0o777==0o600,'owned original public nonce mode/UID')
  except (OSError,ValueError):return None,dict(status='UNAVAILABLE_UNKNOWN_NOT_AUTHORITY',origin=origin,reference=reference)
 try:
  T.need(len(raw)<=65536,'bounded original public nonce');v=T.obj(raw);nonce=v[p['nonce_field']];T.need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce),'original public nonce shape')
 except (ValueError,KeyError,TypeError):return None,dict(status='INVALID_UNKNOWN_NOT_AUTHORITY',origin=origin,reference=reference,raw=pin(raw),raw_base64=base64.b64encode(raw).decode())
 return nonce,dict(status='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION',origin=origin,reference=dict(reference,field=p['nonce_field'],**pin(raw)),raw_base64=base64.b64encode(raw).decode())

def closure_diagnostics(T,files):
 rows=[];count=0
 if 'input-summary.json'not in files:return dict(input_summary='ABSENT_UNKNOWN',mismatches=[],mismatches_omitted=0)
 try:
  refs=T.obj(files['input-summary.json'])['retention'];T.need(type(refs)is list and len(refs)<=1024,'bounded original input references')
  for ref in refs:
   name='inputs/'+T.safe(ref['root'])+'/'+T.safe(ref['ref']['path']);expected={k:ref['ref'][k]for k in('bytes','sha256')};actual=pin(files[name])if name in files else None
   if expected!=actual:
    count+=1
    if len(rows)<8:rows.append(dict(path=name[:512],path_sha256=hashlib.sha256(name.encode()).hexdigest(),path_truncated=len(name)>512,expected=expected,actual=actual))
  return dict(input_summary='ORIGINAL_DATA_ONLY',references=len(refs),mismatches=rows,mismatches_omitted=max(0,count-len(rows)))
 except (ValueError,KeyError,TypeError):return dict(input_summary='INVALID_UNKNOWN',mismatches=[],mismatches_omitted=0)

def capture_failure(namespace,started,ctx,p,output,step,packets,frames,error):
 T=types.SimpleNamespace(**namespace)
 # This is precisely the original reconstruction prefix: every frame/chunk/
 # fullfile hash, membership, type, byte and aggregate bound still must pass.
 index,files=T.reconstruct_bytes(packets);nonce,nonce_receipt=nonce_data(T,files,p,ctx)
 failure=dict(type=type(error).__name__,reason_sha256=hashlib.sha256(str(error).encode()).hexdigest(),stage='ORIGINAL_SEMANTIC_RECONSTRUCTION_REFUSED',input_closure=closure_diagnostics(T,files),consumer_cause='UNKNOWN_UNTIL_ORIGINAL_PUBLIC_RECORDS_REPLAYED',cleanup='ORIGINAL_PUBLIC_RECORDS_ONLY_NO_CREDIT')
 receipt=dict(purpose=T.PURPOSE,status='ORIGINAL_PUBLIC_FRAMED_FAILURE_DATA_ONLY',context=dict(ctx,nonce=nonce),capture_source=pin(T.read(Path(T.__file__),T.M)),policy=pin(T.encoded(p)),encoder=T.ENCODER,frames=frames,retention_index=pin(index),nonce_reference=nonce_receipt,stdout=pin(step),clock=dict(seconds=time.monotonic()-started,time_limit=90),semantic_failure=failure,acceptance='NOT_GRANTED',hardware='NOT_RUN',release='NOT_ADMITTED')
 T.need(receipt['clock']['seconds']<=90 and len(T.encoded(receipt))<=T.M,'unchanged90s/1MiB failure receipt cap');output.mkdir(mode=0o700);T.write(output/'retention-step.txt',step);T.write(output/'transport.json',T.encoded(receipt));return step,receipt

def verify_failure(namespace,receipt,step,expected,run,job,steps,artifact_raw):
 T=types.SimpleNamespace(**namespace);p=T.policy(T.LATEST607_POLICY)
 T.need(job.get('labels')==['ubuntu-24.04-arm'],'exact original hosted ARM runner label')
 fields={'purpose','status','context','capture_source','policy','encoder','frames','retention_index','nonce_reference','stdout','clock','semantic_failure','acceptance','hardware','release'}
 T.need(set(receipt)==fields and receipt['purpose']==T.PURPOSE and receipt['status']=='ORIGINAL_PUBLIC_FRAMED_FAILURE_DATA_ONLY'and receipt['context']==expected and receipt['capture_source']==pin(T.read(Path(T.__file__),T.M))and receipt['policy']==pin(T.encoded(p))and receipt['encoder']==T.ENCODER and receipt['stdout']==pin(step)and receipt['acceptance']=='NOT_GRANTED'and receipt['hardware']=='NOT_RUN'and receipt['release']=='NOT_ADMITTED','whole failure DATA receipt/context/source pins')
 clock=receipt['clock'];T.need(set(clock)=={'seconds','time_limit'}and clock['time_limit']==90 and type(clock['seconds'])in(int,float)and 0<=clock['seconds']<=90,'same original90s diagnostic capture cap')
 packets,frames=T.decode_step(step);index,files=T.reconstruct_bytes(packets)
 try:
  _,positive=T.reconstruct(packets);nonce_raw=positive.get(p['nonce_path']);T.need(nonce_raw is not None and len(nonce_raw)<=65536,'original indexed nonce document required');nonce=T.obj(nonce_raw).get(p['nonce_field']);T.need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce),'actual original owner nonce required')
 except (ValueError,KeyError,TypeError)as error:
  failure=dict(type=type(error).__name__,reason_sha256=hashlib.sha256(str(error).encode()).hexdigest(),stage='ORIGINAL_SEMANTIC_RECONSTRUCTION_REFUSED',input_closure=closure_diagnostics(T,files),consumer_cause='UNKNOWN_UNTIL_ORIGINAL_PUBLIC_RECORDS_REPLAYED',cleanup='ORIGINAL_PUBLIC_RECORDS_ONLY_NO_CREDIT')
 else:raise ValueError('failure DATA cannot replace complete semantic validation')
 T.need(receipt['semantic_failure']==failure and receipt['frames']==frames and receipt['retention_index']==pin(index),'same original semantic refusal and complete structural raw frame joins')
 nr=receipt['nonce_reference'];status=nr.get('status')
 if status=='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION':
  raw=base64.b64decode(nr['raw_base64'],validate=True);T.need(len(raw)<=65536 and pin(raw)=={k:nr['reference'][k]for k in('bytes','sha256')}and nr['reference']['field']==p['nonce_field']and T.obj(raw)[p['nonce_field']]==expected['nonce']and re.fullmatch('[a-f0-9]{32}',expected['nonce']or''),'whole original bounded public nonce DATA')
  if nr['origin']=='ORIGINAL_INDEXED_PUBLIC_FILE':T.need(nr['reference']['path']==p['nonce_path']and raw==files[p['nonce_path']],'original indexed nonce bytes')
  else:
   path=str(Path('/tmp')/('cachy-asahi-expanded604-'+str(expected['run_id'])+'-'+str(expected['attempt']))/p['nonce_path']);T.need(nr['origin']=='ORIGINAL_OWNER_PUBLIC_NONCE_FILE'and nr['reference']['path']==path and p['nonce_path']not in files,'only fixed original owner public nonce fallback')
 else:
  T.need(status in('UNAVAILABLE_UNKNOWN_NOT_AUTHORITY','INVALID_UNKNOWN_NOT_AUTHORITY')and expected['nonce']is None,'unavailable nonce stays UNKNOWN; no positive authority')
  path=str(Path('/tmp')/('cachy-asahi-expanded604-'+str(expected['run_id'])+'-'+str(expected['attempt']))/p['nonce_path'])
  if nr['origin']=='ORIGINAL_OWNER_PUBLIC_NONCE_FILE':T.need(nr['reference']==dict(path=path)and p['nonce_path']not in files,'fixed original owner public nonce UNKNOWN')
  else:T.need(nr['origin']=='ORIGINAL_INDEXED_PUBLIC_FILE'and nr['reference']==dict(path=p['nonce_path']),'original indexed invalid nonce reference')
  if status=='UNAVAILABLE_UNKNOWN_NOT_AUTHORITY':T.need(set(nr)=={'status','origin','reference'},'unavailable nonce has no invented bytes')
  else:
   T.need(set(nr)=={'status','origin','reference','raw','raw_base64'},'whole invalid public nonce DATA');raw=base64.b64decode(nr['raw_base64'],validate=True);T.need(len(raw)<=65536 and pin(raw)==nr['raw'],'whole invalid original nonce bytes')
   if nr['origin']=='ORIGINAL_INDEXED_PUBLIC_FILE':T.need(raw==files[p['nonce_path']],'indexed invalid nonce bytes held')
   try:value=T.obj(raw)[p['nonce_field']];valid=type(value)is str and re.fullmatch('[a-f0-9]{32}',value)
   except (ValueError,KeyError,TypeError):valid=False
   T.need(not valid,'valid nonce cannot be relabeled UNKNOWN')
 return dict(status='VERIFIED_ORIGINAL_FRAMED_FAILURE_DATA_ONLY',context=expected,artifact=pin(artifact_raw),job_id=job['id'],step_number=steps[0]['number'],original_conclusion=run['conclusion'],files=len(files),bytes=sum(map(len,files.values())),semantic_closure='REFUSED_ORIGINAL_PREDICATE',nonce_authority='SOURCE_OWNED_OR_UNKNOWN_NEVER_ROOT_ACCEPTANCE',acceptance='NOT_GRANTED'),files

def rows(root):
 import stat
 result={}
 for q in Path(root).rglob('*'):
  if q.relative_to(root).parts[0]=='.git':continue
  s=q.lstat();need(stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode),'ordinary full source closure')
  if stat.S_ISREG(s.st_mode):
   key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
   need(s.st_nlink==1 and s.st_size<=16*1024**2,'bounded singlelink source');raw=q.read_bytes();need(key(s)==key(q.lstat())and len(raw)==s.st_size,'full source identity/bytes');result[q.relative_to(root).as_posix()]=pin(raw)
 return result

def verify(root,name,want):
 import importlib.util,tempfile
 root=Path(root);raw=(root/name).read_bytes();need(pin(raw)==want and not sys.flags.optimize,'whole hardpinned failed-retention successor');p=json.loads(raw);before=p['before'];actual=rows(root);changed=set(p['before_bodies']);added=set(p['added']);need(len(before)==561 and len(changed)==7 and len(added)==2 and set(actual)==set(before)|added and{n for n in before if before[n]!=actual[n]}==changed,'finite563 source membership;554 held7changed2added');need(all(actual[n]==v for n,v in p['helpers'].items()),'whole source-held failure capture helper')
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in changed else(root/n).read_bytes()for n in before};need(all(pin(bodies[n])==v for n,v in before.items()),'whole genuine published561 inverse')
 need((root/p['transport']).read_text()==derive_transport(bodies[p['transport']].decode()),'exact source-owned bounded DATA insertion; all positive transport bodies held')
 for n,edits in p['edits'].items():
  text=(root/n).read_text()
  for old,new in reversed(edits):need(text.count(new)==1,'one finite failed-retention operand');text=text.replace(new,old,1)
  need(text.encode()==bodies[n],'whole original non-transport source inverse')
 marker='\n# BEGIN_BOUNDED_FAILURE_RETENTION_SUCCESSOR\n';parts=(root/p['guard']).read_text().split(marker);need(len(parts)==2 and parts[0].encode()==bodies[p['guard']]and parts[1]=='def verify():\n import failure_retention\n return failure_retention.verify(ROOT, '+repr(name)+', '+repr(want)+')\n','whole original guard and mandatory appendix')
 mf=json.loads((root/p['manifest']).read_bytes());need(mf['files']=={n:v for n,v in actual.items()if n not in{p['manifest'],*p['workflows']}},'whole new source manifest');restored=dict(mf,files={n:v for n,v in mf['files'].items()if n not in added})
 for n in changed-{p['manifest'],*p['workflows']}:restored['files'][n]=before[n]
 need(enc(restored)==bodies[p['manifest']],'whole original manifest inverse')
 for n in p['workflows']:need((root/n).read_bytes().replace(actual[p['manifest']]['sha256'].encode(),before[p['manifest']]['sha256'].encode())==bodies[n],'whole workflow bodies/budgets held except source stamp')
 pub=p['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='e8cface65674ec4a6072c5675754ad37faa15c9c',ref='codex/current607-prefill-path-v1',files=561,git_joins=561,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['source_authorization']==before and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=before),'whole genuine561 Git/publication/source joins')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='current607-failure-original561-')as td:
   old=Path(td)/'source';old.mkdir()
   for n,body in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(body)
   need(rows(old)==before,'whole original561 before complete original guard')
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str((old/p['guard']).parent));spec=importlib.util.spec_from_file_location('_failure_complete_original561_guard',old/p['guard']);G=importlib.util.module_from_spec(spec);sys.modules[spec.name]=G;spec.loader.exec_module(G);fact=G.verify()
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,files=len(actual),status='SOURCE_ONLY_BOUNDED_FAILED_PUBLIC_DATA_NOT_ACCEPTED',retention_original_source=pub['source'],retention_original_files=561,actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')
