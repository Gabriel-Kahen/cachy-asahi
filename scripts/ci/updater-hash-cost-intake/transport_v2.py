"""Once-original current generic16K API/ZIP/nonce transport; no outcome projection."""
import io,re,stat,zipfile
from pathlib import Path
import context as C
P=C.P;need,read,obj,pin,encoded=C.need,C.read,C.obj,C.pin,C.encoded
ROLES={'result.json','public/result.json','public/adapter.json','public/producer.json','public/producer-cleanup.json','public/transaction-tail.log','owner.json','native4k-wrapper.json','wiring-owner.json','job-cleanup.json','public/updater16k-result.json','public/updater16k-cleanup.json'}
def identity(run,bound,successful=False):
 need(type(run.get('id'))is int and run['id']==bound['run']and run.get('head_sha')==bound['source']and type(run.get('run_attempt'))is int and run['run_attempt']==1 and run.get('status')=='completed'and run.get('conclusion')in('success','failure','timed_out','cancelled')and(not successful or run['conclusion']=='success'),'exact terminal normal first attempt')
 need(type(run.get('workflow_id'))is int and run.get('workflow_id')==381664314 and run.get('path')=='.github/workflows/native-arm-build.yml'and run.get('name')=='native-arm-latest607-updater-generic16k'and run.get('event')=='workflow_dispatch'and run.get('head_branch')==bound['ref']and run['repository']['full_name']=='Gabriel-Kahen/cachy-asahi','exact native4K workflow/repository/ref')
def jobs(value,run,successful=False):
 need(type(value)is dict and type(value.get('total_count'))is int and value['total_count']==1 and len(value['jobs'])==1,'whole sole native job')
 j=value['jobs'][0];need(type(j['run_id'])is int and type(j['run_attempt'])is int and j['run_id']==run['id']and j['head_sha']==run['head_sha']and j['run_attempt']==1 and j['status']=='completed'and j['conclusion']==run['conclusion']and 'ubuntu-24.04-arm'in j['labels'],'same completed native ARM job')
 steps=j['steps'];need(len(steps)<=150 and len({s['number']for s in steps})==len(steps)and all(type(s['number'])is int and s['number']>0 and s['status']=='completed'for s in steps),'whole finite terminal source steps')
 expected=obj(read(C.HERE/'trial/.github/workflows/native-arm-build.yml'))['jobs']['native']['steps'];indices=[]
 mandatory={'root_policy','root_decisions','root_inputs','original_build','fdk_pair','composition'}
 for i,s in enumerate(expected):
  found=[r for r in steps if r['name']==s['name']]
  if not successful and not found:continue
  need(len(found)==1,'exact source step identity '+s['name']);row=found[0];indices.append(row['number'])
  if successful:need(row['conclusion']=='success'if 'if'not in s or s.get('id')in mandatory or i>=60 else row['conclusion']in('success','skipped'),'required natural source step '+s['name'])
 need(indices==sorted(indices)and len(set(indices))==len(indices),'whole source step order')
 return j
def metadata(run,listing,bound):
 identity(run,bound);need(type(listing)is dict and set(listing)=={'total_count','artifacts'}and type(listing['total_count'])is int and type(listing['artifacts'])is list and listing['total_count']==len(listing['artifacts'])and 0<=len(listing['artifacts'])<=1,'finite original artifact listing')
 if not listing['artifacts']:return None
 a=listing['artifacts'][0];need(type(a['id'])is int and a['id']>0 and a['expired']is False and type(a['size_in_bytes'])is int and 0<a['size_in_bytes']<=16*P.M and a['name']=='updater607-normal-lifecycle-'+bound['case']+'-'+str(run['id'])+'-1'and re.fullmatch('sha256:[a-f0-9]{64}',a['digest']),'original source-owned artifact identity')
 need(a['archive_download_url']=='https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/actions/artifacts/'+str(a['id'])+'/zip','original artifact API URL')
 w=a['workflow_run'];rid=run['repository']['id'];need(type(rid)is int and rid>0 and type(w['id'])is int and w['id']==run['id']and w['head_sha']==bound['source']and w['head_branch']==bound['ref']and type(w['repository_id'])is int and type(w['head_repository_id'])is int and w['repository_id']==w['head_repository_id']==rid,'whole artifact/run/source/repository join');return a
def zip_members(raw,cap,count):
 need(0<len(raw)<=cap,'bounded original ZIP')
 with zipfile.ZipFile(io.BytesIO(raw))as z:
  rows=z.infolist();need(len(rows)<=count and len({r.filename for r in rows})==len(rows)and sum(r.file_size for r in rows)<=cap and z.testzip()is None,'whole ZIP closure/CRC')
  out={}
  for r in rows:
   need(not r.is_dir()and not r.flag_bits&1 and stat.S_IFMT(r.external_attr>>16)in(0,stat.S_IFREG)and r.filename and all(x not in('','.','..')for x in r.filename.split('/'))and not r.filename.startswith('/')and '\\'not in r.filename and 0<=r.file_size<=cap,'ordinary bounded ZIP member');out[r.filename]=z.read(r)
  return out
def decode_bound(raw,a,bound):
 need(pin(raw)==dict(bytes=a['size_in_bytes'],sha256=a['digest'][7:]),'artifact original API digest/size');outer=zip_members(raw,16*P.M,1);need(set(outer)=={'evidence.zip'},'one actual uploaded source ZIP');inner=outer['evidence.zip'];data=zip_members(inner,9*P.M,13);need('retention.json'in data and set(data)<=(ROLES|{'retention.json'}),'fixed public original roles only')
 ret=obj(data['retention.json']);need(ret['status']=='SOURCE_BOUND_CURRENT607_GENERIC16K_PUBLIC_DATA_NOT_ACCEPTANCE'and ret['held_owner_source']==C.HELD and ret['private_roots_source_cache']=='NOT_EXPORTED'and ret['root_acceptance']=='NOT_ISSUED'and set(data)==set(ret['files'])|{'retention.json'}and set(ret['files'])<=ROLES and set(ret['missing'])==ROLES-set(ret['files'])and len(ret['missing'])==len(set(ret['missing'])),'complete finite retained closure/missing roles')
 need(type(ret['total_bytes'])is int and ret['total_bytes']==sum(len(data[n])for n in ret['files'])<=8*P.M,'whole original8MiB bound')
 for n,w in ret['files'].items():need(C.same(pin(data[n]),w),'original retained byte/hash join '+n)
 need(type(bound)is dict and bound.get('case')in C.CASES,'explicit bound version route')
 if bound['case']=='normal':
  import initializer_v2
  telemetry=initializer_v2.qualify(data,bound,C.profile(),C.read,C.HERE/'source',proof)
 else:
  _initializer_data(data);telemetry=dict(status='STRICT_FAULT_CASE_V1_DATA',acceptance=False)
 return inner,data,telemetry

def decode(raw,a,bound):
 inner,data,_=decode_bound(raw,a,bound);return inner,data
def proof(value,bound):
 expected=dict(status='HOST4K_CURRENT607_GENERIC16K_VM_CUSTODY_NOT_ACCEPTANCE',source=bound['source'],ref='refs/heads/'+bound['ref'],run=bound['run'],attempt=1,case=bound['case'],page_size=4096,expected_guest_page_size=16384,architecture='aarch64',current607=dict(source=bound['source'],run=str(bound['run']),attempt='1',ref='refs/heads/'+bound['ref'],page_profile='generic16k'),held_library_source=C.HELD,hardware='NOT_RUN')
 need(C.same(value,expected),'exact current source/ref/run/attempt host4K and separate16K expected-context custody');return value
def source_join(data,bound):
 r=obj(data['retention.json']);proof(r['wrapper'],bound)
 if 'owner.json'in data:
  owner=obj(data['owner.json']);need(owner['purpose']=='expanded604-apps6-public-pair-updater'and owner['case']==bound['case']and owner['output']=='/tmp/cachy-asahi-updater607-normal-lifecycle-'+str(bound['run'])+'-1-'+bound['case']and re.fullmatch('[a-f0-9]{32}',owner['token']),'current source-owned output/nonce')
def original(root,bound,successful=False):
 root=Path(root);raws={n:read(root/n,32*P.M if n=='logs.zip'else 2*P.M)for n in('run.json','jobs.json','artifacts.json','logs.zip')};run=obj(raws['run.json']);identity(run,bound,successful);jobs(obj(raws['jobs.json']),run,successful);a=metadata(run,obj(raws['artifacts.json']),bound);P.logs_check(raws['logs.zip']);data={}
 if a is not None:
  raws['artifact.zip']=read(root/'artifact.zip',16*P.M);inner,data=decode(raws['artifact.zip'],a,bound);need(read(root/'evidence.zip',9*P.M)==inner,'unchanged complete inner ZIP');source_join(data,bound)
 else:need(not successful,'missing source-owned artifact refuses positive')
 receipt=obj(read(root/'collection.json',2*P.M));need(C.same(receipt,dict(status='ONCE_GENERIC16K_ORIGINALS_NOT_ACCEPTANCE',source=bound['source'],run=bound['run'],attempt=1,files={n:pin(b)for n,b in raws.items()},artifact=None if a is None else a['id'])),'whole once original collection byte pins')
 public=root/'public';actual=set()
 if public.exists():
  for p in public.rglob('*'):
   need(not p.is_symlink()and(p.is_dir()or p.is_file()),'ordinary public closure')
   if p.is_file():actual.add(p.relative_to(public).as_posix())
 need(actual==set(data),'exact original public disk closure')
 for n,b in data.items():need(read(public/n,4*P.M)==b,'unchanged original public bytes '+n)
 if successful:need(set(data)==ROLES|{'retention.json'}and len(data['public/transaction-tail.log'])<=65536,'all twelve fixed roles and bounded original tail')
 return run,data,{n:pin(b)for n,b in raws.items()}


def intent(bound):return dict(status='ONCE_ONLY_NO_RETRY',purpose='normal-emulated16k-lifecycle-v1',source=bound['source'],ref=bound['ref'],run=bound['run'],attempt=1,case=bound['case'],workflow_id=381664314)

def initial_identity(initial,source,ref):return C.initial_identity(initial,source,ref)

# INITIALIZER_MOUNT_QUERY_TELEMETRY_STRICT_DATA_V1
_TELEMETRY_PREFIX=b'UPDATER607_INITIALIZER_TELEMETRY '
def _initializer_record(value,expected_nonce=None):
 p=C.profile()['initializer_mount_query'];need(type(value)is dict and set(value)==set(p['record_keys']),'closed initializer telemetry record')
 need(type(value['v'])is int and value['v']==1 and value['profile']=='I16K_STATX_V1','exact initializer telemetry profile')
 need(type(value['nonce'])is str and re.fullmatch('[0-9a-f]{32}',value['nonce'])and(expected_nonce is None or value['nonce']==expected_nonce),'initializer telemetry inner nonce')
 need(value['lane']in('WORKER','PARENT')and value['phase']in p['phases']and value['phase'].startswith(value['lane']+'_')and value['state']in('STARTED','PROGRESS','RETURNED','REFUSED'),'fixed initializer telemetry enums')
 need(type(value['seq'])is int and 0<=value['seq']<(6 if value['lane']=='WORKER'else 8) and type(value['elapsed_ns'])is int and 0<=value['elapsed_ns']<=2**63-1 and type(value['saturated'])is bool,'typed finite initializer telemetry counters')
 if 'remaining_ns'in value:need(value['remaining_ns']is None or type(value['remaining_ns'])is int and -(2**63-1)<=value['remaining_ns']<=2**63-1,'signed original remaining deadline DATA')
 need(type(value['ops'])is list and len(value['ops'])==8 and all(type(x)is int and 0<=x<=2**63-1 for x in value['ops']),'fixed true-integer operation vector')
 raw=_TELEMETRY_PREFIX+__import__('json').dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n';need(len(raw)<=768,'held complete initializer telemetry768 line cap');return value

def _initializer_lines(raw,expected_nonce=None):
 need(type(raw)is bytes and len(raw)<=65536,'original bounded telemetry stream DATA');out=[]
 for line in raw.splitlines():
  if not line.startswith(_TELEMETRY_PREFIX):continue
  need(len(line)+1<=768,'whole framed telemetry line bound');out.append(_initializer_record(obj(line[len(_TELEMETRY_PREFIX):]),expected_nonce));need(len(out)<=128,'bounded original telemetry stream count; independent invocations may reset sequence')
 return out

def _initializer_summary(value):
 p=C.profile()['initializer_mount_query'];need(type(value)is dict and set(value)==set(p['wrapper_keys'])and type(value['v'])is int and value['v']==1 and value['profile']=='I16K_STATX_V1'and type(value['saturated'])is bool,'closed initializer telemetry summary')
 need(type(value['history'])is list and len(value['history'])<=8,'bounded initializer observation history')
 for index,row in enumerate(value['history']):
  _initializer_record(row);need(row['lane']=='PARENT'and row['seq']==index,'ordered parent observation history lane/sequence')
  if index:
   prior=value['history'][index-1];need(row['elapsed_ns']>=prior['elapsed_ns']and all(a>=b for a,b in zip(row['ops'],prior['ops'])),'cumulative parent elapsed and operations')
 worker=value['worker']
 if worker is not None:
  need(type(worker)is dict and set(worker)==set(p['worker_keys'])and worker['capture_scope']=='ORIGINAL_SUPERVISOR_CAPTURE_MAY_BE_PARTIAL','closed original telemetry supervisor capture record')
  if worker['last']is not None:
   _initializer_record(worker['last']);need(worker['last']['lane']=='WORKER','worker snapshot lane')
  need(type(worker['records'])is int and 0<=worker['records']<=6,'bounded worker emission count');need((worker['last']is None)==(worker['records']==0),'unknown versus captured snapshot count');need(worker['last']is None or worker['last']['seq']==worker['records']-1,'exact last captured worker sequence')
  need(type(worker['stderr'])is dict and set(worker['stderr'])=={'bytes','sha256'}and type(worker['stderr']['bytes'])is int and 0<=worker['stderr']['bytes']<=65536 and type(worker['stderr']['sha256'])is str and re.fullmatch('[0-9a-f]{64}',worker['stderr']['sha256']),'original supervisor capture pin only')
  need(worker['returncode']is None or type(worker['returncode'])is int and -255<=worker['returncode']<=255,'original supervisor returncode DATA');need(worker['termination']in(None,'timeout','output-limit','interrupted')and type(worker['direct_child_reaped'])is bool,'original supervisor state DATA')
 rows=list(value['history'])+([worker['last']]if worker is not None and worker['last']is not None else[])
 need(len({row['nonce']for row in rows})<=1,'one existing inner nonce within initializer summary')
 return value

def _initializer_data(data):
 import base64
 # Existing approved JSON roles only; no independent authority or new read role.
 for name,raw in data.items():
  if not name.endswith('.json'):continue
  value=obj(raw);stack=[(value,0)];visited=0
  while stack:
   item,depth=stack.pop();visited+=1;need(visited<=1048576 and depth<=64,'finite telemetry JSON walk')
   if type(item)is dict:
    if 'initializer_telemetry'in item:_initializer_summary(item['initializer_telemetry'])
    stack.extend((v,depth+1)for v in item.values()if type(v)in(dict,list))
   elif type(item)is list:stack.extend((v,depth+1)for v in item if type(v)in(dict,list))
 cleanup=obj(data['public/updater16k-cleanup.json'])if'public/updater16k-cleanup.json'in data else {};q=cleanup.get('qemu_failure')
 if not isinstance(q,dict):return
 preview=q.get('stdout',{});encoded=preview.get('preview_base64')
 if encoded is None:return
 need(type(encoded)is str and len(encoded)<=87384,'bounded existing QEMU stdout preview');body=base64.b64decode(encoded,validate=True);need(len(body)<=65536,'held QEMU preview bound')
 for line in body.splitlines():
  if not line.startswith((b'APPS6_UPDATE16K_CALLER_FAILURE ',b'APPS6_UPDATE16K_WORKER_FAILURE ')):continue
  parts=line.split(b' ',2);need(len(parts)==3,'fixed failure frame')
  try:frame=obj(parts[2])
  except ValueError:
   need(preview.get('truncated')is True,'whole failure frame required');continue
  for side,cap in(('stdout',4096),('stderr',8192)):
   row=frame.get(side)
   if not isinstance(row,dict)or'tail_base64'not in row:continue
   need(type(row['tail_base64'])is str and len(row['tail_base64'])<=4*((cap+2)//3),'existing failure suffix text cap');tail=base64.b64decode(row['tail_base64'],validate=True);need(len(tail)<=cap,'existing original stdout4096/stderr8192 caps');_initializer_lines(tail)
