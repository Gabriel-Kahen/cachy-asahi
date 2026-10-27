#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Passive bounded transport framing/receipt predicates; never imports Source."""
import base64,hashlib,json,math,re
CARRIER='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
PROFILE='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
FILES=1154;BYTES=1046432165;RECEIPT_CAP=8*1024**2;DIAGNOSTIC_CAP=4*1024**2;EVIDENCE_CAP=12*1024**2
BEGIN='GNU_RETAINED_TRANSPORT_BEGIN_V1 ';CHUNK='GNU_RETAINED_TRANSPORT_CHUNK_V1 ';END='GNU_RETAINED_TRANSPORT_END_V1 '
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def obj(raw):
 def pairs(items):
  out={}
  for k,v in items:need(k not in out,'duplicate transport JSON field');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite transport JSON'))
def policy():return dict(fetch_seconds=400,transport_seconds=480,outer_seconds=500,reason='Explicit one-fetch allocation for full retained DATA; no measured latency guarantee')
def pin_check(v):need(type(v)is dict and set(v)=={'bytes','sha256'}and type(v['bytes'])is int and v['bytes']>=0 and type(v['sha256'])is str and re.fullmatch('[a-f0-9]{64}',v['sha256']),'complete typed transport byte pin')
def binding_check(b,expected=None):
 need(type(b)is dict and set(b)=={'source','ref','run_id','attempt','selection_nonce','selection_policy'},'complete transport binding')
 need(type(b['source'])is str and re.fullmatch('[a-f0-9]{40}',b['source'])and type(b['ref'])is str and re.fullmatch('codex/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}',b['ref'])and'..'not in b['ref']and not b['ref'].endswith('/'),'exact source/ref transport labels')
 need(type(b['run_id'])is type(b['attempt'])is int and 0<b['run_id']<2**63 and 0<b['attempt']<2**31 and type(b['selection_nonce'])is str and re.fullmatch('[a-f0-9]{32}',b['selection_nonce']),'typed run/attempt and selected bootstrap nonce')
 pin_check(b['selection_policy'])
 if expected is not None:
  need(type(expected)is dict and set(expected)>={'source','ref','run_id','attempt'}and all(k in b and b[k]==v for k,v in expected.items()),'genuine authenticated source/ref/run/attempt binding')
def git_prefix(git_dir=None):
 out=['/usr/bin/git','-c','credential.helper=','-c','http.extraHeader=','-c','http.sslVerify=true','-c','http.followRedirects=false','-c','http.proxy=','-c','core.hooksPath=/dev/null','-c','core.attributesFile=/dev/null','-c','core.fsmonitor=false','-c','gc.auto=0','-c','maintenance.auto=false','-c','fetch.writeCommitGraph=false','-c','protocol.allow=never','-c','protocol.https.allow=always']
 return out+([]if git_dir is None else['--git-dir='+str(git_dir)])
def tree_oid(table):
 root={}
 for name,row in table.items():
  node=root;parts=name.split('/')
  for part in parts[:-1]:node=node.setdefault(part,{})
  node[parts[-1]]=(row['mode'],row['oid'])
 def digest(node):
  raw=bytearray()
  for name,v in sorted(node.items(),key=lambda item:(item[0]+('/'if type(item[1])is dict else'')).encode()):
   mode,oid=('40000',digest(v))if type(v)is dict else v;raw.extend(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid))
  return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
 return digest(root)
def safe_supervision(row):
 v=row['supervision'];need(type(v)is dict and v['passed']is v['reaped']is v['output_complete']is True and v['ownership']=='REAPED'and v['group_census']=='EMPTY_TWICE'and v['exit']==0 and v['timeout']is False and v['error']is None and v['signals']==[]and type(v['seconds'])in(int,float)and math.isfinite(v['seconds'])and v['seconds']>=0,'every child natural/exclusive reap/output complete/group absent')
 need(type(v['exit'])is int and type(row['cap_seconds'])in(int,float)and math.isfinite(row['cap_seconds'])and 0<=v['seconds']<row['cap_seconds']<=400,'finite per-child cap and natural elapsed')
def validate_receipt(receipt,p,carrier):
 files=p['files'];need(receipt['status']=='PASS_EXACT_RETAINED_GIT_DATA_ONLY'and receipt['fixture']is False and receipt['source']==CARRIER and receipt['profile_sha256']==PROFILE and receipt['url']=='https://github.com/Gabriel-Kahen/cachy-asahi.git'and receipt['policy']==policy()and receipt['file_count']==len(files)and receipt['material_bytes']==sum(v['bytes']for v in files.values()),'exact complete carrier identity/profile/policy')
 need(receipt['destination']==carrier.rsplit('/',1)[0]and receipt['data_path']==carrier and type(receipt['fetch_attempts'])is int and receipt['fetch_attempts']==1 and receipt['blob_joins']==len(files)and receipt['full_namespace']is True and receipt['retry']is False and receipt['partial_data_retained']is True,'one fixed full DATA fetch/rawblob namespace')
 need(receipt['source_code_execution']==receipt['signature_authentication']==receipt['native_build']=='NOT_RUN'and receipt['trust_admission']is receipt['release_acceptance']is False,'DATA grants no execution/signature/native/trust/release credit')
 need(type(receipt['elapsed_seconds'])in(int,float)and math.isfinite(receipt['elapsed_seconds'])and 0<=receipt['elapsed_seconds']<480,'full transport under480s')
 rows=receipt['commands'];need(type(rows)is list and len(rows)==len(files)+7,'every rawblob and metadata command')
 g=git_prefix(carrier+'/.git');first=[git_prefix()+['init','--bare','--object-format=sha1','--template=',carrier+'/.git'],g+['-c','http.lowSpeedLimit=65536','-c','http.lowSpeedTime=60','-c','fetch.fsckObjects=true','fetch','--depth=1','--no-tags','--no-recurse-submodules',receipt['url'],CARRIER],g+['rev-parse','--verify','FETCH_HEAD'],g+['cat-file','commit',CARRIER],g+['ls-tree','-rz','--full-tree',CARRIER]];table={}
 for i,row in enumerate(rows):
  need(type(row['number'])is int and row['number']==i and row['passed']is True,'every command numbered and passed once');safe_supervision(row)
  need(row['raw_stderr']==f'logs/{i:04d}.stderr','ordinary numbered raw stderr')
  if i<5:need(row['argv']==first[i]and row['cap_seconds']<=([10,400,30,30,30][i]),'exact safe one-fetch/commit/tree argv and cap')
  elif i<5+len(files):
   name=sorted(files)[i-5];v=row['stdout_material'];need(set(v)=={'bytes','sha256','git_blob','mode'}and{k:v[k]for k in('bytes','sha256')}==files[name]and type(v['mode'])is int and v['mode']in(0o644,0o755)and type(v['git_blob'])is str and re.fullmatch('[a-f0-9]{40}',v['git_blob']),'every exact material pin/mode/blob')
   need(row['argv']==g+['cat-file','blob',v['git_blob']]and row['raw_stdout']=='data/'+name and row['stdout_streams']=='BLOB_STDOUT; SEPARATE_STDERR'and row['cap_seconds']<=30,'rawblob only without filters/checkout/execution');table[name]=dict(oid=v['git_blob'],mode='100755'if v['mode']==0o755 else'100644')
  else:need(row['argv']==g+(['update-ref','--no-deref','HEAD',CARRIER]if i==5+len(files)else['rev-parse','--verify','HEAD'])and row['cap_seconds']<=30,'exact detached DATA HEAD commands')
  if not 5<=i<5+len(files):need(row['raw_stdout']==f'logs/{i:04d}.stdout'and row['stdout_streams']=='STDOUT_AND_STDERR_MERGED_AT_SPAWN'and'stdout_material'not in row,'bounded nonmaterial metadata stdout')
 need(tree_oid(table)==receipt['tree'],'complete modes/blob table reconstructs commit tree');return table

def frame(payload):
 raw=encoded(payload);need(len(raw)<=EVIDENCE_CAP,'bounded whole public transport evidence');header=dict(schema=1,binding=payload['binding'],payload=pin(raw),chunks=(len(raw)+3071)//3072)
 lines=[BEGIN+encoded(header).decode().strip()]
 lines += [CHUNK+str(i)+' '+base64.b64encode(raw[start:start+3072]).decode()for i,start in enumerate(range(0,len(raw),3072))]
 lines += [END+pin(raw)['sha256']];return ('\n'.join(lines)+'\n').encode()
def parse_framed(raw):
 need(type(raw)is bytes and len(raw)<=20*1024**2,'bounded authenticated transport joblog');lines=[]
 for line in raw.decode('utf8','strict').splitlines():
  line=re.sub(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z ','',line)
  if line.startswith((BEGIN,CHUNK,END)):lines.append(line)
 need(len(lines)>=3 and lines[0].startswith(BEGIN)and lines[-1].startswith(END)and sum(v.startswith(BEGIN)for v in lines)==sum(v.startswith(END)for v in lines)==1,'one complete source-owned transport evidence frame')
 h=obj(lines[0][len(BEGIN):].encode());need(type(h)is dict and set(h)=={'schema','binding','payload','chunks'}and type(h['schema'])is int and h['schema']==1,'exact transport frame header');binding_check(h['binding']);pin_check(h['payload']);need(0<h['payload']['bytes']<=EVIDENCE_CAP and type(h['chunks'])is int and h['chunks']==(h['payload']['bytes']+3071)//3072 and len(lines)==h['chunks']+2,'complete bounded chunk count')
 parts=[]
 for i,line in enumerate(lines[1:-1]):
  prefix=CHUNK+str(i)+' ';need(line.startswith(prefix),'every canonical indexed transport chunk exactly once');part=base64.b64decode(line[len(prefix):],validate=True);need(base64.b64encode(part).decode()==line[len(prefix):]and len(part)==min(3072,h['payload']['bytes']-i*3072),'canonical complete transport chunk');parts.append(part)
 body=b''.join(parts);need(pin(body)==h['payload']and lines[-1]==END+h['payload']['sha256'],'whole framed payload hash');v=obj(body);need(encoded(v)==body and v['binding']==h['binding'],'canonical complete transport payload binding');return v

def positive(payload,profile_raw,expected_binding):
 need(type(payload)is dict and set(payload)=={'schema','binding','wrapper_exit','transport','raw_diagnostics','diagnostics_complete','error'}and type(payload['schema'])is int and payload['schema']==1,'exact public transport payload schema');binding_check(payload['binding'],expected_binding)
 need(payload['wrapper_exit']==0 and type(payload['wrapper_exit'])is int and payload['diagnostics_complete']is True and payload['error']is None,'successful wrapper with complete untruncated transport diagnostics')
 need(pin(profile_raw)['sha256']==PROFILE,'whole held1154 carrier profile');p=obj(profile_raw);need(p['source']==CARRIER and p['actual']is None and len(p['files'])==FILES and sum(v['bytes']for v in p['files'].values())==BYTES,'all1154/1046432165 fixed materials')
 r=payload['transport'];carrier=r['data_path'];need(type(carrier)is str and re.fullmatch('/[^\x00\n]+/gnu-retained-transport/data',carrier),'fixed external transport DATA path');table=validate_receipt(r,p,carrier)
 expected={row[side] for row in r['commands']for side in('raw_stdout','raw_stderr')if not(side=='raw_stdout'and'stdout_material'in row)};need(set(payload['raw_diagnostics'])==expected,'every nonmaterial stdout/stderr retained, no package stdout')
 diagnostics={};total=0
 for name,v in payload['raw_diagnostics'].items():
  need(re.fullmatch('logs/[0-9]{4}\\.(stdout|stderr)',name)and set(v)=={'bytes','sha256','base64'},'exact numbered nonmaterial diagnostic');raw=base64.b64decode(v['base64'],validate=True);need(base64.b64encode(raw).decode()==v['base64']and pin(raw)=={k:v[k]for k in('bytes','sha256')},'raw nonmaterial diagnostic byte pin');total+=len(raw);need(total<=DIAGNOSTIC_CAP,'bounded aggregate raw diagnostics');diagnostics[name]=raw
 for row in r['commands']:
  need(pin(diagnostics[row['raw_stderr']])==row['stderr_pin'],'every original raw stderr pin')
  if'stdout_material'not in row:need(pin(diagnostics[row['raw_stdout']])==row['stdout_pin'],'every original nonmaterial stdout pin')
 commit=diagnostics[r['commands'][3]['raw_stdout']];need(hashlib.sha1(b'commit '+str(len(commit)).encode()+b'\0'+commit).hexdigest()==CARRIER and commit.split(b'\n',1)[0]==b'tree '+r['tree'].encode(),'whole raw commit SHA1 and root tree')
 rawtable={}
 for row in diagnostics[r['commands'][4]['raw_stdout']].split(b'\0'):
  if row:
   h,n=row.split(b'\t',1);mode,kind,oid=h.decode('ascii').split();name=n.decode('ascii');need(kind=='blob'and name not in rawtable,'whole raw recursive tree membership');rawtable[name]=dict(mode=mode,oid=oid)
 need(rawtable==table,'original raw Git tree joins every1154 blob and mode')
 for i in(2,len(r['commands'])-1):need(diagnostics[r['commands'][i]['raw_stdout']]==(CARRIER+'\n').encode(),'original fetched and detached source identity')
 return dict(status='PASS_RETAINED_TRANSPORT_DATA_ONLY_AND',binding=payload['binding'],carrier_source=CARRIER,profile_sha256=PROFILE,files=FILES,bytes=BYTES,blob_joins=FILES,tree=r['tree'],fetch_attempts=1,commands=len(r['commands']),seconds=r['elapsed_seconds'],signature_authentication='NOT_RUN',native='NOT_RUN',source_execution='NOT_RUN',nonce_scope='PRE_NATIVE_SELECTION_NONCE_NOT_LATER_VM_OWNER_TOKEN')
