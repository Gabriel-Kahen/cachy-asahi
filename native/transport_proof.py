# SPDX-License-Identifier: MIT
"""Passive canonical transport joins and bounded metadata-only proof export."""
import hashlib,json,math,os,re,stat
from pathlib import Path,PurePosixPath
from capsule import _ordinary,_directory
from public_projection import PRIVATE_MARKER

MAX_LOG=4*1024**2
MAX_PROOF=16*1024**2
FILE_COUNT=1154
MATERIAL_BYTES=1046432165
PROFILE_BYTES=195440
PROFILE_SHA='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
PROFILE_SOURCE='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
CANONICAL_SHA='9b90c423fd67c261d8be1dddd8450df5b927b6dbaba9972c4daff8c0da2836b7'
PUBLIC='https://github.com/Gabriel-Kahen/cachy-asahi.git'
POLICY=dict(fetch_seconds=400,transport_seconds=480,outer_seconds=500,reason='Explicit one-fetch allocation for full retained DATA; no measured latency guarantee')
EMPTY=dict(bytes=0,sha256=hashlib.sha256(b'').hexdigest())
SHA1=re.compile('[0-9a-f]{40}');SHA256=re.compile('[0-9a-f]{64}')


def _need(ok):
 if not ok:raise ValueError('TRANSPORT_PROOF_REFUSED')

def _encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def _pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def _parse(raw):
 def pairs(rows):
  out={}
  for key,value in rows:_need(key not in out);out[key]=value
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('TRANSPORT_PROOF_REFUSED')))

def _path(value):
 _need(type(value) is str and 0<len(value)<=4096);path=Path(value)
 _need(path.is_absolute() and '..' not in path.parts and str(path)==value);return path

def _own(own,map_hash):
 _need(type(own) is dict and set(own)=={'source','ref','run','attempt','token'} and type(map_hash) is str and SHA256.fullmatch(map_hash))
 _need(type(own['source']) is str and SHA1.fullmatch(own['source']) and type(own['ref']) is str and own['ref'].startswith('refs/heads/codex/')
  and type(own['run']) is str and re.fullmatch('[1-9][0-9]*',own['run']) and type(own['attempt']) is int and own['attempt']==1
  and own['token']==hashlib.sha256((own['source']+':'+own['ref']+':'+own['run']).encode()).hexdigest()[:24])

def _profile(profile):
 raw=_encoded(profile);_need(len(raw)==PROFILE_BYTES and _pin(raw)['sha256']==PROFILE_SHA and profile['source']==PROFILE_SOURCE
  and profile['schema']==1 and profile['actual'] is None and len(profile['files'])==FILE_COUNT
  and sum(row['bytes'] for row in profile['files'].values())==MATERIAL_BYTES)
 return profile['files']

def _safe(raw,cap):
 _need(type(raw) is bytes and len(raw)<=cap and not PRIVATE_MARKER.search(raw));return raw

def _supervision(row):
 s=row.get('supervision');_need(type(s) is dict and set(s)=={'exit','reaped','ownership','timeout','signals','output_complete','group_census','error','seconds','passed'}
  and s.get('passed') is True and s.get('reaped') is True and s.get('ownership')=='REAPED'
  and s.get('group_census')=='EMPTY_TWICE' and type(s.get('exit')) is int and s['exit']==0 and s.get('output_complete') is True
  and s.get('error') is None and s.get('timeout') is False and s.get('signals')==[] and type(s.get('seconds')) in (int,float)
  and math.isfinite(s['seconds']) and 0<=s['seconds']<480 and row.get('passed') is True)
 return s['seconds']

def _trees(table):
 root={};identifiers=set()
 for name,row in table.items():
  node=root;parts=name.split('/')
  for part in parts[:-1]:node=node.setdefault(part,{})
  node[parts[-1]]=(row['mode'],row['oid'])
 def digest(node):
  raw=b''
  for name,value in sorted(node.items(),key=lambda x:(x[0]+('/' if type(x[1]) is dict else '')).encode()):
   mode,oid=('40000',digest(value)) if type(value) is dict else value;raw+=mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid)
  oid=hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest();identifiers.add(oid);return oid
 return digest(root),identifiers

def _table(raw,files):
 _need(raw.endswith(b'\0'));table={}
 for record in raw[:-1].split(b'\0'):
  head,name=record.split(b'\t');mode,kind,oid=head.decode('ascii').split();name=name.decode('ascii')
  _need(name in files and name not in table and kind=='blob' and mode in ('100644','100755') and SHA1.fullmatch(oid))
  table[name]=dict(mode=mode,oid=oid)
 _need(set(table)==set(files));return table

def _inventory(raw):
 out={}
 for line in raw.splitlines():
  if line==b'warning: This repository uses promisor remotes. Some objects may not be loaded.':continue
  oid,kind=line.decode('ascii').split();_need(SHA1.fullmatch(oid) and kind in ('blob','tree','commit') and oid not in out);out[oid]=kind
 return out

def _git(carrier):
 base=['/usr/bin/git','--no-replace-objects','-c','credential.helper=','-c','http.extraHeader=','-c','http.sslVerify=true','-c','http.followRedirects=false','-c','http.proxy=',
  '-c','core.hooksPath=/dev/null','-c','core.attributesFile=/dev/null','-c','core.fsmonitor=false','-c','gc.auto=0','-c','maintenance.auto=false','-c','fetch.writeCommitGraph=false',
  '-c','protocol.allow=never','-c','protocol.https.allow=always']
 git=base+['--git-dir='+str(carrier/'.git')];local=git+['-c','protocol.file.allow=never','-c','protocol.https.allow=never']
 network=git+['-c','http.lowSpeedLimit=65536','-c','http.lowSpeedTime=60','-c','fetch.fsckObjects=true','fetch','--progress','--no-tags','--no-recurse-submodules','--no-auto-maintenance','--filter=blob:none']
 return base,git,local,network

RECEIPT_KEYS=set('schema_version status source url fixture profile_sha256 policy file_count material_bytes destination data_path retry partial_data_retained source_code_execution signature_authentication native_build trust_admission release_acceptance acquisition_roles commands fetch_seconds_shared unselected_blobs history lazy_fetch metadata_object_inventory required_blob_oids object_inventory tree blob_joins full_namespace materialized_files acquisition_completed_within_shared400 elapsed_seconds'.split())

def _pin_record(row,cap):
 _need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<=row['bytes']<=cap and type(row['sha256']) is str and SHA256.fullmatch(row['sha256']))

def _validate(certificate,receipt,profile,own,map_hash,read):
 _own(own,map_hash);files=_profile(profile)
 _need(type(certificate) is dict and set(certificate)=={'schema','status','binding','source_map_sha256','canonical_helper_sha256','work_root','canonical_receipt','rows'}
  and type(certificate['schema']) is int and certificate['schema']==1 and certificate['status']=='PASS_EXACT_CANONICAL_TRANSPORT_PROOF_DATA_ONLY'
  and _encoded(certificate['binding'])==_encoded(own) and certificate['source_map_sha256']==map_hash and certificate['canonical_helper_sha256']==CANONICAL_SHA)
 work=_path(certificate['work_root']);_need(work.name=='native-developer-work');evidence=work/'retained-transport-evidence';carrier=work.parent/'pgo-hosted-retained'
 record=certificate['canonical_receipt'];_need(type(record) is dict and set(record)=={'public_path','bytes','sha256'} and record['public_path']=='transport-proof/receipt.json')
 _pin_record({k:record[k] for k in ('bytes','sha256')},MAX_PROOF)
 raw=_safe(read(record['public_path']),MAX_PROOF);_need(_pin(raw)=={k:record[k] for k in ('bytes','sha256')} and _parse(raw)==receipt and raw==_encoded(receipt))
 _need(type(receipt) is dict and set(receipt)==RECEIPT_KEYS and type(receipt['schema_version']) is int and receipt['schema_version']==1
  and receipt['status']=='PASS_EXACT_RETAINED_GIT_DATA_ONLY' and receipt['source']==PROFILE_SOURCE and receipt['url']==PUBLIC and receipt['fixture'] is False
  and receipt['profile_sha256']==PROFILE_SHA and _encoded(receipt['policy'])==_encoded(POLICY)
  and type(receipt['file_count']) is int and receipt['file_count']==FILE_COUNT and type(receipt['material_bytes']) is int and receipt['material_bytes']==MATERIAL_BYTES
  and receipt['destination']==str(evidence) and receipt['data_path']==str(carrier) and receipt['retry'] is False and receipt['partial_data_retained'] is True)
 _need(all(receipt[k]=='NOT_RUN' for k in ('source_code_execution','signature_authentication','native_build'))
  and receipt['trust_admission'] is False and receipt['release_acceptance'] is False and receipt['fetch_seconds_shared'] is True
  and receipt['unselected_blobs']=='REFUSED' and receipt['history']=='REFUSED' and receipt['lazy_fetch']=='DISABLED'
  and receipt['acquisition_roles']==['metadata_fetch','required_blobs_fetch'] and receipt['full_namespace'] is True
  and type(receipt['blob_joins']) is int and receipt['blob_joins']==FILE_COUNT and type(receipt['materialized_files']) is int and receipt['materialized_files']==FILE_COUNT
  and receipt['acquisition_completed_within_shared400'] is True and type(receipt['elapsed_seconds']) in (int,float)
  and math.isfinite(receipt['elapsed_seconds']) and 0<=receipt['elapsed_seconds']<480)
 rows=receipt['commands'];_need(type(rows) is list and len(rows)==FILE_COUNT+10)
 public_indices=list(range(8))+[FILE_COUNT+8,FILE_COUNT+9];cert_rows=certificate['rows']
 _need(type(cert_rows) is list and all(type(r) is dict for r in cert_rows) and [r.get('index') for r in cert_rows]==public_indices)
 outputs={};total=len(raw)
 for info in cert_rows:
  index=info['index'];row=rows[index];_need(type(index) is int and type(info) is dict and set(info)=={'index','phase','stdout','stderr'} and info['phase']==row['phase'])
  for kind in ('stdout','stderr'):
   item=info[kind];source_path='logs/%04d.%s'%(index,kind);public_path='transport-proof/%04d.%s'%(index,kind)
   _need(type(item) is dict and set(item)=={'source_path','public_path','bytes','sha256'} and item['source_path']==source_path and item['public_path']==public_path)
   _pin_record({k:item[k] for k in ('bytes','sha256')},MAX_LOG);body=_safe(read(public_path),MAX_LOG);total+=len(body)
   _need(_pin(body)=={k:item[k] for k in ('bytes','sha256')} and row['raw_'+kind]==source_path)
   _pin_record(row[kind+'_pin'],MAX_LOG);_need(row[kind+'_pin']==_pin(body));outputs[index,kind]=body
   if kind=='stderr':_need(body==b'')
 _need(total+len(_encoded(certificate))<=MAX_PROOF)
 commit=outputs[3,'stdout'];_need(hashlib.sha1(b'commit '+str(len(commit)).encode()+b'\0'+commit).hexdigest()==PROFILE_SOURCE)
 first=commit.split(b'\n',1)[0];_need(first.startswith(b'tree ') and SHA1.fullmatch(first[5:].decode('ascii')))
 table=_table(outputs[4,'stdout'],files);tree,trees=_trees(table);_need(first==b'tree '+tree.encode() and receipt['tree']==tree)
 metadata={PROFILE_SOURCE:'commit',**{oid:'tree' for oid in trees}};required=sorted({r['oid'] for r in table.values()});complete=dict(metadata,**{oid:'blob' for oid in required})
 _need(receipt['metadata_object_inventory']==metadata==_inventory(outputs[5,'stdout']) and receipt['required_blob_oids']==required
  and receipt['object_inventory']==complete==_inventory(outputs[7,'stdout']))
 base,git,local,network=_git(carrier)
 expected=[('setup',base+['init','--bare','--object-format=sha1','--template=',str(carrier/'.git')]),
  ('metadata_fetch',network+['--depth=1',PUBLIC,PROFILE_SOURCE]),('metadata_proof',local+['rev-parse','--verify','FETCH_HEAD']),
  ('metadata_proof',local+['cat-file','commit',PROFILE_SOURCE]),('metadata_proof',local+['ls-tree','-rz','--full-tree',PROFILE_SOURCE]),
  ('metadata_proof',local+['cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype)']),
  ('required_blobs_fetch',network+['--no-write-fetch-head',PUBLIC,*required]),
  ('complete_object_proof',local+['cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype)'])]
 names=sorted(table)
 for name in names:expected.append(('all_required_materialization',local+['cat-file','blob',table[name]['oid']]))
 expected.extend([('final_namespace_proof',local+['update-ref','--no-deref','HEAD',PROFILE_SOURCE]),('final_namespace_proof',local+['rev-parse','--verify','HEAD'])])
 seconds=0;network_seconds=0
 for index,(row,(phase,argv)) in enumerate(zip(rows,expected)):
  _need(type(row) is dict and type(row['number']) is int and row['number']==index and row['phase']==phase and row['argv']==argv
   and row['evidence_root']==str(evidence) and row['data_root']==str(carrier) and row['role']==('NETWORK' if index in (1,6) else 'LOCAL_PROOF_OR_MATERIALIZATION'))
  elapsed=_supervision(row);seconds+=elapsed
  _pin_record(row['stderr_pin'],MAX_LOG)
  if index in (1,6):network_seconds+=elapsed
  if 8<=index<FILE_COUNT+8:
   name=names[index-8];oid=table[name]['oid'];mode=0o755 if table[name]['mode']=='100755' else 0o644
   _need(set(row)=={'number','argv','raw_stdout','raw_stderr','passed','supervision','stderr_pin','stdout_streams','stdout_material','phase','role','evidence_root','data_root'}
    and row['raw_stdout']=='data/'+name and row['raw_stderr']=='logs/%04d.stderr'%index and row['stderr_pin']==EMPTY
    and row['stdout_streams']=='BLOB_STDOUT; SEPARATE_STDERR' and _encoded(row['stdout_material'])==_encoded(dict(files[name],git_blob=oid,mode=mode)))
  else:
   _need(set(row)=={'number','argv','raw_stdout','raw_stderr','passed','supervision','stderr_pin','stdout_streams','stdout_pin','phase','role','evidence_root','data_root'}
    and row['stdout_streams']=='STDOUT_AND_STDERR_MERGED_AT_SPAWN')
 _need(network_seconds<400 and seconds<=receipt['elapsed_seconds']+0.000001 and outputs[2,'stdout'].strip()==PROFILE_SOURCE.encode()
  and outputs[FILE_COUNT+9,'stdout'].strip()==PROFILE_SOURCE.encode() and outputs[FILE_COUNT+8,'stdout']==b'')
 return True

def validate(certificate,canonical_receipt,profile,own,map_hash,read):
 try:return _validate(certificate,canonical_receipt,profile,own,map_hash,read)
 except (ValueError,TypeError,KeyError,IndexError,UnicodeError,OverflowError,RecursionError,OSError):raise ValueError('TRANSPORT_PROOF_REFUSED') from None


def _host_read(path,cap):
 info=path.lstat();_need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.getuid())
 return _safe(_ordinary(path,cap),cap)

def _write(fd,name,raw):
 descriptor=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
 try:
  os.fchmod(descriptor,0o600);view=memoryview(raw)
  while view:
   count=os.write(descriptor,view);_need(count>0);view=view[count:]
  os.fsync(descriptor)
 finally:os.close(descriptor)

def _export(work,own,map_hash,receipt,profile):
 work=_path(str(work));_need(work.name=='native-developer-work');_own(own,map_hash);_profile(profile)
 evidence=work/'retained-transport-evidence';_need(receipt.get('destination')==str(evidence))
 for path in (work,evidence):
  with _directory(path) as fd:
   info=os.fstat(fd);_need(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700)
 raw=_host_read(evidence/'receipt.json',MAX_PROOF);_need(_parse(raw)==receipt and raw==_encoded(receipt))
 data={'transport-proof/receipt.json':raw};rows=[];total=len(raw)
 for index,row in enumerate(receipt['commands']):
  _need(type(row) is dict and type(row.get('raw_stdout')) is str)
  if row['raw_stdout'].startswith('data/'):
   _pin_record(row['stderr_pin'],MAX_LOG);_need(row['stderr_pin']==EMPTY);continue
  item=dict(index=index,phase=row['phase'])
  for kind in ('stdout','stderr'):
   source_path='logs/%04d.%s'%(index,kind);public_path='transport-proof/%04d.%s'%(index,kind)
   _need(row['raw_'+kind]==source_path);body=_host_read(evidence/source_path,MAX_LOG);total+=len(body);_need(total<=MAX_PROOF)
   data[public_path]=body;item[kind]=dict(source_path=source_path,public_path=public_path,**_pin(body))
  rows.append(item)
 certificate=dict(schema=1,status='PASS_EXACT_CANONICAL_TRANSPORT_PROOF_DATA_ONLY',binding=_parse(_encoded(own)),source_map_sha256=map_hash,
  canonical_helper_sha256=CANONICAL_SHA,work_root=str(work),canonical_receipt=dict(public_path='transport-proof/receipt.json',**_pin(raw)),rows=rows)
 validate(certificate,receipt,profile,own,map_hash,data.__getitem__)
 with _directory(work,mutable=True) as fd:
  _need(not os.path.lexists(work/'transport-proof.json'));os.mkdir('transport-proof',0o700,dir_fd=fd)
  proof=os.open('transport-proof',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:
   for name,body in sorted(data.items()):_write(proof,Path(name).name,body)
   os.fsync(proof)
  finally:os.close(proof)
  _write(fd,'transport-proof.json',_encoded(certificate));os.fsync(fd)
 validate(certificate,receipt,profile,own,map_hash,lambda name:_host_read(work/name,MAX_PROOF if name.endswith('/receipt.json') else MAX_LOG))
 return certificate

def export(work,own,map_hash,receipt,profile):
 try:return _export(work,own,map_hash,receipt,profile)
 except (ValueError,TypeError,KeyError,IndexError,UnicodeError,OverflowError,RecursionError,OSError):raise ValueError('TRANSPORT_PROOF_REFUSED') from None
