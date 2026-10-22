# SPDX-License-Identifier: MIT
"""Original signed sysusers fixture and bounded live auxiliary-cache transitions.

No account or cache prefix exemption. Every raw cache byte is retained, and each
saved key is joined to a stable descriptor of its complete observed library.
"""
import base64,json,os,stat
from pathlib import Path
import contract as C
import audio_aux as A
ACCOUNTS=tuple('etc/'+n+s for n in('passwd','shadow','group','gshadow')for s in('','-'))
AUX='var/cache/ldconfig/aux-cache'
SCRIPT_PIN=dict(bytes=2247,sha256='a726c5ae26164ccbbc7036daa7b00f3b0cc06f4d1bfa18aabc771c51b7c2081a')
NEW={'passwd':{'avahi','git','pcscd','polkitd'},'shadow':{'avahi','git','pcscd','polkitd'},'group':{'polkitd','seat','avahi','git','pcscd'},'gshadow':{'polkitd','seat','avahi','git','pcscd'}}
BASE_SHELL='cd /; source /tmp/core-systemd.install; post_upgrade "$1" "$2"; /usr/bin/ldconfig'

def baseline_argv(root,version):
 return ['/usr/bin/chroot',str(root),'/usr/bin/bash','--noprofile','--norc','-e','-x','-c',BASE_SHELL,'original-complete-systemd-baseline',version,version]

def accounts(root):
 result={}
 for name in ACCOUNTS:
  raw=C.read(Path(root)/name,65536);lines=raw.splitlines(keepends=True);records={}
  C.need(lines and all(l.endswith(b'\n')and b'\0'not in l for l in lines),'complete ordinary account lines')
  for line in lines:
   key=line.split(b':',1)[0].decode('ascii');C.need(key and key not in records and b':'in line,'unique typed account names');records[key]=C.pin(line)
  result[name]=dict(file=C.pin(raw),data=base64.b64encode(raw).decode(),records=records)
 return result

def verify_accounts(value):
 C.need(set(value)==set(ACCOUNTS),'complete private disposable account capture')
 for name,row in value.items():
  raw=base64.b64decode(row['data'],validate=True);C.need(0<len(raw)<=65536 and C.pin(raw)==row['file'],'whole bounded original disposable account bytes')
  lines=raw.splitlines(keepends=True);records={}
  for line in lines:
   C.need(line.endswith(b'\n')and b'\0'not in line and b':'in line,'complete account line');key=line.split(b':',1)[0].decode('ascii');C.need(key and key not in records,'unique account key');records[key]=C.pin(line)
  C.need(records==row['records'],'complete account line/full-file join')
 return value

def initialized_accounts(before,after):
 verify_accounts(before);verify_accounts(after)
 for name in ACCOUNTS:
  old,new=before[name],after[name];C.need(type(old['records'])is type(new['records'])is dict,'typed account record maps')
  if name.endswith('-'):continue
  C.need(all(new['records'].get(k)==v for k,v in old['records'].items()),'every pre-existing user/group record byte preserved')
  added=set(new['records'])-set(old['records']);C.need(added<=NEW[Path(name).name],'only exact source-owned missing original service accounts')
  if added:C.need(after[name+'-']['file']==old['file'],'sysusers exact previous active account backup')
 return dict(status='ORIGINAL_SIGNED_SYSUSERS_INITIALIZED_PREEXISTING_RECORDS_HELD',added={n:sorted(set(after[n]['records'])-set(before[n]['records']))for n in ACCOUNTS if not n.endswith('-')})

def read_aux(root):
 # All ancestors are ordinary and C.read is singlelink/bounded. Live post-read
 # graph joins and the descriptor-only capture below independently revalidate it.
 path=Path(root)/AUX;C.need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary fixed auxiliary path')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  info=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  C.need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==info.st_gid==0 and 0<info.st_size<=A.LIMIT,'exact root0600 bounded auxiliary')
  raw=bytearray()
  while len(raw)<=info.st_size:
   block=os.read(fd,min(65536,info.st_size-len(raw)+1))
   if not block:break
   raw.extend(block)
  C.need(len(raw)==info.st_size and key(info)==key(os.fstat(fd))==key(path.lstat()),'whole auxiliary descriptor/path stability');A.parse(bytes(raw));return bytes(raw)
 finally:os.close(fd)

def capture(api,root,graph,limits,raw):
 """Match every record key to a nofollow, same-mount, full-hash library read."""
 import aux_checkpoint
 reader=aux_checkpoint.Reader(root,graph,limits);aux=reader.capture(AUX,data_limit=A.LIMIT);C.need(aux.pop('data')==raw,'complete cache/graph/raw byte join')
 C.need(graph['nodes'].get('usr/bin/ldconfig')==dict(type='file',mode=0o755,uid=0,gid=0,bytes=865664,sha256=A.HELPER_SHA256),'exact original signed helper node')
 records=A.parse(raw);wanted={key for key,_ in records};matches={};nodes=graph['nodes'];roots=api['roots'];copy=api['copy'].measure_copy
 with copy._descriptors()as held:
  descriptor=roots._open_root(root);held.append(descriptor);rootid=roots._identity(os.fstat(descriptor));mount=roots._mount_id(descriptor,limits)
  for name,node in nodes.items():
   limits.tick()
   if not(name.startswith('usr/lib/')and node.get('type')=='file'):continue
   with copy._parent(descriptor,name,mount,{},limits,nodes)as(parent,leaf):
    info=os.stat(leaf,dir_fd=parent,follow_symlinks=False);key=(info.st_ino,info.st_ctime_ns//10**9,info.st_size,info.st_dev)
    if key not in wanted:continue
    # Reader.literal reopens and hashes the entire observed library, verifies
    # metadata, aliases, mount and identity; do not trust this preceding stat.
    row=reader.literal(name);identity=row['identity'];actual=(identity[1],identity[8]//10**9,identity[6],identity[0]);C.need(actual==key,'live cache key did not race');matches.setdefault(key,[]).append(dict(path=name,identity=list(identity),node=nodes[name]))
  copy._root_check(root,descriptor,rootid,mount,limits)
 C.need(set(matches)==wanted,'every auxiliary record has an actual observed live library key')
 return dict(raw=C.pin(raw),data=base64.b64encode(raw).decode(),libraries=[dict(key=list(k),files=matches[k])for k in sorted(matches)])

def check_record(record,nodes):
 C.need(nodes.get('usr/bin/ldconfig')==dict(type='file',mode=0o755,uid=0,gid=0,bytes=865664,sha256=A.HELPER_SHA256),'whole original helper remains pinned');raw=base64.b64decode(record['data'],validate=True);C.need(C.pin(raw)==record['raw']and len(raw)<=A.LIMIT,'whole bounded retained cache bytes');keys={key for key,_ in A.parse(raw)};seen=set()
 C.need(nodes.get(AUX)==dict(type='file',mode=0o600,uid=0,gid=0,**C.pin(raw)),'complete observed auxiliary raw/metadata join')
 for row in record['libraries']:
  key=tuple(row['key']);C.need(key in keys and key not in seen and row['files'],'exact nonempty unique live-key evidence');seen.add(key)
  for item in row['files']:
   info=item['identity'];name=item['path'];C.need(name.startswith('usr/lib/')and nodes.get(name)==item['node']and item['node']['type']=='file'and len(info)==9 and key==(info[1],info[8]//10**9,info[6],info[0])and info[6]==item['node']['bytes'],'complete full-hash library node/physical key join')
 C.need(seen==keys,'no stale or omitted auxiliary key');return raw

def cache_pair(before,after,nodes):
 raw=check_record(after,nodes);prior=base64.b64decode(before['data'],validate=True);C.need(C.pin(prior)==before['raw'],'whole prior cache bytes');result=A.compare(prior,raw)
 C.need({key for key,_ in A.parse(prior)}=={key for key,_ in A.parse(raw)},'same observed live cache keys under original helper idempotence');return result

def changes(before,after,packages,versions,sidecars,proof):
 check_record(proof,after);return C.changes(before,after,packages,versions,set(sidecars)|{AUX})

def initialization(source,first,initial,proof,fixtures):
 C.need(proof['script']==SCRIPT_PIN,'same authenticated original systemd262-1 INSTALL body');C.need(set(proof)=={'before_accounts','after_accounts','second_accounts','account_transition','first_cache','second_cache','cache_idempotence','script'},'closed original baseline initialization proof')
 C.need(proof['account_transition']==initialized_accounts(proof['before_accounts'],proof['after_accounts'])and proof['second_accounts']==proof['after_accounts'],'original sysusers initialization is byte-idempotent on every account/backup')
 for n in ACCOUNTS:
  C.need({k:v for k,v in source[n].items()if k not in('bytes','sha256')}=={k:v for k,v in first[n].items()if k not in('bytes','sha256')},'baseline account full metadata held')
  C.need(proof['before_accounts'][n]['file']=={k:source[n][k]for k in('bytes','sha256')}and proof['after_accounts'][n]['file']=={k:first[n][k]for k in('bytes','sha256')}and initial[n]==first[n],'all eight account raw hashes/full node joins')
 check_record(proof['first_cache'],first);C.need(proof['cache_idempotence']==cache_pair(proof['first_cache'],proof['second_cache'],initial),'original signed helper load/save idempotence')
 C.changes(source,first,[],[],set(fixtures)|set(ACCOUNTS)|{AUX});C.changes(first,initial,[],[],{AUX});return True


def save_record(directory,label,record):
 C.need(label in {case+'-'+phase for case in C.CASES for phase in('fixture-first','initial',*C.STAGES[1:])},'fixed finite cache proof label');path=Path(directory)/(label+'-aux.json');raw=C.encoded(record);C.need(len(raw)<=4*1024**2 and sum(p.stat().st_size for p in Path(directory).iterdir()if p.is_file())+len(raw)<=512*1024**2 and not path.exists(),'fresh bounded full cache proof')
 with path.open('xb')as stream:stream.write(raw)
 return dict(file=path.name,**C.pin(raw))

def load_record(directory,ref):
 C.need(set(ref)=={'file','bytes','sha256'}and type(ref['file'])is str and ref['file']in {case+'-'+phase+'-aux.json'for case in C.CASES for phase in('fixture-first','initial',*C.STAGES[1:])},'exact passive cache role');raw=C.read(Path(directory)/ref['file'],4*1024**2);C.need(C.pin(raw)=={k:ref[k]for k in('bytes','sha256')},'whole source-owned retained cache proof');return json.loads(raw)

def expand_initialization(directory,proof):
 return dict(proof,first_cache=load_record(directory,proof['first_cache']),second_cache=load_record(directory,proof['second_cache']))

def replay(directory,maps,case,row,original_script=None):
 proof=expand_initialization(directory,row['baseline_initialization']);C.need(proof['script']==(SCRIPT_PIN if original_script is None else C.pin(original_script)),'whole authenticated ORIGINAL post_upgrade body baseline');initial=maps[case+'-initial']['nodes'];initialization(maps[case+'-source-before']['nodes'],maps[case+'-fixture-first']['nodes'],initial,proof,C.FIXTURES)
 C.need(set(row['cache_transitions'])==set(C.STAGES[1:]),'all five stage auxiliary proofs')
 for phase in C.STAGES[1:]:
  v=row['cache_transitions'][phase];after=load_record(directory,v['after']);C.need(v['idempotence']==cache_pair(v['before'],after,maps[case+'-'+phase]['nodes']),'exact actual original helper cache idempotence')
 return True
