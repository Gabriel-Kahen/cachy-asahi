# SPDX-License-Identifier: MIT
"""Bounded ext4 DATA scan and exact baseline ownership; no artifact imports."""
import base64
import hashlib
import time
import importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent

def module(n):
 s=importlib.util.spec_from_file_location('perl_image_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def scan(path,deadline,guard):
 K=module('contracts');F=K.helper('independent_readback.py')
 class Reader(F.Ext4Reader):
  def read(self,offset,length):
   if time.monotonic()>=deadline:raise TimeoutError('finite readonly scan deadline')
   guard();return super().read(offset,length)
 with Reader(K.ordinary(path),max_nodes=150000,max_file_bytes=256*1024**2)as r:
  sb=r.read(1024,1024);free_blocks=F.u32(sb,12)|(F.u32(sb,344)<<32 if r.incompat&0x80 else 0)
  free_bytes=free_blocks*4096
  nodes=r.inventory()['nodes'];records={};log_data=None;retained_log=None
  for name,row in nodes.items():
   if name=='var/log/pacman.log':
    K.need(row['type']=='file' and row['size']<=8*1024**2,'bounded ordinary pacman log')
    f,d=r.inode(row['inode']);log_data=base64.b64encode(b''.join(r.chunks(f,d))).decode()
   if name=='var/lib/arm16k-perl5423-vm/receipts/pacman-log-after':
    K.need(row['type']=='file' and row['size']<=24*1024**2,'bounded retained normal transaction log')
    f,d=r.inode(row['inode']);body=b''.join(r.chunks(f,d));K.need(hashlib.sha256(body).hexdigest()==row['sha256'],'retained transaction log hash');retained_log=base64.b64encode(body).decode()
   if name.startswith('var/lib/pacman/local/') and name.rsplit('/',1)[-1] in ('desc','files'):
    K.need(row['type']=='file' and row['size']<=4*1024**2,'bounded ordinary ALPM text')
    fields,data=r.inode(row['inode']);raw=b''.join(r.chunks(fields,data));K.need(hashlib.sha256(raw).hexdigest()==row['sha256'],'ALPM text hash')
    records[name]=raw.decode()
 return dict(nodes=nodes,records=records,filesystem_free_bytes=free_bytes,log_data_b64=log_data,retained_log_data_b64=retained_log)


def stable(row):
 # Timestamps/inode allocation vary across normal ALPM. Permissions, ownership,
 # link target, xattrs and every regular file byte remain exact requirements.
 return {n:v for n,v in row.items() if n in ('type','mode','uid','gid','sha256','target_b64','xattrs') or row.get('type')!='directory' and n in ('mtime','mtime_ns')}


def fields(raw):
 if type(raw)is not str or any(ord(c)<32 and c not in '\n\t' or ord(c)==127 for c in raw):raise ValueError('literal LF ALPM text required')
 result={};key=None
 for line in raw.split('\n'):
  if line.startswith('%') and line.endswith('%'):
   key=line[1:-1]
   if key in result:raise ValueError('duplicate ALPM field')
   result[key]=[]
  elif line:
   if key is None:raise ValueError('ALPM value without field')
   result[key].append(line)
 return result


def ownership_key(value):
 # ALPM DATA keys are not shell/command operands. Preserve punctuation and
 # literal backslashes; never unescape, normalize, resolve aliases or execute.
 if not(type(value)is str and 0<len(value.encode())<=4096 and not any(ord(c)<32 or ord(c)==127 for c in value)):raise ValueError('bounded literal ALPM ownership key')
 path=value[:-1]if value.endswith('/')else value
 if path.startswith('/') or not all(p not in('','.','..')for p in path.split('/')):raise ValueError('relative ALPM ownership key without traversal or empty components')
 return path


def owned_paths(raw):
 if raw=='':return [] # Exact byte-empty metadata package: no owned paths.
 value=fields(raw)
 module('contracts').need('FILES'in value and bool(value['FILES']),'nonempty ALPM files record requires FILES paths')
 paths=[ownership_key(p)for p in value['FILES']]
 module('contracts').need(len(paths)==len(set(paths)),'unique literal ownership keys per package')
 return paths


def owners(scan,inventory):
 K=module('contracts');found={};owned={};records=scan['records'];nodes=scan['nodes']
 for path,text in records.items():
  if not path.endswith('/desc'):continue
  desc=fields(text);name,version=desc.get('NAME',[]),desc.get('VERSION',[]);K.need(len(name)==len(version)==1 and name[0] not in found,'unique nonempty ALPM package description')
  found[name[0]]=version[0]
  K.need(path[:-4]+'files'in records,'actual ALPM files record exists')
  for p in owned_paths(records[path[:-4]+'files']):
   K.need(p in nodes,'literal owned path exists without alias substitution')
   owned.setdefault(p,[]).append(name[0])
 K.need(set(records)=={p[:-4]+n for p in records if p.endswith('/desc')for n in('desc','files')},'complete paired actual ALPM records')
 K.need(found==inventory,'exact actual complete baseline ALPM inventory')
 return {p:dict(owners=sorted(v),inode=stable(nodes[p]))for p,v in sorted(owned.items())}


def qualify(scan,files,owned):
 K=module('contracts');nodes=scan['nodes']
 for path,row in files.items():
  p=path.lstrip('/');target=row['resolved'].lstrip('/');seen=set()
  for _ in range(32):
   if p in seen:raise ValueError('image alias cycle')
   seen.add(p);parts=p.split('/');changed=False
   for i in range(1,len(parts)+1):
    q='/'.join(parts[:i]);node=nodes.get(q);K.need(node is not None,'runtime path missing')
    if node['type']=='symlink':
     import posixpath
     alias=base64.b64decode(node['target_b64'],validate=True).decode()
     p=posixpath.normpath(posixpath.join(alias if alias.startswith('/') else '/'+posixpath.dirname(q)+'/'+alias,*parts[i:])).lstrip('/');changed=True;break
   if not changed:break
  else:raise ValueError('image alias depth')
  node=nodes.get(p,{})
  K.need(p==target and node.get('type')=='file' and node['size']==row['bytes'] and node['sha256']==row['sha256'] and node['mode']==row['mode'] and row['owner'] in owned.get(path.lstrip('/'),owned.get(p,{})).get('owners',[]),'actual runtime path/hash/mode/ALPM owner join')


def preserve(before,after,inventory,runtime):
 K=module('contracts');N=module('restoration');allow=runtime['restoration_allowances']
 date_path=allow['install_date_path'];date_path=date_path.lstrip('/') if date_path else None
 allowed_times={p.lstrip('/')for p in allow['database_timestamp_paths']}
 allowed_dirs={p.lstrip('/')for group in ('candidate_namespace','baseline_namespace')for p,row in runtime[group].items()if row['kind']=='d'}
 if runtime['dependency_transaction']:allowed_dirs|={p.lstrip('/')for p,row in runtime['dependency_transaction']['namespace'].items()if row['kind']=='d'}
 allowed_dirs|={p.lstrip('/')for p in allow['cache_directory_timestamps']}|allowed_times
 dates=N.comparison(before['records'][date_path].encode(),after['records'][date_path].encode())if date_path else None
 log=allow['normal_pacman_log'].lstrip('/')
 original=base64.b64decode(before['log_data_b64'],validate=True)if before.get('log_data_b64')is not None else None
 if allow['pacman_log_before'] is None:
  allowed_dirs.add('var/log') # Only the parent mtime from create/remove of the certified absent normal log.
  K.need(original is None and log not in before['nodes'] and log not in after['nodes'] and after.get('log_data_b64')is None,'certified baseline pacman log absence restored')
  receipt='var/lib/arm16k-perl5423-vm/receipts/pacman-log-after';row=after['nodes'].get(receipt,{})
  K.need(after.get('retained_log_data_b64')is not None and row.get('type')=='file' and row.get('mode')==0o600 and row.get('uid')==row.get('gid')==0,'actual safe retained transaction log for absent baseline log')
  retained=base64.b64decode(after['retained_log_data_b64'],validate=True)
  K.need(retained and len(retained)==row.get('size') and hashlib.sha256(retained).hexdigest()==row.get('sha256'),'actual retained normal transaction log bytes/hash')
 else:
  K.need(original is not None and dict(bytes=len(original),sha256=hashlib.sha256(original).hexdigest())==allow['pacman_log_before'],'certified actual baseline log bytes')
  K.need(after.get('log_data_b64')is not None and after['nodes'].get(log,{}).get('type')=='file' and after['nodes'][log]['uid']==after['nodes'][log]['gid']==0 and not after['nodes'][log]['mode']&0o6002,'actual safe ordinary final pacman log')
  K.need(base64.b64decode(after['log_data_b64'],validate=True).startswith(original),'normal pacman log append-only preservation')
 def normalized(scan,path):
  row=stable(scan['nodes'].get(path,{}))
  if path==date_path:
   body,_=N.normalize_desc(scan['records'][path].encode());row['sha256']=hashlib.sha256(body).hexdigest()
  if path in allowed_times or path==log:
   row.pop('mtime',None);row.pop('mtime_ns',None)
  if path==log:row['sha256']='CERTIFIED_APPEND_ONLY_LOG'
  return row
 a,b=owners(before,inventory),owners(after,inventory)
 K.need(a.keys()==b.keys(),'complete baseline ALPM ownership set')
 for path,row in a.items():
  K.need(row['owners']==b[path]['owners'] and normalized(before,path)==normalized(after,path),'baseline owned file bytes/mode/owner/version/time: '+path)
 compared=set(a)|{p for p in before['nodes']if p.startswith(('root/','home/builder/','etc/','var/lib/pacman/local/','var/lib/arm16k-perl5423-vm/'))or p in ('root','home/builder','var/lib/pacman/local',log)}
 changed_times=[]
 for path in sorted(compared):
  row=before['nodes'][path]
  if path=='var/lib/arm16k-perl5423-vm/trust':continue
  current=after['nodes'].get(path,{})
  K.need(normalized(before,path)==normalized(after,path),'baseline user/platform/database/fixture bytes and metadata: '+path)
  changed=any(row.get(n)!=current.get(n)for n in ('mtime','mtime_ns'))
  if changed:
   K.need(path in allowed_times or path==log or row['type']=='directory' and (path in allowed_dirs or path.startswith('var/lib/arm16k-perl5423-vm/')),'unrelated baseline timestamp drift: '+path)
   changed_times.append(path)
 for path in after['nodes'].keys()-before['nodes'].keys():
  K.need(not path.startswith(('root/','home/builder/','usr/','etc/','var/lib/pacman/local/','var/log/')),'unreviewed user/payload/database/log residue')
 return dict(status='PASS_COMPLETE_BASELINE_AND_USER_PRESERVATION',packages=len(inventory),owned_paths=len(a),normal_install_date=dates,normal_timestamp_differences=changed_times,pacman_log='ABSENCE_RESTORED_WITH_RETAINED_NORMAL_TRANSACTION_LOG'if original is None else'ORIGINAL_BYTES_PLUS_APPEND_ONLY',account_user_residuals=[])
