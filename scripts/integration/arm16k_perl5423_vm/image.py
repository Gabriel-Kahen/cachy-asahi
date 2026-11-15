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
  nodes=r.inventory()['nodes'];records={}
  for name,row in nodes.items():
   if name.startswith('var/lib/pacman/local/') and name.rsplit('/',1)[-1] in ('desc','files'):
    K.need(row['type']=='file' and row['size']<=4*1024**2,'bounded ordinary ALPM text')
    fields,data=r.inode(row['inode']);raw=b''.join(r.chunks(fields,data));K.need(hashlib.sha256(raw).hexdigest()==row['sha256'],'ALPM text hash')
    records[name]=raw.decode()
 return dict(nodes=nodes,records=records,filesystem_free_bytes=free_bytes)


def stable(row):
 # Timestamps/inode allocation vary across normal ALPM. Permissions, ownership,
 # link target, xattrs and every regular file byte remain exact requirements.
 return {n:v for n,v in row.items() if n in ('type','mode','uid','gid','sha256','target_b64','xattrs')}


def fields(raw):
 result={};key=None
 for line in raw.splitlines():
  if line.startswith('%') and line.endswith('%'):
   key=line[1:-1]
   if key in result:raise ValueError('duplicate ALPM field')
   result[key]=[]
  elif line:
   if key is None:raise ValueError('ALPM value without field')
   result[key].append(line)
 return result


def owners(scan,inventory):
 K=module('contracts');found={};owned={};records=scan['records'];nodes=scan['nodes']
 for path,text in records.items():
  if not path.endswith('/desc'):continue
  desc=fields(text);name,version=desc['NAME'],desc['VERSION'];K.need(len(name)==len(version)==1 and name[0] not in found,'unique ALPM package')
  found[name[0]]=version[0]
  for p in fields(records[path[:-4]+'files'])['FILES']:
   p=p.rstrip('/');K.guest_path('/'+p);K.need(p in nodes,'owned path exists')
   owned.setdefault(p,[]).append(name[0])
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


def preserve(before,after,inventory):
 K=module('contracts');a=owners(before,inventory);b=owners(after,inventory);K.need(a==b,'complete baseline ALPM ownership and bytes changed')
 for path,row in before['nodes'].items():
  if path.startswith(('root/','home/builder/','etc/','var/lib/pacman/local/')) or path in ('root','home/builder'):
   K.need(stable(after['nodes'].get(path,{}))==stable(row),'baseline user/platform/database preservation: '+path)
 for path in after['nodes'].keys()-before['nodes'].keys():
  K.need(not path.startswith(('root/','home/builder/','usr/','etc/','var/lib/pacman/local/')),'unreviewed residue outside case-owned storage')
 return dict(status='PASS_COMPLETE_BASELINE_AND_USER_PRESERVATION',packages=len(inventory),owned_paths=len(a))
