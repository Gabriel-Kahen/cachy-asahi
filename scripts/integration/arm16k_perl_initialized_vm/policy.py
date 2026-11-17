# SPDX-License-Identifier: MIT
"""Opt-in initialized state; preserve exact existing nodes, never remove or repair."""
import importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('initialized_ssh_empty',HERE/'ssh_empty.py');EMPTY=importlib.util.module_from_spec(s);s.loader.exec_module(EMPTY)
PUBLIC=(('etc/.pwd.lock','file',0o600),('etc/.updated','file',0o644),('etc/audisp','directory',0o755),('etc/audit/plugins.d','directory',0o750),('etc/audit/rules.d','directory',0o755),('etc/ld.so.cache','file',0o644),('etc/os-release','symlink',0o777),('etc/udev/hwdb.bin','file',0o444),('etc/vconsole.conf','file',0o644))
PARENTS=('etc','etc/audit','etc/udev','root')
FIELDS=('inode','links','type','mode','uid','gid','size','xattrs','mtime','mtime_ns')

def need(ok,why):
 if not ok:raise ValueError(why)

def node(row):
 need(type(row)is dict and row.get('type')in ('file','directory','symlink') and type(row.get('xattrs'))is dict,'complete initialized inode metadata')
 need(all(type(row.get(k))is int for k in FIELDS if k not in('type','xattrs')),'integer initialized inode metadata')
 need(all(type(k)is type(v)is str for k,v in row['xattrs'].items()),'exact initialized xattr encoding')
 need(1<=row['inode']<=2**32-1 and 1<=row['links']<=65535 and 0<=row['mode']<=0o7777 and 0<=row['size']<=256*1024**2 and 0<=row['mtime_ns']<=999999999,'bounded exact initialized inode metadata')
 result={k:row[k]for k in FIELDS};result['xattrs']=dict(row['xattrs'])
 if row['type']=='file':
  value=row.get('sha256');need(type(value)is str and len(value)==64 and all(c in'0123456789abcdef'for c in value),'complete initialized public file hash');result['sha256']=value
 elif row['type']=='symlink':
  value=row.get('target_b64');need(type(value)is str and value,'complete initialized public symlink target');result['target_b64']=value
 return result

def snapshot(scan):
 need(type(scan)is dict and type(scan.get('nodes'))is dict,'complete qualified initialized scan')
 proof=scan.get('root_ssh_empty_proof');bound=EMPTY.require_empty(proof);nodes=scan['nodes'];ssh=nodes.get('root/.ssh',{})
 need(EMPTY.metadata(ssh)==bound and not any(p.startswith('root/.ssh/')for p in nodes),'same empty selected inode and no private descendants')
 public={}
 for path,kind,mode in PUBLIC:
  row=node(nodes.get(path));need(row['type']==kind and row['mode']==mode and row['uid']==row['gid']==0,'exact initialized public state: '+path);public[path]=row
 parents={}
 for path in PARENTS:
  row=node(nodes.get(path));need(row['type']=='directory' and row['mode']==(0o700 if path=='root'else 0o755) and row['uid']==row['gid']==0,'exact initialized parent state: '+path);parents[path]=row
 need(nodes['root']['inode']==proof['parent_inode'],'same literal root parent')
 return dict(kind='INITIALIZED_PUBLIC9_AND_EMPTY_ROOT_SSH_STATE_V1',public_nodes=public,parents=parents,root_ssh=node(ssh))

def preserve(before,after,inventory,runtime,legacy):
 # Existing complete ownership/payload/user/database and allowance checks still run.
 result=legacy.image.preserve(before,after,inventory,runtime)
 legacy.preboot.preserve_etc(legacy.contracts,before,after)
 need(snapshot(before)==snapshot(after),'exact initialized public9/parents/empty SSH bytes, inode, links, xattrs and mtime preserved without repair')
 return dict(status='PASS_INITIALIZED_STATE_PRESERVATION_DATA_ONLY',legacy=result,Root_acceptance=None,Perl_preservation=None,VM_acceptance=None,M2=None,release=None)
