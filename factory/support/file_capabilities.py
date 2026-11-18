# SPDX-License-Identifier: MIT
"""Exact Linux file-capability metadata for an externally pinned complete node graph.

No transaction/source authority is created here. The owner must supply its
immutable original snapshot/map and exclusively owned copied-root node graph.
Only security.capability is understood; unknown xattrs/ACLs refuse. Capability
files are hashed against nodes; full_root remains responsible for all payload
hashes. Values are the exact bytes visible in the calling user namespace: Linux
may translate rev2/rev3 across namespaces, and mismatches must never be normalized.

validate(bytes) -> {revision:int,effective:bool,permitted:uint64,
                   inheritable:uint64,rootid:None|uint32}
pax_value(str) -> exact bytes (UTF8/surrogateescape, never Latin1/base64 fallback)
observe(root,nodes,limits) -> {relative_path:lowercase_hex}
restore(root,nodes,mapping,limits) -> independently observed identical map
"""
import contextlib,hashlib,json,os,re,stat,struct
from pathlib import Path,PurePosixPath

ATTR='security.capability'
PAX='SCHILY.xattr.security.capability'
MAX_CAPS=4096
MAX_MAP_BYTES=1024**2
MAX_NODES=500000
MAX_PATH=4096
FLAGS=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK


def need(ok,message):
 if not ok:raise ValueError(message)


def validate(raw):
 """Linux UAPI vfs_cap_data/ns_cap_data: exact LE layout, effective flag only.

The 64 capability bits are retained verbatim, without inventing a path/bit
allowlist. Revision3's UINT32_MAX is not a valid root UID. Revision1 and unknown
revisions/flags are unsupported. No granted-capability or execution claim follows.
"""
 need(type(raw) is bytes and len(raw) in (20,24),'capability revision2/3 exact byte count required')
 words=struct.unpack('<'+'I'*(len(raw)//4),raw);magic=words[0];revision=magic>>24
 need(revision in (2,3) and len(raw)==(20 if revision==2 else 24) and magic in (revision<<24,(revision<<24)|1),'unsupported capability revision/flags/layout')
 rootid=None if revision==2 else words[5]
 need(rootid!=0xffffffff,'invalid capability root UID')
 return dict(revision=revision,effective=bool(magic&1),permitted=words[1]|words[3]<<32,
             inheritable=words[2]|words[4]<<32,rootid=rootid)


def pax_value(text):
 need(type(text) is str and len(text)<=24,'bounded parsed capability PAX text required')
 try:raw=text.encode('utf-8','surrogateescape')
 except UnicodeError as error:raise ValueError('invalid capability PAX encoding') from error
 validate(raw);return raw


def _path(name,limits):
 need(type(name) is str and name and len(name.encode('utf-8','surrogateescape'))<=MAX_PATH and '\0' not in name and not any(ord(c)<32 for c in name),'bounded ordinary node path required')
 path=PurePosixPath(name)
 need(not path.is_absolute() and path.as_posix()==name and all(p not in ('.','..') for p in path.parts) and len(path.parts)<=limits.max_depth+1,'contained canonical node path required')
 return path.parts


def _graph(nodes,limits):
 limits.tick();need(type(nodes) is dict and len(nodes)<=min(MAX_NODES,limits.max_nodes),'complete bounded node graph required')
 children={'':[]};groups={};total=0
 for name,row in nodes.items():
  limits.tick();parts=_path(name,limits);need(type(row) is dict and row.get('type') in ('file','directory','symlink'),'unsupported node type')
  for key in ('mode','uid','gid'):need(type(row.get(key)) is int and 0<=row[key]<=(0o7777 if key=='mode' else 0xffffffff),'invalid pinned node metadata')
  parent='/'.join(parts[:-1]);need(not parent or nodes.get(parent,{}).get('type')=='directory','missing/linked node parent')
  children.setdefault(parent,[]).append(parts[-1])
  if row['type']=='directory':children.setdefault(name,[])
  elif row['type']=='file':
   need(type(row.get('bytes')) is int and 0<=row['bytes']<=min(limits.max_file_bytes,limits.max_bytes) and type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'pinned regular file contents required')
   total+=row['bytes'];need(total<=limits.max_bytes,'node graph byte bound')
   if 'hardlink_group' in row:
    tag=row['hardlink_group'];_path(tag,limits);groups.setdefault(tag,[]).append(name)
  else:need(type(row.get('target')) is str and '\0' not in row['target'] and len(row['target'].encode('utf8','surrogateescape'))<=MAX_PATH,'pinned symlink target required')
 need(len(groups)<=limits.max_hardlink_groups and sum(map(len,groups.values()))<=limits.max_hardlink_aliases,'hardlink group bound')
 for tag,members in groups.items():
  limits.tick();need(2<=len(members)<=limits.max_hardlink_members and tag==min(members),'closed canonical hardlink group required')
  first={k:v for k,v in nodes[tag].items() if k!='hardlink_group'}
  need(all({k:v for k,v in nodes[n].items() if k!='hardlink_group'}==first for n in members),'hardlink node metadata differs')
 return children,groups


def validate_map(nodes,mapping,limits):
 _,groups=_graph(nodes,limits)
 need(type(mapping) is dict and len(mapping)<=MAX_CAPS,'bounded capability map required')
 for name,value in mapping.items():
  limits.tick();_path(name,limits)
  need(name in nodes and nodes[name]['type']=='file' and type(value) is str and re.fullmatch('(?:[0-9a-f]{40}|[0-9a-f]{48})',value),'capability map must bind regular nodes and exact lowercase hex')
  validate(bytes.fromhex(value))
 for members in groups.values():
  selected=set(members)&mapping.keys()
  need(not selected or selected==set(members) and len({mapping[n] for n in members})==1,'capability hardlink aliases must all agree')
 result={n:mapping[n] for n in sorted(mapping)}
 need(len((json.dumps(result,sort_keys=True,indent=2)+'\n').encode())<=MAX_MAP_BYTES,'capability map byte bound')
 return result


def _identity(info):
 return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _mount(fd,limits):
 limits.tick()
 with open('/proc/self/fdinfo/'+str(fd),'rb') as stream:raw=stream.read(4097)
 found=[line.split(b':',1)[1].strip() for line in raw.splitlines() if line.startswith(b'mnt_id:')]
 need(len(raw)<=4096 and len(found)==1 and found[0].isdigit(),'bounded mount identity required')
 return int(found[0])


@contextlib.contextmanager
def _root(path,limits):
 path=Path(path);need(path.is_absolute() and '..' not in path.parts,'absolute root required')
 fd=os.open('/',FLAGS|os.O_DIRECTORY)
 try:
  for part in path.parts[1:]:
   limits.tick();child=os.open(part,FLAGS|os.O_DIRECTORY,dir_fd=fd);os.close(fd);fd=child
  yield fd
 finally:os.close(fd)


def _attrs(fd,kind,limits,parent=None,name=None):
 limits.tick();target=fd if kind!='symlink' else '/proc/self/fd/'+str(parent)+'/'+name
 options={} if kind!='symlink' else dict(follow_symlinks=False)
 names=os.listxattr(target,**options)
 need(len(names)==len(set(names)) and set(names)<={ATTR},'unknown xattr/ACL metadata refused')
 if not names:return None
 need(kind=='file','capability on nonregular node refused')
 limits.tick();raw=os.getxattr(target,ATTR,**options);validate(raw)
 need(os.listxattr(target,**options)==names,'xattr names changed during observation')
 return raw.hex()


def _hash(fd,row,limits):
 limits.tick();os.lseek(fd,0,os.SEEK_SET);total=0;hashed=hashlib.sha256()
 while True:
  limits.tick();raw=os.read(fd,min(1024**2,row['bytes']-total+1))
  if not raw:break
  total+=len(raw);need(total<=row['bytes'],'capability file grew');hashed.update(raw)
 need(total==row['bytes'] and hashed.hexdigest()==row['sha256'],'capability file contents differ')


def _scan(root,nodes,limits,mutate=None,expected=None):
 children,groups=_graph(nodes,limits);result={};identities={};inodes={};hashed=set()
 with _root(root,limits) as rootfd:
  root_before=_identity(os.fstat(rootfd));mount=_mount(rootfd,limits)
  need(_attrs(rootfd,'directory',limits) is None,'root capability refused')
  def walk(directory,prefix=''):
   limits.tick();before_directory=_identity(os.fstat(directory));need(_mount(directory,limits)==mount,'mount crossing refused')
   with os.scandir(directory) as entries:
    actual=set()
    for entry in entries:
     limits.tick();actual.add(entry.name);need(len(actual)<=min(MAX_NODES,limits.max_nodes),'directory node bound')
   need(actual==set(children[prefix]),'actual node graph differs')
   for name in sorted(actual):
    limits.tick();relative=prefix+'/'+name if prefix else name;row=nodes[relative]
    before=os.stat(name,dir_fd=directory,follow_symlinks=False);identity=_identity(before)
    need(expected is None or identity==expected[relative],'node identity changed before restoration')
    kind='file' if stat.S_ISREG(before.st_mode) else 'directory' if stat.S_ISDIR(before.st_mode) else 'symlink' if stat.S_ISLNK(before.st_mode) else 'special'
    need(kind==row['type'] and stat.S_IMODE(before.st_mode)==row['mode'] and before.st_uid==row['uid'] and before.st_gid==row['gid'],'pinned node metadata differs')
    if kind=='file':need(before.st_size==row['bytes'],'pinned file size differs')
    if kind=='symlink':need(os.readlink(name,dir_fd=directory)==row['target'],'pinned symlink differs')
    fd=os.open(name,(os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC) if kind=='symlink' else FLAGS|(os.O_DIRECTORY if kind=='directory' else 0),dir_fd=directory)
    try:
     need(_identity(os.fstat(fd))==identity and _mount(fd,limits)==mount,'node identity/mount drift')
     value=_attrs(fd,kind,limits,directory,name)
     key=(before.st_dev,before.st_ino)
     if value is not None and key not in hashed:_hash(fd,row,limits);hashed.add(key)
     modified=mutate(relative,fd,before,value,identities,expected) if mutate and kind=='file' else False
     after_value=_attrs(fd,kind,limits,directory,name)
     if not modified:need(after_value==value,'capability changed while observing')
     after=_identity(os.fstat(fd));need((after[:-1]==identity[:-1] if modified else after==identity),'node changed while observing')
     need(_identity(os.stat(name,dir_fd=directory,follow_symlinks=False))==after,'named node changed')
     identities[relative]=after
     if after_value is not None:
      result[relative]=after_value;need(len(result)<=MAX_CAPS,'capability map count bound')
     if kind=='file':
      record=inodes.setdefault(key,dict(identity=after,members=[]));need(record['identity']==after,'hardlink identity drift');record['members'].append(relative)
     if kind=='directory':walk(fd,relative)
    finally:os.close(fd)
   need(_identity(os.fstat(directory))==before_directory,'directory changed while observing')
  walk(rootfd)
  for record in inodes.values():
   limits.tick();members=sorted(record['members']);nlink=record['identity'][5]
   need(nlink==len(members),'external or missing hardlink alias')
   if nlink>1:need(nodes[members[0]].get('hardlink_group')==members[0] and sorted(groups.get(members[0],[]))==members,'actual hardlink graph differs')
   else:need('hardlink_group' not in nodes[members[0]],'declared hardlink group is not linked')
  # Revisit the known graph, not an unbounded second filesystem traversal. Catch
  # post-visit changes (including xattr ctime) and rebound parent/root identities.
  def recheck(directory,prefix=''):
   limits.tick();need(_mount(directory,limits)==mount,'recheck mount crossing')
   for name in children[prefix]:
    limits.tick();relative=prefix+'/'+name if prefix else name;row=nodes[relative]
    need(_identity(os.stat(name,dir_fd=directory,follow_symlinks=False))==identities[relative],'post-observation node drift')
    if row['type']=='directory':
     child=os.open(name,FLAGS|os.O_DIRECTORY,dir_fd=directory)
     try:need(_identity(os.fstat(child))==identities[relative],'recheck directory rebound');recheck(child,relative)
     finally:os.close(child)
  recheck(rootfd)
  need(_identity(os.fstat(rootfd))==root_before,'root identity changed')
  with _root(root,limits) as rebound:need(_identity(os.fstat(rebound))==root_before and _mount(rebound,limits)==mount,'root path/mount changed')
 return validate_map(nodes,result,limits),identities


def observe(root,nodes,limits):
 return _scan(root,nodes,limits)[0]


def restore(root,nodes,mapping,limits):
 """Restore only missing expected caps; refuse conflicting/unknown metadata.

Never removes or overwrites an xattr. Failures may leave a partially restored
owned copy: owner must dispose it, not claim rollback. Does not authorize a host
root or candidate capability additions; ownership/baseline-map policy is external.
"""
 need(Path(root)!=Path('/'),'host root restoration refused')
 wanted=validate_map(nodes,mapping,limits);before,identities=_scan(root,nodes,limits)
 need(before.keys()<=wanted.keys() and all(wanted[n]==v for n,v in before.items()),'unexpected or different existing capability')
 _,groups=_graph(nodes,limits);written=set()
 def write(name,fd,info,value,seen,expected):
  if name not in wanted:return False
  raw=bytes.fromhex(wanted[name]);need(value in (None,wanted[name]),'capability changed before restoration')
  key=(info.st_dev,info.st_ino)
  if value==wanted[name] or key in written:return False
  _hash(fd,nodes[name],limits);limits.tick();os.setxattr(fd,ATTR,raw,flags=os.XATTR_CREATE)
  need(os.getxattr(fd,ATTR)==raw,'restored capability bytes differ')
  after=_identity(os.fstat(fd));aliases=groups.get(nodes[name].get('hardlink_group'),[name])
  for alias in aliases:
   expected[alias]=after
   if alias in seen:seen[alias]=after
  written.add(key);return True
 _scan(root,nodes,limits,mutate=write,expected=identities)
 actual=observe(root,nodes,limits);need(actual==wanted,'complete restored capability map differs')
 return actual
