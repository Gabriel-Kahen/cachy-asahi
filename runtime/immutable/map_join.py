"""Complete logical/capability join; physical identities explicitly re-anchored."""
import hashlib,json,stat

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(v):
 raw=(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False,default=lambda b:{'$bytes':b.hex()}if type(b)is bytes else (_ for _ in()).throw(ValueError('unsupported pin type'))) +'\n').encode();return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def validate(value):
 need(type(value)is dict and {'observation','nodes','capabilities','physical'}<=set(value)and set(value)<={'observation','nodes','capabilities','physical','auxiliary'},'whole original map fields')
 report=value['observation'];nodes=value['nodes'];need(report['complete']is True and nodes==report['nodes']and type(nodes)is dict and 0<len(nodes)<=500000 and set(value['physical'])==set(nodes),'complete full logical/physical graph')
 groups={}
 for name,node in nodes.items():
  need(type(name)is str and name and not name.startswith('/')and all(p not in('','.','..')for p in name.split('/')),'canonical complete node path')
  r=value['physical'][name];need(type(r)in(tuple,list)and len(r)==9 and all(type(n)is int and n>=0 for n in r),'whole nine-field physical identity')
  dev,ino,mode,uid,gid,nlink,size,mtime,ctime=r;kind=node['type'];need(kind in('file','directory','symlink')and stat.S_IMODE(mode)==node['mode']and(uid,gid)==(node['uid'],node['gid'])and ino>0 and nlink>0,'physical/logical complete metadata')
  need({'file':stat.S_ISREG,'directory':stat.S_ISDIR,'symlink':stat.S_ISLNK}[kind](mode),'physical node type')
  if kind=='file':
   need(size==node['bytes'],'physical payload byte count');tag=node.get('hardlink_group',name);groups.setdefault(tag,[]).append(name)
  if kind=='symlink':need(size==len(node['target'].encode('utf8','surrogateescape'))and nlink==1,'exact symlink size/link count')
 for tag,names in groups.items():
  identities={(value['physical'][n][0],value['physical'][n][1])for n in names};need(len(identities)==1 and all(value['physical'][n][5]==len(names)for n in names),'closed complete file hardlink identities')
 need(len({(value['physical'][names[0]][0],value['physical'][names[0]][1])for names in groups.values()})==len(groups),'distinct unaliased file groups')
 need(type(value['capabilities'])is dict and set(value['capabilities'])<=set(nodes),'complete capability map')
 return groups

def group_rows(value):
 need(type(value)is dict,'complete hardlink table');out={}
 for tag,row in value.items():
  need(type(row)is dict and set(row)=={'bytes','mode','uid','gid','members','nlink','sha256'}and type(row['members'])in(tuple,list),'exact original hardlink row')
  names=tuple(row['members']);need(len(names)>=2 and list(names)==sorted(set(names))and tag==names[0]and row['nlink']==len(names),'ordered unique closed hardlink members');out[tag]=dict(row,members=names)
 return out

def auxiliary(value):
 aux=value['auxiliary'];sections={'helper','configs','aliases','scan','targets','caches'};need(set(aux)==sections|{'main_bytes','aux_bytes','closure','scan_directories'},'complete original auxiliary schema')
 identities={tuple(r)for r in value['physical'].values()};inodes={r[:2]for r in identities};out={}
 for section in sections:
  out[section]={}
  for path,row in aux[section].items():
   need(type(row)is dict and 'node'in row and set(row)<={'node','identity','inode','data'},'exact auxiliary physical row')
   if 'identity'in row:need(tuple(row['identity'])in identities,'auxiliary full identity belongs to complete graph')
   if 'inode'in row:need(tuple(row['inode'])in inodes,'auxiliary inode belongs to complete graph')
   out[section][path]={k:v for k,v in row.items()if k not in('identity','inode')}
 for name in('main_bytes','aux_bytes'):need(type(aux[name])is bytes,'full exact original cache bytes');out[name]=aux[name].hex()
 for name in('closure','scan_directories'):
  names=tuple(aux[name]);need(list(names)==sorted(set(names))and all(type(n)is str for n in names),'complete sorted auxiliary paths');out[name]=names
 return out

def join(native,mounted):
 validate(native);validate(mounted);need(native['nodes']==mounted['nodes']and native['capabilities']==mounted['capabilities'],'every payload/rawDB/metadata/symlink/hardlink/capability field held across image')
 # Names/group membership are logical; filesystem-specific dev/inode/ctime,
 # directory size/nlink are new measured values, not normalized equal values.
 need(group_rows(native['observation'].get('hardlink_groups',{}))==group_rows(mounted['observation'].get('hardlink_groups',{})),'complete logical hardlink group topology')
 for name,node in native['nodes'].items():
  a,b=native['physical'][name],mounted['physical'][name]
  need(tuple(a[2:5])==tuple(b[2:5])and a[7]==b[7],'same mode/owner/group/mtime for every node')
  if node['type']!='directory':need(tuple(a[5:7])==tuple(b[5:7]),'file/symlink link count and size unchanged')
 # Full reports are retained; unsupported/eligibility/shape facts cannot change.
 for key in set(native['observation'])|set(mounted['observation']):
  if key not in('footprint','nodes','hardlink_groups'):need(native['observation'].get(key)==mounted['observation'].get(key),'complete original observation field '+key)
 a,b=native['observation']['footprint'],mounted['observation']['footprint'];fresh={'allocated_bytes','allocated_bytes_by_entry','filesystem_free_bytes','filesystem_free_inodes','filesystem_inode_counts_known','filesystem_inode_source','filesystem_free_bytes_source'}
 need(set(a)==set(b)and all(a[k]==b[k]for k in a if k not in fresh),'all logical footprint counts/bytes preserved')
 need('auxiliary'in native and 'auxiliary'in mounted and auxiliary(native)==auxiliary(mounted),'complete auxiliary bytes/logical state; identity reanchored only')
 return dict(purpose='GNU_SEPARATE_VERITY_SOURCE_REANCHOR_V1',status='COMPLETE_LOGICAL_CAPABILITY_MAP_JOIN_PHYSICAL_REANCHORED',native=pin(native),mounted=pin(mounted),nodes=len(native['nodes']),physical_fields_held=['mode','uid','gid','mtime_ns','regular_and_symlink_nlink_size'],physical_reanchored=['st_dev','st_ino','st_ctime_ns','directory_st_size','directory_st_nlink'],fresh_footprint_fields=sorted(fresh),authority='PID1_PRIVATE_SOURCE_CHECK_NOT_KERNEL_BOOT_OR_LIFECYCLE_ACCEPTANCE')
