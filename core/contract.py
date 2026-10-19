"""Finite two-recipe source, split metadata and build-output contract."""
import hashlib,json,os,re,stat,struct,tarfile
from pathlib import Path,PurePosixPath
KINDS=('pacman','systemd')
PACKAGER='Cachy-Asahi Experimental Core Builder'
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def ordinary(path,cap=128*1024**2):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode)or before.st_nlink!=1 or before.st_size>cap:raise ValueError('nonordinary or oversized input: '+str(path))
  blocks=[];size=0
  while block:=os.read(fd,min(1024**2,cap+1-size)):
   blocks.append(block);size+=len(block)
   if size>cap:raise ValueError('input grew beyond bound')
  after=os.fstat(fd)
  identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_nlink)
  if size!=before.st_size or identity(before)!=identity(after):raise ValueError('input changed while read')
  return b''.join(blocks)
 finally:os.close(fd)

def closed(root):
 result={}
 for p in sorted(root.rglob('*')):
  if p.is_symlink():raise ValueError('symlink input')
  if p.is_dir():continue
  result[str(p.relative_to(root))]=pin(ordinary(p))
 return result
def metadata(text):
 sections={};current=None
 for line in text.splitlines():
  if not line.strip()or line.lstrip().startswith('#'):continue
  if ' = 'not in line:raise ValueError('malformed metadata line')
  key,value=line.strip().split(' = ',1)
  if not re.fullmatch(r'[a-z0-9_]+',key)or not value:raise ValueError('malformed metadata field')
  if key=='pkgbase':
   if current is not None:raise ValueError('repeated base')
   current='@base';sections[current]={'pkgbase':[value]}
  elif key=='pkgname':
   if current is None or value in sections:raise ValueError('repeated/missing package')
   current=value;sections[current]={'pkgname':[value]}
  else:
   if current is None:raise ValueError('metadata before base')
   sections[current].setdefault(key,[]).append(value)
 if '@base'not in sections or len(sections)<2:raise ValueError('metadata missing split blocks')
 # Order of fields/array values is not authority; complete values and duplicates are.
 return {s:{k:(v if k=='source'or k.endswith('sums')else sorted(v))for k,v in sorted(d.items())}for s,d in sorted(sections.items())}
def check_release(value):
 if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?',value):raise ValueError('invalid numeric pkgrel')
def bind_generated(expected,text):
 if metadata(text)!=expected:raise ValueError('full generated metadata differs from reviewed source')
def source(profile,kind):
 if kind not in KINDS:raise ValueError('unknown recipe')
 cfg=json.loads(ordinary(profile/'profile.json'))
 if cfg['status']!='UNSELECTED_NEW_SOURCE_BUILD_PROFILE'or cfg['old261']!='UNCHANGED_NOT_RELABELED':raise ValueError('profile scope differs')
 row=cfg['packages'][kind];root=profile/kind
 if closed(root)!=row['inputs']:raise ValueError('whole recipe inputs differ')
 if row['selected_for_target']is not False or row['native_build']!='NOT_RUN':raise ValueError('source profile claims actual selection')
 check_release(row['pkgrel'])
 m=metadata(ordinary(root/'.SRCINFO').decode());base=m['@base']
 if base['arch']!=['aarch64']or base['pkgver']!=[row['version']]or base['pkgrel']!=[row['pkgrel']]:raise ValueError('metadata identity differs')
 names=set(m)-{'@base'}
 expected={'pacman'}if kind=='pacman'else{'systemd','systemd-libs','systemd-resolvconf','systemd-sysvcompat','systemd-tests','systemd-ukify'}
 if names!=expected:raise ValueError('finite split set differs')
 # Source order matters for checksum pairs. Parse in original textual order.
 fields={}
 for line in ordinary(root/'.SRCINFO').decode().splitlines():
  if ' = 'in line:
   k,v=line.strip().split(' = ',1);fields.setdefault(k,[]).append(v)
 alg='sha512'if kind=='systemd'else'sha256';sources=fields['source'];hashes=fields[alg+'sums']
 if len(sources)!=len(hashes)or len(set(sources))!=len(sources):raise ValueError('source/hash arity')
 for name,h in zip(sources,hashes):
  if not re.fullmatch(r'[A-Za-z0-9_.-]+',name)or not re.fullmatch('[0-9a-f]{'+str(128 if alg=='sha512'else 64)+'}',h):raise ValueError('nonlocal or unpinned source')
  if hashlib.new(alg,ordinary(root/name)).hexdigest()!=h:raise ValueError('source checksum differs')
 return cfg,row,m
def dependencies(m):
 # Full runtime/build/check union; makepkg -T checks relations/sonames in actual builder.
 result=set()
 for block in m.values():
  for key in('depends','makedepends','checkdepends'):result.update(block.get(key,[]))
 return sorted(result)
def inspect_archive(path,m,recipe_sha,lock,config):
 """Bound full metadata and native ELF data. Does not grant install/platform acceptance."""
 raw=ordinary(path,1024**3);records={};members=[];elf=[];install=None;total=0
 with tarfile.open(path,'r:xz')as t:
  for i,v in enumerate(t):
   name=v.name.removeprefix('./');p=PurePosixPath(name)
   if not name or i>=200000 or p.is_absolute()or '..'in p.parts or name in members:raise ValueError('unsafe/repeated archive member')
   members.append(name)
   if not(v.isfile()or v.isdir()or v.issym()or v.islnk()):raise ValueError('special archive member')
   if v.issym()or v.islnk():
    target=PurePosixPath(v.linkname)
    # Absolute usr/lib symlinks are present in upstream packaging; retain and report.
    if v.islnk()and(target.is_absolute()or '..'in target.parts):raise ValueError('escaping hardlink')
   if v.isfile():
    total+=v.size
    if v.size>512*1024**2 or total>2*1024**3:raise ValueError('oversized archive member/tree')
    f=t.extractfile(v);head=f.read(min(v.size,1024*1024))
    if name in('.PKGINFO','.BUILDINFO'):
     if v.size>1024*1024:raise ValueError('oversized metadata')
     d={}
     for line in head.decode().splitlines():
      if line.startswith('#')or not line:continue
      if ' = 'not in line:raise ValueError('malformed package record')
      k,val=line.split(' = ',1);d.setdefault(k,[]).append(val)
     records[name]=d
    if name=='.INSTALL':install=pin(head+f.read())
    if head[:4]==b'\x7fELF':
     if len(head)<64 or head[4:6]!=b'\x02\x01':raise ValueError('non-ELF64 little endian')
     machine=struct.unpack_from('<H',head,18)[0]
     if machine==247 and struct.unpack_from('<H',head,16)[0]==1:
      elf.append(dict(path=name,kind='EBPF_RELOCATABLE_DATA_NOT_NATIVE_EXECUTION'));continue
     if machine!=183:raise ValueError('non-aarch64 ELF')
     if struct.unpack_from('<H',head,16)[0]==1:
      elf.append(dict(path=name,kind='AARCH64_RELOCATABLE_DATA_NOT_EXECUTION'));continue
     phoff=struct.unpack_from('<Q',head,32)[0];size,count=struct.unpack_from('<HH',head,54)
     if size!=56 or count>1024 or phoff+size*count>len(head):raise ValueError('unbounded ELF program headers')
     loads=[]
     for j in range(count):
      h=struct.unpack_from('<IIQQQQQQ',head,phoff+j*size)
      if h[0]==1:
       if h[7]<16384 or h[2]%16384!=h[3]%16384:raise ValueError('ELF fails structural 16K segment rule')
       loads.append(dict(offset=h[2],vaddr=h[3],align=h[7]))
     # Relocatable BPF eBPF objects use e_machine247 and are not native aarch64 binaries.
     if not loads:raise ValueError('native executable ELF has no load segments')
     elf.append(dict(path=name,load_segments=loads))
 if not all(k in records for k in('.PKGINFO','.BUILDINFO'))or'.MTREE'not in members:raise ValueError('missing package records')
 p=records['.PKGINFO'];b=records['.BUILDINFO'];base=m['@base'];name=p.get('pkgname',[None])[0]
 if name not in m:raise ValueError('unexpected split name')
 effective=dict(base);effective.update(m[name]);version=base['pkgver'][0]+'-'+base['pkgrel'][0]
 required={'pkgname':[name],'pkgbase':base['pkgbase'],'pkgver':[version],'arch':['aarch64'],'packager':[PACKAGER]}
 mapping={'license':'license','depends':'depend','makedepends':'makedepend','checkdepends':'checkdepend','optdepends':'optdepend','provides':'provides','conflicts':'conflict','replaces':'replaces','backup':'backup'}
 for key,target in mapping.items():
  expected=effective.get(key,[]);actual=p.get(target,[])
  # makepkg expands unversioned soname declarations using actual linked ELF. Preserve
  # exact base identity and require numeric ABI/64, rather than dropping soname fields.
  left=[];right=[]
  for v in expected:left.append(v)
  for v in actual:
   if any(x.endswith('.so')and re.fullmatch(re.escape(x)+r'=[0-9][0-9.]*-64',v)for x in expected):v=v.split('=')[0]
   right.append(v)
  if sorted(left)!=sorted(right):raise ValueError('artifact '+target+' differs')
 for k,v in required.items():
  if p.get(k)!=v:raise ValueError('artifact identity differs: '+k)
 if b.get('pkgbuild_sha256sum')!=[recipe_sha]or b.get('pkgname')!=[name]or b.get('pkgver')!=[version]or b.get('pkgarch')!=['aarch64']:raise ValueError('BUILDINFO source/identity differs')
 expected_installed=config['buildinfo_installed']
 if sorted(b.get('installed',[]))!=expected_installed:raise ValueError('BUILDINFO installed closure differs')
 if bool(install)!=bool(effective.get('install')):raise ValueError('installation script presence differs')
 if install:
  if install!=config['install_pin']:raise ValueError('installation script bytes differ')
 return dict(name=name,archive=pin(raw),records=records,members=members,elf=elf,install=install,status='BUILD_METADATA_AND_ELF_STRUCTURE_ONLY_NOT_INSTALL_ACCEPTANCE')
def installed_descriptions(text,lock):
 rows={};record={}
 for line in text.splitlines()+['']:
  if not line.strip():
   if record:
    name=record.get('Name');version=record.get('Version');arch=record.get('Architecture')
    if not name or not version or arch not in('aarch64','any')or name in rows:raise ValueError('installed description identity')
    rows[name]=(version,arch);record={}
  elif ' : 'in line:
   k,v=line.split(' : ',1);k=k.strip()
   if k in('Name','Version','Architecture'):
    if k in record:raise ValueError('duplicate installed identity')
    record[k]=v.strip()
 expected=''.join(n+' '+v+'\n'for n,(v,a)in sorted(rows.items()))
 if expected!=lock:raise ValueError('installed descriptions differ from exact lock')
 return sorted(n+'-'+v+'-'+a for n,(v,a)in rows.items())
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('profile',type=Path);p.add_argument('kind',choices=KINDS);p.add_argument('--generated',type=Path);p.add_argument('--deps',action='store_true');a=p.parse_args()
 c,r,m=source(a.profile,a.kind)
 if a.generated:bind_generated(m,ordinary(a.generated).decode())
 if a.deps:print('\n'.join(dependencies(m)))
 else:print('PASS: complete offline source/metadata contract; native/installation NOT_RUN')
