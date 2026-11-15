#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite C01 DATA checks; never execute retained package bytes."""
import hashlib,importlib.util,json,re,struct,tarfile
from pathlib import Path,PurePosixPath
HERE=Path(__file__).resolve().parent
REFERENCE=None

def pin(path):
 path=Path(path)
 if path.is_symlink() or not path.is_file():raise ValueError('ordinary pinned file required')
 with path.open('rb') as f:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}

def checked(path,ref):
 if pin(path)!={k:ref[k] for k in ('bytes','sha256')}:raise ValueError('material pin differs: '+str(path))
 return path

def reference():
 lock=json.loads((HERE/'inputs.lock.json').read_text());root=Path(REFERENCE or HERE.parent/'arm16k_systemd_tcg_guest').resolve(strict=True)
 for name,ref in lock['reference_files'].items():checked(root/name,ref)
 spec=importlib.util.spec_from_file_location('c01_exact_arm16k_reference',root/'boot.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 return lock,root,module

def elf_geometry(raw):
 if not raw.startswith(b'\x7fELF'):return None
 if len(raw)<64 or raw[:6]!=b'\x7fELF\x02\x01'or struct.unpack_from('<H',raw,18)[0]!=183:raise ValueError('aarch64 little-endian ELF64 required')
 kind=struct.unpack_from('<H',raw,16)[0]
 if kind==1:return {'machine':'aarch64','type':'relocatable','LOAD_geometry':'not applicable; compiler/link consumption NOT RUN','runtime':'NOT RUN'}
 if kind not in (2,3):raise ValueError('unhandled ELF file type')
 offset=struct.unpack_from('<Q',raw,32)[0];width,count=struct.unpack_from('<HH',raw,54)
 if width!=56 or not 0<count<=128 or offset+width*count>len(raw):raise ValueError('bounded ELF program table required')
 loads=[]
 for i in range(count):
  kind,flags,fileoff,vaddr,_,filesize,memsize,align=struct.unpack_from('<IIQQQQQQ',raw,offset+i*width)
  if kind!=1:continue
  if align<16384 or align&(align-1)or fileoff%16384!=vaddr%16384 or fileoff+filesize>len(raw)or filesize>memsize:raise ValueError('16K ELF LOAD geometry differs')
  loads.append({'offset':fileoff,'vaddr':vaddr,'align':align,'flags':flags})
 if not loads:raise ValueError('ELF LOAD segments absent')
 headers=[struct.unpack_from('<IIQQQQQQ',raw,offset+i*width) for i in range(count)]
 interpreters=[raw[h[2]:h[2]+h[5]].rstrip(b'\0') for h in headers if h[0]==3]
 dynamic=[h for h in headers if h[0]==2]
 if interpreters!=[b'/lib/ld-linux-aarch64.so.1'] or len(dynamic)!=1:raise ValueError('exact glibc interpreter/dynamic table required')
 h=dynamic[0]
 if h[5]>65536 or h[5]%16 or h[2]+h[5]>len(raw):raise ValueError('bounded dynamic table required')
 entries=[struct.unpack_from('<qQ',raw,i) for i in range(h[2],h[2]+h[5],16)]
 tables=[v for k,v in entries if k==5]
 if len(tables)!=1 or any(k in (15,29) for k,v in entries):raise ValueError('exact dynamic string table and no RPATH/RUNPATH required')
 segments=[h for h in headers if h[0]==1 and h[3]<=tables[0]<h[3]+h[5]]
 if len(segments)!=1:raise ValueError('mapped dynamic string table required')
 segment=segments[0];start=tables[0]-segment[3]+segment[2];needed=[]
 for key,value in entries:
  if key==1:
   begin=start+value
   if not 0<=begin<len(raw):raise ValueError('dynamic string bound')
   end=raw.find(b'\0',begin,min(len(raw),begin+256))
   if end<0:raise ValueError('bounded dynamic name required')
   needed.append(raw[begin:end].decode('ascii'))
 if needed!=['libc.so.6','ld-linux-aarch64.so.1']:raise ValueError('exact existing glibc runtime closure required')
 return {'machine':'aarch64','LOAD':loads,'interpreter':'/lib/ld-linux-aarch64.so.1','needed':needed,'runtime':'NOT RUN'}


def package(path):
 if path.stat().st_size>16*1024**2:raise ValueError('package compressed bound')
 files={};metadata={};total=0
 with tarfile.open(path,'r:xz')as archive:
  for member in archive:
   name=member.name.removeprefix('./').rstrip('/');pure=PurePosixPath(name)
   if not name or name=='.':continue
   if pure.is_absolute()or'..'in pure.parts or any(ord(c)<32 for c in name):raise ValueError('unsafe package path')
   total+=member.size
   if total>128*1024**2 or member.size>32*1024**2 or len(files)>25000:raise ValueError('package decoded bound')
   if name=='.INSTALL' or '/libalpm/hooks/' in name:raise ValueError('unexpected package hook/scriptlet')
   if name.startswith('.'):
    if name=='.PKGINFO':
     if member.size>131072:raise ValueError('PKGINFO bound')
     for line in archive.extractfile(member).read().decode().splitlines():
      if' = 'in line:
       key,value=line.split(' = ',1);metadata.setdefault(key,[]).append(value)
    continue
   if name in files:raise ValueError('duplicate package path')
   if not(member.isdir()or member.isfile()or member.issym()or member.islnk()):raise ValueError('package special file refused')
   geometry=None
   if member.isfile():
    raw=archive.extractfile(member).read();digest=hashlib.sha256(raw).hexdigest();geometry=elf_geometry(raw)
   else:digest=None
   files[name]={'type':member.type.decode(),'mode':member.mode,'uid':member.uid,'gid':member.gid,'bytes':member.size,'sha256':digest,'link':member.linkname}
   if geometry is not None:files[name]['ELF']=geometry
 if not metadata:raise ValueError('package metadata missing')
 return {'metadata':metadata,'payload':files,'logical_bytes':total}


def closure(materials,base):
 lock=json.loads((HERE/'inputs.lock.json').read_text())
 if {p.name for p in materials.iterdir()}!=set(lock['materials']):raise ValueError('exact public material namespace required')
 for name,ref in lock['materials'].items():checked(materials/name,ref)
 index={row['name']:row['version'] for row in base['base_packages']}
 if len(index)!=111 or set(index)&set(lock['added_packages']):raise ValueError('pristine111 baseline required')
 if 'glibc' not in index:raise ValueError('existing glibc provider required')
 catalog={};payload={};edges=[]
 for name,version in lock['added_packages'].items():
  archive=materials/(name+'-'+version+'-aarch64.pkg.tar.xz');data=package(archive);meta=data['metadata']
  if any(meta.get(k)!=v for k,v in {'pkgname':[name],'pkgver':[version],'arch':['aarch64'],'depend':['glibc']}.items()):raise ValueError('exact C01 identity/dependency required')
  variant=name.removeprefix('cachy-asahi-zlib-');roots=('usr/lib/cachy-asahi/experiments/zlib-'+variant+'/','usr/share/licenses/'+name+'/')
  regular={n:r for n,r in data['payload'].items() if r['type']=='0'}
  if len(regular)!=14 or any(not n.startswith(roots) or r['uid']!=0 or r['gid']!=0 or r['mode'] not in (0o644,0o755) for n,r in regular.items()):raise ValueError('exclusive reviewed14-file payload required')
  elfs={n:r for n,r in regular.items() if 'ELF' in r}
  if len(elfs)!=3 or any('/bin/' not in n or not r['ELF'].get('LOAD') for n,r in elfs.items()):raise ValueError('exact three runtime ELF objects required')
  payload.update(regular);catalog[name]=data;edges.append({'package':name,'dependency':'glibc','actual_version':index['glibc']})
 return {'packages':catalog,'project_payload':payload,'dependency_edges':edges,'base_packages':111,'installed_packages':113,'guest_execution':'NOT RUN'}


def trust_prerequisite(path,sha256):
 if not re.fullmatch('[0-9a-f]{64}',sha256):raise ValueError('explicit Root receipt SHA required')
 checked(path,{'bytes':path.stat().st_size,'sha256':sha256});report=json.loads(path.read_text())
 fields=report.get('project',{})
 if report.get('status')!='PASS_EMULATED_ARM16K_SIGNED_PROJECT_INSTALL_REMOVE_ONLY' or any(fields.get(k)!=v for k,v in {'STATUS':'PASS','BASELINE_PACKAGES':'111','FINAL_PACKAGES':'111','PRIVATE_TEST_TRUST_REMOVED':'yes','ORDINARY_HOOKS_SCRIPTLETS':'unsuppressed'}.items()):raise ValueError('KSM trust/install/remove HOLD must be resolved by genuine Root result')
 return pin(path)


def fixtures(directory):
 """Generate bounded ordinary DATA with stdlib only; never run a package."""
 import gzip
 corpus=[b'',b'x',b'cachy-asahi public workload\n'*4096,bytes(range(256))*1024]
 corpus += [bytes((i*13+i//257)&255 for i in range(n)) for n in (16383,16384,16385)]
 files={}
 for i,raw in enumerate(corpus):files['corpus-'+str(i)]=raw
 ref=gzip.compress(corpus[2],mtime=0);corrupt=bytearray(ref);corrupt[-8]^=1
 for i,raw in enumerate((bytes(corrupt),ref[:-8],ref+b'garbage')):files['invalid-'+str(i)]=raw
 for variant in ('baseline','lto'):
  report={'status':'PASS','variant':variant,'prefix':'/usr/lib/cachy-asahi/experiments/zlib-'+variant,'zlib':'1.3.2','source_sha256':'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16','roundtrips':21,'negative_checks':42}
  files['probe-'+variant+'.json']=(json.dumps(report,separators=(',',':'))+'\n').encode()
 for name,raw in files.items():
  with (directory/name).open('xb') as f:f.write(raw)
 return {name:pin(directory/name) for name in files}
