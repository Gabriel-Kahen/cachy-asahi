#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Read pinned package data and prove the finite declared dependency closure."""
import hashlib,importlib.util,json,re,struct,tarfile
from pathlib import Path,PurePosixPath
HERE=Path(__file__).resolve().parent


def pin(path):
 if path.is_symlink()or not path.is_file():raise ValueError('ordinary pinned file required')
 with path.open('rb')as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
 return {'bytes':path.stat().st_size,'sha256':digest}


def checked(path,ref):
 if pin(path)!={k:ref[k]for k in ('bytes','sha256')}:raise ValueError('material pin differs: '+path.name)
 return path


def signature_dates(statuses):
 """Diagnostic dates from actual bounded host gpgv results, not a policy bypass."""
 labels={'cachy-asahi-ksmctl':'ksm','python':'python','mpdecimal':'mpdecimal'};dates={}
 if set(statuses)!=set(labels):raise ValueError('exact three signature date records required')
 for name,line in statuses.items():
  fields=line.split()
  if len(fields)not in (11,12)or fields[:2]!=['[GNUPG:]','VALIDSIG']or not all(re.fullmatch(r'(0|[1-9][0-9]{0,11})',value)for value in fields[4:6]):raise ValueError('unhandled signature timestamp format')
  dates[labels[name]]={'created':int(fields[4]),'expires':int(fields[5]),'source':'fresh host gpgv over exact pinned signature/archive; diagnostic only'}
 return dates


def reference():
 lock=json.loads((HERE/'inputs.lock.json').read_text());root=HERE.parent/'arm16k_systemd_tcg_guest'
 legacy=HERE.parent/'arm16k_project_lifecycle'
 for name,ref in lock['legacy_source_files'].items():checked(legacy/name,ref)
 for name,ref in lock['reference_files'].items():checked(root/name,ref)
 spec=importlib.util.spec_from_file_location('arm16k_project_reference',root/'boot.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
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
 return {'machine':'aarch64','LOAD':loads,'runtime':'NOT RUN'}


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
 lock,root,_=reference()
 spec=importlib.util.spec_from_file_location('arm16k_project_alpm_versions',root/'select_guest.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
 index={row['name']:row['version']for row in base['base_packages']}
 if len(index)!=111 or set(index)&lock['added_packages'].keys():raise ValueError('pristine111 baseline required')
 catalog={};edges=[]
 for name,version in lock['added_packages'].items():
  paths=[p for p in materials.glob(name+'-*.pkg.tar.xz')if not p.name.endswith('.sig')]
  if len(paths)!=1:raise ValueError('exact single package material required')
  data=package(paths[0]);meta=data['metadata']
  if meta.get('pkgname')!=[name]or meta.get('pkgver')!=[version]or meta.get('arch')!=(['any']if name=='cachy-asahi-ksmctl'else['aarch64']):raise ValueError('package identity differs')
  catalog[name]=data;index[name]=version
 for name,data in catalog.items():
  for expression in data['metadata'].get('depend',[]):
   dependency,op,wanted=S.atom(expression)
   if dependency not in index or not S.satisfies(index[dependency],op,wanted):raise ValueError('missing actual declared dependency: '+expression)
   edges.append({'package':name,'dependency':expression,'actual_provider':dependency,'actual_version':index[dependency]})
 if catalog['cachy-asahi-ksmctl']['metadata'].get('depend')!=['python>=3.11']:raise ValueError('project dependency drift')
 payload={n:r for n,r in catalog['cachy-asahi-ksmctl']['payload'].items()if r['type']=='0'}
 if len(payload)!=5 or payload['usr/bin/cachy-asahi-ksmctl']['sha256']!='f9fd76eaa6a205d56fa4bb9123b8c721ea1277249c4cab58d1b57eaf8edc7558':raise ValueError('current five-file diagnostic payload required')
 return {'packages':catalog,'dependency_edges':edges,'base_packages':111,'installed_packages':114,'project_payload':payload,'guest_execution':'NOT RUN'}
