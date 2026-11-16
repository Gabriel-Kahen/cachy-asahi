# SPDX-License-Identifier: MIT
"""Passive export/package/transfer parsing using one pinned independent tar/ELF helper."""
import hashlib,importlib.util,io,posixpath,re,stat,sys,tarfile,tempfile,zipfile
from pathlib import Path
S=None;H=None;ELF=None;E=None
PACKAGE='cachy-asahi-rust199-source-reference-1.99.0-1-aarch64.pkg.tar.zst'
PREFIX='opt/cachy-asahi/rust199-source-reference';NOTICES=PREFIX+'/share/licenses/rust199-source-reference/source-notices/'
def helper():
 global H,ELF
 if H is None:
  path=Path(__file__).resolve().parents[3]/'port/llvm23-native-independent-reader/v2/reader.py'
  # parents[3] is scripts; never resolve this dependency from a Source operand.
  S.need(S.pin(S.read(path,2*S.MIB))['sha256']=='e3fed71e01be989b5c84cd0e33124ca096e452eda380f4840b45786cb385335c','INDEPENDENT_TAR_ELF_HELPER_PIN')
  spec=importlib.util.spec_from_file_location('fixed_independent_LLVM2_archive_primitives',path);H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
  ELF,proof=E.parser(H,S.read(path,2*S.MIB))
 H.END=S.END;return H

def zip_members(path,pin,members,corpus,cap):
 before=S.identity(path.lstat());S.need(S.hashed(path,cap)==pin,'WHOLE_PROVIDER_ARTIFACT_ZIP_PIN');seen=set();dirs=set();total=0
 # Bound the central-directory table before ZipFile allocates it.
 import struct
 with path.open('rb')as stream:
  size=path.stat().st_size;stream.seek(max(0,size-65557));tail=stream.read(65557);i=tail.rfind(b'PK\x05\x06');S.need(i>=0 and i+22<=len(tail),'ZIP_END_RECORD')
  disk,start,one,count,cd,offset,comment=struct.unpack('<4H2LH',tail[i+4:i+22]);S.need(disk==start==0 and i+22+comment==len(tail),'ZIP_SINGLE_DISK_END')
  if count==65535 or cd==0xffffffff or offset==0xffffffff:
   end=size-len(tail)+i;S.need(end>=20,'ZIP64_LOCATOR');stream.seek(end-20);locator=stream.read(20);S.need(locator[:4]==b'PK\x06\x07','ZIP64_LOCATOR')
   disk,position,disks=struct.unpack('<LQL',locator[4:]);S.need(disk==0 and disks==1 and position+56<=end-20,'ZIP64_POSITION');stream.seek(position);record=stream.read(56);S.need(record[:4]==b'PK\x06\x06','ZIP64_END_RECORD')
   length,made,needed,disk,start,one,count,cd,offset=struct.unpack('<Q2H2L4Q',record[4:]);S.need(44<=length<=65536 and position+12+length==end-20 and disk==start==0,'ZIP64_END_BOUND')
  S.need(one==count and 0<count<=4096 and 0<cd<=4*S.MIB and offset+cd<=size,'ZIP_CENTRAL_DIRECTORY_BOUND')
 with zipfile.ZipFile(path)as archive:
  for row in archive.infolist():
   name=row.filename.rstrip('/')if row.is_dir()else row.filename;S.relative(name);S.need(name not in seen and not row.flag_bits&1 and row.compress_type in(zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED),'ZIP_DUPLICATE_ENCRYPTION_COMPRESSION');seen.add(name)
   kind=stat.S_IFMT(row.external_attr>>16);S.need(kind in((0,stat.S_IFDIR)if row.is_dir()else(0,stat.S_IFREG))and row.file_size<=cap and row.file_size<=max(1,row.compress_size)*1000,'ZIP_SPECIAL_OR_RATIO_BOUND');total+=row.file_size;S.need(total<=cap,'ZIP_LOGICAL_BOUND')
   if row.is_dir():dirs.add(name);continue
   S.need(name in members,'ZIP_UNSELECTED_MEMBER');target=members[name];expected=corpus.rows[target];h=hashlib.sha256();length=0
   with archive.open(row)as stream:
    while block:=stream.read(S.MIB):length+=len(block);S.need(length<=expected['bytes'],'ZIP_MEMBER_BOUND');h.update(block)
   S.need(dict(bytes=length,sha256=h.hexdigest())==expected,'ZIP_WHOLE_MEMBER_PIN')
  actual={r.filename for r in archive.infolist()if not r.is_dir()};S.need(actual==set(members)and dirs<={str(parent)for name in actual for parent in Path(name).parents if str(parent)!='.'},'ZIP_COMPLETE_MEMBER_NAMESPACE')
 S.need(S.identity(path.lstat())==before,'PROVIDER_ARTIFACT_CHANGED_DURING_PARSE')
 return dict(files=len(members),logical_bytes=total)

def fields(raw):
 values={}
 for line in raw.decode('utf-8').splitlines():
  if not line or line.startswith('#'):continue
  S.need(' = 'in line,'PACKAGE_METADATA_LINE');key,value=line.split(' = ',1);values.setdefault(key,[]).append(value)
 return values

def package_tar(stream,source,inventory,scratch):
 h=helper();rows={};elfs={};metadata={};kept={};total=0;info,state=h.tar_info(400000)
 with tarfile.open(fileobj=stream,mode='r|',tarinfo=info)as archive:
  for item in archive:
   S.need(not item.sparse and not any(k.startswith('GNU.sparse')for k in item.pax_headers),'PACKAGE_SPARSE');name=item.name.removeprefix('./').rstrip('/')
   if name in('','.'):continue
   S.relative(name);S.need(name not in rows and len(rows)<200000 and not item.mode&0o7000,'PACKAGE_NAMESPACE_OR_SETID');S.need(item.uid==item.gid==0,'PACKAGE_ARCHIVE_OWNERSHIP');row=dict(mode=item.mode&0o777)
   S.need(name in('.PKGINFO','.BUILDINFO','.MTREE')or name==PREFIX or name.startswith(PREFIX+'/')or item.isdir()and PREFIX.startswith(name+'/'),'PACKAGE_PRIVATE_PREFIX_ESCAPE')
   if item.isdir():row['kind']='dir'
   elif item.issym():row.update(kind='link',target=item.linkname)
   else:
    S.need(item.isfile()and 0<=item.size<=2*S.GIB,'PACKAGE_SPECIAL_OR_FILE_BOUND');total+=item.size;S.need(total<=16*S.GIB,'PACKAGE_LOGICAL_BOUND')
    body=archive.extractfile(item);first=body.read(min(64,item.size));digest=hashlib.sha256(first);size=len(first);selected=first.startswith(b'\x7fELF');collect=name in('.PKGINFO','.BUILDINFO','.MTREE')or name.startswith(NOTICES)and(name.endswith(('index.json','catalogue.DATA.json')))
    retained=bytearray(first)if collect else None
    with tempfile.TemporaryFile(dir=scratch)as elf:
     if selected:elf.write(first)
     while block:=body.read(S.MIB):
      size+=len(block);S.need(size<=item.size,'PACKAGE_TRUNCATED_OR_GROWING');digest.update(block)
      if selected:elf.write(block)
      if retained is not None:S.need(len(retained)+len(block)<=8*S.MIB,'PACKAGE_METADATA_BOUND');retained.extend(block)
     S.need(size==item.size,'PACKAGE_TRUNCATED')
     if selected:elf.seek(0);elfs[name]=ELF(elf,size,name)
    row.update(kind='file',bytes=size,sha256=digest.hexdigest())
    if retained is not None:kept[name]=bytes(retained)
   rows[name]=row;archive.members.clear()
  h.tar_end(archive,state)
 S.need({'.PKGINFO','.BUILDINFO','.MTREE'}<=set(kept),'PACKAGE_METADATA_MISSING')
 def resolve(name):
  seen=set()
  while rows.get(name,{}).get('kind')=='link':
   S.need(name not in seen and len(seen)<16,'PACKAGE_SYMLINK_CYCLE');seen.add(name);target=rows[name]['target'];S.need(not target.startswith('/'),'PACKAGE_ABSOLUTE_SYMLINK');name=posixpath.normpath(posixpath.join(posixpath.dirname(name),target));S.need(name.startswith(PREFIX+'/')and name in rows,'PACKAGE_SYMLINK_ESCAPE_OR_MISSING')
  return name
 for n,r in rows.items():
  if r['kind']=='link':S.need(rows.get(resolve(n),{}).get('kind')in('file','dir'),'PACKAGE_SYMLINK_TARGET')
 for tool in('bin/rustc','bin/cargo','bin/rustdoc','bin/rustfmt','bin/clippy-driver','libexec/rust-analyzer-proc-macro-srv'):
  n=resolve(PREFIX+'/'+tool);S.need(n in elfs and rows[n]['mode']&0o111 and elfs[n]['kind']in(2,3),'RUST_TOOL_NATIVE_AARCH64_ELF_MISSING')
 library=rows.get(resolve(PREFIX+'/lib/rustlib/src/rust/library/Cargo.toml'),{});S.need(library.get('kind')=='file'and library.get('bytes',0)>0,'RUST_LIBRARY_SOURCE_MISSING')
 pkg=fields(kept['.PKGINFO']);S.need(all(pkg.get(k)==[v]for k,v in dict(pkgname='cachy-asahi-rust199-source-reference',pkgver='1.99.0-1',arch='aarch64').items()),'RUST_PKGINFO_IDENTITY')
 wanted={'bash','curl','gcc','glibc','libgcc','libstdc++','libgit2','libssh2','openssl','sqlite','zlib','cachy-asahi-llvm23-source-reference=23.1.1'};S.need(set(pkg.get('depend',[]))==wanted and len(pkg.get('depend',[]))==len(wanted),'RUST_PKGINFO_DEPENDENCIES')
 bi=fields(kept['.BUILDINFO']);S.need(all(bi.get(k)==[v]for k,v in dict(pkgname='cachy-asahi-rust199-source-reference',pkgver='1.99.0-1',pkgarch='aarch64').items()),'RUST_BUILDINFO_IDENTITY')
 expected={line.replace(' ','-',1)for line in inventory.decode().splitlines()};S.need(len(inventory.splitlines())==len(expected)and set(bi.get('installed',[]))==expected and len(bi.get('installed',[]))==len(expected),'COMPLETE_QUALIFIED_BUILDINFO_INVENTORY')
 catalogue_raw=source['packages/port/rust199-source-reference/notice-catalogue.DATA.json'][0];catalogue=S.decode(catalogue_raw);S.need(kept.get(NOTICES+'catalogue.DATA.json')==catalogue_raw,'COMPLETE_NOTICE_CATALOGUE_BYTES')
 index=S.decode(kept.get(NOTICES+'index.json',b'{}'));S.need(index.get('holds_preserved')is True and index.get('copyright_ownership_inferred')is False and index.get('manifest_authors_are_owners')is False and index.get('catalogue_sha256')==S.pin(catalogue_raw)['sha256']and index.get('scope')==catalogue['scope'] and index.get('source_archive')==catalogue['source_archive'],'NOTICE_SCOPE_AND_HOLDS')
 expected_bodies={r['sha256']:{k:r[k]for k in('bytes','sha256')}for r in catalogue['files'].values()};expected_bodies.update({k:{n:r[n]for n in('bytes','sha256')}for k,r in catalogue['retained_upstream_grant_bodies'].items()})
 S.need(set(index.get('paths',{}))==set(catalogue['files'])and set(index.get('retained_grants',{}))==set(catalogue['retained_upstream_grant_bodies']),'COMPLETE_NOTICE_PROVENANCE_NAMESPACE')
 for n,r in catalogue['files'].items():S.need({k:index['paths'][n].get(k)for k in('bytes','sha256')}=={k:r[k]for k in('bytes','sha256')}and index['paths'][n]['body']=='bodies/'+r['sha256']+'.txt','NOTICE_FILE_PROVENANCE')
 for digest,row in catalogue['retained_upstream_grant_bodies'].items():
  expected=dict(bytes=row['bytes'],sha256=row['sha256'],retained_evidence_path=row.get('path',row.get('file')),retained_evidence={k:v for k,v in row.items()if k!='text'},body='bodies/'+digest+'.txt',components=[c['component']for c in sorted(catalogue['components'],key=lambda c:c['component'])if digest in c.get('retained_exact_upstream_grant_bodies',[])],scope=catalogue['grant_scope'])
  S.need(index['retained_grants'][digest]==expected,'EXACT_RETAINED_GRANT_CONTEXT_AND_SCOPE')
 for digest,pin in expected_bodies.items():
  row=rows.get(NOTICES+'bodies/'+digest+'.txt',{});S.need({k:row.get(k)for k in('bytes','sha256')}==pin and row.get('kind')=='file'and row.get('mode')==0o644,'NOTICE_OR_GRANT_WHOLE_BODY')
 mtree(kept['.MTREE'],rows)
 # Producer emits no postbuild Rust1.99 runtime-probe evidence. Do not infer it.
 return dict(package_files=len(rows),elf_files=len(elfs),metadata={n:S.pin(kept[n])for n in('.PKGINFO','.BUILDINFO','.MTREE')},notice_bodies=len(expected_bodies),historical_holds_preserved=True,new_tool_runtime='NOT_EMITTED_NOT_QUALIFIED',legal_acceptance=False)

def export(path,expected,source,inventory,scratch):
 S.need(S.hashed(path,4*S.GIB)==expected,'WHOLE_BUILD_EXPORT_PIN');before=S.identity(path.lstat());h=helper();info,state=h.tar_info(512);data={};package=None;seen=set();total=0;logs=0
 with tarfile.open(path,mode='r|',tarinfo=info)as archive:
  for item in archive:
   if item.isdir()and item.name.rstrip('/')=='output':continue
   parts=Path(item.name).parts;S.need(len(parts)==2 and parts[0]=='output'and item.isfile()and not item.sparse and not any(k.startswith('GNU.sparse')for k in item.pax_headers),'EXPORT_FLAT_ORDINARY_ONLY');name=parts[1];S.relative(name);S.need(name not in seen and len(seen)<256 and not item.mode&0o111 and 0<=item.size<=2*S.GIB,'EXPORT_NAMESPACE_OR_MODE_BOUND');seen.add(name);total+=item.size;S.need(total<=4*S.GIB,'EXPORT_TOTAL_BOUND')
   if name.endswith(('.stdout','.stderr'))or '.log'in name:logs+=item.size;S.need(logs<=64*S.MIB,'EXPORT_LOG_BOUND')
   stream=archive.extractfile(item)
   if name==PACKAGE:
    with tempfile.TemporaryFile(dir=scratch)as spool:
     digest=hashlib.sha256();length=0
     while block:=stream.read(S.MIB):length+=len(block);S.need(length<=item.size,'EXPORT_PACKAGE_TRUNCATED');digest.update(block);spool.write(block)
     S.need(length==item.size,'EXPORT_PACKAGE_TRUNCATED');package_pin=dict(file=name,bytes=length,sha256=digest.hexdigest());spool.seek(0)
     S.need(sys.version_info>=(3,14),'PYTHON_STDLIB_ZSTD_UNAVAILABLE')
     import compression.zstd
     with compression.zstd.ZstdFile(spool,'rb')as decoded:package=package_tar(decoded,source,inventory,scratch)
   else:
    S.need(name in('actual-packages.txt','prepared.json','built.json','work-preentry-prepare.json','work-preentry-makepkg.json')or re.fullmatch(r'cachy-asahi-rust199-source-reference-1\.99\.0-1-aarch64-(?:build|package)\.log',name)or re.fullmatch(r'(?:phase-(?:prepare|build|package|makepkg)-[1-9][0-9]{0,19}-[0-9a-f]{32}\.json|cmd-[1-9][0-9]{0,19}-[0-9a-f]{32}\.(?:json|stdout|stderr))',name),'EXPORT_UNKNOWN_PRODUCER_MEMBER')
    S.need(item.size<=64*S.MIB and sum(len(v)for v in data.values())+item.size<=128*S.MIB,'EXPORT_DATA_MEMBER_BOUND');raw=stream.read(item.size+1);S.need(len(raw)==item.size,'EXPORT_MEMBER_TRUNCATED');data[name]=raw
   archive.members.clear()
  h.tar_end(archive,state)
 S.need(S.identity(path.lstat())==before and package is not None,'EXPORT_CHANGED_OR_PACKAGE_MISSING');return data,package_pin,package

def mtree(raw,rows):
 import zlib
 decoder=zlib.decompressobj(31);text=decoder.decompress(raw,64*S.MIB+1)
 S.need(len(text)<=64*S.MIB and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'MTREE_COMPRESSION_OR_BOUND')
 defaults={};found={}
 def unescape(v):return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),v)
 for line in text.decode('utf-8').splitlines():
  if not line or line.startswith('#'):continue
  parts=line.split()
  if parts[0]=='/set':
   defaults.update(dict(v.split('=',1)for v in parts[1:]));continue
  S.need(not parts[0].startswith('/'),'MTREE_UNSUPPORTED_DIRECTIVE');name=unescape(parts[0]).removeprefix('./')
  if name in('','.'):continue
  S.relative(name);S.need(name not in found,'MTREE_DUPLICATE');value=dict(defaults);value.update(dict(v.split('=',1)for v in parts[1:]));found[name]=value
 S.need(set(found)==set(rows)-{'.MTREE'},'MTREE_COMPLETE_PACKAGE_NAMESPACE')
 for n,v in found.items():
  r=rows[n];S.need(v.get('type')==r['kind'].replace('dir','dir').replace('link','link')and int(v.get('uid','-1'))==int(v.get('gid','-1'))==0 and int(v['mode'],8)==r['mode'],'MTREE_KIND_OWNER_MODE')
  if r['kind']=='file':S.need(int(v['size'])==r['bytes']and v.get('sha256digest')==r['sha256'],'MTREE_WHOLE_FILE')
  if r['kind']=='link':S.need(unescape(v['link'])==r['target'],'MTREE_LINK_TARGET')

def image_tar(path,expected,image_id,owner):
 S.need(S.hashed(path,12*S.GIB)==expected,'WHOLE_TRANSFER_IMAGE_TAR_PIN');before=S.identity(path.lstat());h=helper();info,state=h.tar_info(8192);rows={};objects={};logical=0
 with tarfile.open(path,mode='r|',tarinfo=info)as archive:
  for item in archive:
   name=item.name.removeprefix('./').rstrip('/')
   if name in('','.'):continue
   S.relative(name);S.need(name not in rows and len(rows)<4096 and not item.sparse,'IMAGE_TAR_NAMESPACE')
   if item.isdir():rows[name]=None;archive.members.clear();continue
   S.need(item.isfile()and 0<=item.size<=12*S.GIB,'IMAGE_TAR_SPECIAL_NODE_OR_SIZE');logical+=item.size;S.need(logical<=12*S.GIB,'IMAGE_TAR_LOGICAL_BOUND');digest=hashlib.sha256();count=0;body=bytearray()if item.size<=8*S.MIB and name in('manifest.json',image_id.removeprefix('sha256:')+'.json','blobs/sha256/'+image_id.removeprefix('sha256:'))else None
   with archive.extractfile(item)as stream:
    while block:=stream.read(S.MIB):
     count+=len(block);S.need(count<=item.size,'IMAGE_TAR_TRUNCATED');digest.update(block)
     if body is not None:body.extend(block)
    # Metadata is re-read only from the bounded ordinary tar member below.
   S.need(count==item.size,'IMAGE_TAR_TRUNCATED');rows[name]=dict(bytes=count,sha256=digest.hexdigest())
   if body is not None:
    objects[name]=bytes(body);S.need(sum(map(len,objects.values()))<=64*S.MIB,'IMAGE_METADATA_TOTAL_BOUND')
   archive.members.clear()
  h.tar_end(archive,state)
 S.need(S.identity(path.lstat())==before,'IMAGE_TAR_CHANGED');manifest=S.decode(objects.get('manifest.json',b'[]'));S.need(type(manifest)is list and len(manifest)==1,'ONE_DOCKER_IMAGE_MANIFEST');item=manifest[0];name=item['Config'];S.relative(name)
 S.need(name in objects and 'sha256:'+S.pin(objects[name])['sha256']==image_id,'IMAGE_CONFIG_IDENTITY');config=S.decode(objects[name]);S.need(config['architecture']=='arm64'and config['os']=='linux'and not config['config'].get('Volumes'),'IMAGE_NATIVE_NO_ANONYMOUS_VOLUME')
 labels=config['config']['Labels'];S.need(labels.get('cachy-asahi.rust199-bootstrap')==owner['token']and labels.get('cachy-asahi.rust199-bootstrap.source')==owner['source']and item['RepoTags']==[owner['tag']],'IMAGE_SOURCE_OWNER_AND_TAG')
 layers=item['Layers'];S.need(type(layers)is list and 1<=len(layers)<=256 and len(set(layers))==len(layers),'IMAGE_LAYER_NAMESPACE')
 S.need(config['rootfs']['type']=='layers'and config['rootfs']['diff_ids']==['sha256:'+rows[n]['sha256']for n in layers],'IMAGE_UNSUPPORTED_LAYER_ENCODING_OR_DIFFID_MISMATCH')
 return dict(image_id=image_id,archive_pin=expected,layers=len(layers),rootfs_reconstruction='NOT_PERFORMED',native_acceptance=False)
