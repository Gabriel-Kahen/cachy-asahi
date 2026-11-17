#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite llhttp postconditions after the unchanged strict native comparator."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import struct
import tarfile

HERE=Path(__file__).resolve().parent
MARKER=b'llhttp: fragmented response and malformed length controls passed'
PACKAGE='cachy-asahi-llhttp-reference-9.3.1-1-aarch64.pkg.tar.'

def need(value,why):
    if not value:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def read(path,cap=4*1024**2):
    before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=cap,'ordinary bounded pair DATA')
    raw=path.read_bytes();after=path.lstat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(after) and len(raw)==before.st_size,'stable pair DATA');return raw

def elf(raw):
    need(64<=len(raw)<=4*1024**2 and raw[:6]==b'\x7fELF\x02\x01','bounded little-endian ELF64')
    need(struct.unpack_from('<HH',raw,16)==(3,183),'AArch64 shared object')
    offset=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
    need(size==56 and 0<count<64 and offset+size*count<=len(raw),'finite complete program headers')
    loads=[];dynamic=[]
    for index in range(count):
        row=struct.unpack_from('<IIQQQQQQ',raw,offset+size*index)
        kind,flags,position,vaddr,paddr,filesize,memsize,alignment=row
        need(position+filesize<=len(raw) and filesize<=memsize,'complete bounded segment')
        if kind==1:
            need(alignment>=4096 and alignment&(alignment-1)==0 and position%alignment==vaddr%alignment,'structural native4K PT_LOAD geometry')
            loads.append(dict(offset=position,vaddr=vaddr,filesize=filesize,alignment=alignment))
        if kind==2:dynamic.append((position,filesize))
    need(loads and len(dynamic)==1,'load and single dynamic table')
    position,extent=dynamic[0];need(extent%16==0 and extent<=65536,'bounded dynamic table')
    values={};terminated=False
    for i in range(position,position+extent,16):
        tag,value=struct.unpack_from('<qQ',raw,i)
        if tag==0:terminated=True;break
        values.setdefault(tag,[]).append(value)
    need(terminated and len(values.get(5,[]))==len(values.get(10,[]))==len(values.get(14,[]))==1,'terminated dynamic table with unique string table/SONAME')
    address=values[5][0];length=values[10][0];matches=[r for r in loads if r['vaddr']<=address and address+length<=r['vaddr']+r['filesize']]
    need(len(matches)==1 and 0<length<=65536,'bounded file-backed string table')
    start=matches[0]['offset']+address-matches[0]['vaddr'];strings=raw[start:start+length]
    def string(offset):
        need(offset<len(strings),'dynamic string offset');end=strings.find(b'\0',offset);need(end>=offset,'terminated dynamic string');return strings[offset:end].decode('ascii')
    soname=string(values[14][0]);needed=[string(v) for v in values.get(1,[])]
    need(soname=='libllhttp.so.9.3' and needed==['libc.so.6'],'exact llhttp SONAME and DT_NEEDED closure')
    need(not values.get(15) and not values.get(29),'no package RPATH/RUNPATH')
    return dict(machine=183,soname=soname,needed=needed,PT_LOAD=loads,structural16K=all(r['alignment']>=16384 and r['offset']%16384==r['vaddr']%16384 for r in loads),native16K='NOT RUN',M2='NOT RUN')

def archive_members(path,selected):
    need(path.name==PACKAGE+'xz','fixed llhttp XZ-only archive basename')
    raw=read(path);need(raw.startswith(b'\xfd7zXZ\x00'),'actual XZ compression only')
    found={};names=set();total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r|xz') as archive:
        for member in archive:
            name=str(Path(member.name.removeprefix('./')))
            need(not name.startswith('/') and '..' not in Path(name).parts and name not in names and len(names)<512,'safe unique bounded native package namespace')
            names.add(name);need(member.isdir() or member.isfile() or member.issym(),'ordinary llhttp package types only')
            need(0<=member.size<=4*1024**2,'bounded package member');total+=member.size;need(total<=8*1024**2,'bounded complete XZ package')
            if name in selected:
                need(member.isfile(),'selected archive member must be regular')
                with archive.extractfile(member) as stream:body=stream.read(member.size+1)
                need(len(body)==member.size,'whole selected XZ member');found[name]=body
    need(set(found)==set(selected),'complete five-member XZ inspection closure')
    return raw,found


def finish(first,second,comparison,image):
    need(re.fullmatch('sha256:[0-9a-f]{64}',image) and first.resolve()!=second.resolve(),'immutable image and distinct builds')
    reviewed=json.loads(read(HERE/'reviewed-inputs.json'));recipe=json.loads(read(HERE/'recipe-pin.json'));lock=pin(read(HERE/'expected349.lock'))['sha256'];records=[];observations=[]
    result=json.loads(read(comparison));need(result['status']=='contents-reproduced' and not result['errors'] and len(result['packages'])==1,'successful unchanged strict comparator')
    name,values=next(iter(result['packages'].items()));need(name==PACKAGE+'xz' and all(values[k] is True for k in ('installed_contents_equal','pkginfo_equal','buildinfo_equal','bytes_equal')),'exact archive/payload/PKGINFO/BUILDINFO pair equality')
    for root in (first,second):
        record=json.loads(read(root/'provenance.json'));need(record['status']=='built-package-static-pass' and record['exit_code']==0 and record['mode']=='native' and record['image_id']==image and record['recipe_inputs']==reviewed and record['expected_packages_sha256']==lock,'actual successful exact native build')
        need(record['builder_host_arch'] in ('arm64','aarch64'),'actual native Docker architecture')
        env=read(root/'artifacts/environment.txt');need(b'aarch64' in env,'retained native uname identity')
        logs=[p for p in (root/'artifacts').iterdir() if p.name=='cachy-asahi-llhttp-reference-9.3.1-1-aarch64-check.log'];need(len(logs)==1 and read(logs[0]).count(MARKER)==1,'one genuine current makepkg check phase and marker')
        validation=json.loads(read(root/'validation.json'));need(not validation['errors'] and len(validation['artifacts'])==1,'one validated actual archive')
        report=validation['artifacts'][0];need(report['artifact']==name and not report['errors'],'matching llhttp archive report');members=report['members']
        need(all(n in members for n in ('.PKGINFO','.BUILDINFO','.MTREE',recipe['license']['path'])),'exact required metadata/license members')
        need(len(report['elf'])==1,'one shared ELF payload')
        library,geometry=next(iter(report['elf'].items()));need(library=='usr/lib/libllhttp.so.9.3.1' and not geometry['errors'],'fixed native library and inherited geometry gate')
        archive=root/'artifacts'/name
        raw,bodies=archive_members(archive,('.PKGINFO','.BUILDINFO','.MTREE',recipe['license']['path'],library))
        need(pin(raw)['sha256']==record['artifacts'][name]==report['sha256'],'current whole archive custody after comparator')
        observed={}
        for member,body in bodies.items():
            need(pin(body)['sha256']==members[member]['sha256'],'whole actual archive member digest: '+member);observed[member]=pin(body)
            if member==recipe['license']['path']:need(pin(body)=={k:recipe['license'][k] for k in ('bytes','sha256')},'exact upstream MIT payload')
            if member=='.MTREE':
                # Header ISIZE is a pre-decompression bound; payload remains data.
                need(len(body)>=18 and int.from_bytes(body[-4:],'little')<=1024**2,'finite gzip MTREE')
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:tree=stream.read(1024**2+1)
                need(len(tree)<=1024**2 and tree.startswith(b'#mtree'),'actual complete MTREE')
            if member==library:observed['ELF']=elf(body)
        observations.append(observed);records.append(record)
    need(records[0]['clean_environment_id'] and records[0]['clean_environment_id']!=records[1]['clean_environment_id'],'two separate clean native builds')
    need(observations[0]==observations[1],'exact MTREE/licenses/ELF and metadata pair equality')
    return dict(status='LLHTTP_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED',builds=2,image_id=image,archive=name,observations=observations,comparison=result,signature='NOT RUN; Root offline follow-up',installation='NOT RUN',native16K='NOT RUN',M2='NOT RUN',performance='NOT MEASURED',release='NOT ADMITTED',Root_acceptance=None)
