#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite libgit2 postconditions; structural observations confer no target acceptance."""
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile

HERE=Path(__file__).resolve().parent
MARKER=b'libgit2: version/features, repository/blob and invalid-OID controls passed'
PACKAGE='cachy-asahi-libgit2-reference-1.9.7-1-aarch64.pkg.tar.'
LIBRARY='usr/lib/libgit2.so.1.9.7'
SONAME='libgit2.so.1.9'
# Explicit policy, derived from the pinned original host dynamic metadata and
# native-plan dependencies. Actual native output must independently satisfy it.
NEEDED=['libc.so.6','libcrypto.so.3','libllhttp.so.9.3','libpcre2-8.so.0','libssh2.so.1','libssl.so.3','libz.so.1']
DEPENDS=['glibc','openssl','libssh2','pcre2','zlib','llhttp=9.3.1']
SIGNED349_SHA256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'

def need(value,why):
    if not value:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def read(path,cap=8*1024**2):
    before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=cap,'ordinary bounded pair DATA')
    raw=path.read_bytes();after=path.lstat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(after) and len(raw)==before.st_size,'stable pair DATA');return raw

def elf(raw):
    need(64<=len(raw)<=8*1024**2 and raw[:6]==b'\x7fELF\x02\x01','bounded little-endian ELF64')
    need(struct.unpack_from('<HH',raw,16)==(3,183),'AArch64 shared object')
    offset=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
    need(size==56 and 0<count<64 and offset+size*count<=len(raw),'finite complete program headers')
    loads=[];dynamic=[]
    for index in range(count):
        kind,flags,position,vaddr,paddr,filesize,memsize,alignment=struct.unpack_from('<IIQQQQQQ',raw,offset+size*index)
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
    need(soname==SONAME and len(needed)==len(set(needed)) and sorted(needed)==NEEDED,'exact libgit2 SONAME and finite DT_NEEDED policy')
    need(not values.get(15) and not values.get(29),'no package RPATH/RUNPATH')
    return dict(machine=183,soname=soname,needed=needed,PT_LOAD=loads,structural16K=all(r['alignment']>=16384 and r['offset']%16384==r['vaddr']%16384 for r in loads),native16K='NOT RUN',M2='NOT RUN')

def archive_members(path,selected):
    need(path.name==PACKAGE+'xz','fixed libgit2 XZ-only archive basename')
    raw=read(path);need(raw.startswith(b'\xfd7zXZ\x00'),'actual XZ compression only')
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=64*1024**2)
    tar=decoder.decompress(raw,max_length=32*1024**2+1)
    need(len(tar)<=32*1024**2 and decoder.eof and not decoder.unused_data,'complete bounded single XZ stream')
    found={};nodes={};total=0
    with tarfile.open(fileobj=io.BytesIO(tar),mode='r:') as archive:
        for member in archive:
            original=member.name.removeprefix('./');name=str(PurePosixPath(original))
            need(name not in ('','.') and not name.startswith('/') and '..' not in PurePosixPath(name).parts and name==original.rstrip('/') and name not in nodes and len(nodes)<1024,'safe unique bounded native package namespace')
            need(member.isdir() or member.isfile() or member.issym(),'ordinary libgit2 package types only')
            need(0<=member.size<=8*1024**2,'bounded package member');total+=member.size;need(total<=16*1024**2,'bounded complete XZ package')
            if member.issym():
                need(name in ('usr/lib/libgit2.so','usr/lib/libgit2.so.1.9') and member.linkname=={'usr/lib/libgit2.so':'libgit2.so.1.9','usr/lib/libgit2.so.1.9':'libgit2.so.1.9.7'}[name],'exact library symlink chain')
            nodes[name]='directory' if member.isdir() else 'file' if member.isfile() else 'symlink'
            if name in selected:
                need(member.isfile(),'selected archive member must be regular')
                with archive.extractfile(member) as stream:body=stream.read(member.size+1)
                need(len(body)==member.size,'whole selected XZ member');found[name]=body
    for name in nodes:
        need(all(str(parent) not in nodes or nodes[str(parent)]=='directory' for parent in PurePosixPath(name).parents),'ordinary archive ancestors')
    need(set(found)==set(selected),'complete metadata/license/ELF XZ inspection closure')
    return raw,found

def metadata(raw):
    result={}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):continue
        need(' = ' in line,'ordinary package metadata record');key,value=line.split(' = ',1)
        need(re.fullmatch('[a-z0-9_]+',key) and value,'finite package metadata key/value');result.setdefault(key,[]).append(value)
    return result

def metadata_joins(bodies,reviewed,lock):
    pkg=metadata(bodies['.PKGINFO']);build=metadata(bodies['.BUILDINFO'])
    fixed=dict(pkgname=['cachy-asahi-libgit2-reference'],pkgver=['1:1.9.7-1'],arch=['aarch64'],license=['LicenseRef-libgit2'],depend=DEPENDS)
    need(all(sorted(pkg.get(k,[]))==sorted(v) for k,v in fixed.items()),'exact original libgit2 PKGINFO identity/license/dependencies')
    need(build.get('format')==['2'] and build.get('pkgname')==fixed['pkgname'] and build.get('pkgver')==fixed['pkgver'] and build.get('pkgarch')==fixed['arch'] and build.get('pkgbuild_sha256sum')==[reviewed['PKGBUILD']],'exact BUILDINFO source and package identity')
    expected=[name+'-'+version for name,version in (line.split(' ') for line in lock.decode().splitlines())]
    installed=build.get('installed',[])
    need(len(installed)==350 and all(value.rsplit('-',1)[-1] in ('aarch64','any') for value in installed) and sorted(value.rsplit('-',1)[0] for value in installed)==sorted(expected),'exact350 BUILDINFO inventory with project TEST llhttp')

def finish(first,second,comparison,image):
    need(re.fullmatch('sha256:[0-9a-f]{64}',image) and first.resolve()!=second.resolve(),'immutable image and distinct builds')
    reviewed=json.loads(read(HERE/'reviewed-inputs.json'));recipe=json.loads(read(HERE/'recipe-pin.json'));lock=read(HERE/'expected350.lock');lock_sha=pin(lock)['sha256'];records=[];observations=[]
    expected={n:r['sha256'] for n,r in recipe['files'].items()};expected[recipe['upstream']['archive']['filename']]=recipe['upstream']['archive']['sha256']
    need(reviewed==expected,'complete exact original recipe and upstream source joins')
    lines=lock.decode().splitlines();need(len(lines)==350 and lines==sorted(set(lines)) and all(re.fullmatch(r'[a-z0-9@_+.-]+ [^\s]+',line) for line in lines) and len({line.split(' ')[0] for line in lines})==350 and 'cachy-asahi-llhttp-reference 9.3.1-1' in lines,'exact sorted350 dependency image inventory')
    original=('\n'.join(line for line in lines if line!='cachy-asahi-llhttp-reference 9.3.1-1')+'\n').encode()
    need(pin(original)['sha256']==SIGNED349_SHA256,'unchanged exact signed349 plus project TEST llhttp only')
    policy=recipe['elf_policy'];need(policy['soname']==SONAME and policy['library']==LIBRARY and policy['needed']==NEEDED and policy['evidence_pin']==recipe['files'][policy['evidence']] and policy['native_plan_pin']==recipe['files'][policy['native_plan']],'pinned original dependency-policy evidence')
    licenses={row['path']:row for row in recipe['licenses']};need(set(licenses)=={'usr/share/licenses/cachy-asahi-libgit2-reference/'+n for n in ('AUTHORS','COPYING')},'complete original upstream notices')
    for row in licenses.values():
        source=recipe['upstream']['members'][row['source_member']]
        need(source['type']=='file' and all(source[k]==row[k] for k in ('bytes','sha256')),'exact upstream license/source member join')
    result=json.loads(read(comparison));need(result['status']=='contents-reproduced' and not result['errors'] and len(result['packages'])==1,'successful unchanged strict comparator')
    name,values=next(iter(result['packages'].items()));need(name==PACKAGE+'xz' and all(values[k] is True for k in ('installed_contents_equal','pkginfo_equal','buildinfo_equal','bytes_equal')),'exact archive/payload/PKGINFO/BUILDINFO pair equality')
    for root in (first,second):
        record=json.loads(read(root/'provenance.json'));need(record['status']=='built-package-static-pass' and record['exit_code']==0 and record['mode']=='native' and record['image_id']==image and record['recipe_inputs']==reviewed and record['expected_packages_sha256']==lock_sha,'actual successful exact native build')
        need(record['builder_host_arch'] in ('arm64','aarch64'),'actual native Docker architecture')
        env=read(root/'artifacts/environment.txt');need(b'aarch64' in env.splitlines()[0],'retained native uname identity')
        need(read(root/'artifacts/packages.lock')==lock and read(root/'expected-packages.lock')==lock,'retained exact350 clean-build inventory')
        need(read(root/'build.log').count(b'Starting check()')==1,'one normal makepkg check phase')
        logs=[p for p in (root/'artifacts').iterdir() if p.name=='cachy-asahi-libgit2-reference-1.9.7-1-aarch64-check.log'];need(len(logs)==1,'one current makepkg check log')
        log=read(logs[0]);need(log.count(MARKER)==1 and b'100% tests passed, 0 tests failed out of 2' in log and all(re.search(rb'Test\s+#\d+: '+suite+rb'\s+\.+\s+Passed\s',log) for suite in (b'offline',b'util')),'genuine current upstream offline/util and smoke checks')
        validation=json.loads(read(root/'validation.json'));need(not validation['errors'] and len(validation['artifacts'])==1,'one validated actual archive')
        report=validation['artifacts'][0];need(report['artifact']==name and not report['errors'],'matching libgit2 archive report');members=report['members']
        selected=('.PKGINFO','.BUILDINFO','.MTREE',*licenses,LIBRARY)
        need(all(n in members for n in selected),'exact required metadata/license/ELF members')
        need(set(report['elf'])=={LIBRARY} and not report['elf'][LIBRARY]['errors'],'one fixed native shared library and inherited geometry gate')
        raw,bodies=archive_members(root/'artifacts'/name,selected)
        need(pin(raw)['sha256']==record['artifacts'][name]==report['sha256'],'current whole archive custody after comparator')
        metadata_joins(bodies,reviewed,lock);observed={}
        for member,body in bodies.items():
            need(pin(body)['sha256']==members[member]['sha256'],'whole actual archive member digest: '+member);observed[member]=pin(body)
            if member in licenses:need(pin(body)=={k:licenses[member][k] for k in ('bytes','sha256')},'exact upstream COPYING/AUTHORS payload')
            if member=='.MTREE':
                need(len(body)>=18 and int.from_bytes(body[-4:],'little')<=1024**2,'finite gzip MTREE')
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:tree=stream.read(1024**2+1)
                need(len(tree)<=1024**2 and tree.startswith(b'#mtree'),'actual complete MTREE')
            if member==LIBRARY:observed['ELF']=elf(body)
        observations.append(observed);records.append(record)
    need(records[0]['clean_environment_id'] and records[0]['clean_environment_id']!=records[1]['clean_environment_id'],'two separate clean native builds')
    need(observations[0]==observations[1],'exact MTREE/licenses/ELF and metadata pair equality')
    return dict(status='LIBGIT2_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED',builds=2,image_id=image,archive=name,observations=observations,comparison=result,signature='NOT RUN; Root offline follow-up',installation='NOT RUN',native16K='NOT RUN',M2='NOT RUN',performance='NOT MEASURED',release='NOT ADMITTED',Root_acceptance=None)
