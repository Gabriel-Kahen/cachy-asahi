#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only signed initial587 profile; never install, extract, mount or fetch."""
import ast
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import time
from types import SimpleNamespace

GIB = 1024**3
EXPECTED = '2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
SHARED = Path('/usr/local/share/full-installer')
MAX_JSON = 96 * 1024**2
NUMERIC_VM = dict(purpose='full-installer-owned-vm-numeric-groups-v1',uid_map=[[0,23001,1]],
    gid_map=[[0,23001,1],[5,23005,1],[11,23011,1],[50,23050,1],[81,23081,1],[102,23102,1]])


# Exact signed archive identities from the held574 input manifest and passive
# header audit. All other nonroot ownership remains refused, including uid!=0.
GROUP_METADATA = {
    ('dbus','1.16.2-1','1aa0bc2be4fa083ec0cb678f05223f55b0c8e498351ad781dc4b7a0987b62bcc'): {
        'usr/lib/dbus-daemon-launch-helper': (b'0',0,81,0o4110,152400)},
    ('filesystem','2025.10.12-1','228b63ef4a88501a68856231a19325a1ad31d92016a692d0a8be181edc70703f'): {
        'srv/ftp': (b'5',0,11,0o555,0), 'var/games': (b'5',0,50,0o775,0)},
    ('polkit','127-3','dbfa3447df79d526968deb0117ff73580969b1f02ce678270a0ba2f1b134244a'): {
        'etc/polkit-1/rules.d': (b'5',0,102,0o750,0)},
    ('util-linux','2.42.4-1','a9ab17512f0f4d1cf7614574e8407561bebd632a50e568111199da0633955046'): {
        'usr/bin/wall': (b'0',0,5,0o2755,67800), 'usr/bin/write': (b'0',0,5,0o2755,67800)},
}


def numeric_metadata(member, name, declared):
    expected=declared.get(name)
    actual=(member.type,member.uid,member.gid,member.mode,member.size)
    if expected is not None:
        need(actual==expected,'declared numeric metadata differs: '+name)
    else:
        need(member.uid==member.gid==0,'undeclared nonroot numeric ownership: '+name)
    return {'mode':member.mode & 0o7777,'uid':member.uid,'gid':member.gid}


def numeric_ids(payload):
    return dict(uids=sorted({n['uid'] for n in payload['nodes'].values()}),
                gids=sorted({n['gid'] for n in payload['nodes'].values()}))


def require_single_id_backend(payload):
    # The default unprivileged --map-root-user engine and parent observer map
    # only0 to guest23001. They cannot chown/map the six declared group entries.
    # Metadata is never flattened to make a single-ID backend appear compatible.
    ids=numeric_ids(payload)
    need(set(ids['uids'])<={0} and set(ids['gids'])<={0},
         'FULL_INSTALLER_NUMERIC_ID_ADAPTER_REQUIRED: uid/gid preservation exceeds the single-ID backend; gids='+str(ids['gids']))
    return ids


def need(value, reason):
    if not value: raise ValueError(reason)


def encoded(value): return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def unique(rows):
    result = {}
    for name, value in rows:
        need(name not in result, 'duplicate JSON key'); result[name] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(name):
    need(type(name) is str and 0 < len(name) <= 4096 and '\0' not in name and
         not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')),
         'canonical relative path required')
    return name


def reference(path): return {'sha256': sha(path), 'bytes': path.stat().st_size}


def checked(root, name, row, *, maximum=256*1024**2, protected=False):
    relative(name); root = Path(root); path = root/name
    need(root.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary path required')
    if protected:
        for parent in path.parents:
            info = parent.stat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
                 'root-protected parent required')
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        size = row.get('bytes', row.get('size'))
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and type(size) is int and
             0 <= size <= maximum and before.st_size == size, 'file size/type differs: '+name)
        if protected:
            need(before.st_uid == before.st_gid == 0 and not before.st_mode & 0o022, 'root-protected file required')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    stable = lambda s: (s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_uid,s.st_gid,s.st_mtime_ns,s.st_ctime_ns)
    need(stable(before) == stable(after) == stable(path.stat()) and digest == row['sha256'], 'input bytes changed: '+name)
    return path


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module); return module


def constants(path, names):
    result = {}
    for node in ast.parse(path.read_bytes()).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in names: result[target.id] = ast.literal_eval(node.value)
    need(set(result) == set(names), 'held literal constants absent')
    return result


def lock(raw, count):
    result = {}
    for line in raw.decode().splitlines():
        pair = line.split()
        need(len(pair) == 2 and re.fullmatch('[a-zA-Z0-9@._+:-]+', pair[0]) and
             pair[0] not in result and len(pair[1]) <= 128, 'invalid package lock')
        result[pair[0]] = pair[1]
    need(len(result) == count, 'exact package count differs'); return result


def manifest(ready, *, protected=False):
    path = Path(ready)/'manifest.json'
    need(path.stat().st_size <= 1024**2, 'manifest byte limit')
    row = reference(path); checked(ready,'manifest.json',row,maximum=1024**2,protected=protected)
    value = decode(path.read_bytes())
    need(value['schema_version'] == 1 and value['status'] == 'READY_SIGNED_INITIAL587', 'producer preparation missing')
    ref = value['expected_lock']; need(ref['path'] == 'expected-installed.lock' and ref['sha256'] == EXPECTED, 'held initial587 lock differs')
    lp = Path(ready)/ref['path']; checked(ready,ref['path'],dict(ref,bytes=lp.stat().st_size),maximum=1024**2,protected=protected)
    expected = lock(lp.read_bytes(),587)
    rows = value['packages']; need(type(rows) is list and len(rows) == 587 and
        {r['name']:r['version'] for r in rows} == expected and len({r['name'] for r in rows}) == 587, 'producer package map differs')
    need(expected.get('cachy-asahi-update') == '4.4.2-2' and expected.get('cachy-asahi-setup') == '0.1.0-3', 'initial updater2/setup3 required')
    signers = {r['signer'] for r in rows}; need(len(signers)==2 and all(re.fullmatch('[0-9A-F]{40}',s) for s in signers), 'exact two declared signer roles required')
    need(len(value['keyrings']) == 2, 'two public keyrings required')
    total = 0
    for r in rows:
        total += r['size']; need(total <= 4*GIB, 'compressed cache aggregate bound')
        checked(ready,r['archive'],{'bytes':r['size'],'sha256':r['sha256']},protected=protected)
        need(r['signature'] == r['archive']+'.sig', 'detached signature sibling required')
        checked(ready,r['signature'],{'bytes':r['signature_size'],'sha256':r['signature_sha256']},maximum=1024**2,protected=protected)
    for key in value['keyrings']: checked(ready,key['path'],key,maximum=1024**2,protected=protected)
    return value, row, expected


def archive(path, stream_module, limits, accounting, *, package=None, library_facts=None):
    """Inspect signed tar bytes, retaining literal links and closed hardlink sets.

    Uses the held bounded decompressor. Unlike the tiny fixture, this distinct
    profile admits full signed payloads, absolute symlinks and the pinned helper.
    No path is extracted and no archive value can increase the fixed budgets.
    """
    rows, hard, seen, headers, ended = {}, {}, set(), 0, False
    key=None if package is None else (package['name'],package['version'],package['sha256'])
    declared=GROUP_METADATA.get(key,{})
    if declared:need(sha(path)==key[2],'numeric metadata archive bytes differ')
    class Header(tarfile.TarInfo):
        @classmethod
        def _fromtarfile(cls, obj, *, dircheck=True):
            nonlocal headers, ended
            limits_tick(); raw = obj.fileobj.read(512)
            if raw == b'\0'*512: ended = True
            else:
                headers += 1; need(accounting['nodes']+headers <= limits.members, 'aggregate tar member limit')
            # Python3.12 host and held3.14 guest expose different private
            # buffer helpers; both use the public header parser semantics.
            parser=getattr(cls,'_frombuf',cls.frombuf)
            options={'dircheck':dircheck} if 'dircheck' in inspect.signature(parser).parameters else {}
            item=parser(raw,obj.encoding,obj.errors,**options)
            item.offset = obj.fileobj.tell()-512
            return item._proc_member(obj)
        def _proc_pax(self,obj):
            need(0 <= self.size <= 65536, 'PAX size limit'); return super()._proc_pax(obj)
        def _proc_gnulong(self,obj):
            need(0 <= self.size <= 65536, 'GNU header size limit'); return super()._proc_gnulong(obj)
        def _proc_sparse(self,*args): raise ValueError('sparse tar refused')
        _proc_gnusparse_00 = _proc_sparse
        _proc_gnusparse_01 = _proc_sparse
        _proc_gnusparse_10 = _proc_sparse
    def limits_tick(): stream_module.tick(limits)
    with Path(path).open('rb') as source:
        size = os.fstat(source.fileno()).st_size
        need(0 < size <= limits.compressed_bytes and accounting['compressed_bytes']+size <= limits.total_compressed_bytes,'archive compressed limit')
        decoded = stream_module.Decoded(source,limits,accounting['bytes'])
        with tarfile.open(fileobj=decoded,mode='r|',bufsize=65536,tarinfo=Header) as tar:
            for member in tar:
                # No retained member catalog; hardlinks use our closed map.
                tar.members.clear()
                limits_tick(); name=member.name.removeprefix('./').rstrip('/')
                if name in ('', '.'):
                    need(member.isdir(), 'tar root must be directory'); continue
                relative(name)
                need(name not in seen and not member.sparse and
                     not any(k.startswith('GNU.sparse') for k in member.pax_headers), 'duplicate/nonroot/sparse payload')
                seen.add(name); need(0 <= member.size <= limits.file_bytes,'file byte limit')
                numeric=numeric_metadata(member,name,declared)
                if name.startswith('.'):
                    need(name in stream_module.CONTROLS and member.isfile() and member.size <= 4*1024**2,'unknown/oversized control member'); continue
                row=numeric
                if member.isdir(): row['type']='directory'
                elif member.isfile():
                    data=tar.extractfile(member); digest=hashlib.sha256(); consumed=0; capture=None
                    config=bytearray() if library_facts is not None and (name=='etc/ld.so.conf' or name.rpartition('/')[0] in ('etc/ld.so.conf.d','usr/lib/ld.so.conf.d') and not name.rsplit('/',1)[1].startswith('.') and name.endswith('.conf')) else None
                    while block:=data.read(65536):
                        limits_tick(); consumed+=len(block); need(consumed<=member.size,'payload size drift'); digest.update(block)
                        if library_facts is not None and consumed==len(block) and block.startswith(b'\x7fELF'):
                            need(member.size<=512*1024**2,'SONAME ELF input byte bound');capture=bytearray()
                        if capture is not None:capture.extend(block)
                        if config is not None:
                            need(consumed<=4096,'SONAME configuration byte bound');config.extend(block)
                    need(consumed==member.size,'truncated file'); row.update(type='file',bytes=consumed,sha256=digest.hexdigest())
                    if capture is not None:
                        need(len(library_facts['elf'])<8192,'SONAME ELF count bound')
                        try:
                            facts=library_facts['parser'](capture)
                            library_facts['elf'][name]={key:facts[key] for key in ('class','byte_order','machine','type','dynamic_present','soname')}
                        except ValueError as error:library_facts['elf'][name]={'refused':str(error)[:128]}
                    if config is not None:library_facts['configs'][name]=bytes(config).decode('ascii')
                elif member.issym():
                    need(member.linkname and len(os.fsencode(member.linkname))<=4096 and '\0' not in member.linkname,'invalid signed symlink')
                    row.update(type='symlink',target=member.linkname)
                elif member.islnk():
                    hard[name]=relative(member.linkname.removeprefix('./')); row['type']='hardlink'
                else: raise ValueError('special archive node refused')
                rows[name]=row
            need(ended,'tar end marker absent'); tail=0
            while block:=tar.fileobj.read(65536):
                limits_tick(); need(not any(block),'trailing tar body'); tail+=len(block)
            need(tail>=512 and decoded.total%512==0 and decoded.done,'incomplete tar padding/frame')
    need(set(declared)<=seen,'declared numeric metadata entry missing')
    groups={}
    for name in hard:
        target=hard[name]; visited={name}
        while target in hard:
            need(target not in visited and len(visited)<40,'hardlink cycle'); visited.add(target); target=hard[target]
        need(target in rows and rows[target]['type']=='file','hardlink must end at archived regular file')
        need(all(rows[name][key]==rows[target][key] for key in ('mode','uid','gid')),'hardlink metadata differs')
        rows[name]=dict(rows[target]); groups.setdefault(target,{target}).add(name)
        if library_facts is not None and target in library_facts['elf']:library_facts['elf'][name]=dict(library_facts['elf'][target])
    if library_facts is not None:need(len(library_facts['elf'])<=8192,'SONAME ELF count bound')
    accounting.update(bytes=accounting['bytes']+decoded.total,nodes=accounting['nodes']+headers,
                      compressed_bytes=accounting['compressed_bytes']+size)
    return rows,[sorted(group) for group in groups.values()]


def payload(ready, rows, code):
    module=load('_full_installer_archive_stream',Path(code)/'scripts/update/archive_stream.py')
    limits=module.Limits(256*1024**2,4*GIB,8*GIB,500000,GIB,64*1024**2,time.monotonic()+3600)
    parser=Path(code)/'scripts/platform/elf_audit.py'
    need(sha(parser)==SONAME_ELF_PARSER_SHA,'SONAME data parser pin differs')
    elf=load('_full_installer_soname_elf',parser)
    library_facts={'parser':elf.parse_elf,'elf':{},'configs':{}}
    accounting={'bytes':0,'nodes':0,'compressed_bytes':0}; nodes={}; owners={}; groups=[]
    for row in rows:
        incoming,links=archive(Path(ready)/row['archive'],module,limits,accounting,package=row,library_facts=library_facts)
        owners[row['name']]=sorted(incoming)
        for name,node in incoming.items():
            need(name not in nodes or nodes[name]['type']==node['type']=='directory' and nodes[name]==node,
                 'signed payload overlap: '+name)
            nodes[name]=node
        groups.extend(links)
    # Canonical payloads may use filesystem aliases only as literal root links,
    # never as extraction parents. This is deliberately fail-closed on new shapes.
    for name in nodes:
        parent=name.rpartition('/')[0]
        while parent:
            need(parent not in nodes or nodes[parent]['type']=='directory','payload parent alias refused: '+name)
            parent=parent.rpartition('/')[0]
    need(len(nodes)<=200000 and sum(n.get('bytes',0) for n in nodes.values())<=6*GIB,'physical payload bound')
    need(nodes.get('usr/bin/ldconfig',{}).get('sha256')=='8794bf13f7a651963a219d8031fe04800d06ac6e44a29fbdfd81b64855b2bd98', 'held static auxiliary differs')
    return dict(schema_version=1,nodes=nodes,ownership=owners,hardlinks=sorted(groups),accounting=accounting,
                library_facts={key:library_facts[key] for key in ('elf','configs')},
                packages={row['name']:row['version'] for row in rows})


# This lane preserves the exact signed574 root. The historical generic profile
# stays frozen globally; only the proven SQLite member differs here.
BASE_TOOL_PROFILE_SHA='b7fbd65e357e132949432fb00e765a05e3c76ea29a41d1df93413870d9fd1ed8'
BUILDER_LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
COHERENT_TOOL_PROFILE_SHA='92342499a72bfde278975c12d33e97165d51ddeb0fd8094ad8bd4d3f0eb6c741'
COHERENT_TOOL_BYTES=85444968
OLD_SQLITE={'owner': 'signed-rootfs', 'path': '/usr/lib/libsqlite3.so.3.53.4', 'sha256': '2db449a85914b1fefa35388d205fa3a8dc946ee3e8ab289cb8a0bfbdc17f575f', 'size': 1657608}
NEW_SQLITE={'owner': 'sqlite 3.54.0-1', 'path': '/usr/lib/libsqlite3.so.3.54.0', 'sha256': 'a98f9af57cba3aab9b499408fd8dc7370f7a4d39beba5ad2dd47fcf8e5ff1c90', 'size': 1657528}
SQLITE_ARCHIVE=dict(name='sqlite',version='3.54.0-1',sha256='88c1b8d04c68597ea09bc1e393ad79fb0faf94b7fe45f507f663a6e68c1c7102',
    size=1849948,signature_sha256='567c1ca19cbee1f80b166232b0d0cc2619f1ad2100d3faf0aedcdf47656c1177',signature_size=566)
SQLITE_ELF=dict(soname='libsqlite3.so.0',needed=['ld-linux-aarch64.so.1','libc.so.6','libm.so.6'],runpath='/usr/lib',rpath=None,interpreter=None)


def coherent_tools(raw):
    need(hashlib.sha256(raw).hexdigest()==BASE_TOOL_PROFILE_SHA,'exact historical tool profile required')
    value=decode(raw)
    need(len(value['files'])==136 and sum(row['size'] for row in value['files'])==85445048 and
         [row for row in value['files'] if row['path']==OLD_SQLITE['path']]==[OLD_SQLITE], 'historical SQLite role differs')
    value['files']=[dict(NEW_SQLITE) if row['path']==OLD_SQLITE['path'] else row for row in value['files']]
    need(value['aliases'].pop(OLD_SQLITE['path'])==OLD_SQLITE['path'],'historical SQLite alias differs')
    for path in (NEW_SQLITE['path'],'/usr/lib/libsqlite3.so','/usr/lib/libsqlite3.so.0'):
        need(path not in value['aliases'],'unexpected existing SQLite alias');value['aliases'][path]=NEW_SQLITE['path']
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    need(hashlib.sha256(raw).hexdigest()==COHERENT_TOOL_PROFILE_SHA and len(value['files'])==136 and
         sum(row['size'] for row in value['files'])==COHERENT_TOOL_BYTES,'closed coherent profile differs')
    return value


def tool_selection(manifest,payload,builder):
    raw=''.join(name+' '+version+'\n' for name,version in sorted(builder.items())).encode()
    need(len(builder)==574 and hashlib.sha256(raw).hexdigest()==BUILDER_LOCK and builder.get('sqlite')=='3.54.0-1',
         'exact preserved574 builder required')
    rows=[row for row in manifest['packages'] if row['name']=='sqlite']
    need(len(rows)==1 and all(rows[0].get(k)==v for k,v in SQLITE_ARCHIVE.items()),'exact signed SQLite source tuple required')
    nodes=payload['nodes'];path=NEW_SQLITE['path'].lstrip('/')
    expected=dict(type='file',uid=0,gid=0,mode=0o755,bytes=NEW_SQLITE['size'],sha256=NEW_SQLITE['sha256'])
    need(nodes.get(path)==expected and OLD_SQLITE['path'].lstrip('/') not in nodes,'signed SQLite payload differs')
    for name in ('usr/lib/libsqlite3.so','usr/lib/libsqlite3.so.0'):
        need(nodes.get(name)==dict(type='symlink',uid=0,gid=0,mode=0o777,target='libsqlite3.so.3.54.0'),'signed SQLite alias differs')
    return dict(purpose='full-installer-preserved574-sqlite354-v1',builder_lock_sha256=BUILDER_LOCK,
                base_profile_sha256=BASE_TOOL_PROFILE_SHA,profile_sha256=COHERENT_TOOL_PROFILE_SHA,archive=SQLITE_ARCHIVE,elf=SQLITE_ELF)


def validate_tools(profile,manifest,payload,builder,held):
    need(profile['tools']==coherent_tools(held) and profile['base_tool_profile_sha256']==BASE_TOOL_PROFILE_SHA and
         profile['tool_profile_sha256']==COHERENT_TOOL_PROFILE_SHA and
         profile['tool_profile_binding']==tool_selection(manifest,payload,builder),'coherent signed tool binding differs')


def sqlite_elf(raw):
    # Parse only the one archive-pinned replacement. All135 other exact ELF/DSO
    # bytes remain the original reviewed closure. No loader or CDLL executes.
    need(len(raw)==NEW_SQLITE['size'] and hashlib.sha256(raw).hexdigest()==NEW_SQLITE['sha256'],'SQLite ELF bytes differ')
    need(raw[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH',raw,16)==(3,183),'SQLite ELF64LE AArch64 DSO required')
    offset=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
    need(size==56 and 0<count<=128 and offset+size*count<=len(raw),'SQLite program header bounds')
    loads=[];dynamic=[];interpreter=None
    for i in range(count):
        kind,flags,fileoff,vaddr,paddr,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',raw,offset+i*size)
        need(fileoff+filesz<=len(raw),'SQLite segment bounds')
        if kind==1:loads.append((vaddr,filesz,fileoff))
        elif kind==2:dynamic.append((fileoff,filesz))
        elif kind==3:
            need(interpreter is None and filesz<=4096 and raw[fileoff+filesz-1]==0,'SQLite interpreter bounds')
            interpreter=raw[fileoff:fileoff+filesz-1].decode()
    need(len(dynamic)==1 and dynamic[0][1]%16==0 and dynamic[0][1]<=65536,'SQLite dynamic table bounds')
    values={};terminated=False
    for pos in range(dynamic[0][0],sum(dynamic[0]),16):
        tag,value=struct.unpack_from('<qQ',raw,pos)
        if tag==0:terminated=True;break
        values.setdefault(tag,[]).append(value)
    need(terminated and len(values.get(5,[]))==len(values.get(10,[]))==1,'SQLite string table missing')
    pointer=values[5][0];length=values[10][0];need(0<length<=65536,'SQLite string table bound')
    maps=[fileoff+pointer-address for address,filesz,fileoff in loads if address<=pointer and pointer+length<=address+filesz]
    need(len(maps)==1,'SQLite string table mapping differs');strings=raw[maps[0]:maps[0]+length]
    def string(index):
        need(0<=index<len(strings),'SQLite string offset');end=strings.find(b'\0',index)
        need(end>=index and end-index<=4096,'SQLite string bound');return strings[index:end].decode('ascii')
    def single(tag):
        need(len(values.get(tag,[]))<=1,'duplicate SQLite dynamic role');return None if tag not in values else string(values[tag][0])
    facts=dict(soname=single(14),needed=sorted(string(i) for i in values.get(1,[])),runpath=single(29),rpath=single(15),interpreter=interpreter)
    need(facts==SQLITE_ELF,'SQLite dynamic closure differs')
    return facts


# This policy models only the held GNU8362 scan/link rules and exact full587 lane.
SONAME_ELF_PARSER_SHA='72ec18c7d8580094164b3ea4c11fcff2583519b4cd861e5c436ec9d7a779401b'
SONAME_PURPOSE='full-installer-held587-ldconfig-sonames-v1'
SONAME_OUTPUTS={'usr/lib/libvsscript.so':dict(type='symlink',mode=0o777,uid=0,gid=0,target='libvapoursynth-script.so.0')}
SONAME_TARGET='usr/lib/python3.14/site-packages/vapoursynth/libvsscript.so'
SONAME_TARGET_NODE=dict(type='file',mode=0o755,uid=0,gid=0,bytes=67816,sha256='3ba72b1bc64942269cc29de3343a6250fcfb0a1b89f9a5d615d2f78973b3e65c')
SONAME_PACKAGES={
 'vapoursynth':dict(version='80-1',sha256='92bfe702802d00826933e5c3ac711709c6132f76813c168b0b98122499199536',size=1624620,
     signature_sha256='6a990da1b1f1d87d7789d30babb41d2671094b806f3744bde9b36277a176c5d4',signature_size=566),
 'glibc':dict(version='2.43+r22+g8362e8ce10b2-2',sha256='8fac217e98c6e4342326726b2640ac254e8c82032f06f30bfa13ebbcc4fcb25b',size=9676568,
     signature_sha256='82501115482ffeb93cce58cbc36372d917159f9dd60e3b98fd465e94e16c2103',signature_size=566)}


def soname_compare(left,right):
    # GNU _dl_cache_libcmp, restricted to bounded source-held ASCII basenames.
    need(all(re.fullmatch('[A-Za-z0-9_.+-]{1,255}',name) for name in (left,right)),'SONAME candidate basename')
    a,b=left+'\0',right+'\0';i=j=0
    while a[i]!='\0':
        if a[i].isdigit() and b[j].isdigit():
            x,y=i,j
            while a[i].isdigit():i+=1
            while b[j].isdigit():j+=1
            need(i-x<=9 and j-y<=9,'SONAME numeric comparison bound')
            value=int(a[x:i])-int(b[y:j])
            if value:return value
        elif a[i].isdigit():return 1
        elif b[j].isdigit():return -1
        elif a[i]!=b[j]:return ord(a[i])-ord(b[j])
        else:i+=1;j+=1
    return ord(a[i])-ord(b[j])


def project_sonames(payload,resolver):
    """Finite data projection, not an execution or source/binary correspondence proof."""
    nodes=payload['nodes'];facts=payload['library_facts'];deadline=time.monotonic()+60
    def tick():need(time.monotonic()<deadline,'SONAME projection deadline')
    limits=SimpleNamespace(max_nodes=200000,max_depth=64,tick=tick)
    def endpoint(name):return resolver(nodes,name,limits=limits)[0]
    main=nodes.get('etc/ld.so.conf',{})
    need(main.get('sha256')=='785c6c3614a27ae6115a27c1ca55bbf333654780997c4ba7e181172b021d1bf3','SONAME main configuration pin')
    active={name for name in nodes if name=='etc/ld.so.conf' or name.rpartition('/')[0] in
            ('etc/ld.so.conf.d','usr/lib/ld.so.conf.d') and not name.rsplit('/',1)[1].startswith('.') and name.endswith('.conf')}
    need(active==set(facts['configs']),'SONAME configuration facts incomplete')
    for name,text in facts['configs'].items():
        raw=text.encode('ascii');node=nodes[name]
        need(node['type']=='file' and node['bytes']==len(raw) and node['sha256']==hashlib.sha256(raw).hexdigest(),'SONAME configuration facts/content mismatch')
    dirs={'usr/lib','usr/lib64'};config_count=0
    for name,text in facts['configs'].items():
        tick()
        if name=='etc/ld.so.conf':continue
        parent,_,base=name.rpartition('/')
        if parent not in ('etc/ld.so.conf.d','usr/lib/ld.so.conf.d') or base.startswith('.') or not base.endswith('.conf'):continue
        config_count+=1;need(config_count<=32,'SONAME configuration count bound')
        need(nodes[name]['type']=='file' and nodes[name]['uid']==nodes[name]['gid']==0 and not nodes[name]['mode']&0o022,'SONAME configuration metadata')
        for line in text.splitlines():
            line=line.split('#',1)[0].strip(' \t')
            if not line:continue
            allowed=('/usr/lib/libfakeroot',) if name=='usr/lib/ld.so.conf.d/fakeroot.conf' else ('/usr/lib','/usr/lib64')
            need(line in allowed,'SONAME undeclared scan directory');dirs.add(line.lstrip('/'))
    actual=set()
    for directory in sorted(dirs):
        if directory not in nodes:continue
        resolved=endpoint(directory)
        need(nodes[resolved]==dict(type='directory',mode=0o755,uid=0,gid=0),'SONAME scan directory metadata');actual.add(resolved)
    children={directory:[] for directory in actual}
    for name in nodes:
        tick();directory,_,base=name.rpartition('/')
        if directory in children:children[directory].append(name)
    need(sum(map(len,children.values()))<=8192,'SONAME directory entry bound')
    hard={name:tuple(group) for group in payload['hardlinks'] for name in group}
    same=lambda a,b:a==b or a in hard and b in hard and hard[a]==hard[b]
    generated={};replacements=[];candidates=0;hwcaps=[]
    for directory,names in sorted(children.items()):
        winners={}
        hw=directory+'/glibc-hwcaps'
        if hw in nodes:
            need(nodes[hw]['type']=='directory','SONAME hwcaps directory shape')
            hwcaps.extend(name for name,node in nodes.items() if name.rpartition('/')[0]==hw and node['type']=='directory')
        for name in sorted(names):
            tick();base=name.rsplit('/',1)[1];node=nodes[name]
            dso=(base.startswith(('lib','ld-')) and '.so' in base) or base.startswith(('ld.so.','ld64.so.'))
            temporary=(base.endswith(('.#prelink#','.dpkg-new','.dpkg-tmp')) or re.search(r'\.#prelink#\..{6}$',base) is not None or ';' in base)
            if not dso or temporary or node['type']=='directory':continue
            resolved=endpoint(name);need(nodes[resolved]['type']=='file','SONAME candidate endpoint must be regular')
            elf=facts['elf'].get(resolved)
            if elf is None:continue  # Inspected non-ELF linker script, like libc.so.
            need('refused' not in elf,'SONAME ELF facts incomplete: '+resolved)
            if elf['type']!=3:continue  # The held GNU reader rejects non-ET_DYN.
            need((elf['class'],elf['byte_order'],elf['machine'])==(64,'little',183),'SONAME foreign architecture candidate')
            soname=elf['soname'] or base
            need(re.fullmatch('[A-Za-z0-9_.+-]{1,255}',soname),'SONAME output must be a contained basename')
            linked=node['type']=='symlink'
            if linked and base!=soname and not(base.endswith('.so') and soname.startswith(base)):linked=False
            if linked:soname=base
            candidate=dict(name=base,endpoint=resolved,is_link=linked);old=winners.get(soname)
            if old is None or (old['is_link'] and not linked) or linked==old['is_link'] and soname_compare(old['name'],base)<0:winners[soname]=candidate
            elif old is not None and old['is_link']==linked and soname_compare(old['name'],base)==0:
                need(old['name']==base,'SONAME equal-version literal-target ambiguity')
            candidates+=1
        for soname,winner in winners.items():
            if winner['is_link']:continue
            name=directory+'/'+soname
            if name in nodes:
                current=endpoint(name)
                if nodes[name]['type']=='symlink' and not same(current,winner['endpoint']):replacements.append(name)
                continue  # Existing regular files are never replaced by GNU.
            generated[name]=dict(type='symlink',mode=0o777,uid=0,gid=0,target=winner['name'])
    need(len(generated)<=32 and not replacements,'SONAME packaged alias replacement refused')
    return dict(directories=sorted(actual),entries=sum(map(len,children.values())),candidates=candidates,
                hwcaps_no_link_directories=sorted(hwcaps),outputs=generated)


def soname_binding(payload):
    nodes=payload['nodes']
    need(payload['soname_projection']['outputs']==SONAME_OUTPUTS,'unexpected finite SONAME output set: '+encoded(payload['soname_projection']['outputs']).decode()[:4096])
    need(nodes.get(SONAME_TARGET)==SONAME_TARGET_NODE,'SONAME target payload differs')
    for name in ('usr/lib/libvapoursynth-script.so','usr/lib/libvapoursynth-script.so.0'):
        need(nodes.get(name)==dict(type='symlink',mode=0o777,uid=0,gid=0,target='python3.14/site-packages/vapoursynth/libvsscript.so'),'SONAME input alias differs')
    need(all(name not in nodes for name in SONAME_OUTPUTS),'SONAME output is already package-owned')
    need({SONAME_TARGET,'usr/lib/libvapoursynth-script.so','usr/lib/libvapoursynth-script.so.0'}<=set(payload['ownership'].get('vapoursynth',())) and
         'usr/bin/ldconfig' in payload['ownership'].get('glibc',()),'SONAME package ownership differs')
    need(nodes.get('usr/bin/ldconfig')==dict(type='file',mode=0o755,uid=0,gid=0,bytes=865664,sha256='8794bf13f7a651963a219d8031fe04800d06ac6e44a29fbdfd81b64855b2bd98'),'SONAME helper payload differs')
    need(all(payload['packages'].get(name)==row['version'] for name,row in SONAME_PACKAGES.items()),'SONAME payload package identity differs')
    return dict(purpose=SONAME_PURPOSE,packages=SONAME_PACKAGES,outputs=SONAME_OUTPUTS,
                facts_sha256=hashlib.sha256(encoded(payload['library_facts'])).hexdigest(),
                projection=payload['soname_projection'],elf_parser_sha256=SONAME_ELF_PARSER_SHA,
                helper_source_sha256='0ba98dc9182e70f18f0b22c721cd9a4fbff7ce635250acc41ed1200faf2b6d57',
                libcmp_source_sha256='b41065543cd93b202ccc9c72c3648339c35470d251bb36ba563d84c1733d3728')


def soname_selection(manifest,payload,code):
    for name,expected in SONAME_PACKAGES.items():
        rows=[row for row in manifest['packages'] if row['name']==name]
        need(len(rows)==1 and all(rows[0].get(key)==value for key,value in expected.items()),'SONAME signed archive tuple differs: '+name)
    resolver=load('_full_installer_soname_paths',Path(code)/'scripts/update/root_path.py')
    need(project_sonames(payload,resolver.resolve)==payload['soname_projection'],'SONAME projection/facts differ')
    return soname_binding(payload)


def build(ready, code, output):
    ready,code,output=map(lambda p:Path(p).resolve(strict=True),(ready,code,output))
    need(not (output/'installer-profile.json').exists() and not (output/'payload.json').exists(),'fresh profile output required')
    value,manifest_ref,expected=manifest(ready)
    config_path=code/'scripts/ci/full-root-upgrade-caller/upgrade-config.json'
    config=decode(config_path.read_bytes()); refs={}
    for name,pin in config['code_pins'].items():
        ref=reference(code/name); need(ref['sha256']==pin,'held source pin changed: '+name); refs[name]=ref
    for name in ('scripts/ci/full-root-upgrade-caller/upgrade-config.json','scripts/virtual/common.py',
                 'scripts/virtual/tooling.lock.json','scripts/virtual/audit_tooling.py',
                 'scripts/platform/elf_audit.py','scripts/update/root_path.py'):
        refs[name]=reference(code/name)
    constants_=constants(code/'scripts/virtual/common.py',{'TRANSACTION_PROFILE_BYTES','TRANSACTION_LAUNCHER'})
    tool_bytes=constants_['TRANSACTION_PROFILE_BYTES']
    pins=constants(code/'scripts/install/local_transaction.py',{'NATIVE_PROFILE_SHA'})
    need(hashlib.sha256(tool_bytes).hexdigest()==pins['NATIVE_PROFILE_SHA'],'held tool-profile pin differs')
    data=payload(ready,value['packages'],code)
    need(numeric_ids(data)==dict(uids=[0],gids=[0,5,11,50,81,102]),'exact signed numeric identity set required')
    resolver=load('_full_installer_soname_projection_paths',code/'scripts/update/root_path.py')
    data['soname_projection']=project_sonames(data,resolver.resolve)
    derived=soname_selection(value,data,code)
    raw=encoded(data)
    need(len(raw)<=MAX_JSON,'payload contract byte bound'); (output/'payload.json').write_bytes(raw)
    builder=value['builder_lock'];need(builder['path']=='builder-packages.lock' and builder['sha256']==BUILDER_LOCK,'preserved builder binding differs')
    builder_path=checked(ready,builder['path'],builder,maximum=1024**2)
    builder_inventory=lock(builder_path.read_bytes(),574)
    binding=tool_selection(value,data,builder_inventory);tool=coherent_tools(tool_bytes)
    profile=dict(schema_version=1,purpose='full-composition-installer-vm',architecture='aarch64',
        expected_lock_sha256=EXPECTED,expected=expected,manifest=manifest_ref,code_files=refs,numeric_vm=NUMERIC_VM,
        payload=reference(output/'payload.json'),derived_output_binding=derived,tools=tool,tool_profile_sha256=COHERENT_TOOL_PROFILE_SHA,
        base_tool_profile_sha256=pins['NATIVE_PROFILE_SHA'],tool_profile_binding=binding,
        launcher=constants_['TRANSACTION_LAUNCHER'],limits=dict(packages=587,nodes=200000,bytes=6*GIB,file_bytes=GIB,seconds=4500),
        scope='fresh signed initial587 transaction plus declared user fixtures in generic4K VM',
        excluded=['native-container P0','Asahi production install','target boot/session','partitioning','macOS recovery','M2 hardware','16K kernel','performance'])
    (output/'installer-profile.json').write_bytes(encoded(profile)); return profile


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('ready','code','output'): parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args(); build(args.ready,args.code,args.output)
