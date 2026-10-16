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


def archive(path, stream_module, limits, accounting, *, package=None):
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
                    data=tar.extractfile(member); digest=hashlib.sha256(); consumed=0
                    while block:=data.read(65536):
                        limits_tick(); consumed+=len(block); need(consumed<=member.size,'payload size drift'); digest.update(block)
                    need(consumed==member.size,'truncated file'); row.update(type='file',bytes=consumed,sha256=digest.hexdigest())
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
    accounting.update(bytes=accounting['bytes']+decoded.total,nodes=accounting['nodes']+headers,
                      compressed_bytes=accounting['compressed_bytes']+size)
    return rows,[sorted(group) for group in groups.values()]


def payload(ready, rows, code):
    module=load('_full_installer_archive_stream',Path(code)/'scripts/update/archive_stream.py')
    limits=module.Limits(256*1024**2,4*GIB,8*GIB,500000,GIB,64*1024**2,time.monotonic()+3600)
    accounting={'bytes':0,'nodes':0,'compressed_bytes':0}; nodes={}; owners={}; groups=[]
    for row in rows:
        incoming,links=archive(Path(ready)/row['archive'],module,limits,accounting,package=row)
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


def build(ready, code, output):
    ready,code,output=map(lambda p:Path(p).resolve(strict=True),(ready,code,output))
    need(not (output/'installer-profile.json').exists() and not (output/'payload.json').exists(),'fresh profile output required')
    value,manifest_ref,expected=manifest(ready)
    config_path=code/'scripts/ci/full-root-upgrade-caller/upgrade-config.json'
    config=decode(config_path.read_bytes()); refs={}
    for name,pin in config['code_pins'].items():
        ref=reference(code/name); need(ref['sha256']==pin,'held source pin changed: '+name); refs[name]=ref
    for name in ('scripts/ci/full-root-upgrade-caller/upgrade-config.json','scripts/virtual/common.py',
                 'scripts/virtual/tooling.lock.json','scripts/virtual/audit_tooling.py'):
        refs[name]=reference(code/name)
    constants_=constants(code/'scripts/virtual/common.py',{'TRANSACTION_PROFILE_BYTES','TRANSACTION_LAUNCHER'})
    tool_bytes=constants_['TRANSACTION_PROFILE_BYTES']
    pins=constants(code/'scripts/install/local_transaction.py',{'NATIVE_PROFILE_SHA'})
    need(hashlib.sha256(tool_bytes).hexdigest()==pins['NATIVE_PROFILE_SHA'],'held tool-profile pin differs')
    data=payload(ready,value['packages'],code)
    need(numeric_ids(data)==dict(uids=[0],gids=[0,5,11,50,81,102]),'exact signed numeric identity set required')
    raw=encoded(data)
    need(len(raw)<=MAX_JSON,'payload contract byte bound'); (output/'payload.json').write_bytes(raw)
    builder=value['builder_lock'];need(builder['path']=='builder-packages.lock' and builder['sha256']==BUILDER_LOCK,'preserved builder binding differs')
    builder_path=checked(ready,builder['path'],builder,maximum=1024**2)
    builder_inventory=lock(builder_path.read_bytes(),574)
    binding=tool_selection(value,data,builder_inventory);tool=coherent_tools(tool_bytes)
    profile=dict(schema_version=1,purpose='full-composition-installer-vm',architecture='aarch64',
        expected_lock_sha256=EXPECTED,expected=expected,manifest=manifest_ref,code_files=refs,numeric_vm=NUMERIC_VM,
        payload=reference(output/'payload.json'),tools=tool,tool_profile_sha256=COHERENT_TOOL_PROFILE_SHA,
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
