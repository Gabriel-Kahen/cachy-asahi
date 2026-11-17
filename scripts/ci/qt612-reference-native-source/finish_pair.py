# SPDX-License-Identifier: MIT
"""Passive current-byte Qt612 receipt finisher; no actor or admission authority."""
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile

JSON_CAP, COMPRESSED_CAP, EXPANDED_CAP = 32*1024**2, 512*1024**2, 2*1024**3
MEMBER_CAP, NODE_CAP = 128*1024**2, 100000
MARKER = b'PASS_QT612_OFFSCREEN_API_SMOKE_ONLY'
METADATA = {'.PKGINFO','.BUILDINFO','.MTREE'}
VERSION_HEADER = 'usr/include/qt6/QtCore/qtcoreversion.h'
CONTRACT_PIN = dict(bytes=10867,sha256='1cc18024992ddd926d0ce12efa0a1f1901f9d73b823214f51f6f24fb679220ec')
SERIAL_CONTRACT_PIN = dict(bytes=12002,sha256='5d3d9a17f91b7849214fa405b577b4584830ebe5a7d2f2c3fdb1794ec0a50dfc')
NOTICE_PIN = dict(bytes=20042,sha256='3651e4bca7846caee61183c2bc55bf4988c6f4f2a56af81f3948afe03d41cfda')


def need(value, why):
    if not value:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def validate_pair_records(first, second, comparison, *, expected):
    """Pure MODEL-test seam; this checks records, never current filesystem custody."""
    need(type(expected) is dict and set(expected) == {'image','inventory_sha256','recipe_inputs','nonce','contract','notice_policy'}, 'EXACT_PAIR_EXPECTATION')
    need(re.fullmatch('sha256:[0-9a-f]{64}',expected['image'] or '')
         and re.fullmatch('[0-9a-f]{64}',expected['inventory_sha256'] or '')
         and re.fullmatch('[0-9a-f]{32}',expected['nonce'] or ''), 'IMMUTABLE_PAIR_EXPECTATION')
    contract, policy = expected['contract'], expected['notice_policy']
    need(pin(encoded(contract)) in (CONTRACT_PIN,SERIAL_CONTRACT_PIN)
         and pin(encoded(policy)) == NOTICE_PIN, 'EXACT_F_CONTRACT_NOTICE_PINS')
    # F's sealed active14 stay unchanged. The isolated build view additionally
    # carries the exact pinned archive so normal offline makepkg finds its URL.
    reviewed = {n:r['sha256'] for n,r in contract['native_recipe_files'].items()}
    need(len(reviewed) == 14, 'F_SEALED_ACTIVE14')
    reviewed['qtbase-everywhere-src-6.12.0.tar.xz'] = contract['upstream']['archive']['sha256']
    need(expected['recipe_inputs'] == reviewed and len(reviewed) == 15, 'F_ACTIVE14_PLUS_ARCHIVE_BUILDVIEW15')
    name = contract['package']['filename']
    need(comparison['status'] == 'contents-reproduced' and comparison['errors'] == []
         and set(comparison['packages']) == {name}
         and all(comparison['packages'][name].get(k) is True for k in
                 ('installed_contents_equal','pkginfo_equal','buildinfo_equal','bytes_equal')), 'UNCHANGED_STRICT_COMPARISON')
    for index, record in enumerate((first,second),1):
        need(record['status'] == 'built-package-static-pass' and type(record['exit_code']) is int
             and record['exit_code'] == 0 and record['mode'] == 'native'
             and record['image_id'] == record['image'] == expected['image']
             and record['expected_packages_sha256'] == expected['inventory_sha256']
             and record['recipe_inputs'] == expected['recipe_inputs']
             and record['builder_host_arch'] in ('aarch64','arm64')
             and record['clean_environment_id'] == 'cachy-qt612-reference-'+expected['nonce']+'-'+str(index)
             and set(record['artifacts']) == {name}, 'EXACT_SUCCESSFUL_NATIVE_BUILD_RECORD')
    for key in ('source_date_epoch','recipe_metadata','entry_script_sha256'):
        need(key in first and first[key] == second[key], 'PAIR_SHARED_INPUT_'+key)
    need(first['artifacts'] == second['artifacts'], 'PAIR_CURRENT_ARCHIVE_IDENTITIES')
    return name


class HashSink:
    def __init__(self):self.hash,self.size = hashlib.sha256(),0
    def write(self,raw):self.hash.update(raw);self.size += len(raw)
    def result(self):return dict(bytes=self.size,sha256=self.hash.hexdigest())


class XZReader:
    """One XZ stream, bounded decoder memory and all expanded bytes counted."""
    def __init__(self,source):
        self.source,self.decoder,self.total = source,lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=256*1024**2),0
    def read(self,size):
        need(type(size) is int and 0 <= size <= MEMBER_CAP, 'BOUNDED_XZ_READ')
        chunks, remaining = [],size
        while remaining and not self.decoder.eof:
            block = self.source.read(65536) if self.decoder.needs_input else b''
            need(block or not self.decoder.needs_input, 'COMPLETE_XZ_STREAM')
            raw = self.decoder.decompress(block,max_length=remaining)
            self.total += len(raw)
            need(self.total <= EXPANDED_CAP, 'XZ_EXPANDED_BYTE_CAP')
            chunks.append(raw);remaining -= len(raw)
        if self.decoder.eof:
            need(not self.decoder.unused_data and self.source.read(1) == b'', 'SINGLE_XZ_STREAM_NO_TRAILING_BYTES')
        return b''.join(chunks)


def safe_name(name):
    need(type(name) is str and '\\' not in name and not name.startswith('/')
         and len(name) <= 4096 and all(32 <= ord(c) != 127 for c in name), 'SAFE_ARCHIVE_NAME')
    if name.startswith('./'):name = name[2:]
    name = name.rstrip('/')
    need(name and not {'.','..',''}.intersection(name.split('/')), 'CANONICAL_ARCHIVE_NAME')
    return name


def elf_reports(raw):
    need(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01', 'F_ELF64_LITTLE_ENDIAN')
    kind,machine,version = struct.unpack_from('<HHI',raw,16)
    offset = struct.unpack_from('<Q',raw,32)[0]
    size,count = struct.unpack_from('<HH',raw,54)
    need(machine == 183 and kind in (2,3) and version == 1
         and struct.unpack_from('<H',raw,52)[0] == 64 and size == 56
         and 0 < count < 1024 and offset+size*count <= len(raw), 'F_AARCH64_ELF_HEADERS')
    segments = [struct.unpack_from('<IIQQQQQQ',raw,offset+i*size) for i in range(count)]
    loads = [s for s in segments if s[0] == 1]
    need(loads and all(s[2]+s[5] <= len(raw) for s in segments), 'F_ELF_SEGMENT_EXTENTS')
    need(all(s[5] <= s[6] and s[7] >= 16384 and not s[7]&(s[7]-1)
             and s[2]%s[7] == s[3]%s[7] and s[2]%16384 == s[3]%16384 for s in loads), 'INHERITED_STRUCTURAL16K_ELF_GATE')
    soname = None
    for segment in (s for s in segments if s[0] == 2):
        need(segment[5]%16 == 0, 'F_ELF_DYNAMIC_EXTENT')
        values = {}
        for position in range(segment[2],segment[2]+segment[5],16):
            tag,value = struct.unpack_from('<qQ',raw,position)
            if tag == 0:break
            values[tag] = value
        if 14 not in values:continue
        need(5 in values and 10 in values and values[14] < values[10], 'F_ELF_SONAME_TABLE')
        tables = [s for s in loads if s[3] <= values[5] and values[5]+values[10] <= s[3]+s[5]]
        need(len(tables) == 1, 'F_ELF_FILE_BACKED_SONAME')
        start = tables[0][2]+values[5]-tables[0][3]
        stop = raw.find(b'\0',start+values[14],start+values[10])
        need(stop >= start+values[14], 'F_ELF_TERMINATED_SONAME')
        soname = raw[start+values[14]:stop].decode('ascii')
    return (dict(type=kind,machine=machine,soname=soname),
            dict(machine=183,load_segments=len(loads),errors=[],hardware_status='NOT RUN'))


def validate_stage(stage, contract):
    files,links,elf = stage['files'],stage['symlinks'],stage['elf']
    profile = contract['expected_stage']
    for module in profile['public_modules']+profile['private_modules']:
        library = 'usr/lib/libQt6'+module
        need(elf.get(library+'.so.6.12.0') == dict(type=3,machine=183,soname='libQt6'+module+'.so.6'), 'F_REQUIRED_MODULE_ELF')
        for suffix,target in (('.so.6','libQt6'+module+'.so.6.12.0'),('.so','libQt6'+module+'.so.6')):
            need(links.get(library+suffix,{}).get('target') == target, 'F_MODULE_SONAME_LINKS')
        if module in profile['public_modules']:
            need(all(n in files for n in ('usr/include/qt6/Qt'+module+'/Qt'+module,
                 'usr/lib/pkgconfig/Qt6'+module+'.pc','usr/lib/cmake/Qt6'+module+'/Qt6'+module+'Config.cmake')), 'F_MODULE_DEVELOPMENT_FILES')
    for name in profile['tools_required']+['usr/lib/qt6/plugins/'+p for p in profile['plugins_required']]:
        need(name in elf and files[name]['mode']&0o111, 'F_REQUIRED_TOOL_PLUGIN_ELF')
    for name in set(files)|set(links):
        if name.startswith('usr/lib/qt6/plugins/sqldrivers/'):
            need(name == 'usr/lib/qt6/plugins/sqldrivers/libqsqlite.so', 'F_SQLITE_ONLY')
        need(not name.startswith(tuple('usr/lib/qt6/plugins/'+p for p in (
            'platforms/libqeglfs','platforms/libqlinuxfb','platforms/libqvkkhrdisplay',
            'platforms/libqdirectfb','platforms/libqwayland','platforms/libqvnc','platformthemes/libqgtk3'))), 'F_DISABLED_PLATFORM_PLUGIN_ABSENT')
    def owned(name):
        trees = ('usr/include/qt6','usr/lib/qt6','usr/share/qt6','usr/share/doc/qt6',
                 'usr/share/licenses/'+contract['package']['name'])
        return (name in ('usr','usr/bin','usr/include','usr/lib','usr/lib/cmake','usr/lib/pkgconfig',
                         'usr/share','usr/share/doc','usr/share/licenses','usr/bin/qmake6','usr/bin/qtpaths6')
                or any(name == t or name.startswith(t+'/') for t in trees)
                or name.startswith(('usr/lib/cmake/Qt6','usr/lib/pkgconfig/Qt6'))
                or (name.startswith('usr/lib/libQt6') and '/' not in name[len('usr/lib/'):]))
    need(all(owned(n) for n in set(files)|set(links)|set(stage['directories'])), 'F_QT_OWNED_NAMESPACE')


def inspect_archive(path, *, io, observed):
    sink = HashSink();io.stream(path,None,observed,cap=COMPRESSED_CAP,target=sink)
    fd = os.open(io.ordinary(path),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    before = os.fstat(fd)
    try:need(io.identity(before) == observed[str(path)], 'SAME_ARCHIVE_FD_AFTER_PIN')
    except BaseException:
        os.close(fd);raise
    members, files, links, directories, elf, geometry, metadata = {},{},{},{},{},{},{}
    version_header = False
    class BoundedInfo(tarfile.TarInfo):
        count = 0
        @classmethod
        def frombuf(cls,buf,encoding,errors):
            item = super().frombuf(buf,encoding,errors)
            cls.count += 1
            need(cls.count <= NODE_CAP and 0 <= item.size <= MEMBER_CAP, 'BOUNDED_TAR_HEADER')
            if item.type in (tarfile.XHDTYPE,tarfile.XGLTYPE,tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_LONGLINK):
                need(item.size <= 1024**2, 'BOUNDED_TAR_EXTENSION')
            return item
    with os.fdopen(fd,'rb') as source:
        reader = XZReader(source)
        with tarfile.open(fileobj=reader,mode='r|',tarinfo=BoundedInfo) as archive:
            for item in archive:
                if item.name in ('.','./'):
                    need(item.isdir(), 'ORDINARY_ARCHIVE_ROOT');continue
                name = safe_name(item.name)
                need(name not in members and len(members) < NODE_CAP and 0 <= item.size <= MEMBER_CAP
                     and (item.isfile() or item.isdir() or item.issym()) and item.uid == item.gid == 0
                     and (item.issym() or not item.mode&0o7022), 'SAFE_ORDINARY_ARCHIVE_MEMBER')
                digest, body = None,b''
                if item.isfile():
                    h = hashlib.sha256();parts = [];size = 0;is_elf = False
                    with archive.extractfile(item) as stream:
                        while block := stream.read(1024**2):
                            if size == 0:is_elf = block.startswith(b'\x7fELF')
                            size += len(block);need(size <= item.size, 'EXACT_MEMBER_SIZE');h.update(block)
                            if is_elf or name in ('.PKGINFO','.BUILDINFO',VERSION_HEADER):parts.append(block)
                    need(size == item.size, 'WHOLE_ARCHIVE_MEMBER')
                    body = b''.join(parts);digest = h.hexdigest()
                    if name == VERSION_HEADER:
                        version_header = bool(re.search(rb'^#define\s+QTCORE_VERSION_STR\s+"6\.12\.0"\s*$',body,re.MULTILINE))
                    files[name] = dict(bytes=size,sha256=digest,mode=item.mode)
                    if is_elf:elf[name],geometry[name] = elf_reports(body)
                    if name in ('.PKGINFO','.BUILDINFO'):
                        md = {}
                        for line in body.decode().splitlines():
                            if not line or line.startswith('#'):continue
                            need(' = ' in line, 'PACKAGE_METADATA_ROW')
                            key,value = line.split(' = ',1);md.setdefault(key,[]).append(value)
                        metadata[name] = md
                elif item.isdir():directories[name] = item.mode
                else:
                    target = item.linkname
                    need(target and not target.startswith('/') and '\\' not in target
                         and all(32 <= ord(c) != 127 for c in target), 'SAFE_RELATIVE_ARCHIVE_LINK')
                    links[name] = dict(target=target,sha256=hashlib.sha256(target.encode()).hexdigest(),mode=item.mode)
                members[name] = dict(type=item.type.decode('ascii'),mode=item.mode,uid=item.uid,gid=item.gid,
                                     size=item.size,mtime=item.mtime,link=item.linkname,sha256=digest)
        while reader.read(65536):pass
        need(reader.decoder.eof and io.identity(before) == io.identity(os.fstat(source.fileno()))
             == io.identity(path.lstat()), 'STABLE_COMPLETE_CURRENT_XZ_ARCHIVE')
    for name in members:
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':need(str(parent) in directories, 'NO_ARCHIVE_NONDIRECTORY_ANCESTOR')
    for name,row in links.items():
        resolved = list(PurePosixPath(name).parent.parts)
        for part in row['target'].split('/'):
            if part in ('','.'):continue
            if part == '..':need(resolved, 'NONESCAPING_ARCHIVE_LINK');resolved.pop()
            else:resolved.append(part)
        target = '/'.join(resolved)
        chain = {name}
        while target in links:
            need(target not in chain, 'ACYCLIC_ARCHIVE_LINK');chain.add(target)
            parts = list(PurePosixPath(target).parent.parts)
            for part in links[target]['target'].split('/'):
                if part in ('','.'):continue
                if part == '..':need(parts, 'NONESCAPING_ARCHIVE_LINK');parts.pop()
                else:parts.append(part)
            target = '/'.join(parts)
        need(target in files or target in directories, 'NONDANGLING_ARCHIVE_LINK')
    need(METADATA <= set(files), 'THREE_REGULAR_PACKAGE_METADATA_MEMBERS')
    return dict(archive=sink.result(),members=members,files=files,symlinks=links,directories=directories,
                elf=elf,geometry=geometry,metadata=metadata,version_header=version_header)


def qualify_pair(first, second, comparison, *, expected, io_module):
    io, observed = io_module,{}
    roots = [io.ordinary(p) for p in (first,second)]
    need(roots[0] != roots[1], 'TWO_DISTINCT_BUILD_RECEIPT_ROOTS')
    def read(path):return io.stream(path,None,observed,cap=JSON_CAP,collect=True)
    def load(path):return io.decode(read(path))
    records = [load(p/'provenance.json') for p in roots]
    comparison_value = load(io.ordinary(comparison))
    name = validate_pair_records(*records,comparison_value,expected=expected)
    check_log = 'artifacts/'+name.removesuffix('.pkg.tar.xz')+'-check.log'
    observations = []
    for root,record in zip(roots,records):
        required = {'build.log','validation.json','expected-packages.lock','artifacts/packages.lock','artifacts/environment.txt',
                    'artifacts/generated.SRCINFO','artifacts/config.sha256','artifacts/makepkg.conf','artifacts/pacman.conf',
                    'artifacts/qt612-configuration.json','artifacts/qt612-source-notices.json',
                    'artifacts/qt612-stage-contract.json',
                    check_log}
        need(required <= set(record['files']) and len(record['files']) <= 512, 'RETAINED_QT_RECEIPT_CLOSURE')
        artifact_paths = list((root/'artifacts').iterdir())
        need(len(artifact_paths) <= 512 and all(not p.is_symlink() and p.is_file() for p in artifact_paths)
             and {p.name for p in artifact_paths if '.pkg.tar.' in p.name and not p.name.endswith('.sig')} == {name},
             'CURRENT_SINGLE_ARCHIVE_ARTIFACT_SET')
        for relative,digest in record['files'].items():
            io.member(relative);need(re.fullmatch('[0-9a-f]{64}',digest), 'RECEIPT_WHOLE_HASH')
            sink = HashSink();io.stream(root/relative,None,observed,
                                      cap=COMPRESSED_CAP if relative == 'artifacts/'+name else JSON_CAP,target=sink)
            need(sink.result()['sha256'] == digest, 'CURRENT_RETAINED_RECEIPT_HASH')
        for relative in ('expected-packages.lock','artifacts/packages.lock'):
            need(pin(read(root/relative))['sha256'] == expected['inventory_sha256'], 'CURRENT_EXACT_INVENTORY')
        for relative,digest in expected['recipe_inputs'].items():
            row = expected['contract']['native_recipe_files'].get(relative,expected['contract']['upstream']['archive'])
            io.stream(root/'inputs'/relative,{k:row[k] for k in ('bytes','sha256')},observed,cap=COMPRESSED_CAP)
            need(row['sha256'] == digest, 'CURRENT_F_BUILDVIEW15_SNAPSHOT')
        env = read(root/'artifacts/environment.txt')
        need(re.search(rb'(?<![A-Za-z0-9_])aarch64(?![A-Za-z0-9_])',env), 'RETAINED_AARCH64_UNAME')
        log = read(root/check_log)
        need(log.splitlines().count(MARKER) == 1 and log.count(MARKER) == 1, 'ONE_EXACT_OFFSCREEN_CHECK_MARKER')
        configuration = load(root/'artifacts/qt612-configuration.json')
        notices = load(root/'artifacts/qt612-source-notices.json')
        stage = load(root/'artifacts/qt612-stage-contract.json')
        need(configuration == dict(status='PASS_CONFIGURED_PROFILE_ONLY',settings=len(expected['contract']['configuration']['settings']),native='NOT_ESTABLISHED')
             and notices == dict(status='PASS_QT612_SOURCE_NOTICES_ONLY',notices=173,bytes=636122), 'F_CONFIGURATION_NOTICE_RECEIPTS')
        need(set(stage) == {'status','architecture','evidence_scope','files','symlinks','directories','elf','payload_bytes',
                            'native_execution','installation','hardware'}
             and stage['status'] == 'PASS_QT612_DESTDIR_CONTRACT_ONLY' and stage['architecture'] == 'aarch64'
             and stage['evidence_scope'] == 'STAGED_AARCH64_ELF_ONLY'
             and stage['native_execution'] == 'NOT_ESTABLISHED' and stage['installation'] == stage['hardware'] == 'NOT_RUN', 'EXACT_F_STAGE_RECEIPT')
        validate_stage(stage,expected['contract'])
        validation = load(root/'validation.json')
        need(validation['errors'] == [] and len(validation['artifacts']) == 1, 'ONE_VALIDATED_QT_ARCHIVE')
        report = validation['artifacts'][0]
        need(report['artifact'] == name and report['errors'] == [], 'MATCHING_QT_VALIDATION_REPORT')
        actual = inspect_archive(root/'artifacts'/name,io=io,observed=observed)
        need(actual['version_header'] and actual['archive']['sha256'] == record['artifacts'][name] == report['sha256']
             and actual['members'] == report['members'] and actual['geometry'] == report['elf']
             and actual['metadata'] == report['metadata'], 'CURRENT_ARCHIVE_VALIDATION_BINDING')
        files = {n:r for n,r in actual['files'].items() if n not in METADATA}
        need(files == stage['files'] and actual['symlinks'] == stage['symlinks']
             and actual['directories'] == stage['directories'] and actual['elf'] == stage['elf']
             and sum(r['bytes'] for r in files.values()) == stage['payload_bytes'], 'EXACT_CURRENT_ARCHIVE_STAGE_BINDING')
        notice_root = expected['contract']['source_notices']['destination']+'/'
        notice_hashes = {n[len(notice_root):]:r['sha256'] for n,r in files.items() if n.startswith(notice_root)}
        need(notice_hashes == expected['notice_policy']['source_notices'] and len(notice_hashes) == 173
             and sum(r['bytes'] for n,r in files.items() if n.startswith(notice_root)) == 636122, 'ALL173_ACTUAL_ARCHIVE_LICENSE_BYTES')
        package = actual['metadata']['.PKGINFO']
        need(package.get('pkgname') == [expected['contract']['package']['name']]
             and package.get('pkgver') == [expected['contract']['package']['version']]
             and package.get('arch') == ['aarch64'], 'ACTUAL_F_PACKAGE_IDENTITY')
        need(package.get('depend') == expected['contract']['dependencies']['runtime']
             and package.get('provides') == expected['contract']['package']['provides']
             and package.get('conflict') == expected['contract']['package']['conflicts']
             and package.get('replaces',[]) == [], 'ACTUAL_F_PACKAGE_DEPENDENCIES')
        build = actual['metadata']['.BUILDINFO']
        need(build.get('pkgname') == package['pkgname'] and build.get('pkgver') == package['pkgver']
             and build.get('pkgarch') == package['arch']
             and build.get('pkgbuild_sha256sum') == [expected['recipe_inputs']['PKGBUILD']], 'ACTUAL_F_BUILDINFO_BINDING')
        observations.append(dict(archive=actual['archive'],stage_sha256=pin(encoded(stage))['sha256'],
                                 notice_count=173,elf_count=len(actual['elf'])))
    need(observations[0] == observations[1], 'EXACT_QT_PAIR_POSTCONDITIONS')
    io.unchanged(observed)
    return dict(status='QT612_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED',builds=2,image_id=expected['image'],
                archive=name,observations=observations,comparison=comparison_value,
                signature='NOT RUN',installation='NOT RUN',removal='NOT RUN',native16K='NOT RUN',M2='NOT RUN',
                performance='NOT MEASURED',release='NOT ADMITTED',Root_acceptance=None)
