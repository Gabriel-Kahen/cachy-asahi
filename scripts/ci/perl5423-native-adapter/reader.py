# SPDX-License-Identifier: MIT
"""Independent bounded Perl ARM evidence DATA checks; no operational entry point."""
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time
import zlib

HERE = Path(__file__).resolve().parent
DOMAIN = 'PERL_ARM_CAP0_NNP_RO_CONTAINER_V1'
ARCHIVE = 'perl-5.42.3-1.3-aarch64.pkg.tar.zst'
CF_TIME = 'Sun Aug  2 00:00:00 UTC 2026'
EPOCH = 1785628800
MIB = 1024**2
MAKEPKG_ARGV = ['/usr/bin/makepkg','--config','/work/makepkg.conf','--cleanbuild','--nosign','--noconfirm','--log']
MAKEPKG_SUFFIX = ("\n# Fixed Perl native adapter: retained base plus explicit package format.\n"
                  "PKGEXT='.pkg.tar.zst'\nCOMPRESSZST=(zstd -c -T2 -19 -)\nMAKEFLAGS='-j2'\n")
COMMANDS = tuple('''corelist cpan enc2xs encguess h2ph h2xs instmodsh json_pp
libnetcfg perlbug perldoc perlivp perlthanks piconv pl2pm pod2html pod2man
pod2text pod2usage podchecker prove ptar ptardiff ptargrep shasum splain
streamzip xsubpp zipdetails'''.split())
XS = frozenset(('List/Util/Util.so', 'Cwd/Cwd.so', 'Fcntl/Fcntl.so',
                'DB_File/DB_File.so', 'GDBM_File/GDBM_File.so',
                'Compress/Raw/Zlib/Zlib.so', 'Compress/Raw/Bzip2/Bzip2.so',
                'threads/threads.so'))
HELPERS = {'archive_stream.py': '10f1a4c0ac5b98852d9ebb150af28f9ce345c800935a64fa463bc90f72fcb838',
           'elf64le_aarch64.py': '7c89596b854457897a6addb5b28794c2e0d9ffeffee44369a19b5a70f0a3cc53'}
_HELPERS = None


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def json_data(raw, maximum=MIB):
    need(type(raw) is bytes and len(raw) <= maximum, 'bounded JSON DATA required')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def number(value):
        result = float(value)
        need(math.isfinite(result), 'nonfinite JSON refused')
        return result
    def invalid(_):
        raise ValueError('nonfinite JSON refused')
    try:
        result = json.loads(raw, object_pairs_hook=unique, parse_float=number, parse_constant=invalid)
    except RecursionError as error:
        raise ValueError('JSON depth bound') from error
    pending = [(result,0)]
    count = 0
    while pending:
        value, depth = pending.pop(); count += 1
        need(depth <= 32 and count <= 100000, 'JSON structure bound')
        if type(value) is dict:
            pending.extend((item,depth+1) for item in value.values())
        elif type(value) is list:
            pending.extend((item,depth+1) for item in value)
    return result


def object_data(raw, maximum=MIB):
    result = json_data(raw, maximum)
    need(type(result) is dict, 'JSON object required')
    return result


def relative(name):
    need(type(name) is str and 0 < len(name) <= 4096 and
         not re.search(r'[\x00-\x20\x7f\\]', name) and not name.startswith('/') and
         all(part not in ('', '.', '..') for part in name.split('/')), 'canonical relative DATA path required')
    return name


def read(root, name, maximum, *, empty=False):
    relative(name)
    root = Path(root)
    need(root.is_absolute() and root == root.resolve() and
         not any(p.is_symlink() for p in (root, *root.parents)), 'canonical evidence root required')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = name.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(leaf)
            key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 (0 if empty else 1) <= before.st_size <= maximum, 'ordinary bounded evidence file required')
            chunks = []
            size = 0
            while block := os.read(leaf, min(65536, maximum + 1 - size)):
                size += len(block)
                need(size <= maximum, 'evidence read bound exceeded')
                chunks.append(block)
            need(size == before.st_size and key(before) == key(os.fstat(leaf)) ==
                 key(os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)), 'evidence changed during read')
            return b''.join(chunks)
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


def helpers():
    global _HELPERS
    if _HELPERS is None:
        result = {}
        for name, digest in HELPERS.items():
            raw = read(HERE, 'helpers/' + name, 128*1024)
            need(pin(raw)['sha256'] == digest, 'fixed passive helper differs: ' + name)
            spec = importlib.util.spec_from_file_location('perl_arm_reader_' + name[:-3], HERE/'helpers'/name)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            exec(compile(raw,str(HERE/'helpers'/name),'exec'),module.__dict__)
            result[name] = module
        _HELPERS = result
    return _HELPERS


def fields(raw):
    need(type(raw) is bytes and len(raw) <= MIB, 'bounded package metadata required')
    result = {}
    for line in raw.decode().splitlines():
        if not line or line.startswith('#'):
            continue
        need(' = ' in line, 'literal package metadata field required')
        key, value = line.split(' = ', 1)
        need(re.fullmatch(r'[A-Za-z0-9_]+', key) and value, 'package metadata key/value required')
        result.setdefault(key, []).append(value)
    return result


def archive(raw, *, require_zstd=True):
    """Recompute every tar node/hash and each ELF table, without extraction."""
    need(type(raw) is bytes and 0 < len(raw) <= 64*MIB, 'bounded compressed package required')
    if require_zstd:
        need(raw.startswith(b'\x28\xb5\x2f\xfd'), 'actual zstd package required')
    h = helpers()
    api = h['archive_stream.py']
    elf = h['elf64le_aarch64.py']
    limits = api.Limits(compressed_bytes=64*MIB, total_compressed_bytes=64*MIB,
                        decoded_bytes=160*MIB, members=12000, file_bytes=32*MIB,
                        window_bytes=128*MIB, deadline=time.monotonic()+90)
    source = api.Decoded(io.BytesIO(raw), limits, 0)
    decoded = io.BytesIO()
    while block := source.read(65536):
        decoded.write(block)
    need(source.done, 'complete single compressed frame required')
    decoded.seek(0)
    headers = 0
    ended = False
    class Info(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls, stream):
            return cls._fromtarfile(stream)
        @classmethod
        def _fromtarfile(cls, stream, *, dircheck=True):
            nonlocal headers, ended
            api.tick(limits)
            body = stream.fileobj.read(512)
            if body == bytes(512):
                ended = True
            else:
                headers += 1
                need(headers <= 12000, 'tar header budget')
            if hasattr(cls, '_frombuf'):
                item = cls._frombuf(body, stream.encoding, stream.errors, dircheck=dircheck)
            else:
                item = cls.frombuf(body, stream.encoding, stream.errors)
            item.offset = stream.fileobj.tell()-512
            return item._proc_member(stream)
        def _proc_pax(self, stream):
            need(0 <= self.size <= 65536, 'PAX budget')
            return super()._proc_pax(stream)
        def _proc_gnulong(self, stream):
            need(0 <= self.size <= 65536, 'long-name budget')
            return super()._proc_gnulong(stream)
        def _proc_sparse(self, *args):
            raise ValueError('sparse package refused')
        _proc_gnusparse_00 = _proc_sparse
        _proc_gnusparse_01 = _proc_sparse
        _proc_gnusparse_10 = _proc_sparse
    nodes = {}
    controls = {}
    elfs = {}
    selected = {}
    with tarfile.open(fileobj=decoded, mode='r:', tarinfo=Info) as stream:
        for member in stream:
            api.tick(limits)
            name = relative(member.name.removeprefix('./').rstrip('/'))
            need(name not in nodes and member.uid == member.gid == 0 and
                 not member.sparse and not any(k.startswith('GNU.sparse') for k in member.pax_headers), 'unique ordinary root-owned tar entry required')
            need(0 <= member.size <= 32*MIB, 'tar entry byte budget')
            row = dict(mode=member.mode, uid=member.uid, gid=member.gid, mtime=member.mtime)
            if member.isdir():
                row['type'] = 'directory'
            elif member.isfile():
                data = stream.extractfile(member).read(32*MIB+1)
                need(len(data) == member.size, 'whole regular tar body required')
                row.update(type='file', **pin(data))
                if name.startswith('.'):
                    need(name in ('.PKGINFO', '.BUILDINFO', '.MTREE') and 0 < len(data) <= MIB, 'only bounded package controls allowed')
                    controls[name] = data
                parsed = elf.parse_elf(data)
                if parsed is not None:
                    need(parsed['type'] in (2, 3), 'loadable package ELF required')
                    elfs[name] = parsed
                if name in ('usr/lib/perl5/5.42/core_perl/Config_heavy.pl',
                            'usr/lib/perl5/5.42/core_perl/CORE/config.h') or name.startswith('usr/share/licenses/perl/'):
                    selected[name] = data
            elif member.issym():
                need(type(member.linkname) is str and not member.linkname.startswith('/') and
                     not re.search(r'[\x00-\x20\x7f\\]', member.linkname), 'relative ordinary symlink required')
                row.update(type='symlink', target=member.linkname)
            elif member.islnk():
                target = relative(member.linkname.removeprefix('./'))
                need(nodes.get(target, {}).get('type') == 'file' and member.size == 0, 'prior ordinary hardlink target required')
                row.update(type='hardlink', target=target,
                           **{key: nodes[target][key] for key in ('bytes', 'sha256')})
            else:
                raise ValueError('special package entry refused')
            need(name in ('.PKGINFO','.BUILDINFO','.MTREE') or name == 'usr' or name.startswith('usr/'), 'package escapes usr')
            need(not name.startswith(('usr/local', 'usr/share/libalpm', 'usr/lib/systemd', 'usr/bin/vendor_perl','usr/share/fish/vendor_conf.d')) and
                 '/vendor_perl/' not in name, 'operator/vendor/hook/service payload refused')
            need(row['type'] == 'symlink' or not row['mode'] & 0o7022, 'unsafe payload mode')
            need(member.mtime == EPOCH, 'source-epoch package node required')
            nodes[name] = row
        need(ended, 'tar end marker required')
        tail = stream.fileobj.read()
        need(len(tail) >= 512 and not any(tail) and source.total % 512 == 0, 'complete zero tar padding required')
    for name, row in nodes.items():
        if row['type'] == 'symlink':
            need(api.resolve(nodes, name, limits) in nodes, 'dangling/escaping package alias')
        need(not any(nodes.get(str(p), {}).get('type') != 'directory' for p in Path(name).parents
                     if p != Path('.') and str(p) in nodes), 'package parent is not an ordinary directory')
    need(set(controls) == {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'complete package control namespace required')
    decoder = zlib.decompressobj(31)
    mtree = decoder.decompress(controls['.MTREE'], 4*MIB+1)
    need(len(mtree) <= 4*MIB and decoder.eof and not decoder.unused_data and
         not decoder.unconsumed_tail and mtree.startswith(b'#mtree\n'), 'whole bounded gzip MTREE required')
    for command in COMMANDS:
        need(nodes.get('usr/bin/' + command, {}).get('type') == 'symlink' and
             nodes['usr/bin/' + command]['target'] == 'core_perl/' + command, 'exact core command alias required')
        script = nodes.get('usr/bin/core_perl/' + command, {})
        need(script.get('type') in ('file', 'hardlink') and script.get('mode') == 0o755, 'executable original core script required')
    need({name.removeprefix('usr/bin/core_perl/') for name in nodes if name.startswith('usr/bin/core_perl/')}==set(COMMANDS),
         'exact original core command namespace required')
    for name in ('usr/bin/perl', 'usr/lib/perl5/5.42/core_perl/CORE/libperl.so'):
        need(name in elfs, 'actual AArch64 interpreter/shared library required')
    need(nodes['usr/bin/perl']['mode'] == 0o755 and
         'usr/share/perl5/core_perl/pod/perldiag.pod' in nodes, 'executable interpreter and diagnostic POD required')
    need(all('usr/lib/perl5/5.42/core_perl/auto/'+name in elfs for name in XS), 'all eight archived actual AArch64 core extensions required')
    need(all(nodes.get(name,{}).get('type')=='file' for name in ('usr/lib/perl5/5.42/core_perl/Config.pm','usr/share/perl5/core_perl/strict.pm')),
         'actual archived core configuration and strict module required')
    need("cf_time='" + CF_TIME + "'" in selected.get('usr/lib/perl5/5.42/core_perl/Config_heavy.pl', b'').decode(), 'archived Config time differs')
    return dict(identity=pin(raw), nodes=nodes, controls=controls, elfs=elfs, selected=selected)


def harness(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 64*MIB, 'bounded complete check log required')
    text = raw.decode()
    need(len(re.findall(r'^All tests successful\.$', text, re.M)) == 1 and
         len(re.findall(r'^Result: PASS$', text, re.M)) == 1, 'one complete upstream harness PASS required')
    rows = re.findall(r'^Files=(\d+), Tests=(\d+), (\d+) wallclock secs .*$', text, re.M)
    need(len(rows) == 1, 'one complete upstream harness summary required')
    files, tests, seconds = map(int, rows[0])
    need(0 < files <= 12000 and 0 < tests <= 3000000 and 0 < seconds <= 2400,
         'positive bounded target upstream harness required')
    need(not re.search(r'^Result: (?!PASS)|^Failed [1-9]|^not ok\b', text, re.M), 'failed upstream check log')
    need('PASS selected shared threaded Perl5.42.3 paths,113 core providers and five C extensions' in text,
         'actual provider and core extension check required')
    need('[libz.so.1]' in text and '[libbz2.so.1.0]' in text, 'actual system compression DT_NEEDED checks required')
    return dict(files=files, tests=tests, seconds=seconds,
                whole_file_skips=len(re.findall(r'^.+?\.\.\.\s+skipped:', text, re.M)),
                TODO_passed=re.findall(r'^\s+TODO passed:.*$', text, re.M),
                log=pin(raw))


def alpm_desc(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 65536, 'bounded installed ALPM metadata required')
    result = {}
    key = None
    for line in raw.decode().splitlines():
        if re.fullmatch(r'%[A-Z0-9_]+%', line):
            key = line[1:-1]
            need(key not in result, 'duplicate ALPM field')
            result[key] = []
        elif line:
            need(key is not None, 'ALPM value without field')
            result[key].append(line)
    return result


def provider(data, description, files, owner, raw, readelf):
    """Join ALPM ownership/provides, resolved binary tables and readelf DATA."""
    need(type(data) is dict and set(data) == {'path', 'soname', 'owner', 'version', 'symlinks', 'readelf_argv'},
         'exact provider observation fields required')
    desc = alpm_desc(description)
    listed = alpm_desc(files)
    need(desc.get('NAME') == ['libxcrypt'] and desc.get('VERSION') == ['4.5.2-1'] and
         'libcrypt.so=2-64' in desc.get('PROVIDES', []) and owner == b'libxcrypt\n', 'actual ALPM libcrypt provider required')
    need(listed.get('FILES') and len(listed['FILES']) <= 4096 and
         len(listed['FILES']) == len(set(listed['FILES'])), 'complete finite ALPM provider file list required')
    names = {relative(name.rstrip('/')) for name in listed['FILES']}
    need(data['owner'] == 'libxcrypt' and data['version'] == '4.5.2-1' and data['soname'] == 'libcrypt.so.2',
         'fixed provider identity differs')
    target = data['path']
    need(type(target) is str and target.startswith('/usr/lib/') and
         relative(target[1:]) in names and len(raw) <= 16*MIB, 'owned resolved provider path required')
    links = data['symlinks']
    need(type(links) is list and 1 <= len(links) <= 8, 'finite actual provider alias chain required')
    aliases = {}
    for row in links:
        need(type(row) is dict and set(row) == {'path', 'target'} and
             type(row['path']) is str and row['path'].startswith('/usr/lib/') and
             relative(row['path'][1:]) in names and row['path'] not in aliases and
             type(row['target']) is str and row['target'] and not row['target'].startswith('/') and
             not re.search(r'[\x00-\x20\x7f\\]', row['target']), 'ordinary owned provider alias required')
        destination = Path(row['path']).parent / row['target']
        need('..' not in destination.parts and str(destination).startswith('/usr/lib/'), 'provider alias escapes library directory')
        aliases[row['path']] = str(destination)
    used = set()
    for start in ('/usr/lib/libcrypt.so','/usr/lib/libcrypt.so.2'):
        current = start;visited = set()
        while current in aliases:
            need(current not in visited, 'cyclic provider alias')
            visited.add(current);used.add(current)
            current = aliases[current]
        need(visited and current == target and target not in aliases,
             'whole linker/runtime alias chains must reach same observed ordinary provider')
    need(set(aliases)==used, 'unobserved extraneous provider aliases refused')
    parsed = helpers()['elf64le_aarch64.py'].parse_elf(raw)
    need(parsed is not None and parsed['type'] == 3 and parsed['soname'] == 'libcrypt.so.2',
         'actual AArch64 provider ELF SONAME required')
    need(data['readelf_argv'] == ['/usr/bin/readelf', '--wide', '-h', '-d', target], 'literal provider readelf command required')
    need(type(readelf) is bytes and 0 < len(readelf) <= MIB, 'bounded actual readelf output required')
    text = readelf.decode()
    need(re.findall(r'^\s*Class:\s*(\S+)\s*$', text, re.M) == ['ELF64'] and
         re.findall(r'^\s*Machine:\s*(.+?)\s*$', text, re.M) == ['AArch64'] and
         len(re.findall(r'^\s*Data:.*little endian\s*$', text, re.M)) == 1, 'actual readelf AArch64 header differs')
    sonames = re.findall(r'\(SONAME\)\s+Library soname: \[([^\]\n]+)\]', text)
    needed = re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]\n]+)\]', text)
    need(sonames == [parsed['soname']] and needed == parsed['needed'], 'readelf/actual provider ELF dynamic tables differ')
    return dict(owner='libxcrypt', version='4.5.2-1', path=target, soname=parsed['soname'],
                elf=pin(raw), description=pin(description), files=pin(files), readelf=pin(readelf))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def digest(value, length=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}', value) is not None


def contract_data(c):
    need(c['schema'] == 1 and c['operation'] == 'perl5423-native-pair-v1' and
         c['target'] == 'aarch64' and c['version'] == '5.42.3-1.3' and c['epoch'] == EPOCH and
         c['cf_time'] == CF_TIME and c['native_acceptance'] is False, 'fixed unadmitted Perl ARM contract required')
    need(c['recipe_sha256'] == 'cf0df8990ac83f48a4c29978c932922108f0e01cb6d052209934da5b01af4068' and
         c['source_sha256'] == '16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725' and
         c['source_bytes'] == 22610875 and c['expected349_sha256'] == '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453', 'independent candidate/source/baseline bindings differ')
    need(c['packet_map_sha256']=='cf02013d1a06b90bf7e3c32e8471efb3a896d3e1881a492386a6d0b70fc0a1a5' and
         c['source_name']=='perl5-bc3dab4d4f66de5ea67dda34e5feb5230a54c603.tar.gz', 'independent complete source packet binding differs')
    need(c['makepkg_argv'] == MAKEPKG_ARGV and c['makepkg_config_suffix']==MAKEPKG_SUFFIX and
         c['resources']['build_seconds'] == 2400 and c['resources']['pair_seconds'] == 6000 and
         c['resources']['cleanup_seconds'] == 180, 'full dependency-checked recipe and finite budgets required')
    for key, value in [('archive_bytes',64*MIB), ('decoded_bytes',160*MIB), ('log_bytes',64*MIB)]:
        need(c['resources'][key] == value, 'fixed evidence budget differs')
    for key,value in [('disk_reserve_bytes',1024*MIB),('host_memory_reserve_bytes',4096*MIB),
                      ('source_input_bytes',64*MIB),('output_export_bytes',512*MIB),('export_tar_bytes',256*MIB),('export_files',64)]:
        need(c['resources'][key]==value, 'fixed capacity demand/reserve differs')
    need(c['domain_sha256'] == pin(encoded(c['domain']))['sha256'] ==
         '6c6bdc29acf59e8ea911167f08d4d66a993777c121b2399211cec030e2a5b804' and
         c['domain']['kind'] == DOMAIN and c['namespace']['Source3937_equivalent'] is False and
         c['namespace']['required_domain'] == DOMAIN, 'separate exact consumer namespace domain required')
    need('aarch64' in c['recipe_metadata']['arch'] and c['recipe_files']['PKGBUILD']['sha256'] == c['recipe_sha256'] and
         len(c['recipe_files']) == 18 and len(c['recipe_metadata']['provides']) == 113,
         'complete pinned dual-architecture recipe metadata required')


def retirement(row, *, actual=False, code=0):
    need(type(row) is dict and row.get('natural_exit') is True and row.get('forced_cleanup') is False and
         row.get('retirement') == 'REAPED' and row.get('group_absent') is True and
         row.get('leader_held_until_group_inspection') is True and not row.get('ownership_lost',False) and
         not row.get('cleanup_error'), 'complete natural owned retirement required')
    if actual:
        need(type(row.get('pid')) is int and row['pid'] > 0 and type(row.get('exit')) is int and row['exit'] == code and
             row.get('exit_observed_via_waitpid') is True and row.get('ownership_lost') is False,
             'direct observed waitpid exit required')
        need(type(row.get('elapsed_seconds')) in (int,float) and
             math.isfinite(row['elapsed_seconds']) and 0 < row['elapsed_seconds'] <= 2400,
             'finite naturally completed operation clock required')


def namespace_state(value):
    need(type(value) is dict and set(value) == {'uid','gid','namespaces','uid_map','gid_map'}, 'exact namespace effect state required')
    need(type(value['uid']) is int and type(value['gid']) is int, 'numeric namespace identity required')
    need(type(value['namespaces']) is dict and set(value['namespaces']) == {'user','mnt','net','pid'}, 'complete namespace effects required')
    for kind, name in value['namespaces'].items():
        need(type(name) is str and re.fullmatch(kind+r':\[[1-9][0-9]{0,19}\]', name), 'literal namespace identity required')
    for key in ('uid_map','gid_map'):
        rows = value[key]
        need(type(rows) is list and 0 < len(rows) <= 8, 'finite actual ID map required')
        for row in rows:
            need(type(row) is list and len(row) == 3 and all(type(n) is int and 0 <= n <= 2**32-1 for n in row) and
                 row[2] > 0 and row[0]+row[2] <= 2**32 and row[1]+row[2] <= 2**32, 'literal nonoverflowing ID map required')
        for left, right in zip(sorted(rows), sorted(rows)[1:]):
            need(left[0]+left[2] <= right[0], 'overlapping namespace ID maps')


def qualified(c, admission, qualification):
    """Operands must be independently authenticated by the Root once caller."""
    contract_data(c)
    need(admission['schema'] == 1 and admission['operation'] == c['operation'] and digest(admission['approval']),
         'independent non-NULL Root admission required')
    need(type(admission['source']) is dict and set(admission['source']) == {'sha','ref'} and
         digest(admission['source']['sha'],40) and type(admission['source']['ref']) is str and
         re.fullmatch(r'codex/[A-Za-z0-9._/-]+', admission['source']['ref']), 'actual Root Source/ref binding required')
    for key in ('source_map_sha256','qualification_sha256','expected349_sha256','input_signature_audit_sha256'):
        need(digest(admission[key]), 'independent Root pin required: ' + key)
    for key in ('run','job'):
        need(type(admission[key]) is str and re.fullmatch(r'[1-9][0-9]{0,19}', admission[key]) and
             type(qualification[key]) is str and qualification[key] == admission[key], 'same actual run/job qualification required')
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', admission['image'] or '') and
         qualification['image'] == admission['image'] and admission['domain_sha256'] ==
         qualification['domain_sha256'] == c['domain_sha256'] and
         admission['expected349_sha256'] == c['expected349_sha256'], 'same immutable image/domain/baseline required')
    need(pin(encoded(qualification))['sha256'] == admission['qualification_sha256'] and
         qualification['schema'] == 1 and qualification['status'] == 'PASS_NAMESPACE_EFFECTS' and
         digest(qualification['source'],40) and qualification['source'] != '3937d8b9f3210f4e9868bf19f01dfa22de64ddfe' and
         digest(qualification['reader_sha256']), 'independent matching qualification cannot reuse Source3937')
    cases = qualification['cases']
    need(type(cases) is dict and set(cases) == {'bwrap-user-mount-net','unshare-mapped-root'}, 'both namespace cases required')
    for kind, case in cases.items():
        need(case['exit_code'] == 0 and type(case['exit_code']) is int and case['outcome'] == 'SUPPORTED', 'actual supported namespace effects required')
        retirement(case['retirement'])
        need(type(case['retirement'].get('exit')) is int and case['retirement']['exit'] == 0 and
             case['retirement'].get('ownership_lost') is False and
             case['retirement'].get('exit_observed_via_waitpid') is True, 'direct namespace command retirement required')
        before, after = case['before'], case['after']
        namespace_state(before); namespace_state(after)
        need(before['uid'] == before['gid'] == 1001 and before['namespaces']['pid'] == after['namespaces']['pid'], 'qualification preserves actual outer identity/PID namespace')
        changed = {key for key in before['namespaces'] if before['namespaces'][key] != after['namespaces'][key]}
        if kind == 'bwrap-user-mount-net':
            need(changed == {'user','mnt','net'} and after['uid'] == after['gid'] == 1001, 'actual bubblewrap user/mount/net effects required')
            for key in ('uid_map','gid_map'):
                owners = [outside+1001-inside for inside,outside,count in after[key] if inside<=1001<inside+count]
                need(owners==[1001], 'bubblewrap actual1001 identity must map to outer1001')
        else:
            need(changed == {'user'} and after['uid'] == after['gid'] == 0 and
                 after['uid_map'] == after['gid_map'] == [[0,1001,1]], 'actual mapped-root user namespace effects required')


def actor(row, record, c, admission):
    host, config = row['HostConfig'], row['Config']
    need(row['Image'] == admission['image'] and config['User'] == '1001:1001' and
         config['Hostname'] == 'perl5423-native', 'actual immutable ARM image/user/hostname required')
    need(host['NanoCpus'] == 2000000000 and host['Memory'] == host['MemorySwap'] == 4294967296 and
         host['PidsLimit'] == 256 and host['ReadonlyRootfs'] is True and host['Init'] is True and
         host['NetworkMode'] == 'none' and host['Privileged'] is False and host['CapDrop'] == ['ALL'] and
         host['CapAdd'] in (None,[]) and host['SecurityOpt'] == ['no-new-privileges'], 'actual cap0/NNP/RO/offline resource domain differs')
    for key in ('Devices','DeviceRequests','Binds'):
        need(host.get(key) in (None,[]), 'additional host/device exposure refused')
    need(host.get('PidMode','') == '' and host.get('IpcMode','private') == 'private' and
         host.get('UTSMode','') == '' and not config.get('Volumes'), 'shared namespace or image volume refused')
    need(host['Tmpfs'] == c['domain']['tmpfs'], 'exact bounded noexec scratch required')
    need(config['Entrypoint']==['/usr/bin/bash'] and
         config['Cmd']==['--noprofile','--norc','/inputs/entry.sh'] and
         row['Path']=='/usr/bin/bash' and row['Args']==config['Cmd'], 'actual actor entry command differs')
    env = config['Env']
    need(type(env) is list and all(type(value) is str and '=' in value for value in env) and
         len({value.split('=',1)[0] for value in env})==len(env) and
         'ADAPTER_ADMISSION_SHA256='+pin(encoded(admission))['sha256'] in env,
         'actual admission environment binding differs')
    mounts = row['Mounts']
    need(type(mounts) is list and len(mounts) == 2 and {m['Destination'] for m in mounts} == {'/inputs','/work'}, 'exact source/work mounts required')
    inputs = next(m for m in mounts if m['Destination']=='/inputs')
    work = next(m for m in mounts if m['Destination']=='/work')
    need(inputs['Type'] == 'bind' and inputs['RW'] is False and type(inputs['Source']) is str and
         inputs['Source'].startswith('/') and Path(inputs['Source']).name == 'inputs' and
         work['Type'] == 'volume' and work['RW'] is True and work['Name'] == record['volume'], 'actual readonly input/private work volume required')


def build_data(get, c, admission):
    """get(name, cap) reads one already-bound build export; never executes it."""
    need(get('makepkg-exit.txt',64) == b'0\n', 'ordinary full makepkg must exit zero')
    packages = get('packages.txt',MIB)
    need(pin(packages)['sha256'] == c['expected349_sha256'], 'actual exact349 ALPM inventory differs')
    lines = packages.decode().splitlines()
    need(len(lines) == 349 and lines == sorted(lines) and len({line.split(' ',1)[0] for line in lines}) == 349, 'complete sorted actual package inventory required')
    # BUILDINFO records any packages with their real ALPM architecture; validate
    # versions below, without pretending every package is architecture-specific.
    actual_versions = dict(line.split(' ',1) for line in lines)
    inputs = object_data(get('recipe-input-map.json',MIB))
    need(set(inputs) == set(c['recipe_files']), 'complete actual recipe input map required')
    for name, expected in c['recipe_files'].items():
        need(inputs[name]['type'] == 'file' and
             {key:inputs[name][key] for key in ('bytes','sha256','mode')} == expected, 'actual recipe input pin differs: ' + name)
    source = object_data(get('source-input.json',MIB))
    need(source == dict(source=dict(bytes=c['source_bytes'],sha256=c['source_sha256']),
                        packet_map_sha256=c['packet_map_sha256'],expected349_sha256=c['expected349_sha256'],
                        adapter_source_map_sha256=admission['source_map_sha256'],recipe_sha256=c['recipe_sha256']), 'actual upstream/packet/source-map pins differ')
    environment = object_data(get('environment.json',MIB))
    need(environment['uid'] == environment['gid'] == 1001 and environment['uname'][-1] == 'aarch64' and
         environment['page_bytes'] in (4096,16384) and environment['makepkg_exit'] == 0 and
         environment['cgroup'] == {'cpu.max':'200000 100000','memory.max':'4294967296','memory.swap.max':'0','pids.max':'256'}, 'actual ARM credentials/page/cgroup observations required')
    status = environment['status']
    for key, value in [('CapEff','0000000000000000'),('CapBnd','0000000000000000'),('NoNewPrivs','1')]:
        need(re.findall(r'^'+key+r':\s*(\S+)\s*$',status,re.M) == [value], 'actual process capability/NNP observation differs')
    need(environment['environment']==dict(PATH='/usr/bin',HOME='/work/home',TMPDIR='/work/tmp',
         CACHY_ASAHI_PERL_BUILD='1',SOURCE_DATE_EPOCH=str(EPOCH),LC_ALL='C',TZ='UTC',MAKEFLAGS='-j2',PKGDEST='/work/output'),
         'exact actual recorded build environment required')
    configs = makepkg_configs(get,c,environment)
    need(get('source-config.over',128) == ("cf_time='"+CF_TIME+"'\n").encode() and
         get('staged-cf-time.txt',128) == (CF_TIME+'\n').encode(), 'actual canonical source/staged time required')
    config = get('source-config.sh',MIB).decode()
    need(re.findall(r'^cf_time=.*$',config,re.M) == ["cf_time='"+CF_TIME+"'"], 'effective configured time differs')
    smoke = object_data(get('staged-smoke.json',65536))
    prefix = '/work/recipe/pkg/perl/usr/lib/perl5/5.42/core_perl/'
    need(smoke['version'] == 'v5.42.3' and smoke['config'] == prefix+'Config.pm' and
         type(smoke['shared_objects']) is list and len(smoke['shared_objects']) == len(XS) and
         set(smoke['shared_objects']) == {prefix+'auto/'+name for name in XS}, 'all eight actual candidate XS paths required')
    checked = harness(get('perl-5.42.3-1.3-aarch64-check.log',64*MIB))
    log = get('makepkg.log',64*MIB)
    need(b'All tests successful.' in log and b'Starting check()' in log and
         b'Starting package()' in log, 'actual ordinary check/package phases required')
    binary = provider(object_data(get('provider.json',65536)),get('provider-desc.txt',65536),
                      get('provider-files.txt',65536),get('provider-owner.txt',128),
                      get('provider-elf.bin',16*MIB),get('provider-readelf.txt',MIB))
    parsed = archive(get(ARCHIVE,64*MIB))
    need(parsed['controls']['.PKGINFO'] == get('PKGINFO',MIB) and
         parsed['controls']['.BUILDINFO'] == get('BUILDINFO',MIB), 'retained/embedded package metadata differs')
    info, build = fields(parsed['controls']['.PKGINFO']), fields(parsed['controls']['.BUILDINFO'])
    need(info.get('pkgname') == ['perl'] and info.get('pkgbase') == ['perl'] and
         info.get('pkgver') == [c['version']] and info.get('arch') == ['aarch64'] and
         info.get('builddate') == [str(EPOCH)], 'actual target package identity differs')
    meta = c['recipe_metadata']
    expected_depends = ['libcrypt.so=2-64' if value=='libcrypt.so' else value for value in meta['depends']]
    for key, values in [('depend',expected_depends),('makedepend',meta['makedepends']),
                        ('checkdepend',meta['checkdepends']),('optdepend',meta['optdepends']),
                        ('license',meta['license']),('provides',meta['provides'])]:
        need(sorted(info.get(key,[])) == sorted(values), 'source/actual package metadata differs: ' + key)
    need(not any(key in info for key in ('backup','conflict','replaces')) and
         build.get('pkgbuild_sha256sum') == [c['recipe_sha256']] and
         build.get('pkgarch') == ['aarch64'] and build.get('pkgver') == [c['version']] and
         build.get('builddate') == [str(EPOCH)], 'actual BUILDINFO/backup policy differs')
    observed = {}
    for line in build.get('installed',[]):
        need(line.endswith(('-aarch64','-any')), 'actual BUILDINFO architecture required')
        stem = line.rsplit('-',1)[0]
        matches = [name for name, version in actual_versions.items() if stem == name+'-'+version]
        need(len(matches) == 1 and matches[0] not in observed, 'unique actual BUILDINFO installed package/version join required')
        observed[matches[0]] = actual_versions[matches[0]]
    need(observed == actual_versions, 'complete actual349 BUILDINFO inventory required')
    for name, source_name in [('README','UPSTREAM-README'),('Artistic','UPSTREAM-Artistic'),
                              ('Copying','UPSTREAM-Copying'),('LICENSE.packaging','LICENSE.packaging')]:
        body = parsed['selected'].get('usr/share/licenses/perl/'+name,b'')
        need(pin(body) == {key:c['recipe_files'][source_name][key] for key in ('bytes','sha256')}, 'exact packaged notice differs')
    for extension, required in [('Compress/Raw/Zlib/Zlib.so','libz.so.1'),('Compress/Raw/Bzip2/Bzip2.so','libbz2.so.1.0')]:
        need(required in parsed['elfs'].get('usr/lib/perl5/5.42/core_perl/auto/'+extension,{}).get('needed',[]), 'actual package uses required system compression library')
    needed = {name for row in parsed['elfs'].values() for name in row.get('needed',[])}
    need('libcrypt.so.2' in needed, 'actual Perl package crypt dependency must join observed provider')
    clocks = entry_operations(get,c,binary['path'])
    need(checked['seconds'] <= clocks['makepkg_seconds']+1, 'full harness clock exceeds actual makepkg retirement clock')
    return dict(archive=parsed['identity'],nodes=parsed['nodes'],harness=checked,provider=binary,
                page_bytes=environment['page_bytes'],ELF_files=len(parsed['elfs']),commands=clocks,makepkg_configs=configs,
                warnings=dict(fakeroot_preload=log.count(b"ERROR: ld.so: object 'libfakeroot.so'"),
                              source_directory=b'WARNING: Package contains reference to $srcdir' in log))


DOCKER = ['/usr/bin/docker','--host=unix:///var/run/docker.sock']
CONTAINERS = ['container','ls','--all','--format','{{.Names}}']
VOLUMES = ['volume','ls','--quiet']


def makepkg_configs(get,c,environment):
    """Treat both shell configurations as inert bytes; never source either."""
    need(c['makepkg_argv']==MAKEPKG_ARGV and c['makepkg_config_suffix']==MAKEPKG_SUFFIX, 'fixed full makepkg config interface required')
    base = get('makepkg-base.conf',MIB)
    effective = get('makepkg-effective.conf',MIB)
    suffix = MAKEPKG_SUFFIX.encode()
    need(base.decode()==environment['makepkg_configuration'] and effective==base+suffix and
         effective.endswith(suffix) and effective[:-len(suffix)]==base, 'exact retained base plus fixed makepkg suffix required')
    return dict(base=pin(base),effective=pin(effective))


def export_tar(raw,c):
    """Parse bounded retained plain Docker export DATA without extraction."""
    need(type(raw) is bytes and 1024<=len(raw)<=c['resources']['export_tar_bytes'] and len(raw)%512==0,
         'complete bounded plain export tar required')
    api = helpers()['archive_stream.py']
    limits = api.Limits(compressed_bytes=256*MIB,total_compressed_bytes=256*MIB,decoded_bytes=256*MIB,
                        members=256,file_bytes=64*MIB,window_bytes=128*MIB,deadline=time.monotonic()+90)
    headers=0;ended=False
    class Info(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls,stream):return cls._fromtarfile(stream)
        @classmethod
        def _fromtarfile(cls,stream,*,dircheck=True):
            nonlocal headers,ended
            api.tick(limits);body=stream.fileobj.read(512)
            if body==bytes(512):ended=True
            else:
                headers+=1;need(headers<=256,'export tar header budget')
            item = (cls._frombuf(body,stream.encoding,stream.errors,dircheck=dircheck) if hasattr(cls,'_frombuf')
                    else cls.frombuf(body,stream.encoding,stream.errors))
            item.offset=stream.fileobj.tell()-512
            return item._proc_member(stream)
        def _proc_pax(self,stream):
            need(0<=self.size<=65536,'export PAX budget');return super()._proc_pax(stream)
        def _proc_gnulong(self,stream):
            need(0<=self.size<=65536,'export long-name budget');return super()._proc_gnulong(stream)
        def _proc_sparse(self,*args):raise ValueError('sparse export refused')
        _proc_gnusparse_00=_proc_sparse
        _proc_gnusparse_01=_proc_sparse
        _proc_gnusparse_10=_proc_sparse
    rows={};root_seen=False
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:',tarinfo=Info) as stream:
        for member in stream:
            api.tick(limits)
            need(not member.sparse and not any(key.startswith('GNU.sparse') for key in member.pax_headers) and
                 not member.mode&0o7022,'ordinary safe export metadata required')
            if member.name in ('output','output/'):
                need(member.isdir() and not root_seen and member.size==0,'one ordinary export root directory required')
                root_seen=True;continue
            name=relative(member.name)
            parts=name.split('/')
            need(len(parts)==2 and parts[0]=='output' and member.isfile() and parts[1] not in rows and
                 re.fullmatch(r'[A-Za-z0-9._+-]{1,128}',parts[1]) and member.mode in (0o600,0o644) and
                 len(rows)<64 and 0<=member.size<=64*MIB,'unique flat bounded regular output member required')
            body=stream.extractfile(member).read(64*MIB+1)
            need(len(body)==member.size,'complete export member bytes required')
            rows[parts[1]]=dict(mode=member.mode,**pin(body))
        tail=stream.fileobj.read()
        need(ended and len(tail)>=512 and not any(tail),'complete zero-terminated export tar padding required')
    need(root_seen and rows,'nonvacuous complete export namespace required')
    return rows


def export_limit(row,c,size):
    receipt=row['fsize']
    need(type(receipt) is dict and set(receipt)=={'before','inherited_soft','after'}, 'complete file-size limit receipt required')
    before=receipt['before']
    need(type(before) is list and len(before)==2 and
         all(type(value) is int and -1<=value<=2**63-1 for value in before) and
         (before[1]==-1 or 0<=before[0]<=before[1]), 'actual finite-or-unlimited soft/hard file limits required')
    bound=min([c['resources']['export_tar_bytes']]+[value for value in before if value!=-1])
    need(type(receipt['inherited_soft']) is int and 0<bound==receipt['inherited_soft'] and
         receipt['after']==before and type(receipt['after']) is list and
         all(type(value) is int for value in receipt['after']) and size<=bound,
         'export must inherit tighter soft cap and restore exact prior file limits')


def export_namespace(root,name,expected):
    """No missing, additional, linked or nested retained output leaves."""
    relative(name)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            actual=set()
            with os.scandir(child) as entries:
                for entry in entries:
                    need(len(actual)<64,'retained output namespace count exceeds export bound')
                    actual.add(entry.name)
            need(actual==set(expected),'retained output namespace differs from raw export')
            for leaf,row in expected.items():
                info=os.stat(relative(leaf),dir_fd=child,follow_symlinks=False)
                need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==row['bytes'] and
                     stat.S_IMODE(info.st_mode)==row['mode'],'retained ordinary output type/size/mode differs from raw export')
        finally:os.close(child)
    finally:os.close(fd)


def entry_operations(get, c, provider_path):
    rows = json_data(get('entry-commands.json',MIB))
    stage = '/work/recipe/pkg/perl/'
    includes = ['-I'+stage+'usr/lib/perl5/5.42/core_perl','-I'+stage+'usr/share/perl5/core_perl']
    expected = [(['/usr/bin/pacman','-Q'],'packages-unsorted.txt'),
                (['/usr/bin/pacman','-Qoq',provider_path],'provider-owner.txt'),
                (['/usr/bin/readelf','--wide','-h','-d',provider_path],'provider-readelf.txt'),
                (c['makepkg_argv'],'makepkg.log'),
                ([stage+'usr/bin/perl',*includes,'/inputs/helpers/staged_smoke.pl','/work/recipe/pkg/perl'],'staged-smoke.json'),
                ([stage+'usr/bin/perl',*includes,'-MConfig','-e','print $Config{cf_time}, chr(10)'],'staged-cf-time.txt'),
                (['/usr/bin/bsdtar','-xOf','/work/output/'+ARCHIVE,'.PKGINFO'],'PKGINFO'),
                (['/usr/bin/bsdtar','-xOf','/work/output/'+ARCHIVE,'.BUILDINFO'],'BUILDINFO')]
    need(type(rows) is list and len(rows)==len(expected), 'all eight actual entry commands required')
    for row,(argv,log) in zip(rows,expected):
        need(row['argv']==argv and row['log']==log and row['success'] is True and
             type(row['returncode']) is int and row['returncode']==0, 'actual full entry command/exit differs')
        retirement(row['lifecycle'],actual=True)
        need(0<len(get(log,64*MIB))<=64*MIB, 'actual complete entry command output required')
    raw = get('packages-unsorted.txt',MIB)
    need(('\n'.join(sorted(raw.decode().splitlines()))+'\n').encode()==get('packages.txt',MIB), 'actual pacman raw/sorted inventory differs')
    seconds = sum(row['lifecycle']['elapsed_seconds'] for row in rows)
    need(seconds <= c['resources']['build_seconds'], 'finite entry commands exceed build budget')
    return dict(count=len(rows),seconds=seconds,makepkg_seconds=rows[3]['lifecycle']['elapsed_seconds'])


def create_argv(item, admission, inputs, c):
    """Independent literal consumer profile; never call this command."""
    return DOCKER+['create','--name',item['name'],'--label','cachy-asahi.operation='+c['operation'],
        '--cpus=2','--memory=4g','--memory-swap=4g','--pids-limit=256','--init','--read-only',
        '--network=none','--hostname=perl5423-native','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--user=1001:1001','--ulimit=nofile=1024:1024','--ulimit=core=0:0',
        *['--tmpfs='+name+':'+value for name,value in c['domain']['tmpfs'].items()],
        '--mount','type=volume,src='+item['volume']+',dst=/work',
        '--mount','type=bind,src='+inputs+',dst=/inputs,readonly',
        '--env','ADAPTER_ADMISSION_SHA256='+pin(encoded(admission))['sha256'],
        '--entrypoint=/usr/bin/bash',admission['image'],'--noprofile','--norc','/inputs/entry.sh']


def inventory(raw):
    need(type(raw) is bytes and len(raw) <= 8*MIB, 'bounded raw resource inventory required')
    text = raw.decode()
    lines = text.splitlines()
    need(not text or text.endswith('\n'), 'whole resource inventory lines required')
    need(len(lines) == len(set(lines)) and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}', name) for name in lines),
         'unique ordinary resource names required')
    return set(lines)


def input_snapshot(get, c, admission, qualification):
    """Check retained readonly inputs against independently supplied pins."""
    need(get('contract.json',MIB) == encoded(c) and get('admission.json',MIB) == encoded(admission) and
         get('qualification.json',MIB) == encoded(qualification), 'exact canonical readonly contract operands required')
    raw_map = get('adapter-source-map.json',MIB)
    need(pin(raw_map)['sha256'] == admission['source_map_sha256'], 'Root authenticated adapter Source map differs')
    source_map = object_data(raw_map)
    need(source_map['schema'] == 1 and type(source_map['files']) is dict and
         1 <= len(source_map['files']) <= 80, 'bounded complete Source map required')
    pins = object_data(get('helper-pins.json',MIB))
    need(1 <= len(pins) <= 8 and all(name in pins and pins[name]['sha256']==sha for name,sha in HELPERS.items()),
         'independent passive helper pins differ')
    for name in ['common.py','entry.py','entry.sh','contract.json','helper-pins.json',*['helpers/'+name for name in pins]]:
        relative(name)
        expected = source_map['files'][name]
        need(pin(get(name,MIB)) == {key:expected[key] for key in ('bytes','sha256')}, 'retained actual actor Source leaf differs: '+name)
    for name, expected in c['recipe_files'].items():
        relative(name)
        need('/' not in name and pin(get('recipe/'+name,MIB)) == {key:expected[key] for key in ('bytes','sha256')},
             'retained recipe leaf differs: '+name)
    need(pin(get(c['source_name'],32*MIB)) == dict(bytes=c['source_bytes'],sha256=c['source_sha256']) and
         pin(get('packet-map.json',MIB))['sha256'] == c['packet_map_sha256'], 'retained actual upstream/packet map differs')


def capacity_data(report, c, root, docker_root):
    """Validate numerical pre-allocation receipts, not present host capacity."""
    phases = [('before-input-snapshot',True,2,True),
              ('before-volume-1',True,2,False),('before-actor-1',True,2,False),('before-export-1',False,2,False),
              ('before-volume-2',True,1,False),('before-actor-2',True,1,False),('before-export-2',False,1,False)]
    records = report['capacity']
    need(type(records) is list and len(records)==len(phases), 'exact seven capacity receipts required')
    baseline = None
    def integer(value):return type(value) is int and 0 <= value <= 2**63-1
    for record,(phase,work,exports,inputs) in zip(records,phases):
        need(type(record) is dict and set(record)=={'phase','filesystems','MemAvailable_bytes','status'} and
             record['phase']==phase and record['status']=='PASS', 'ordered capacity phase/PASS receipt required')
        need(integer(record['MemAvailable_bytes']) and record['MemAvailable_bytes'] >=
             c['domain']['memory']+c['resources']['host_memory_reserve_bytes'], 'fixed actor plus host RAM reserve required')
        groups = record['filesystems']
        need(type(groups) is dict and 1 <= len(groups) <= 2, 'exact measured fixed filesystem groups required')
        path_devices = {}
        required = {str(docker_root):2048*MIB if work else 0,
                    str(root):(c['resources']['source_input_bytes'] if inputs else 0)+exports*c['resources']['output_export_bytes']}
        need(len(required)==2, 'separate actual storage paths required')
        for device,row in groups.items():
            need(type(device) is str and re.fullmatch(r'[1-9][0-9]{0,19}',device) and int(device)<=2**64-1 and
                 type(row) is dict and set(row)=={'paths','required_bytes','available_bytes','available_inodes','total_inodes'},
                 'literal device and complete fixed filesystem capacity counters required')
            paths = row['paths']
            need(type(paths) is list and 1 <= len(paths) <= 2 and len(paths)==len(set(paths)) and
                 all(type(path) is str and path in required and path not in path_devices for path in paths),
                 'exact unique storage path/device attribution required')
            path_devices.update({path:device for path in paths})
            for key in ('required_bytes','available_bytes','available_inodes','total_inodes'):
                need(integer(row[key]), 'nonnegative finite integer capacity counter required')
            need(row['required_bytes']==c['resources']['disk_reserve_bytes']+sum(required[path] for path in paths) and
                 row['available_bytes']>=row['required_bytes'], 'remaining allocation plus retained per-device byte reserve required')
            need(120000 <= row['available_inodes'] <= row['total_inodes'], 'positive fixed inode inventory/reserve required; unknown dynamic counters refused')
        need(set(path_devices)==set(required), 'every actual storage path requires capacity evidence')
        if baseline is None:baseline=path_devices
        need(path_devices==baseline, 'storage filesystem identity changed across capacity receipts')
    active = report['active_reserve']
    need(type(active) is dict and set(active)=={'samples','minimum_bytes','minimum_MemAvailable_bytes'} and
         integer(active['samples']) and 0 < active['samples'] <= c['resources']['pair_seconds'],
         'positive bounded active reserve sample receipt required')
    need(type(active['minimum_bytes']) is dict and set(active['minimum_bytes'])==set(baseline.values()) and
         all(integer(value) and value>=c['resources']['disk_reserve_bytes'] for value in active['minimum_bytes'].values()),
         'all active storage devices must retain disk reserve')
    need(integer(active['minimum_MemAvailable_bytes']) and
         active['minimum_MemAvailable_bytes']>=c['resources']['host_memory_reserve_bytes'], 'active host RAM reserve required')
    return dict(phases=len(records),fixed_inode_only=True,active_samples=active['samples'])


def operations(get, report, c, admission, root):
    """Recompute the ordered finite lifecycle using raw command output DATA."""
    rows = report['operations']
    need(type(rows) is list and 1 <= len(rows) <= 80, 'finite operation transcript required')
    for number, row in enumerate(rows):
        need(type(row) is dict and row['log'] == 'logs/'+str(number).zfill(3)+'.log' and
             row.get('success') is True and type(row['returncode']) is int, 'complete ordered operation identity required')
        retirement(row['lifecycle'],actual=True,code=row['returncode'])
    position = 0
    def take(argv, *, code=0, log=None,captured=False):
        nonlocal position
        need(position < len(rows), 'operation transcript truncated')
        row = rows[position]; position += 1
        need(row['argv'] == argv and row['returncode'] == code and (log is None or row['log'] == log),
             'exact operation ordering/argv/exit differs at '+str(position-1))
        need({'stdout','stdout_pin','fsize'}&set(row)==({'stdout','stdout_pin','fsize'} if captured else set()),
             'only bounded tar export may have captured stdout/file-limit receipt')
        return get(row['log'],8*MIB,empty=True),row
    image_raw,_ = take(DOCKER+['image','inspect',admission['image']])
    need(image_raw == get('image.json',MIB), 'retained/raw image inspect differs')
    image = json_data(image_raw)
    need(type(image) is list and len(image)==1 and image[0]['Id']==admission['image'] and
         image[0]['Architecture']=='arm64' and image[0]['Os']=='linux', 'actual admitted native image required')
    need(not image[0]['Config'].get('Volumes'), 'inherited anonymous image volumes refused')
    daemon,_ = take(DOCKER+['info','--format','{{.Architecture}}'])
    need(daemon in (b'arm64\n',b'aarch64\n'), 'actual native daemon required')
    docker_root,_ = take(DOCKER+['info','--format','{{.DockerRootDir}}'])
    path = Path(docker_root.decode().strip())
    need(path.is_absolute() and '..' not in path.parts and str(path).encode()+b'\n'==docker_root, 'canonical actual daemon storage path required')
    capacity = capacity_data(report,c,root,path)
    builds, retired = report['builds'], report['retired']
    need(type(builds) is list and len(builds)==2 and type(retired) is list and len(retired)==2,
         'two complete independently retired builds required')
    names = set(); volumes = set()
    for index, item in enumerate(builds,1):
        need(type(item) is dict and re.fullmatch(r'perl-native-'+admission['run']+r'-[0-9a-f]{12}-'+str(index),item['name']) and
             item['init']==item['name'].rsplit('-',1)[0]+'-init-'+str(index) and
             item['volume']==item['name'].rsplit('-',1)[0]+'-work-'+str(index) and
             item['admission_sha256']==report['admission_sha256'], 'fresh exactly owned actor/initializer/volume names required')
        need(not {item['name'],item['init']} & names and item['volume'] not in volumes, 'independent actor/volume identities required')
        names.update((item['name'],item['init']));volumes.add(item['volume'])
    need(builds[0]['name'].rsplit('-',1)[0] == builds[1]['name'].rsplit('-',1)[0], 'same finite pair resource token required')
    need(report['planned'] == [{key:item[key] for key in ('name','init','volume','admission_sha256')} for item in builds],
         'planned/actual resource identities differ')
    raw,_ = take(DOCKER+CONTAINERS,log=report['initial_container_log'])
    rawv,_ = take(DOCKER+VOLUMES,log=report['initial_volume_log'])
    need(raw==get('initial-containers.txt',8*MIB,empty=True) and rawv==get('initial-volumes.txt',8*MIB,empty=True) and
         not names&inventory(raw) and not volumes&inventory(rawv), 'fresh initial resource absence required')
    actor_seconds = [];exports=[]
    for index,(item,retired_row) in enumerate(zip(builds,retired),1):
        volume_raw,_ = take(DOCKER+['volume','create',item['volume']])
        need(volume_raw==(item['volume']+'\n').encode(), 'actual fresh volume creation output required')
        take(DOCKER+['create','--name',item['init'],'--cpus=2','--memory=4g','--memory-swap=4g',
            '--pids-limit=256','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--cap-add=CHOWN',
            '--security-opt=no-new-privileges','--mount','type=volume,src='+item['volume']+',dst=/work',
            '--entrypoint=/usr/bin/chown',admission['image'],'1001:1001','/work'])
        take(DOCKER+['start','--attach',item['init']])
        created,_ = take(create_argv(item,admission,report['inputs'],c))
        need(re.fullmatch(b'[0-9a-f]{64}\n',created), 'actual Docker create identity required')
        raw,_ = take(DOCKER+['inspect',item['name']],log=item['inspect_log'])
        inspection = json_data(raw)
        need(type(inspection) is list and len(inspection)==1, 'one actual actor inspection required')
        actual = object_data(get('actor-'+str(index)+'.json',MIB))
        need(actual==inspection[0] and actual['Id']==created.decode().strip() and actual['Name']=='/'+item['name'] and
             actual['State']['Running'] is False and actual['State']['Status']=='created', 'actual pre-start actor inspection join required')
        actor(actual,item,c,admission)
        need(next(m for m in actual['Mounts'] if m['Destination']=='/inputs')['Source']==report['inputs'],
             'exact readonly actor snapshot mount required')
        _,start = take(DOCKER+['start','--attach',item['name']])
        actor_seconds.append(start['lifecycle']['elapsed_seconds'])
        _,copied = take(DOCKER+['cp',item['name']+':/work/output','-'],captured=True)
        need(copied['stdout']=='export-'+str(index)+'.tar','exact retained export stdout path required')
        raw_export=get(copied['stdout'],c['resources']['export_tar_bytes'])
        need(copied['stdout_pin']==pin(raw_export),'actual raw export stdout pin differs')
        export_limit(copied,c,len(raw_export))
        exported=export_tar(raw_export,c)
        for leaf,row in exported.items():
            need(pin(get('build-'+str(index)+'/'+leaf,64*MIB,empty=True))=={key:row[key] for key in ('bytes','sha256')},
                 'retained output bytes differ from raw export tar')
        exports.append(exported)
        for name in (item['name'],item['init']):
            raw,_ = take(DOCKER+['rm',name]);need(raw==(name+'\n').encode(), 'natural container retirement required')
        raw,_ = take(DOCKER+['volume','rm',item['volume']])
        need(raw==(item['volume']+'\n').encode(), 'natural volume retirement required')
        need({key:retired_row[key] for key in ('name','init','volume')} ==
             {key:item[key] for key in ('name','init','volume')}, 'actual ordered retirement identities differ')
        raw,_ = take(DOCKER+CONTAINERS,log=retired_row['container_list_log'])
        rawv,_ = take(DOCKER+VOLUMES,log=retired_row['volume_list_log'])
        need(not {item['name'],item['init']}&inventory(raw) and item['volume'] not in inventory(rawv),
             'retirement absence must precede next resource allocation')
    cleanup = report['cleanup'];need(type(cleanup) is list and len(cleanup)==6, 'complete six-resource final cleanup transcript required')
    cursor = 0
    for item in reversed(builds):
        for argv in (DOCKER+['rm','-f',item['name']],DOCKER+['rm','-f',item['init']],DOCKER+['volume','rm',item['volume']]):
            row = cleanup[cursor];cursor += 1
            need(set(row)=={'argv','log','returncode'} and row['argv']==argv and row['returncode'] in (0,1), 'final owned cleanup operation differs')
            raw,_ = take(argv,code=row['returncode'],log=row['log'])
            if row['returncode']:
                resource = argv[-1]
                patterns = [r'Error response from daemon: No such container: '+re.escape(resource)+r'\n',
                            r'Error response from daemon: (?:get )?'+re.escape(resource)+r': no such volume\n']
                need(any(re.fullmatch(p,raw.decode()) for p in patterns), 'cleanup nonzero must mean exact already-retired owned resource absent')
    raw,_ = take(DOCKER+CONTAINERS)
    rawv,_ = take(DOCKER+VOLUMES)
    need(raw==get('final-containers.txt',8*MIB,empty=True) and rawv==get('final-volumes.txt',8*MIB,empty=True) and
         not names&inventory(raw) and not volumes&inventory(rawv), 'actual final owned resource absence required')
    need(position==len(rows) and report.get('owned_resources_absence_verified') is True, 'unaccounted operations or missing final absence observation')
    need(sum(row['lifecycle']['elapsed_seconds'] for row in rows) <= c['resources']['pair_seconds'], 'finite pair operation clocks exceed budget')
    return dict(count=len(rows),retired_volumes=2,final_absence=True,actor_seconds=actor_seconds,capacity=capacity,exports=exports)


def validate_pair(evidence_root, contract, admission, qualification):
    """Passive DATA API. Root must authenticate Source and operands beforehand.

    No native actor, namespace, extraction, installation, subprocess or role runs.
    A positive verdict is bounded package evidence, never hardware acceptance.
    """
    qualified(contract,admission,qualification)  # Refuse unqualified operands before artifact reads.
    root = Path(evidence_root)
    need(root.is_absolute() and root==root.resolve(), 'canonical evidence root required')
    def get(name, maximum, *, empty=False):return read(root,name,maximum,empty=empty)
    report = object_data(get('report.json',MIB))
    need(report['schema']==1 and report['status']=='PASS_NATIVE_PAIR' and report['native_acceptance'] is False and
         not any(key in report for key in ('failure','cleanup_failure')) and
         report['admission_sha256']==pin(encoded(admission))['sha256'] and
         report['qualification_sha256']==admission['qualification_sha256'] and
         report['domain_sha256']==contract['domain_sha256'] and
         report['source_map_sha256']==admission['source_map_sha256'] and
         report['inputs']==str(root/'inputs'), 'actual finite report/Root operand/input bindings differ')
    input_snapshot(lambda name,cap:get('inputs/'+name,cap),contract,admission,qualification)
    lifecycle = operations(get,report,contract,admission,root)
    results = []
    for index in (1,2):
        export_namespace(root,'build-'+str(index),lifecycle['exports'][index-1])
        result = build_data(lambda name,cap:get('build-'+str(index)+'/'+name,cap),contract,admission)
        need(result['archive']==report['builds'][index-1]['archive'], 'raw archive/report identity differs')
        need(result['commands']['seconds'] <= lifecycle['actor_seconds'][index-1]+1,
             'actual entry command clocks exceed observed native actor retirement clock')
        results.append(result)
    need(results[0]['archive']==results[1]['archive'] and results[0]['nodes']==results[1]['nodes'], 'independent compressed archive or complete payload differs')
    need(results[0]['makepkg_configs']==results[1]['makepkg_configs'] and
         all(get('build-1/'+name,MIB)==get('build-2/'+name,MIB) for name in ('makepkg-base.conf','makepkg-effective.conf')),
         'base/effective makepkg configurations differ across pair')
    need(get('build-1/'+ARCHIVE,64*MIB)==get('build-2/'+ARCHIVE,64*MIB), 'raw pair archive byte comparison differs')
    lifecycle['export_files']=[len(row) for row in lifecycle.pop('exports')]
    return dict(schema=1,status='PASS_NATIVE_PAIR_DATA',native_acceptance=False,domain=DOMAIN,
                archive=results[0]['archive'],entries=len(results[0]['nodes']),
                payload_identical=True,raw_bytes_identical=True,lifecycle=lifecycle,
                builds=[{key:value for key,value in result.items() if key!='nodes'} for result in results],
                limits=['Root must independently authenticate Source, approval, image/bootstrap signature audit and qualification operands',
                        'No install/removal, external XS, target ABI, native 16K, M2, performance or release acceptance'])
