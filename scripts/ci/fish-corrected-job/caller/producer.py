"""Bounded Topmem repository metadata, constructed from package bytes only.

No extraction, commands, signing, or publication. Pacman section/file mapping
adapts reviewed scripts/port/repository-client-native/crypto.py:database; this
module neither verifies signatures nor grants repository acceptance.
"""
import base64
import gzip
import hashlib
import io
import lzma
import math
import os
from pathlib import Path
import re
import stat
import tarfile
import time
import unicodedata
import zlib

MIB = 1024 * 1024
ARCHIVE_LIMIT, TAR_LIMIT, MEMBER_LIMIT = 16 * MIB, 32 * MIB, 8 * MIB
META_LIMIT, SIGNATURE_LIMIT, DATABASE_LIMIT, NODE_LIMIT = 65536, 65536, 512 * 1024, 512
NAME = 'cachy-asahi-topmem'
VERSIONS = {'current': '0.1.0-1', 'upgrade-fixture': '0.1.0-2'}
PAYLOAD = {'usr/bin/' + NAME: 0o755,
           'usr/share/doc/' + NAME + '/README.md': 0o644,
           'usr/share/licenses/' + NAME + '/NOTICE': 0o644,
           'usr/share/licenses/' + NAME + '/LICENSE': 0o644}
SCALARS = frozenset(('pkgname', 'pkgbase', 'pkgver', 'pkgdesc', 'url', 'builddate', 'packager', 'size', 'arch'))
LISTS = frozenset(('license', 'group', 'depend', 'optdepend', 'makedepend', 'checkdepend',
                   'conflict', 'replaces', 'provides', 'backup', 'xdata'))
RELATIONS = (('pkgbase', 'BASE'), ('pkgdesc', 'DESC'), ('group', 'GROUPS'), ('size', 'ISIZE'),
             ('url', 'URL'), ('license', 'LICENSE'), ('builddate', 'BUILDDATE'), ('packager', 'PACKAGER'),
             ('replaces', 'REPLACES'), ('conflict', 'CONFLICTS'), ('provides', 'PROVIDES'),
             ('depend', 'DEPENDS'), ('optdepend', 'OPTDEPENDS'), ('makedepend', 'MAKEDEPENDS'),
             ('checkdepend', 'CHECKDEPENDS'))

from types import SimpleNamespace
FISH_PINS = {'usr/share/cachy-asahi/fish-bang-bang/__history_previous_command.fish': 'd34b75125a34199775eaa74dd47ae37488c4e67f95f40f71b101b6a8f6f32e50', 'usr/share/cachy-asahi/fish-bang-bang/__history_previous_command_arguments.fish': '4e72dcce435d0fe1cf332fb339ed9608f10b29295b28f85ed6e7411ef8c05b64', 'usr/share/cachy-asahi/fish-bang-bang/opt-in.fish': 'd4dbd9dc123ebb31f821afd78c4b55554b4f17929d214baff35e405436e4cce7', 'usr/share/cachy-asahi/fish-bang-bang/README.md': '37a52ff036984a5beb4f42b8837a78f3de3391081240b470177ecc0b03aa6890', 'usr/share/licenses/cachy-asahi-fish-bang-bang/NOTICE': '0704c1ff8bcd8c94ad40888b35c5e25468ea9152b5781e7722ff0d04fb8aa879', 'usr/share/licenses/cachy-asahi-fish-bang-bang/LICENSE.upstream': '14c6826a7e33a6c74194ece88b26b5f5aee8473474001946a73d0f298b69fce0', 'usr/share/licenses/cachy-asahi-fish-bang-bang/LICENSE.project': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'}

def bind(profile='topmem-v1'):
    """Return a closed profile namespace; do not mutate shared module globals."""
    if type(profile) is not str or profile not in ('topmem-v1', 'fish-history-v1'):
        raise ValueError('producer-profile-unselected')
    PROFILE = profile
    VERSIONS = {'current': '0.1.0-1', 'upgrade-fixture': '0.1.0-2'}
    if profile == 'topmem-v1':
        NAME = 'cachy-asahi-topmem'
        PAYLOAD = {'usr/bin/' + NAME: 0o755,
                   'usr/share/doc/' + NAME + '/README.md': 0o644,
                   'usr/share/licenses/' + NAME + '/NOTICE': 0o644,
                   'usr/share/licenses/' + NAME + '/LICENSE': 0o644}
        DEPENDS, OPTDEPENDS, PAYLOAD_SHA = ['python>=3.11'], [], {}
    else:
        NAME = 'cachy-asahi-fish-bang-bang'
        DEPENDS = ['fish>=4.0']
        OPTDEPENDS = ['cachy-asahi-fish-config: separately enabled original shell helpers']
        PAYLOAD_SHA = dict(FISH_PINS)
        PAYLOAD = {name: 0o644 for name in PAYLOAD_SHA}

    def need(value, code):
        if not value:
            raise ValueError(code)


    def live(end):
        need(type(end) in (int, float) and math.isfinite(end) and time.monotonic() < end,
             'topmem-producer-deadline')


    def digest(raw):
        return hashlib.sha256(raw).hexdigest()


    def zstd_decoder(c, policy, end):
        """Load only the explicitly selected root-owned ARM libzstd helper.

        The caller first validates the V2 tool/linkage policy. Stable streaming ABI
        declarations follow zstd.h: windowLogMax=100, DCtx/DStream equivalence,
        three-field in/out buffers. Loading/calling this library is a native actor;
        review controls substitute the entire ctypes module with an inert model.
        """
        live(end)
        need(type(policy) is dict and type(policy.get('helpers')) is dict,
             'topmem-producer-zstd-policy')
        helpers = policy['helpers']
        selected = [name for name in helpers if type(name) is str and 'libzstd.so' in name.rsplit('/', 1)[-1]]
        need(len(selected) == 1 and re.fullmatch(r'/usr/lib/aarch64-linux-gnu/libzstd\.so\.[0-9]+(?:\.[0-9]+)*', selected[0]),
             'topmem-producer-zstd-selection')
        path, row = Path(selected[0]), helpers[selected[0]]
        need(type(row) is dict and set(row) == {'sha256', 'bytes', 'mode'}
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
             and type(row['bytes']) is int and 0 < row['bytes'] <= 64 * MIB
             and type(row['mode']) is int and row['mode'] in (0o644, 0o755),
             'topmem-producer-zstd-policy-row')
        row = dict(row)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')

        held = [None]

        def checked_library(cutoff=end):
            live(cutoff)
            need(path == path.resolve(), 'topmem-producer-zstd-canonical')
            parents = [p.lstat() for p in path.parents]
            need(all(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022
                     for s in parents), 'topmem-producer-zstd-parent')
            before = path.lstat()
            need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                 and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == row['mode']
                 and before.st_size == row['bytes'], 'topmem-producer-zstd-library')
            if held[0] is None:
                held[0] = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            opened = os.fstat(held[0])
            need(all(getattr(before, k) == getattr(opened, k) for k in fields),
                 'topmem-producer-zstd-open-drift')
            os.lseek(held[0], 0, os.SEEK_SET)
            body = bytearray()
            while True:
                live(cutoff)
                chunk = os.read(held[0], min(65536, row['bytes'] + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                need(len(body) <= row['bytes'], 'topmem-producer-zstd-pin')
            raw = bytes(body)
            final = os.fstat(held[0])
            after = path.lstat()
            need(type(raw) is bytes and len(raw) == row['bytes'] and digest(raw) == row['sha256']
                 and all(getattr(before, k) == getattr(after, k) == getattr(final, k) for k in fields)
                 and all(all(getattr(s, k) == getattr(p.lstat(), k) for k in fields)
                         for p, s in zip(path.parents, parents)), 'topmem-producer-zstd-pin')
            need(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01' and raw[18:20] == b'\xb7\x00',
                 'topmem-producer-zstd-architecture')
            return tuple(getattr(before, k) for k in fields)

        try:
            identity = checked_library()
            import ctypes
            library = ctypes.CDLL('/proc/self/fd/' + str(held[0]), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            need(checked_library() == identity, 'topmem-producer-zstd-load-drift')
        except BaseException:
            if held[0] is not None:
                descriptor, held[0] = held[0], None
                os.close(descriptor)
            raise

        try:
            class Input(ctypes.Structure):
                _fields_ = [('src', ctypes.c_void_p), ('size', ctypes.c_size_t), ('pos', ctypes.c_size_t)]

            class Output(ctypes.Structure):
                _fields_ = [('dst', ctypes.c_void_p), ('size', ctypes.c_size_t), ('pos', ctypes.c_size_t)]

            definitions = {
                'ZSTD_createDStream': ([], ctypes.c_void_p),
                'ZSTD_initDStream': ([ctypes.c_void_p], ctypes.c_size_t),
                'ZSTD_DCtx_setParameter': ([ctypes.c_void_p, ctypes.c_int, ctypes.c_int], ctypes.c_size_t),
                'ZSTD_decompressStream': ([ctypes.c_void_p, ctypes.POINTER(Output), ctypes.POINTER(Input)], ctypes.c_size_t),
                'ZSTD_freeDStream': ([ctypes.c_void_p], ctypes.c_size_t),
                'ZSTD_isError': ([ctypes.c_size_t], ctypes.c_uint)}
            functions = {}
            for name, (args, result) in definitions.items():
                try:
                    function = getattr(library, name)
                    function.argtypes, function.restype = args, result
                    functions[name] = function
                except AttributeError:
                    raise ValueError('topmem-producer-zstd-abi') from None

            def checked(result):
                need(type(result) is int and 0 <= result < 2**(8 * ctypes.sizeof(ctypes.c_size_t))
                     and functions['ZSTD_isError'](result) == 0, 'topmem-producer-zstd-api')
                return result

            def decode(raw, deadline):
                cutoff = min(end, deadline) if type(deadline) in (int, float) and math.isfinite(deadline) else deadline
                live(cutoff)
                need(held[0] is not None, 'topmem-producer-zstd-closed')
                need(type(raw) is bytes and 6 <= len(raw) <= ARCHIVE_LIMIT
                     and raw[:4] == b'\x28\xb5\x2f\xfd' and not raw[4] & 0x1b,
                     'topmem-producer-zstd-frame')
                need(checked_library(cutoff) == identity, 'topmem-producer-zstd-library-drift')
                stream = functions['ZSTD_createDStream']()
                need(type(stream) is int and 0 < stream < 2**(8 * ctypes.sizeof(ctypes.c_void_p)),
                     'topmem-producer-zstd-context')
                first, result, offset, incoming, source, calls = None, bytearray(), 0, None, None, 0
                try:
                    checked(functions['ZSTD_initDStream'](stream))
                    need(checked(functions['ZSTD_DCtx_setParameter'](stream, 100, 25)) == 0,
                         'topmem-producer-zstd-window')
                    while True:
                        live(cutoff)
                        calls += 1
                        need(calls <= 2048, 'topmem-producer-zstd-call-bound')
                        if incoming is None or incoming.pos == incoming.size:
                            chunk = raw[offset:offset + 65536]
                            offset += len(chunk)
                            source = ctypes.create_string_buffer(chunk, max(1, len(chunk)))
                            incoming = Input(ctypes.cast(source, ctypes.c_void_p), len(chunk), 0)
                        capacity = min(65536, TAR_LIMIT + 1 - len(result))
                        target = ctypes.create_string_buffer(capacity)
                        output = Output(ctypes.cast(target, ctypes.c_void_p), capacity, 0)
                        prior = incoming.pos
                        code = checked(functions['ZSTD_decompressStream'](stream, ctypes.byref(output), ctypes.byref(incoming)))
                        need(prior <= incoming.pos <= incoming.size and 0 <= output.pos <= output.size,
                             'topmem-producer-zstd-buffer')
                        result.extend(target.raw[:output.pos])
                        need(len(result) <= TAR_LIMIT, 'topmem-producer-expanded-bound')
                        if code == 0:
                            need(incoming.pos == incoming.size and offset == len(raw),
                                 'topmem-producer-trailing-stream')
                            break
                        need(incoming.pos > prior or output.pos > 0, 'topmem-producer-zstd-progress')
                except BaseException as error:
                    first = error
                finally:
                    try:
                        need(checked(functions['ZSTD_freeDStream'](stream)) == 0,
                             'topmem-producer-zstd-free')
                    except BaseException as error:
                        if first is None:
                            first = error
                if first is not None:
                    raise first
                live(cutoff)
                need(checked_library(cutoff) == identity, 'topmem-producer-zstd-library-drift')
                return bytes(result)

            decode.sha256 = row['sha256']

            def close():
                if held[0] is not None:
                    current = tuple(getattr(os.fstat(held[0]), k) for k in fields)
                    need(current[:2] == identity[:2], 'topmem-producer-zstd-close-drift')
                    descriptor, held[0] = held[0], None
                    os.close(descriptor)
                    need(current == identity, 'topmem-producer-zstd-close-drift')

            decode.close = close
            return decode

        except BaseException:
            if held[0] is not None:
                descriptor, held[0] = held[0], None
                os.close(descriptor)
            raise


    def expanded(raw, extension, end):
        """One stream only; bound output before allocation and XZ dictionary memory."""
        live(end)
        need(raw.startswith(b'\xfd7zXZ\x00' if extension == 'xz' else b'\x1f\x8b'),
             'topmem-producer-compression')
        decoder = (lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * MIB)
                   if extension == 'xz' else zlib.decompressobj(31))
        output, offset, pending = bytearray(), 0, b''
        try:
            while True:
                live(end)
                if extension == 'xz':
                    if decoder.needs_input:
                        need(offset < len(raw), 'topmem-producer-truncated-stream')
                        pending = raw[offset:offset + 65536]
                        offset += len(pending)
                    else:
                        pending = b''
                elif not pending:
                    need(offset < len(raw), 'topmem-producer-truncated-stream')
                    pending = raw[offset:offset + 65536]
                    offset += len(pending)
                chunk = decoder.decompress(pending, max_length=min(65536, TAR_LIMIT + 1 - len(output)))
                output.extend(chunk)
                need(len(output) <= TAR_LIMIT, 'topmem-producer-expanded-bound')
                if decoder.eof:
                    need(not decoder.unused_data and offset == len(raw), 'topmem-producer-trailing-stream')
                    break
                if extension == 'gz':
                    pending = decoder.unconsumed_tail
        except (lzma.LZMAError, zlib.error):
            raise ValueError('topmem-producer-compression') from None
        live(end)
        return bytes(output)


    def members(payload, end):
        """Read fixed tar headers directly: extension bodies are never applied."""
        result, offset = {}, 0
        need(len(payload) % 512 == 0, 'topmem-producer-tar-alignment')
        while offset + 512 <= len(payload):
            live(end)
            header = payload[offset:offset + 512]
            if header == b'\0' * 512:
                need(offset + 1024 <= len(payload) and not any(payload[offset:]),
                     'topmem-producer-tar-terminator')
                return result
            need(len(result) < NODE_LIMIT, 'topmem-producer-node-bound')
            try:
                row = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            except (tarfile.TarError, UnicodeError, ValueError):
                raise ValueError('topmem-producer-tar-header') from None
            need(row.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                 and not row.linkname and not row.pax_headers and not row.sparse,
                 'topmem-producer-tar-type')
            need(0 <= row.size <= MEMBER_LIMIT and (not row.isdir() or row.size == 0),
                 'topmem-producer-member-bound')
            name = row.name
            if name in ('.', './'):
                need(row.isdir(), 'topmem-producer-tar-path')
                name = '.'
            else:
                name = name.removeprefix('./')
                if row.isdir():
                    name = name.removesuffix('/')
                need(name and len(name.encode()) <= 256 and not name.startswith('/')
                     and all(p not in ('', '.', '..') for p in name.split('/'))
                     and '\\' not in name and not any(unicodedata.category(c) in ('Cc', 'Cf') for c in name),
                     'topmem-producer-tar-path')
            need(name not in result, 'topmem-producer-tar-duplicate')
            start = offset + 512
            offset = start + ((row.size + 511) // 512) * 512
            need(offset <= len(payload), 'topmem-producer-tar-truncated')
            result[name] = {'type': 'dir' if row.isdir() else 'file', 'size': row.size,
                            'mode': row.mode, 'uid': row.uid, 'gid': row.gid,
                            'body': memoryview(payload)[start:start + row.size]}
        raise ValueError('topmem-producer-tar-terminator')


    def pkginfo(raw, version, end):
        need(0 < len(raw) <= META_LIMIT and raw.endswith(b'\n'), 'topmem-producer-pkginfo-bound')
        try:
            text = raw.decode('utf-8', errors='strict')
        except UnicodeError:
            raise ValueError('topmem-producer-pkginfo-encoding') from None
        result, lines = {}, text.split('\n')
        need(len(lines) <= NODE_LIMIT, 'topmem-producer-pkginfo-count')
        for line in lines:
            live(end)
            need(not any(unicodedata.category(c) in ('Cc', 'Cf') for c in line),
                 'topmem-producer-pkginfo-control')
            if not line or line.startswith('#'):
                continue
            key, sep, value = line.partition(' = ')
            need(sep and key in SCALARS | LISTS and len(value.encode()) <= 4096
                 and (value or key == 'url') and value == value.strip()
                 and not re.fullmatch(r'%[A-Z0-9_]+%', value), 'topmem-producer-pkginfo-field')
            need(key not in result or key in LISTS and value not in result[key],
                 'topmem-producer-pkginfo-duplicate')
            result.setdefault(key, []).append(value)
        need(all(len(result.get(k, [])) == 1 for k in
                 ('pkgname', 'pkgver', 'pkgdesc', 'arch', 'size', 'builddate', 'packager')),
             'topmem-producer-pkginfo-required')
        need(result['pkgname'] == [NAME] and result['pkgver'] == [version] and result['arch'] == ['any']
             and result.get('pkgbase', [NAME]) == [NAME] and result.get('license') == ['MIT']
             and result.get('depend') == DEPENDS, 'topmem-producer-package-identity')
        if PROFILE == 'fish-history-v1':
            need(result.get('optdepend') == OPTDEPENDS
                 and result['pkgdesc'] == ['Explicitly enabled pinned Fish history expansion for cachy-asahi']
                 and result.get('url') == ['https://github.com/oh-my-fish/plugin-bang-bang']
                 and all(not result.get(k) for k in ('group', 'makedepend', 'checkdepend', 'conflict', 'replaces', 'provides')),
                 'fish-producer-package-metadata')
        for key, maximum in (('size', TAR_LIMIT), ('builddate', 2**63 - 1)):
            value = result[key][0]
            need(re.fullmatch(r'0|[1-9][0-9]{0,18}', value) and int(value) <= maximum,
                 'topmem-producer-pkginfo-number')
        need(not result.get('backup') and result.get('xdata', []) in ([], ['pkgtype=pkg']),
             'topmem-producer-package-kind')
        if result.get('url') == ['']:
            result.pop('url')
        need(all(not any(c.isspace() for c in v) for v in result.get('url', [])),
             'topmem-producer-package-url')
        return result


    def sections(rows):
        return ''.join('%' + key + '%\n' + '\n'.join(values) + '\n\n'
                       for key, values in rows if values).encode('utf-8')


    def database(prefix, desc, files, end):
        live(end)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
            for name, body in [(prefix + '/', None), (prefix + '/desc', desc)] + (
                    [(prefix + '/files', files)] if files is not None else []):
                live(end)
                row = tarfile.TarInfo(name)
                row.uid = row.gid = row.mtime = 0
                row.uname = row.gname = ''
                row.mode = 0o755 if body is None else 0o644
                row.type = tarfile.DIRTYPE if body is None else tarfile.REGTYPE
                row.size = 0 if body is None else len(body)
                archive.addfile(row, None if body is None else io.BytesIO(body))
        need(output.tell() <= DATABASE_LIMIT, 'topmem-producer-database-bound')
        compressed = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed, mode='wb', filename='', mtime=0, compresslevel=9) as stream:
            stream.write(output.getvalue())
        live(end)
        need(compressed.tell() <= DATABASE_LIMIT, 'topmem-producer-database-bound')
        return compressed.getvalue()


    def build(package_raw, signature_raw, filename, variant, end, zstd_decoder=None):
        """Build desc and files databases. Signature bytes are included, not verified."""
        live(end)
        need(type(package_raw) is bytes and 0 < len(package_raw) <= ARCHIVE_LIMIT,
             'topmem-producer-archive-bound')
        need(type(signature_raw) is bytes and 0 < len(signature_raw) <= SIGNATURE_LIMIT,
             'topmem-producer-signature-bound')
        need(type(variant) is str and variant in VERSIONS, 'topmem-producer-variant')
        version = VERSIONS[variant]
        need(type(filename) is str and filename in {NAME + '-' + version + '-any.pkg.tar.' + x
                                                   for x in ('xz', 'gz', 'zst')}, 'topmem-producer-filename')
        extension = filename.rsplit('.', 1)[1]
        if extension == 'zst':
            need(callable(zstd_decoder) and type(getattr(zstd_decoder, 'sha256', None)) is str
                 and re.fullmatch('[0-9a-f]{64}', zstd_decoder.sha256), 'topmem-producer-zstd-unselected')
            payload = zstd_decoder(package_raw, end)
            need(type(payload) is bytes and 0 < len(payload) <= TAR_LIMIT, 'topmem-producer-expanded-bound')
        else:
            payload = expanded(package_raw, extension, end)
        rows = members(payload, end)
        need('.PKGINFO' in rows and rows['.PKGINFO']['type'] == 'file', 'topmem-producer-pkginfo-missing')
        info_raw = bytes(rows['.PKGINFO']['body'])
        info = pkginfo(info_raw, version, end)
        dirs = {p for n in PAYLOAD for p in ('/'.join(n.split('/')[:i]) for i in range(1, len(n.split('/'))))}
        actual_files = {n for n, r in rows.items() if not n.startswith('.') and r['type'] == 'file'}
        need(actual_files == set(PAYLOAD) and {n for n in rows if n.startswith('.')}
             <= {'.', '.PKGINFO', '.BUILDINFO', '.MTREE'}, 'topmem-producer-payload-set')
        for name, row in rows.items():
            live(end)
            need(row['uid'] == row['gid'] == 0, 'topmem-producer-payload-owner')
            if row['type'] == 'dir':
                need(name == '.' or name in dirs, 'topmem-producer-payload-directory')
                need(row['mode'] == 0o755, 'topmem-producer-payload-mode')
            elif name in PAYLOAD:
                need(row['mode'] == PAYLOAD[name], 'topmem-producer-payload-mode')
                if PROFILE == 'fish-history-v1':
                    need(digest(row['body']) == PAYLOAD_SHA[name], 'fish-producer-payload-pin')
            else:
                need(row['mode'] == 0o644, 'topmem-producer-payload-mode')
        files = sorted(n + ('/' if r['type'] == 'dir' else '') for n, r in rows.items() if not n.startswith('.'))
        sha = digest(package_raw)
        md5 = hashlib.md5(package_raw, usedforsecurity=False).hexdigest()
        desc = sections([('FILENAME', [filename]), ('NAME', [NAME]), ('VERSION', [version]), ('ARCH', ['any']),
                         ('CSIZE', [str(len(package_raw))]), ('MD5SUM', [md5]), ('SHA256SUM', [sha]),
                         ('PGPSIG', [base64.b64encode(signature_raw).decode('ascii')])]
                        + [(target, info.get(source, [])) for source, target in RELATIONS])
        listing = sections([('FILES', files)])
        need(len(desc) <= DATABASE_LIMIT and len(listing) <= DATABASE_LIMIT, 'topmem-producer-database-bound')
        prefix = NAME + '-' + version
        db, file_db = database(prefix, desc, None, end), database(prefix, desc, listing, end)
        metadata = {'name': NAME, 'version': version, 'arch': 'any', 'filename': filename,
                    'archive_bytes': len(package_raw), 'archive_sha256': sha, 'archive_md5': md5,
                    'signature_bytes': len(signature_raw), 'signature_sha256': digest(signature_raw),
                    'pkginfo_bytes': len(info_raw), 'pkginfo_sha256': digest(info_raw), 'pkginfo': info,
                    'files': files, 'payload_bytes': sum(rows[n]['size'] for n in actual_files),
                    'db_sha256': digest(db), 'files_sha256': digest(file_db)}
        live(end)
        return {'db': db, 'files': file_db, 'metadata': metadata}

    return SimpleNamespace(profile=PROFILE, NAME=NAME, PAYLOAD=dict(PAYLOAD), PAYLOAD_SHA=dict(PAYLOAD_SHA), VERSIONS=dict(VERSIONS), live=live, digest=digest, zstd_decoder=zstd_decoder, expanded=expanded, members=members, pkginfo=pkginfo, sections=sections, database=database, build=build)

_DEFAULT = bind()
for _name in ('live','digest','zstd_decoder','expanded','members','pkginfo','sections','database','build'):
    globals()[_name] = getattr(_DEFAULT, _name)
