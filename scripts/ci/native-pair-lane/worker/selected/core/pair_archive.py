"""Pure bounded uncompressed ordinary USTAR/GNU inspection of the two sealed recipes.

No extraction, compression auto-detection, filesystem, process, or ELF execution.
PAX/GNU extended headers are deliberately outside this proposal until an actual
bounded package-layout observation is reviewed by Root.
"""
import hashlib
import json
import re

DECODED_LIMIT = 8 * 1024 * 1024
MEMBER_LIMIT = 1024 * 1024
MEMBER_COUNT_LIMIT = 64
PATH_LIMIT = 200
METADATA_LIMIT = 65536
EPOCH = 1791748800
RECIPE_PIN = {'cachy-asahi-fish-bang-bang': '05a1b2cb4710cc14f62678df37d1236fee909874b5b709d82d54fe4b8dc0f93d',
 'cachy-asahi-topmem': 'fc17b0af876ae0dfb97b00e2293bb01fb8c054702d19252804e8ab11196315d2'}
PAYLOAD = {'cachy-asahi-fish-bang-bang': {'usr/share/cachy-asahi/fish-bang-bang/README.md': {'mode': 420,
                                                                                   'sha256': '37a52ff036984a5beb4f42b8837a78f3de3391081240b470177ecc0b03aa6890',
                                                                                   'size': 2810},
                                'usr/share/cachy-asahi/fish-bang-bang/__history_previous_command.fish': {'mode': 420,
                                                                                                         'sha256': 'd34b75125a34199775eaa74dd47ae37488c4e67f95f40f71b101b6a8f6f32e50',
                                                                                                         'size': 170},
                                'usr/share/cachy-asahi/fish-bang-bang/__history_previous_command_arguments.fish': {'mode': 420,
                                                                                                                   'sha256': '4e72dcce435d0fe1cf332fb339ed9608f10b29295b28f85ed6e7411ef8c05b64',
                                                                                                                   'size': 198},
                                'usr/share/cachy-asahi/fish-bang-bang/opt-in.fish': {'mode': 420,
                                                                                     'sha256': 'd4dbd9dc123ebb31f821afd78c4b55554b4f17929d214baff35e405436e4cce7',
                                                                                     'size': 2599},
                                'usr/share/licenses/cachy-asahi-fish-bang-bang/LICENSE.project': {'mode': 420,
                                                                                                  'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7',
                                                                                                  'size': 1081},
                                'usr/share/licenses/cachy-asahi-fish-bang-bang/LICENSE.upstream': {'mode': 420,
                                                                                                   'sha256': '14c6826a7e33a6c74194ece88b26b5f5aee8473474001946a73d0f298b69fce0',
                                                                                                   'size': 1108},
                                'usr/share/licenses/cachy-asahi-fish-bang-bang/NOTICE': {'mode': 420,
                                                                                         'sha256': '0704c1ff8bcd8c94ad40888b35c5e25468ea9152b5781e7722ff0d04fb8aa879',
                                                                                         'size': 811}},
 'cachy-asahi-topmem': {'usr/bin/cachy-asahi-topmem': {'mode': 493,
                                                       'sha256': '96c1b49a92cb6e97d1fe5c51c23f452d79341f2d71cd624cd3197d33b29633b1',
                                                       'size': 4203},
                        'usr/share/doc/cachy-asahi-topmem/README.md': {'mode': 420,
                                                                       'sha256': '90082e9119cdea843b0e060f4061a300015dffd6a25c55d12a72b0a75348cf2b',
                                                                       'size': 2543},
                        'usr/share/licenses/cachy-asahi-topmem/LICENSE': {'mode': 420,
                                                                          'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7',
                                                                          'size': 1081},
                        'usr/share/licenses/cachy-asahi-topmem/NOTICE': {'mode': 420,
                                                                         'sha256': '07227afce6f380bcf3deaf9b273fb286f6bcee69b5f1dddec9ebcd1dc2ecd098',
                                                                         'size': 395}}}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def _octal(raw):
    value = raw.rstrip(b'\x00 ').lstrip(b' ')
    need(value and re.fullmatch(b'[0-7]+', value), 'tar-octal')
    return int(value, 8)


def _text(raw):
    head, separator, tail = raw.partition(b'\x00')
    need(not separator or not any(tail), 'tar-string-padding')
    return head.decode('ascii')


def _name(raw, directory):
    need(raw and len(raw.encode('ascii')) <= PATH_LIMIT and '\\' not in raw and not raw.startswith('/'), 'tar-path')
    # One conventional ./ prefix is explicit; no normalization of other aliases.
    if raw == './' and directory:
        return '.'
    name = raw[2:] if raw.startswith('./') else raw
    if directory:
        need(name.endswith('/'), 'tar-directory-name')
        name = name[:-1]
    need(name and all(p and p not in ('.', '..') for p in name.split('/'))
         and all(32 < ord(c) < 127 for c in name), 'tar-path')
    return name


def metadata(raw):
    need(len(raw) <= METADATA_LIMIT and b'\x00' not in raw, 'metadata-bound')
    text = raw.decode('utf-8')
    result = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_]+) = ([^\x00-\x1f\x7f]*)', line)
        need(match is not None, 'metadata-line')
        key, value = match.groups()
        result.setdefault(key, []).append(value)
    return result


def interpret(raw, package, epoch, pkgbuild_sha256, authority):
    """Closed Source gate; report equality is enforced separately by pair owner.

    The exact payload pins derive from b994876ba... captured19 selected Source.
    Caller supplies the sealed PKGBUILD pin and its original authority. Metadata
    is bounded and package identity/dependencies agree with these arch=any recipes.
    MTREE remains an opaque hashed metadata file (never executed or decompressed).
    """
    try:
        authority.check()
        need(type(raw) is bytes and 1024 <= len(raw) <= DECODED_LIMIT and len(raw) % 512 == 0, 'tar-bound')
        need(package in PAYLOAD and type(epoch) is int and epoch == EPOCH, 'package-selection')
        need(type(pkgbuild_sha256) is str and pkgbuild_sha256 == RECIPE_PIN[package], 'recipe-pin')
        allowed = PAYLOAD[package]
        directories = {path.rsplit('/', 1)[0] for path in allowed}
        directories.add('.')
        directories |= {parent for path in allowed for parent in ('/'.join(path.split('/')[:i]) for i in range(1, len(path.split('/'))))}
        members, contents, offset, ended = {}, {}, 0, False
        while offset < len(raw):
            authority.check()
            header = raw[offset:offset + 512]
            if not any(header):
                need(len(raw) - offset >= 1024 and not any(raw[offset:]), 'tar-tail')
                ended = True
                break
            need(len(members) < MEMBER_COUNT_LIMIT and len(header) == 512, 'tar-count')
            magic = header[257:265]
            need(magic in (b'ustar\x0000', b'ustar  \x00'), 'tar-format')
            need(_text(header[265:297]) in ('', 'root') and _text(header[297:329]) in ('', 'root'), 'tar-owner-name')
            for field in (header[329:337], header[337:345]):
                need(not any(field) or _octal(field) == 0, 'tar-device-field')
            checksum = _octal(header[148:156])
            need(checksum == sum(header[:148]) + 8 * 32 + sum(header[156:]), 'tar-checksum')
            kind = header[156:157]
            need(kind in (b'0', b'\x00', b'5'), 'tar-kind')
            directory = kind == b'5'
            if magic == b'ustar  \x00':
                # Ordinary GNU layout has no POSIX prefix. No atime/ctime,
                # multivolume, sparse or extended-header state is selected.
                need(not any(header[345:512]), 'tar-gnu-extension')
                prefix = ''
            else:
                prefix = _text(header[345:500])
            name = _text(header[:100])
            name = _name((prefix + '/' if prefix else '') + name, directory)
            need(name not in members, 'tar-duplicate')
            size, mode = _octal(header[124:136]), _octal(header[100:108])
            need(size <= MEMBER_LIMIT and _octal(header[108:116]) == _octal(header[116:124]) == 0,
                 'tar-owner-or-size')
            need(_octal(header[136:148]) == epoch and not _text(header[157:257]), 'tar-time-or-link')
            need(not any(header[500:512]), 'tar-header-tail')
            end = offset + 512 + size
            padded = end + (-size % 512)
            need(padded <= len(raw), 'tar-truncated')
            content = raw[offset + 512:end]
            need(not any(raw[end:padded]), 'tar-data-padding')
            if directory:
                need(name in directories and size == 0 and mode == 0o755, 'tar-directory')
            elif name in allowed:
                row = allowed[name]
                need(size == row['size'] and mode == row['mode']
                     and hashlib.sha256(content).hexdigest() == row['sha256'], 'payload-pin')
                need(not content.startswith(b'\x7fELF'), 'payload-elf')
            else:
                need(name in ('.PKGINFO', '.BUILDINFO', '.MTREE') and mode == 0o644 and size <= METADATA_LIMIT,
                     'unreviewed-member')
                contents[name] = content
            members[name] = {'type': '5' if directory else '0', 'size': size, 'mode': mode,
                             'uid': 0, 'gid': 0, 'mtime': epoch,
                             'sha256': None if directory else hashlib.sha256(content).hexdigest()}
            offset = padded
            authority.check()
        need(ended and set(allowed) <= set(members) and set(contents) == {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'tar-members')
        info, build = metadata(contents['.PKGINFO']), metadata(contents['.BUILDINFO'])
        need(set(info) <= {'pkgname','pkgbase','pkgver','pkgdesc','url','builddate','packager','size','arch','license','depend','optdepend','xdata'}, 'pkginfo-fields')
        need(set(build) <= {'format','pkgname','pkgbase','pkgver','pkgarch','pkgbuild_sha256sum','packager','builddate','builddir','startdir','buildenv','options','installed'}, 'buildinfo-fields')
        need(len(build.get('installed', [])) == 341 and len(set(build['installed'])) == 341, 'buildinfo-inventory-count')
        need(info.get('size') == [str(sum(v['size'] for v in allowed.values()))], 'pkginfo-size')
        need(info.get('xdata', ['pkgtype=pkg']) == ['pkgtype=pkg'], 'pkginfo-kind')
        need(info.get('pkgbase', [package]) == build.get('pkgbase', [package]) == [package], 'metadata-pkgbase')
        for key, value in {'pkgname': package, 'pkgver': '0.1.0-1', 'arch': 'any', 'license': 'MIT', 'builddate': str(epoch)}.items():
            need(info.get(key) == [value], 'pkginfo-identity')
        need(not (set(info) & {'install', 'backup', 'conflict', 'replaces', 'provides'}), 'pkginfo-unreviewed')
        dependencies = ['python>=3.11'] if package == 'cachy-asahi-topmem' else ['fish>=4.0']
        need(info.get('depend') == dependencies, 'pkginfo-dependencies')
        expected_optional = [] if package == 'cachy-asahi-topmem' else ['cachy-asahi-fish-config: separately enabled original shell helpers']
        need(info.get('optdepend', []) == expected_optional, 'pkginfo-optional')
        for key, value in {'format': '2', 'pkgname': package, 'pkgver': '0.1.0-1', 'pkgarch': 'any',
                           'pkgbuild_sha256sum': pkgbuild_sha256, 'builddate': str(epoch)}.items():
            need(build.get(key) == [value], 'buildinfo-identity')
        authority.check()
        payload_manifest = {name: members[name] for name in sorted(members) if name not in contents}
        payload_raw = json.dumps(payload_manifest, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        return {'schema_version': 1, 'payload_sha256': hashlib.sha256(payload_raw).hexdigest(),
                'pkginfo_sha256': hashlib.sha256(contents['.PKGINFO']).hexdigest(),
                'buildinfo_sha256': hashlib.sha256(contents['.BUILDINFO']).hexdigest(),
                'parsed_pkginfo_sha256': hashlib.sha256(json.dumps(info, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'parsed_buildinfo_sha256': hashlib.sha256(json.dumps(build, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'payload_manifest': payload_manifest, 'status': 'SOURCE_STATIC_ONLY', 'sha256': hashlib.sha256(raw).hexdigest(),
                'payload': {name: members[name] for name in sorted(allowed)},
                'members': members, 'PKGINFO': info, 'BUILDINFO': build, 'review': [],
                'installed_acceptance': False, 'hardware_acceptance': False}
    except BaseException as error:
        try:
            authority.record_failure(error)
        except BaseException:
            pass
        raise
