#!/usr/bin/env python3
"""Data-only DEVELOPMENT KSM build-pair contract; never extracts or executes inputs.

The controller must authenticate the provenance hashes, image/bootstrap receipt,
source commit, daemon and job identity before calling this helper. Provenance is
a checked assertion, not independent proof of native execution or hardware use.
"""
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

NAME = 'cachy-asahi-ksmctl'
VERSION = '0.1.0-1'
APPROVED_MAP_SHA256 = 'f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44'
ENTRY_SHA256 = '89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24'
# ALARM PKGBUILDs@fd636a0077db0efe900d67d4de910c0d270fc8c4 pins
# pacman@54d94116164b0b2202c6061c4a59c6f3e70820d8. Its meson.build
# project version is 7.1.0, substituted into scripts/makepkg.sh.in, despite
# git-describe producing the distinct distribution package version below.
PACMAN_PACKAGE_VERSION = '7.1.0.r9.g54d9411-2'
MAKEPKG_VERSION = '7.1.0'
PAYLOAD = {
    'usr/bin/' + NAME: ('cachy-asahi-ksmctl', 0o755),
    'usr/share/doc/' + NAME + '/README.md': ('README.md', 0o644),
    'usr/share/doc/' + NAME + '/source-provenance.json': ('source-provenance.json', 0o644),
    'usr/share/licenses/' + NAME + '/NOTICE': ('NOTICE', 0o644),
    'usr/share/licenses/' + NAME + '/LICENSE': ('LICENSE', 0o644),
}
INPUTS = {'.SRCINFO', 'LICENSE', 'NOTICE', 'PKGBUILD', 'README.md', 'adaptation.patch',
          'cachy-asahi-ksmctl', 'check-source.py', 'management-policy.md', 'native-stage.md',
          'policy.py', 'source-provenance.json', 'test_ksmctl.py', 'test_policy.py', 'upstream-ksmctl'}
REQUIRED = {'build.log', 'validation.json', 'expected-packages.lock',
            'artifacts/packages.lock', 'artifacts/generated.SRCINFO',
            'artifacts/environment.txt', 'artifacts/config.sha256',
            'artifacts/makepkg.conf', 'artifacts/pacman.conf'}
MAX_FILE = 4 * 1024 * 1024
MAX_EXPANDED = 8 * 1024 * 1024
HASH = re.compile(r'[0-9a-f]{64}\Z')


class Refused(ValueError):
    """A bounded, public-safe diagnostic; input contents are never interpolated."""


def require(ok, message):
    if not ok:
        raise Refused(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, 'duplicate JSON key')
        out[key] = value
    return out


def json_object(data):
    try:
        result = json.loads(data, object_pairs_hook=_pairs,
                            parse_constant=lambda _: require(False, 'nonfinite JSON value'))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise Refused('invalid bounded JSON') from None
    require(isinstance(result, dict), 'JSON object required')
    return result


def _path(name):
    require(isinstance(name, str) and 0 < len(name) <= 240, 'invalid relative evidence path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and
            all(p not in ('.', '..') for p in path.parts) and
            re.fullmatch(r'[A-Za-z0-9_./+-]+', name), 'unsafe relative evidence path')
    return path


def read_file(path, limit=MAX_FILE):
    """Reject links/special files and avoid following any path component."""
    path = Path(path).absolute()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        item = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(item)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                    before.st_size <= limit, 'evidence must be a bounded single-link regular file')
            with os.fdopen(item, 'rb', closefd=False) as stream:
                data = stream.read(limit + 1)
            after = os.fstat(item)
            require(len(data) <= limit and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'evidence changed while reading')
            return data
        finally:
            os.close(item)
    except OSError:
        raise Refused('missing or unsafe evidence file') from None
    finally:
        os.close(fd)


def _inventory(data):
    require(isinstance(data, bytes) and len(data) < 65536, 'bounded package lock required')
    try:
        lines = data.decode('ascii').splitlines(keepends=True)
    except UnicodeError:
        raise Refused('invalid package lock encoding') from None
    require(len(lines) == 341 and lines == sorted(lines), 'exact sorted 341-package lock required')
    result = {}
    for line in lines:
        require(re.fullmatch(r'[a-z0-9][a-z0-9@._+-]* [A-Za-z0-9:._+~-]+\n', line),
                'invalid package lock row')
        name, version = line.rstrip('\n').split(' ')
        require(name not in result, 'duplicate package lock name')
        result[name] = version
    return result


def _entries(path, limit):
    """Stop scanning at limit + 1; never materialize an unbounded directory."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                require(len(names) < limit, 'build evidence directory entry bound exceeded')
                require(entry.is_file(follow_symlinks=False), 'flat regular evidence directory required')
                names.append(entry.name)
        return names
    except OSError:
        raise Refused('missing or unsafe evidence directory') from None
    finally:
        if fd is not None:
            os.close(fd)


def metadata(data):
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        raise Refused('invalid package metadata encoding') from None
    require(len(data) <= 65536 and '\x00' not in text, 'bounded package metadata required')
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*', line)
        require(match is not None, 'invalid package metadata row')
        key, value = match.groups()
        require(not any(ord(c) < 32 for c in value), 'control character in metadata')
        result.setdefault(key, []).append(value)
    return result


def _one(data, key, value):
    require(data.get(key) == [value], 'package metadata binding mismatch')


def _uncompress(data, kind, limit=MAX_EXPANDED):
    try:
        if kind == 'xz':
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024 * 1024)
            output = decoder.decompress(data, max_length=limit + 1)
            require(len(output) <= limit, 'expanded archive exceeds bound')
            require(decoder.eof and not any(decoder.unused_data) and len(decoder.unused_data) % 4 == 0,
                    'incomplete or trailing compressed archive')
        else:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                output = stream.read(limit + 1)
        require(len(output) <= limit, 'expanded archive exceeds bound')
        return output
    except (OSError, EOFError, lzma.LZMAError):
        raise Refused('invalid compressed archive') from None


def _mtree(data, members):
    """Validate the finite makepkg mtree rather than trusting arbitrary paths."""
    try:
        text = _uncompress(data, 'gz', 65536).decode('ascii')
    except UnicodeError:
        raise Refused('invalid mtree encoding') from None
    defaults, seen = {}, set()
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        settings = {}
        for field in parts[1:]:
            require('=' in field, 'invalid mtree attribute')
            key, value = field.split('=', 1)
            require(key in {'type', 'uid', 'gid', 'mode', 'time', 'size', 'sha256digest'} and
                    key not in settings, 'unknown or duplicate mtree attribute')
            settings[key] = value
        if parts[0] == '/set':
            defaults.update(settings)
            continue
        require(parts[0].startswith('./'), 'unsafe mtree path')
        name = parts[0][2:]
        _path(name)
        require(name in members and name != '.MTREE' and name not in seen, 'unexpected mtree member')
        seen.add(name)
        attributes = defaults | settings
        entry, content = members[name]
        require(attributes.get('type') == ('dir' if entry.isdir() else 'file') and
                attributes.get('uid') == '0' and attributes.get('gid') == '0' and
                attributes.get('mode') == format(entry.mode, 'o'), 'mtree attributes mismatch')
        if entry.isfile():
            require(attributes.get('size') == str(len(content)) and
                    attributes.get('sha256digest') == sha(content), 'mtree file binding mismatch')
    require(seen == set(members) - {'.MTREE'}, 'mtree member set mismatch')


def _package(data, filename, approved, inventory, epoch):
    suffix = filename.rsplit('.', 1)[-1]
    require(filename == f'{NAME}-{VERSION}-any.pkg.tar.{suffix}' and suffix in {'xz', 'gz'},
            'unsupported package filename or compression')
    raw = _uncompress(data, suffix)
    directories = {str(parent) for name in PAYLOAD for parent in PurePosixPath(name).parents
                   if str(parent) != '.'}
    allowed = set(PAYLOAD) | directories | {'.PKGINFO', '.BUILDINFO', '.MTREE'}
    members = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                name = member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
                _path(name)
                require(name in allowed and name not in members and len(members) < 32,
                        'unexpected or duplicate archive member')
                require(member.uid == member.gid == 0 and member.mtime == epoch and
                        not member.linkname and not member.pax_headers and member.sparse is None and
                        0 <= member.size <= MAX_FILE,
                        'archive member attributes refused')
                if name in directories:
                    require(member.isdir() and member.mode == 0o755 and member.size == 0,
                            'archive directory attributes refused')
                    content = b''
                else:
                    require(member.type in {tarfile.REGTYPE, tarfile.AREGTYPE} and
                            member.mode == PAYLOAD.get(name, ('', 0o644))[1],
                            'archive file type or mode refused')
                    with archive.extractfile(member) as source:
                        content = source.read(MAX_FILE + 1)
                    require(len(content) == member.size, 'archive file size mismatch')
                members[name] = (member, content)
            end = archive.offset
        require(not any(raw[end:]), 'nonzero trailing archive data')
    except (tarfile.TarError, OSError, EOFError):
        raise Refused('invalid package tar archive') from None
    require(set(PAYLOAD) | {'.PKGINFO', '.BUILDINFO', '.MTREE'} <= members.keys(),
            'required package members missing')
    for name, (source, _) in PAYLOAD.items():
        require(sha(members[name][1]) == approved[source], 'payload differs from approved source')
    pkg = metadata(members['.PKGINFO'][1])
    build = metadata(members['.BUILDINFO'][1])
    require(set(pkg) <= {'pkgname', 'pkgbase', 'xdata', 'pkgver', 'pkgdesc', 'url', 'builddate',
                         'packager', 'size', 'arch', 'license', 'depend'}, 'unapproved package relation or field')
    for key, value in {'pkgname': NAME, 'pkgbase': NAME, 'pkgver': VERSION, 'arch': 'any',
                       'license': 'GPL-2.0-or-later', 'depend': 'python>=3.11',
                       'xdata': 'pkgtype=pkg', 'builddate': str(epoch),
                       'pkgdesc': 'Read-only KSM status and page-size-aware counter reporting',
                       'url': 'https://github.com/Gabriel-Kahen/cachy-asahi',
                       'size': str(sum(len(members[n][1]) for n in PAYLOAD))}.items():
        _one(pkg, key, value)
    require(len(pkg.get('packager', [])) == 1, 'single package packager required')
    require(set(build) <= {'format', 'pkgname', 'pkgbase', 'pkgver', 'pkgarch', 'pkgbuild_sha256sum',
                           'packager', 'builddate', 'builddir', 'startdir', 'buildtool', 'buildtoolver',
                           'buildenv', 'options', 'installed'}, 'unapproved BUILDINFO field')
    for key, value in {'format': '2', 'pkgname': NAME, 'pkgbase': NAME, 'pkgver': VERSION,
                       'pkgarch': 'any', 'pkgbuild_sha256sum': approved['PKGBUILD'],
                       'builddate': str(epoch), 'builddir': '/tmp/work', 'startdir': '/tmp/work',
                       'buildtool': 'makepkg', 'buildtoolver': MAKEPKG_VERSION}.items():
        _one(build, key, value)
    require(build.get('packager') == pkg['packager'], 'package packager binding mismatch')
    installed = build.get('installed', [])
    expected = {name + '-' + version for name, version in inventory.items()}
    actual = []
    for row in installed:
        require(row.endswith(('-aarch64', '-any')), 'BUILDINFO installed architecture refused')
        actual.append(row.rsplit('-', 1)[0])
    require(len(actual) == 341 and len(set(actual)) == 341 and set(actual) == expected,
            'BUILDINFO inventory differs from accepted 341-package lock')
    _mtree(members['.MTREE'][1], members)
    return {'pkginfo_sha256': sha(members['.PKGINFO'][1]),
            'buildinfo_sha256': sha(members['.BUILDINFO'][1]),
            'payload': {name: {'sha256': sha(members[name][1]), 'mode': mode, 'uid': 0, 'gid': 0}
                        for name, (_, mode) in PAYLOAD.items()}}


def _build(root, approved, image, lock_bytes, inventory):
    provenance_bytes = read_file(root / 'provenance.json')
    record = json_object(provenance_bytes)
    for key, value in {'schema_version': 1, 'status': 'built-package-static-pass',
                       'hardware_status': 'NOT RUN', 'mode': 'native', 'network': 'none',
                       'image': image, 'image_id': image, 'expected_packages_sha256': sha(lock_bytes),
                       'entry_script_sha256': ENTRY_SHA256, 'exit_code': 0,
                       'recipe_inputs': approved}.items():
        require(record.get(key) == value and type(record.get(key)) is type(value),
                'native build provenance binding mismatch')
    require(isinstance(record.get('builder_host_arch'), str) and
            record['builder_host_arch'] in {'aarch64', 'arm64'}, 'native builder architecture required')
    environment = record.get('clean_environment_id')
    require(isinstance(environment, str) and re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', environment),
            'unique clean build environment identifier required')
    epoch = record.get('source_date_epoch')
    require(type(epoch) is int and 0 <= epoch <= 2**63 - 1, 'valid source epoch required')
    _command(record.get('command'), image, environment, epoch)
    artifacts, files = record.get('artifacts'), record.get('files')
    require(isinstance(artifacts, dict) and len(artifacts) == 1 and isinstance(files, dict) and
            REQUIRED <= files.keys() and len(files) <= 32, 'complete bounded build evidence required')
    filename, digest = next(iter(artifacts.items()))
    _path(filename)
    require('/' not in filename and isinstance(digest, str) and HASH.fullmatch(digest),
            'invalid artifact identity')
    require(files.get('artifacts/' + filename) == digest, 'artifact file pin missing')
    entries = _entries(root / 'artifacts', 32)
    inputs = _entries(root / 'inputs', 15)
    require(len(inputs) == 15, 'exact 15-input snapshot required')
    require({'artifacts/' + name for name in entries} ==
            {name for name in files if name.startswith('artifacts/')}, 'unrecorded artifact evidence')
    total, verified = 0, {}
    for name, checksum in files.items():
        _path(name)
        require(name in REQUIRED or name == 'artifacts/' + filename or
                (name.startswith('artifacts/') and '/' not in name[10:] and name.endswith('.log')),
                'unapproved evidence file')
        require(isinstance(checksum, str) and HASH.fullmatch(checksum), 'invalid evidence digest')
        value = read_file(root / name)
        total += len(value)
        require(total <= 16 * 1024 * 1024 and sha(value) == checksum, 'changed or oversized build evidence')
        verified[name] = value
    require(verified['expected-packages.lock'] == verified['artifacts/packages.lock'] == lock_bytes,
            'copied package lock mismatch')
    validation = json_object(verified['validation.json'])
    require(validation.get('errors') == [] and isinstance(validation.get('artifacts'), list) and
            len(validation['artifacts']) == 1 and isinstance(validation['artifacts'][0], dict) and
            validation['artifacts'][0].get('errors') == [],
            'static build validation did not pass')
    snapshots = set(inputs)
    require(snapshots == INPUTS, 'recipe snapshot file set differs from approved map')
    for name, checksum in approved.items():
        require(sha(read_file(root / 'inputs' / name)) == checksum, 'changed approved recipe snapshot')
    reviewed = metadata(read_file(root / 'inputs/.SRCINFO'))
    require(record.get('recipe_metadata') == reviewed and
            metadata(verified['artifacts/generated.SRCINFO']) == reviewed, 'generated recipe metadata mismatch')
    package = verified['artifacts/' + filename]
    result = _package(package, filename, approved, inventory, epoch)
    result.update({'filename': filename, 'sha256': digest, 'provenance_sha256': sha(provenance_bytes),
                   'clean_environment_id': environment, 'source_date_epoch': epoch})
    return result, package


def _command(command, image, environment, epoch):
    require(isinstance(command, list) and 20 <= len(command) <= 100 and
            all(isinstance(v, str) and len(v) <= 4096 and not any(ord(c) < 32 for c in v)
                for v in command), 'bounded builder command required')
    tokens = list(command)
    require(tokens.pop(0) == 'docker', 'Docker builder command required')
    if tokens[:1] == ['--host']:
        require(len(tokens) >= 3 and re.fullmatch(r'unix:///[^,\s]+', tokens[1]),
                'local daemon endpoint required')
        tokens = tokens[2:]
    require(tokens[:1] == ['run'] and tokens[-2:] == [image, '/builder-entry.sh'],
            'builder entrypoint or image mismatch')
    flags, options, index = set(), {}, 1
    singles = {'--rm', '--pull=never', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only'}
    values = {'--name', '--platform', '--user', '--pids-limit', '--memory', '--cpus', '--network',
              '--tmpfs', '--env', '--mount', '--entrypoint'}
    while index < len(tokens) - 2:
        token = tokens[index]
        if token in singles:
            require(token not in flags, 'duplicate builder isolation flag')
            flags.add(token)
            index += 1
        else:
            require(token in values and index + 1 < len(tokens) - 2, 'unapproved builder command option')
            options.setdefault(token, []).append(tokens[index + 1])
            index += 2
    require(flags == singles, 'builder isolation flags mismatch')
    for flag, value in {'--name': environment, '--platform': 'linux/arm64', '--pids-limit': '512',
                         '--memory': '4g', '--cpus': '4', '--network': 'none',
                         '--tmpfs': '/tmp:rw,nosuid,nodev,exec,size=4g', '--entrypoint': '/bin/bash'}.items():
        require(options.get(flag) == [value], 'builder isolation command mismatch')
    require(len(options.get('--user', [])) == 1 and
            re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*', options['--user'][0]), 'nonroot build user required')
    require(set(options.get('--env', [])) == {'CACHY_ASAHI_CONTAINER=1', f'SOURCE_DATE_EPOCH={epoch}'} and
            len(options['--env']) == 2, 'builder environment mismatch')
    mounts = options.get('--mount', [])
    require(len(mounts) == 4, 'finite builder mount set required')
    found = set()
    for mount in mounts:
        match = re.fullmatch(r'type=bind,src=([^,]+),dst=(/inputs|/out|/builder-entry.sh|/expected-packages.lock)(,readonly)?', mount)
        require(match is not None, 'unapproved builder mount')
        source, destination, readonly = match.groups()
        require(source.startswith('/') and '..' not in PurePosixPath(source).parts and destination not in found and
                bool(readonly) == (destination != '/out'), 'builder mount isolation mismatch')
        found.add(destination)
    require(found == {'/inputs', '/out', '/builder-entry.sh', '/expected-packages.lock'},
            'builder mount destinations mismatch')


def validate_build_pair(build1: Path, build2: Path, approved_map: Path,
                        image: str, lock_bytes: bytes):
    """Return (curated record, validated archive bytes), retaining no raw provenance.

    Reject unsupported compression explicitly. This checks supplied native-build
    records; the caller must bind them to its actual accepted native job receipt.
    """
    require(isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image),
            'immutable image ID required')
    roots = [Path(build1).absolute(), Path(build2).absolute()]
    try:
        identities = [root.stat(follow_symlinks=False) for root in roots]
    except OSError:
        raise Refused('missing build directory') from None
    require(all(stat.S_ISDIR(s.st_mode) for s in identities) and
            (identities[0].st_dev, identities[0].st_ino) != (identities[1].st_dev, identities[1].st_ino),
            'two distinct real build directories required')
    approved_bytes = read_file(approved_map, 16384)
    require(sha(approved_bytes) == APPROVED_MAP_SHA256, 'approved 15-input map hash mismatch')
    approved = json_object(approved_bytes)
    require(set(approved) == INPUTS and all(isinstance(v, str) and HASH.fullmatch(v)
                                          for v in approved.values()), 'invalid approved input map')
    inventory = _inventory(lock_bytes)
    require(inventory.get('pacman') == PACMAN_PACKAGE_VERSION, 'accepted buildtool package pin differs')
    left, a = _build(roots[0], approved, image, lock_bytes, inventory)
    right, b = _build(roots[1], approved, image, lock_bytes, inventory)
    require(left['clean_environment_id'] != right['clean_environment_id'], 'distinct clean build IDs required')
    for key in ('filename', 'sha256', 'source_date_epoch', 'pkginfo_sha256', 'buildinfo_sha256', 'payload'):
        require(left[key] == right[key], 'build pair package or metadata mismatch')
    require(a == b, 'build pair archive bytes differ')
    return ({'status': 'PASS-build-pair-contract', 'scope': 'DEVELOPMENT-TEST',
             'native_execution': 'controller-receipt-required', 'hardware_status': 'NOT RUN',
             'name': NAME, 'version': VERSION, 'arch': 'any', 'license': 'GPL-2.0-or-later',
             'depends': ['python>=3.11'], 'image_id': image, 'expected_packages_sha256': sha(lock_bytes),
             'approved_inputs_sha256': APPROVED_MAP_SHA256, 'filename': left['filename'],
             'sha256': left['sha256'], 'pkginfo_sha256': left['pkginfo_sha256'],
             'source_date_epoch': left['source_date_epoch'],
             'buildinfo_sha256': left['buildinfo_sha256'], 'payload': left['payload'],
             'provenance_sha256': [left['provenance_sha256'], right['provenance_sha256']],
             'clean_environment_ids': [left['clean_environment_id'], right['clean_environment_id']],
             'comparisons': {'bytes_equal': True, 'payload_equal': True,
                             'pkginfo_equal': True, 'buildinfo_equal': True}}, a)


def validate_archive(data: bytes, approved: dict, lock_bytes: bytes,
                     source_date_epoch: int, filename: str):
    """Independently recheck bytes before signing or installing; never extract.

    The caller supplies the accepted lock and the pair's authenticated epoch and
    filename. The dictionary is required to match the finite approved map pin.
    Return only the package identity, archive hash, metadata hashes and payload.
    """
    require(isinstance(data, bytes) and len(data) <= MAX_FILE, 'bounded package archive required')
    require(isinstance(approved, dict) and set(approved) == INPUTS and
            all(isinstance(v, str) and HASH.fullmatch(v) for v in approved.values()),
            'invalid approved input map')
    require(sha((json.dumps(approved, sort_keys=True, indent=2) + '\n').encode()) == APPROVED_MAP_SHA256,
            'approved 15-input map hash mismatch')
    require(type(source_date_epoch) is int and 0 <= source_date_epoch <= 2**63 - 1,
            'valid source epoch required')
    require(isinstance(filename, str), 'valid package filename required')
    inventory = _inventory(lock_bytes)
    require(inventory.get('pacman') == PACMAN_PACKAGE_VERSION, 'accepted buildtool package pin differs')
    result = _package(data, filename, approved, inventory, source_date_epoch)
    return {'name': NAME, 'version': VERSION, 'arch': 'any', 'license': 'GPL-2.0-or-later',
            'depends': ['python>=3.11'], 'filename': filename, 'sha256': sha(data), **result}
