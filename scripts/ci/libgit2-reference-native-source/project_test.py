#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure bounded PROJECT TEST llhttp DATA inspection; no cryptographic actors.

Root receipt JSON is not authentication. Runtime admission additionally requires
the independently admitted tuple hash AND Root receipt byte hash. No actual
package, key, signature or acceptance is supplied by this module.
"""
import hashlib
import io
import importlib.util
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

KEYS = ('package', 'signature', 'public_key', 'native_receipt', 'signing_receipt', 'root_receipt')
KIND = 'PROJECT_TEST_LLHTTP_DEPENDENCY'
DEFAULT_EXPECTED = {
    'package': 'cachy-asahi-llhttp-reference', 'version': '9.3.1-1', 'arch': 'aarch64',
    'filename': 'cachy-asahi-llhttp-reference-9.3.1-1-aarch64.pkg.tar.xz',
    'source': {
        'recipe_commit': '7e4d4ce45b19e45b6241af6f4fd787e67a1cdf18',
        'recipe_path': 'packages/libraries/cachy-asahi-llhttp-reference',
        'recipe_origin': 'ORIGINAL_PROJECT_RECIPE_NOT_ALARM_BINARY_CORRESPONDENCE',
        'upstream_commit': '4fce8cac9433aa4728428bb3b26880d32ad05c88',
        'upstream_archive': {'bytes': 39211, 'sha256': 'ac1d762ad696e05cc6f8be52465632a2700af662b4682b2e6d13228d92fd5c09'},
    },
    'license': {'path': 'usr/share/licenses/cachy-asahi-llhttp-reference/LICENSE-MIT',
                'bytes': 1105, 'sha256': 'ebca854e0134cd256d673627c20499f42577eb74bacf08b9f25b626a73c91277'},
}


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def tuple_binding(actual, expected):
    value = {'schema': 1, 'kind': KIND, 'source': expected['source'], 'license': expected['license'],
             'fingerprint': expected['fingerprint'], 'operands': {k: actual[k] for k in KEYS[:-1]}}
    if 'signing_fingerprint' in expected:
        value['signing_fingerprint'] = expected['signing_fingerprint']
    return value


def read(path, cap=1024**2):
    """Read stable, singly linked, owned ordinary DATA, without symlink traversal."""
    path = Path(path).absolute()
    need(path == path.resolve(), 'PROJECT TEST operands cannot traverse symlinks')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid in (0, os.getuid())
         and not before.st_mode & 0o022 and 0 < before.st_size <= cap, 'bounded owned ordinary PROJECT TEST DATA')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    after = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(before) == identity(after) and len(raw) == before.st_size, 'stable complete PROJECT TEST DATA')
    return raw


def load(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate receipt JSON key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict, 'receipt must be a JSON object')
    return value


def package_data(raw, expected):
    need(raw.startswith(b'\xfd7zXZ\x00'), 'PROJECT TEST package must be actual XZ')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64*1024**2)
    expanded = decoder.decompress(raw, max_length=16*1024**2 + 1)
    need(len(expanded) <= 16*1024**2 and decoder.eof and not decoder.unused_data,
         'single complete bounded XZ stream; no trailing operands')
    names = set(); selected = {}; total = 0
    wanted = {'.PKGINFO', expected['license']['path']}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            path = PurePosixPath(name)
            need(name and str(path) == name and not path.is_absolute() and '..' not in path.parts
                 and name not in names and len(names) < 512, 'safe unique bounded PROJECT TEST package namespace')
            names.add(name)
            need(member.isfile() or member.isdir() or member.issym(), 'ordinary PROJECT TEST package member type')
            need(not member.mode & 0o6000 and 0 <= member.size <= 4*1024**2, 'bounded package member without privileged mode')
            total += member.size
            need(total <= 8*1024**2, 'bounded PROJECT TEST payload')
            need(name not in ('.INSTALL', '.CHANGELOG') and not name.startswith(('etc/', 'usr/share/libalpm/')),
                 'dependency cannot install hooks or system configuration')
            if member.issym():
                target = PurePosixPath(member.linkname)
                need(member.linkname and not target.is_absolute() and '..' not in target.parts, 'bounded relative dependency symlink')
            if name in wanted:
                need(member.isfile(), 'PROJECT TEST metadata/license must be regular')
                with archive.extractfile(member) as stream:
                    selected[name] = stream.read(member.size + 1)
                need(len(selected[name]) == member.size, 'complete PROJECT TEST metadata/license')
        need(len(expanded) % 512 == 0 and not any(expanded[archive.offset:]), 'complete tar namespace with zero-only end padding')
    need(set(selected) == wanted, 'complete PROJECT TEST PKGINFO/license')
    fields = {}
    need(len(selected['.PKGINFO']) <= 65536, 'bounded PKGINFO')
    for line in selected['.PKGINFO'].decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition(' = ')
        need(separator and re.fullmatch('[a-z][a-z0-9_]*', key) and value, 'ordinary PKGINFO field')
        fields.setdefault(key, []).append(value)
    for key, value in (('pkgname', expected['package']), ('pkgver', expected['version']), ('arch', 'aarch64')):
        need(fields.get(key) == [value], 'exact project llhttp ' + key)
    need(fields.get('license') == ['MIT'] and fields.get('depend') == ['glibc'], 'exact llhttp license/dependency closure')
    provides = fields.get('provides', [])
    need('llhttp=9.3.1' in provides and len(provides) == 2
         and any(re.fullmatch(r'libllhttp\.so(?:=9\.3-64)?', p) for p in provides), 'exact llhttp provider closure')
    need(fields.get('conflict') == ['llhttp'] and not fields.get('replaces') and not fields.get('backup'), 'project provider conflict without replacements')
    need(pin(selected[expected['license']['path']]) == {k: expected['license'][k] for k in ('bytes', 'sha256')}, 'exact source-bound MIT license')
    return {'pkginfo': fields, 'license': pin(selected[expected['license']['path']]), 'members': sorted(names)}


def validate_tuple(paths, expected=None, authorization=None):
    """Inspect six pinned DATA operands. Only an external Root binding admits them.

    ``expected`` extends DEFAULT_EXPECTED with ``fingerprint`` and all six
    ``pins``. Missing actual pins/fingerprint fail closed. This does not invoke
    GPG, pacman, Docker, signing, key generation or any host mutation.
    """
    expected = DEFAULT_EXPECTED if expected is None else expected
    need(type(paths) is dict and set(paths) == set(KEYS), 'explicit complete PROJECT TEST operand tuple')
    for key, value in DEFAULT_EXPECTED.items():
        need(expected.get(key) == value, 'fixed original llhttp source/license/package identity: ' + key)
    fingerprint = expected.get('fingerprint')
    need(type(fingerprint) is str and re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', fingerprint), 'bound public PROJECT TEST fingerprint required')
    pins = expected.get('pins')
    need(type(pins) is dict and set(pins) == set(KEYS), 'all six actual PROJECT TEST pins required')
    raw = {k: read(paths[k], 4*1024**2 if k == 'package' else 256*1024) for k in KEYS}
    actual = {k: pin(v) for k, v in raw.items()}
    need(actual == pins, 'exact PROJECT TEST tuple operand pins')
    need(Path(paths['package']).name == expected['filename']
         and Path(paths['signature']).name == expected['filename'] + '.sig', 'exact project XZ package/detached signature basenames')
    key = raw['public_key'].strip()
    # Legacy DATA controls retain armor inspection. Executable admission below
    # requires the consumer's immutable binary-v4 public packet predicates.
    need((key.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n')
          and key.endswith(b'-----END PGP PUBLIC KEY BLOCK-----')
          and b'PRIVATE KEY' not in key and b'SECRET KEY' not in key)
         or (key and key[0] & 128 and not key.startswith(b'-----')), 'bounded public PROJECT TEST key DATA')
    need(16 <= len(raw['signature']) <= 16384, 'bounded detached PROJECT TEST signature DATA')
    package = package_data(raw['package'], expected)
    native, signing, root = (load(raw[k]) for k in ('native_receipt', 'signing_receipt', 'root_receipt'))
    need(native.get('status') == 'LLHTTP_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED'
         and type(native.get('builds')) is int and native['builds'] == 2 and native.get('archive') == expected['filename']
         and native.get('package') == actual['package'] and native.get('source') == expected['source']
         and native.get('license') == expected['license'], 'exact source/license-bound native llhttp pair receipt')
    need(signing.get('status') == 'PROJECT_TEST_DETACHED_SIGNATURE_CREATED' and signing.get('test_only') is True
         and signing.get('fingerprint') == fingerprint
         and all(signing.get(k) == actual[k] for k in ('package', 'signature', 'public_key', 'native_receipt')),
         'exact native package/public TEST key/signing receipt binding')
    binding = tuple_binding(actual, expected)
    digest = pin(canonical(binding))['sha256']
    need(root.get('accepted') is True and root.get('issued_by') == 'Root' and root.get('scope') == KIND
         and root.get('tuple_sha256') == digest, 'Root receipt must bind this exact PROJECT TEST tuple')
    admitted = authorization is not None
    if admitted:
        need(type(authorization) is dict and authorization.get('project_test_tuple_sha256') == digest
             and authorization.get('project_test_root_receipt_sha256') == actual['root_receipt']['sha256'],
             'independent Root admission must bind exact tuple and Root receipt bytes')
    return {'schema': 1, 'kind': KIND, 'admitted': admitted, 'tuple_sha256': digest, 'binding': binding,
            'pins': actual, 'fingerprint': fingerprint, 'package': package, 'crypto': 'NOT RUN',
            'expected': expected, 'Root_authorization': authorization}


def validate_compatible_tuple(paths, expected, authorization=None, *, consumer_root):
    """Production dependency admission uses the unchanged consumer predicates.

    This remains DATA: no signature math, native credit or Rust admission.
    Missing actual external bindings cannot create an executable context.
    """
    need(consumer_root is not None, 'explicit immutable consumer interface root required')
    value = validate_tuple(paths, expected, authorization)
    need(type(expected.get('signing_fingerprint')) is str
         and re.fullmatch('[A-F0-9]{40}', expected['signing_fingerprint']), 'explicit shared v4 signing fingerprint')
    signing = load(read(paths['signing_receipt'], 256*1024))
    need(signing.get('signing_fingerprint') == expected['signing_fingerprint'], 'same explicit TEST signing fingerprint receipt')
    spec = importlib.util.spec_from_file_location('libgit2_consumer_bridge', Path(__file__).with_name('consumer_bridge.py'))
    B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
    value['consumer'] = B.validate(paths, expected, Path(consumer_root), load(read(paths['native_receipt'], 256*1024)), value['package']['pkginfo'])
    value['consumer_root'] = str(Path(consumer_root))
    return value
