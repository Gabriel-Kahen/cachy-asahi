#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Passive candidate-to-native profile projection; no authority or provisioning."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import posixpath
import stat
import struct
import sys
import time

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2]
spec = importlib.util.spec_from_file_location('bankstown_qt3_admission_v1', HERE / 'admission.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)
BASE = 'scripts/port/arm-rust-toolchain-inputs/'
RUST = 'packages/port/bankstown-source-candidate/native-rust-inputs.json'
RUST_PIN = {'bytes': 25105, 'sha256': '65c0857c6278d82cc30afaff91a424dd753ba4435b6ac60ea377b3a0d6c9c1bc'}
LOCK_PIN = {'bytes': 88821, 'sha256': 'b9053079a1c2f6dab8cee3b782d8ebbedae5865c6f9fad74de85357fec2d07a7'}
PARENT_PIN = {'bytes': 3972, 'sha256': 'ae78fac40449df9da2d055a39ef8431339813f3fbba9c9569c8bcd23a09b87ed'}
RECIPE_PINS = {
    'PKGBUILD': {'bytes': 4991, 'sha256': 'ce2a5cc3292e1de7f930c4c249c1839f3c4040e75aa1b37cdfc5d3b3b38e9659'},
    '.SRCINFO': {'bytes': 1388, 'sha256': '9db5e128ca662252cea5980bac45455b0504485997276badaeeebdea7420a908'},
    'build_guard.py': {'bytes': 8777, 'sha256': '778c22cb52a4ffe4103a0e7a2c907def00bd9cd2411d0fdbca339a4cc010e21a'},
}


def identity(s):
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
                 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def ordinary(path):
    path = Path(path)
    A.need(path.is_absolute() and '..' not in path.parts
           and not any(p.is_symlink() for p in (path, *path.parents)), 'UNALIASED_ABSOLUTE_PATH_REQUIRED')
    return path


def held(path, expected, *, cap=256 * 1024**2, deadline=None):
    A.descriptor(expected, cap, empty=True)
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        A.need(stat.S_ISREG(before.st_mode) and before.st_size == expected['bytes'], 'REGULAR_PINNED_FILE_REQUIRED')
        body = bytearray()
        h = hashlib.sha256()
        while True:
            A.need(deadline is None or time.monotonic() < deadline, 'PROFILE_READ_DEADLINE')
            part = os.read(fd, min(1024**2, expected['bytes'] + 1 - len(body)))
            if not part:
                break
            body.extend(part)
            A.need(len(body) <= expected['bytes'], 'PINNED_FILE_GREW')
            h.update(part)
        A.need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'PINNED_FILE_CHANGED')
        A.need(len(body) == expected['bytes'] and h.hexdigest() == expected['sha256'], 'FILE_PIN_DIFFERS')
        return bytes(body)
    finally:
        os.close(fd)


def _source(d, deadline):
    for path, expected in d['materials'].items():
        held(SOURCE / path, expected, cap=64 * 1024**2, deadline=deadline)
    for name, expected in RECIPE_PINS.items():
        A.need(d['materials'][A.RECIPE + '/' + name] == expected, 'ORIGINAL_RECIPE_CONSUMER_REQUIRED')
        held(SOURCE / A.RECIPE / name, expected, deadline=deadline)
    # These are historical production pins, independent of the proposed trial.
    lock_raw = held(SOURCE / (BASE + 'qtbase-successor/candidate.lock.json'), LOCK_PIN, deadline=deadline)
    parent = A.decoded(held(SOURCE / (BASE + 'qtbase-successor/parent-binding.json'), PARENT_PIN, deadline=deadline))
    for path, expected in parent['files'].items():
        A.need(type(path) is str and not path.startswith('/') and '..' not in path.split('/'), 'PARENT_MATERIAL_PATH')
        A.need(d['materials'].get(BASE + path) == expected, 'CLOSED_PARENT_MATERIAL_REQUIRED')
        held(SOURCE / BASE / path, expected, deadline=deadline)
    rust_raw = held(SOURCE / RUST, RUST_PIN, deadline=deadline)
    A.need(held(SOURCE / (BASE + 'rust-137-files.json'), RUST_PIN, deadline=deadline) == rust_raw,
           'INDEPENDENT_RUST_ASSOCIATION_DIFFERS')
    rust = A.decoded(rust_raw)
    A.need(len(rust['files']) == 137, 'RUST137_REQUIRED')
    return A.decoded(lock_raw), A.decoded(held(SOURCE / (BASE + 'inputs.lock.json'),
           parent['files']['inputs.lock.json'], deadline=deadline)), rust


def _catalog(raw, d, lock, baseline, rust):
    A.need(A.pin(raw) == d['catalog'], 'ROOT_CATALOG_PIN_DIFFERS')
    c = A.decoded(raw, 64 * 1024**2)
    A.need('schema' not in c and c.get('purpose') == 'bankstown-optional-qtbase6.12.0-3-input-candidate'
           and c.get('candidate') == 'EXPLICIT_OPTIONAL_QT_BASE_6.12.0-3'
           and c.get('complete') is True and c.get('original_minus2_hold') == 'UNCHANGED'
           and c.get('protected_input_count') == 275 and c.get('native_tools_profile') == 'NOT_PRODUCED'
           and c.get('source_legal_freshness_acceptance') == 'HELD'
           and c.get('payload_execution') == 'NOT_RUN', 'EXACT_CANDIDATE_REPORT_REQUIRED')
    A.need(c.get('candidate_lock') == LOCK_PIN and c.get('parent_binding') == PARENT_PIN,
           'CANDIDATE_CODE_BINDING_DIFFERS')
    for field, path in (('version_parser', 'elf_versions.py'), ('source_facts', 'source-facts.json')):
        expected = d['materials'].get(BASE + 'qtbase-successor/' + path)
        A.need(expected is not None and c.get(field) == expected, 'CANDIDATE_HELPER_BINDING_DIFFERS')
    for key in ('missing_inputs', 'unresolved_package_dependencies', 'unresolved_elf_dependencies', 'unresolved_GNU_versions'):
        A.need(c.get(key) == [], 'CANDIDATE_CLOSURE_REQUIRED')
    selected = {n: row for n, row in baseline['packages'].items() if n != 'qt6-base'} | lock['new_packages']
    A.need(len(selected) == 333 and set(c['packages']) == set(selected)
           and selected['qt6-base']['version'] == '6.12.0-3'
           and selected['rust']['version'] == '1:1.99.0-1', 'EXACT333_SELECTION_REQUIRED')
    inventory_path = next(path for path, expected in d['materials'].items() if expected == d['image']['inventory'])
    inventory_raw = held(SOURCE / inventory_path, d['image']['inventory'], cap=2 * 1024**2)
    text = inventory_raw.decode('utf-8', errors='strict')
    lines = text.split('\n')
    A.need(lines[-1] == '' and lines[:-1] == sorted(set(lines[:-1])) and len(lines) <= 4097,
           'EXACT_SORTED_IMAGE_INVENTORY_REQUIRED')
    inventory = {}
    for line in lines[:-1]:
        words = line.split(' ')
        A.need(len(words) == 2 and all(words) and words[0] not in inventory
               and all(ord(c) > 32 and ord(c) != 127 for c in line if c != ' '), 'IMAGE_INVENTORY_ROW')
        inventory[words[0]] = words[1]
    A.need(all(inventory.get(name) == row['version'] for name, row in selected.items())
           and {'make', 'pacman', 'fakeroot', 'rust', 'gcc', 'binutils', 'python', 'lv2'} <= set(inventory),
           'COMPLETE_NATIVE_BUILDER_INVENTORY_REQUIRED')
    entries = {}
    for name, package in c['packages'].items():
        expected = selected[name]
        info = package['metadata']['/.PKGINFO']
        A.need(info.get('pkgname') == [name] and all(info.get(k) == [expected[v]] for k, v in
               (('pkgver', 'version'), ('arch', 'arch'))), 'CATALOG_PACKAGE_IDENTITY')
        A.need(all(sorted(info.get(key, [])) == sorted(expected[field]) for key, field in
                   (('depend', 'depends'), ('provides', 'provides'))), 'CATALOG_DECLARED_PROVIDERS_DIFFER')
        signature = package['signature']
        A.need(signature.get('status') == 'VALID_SIGNATURE_MATHEMATICS'
               and signature.get('signer') == lock['signer_primary']
               and signature.get('key_freshness') == 'NOT_ESTABLISHED'
               and signature.get('source_acceptance') == 'NOT_ESTABLISHED', 'CATALOG_SIGNATURE_OBSERVATION_REQUIRED')
        for path, row in package['entries'].items():
            A.logical(path)
            if path.startswith('/.'):
                continue
            if path in entries:
                A.need(row['type'] == entries[path]['type'] == 'directory', 'CATALOG_NAMESPACE_COLLISION')
            else:
                entries[path] = row
    actual = {p: {k: row[k] for k in ('bytes', 'sha256')}
              for p, row in c['packages']['rust']['entries'].items()
              if not p.startswith('/.') and row['type'] == 'file'}
    A.need(actual == rust['files'], 'FULL_RUST137_CATALOG_BINDING')
    for path, row in rust['files'].items():
        if path in ('/usr/bin/cargo', '/usr/bin/rustc') or path.startswith('/usr/lib/'):
            A.need(d['selected_files'].get(path) == row, 'REQUIRED_RETAINED_RUST_FILES')
    return c, entries


def _target(path, target):
    A.need(type(target) is str and target and '\x00' not in target and '\\' not in target,
           'LITERAL_LINK_TARGET_REQUIRED')
    joined = target if target.startswith('/') else posixpath.dirname(path) + '/' + target
    parts = []
    for p in joined.split('/'):
        if p == '..':
            A.need(parts, 'LINK_ESCAPES_LOGICAL_ROOT')
            parts.pop()
        elif p not in ('', '.'):
            parts.append(p)
    result = '/' + '/'.join(parts)
    A.logical(result)
    return result


def resolve(path, entries, root):
    A.logical(path)
    seen = set()
    for _ in range(64):
        A.need(path not in seen, 'LOGICAL_LINK_CYCLE')
        seen.add(path)
        parts = path[1:].split('/')
        for i in range(1, len(parts) + 1):
            prefix = '/' + '/'.join(parts[:i])
            physical = root / prefix[1:]
            s = physical.lstat()
            row = entries.get(prefix)
            if stat.S_ISLNK(s.st_mode):
                A.need(row is not None and row['type'] == 'symlink'
                       and os.readlink(physical) == row['target'], 'MATERIALIZED_LINK_DIFFERS')
                target = _target(prefix, row['target'])
                A.need(row['resolved'] == target, 'CATALOG_LINK_RESOLUTION_DIFFERS')
                path = target + ('/' + '/'.join(parts[i:]) if parts[i:] else '')
                break
            A.need(row is None or row['type'] != 'symlink', 'MISSING_MATERIALIZED_LINK')
            if i < len(parts):
                A.need(stat.S_ISDIR(s.st_mode), 'MATERIALIZED_ANCESTOR_NOT_DIRECTORY')
            else:
                A.need(stat.S_ISREG(s.st_mode) and row is not None and row['type'] in ('file', 'hardlink'),
                       'CANONICAL_CATALOG_REGULAR_FILE_REQUIRED')
                return path
        else:
            raise ValueError('LOGICAL_RESOLUTION_REQUIRED')
    raise ValueError('LOGICAL_LINK_DEPTH')


def data_row(path, entries, root):
    original, seen = path, set()
    for _ in range(64):
        A.need(path not in seen, 'CATALOG_HARDLINK_CYCLE')
        seen.add(path)
        row = entries[path]
        if row['type'] == 'file':
            if original != path:
                a, b = (root / original[1:]).stat(), (root / path[1:]).stat()
                A.need((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'MATERIALIZED_HARDLINK_DIFFERS')
            return row
        A.need(row['type'] == 'hardlink', 'CATALOG_REGULAR_DATA_REQUIRED')
        target = _target('/', row['target'])
        A.need(target == row['resolved'] and resolve(target, entries, root) == target,
               'CATALOG_HARDLINK_TARGET_DIFFERS')
        path = target
    raise ValueError('CATALOG_HARDLINK_DEPTH')


def elf(raw):
    if not raw.startswith(b'\x7fELF'):
        return None
    A.need(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01', 'AARCH64_ELF64_REQUIRED')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    A.need(h[2] == 183 and h[1] in (1, 2, 3) and h[10] < 4096
           and (not h[10] or h[9] == 56) and h[5] + h[9] * h[10] <= len(raw), 'AARCH64_ELF_TABLE_BOUND')
    loads, dynamic, interp = [], None, None
    for i in range(h[10]):
        typ, flags, off, va, pa, size, mem, align = struct.unpack_from('<IIQQQQQQ', raw, h[5] + i * 56)
        A.need(off + size <= len(raw), 'ELF_SEGMENT_BOUND')
        if typ == 1:
            loads.append((off, va, size))
        elif typ == 2:
            A.need(dynamic is None, 'MULTIPLE_DYNAMIC_SEGMENTS')
            dynamic = (off, size)
        elif typ == 3:
            body = raw[off:off + size]
            A.need(interp is None and body.endswith(b'\0') and b'\0' not in body[:-1], 'ELF_INTERPRETER')
            interp = body[:-1].decode('ascii')
    result = dict(machine=183, interpreter=interp, needed=[], soname=None, rpath=[], runpath=[],
                  rpath_present=False, runpath_present=False)
    if dynamic:
        off, size = dynamic
        A.need(size % 16 == 0, 'ELF_DYNAMIC_BOUND')
        tags = []
        for at in range(off, off + size, 16):
            tag, value = struct.unpack_from('<qQ', raw, at)
            if tag == 0:
                break
            tags.append((tag, value))
        else:
            raise ValueError('UNTERMINATED_DYNAMIC')
        for single in (5, 10, 14, 15, 29):
            A.need(sum(t == single for t, _ in tags) <= 1, 'ELF_DYNAMIC_SINGLETON')
        if any(t in (1, 14, 15, 29) for t, _ in tags):
            address, length = dict(tags).get(5), dict(tags).get(10)
            A.need(address is not None and length is not None and length > 0, 'ELF_STRING_TABLE_REQUIRED')
            offsets = [o + address - v for o, v, s in loads if v <= address and address + length <= v + s]
            A.need(len(offsets) == 1, 'ELF_STRING_MAPPING_REQUIRED')
            text = raw[offsets[0]:offsets[0] + length]
            for tag, value in tags:
                if tag not in (1, 14, 15, 29):
                    continue
                A.need(value < len(text) and b'\0' in text[value:], 'ELF_STRING_BOUND')
                word = text[value:text.index(b'\0', value)].decode('utf-8')
                if tag == 1:
                    result['needed'].append(word)
                elif tag == 14:
                    result['soname'] = word
                else:
                    key = 'rpath' if tag == 15 else 'runpath'
                    result[key], result[key + '_present'] = word.split(':'), True
    return result


def _project(d, c, entries, root, admission_pin, deadline):
    files, parsed = {}, {}
    for path, expected in sorted(d['selected_files'].items()):
        A.need(resolve(path, entries, root) == path, 'SELECTED_PATH_NOT_CANONICAL')
        row = data_row(path, entries, root)
        A.need({k: row[k] for k in ('bytes', 'sha256')} == expected, 'SELECTED_FILE_NOT_CATALOG_BOUND')
        raw = held(root / path[1:], expected, deadline=deadline)
        A.need(stat.S_IMODE((root / path[1:]).stat().st_mode) == row['mode'], 'CATALOG_FILE_MODE_DIFFERS')
        observed = elf(raw)
        A.need(observed == row.get('elf'), 'ACTUAL_ELF_CATALOG_DIFFERS')
        if observed is not None:
            parsed[path] = observed
        files[path] = expected
    for path in d['tool_paths'].values():
        canonical = resolve(path, entries, root)
        A.need(canonical in parsed and struct.unpack_from('<H', held(root / canonical[1:], files[canonical], deadline=deadline), 16)[0] in (2, 3)
               and (root / canonical[1:]).stat().st_mode & 0o111, 'DIRECT_EXECUTABLE_NATIVE_TOOL_REQUIRED')
    for path in d['closure']['non_elf_support']:
        A.need(path in files and path not in parsed, 'NON_ELF_SUPPORT_DECLARATION_DIFFERS')
    joins = c['elf_dependency_joins']
    for path, obj in parsed.items():
        consumer = path
        while entries[consumer]['type'] == 'hardlink':
            consumer = entries[consumer]['resolved']
        for needed in obj['needed'] + ([obj['interpreter']] if obj['interpreter'] else []):
            matches = [j for j in joins if j.get('consumer') == consumer and j.get('needed') == needed]
            A.need(len(matches) == 1 and type(matches[0].get('provider')) is str, 'EXACT_CATALOG_ELF_JOIN_REQUIRED')
            provider = resolve(matches[0]['provider'], entries, root)
            A.need(provider in parsed, 'SELECTED_ELF_PROVIDER_REQUIRED')
            if '/' not in needed:
                A.need(parsed[provider]['soname'] == needed, 'MATCHING_PROVIDER_SONAME_REQUIRED')
    return dict(schema=1, purpose='bankstown-1.1.0-5-native-toolchain', compiler_version='1.99.0',
                target='aarch64-unknown-linux-gnu', tools=d['tool_paths'], files=files,
                admission_pin=admission_pin, catalog_pin=d['catalog'], image=d['image'],
                legal='HELD', key_freshness='HELD', **A.FINAL)


def _prepare(admission_raw, admission_sha256, catalog_path, root):
    d = A.validate_trial(admission_raw, admission_sha256, now=time.time())
    deadline = time.monotonic() + min(d['resources']['command_seconds'], 300)
    root = ordinary(root)
    A.need(root.is_dir(), 'MATERIALIZED_ROOT_REQUIRED')
    lock, baseline, rust = _source(d, deadline)
    raw = held(catalog_path, d['catalog'], cap=64 * 1024**2, deadline=deadline)
    c, entries = _catalog(raw, d, lock, baseline, rust)
    return _project(d, c, entries, root, A.pin(admission_raw), deadline)


def export_profile(*, admission_raw, admission_sha256, catalog_path, root, output):
    output = ordinary(output)
    A.need(not output.exists(), 'FRESH_PROFILE_OUTPUT_REQUIRED')
    expected = _prepare(admission_raw, admission_sha256, catalog_path, root)
    raw = A.encoded(expected)
    A.need(len(raw) <= 2 * 1024**2, 'PROFILE_OUTPUT_BOUND')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    held(output, A.pin(raw), cap=2 * 1024**2)
    return expected


def verify_profile(*, admission_raw, admission_sha256, catalog_path, root, profile_path, profile_sha256):
    A.need(Path(root) == Path('/'), 'RUNTIME_ACTUAL_ROOT_REQUIRED')
    expected = _prepare(admission_raw, admission_sha256, catalog_path, root)
    raw = A.encoded(expected)
    A.descriptor({'bytes': len(raw), 'sha256': profile_sha256})
    A.need(A.pin(raw)['sha256'] == profile_sha256, 'ROOT_SELECTED_PROFILE_PIN_DIFFERS')
    actual = held(profile_path, A.pin(raw), cap=2 * 1024**2)
    A.need(actual == raw, 'PROFILE_PROJECTION_DIFFERS')
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['verify'])
    for name in ('admission', 'admission-sha256', 'catalog', 'root', 'profile', 'profile-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        A.need(sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_NO_BYTECODE_REQUIRED')
        path = ordinary(args.admission)
        A.need(path.stat().st_size <= 2 * 1024**2, 'ADMISSION_BYTE_BOUND')
        raw = held(path, {'bytes': path.stat().st_size, 'sha256': args.admission_sha256}, cap=2 * 1024**2)
        verify_profile(admission_raw=raw, admission_sha256=args.admission_sha256,
                       catalog_path=Path(args.catalog), root=Path(args.root),
                       profile_path=Path(args.profile), profile_sha256=args.profile_sha256)
    except (OSError, ValueError, KeyError, TypeError, struct.error):
        print('Bankstown native profile refused', file=sys.stderr)
        return 2
    print('BANKSTOWN_NATIVE_PROFILE=PASS_DATA_ONLY')
    return 0


if __name__ == '__main__':
    sys.exit(main())
