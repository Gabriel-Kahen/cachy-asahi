#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite md4c postconditions after the unchanged strict native comparator."""
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile

HERE = Path(__file__).resolve().parent
PACKAGE = 'md4c-0.5.3-1-aarch64.pkg.tar.xz'
MARKERS = (b'652 passed, 0 failed, 0 errored, 0 skipped',
           b'65 passed, 0 failed, 0 errored, 0 skipped',
           b'md4c 0.5.3 staged CLI, C API, pkg-config, CMake and SONAME smoke PASS')
LICENSE = dict(path='usr/share/licenses/md4c/LICENSE.md', bytes=1096,
               sha256='d30937367d5413e7eaa218b1640b8946ff76fd34d97152f6979fd96169d5d0fc')
ELFS = {
    'usr/lib/libmd4c.so.0.5.3': ('libmd4c.so.0', {'libc.so.6'}),
    'usr/lib/libmd4c-html.so.0.5.3': ('libmd4c-html.so.0', {'libmd4c.so.0', 'libc.so.6'}),
    'usr/bin/md2html': (None, {'libmd4c-html.so.0', 'libmd4c.so.0', 'libc.so.6'}),
}
LINKS = {f'usr/lib/lib{name}.so{suffix}': f'lib{name}.so{target}'
         for name in ('md4c', 'md4c-html') for suffix, target in (('', '.0'), ('.0', '.0.5.3'))}
FILES = {'.PKGINFO', '.BUILDINFO', '.MTREE', LICENSE['path'], *ELFS,
         'usr/include/md4c.h', 'usr/include/md4c-html.h',
         'usr/lib/pkgconfig/md4c.pc', 'usr/lib/pkgconfig/md4c-html.pc',
         'usr/lib/cmake/md4c/md4cConfig.cmake',
         'usr/lib/cmake/md4c/md4cConfig-release.cmake'}
MANPAGES = {'usr/share/man/man1/md2html.1', 'usr/share/man/man1/md2html.1.gz'}


def need(value, why):
    if not value: raise ValueError(why)


def pin(raw): return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path, cap=4 * 1024**2):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap,
         'ordinary bounded pair DATA')
    raw = path.read_bytes(); after = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(before) == identity(after) and len(raw) == before.st_size, 'stable pair DATA')
    return raw


def elf(raw, name):
    soname, required = ELFS[name]
    need(64 <= len(raw) <= 4 * 1024**2 and raw[:7] == b'\x7fELF\x02\x01\x01',
         'bounded little-endian ELF64')
    kind, machine = struct.unpack_from('<HH', raw, 16)
    need(machine == 183 and kind in ((3,) if soname else (2, 3)), 'native AArch64 ELF type')
    offset = struct.unpack_from('<Q', raw, 32)[0]
    size, count = struct.unpack_from('<HH', raw, 54)
    need(size == 56 and 0 < count < 64 and offset + size * count <= len(raw), 'finite complete program headers')
    loads = []; dynamic = []; interpreters = []
    for index in range(count):
        tag, flags, position, vaddr, paddr, filesize, memsize, alignment = struct.unpack_from('<IIQQQQQQ', raw, offset + size * index)
        need(position + filesize <= len(raw) and filesize <= memsize, 'complete bounded segment')
        if tag == 1:
            need(alignment >= 4096 and alignment & (alignment - 1) == 0 and position % alignment == vaddr % alignment,
                 'structural native4K PT_LOAD geometry')
            loads.append(dict(offset=position, vaddr=vaddr, filesize=filesize, alignment=alignment))
        if tag == 2: dynamic.append((position, filesize))
        if tag == 3: interpreters.append(raw[position:position + filesize])
    need(loads and len(dynamic) == 1, 'load and single dynamic table')
    need(not interpreters if soname else len(interpreters) == 1 and interpreters[0] in
         (b'/lib/ld-linux-aarch64.so.1\0', b'/usr/lib/ld-linux-aarch64.so.1\0'), 'expected native loader role')
    position, extent = dynamic[0]
    need(extent % 16 == 0 and extent <= 65536, 'bounded dynamic table')
    values = {}; terminated = False
    for index in range(position, position + extent, 16):
        tag, value = struct.unpack_from('<qQ', raw, index)
        if tag == 0: terminated = True; break
        values.setdefault(tag, []).append(value)
    need(terminated and len(values.get(5, [])) == len(values.get(10, [])) == 1 and
         len(values.get(14, [])) == (1 if soname else 0), 'unique string table and expected SONAME role')
    address = values[5][0]; length = values[10][0]
    matches = [r for r in loads if r['vaddr'] <= address and address + length <= r['vaddr'] + r['filesize']]
    need(len(matches) == 1 and 0 < length <= 65536, 'bounded file-backed string table')
    start = matches[0]['offset'] + address - matches[0]['vaddr']; strings = raw[start:start + length]
    def string(index):
        need(index < len(strings), 'dynamic string offset'); end = strings.find(b'\0', index)
        need(end >= index, 'terminated dynamic string'); return strings[index:end].decode('ascii')
    actual_soname = string(values[14][0]) if soname else None
    needed = [string(v) for v in values.get(1, [])]
    need(actual_soname == soname and len(needed) == len(required) and set(needed) == required,
         'exact md4c SONAME and DT_NEEDED closure')
    need(not values.get(15) and not values.get(29), 'no package RPATH/RUNPATH')
    return dict(machine=183, soname=actual_soname, needed=sorted(needed), PT_LOAD=loads,
                structural16K=all(r['alignment'] >= 16384 and r['offset'] % 16384 == r['vaddr'] % 16384 for r in loads),
                native16K='NOT RUN', M2='NOT RUN')


def pkginfo(raw):
    info = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'): continue
        key, sep, value = line.partition(' = ')
        need(sep and key and value, 'well-formed package metadata')
        info.setdefault(key, []).append(value)
    need(all(info.get(k) == v for k, v in dict(pkgname=['md4c'], pkgver=['0.5.3-1'],
         arch=['aarch64'], depend=['glibc']).items()), 'exact md4c provider PKGINFO/dependencies')
    need(not any(info.get(k) for k in ('install', 'replaces', 'conflict', 'provides')),
         'no new install/provider relations')
    return info


def archive_members(path):
    need(path.name == PACKAGE, 'fixed md4c XZ-only archive basename')
    raw = read(path); need(raw.startswith(b'\xfd7zXZ\x00'), 'actual XZ compression only')
    found = {}; names = set(); links = {}; total = 0
    directories = {str(p) for name in FILES | set(LINKS) | MANPAGES for p in PurePosixPath(name).parents}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r|xz') as archive:
        for member in archive:
            name = str(PurePosixPath(member.name.removeprefix('./')))
            need(not name.startswith('/') and '..' not in PurePosixPath(name).parts and name not in names and len(names) < 512,
                 'safe unique bounded native package namespace')
            names.add(name)
            need(member.mode & 0o7000 == 0 and (member.isdir() or member.isfile() or member.issym()),
                 'ordinary non-privileged md4c package types only')
            need(0 <= member.size <= 4 * 1024**2, 'bounded package member')
            total += member.size; need(total <= 8 * 1024**2, 'bounded complete XZ package')
            if member.isdir(): need(name in directories, 'package directory outside fixed md4c payload'); continue
            if member.issym():
                need(name in LINKS and member.linkname == LINKS[name], 'exact md4c symlink chain')
                links[name] = member.linkname; continue
            need(name in FILES | MANPAGES, 'package file outside fixed md4c payload')
            with archive.extractfile(member) as stream: body = stream.read(member.size + 1)
            need(len(body) == member.size, 'whole XZ member'); found[name] = body
    need(set(links) == set(LINKS) and set(found) - MANPAGES == FILES and len(set(found) & MANPAGES) == 1,
         'complete fixed md4c package closure')
    return raw, found


def finish(first, second, comparison, image):
    need(re.fullmatch('sha256:[0-9a-f]{64}', image) and first.resolve() != second.resolve(),
         'immutable image and distinct builds')
    reviewed = json.loads(read(HERE / 'reviewed-inputs.json'))
    recipe = json.loads(read(HERE / 'recipe-pin.json')); need(recipe['license'] == LICENSE, 'fixed original MIT license pin')
    lock = pin(read(HERE / 'expected349.lock'))['sha256']; records = []; observations = []
    result = json.loads(read(comparison))
    need(result['status'] == 'contents-reproduced' and not result['errors'] and len(result['packages']) == 1,
         'successful unchanged strict comparator')
    name, values = next(iter(result['packages'].items()))
    need(name == PACKAGE and all(values[k] is True for k in ('installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal')),
         'exact archive/payload/PKGINFO/BUILDINFO pair equality')
    for root in (first, second):
        record = json.loads(read(root / 'provenance.json'))
        need(record['status'] == 'built-package-static-pass' and record['exit_code'] == 0 and record['mode'] == 'native' and
             record['image_id'] == image and record['recipe_inputs'] == reviewed and record['expected_packages_sha256'] == lock,
             'actual successful exact native build')
        need(record['builder_host_arch'] in ('arm64', 'aarch64'), 'actual native Docker architecture')
        need(b'aarch64' in read(root / 'artifacts/environment.txt'), 'retained native uname identity')
        logs = [p for p in (root / 'artifacts').iterdir() if p.name == 'md4c-0.5.3-1-aarch64-check.log']
        need(len(logs) == 1, 'one current makepkg check log'); log = read(logs[0])
        need(all(log.count(marker) == 1 for marker in MARKERS), 'all717 upstream cases and staged smoke required')
        validation = json.loads(read(root / 'validation.json'))
        need(not validation['errors'] and len(validation['artifacts']) == 1, 'one validated actual archive')
        report = validation['artifacts'][0]; need(report['artifact'] == name and not report['errors'], 'matching md4c archive report')
        need(set(report['elf']) == set(ELFS) and all(not g['errors'] for g in report['elf'].values()),
             'both native libraries and CLI pass inherited ELF geometry gate')
        raw, bodies = archive_members(root / 'artifacts' / name)
        need(pin(raw)['sha256'] == record['artifacts'][name] == report['sha256'], 'whole archive custody after comparator')
        need(pin(bodies[LICENSE['path']]) == {k: LICENSE[k] for k in ('bytes', 'sha256')}, 'exact upstream MIT payload')
        pkginfo(bodies['.PKGINFO']); observed = {}
        for member, body in bodies.items():
            need(pin(body)['sha256'] == report['members'][member]['sha256'], 'whole actual archive member digest: ' + member)
            observed[member] = pin(body)
            if member == '.MTREE':
                need(len(body) >= 18 and int.from_bytes(body[-4:], 'little') <= 1024**2, 'finite gzip MTREE')
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream: tree = stream.read(1024**2 + 1)
                need(len(tree) <= 1024**2 and tree.startswith(b'#mtree'), 'actual complete MTREE')
            if member in ELFS: observed[member]['ELF'] = elf(body, member)
        observations.append(observed); records.append(record)
    need(records[0]['clean_environment_id'] and records[0]['clean_environment_id'] != records[1]['clean_environment_id'],
         'two separate clean native builds')
    need(observations[0] == observations[1], 'exact payload/license/ELF and metadata pair equality')
    return dict(status='MD4C053_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED', builds=2, image_id=image,
                archive=name, observations=observations, comparison=result, signature='NOT RUN; Root offline follow-up',
                installation='NOT RUN', native16K='NOT RUN', M2='NOT RUN', performance='NOT MEASURED',
                official_binary_recovery='HOLD', release='NOT ADMITTED', Root_acceptance=None)
