# SPDX-License-Identifier: MIT
"""Assemble pinned package DATA into a deterministic regular-only rootfs tar.

Never installs, extracts to the host, executes input code, or downloads inputs.
The closed manifest describes DATA; it does not qualify a kernel or runtime.
"""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).absolute().parent))
from elf64le_aarch64 import audit_closure, canonical, need, MAX_ROWS, MAX_TOTAL

LOCK = dict(commit='50d50603305c5a64ee090313b05f68e11ca64bce',
            path='native/expected349.lock', bytes=6800,
            sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453')
REQUIRED = {'bubblewrap': '0.13.0-1', 'python': '3.14.8-1', 'mkinitcpio-busybox': '1.36.1-1'}
ROOTS = {'busybox': ('mkinitcpio-busybox', 'usr/lib/initcpio/busybox'),
         'usr/bin/bwrap': ('bubblewrap', 'usr/bin/bwrap'),
         'usr/bin/python3': ('python', 'usr/bin/python3.14')}
STDLIB = 'usr/lib/python3.14/'
HEADLESS = 'finite-headless-namespace-v1'
MAX_INPUT = 128*1024**2
MAX_EXPANDED = 512*1024**2


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def relative(name):
    need(type(name) is str and name and not name.startswith('/') and '\\' not in name
         and not re.search(r'[\x00-\x20\x7f]', name)
         and all(p not in ('', '.', '..') for p in name.split('/')), 'noncanonical input path')
    return name


def read_regular(path, cap):
    """Read one bounded, stable ordinary input, refusing ancestor symlinks."""
    path = Path(os.path.abspath(path))
    for parent in reversed((path, *path.parents[:-1])):
        need(not parent.is_symlink(), 'input symlink component')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap,
             'bounded unaliased regular input required')
        raw = stream.read(cap+1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(len(raw) <= cap and len(raw) == before.st_size and identity(before) == identity(after)
         and identity(os.stat(path, follow_symlinks=False)) == identity(after), 'input changed during read')
    return raw


def pinned(base, pin, cap=MAX_INPUT):
    need(type(pin) is dict and set(pin) == {'path', 'bytes', 'sha256'}, 'exact input pin fields')
    relative(pin['path'])
    need(type(pin['bytes']) is int and 0 < pin['bytes'] <= cap
         and type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256']), 'input byte/hash pin')
    raw = read_regular(Path(base)/pin['path'], cap)
    need(len(raw) == pin['bytes'] and digest(raw) == pin['sha256'], 'input pin mismatch: '+pin['path'])
    return raw


class OrdinaryTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        need(self.type not in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                              tarfile.GNUTYPE_LONGLINK), 'extended package metadata unsupported')
        return super()._proc_member(archive)


class Package:
    def __init__(self, raw):
        self.stream = io.BytesIO(raw)
        self.tar = tarfile.open(fileobj=self.stream, mode='r:xz', tarinfo=OrdinaryTarInfo)
        self.members, expanded = {}, 0
        for member in self.tar:
            name = relative(member.name.rstrip('/') if member.isdir() else member.name)
            need(name not in self.members, 'duplicate package member')
            need(len(self.members) < 50000, 'package member cap')
            need(member.isdir() or member.isfile() or member.issym() or member.islnk(), 'special package member')
            need(0 <= member.size <= MAX_INPUT, 'package file byte cap')
            expanded += member.size
            need(expanded <= MAX_EXPANDED, 'package expanded byte cap')
            self.members[name] = member
        self.expanded = expanded

    def close(self):
        self.tar.close()
        self.stream.close()

    def resolve(self, name):
        relative(name)
        seen = set()
        while True:
            need(name not in seen and len(seen) < 40 and name in self.members, 'missing/cyclic package alias')
            seen.add(name)
            member = self.members[name]
            if member.isfile():
                need(member.mode & 0o7000 == 0, 'privileged package file')
                with self.tar.extractfile(member) as stream:
                    raw = stream.read(MAX_INPUT+1)
                need(len(raw) == member.size and len(raw) <= MAX_INPUT, 'package member byte count')
                return raw, 0o755 if member.mode & 0o111 else 0o644, name
            need(member.issym() or member.islnk(), 'package alias is not a regular file')
            target = member.linkname
            need(type(target) is str and '\\' not in target and not re.search(r'[\x00-\x20\x7f]', target), 'invalid package link')
            name = posixpath.normpath(target.lstrip('/') if target.startswith('/') or member.islnk()
                                     else posixpath.join(posixpath.dirname(name), target))
            relative(name)


def metadata_fields(raw):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        if line and not line.startswith('#'):
            key, separator, value = line.partition(' = ')
            need(separator, 'malformed package metadata')
            result.setdefault(key, []).append(value)
    return result


def gui_path(path):
    return (path == STDLIB+'lib-dynload/_tkinter.cpython-314-aarch64-linux-gnu.so'
            or path.startswith(tuple(STDLIB+p+'/' for p in ('tkinter', 'turtledemo', 'idlelib')))
            or path == STDLIB+'turtle.py'
            or bool(re.fullmatch(re.escape(STDLIB)+r'__pycache__/turtle\.cpython-314(?:\.opt-[12])?\.pyc', path))
            or path in ('usr/bin/idle', 'usr/bin/idle3', 'usr/bin/idle3.14'))


def headless_profile(profile, base, packages, files):
    """One explicit finite headless profile, never a generic missing-library waiver."""
    need(type(profile) is dict and set(profile) == {'name', 'excluded', 'probe_sources', 'required_modules'}
         and profile['name'] == HEADLESS and type(profile['excluded']) is list
         and 0 < len(profile['excluded']) <= MAX_ROWS, 'exact finite headless profile')
    excluded = {}
    for row in profile['excluded']:
        need(type(row) is dict and set(row) == {'path', 'package', 'member', 'bytes', 'sha256', 'mode', 'reason'}, 'exact exclusion provenance')
        path = canonical(row['path'])
        need(gui_path(path) and row['package'] == 'python' and row['member'] == path
             and path not in excluded and path not in files and type(row['reason']) is str
             and 0 < len(row['reason']) <= 512, 'only declared unused Tk/GUI paths may be excluded')
        raw, mode, _ = packages['python'].resolve(path)
        need(type(row['bytes']) is int and type(row['mode']) is int
             and (row['bytes'], row['sha256'], row['mode']) == (len(raw), digest(raw), mode), 'exclusion pin mismatch')
        excluded[path] = row
    need(type(profile['probe_sources']) is list and 1 <= len(profile['probe_sources']) <= 16,
         'finite pinned probe sources required')
    modules, sources = set(), {}
    for pin in profile['probe_sources']:
        raw = pinned(base, pin, 1024**2)
        name = Path(pin['path']).stem
        need(name.isidentifier() and name not in sources, 'unique named probe sources')
        sources[name] = pin
        for node in ast.walk(ast.parse(raw)):
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                need(node.level == 0 and node.module, 'relative probe imports unsupported')
                modules.add(node.module)
    need(type(profile['required_modules']) is list and profile['required_modules'] == sorted(modules), 'exact probe AST import inventory')
    resolved = {}
    for module in sorted(modules | {'encodings', 'encodings.utf_8', 'codecs', 'io', 'abc', 'site', '_sitebuiltins'}):
        if module in sources:
            resolved[module] = dict(kind='PINNED_PROBE_SOURCE', **sources[module])
        elif module in ('sys', 'time'):
            resolved[module] = dict(kind='CPYTHON_CORE_BUILTIN', runtime_import='NOT_RUN')
        else:
            relative_module = module.replace('.', '/')
            candidate = next((STDLIB+p for p in (relative_module+'.py', relative_module+'/__init__.py') if STDLIB+p in files), None)
            need(candidate is not None and not gui_path(candidate), 'probe/bootstrap module absent: '+module)
            resolved[module] = dict(kind='SELECTED_STDLIB_SOURCE', path=candidate,
                                    sha256=digest(files[candidate]['raw']))
    return excluded, dict(profile=profile, imports=resolved, method='STATIC_AST_AND_SELECTED_FILE_PINS', runtime_import='NOT_RUN')


def assemble_files(plan, base, lock_raw):
    keys = {'schema', 'actual', 'lock', 'packages', 'files'}
    need(type(plan) is dict and set(plan) in (keys, keys | {'python_profile'})
         and type(plan['schema']) is int and plan['schema'] == 1 and plan['actual'] is None
         and plan['lock'] == LOCK, 'exact DATA plan and null actual selector required')
    need(len(lock_raw) == LOCK['bytes'] and digest(lock_raw) == LOCK['sha256'], 'frozen349 lock pin')
    lock_rows = [line.split() for line in lock_raw.decode('ascii').splitlines()]
    need(len(lock_rows) == 349 and all(len(r) == 2 for r in lock_rows), 'exact349 lock rows')
    lock = unique(lock_rows)
    need(type(plan['packages']) is list and 3 <= len(plan['packages']) <= 349, 'bounded package set')
    need(type(plan['files']) is list and 0 < len(plan['files']) <= MAX_ROWS, 'bounded output rows')
    packages, reports, files, custody = {}, {}, {}, {}
    compressed, expanded = 0, 0
    try:
        for row in plan['packages']:
            need(type(row) is dict and set(row) == {'name', 'version', 'arch', 'archive', 'signature',
                 'license', 'upstream_sources', 'metadata', 'pkgbuild_sha256', 'retained_provenance'}, 'exact package fields')
            name = row['name']
            need(type(name) is str and name not in packages and lock.get(name) == row['version']
                 and row['arch'] in ('aarch64', 'any'), 'duplicate or non349 package/version/arch')
            need(type(row['license']) is list and row['license'] and all(type(s) is str and s for s in row['license'])
                 and type(row['upstream_sources']) is list and row['upstream_sources']
                 and all(type(s) is str and s.startswith('https://') for s in row['upstream_sources'])
                 and type(row['retained_provenance']) is dict, 'license/source/provenance required')
            body = pinned(base, row['archive'])
            compressed += len(body)
            need(compressed <= MAX_TOTAL, 'aggregate compressed input cap')
            archive = Package(body)
            packages[name] = archive
            expanded += archive.expanded
            need(expanded <= MAX_EXPANDED, 'aggregate expanded input cap')
            pinned(base, row['signature'], 1024**2)  # custody only; no fresh signature authentication
            need(set(row['metadata']) == {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'required original package metadata')
            metadata = {}
            for key, pin in row['metadata'].items():
                raw, _, _ = archive.resolve(key)
                need(pin == dict(bytes=len(raw), sha256=digest(raw)), 'package metadata hash pin')
                metadata[key] = raw
            info = metadata_fields(metadata['.PKGINFO'])
            need(info.get('pkgname') == [name] and info.get('pkgver') == [row['version']]
                 and info.get('arch') == [row['arch']] and info.get('license') == row['license']
                 and info.get('url') == row['upstream_sources'], 'PKGINFO identity/source mismatch')
            build = metadata_fields(metadata['.BUILDINFO'])
            need(build.get('pkgbuild_sha256sum') == [row['pkgbuild_sha256']]
                 and build.get('pkgname') == [name] and build.get('pkgver') == [row['version']]
                 and build.get('pkgarch') == [row['arch']]
                 and re.fullmatch('[0-9a-f]{64}', row['pkgbuild_sha256']), 'BUILDINFO recipe pin')
            provenance = row['retained_provenance']
            need(all(provenance.get(key) == row[key] for key in ('name', 'version', 'license')), 'retained provenance identity mismatch')
            for kind in ('archive', 'signature'):
                retained = provenance.get(kind, {})
                need(all(retained.get(key) == row[kind][key] for key in ('bytes', 'sha256'))
                     and retained.get('path') == str(Path(os.path.abspath(Path(base)/row[kind]['path']))), 'retained provenance input mismatch')
            for key, pin in row['metadata'].items():
                retained = provenance.get('metadata_members', {}).get(key, {})
                need(all(retained.get(field) == pin[field] for field in ('bytes', 'sha256')), 'retained provenance metadata mismatch')
            need(provenance.get('recipe_identity_from_BUILDINFO', {}).get('pkgbuild_sha256sum') == row['pkgbuild_sha256'], 'retained provenance recipe mismatch')
            reports[name] = row
        need(all(name in packages and reports[name]['version'] == version for name, version in REQUIRED.items()), 'required package versions')
        total = 0
        for row in plan['files']:
            need(type(row) is dict and set(row) == {'path', 'package', 'member', 'bytes', 'sha256', 'mode'}, 'exact file recipe')
            path = canonical(row['path'])
            need(path not in files and row['package'] in packages, 'duplicate path or unknown package')
            raw, mode, member = packages[row['package']].resolve(row['member'])
            need(type(row['bytes']) is int and type(row['mode']) is int
                 and (row['bytes'], row['sha256'], row['mode']) == (len(raw), digest(raw), mode), 'file recipe byte/hash/mode mismatch')
            files[path] = dict(raw=raw, mode=mode)
            custody[path] = dict(package=row['package'], member=member, requested_member=row['member'])
            total += len(raw)
            need(total <= MAX_TOTAL, 'rootfs aggregate payload cap')
        for path, (package, member) in ROOTS.items():
            need(path in files and files[path]['mode'] == 0o755 and custody[path]['package'] == package
                 and custody[path]['member'] == member, 'required entrypoint provenance/mode')
        excluded, scope = ({}, dict(profile='FULL_PACKAGED_STDLIB')) if 'python_profile' not in plan else headless_profile(plan['python_profile'], base, packages, files)
        # Only the exact declared Tk/GUI exclusions may narrow packaged stdlib.
        for name, archive in packages.items():
            for member, entry in archive.members.items():
                if (name == 'python' and member.startswith(STDLIB) or member.startswith('usr/share/licenses/')) and not entry.isdir():
                    if name == 'python' and member in excluded:
                        continue
                    need(not (name == 'python' and 'python_profile' in plan and gui_path(member)), 'headless GUI exclusion inventory incomplete')
                    raw, mode, _ = archive.resolve(member)
                    need(member in files and files[member] == dict(raw=raw, mode=mode), 'missing full stdlib or package license: '+member)
        return files, dict(packages=reports, file_custody=custody, python_scope=scope)
    finally:
        for archive in packages.values():
            archive.close()


def archive_bytes(files):
    need(type(files) is dict and 0 < len(files) <= MAX_ROWS, 'archive row cap')
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for path, row in sorted(files.items()):
            canonical(path)
            need(type(row) is dict and set(row) == {'raw', 'mode'} and type(row['raw']) is bytes
                 and len(row['raw']) <= MAX_INPUT and type(row['mode']) is int
                 and row['mode'] in (0o644, 0o755), 'output bytes/mode')
            need(not any('/'.join(path.split('/')[:i]) in files for i in range(1, len(path.split('/')))), 'output file/directory collision')
            info = tarfile.TarInfo(path)
            info.mode, info.size = row['mode'], len(row['raw'])
            archive.addfile(info, io.BytesIO(row['raw']))
            need(output.tell() <= MAX_TOTAL, 'archive byte cap')
    raw = output.getvalue()
    need(len(raw) <= MAX_TOTAL, 'archive byte cap')
    return raw


def manifest(files):
    return dict(schema=1, status='CLOSED_GENERIC16K_NAMESPACE_ROOTFS_DATA', files={
        path: dict(bytes=len(row['raw']), sha256=digest(row['raw']), mode=row['mode'])
        for path, row in sorted(files.items())})


def verify_archive(raw, description):
    need(type(description) is dict and set(description) == {'schema', 'status', 'files'}
         and description['schema'] == 1 and type(description['schema']) is int
         and description['status'] == 'CLOSED_GENERIC16K_NAMESPACE_ROOTFS_DATA', 'manifest contract')
    need(type(raw) is bytes and len(raw) <= MAX_TOTAL, 'archive cap')
    need(type(description['files']) is dict and 0 < len(description['files']) <= MAX_ROWS, 'manifest row cap')
    for path, row in description['files'].items():
        canonical(path)
        need(type(row) is dict and set(row) == {'bytes', 'sha256', 'mode'}
             and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_INPUT
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
             and type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'manifest file fields')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            canonical(member.name)
            need(len(files) < MAX_ROWS and member.name not in files and member.isfile()
                 and member.type == tarfile.REGTYPE and not member.pax_headers
                 and member.uid == member.gid == member.mtime == 0 and member.uname == member.gname == ''
                 and member.mode in (0o644, 0o755) and not member.linkname
                 and 0 <= member.size <= MAX_INPUT, 'noncanonical output member')
            with archive.extractfile(member) as stream:
                payload = stream.read(MAX_INPUT+1)
            need(len(payload) == member.size, 'truncated output file')
            files[member.name] = dict(raw=payload, mode=member.mode)
    need(manifest(files) == description and archive_bytes(files) == raw, 'manifest/tar or canonical-byte mismatch')
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--input-root', type=Path, required=True)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = read_regular(args.plan, 8*1024**2)
    need(digest(raw) == args.plan_sha256, 'plan SHA256 mismatch')
    plan = json.loads(raw, object_pairs_hook=unique)
    files, report = assemble_files(plan, args.input_root, read_regular(args.lock, 8192))
    audit = audit_closure(files, roots=list(ROOTS))
    tar = archive_bytes(files)
    description = manifest(files)
    verify_archive(tar, description)
    # No output exists before all DATA checks pass. A fresh directory prevents replacement.
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    report.update(schema=1, status='ASSEMBLED_STATIC_DATA_ONLY', actual=None,
                  plan_sha256=digest(raw), lock=LOCK, elf_audit=audit,
                  tar=dict(bytes=len(tar), sha256=digest(tar)),
                  runtime='NOT_RUN', hardware='NOT_RUN', signature_authentication='NOT_RUN')
    for name, data in [('guest-rootfs.tar', tar), ('guest-rootfs.json', json_bytes(description)),
                       ('assembly-report.json', json_bytes(report))]:
        with open(args.output/name, 'xb') as stream:
            stream.write(data)
    print(json.dumps(dict(status=report['status'], files=len(files), tar=report['tar'], actual=None), sort_keys=True))


if __name__ == '__main__':
    main()
