#!/usr/bin/env python3
"""Read-only recipe/package inspection. Never source a PKGBUILD or extract a tar."""
import argparse
import hashlib
import json
import re
import shlex
import struct
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

FIELDS = {'pkgbase', 'pkgname', 'pkgver', 'pkgrel', 'epoch', 'arch', 'license',
          'depends', 'makedepends', 'checkdepends', 'optdepends', 'provides',
          'conflicts', 'replaces', 'source', 'sha256sums', 'backup', 'install'}
PROTECTED = ('boot/', 'usr/lib/modules/', 'usr/lib/firmware/',
             'usr/share/alsa/', 'etc/pacman.d/', 'etc/mkinitcpio',
             'usr/lib/initcpio/', 'usr/lib/udev/', 'etc/udev/',
             'usr/share/pipewire/', 'usr/share/wireplumber/', 'etc/pipewire/',
             'etc/wireplumber/', 'etc/modprobe.d/', 'etc/modules-load.d/',
             'etc/sysctl.d/', 'usr/bin/speakersafetyd', 'usr/bin/asahi-audio',
             'usr/lib/systemd/system/speakersafetyd',
             'usr/lib/systemd/system/asahi-audio',
             'usr/lib/systemd/user/asahi-audio')
PROTECTED_PACKAGES = {'linux-asahi', 'm1n1', 'u-boot', 'asahi-fwextract', 'mesa',
                      'asahi-audio', 'speakersafetyd', 'alsa-ucm-conf-asahi'}
ARCH_FIELDS = {'depends', 'makedepends', 'checkdepends', 'optdepends', 'provides',
               'conflicts', 'replaces', 'source', 'sha256sums'}
FIELDS |= {key + '_aarch64' for key in ARCH_FIELDS}
PACKAGE_METADATA = {'.PKGINFO', '.BUILDINFO', '.MTREE', '.INSTALL', '.Changelog'}
MAX_MEMBER = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def metadata(text):
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*', line)
        if not match:
            raise ValueError(f'invalid metadata line: {line[:100]}')
        key, value = match.groups()
        result.setdefault(key, []).append(value)
    return result


def literal_metadata(text):
    """Conservative fallback: constant assignments only; no shell evaluation."""
    result = {}
    # Ignore indented function bodies. Complex top-level shell remains human review.
    assignment = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', re.M)
    for match in assignment.finditer(text):
        key, value = match.groups()
        if key not in FIELDS:
            continue
        if value.startswith('('):
            end = text.find(')', match.start(2) + 1)
            if end < 0:
                raise ValueError(f'unterminated {key}')
            value = text[match.start(2) + 1:end]
        # Shell expansions anywhere, even quotes, are outside the static subset.
        if any(token in value for token in ('$', '`', ';', '\\', '<', '>')):
            raise ValueError(f'dynamic {key}; provide reviewed .SRCINFO')
        result[key] = shlex.split(value, comments=True)
    return result


def effective_values(data, key):
    return list(data.get(key, [])) + (data.get(key + '_aarch64', []) if key in ARCH_FIELDS else [])


def platform_relations(data, artifact=False):
    keys = ('provides', 'conflict', 'replaces') if artifact else ('provides', 'conflicts', 'replaces',
             'provides_aarch64', 'conflicts_aarch64', 'replaces_aarch64')
    errors = []
    for name in data.get('pkgname', []):
        if name in PROTECTED_PACKAGES:
            errors.append(f'protected platform package name: {name}')
    for key in keys:
        for value in data.get(key, []):
            name = re.split(r'[<>=]', value, maxsplit=1)[0]
            if name in PROTECTED_PACKAGES:
                errors.append(f'protected platform package relation: {key} {value}')
    return errors


def discover(root):
    return sorted(p for category in ('desktop', 'shells', 'settings')
                  for p in (Path(root) / 'packages' / category).rglob('PKGBUILD'))


def recipe(path):
    path = Path(path).absolute()
    base = path.parent
    errors, review = [], []
    srcinfo = base / '.SRCINFO'
    hashes = {}
    for item in sorted(base.rglob('*')):
        if item.is_symlink():
            errors.append(f'symlink recipe input forbidden: {item.relative_to(base)}')
        elif item.is_file():
            hashes[str(item.relative_to(base))] = digest(item)
        elif not item.is_dir():
            errors.append(f'special recipe input forbidden: {item.relative_to(base)}')
    if errors:
        return {'recipe': str(path), 'metadata': {}, 'input_sha256': hashes,
                'errors': errors, 'review': [], 'status': 'fail'}
    data = metadata(srcinfo.read_text()) if srcinfo.is_file() else literal_metadata(path.read_text())
    for field in ('pkgname', 'pkgver', 'pkgrel', 'arch', 'license', 'source'):
        if not data.get(field) and not (field == 'source' and data.get('source_aarch64')):
            errors.append(f'missing {field}')
    for field in ('pkgname', 'pkgbase', 'pkgver', 'pkgrel', 'epoch'):
        if len(data.get(field, [])) > 1:
            errors.append(f'duplicate/split {field} unsupported; single-package recipes only')
    if len(data.get('arch', [])) != 1:
        errors.append('exactly one architecture declaration required')
    if data.get('arch') and not set(data['arch']) <= {'any', 'aarch64'}:
        errors.append('recipe architecture must be any or aarch64 only')
    for suffix in ('', '_aarch64'):
        if len(data.get('source' + suffix, [])) != len(data.get('sha256sums' + suffix, [])):
            errors.append(f'source/SHA-256 count mismatch in {suffix or "generic"} group')
    sources = data.get('source', []) + data.get('source_aarch64', [])
    sums = data.get('sha256sums', []) + data.get('sha256sums_aarch64', [])
    if len(sources) != len(sums):
        errors.append('source/SHA-256 count mismatch')
    for source, checksum in zip(sources, sums):
        source = source.split('::', 1)[-1]
        git = source.startswith('git+')
        if git:
            if not re.search(r'#commit=[0-9a-f]{40}$', source):
                errors.append(f'unpinned Git source: {source}')
            if checksum != 'SKIP':
                errors.append('Git SHA-256 must be SKIP; commit is recorded separately')
            review.append('Git commit pin is not archive verification; retain source snapshot and Git provenance')
        elif not re.fullmatch(r'[0-9a-f]{64}', checksum):
            errors.append(f'missing fixed SHA-256 for {source}')
        elif '://' in source:
            if not source.startswith('https://'):
                errors.append(f'non-HTTPS source: {source}')
        else:
            local = (base / source).resolve()
            if not local.is_relative_to(base) or not local.is_file():
                errors.append(f'unsafe/missing local source: {source}')
            elif digest(local) != checksum:
                errors.append(f'local source checksum mismatch: {source}')
    if data.get('install'):
        review.append('installation script requires independent review')
        for hook in data['install']:
            if hook not in hashes:
                errors.append(f'missing installation script: {hook}')
    errors.extend(platform_relations(data))
    if data.get('replaces'):
        review.append('replaces metadata requires conflict review')
    review.append('PKGBUILD body and metadata consistency require independent review; static checks are not a shell sandbox')
    return {'recipe': str(path), 'metadata': data, 'input_sha256': hashes,
            'errors': errors, 'review': review, 'status': 'fail' if errors else 'static-pass'}


def clean_name(name):
    if name.startswith('/') or '\\' in name:
        raise ValueError(f'unsafe archive path: {name}')
    parts = PurePosixPath(name).parts
    if '..' in parts:
        raise ValueError(f'unsafe archive path: {name}')
    name = str(PurePosixPath(name))
    return name.removeprefix('./').rstrip('/')


def elf_check(data):
    """Inspect ELF PT_LOAD; structural 16K check, never a hardware PASS."""
    if not data.startswith(b'\x7fELF'):
        return None
    if len(data) < 64 or data[4] != 2 or data[5] != 1:
        return {'errors': ['only little-endian ELF64 supported']}
    kind = struct.unpack_from('<H', data, 16)[0]
    header_size = struct.unpack_from('<H', data, 52)[0]
    machine = struct.unpack_from('<H', data, 18)[0]
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    errors = []
    if machine != 183:
        errors.append(f'ELF machine {machine}, expected AArch64 (183)')
    if header_size != 64:
        errors.append('invalid ELF64 header size')
    if kind == 1:
        return {'machine': machine, 'errors': errors, 'page_alignment': 'not-applicable-relocatable',
                'hardware_status': 'NOT RUN'}
    if kind not in (2, 3):
        errors.append(f'unsupported ELF type {kind}')
    if not count:
        errors.append('ELF executable/shared object has no program headers')
    if size < 56 or offset + size * count > len(data):
        errors.append('truncated/invalid ELF program headers')
        return {'errors': errors}
    loads = 0
    for index in range(count):
        entry = offset + index * size
        kind = struct.unpack_from('<I', data, entry)[0]
        if kind != 1:
            continue
        loads += 1
        file_offset, vaddr = struct.unpack_from('<QQ', data, entry + 8)
        filesize, memsize = struct.unpack_from('<QQ', data, entry + 32)
        if filesize > memsize or file_offset + filesize > len(data):
            errors.append('invalid PT_LOAD file/memory size')
        alignment = struct.unpack_from('<Q', data, entry + 48)[0]
        if alignment < 16384 or alignment & (alignment - 1) or file_offset % 16384 != vaddr % 16384:
            errors.append('PT_LOAD fails structural 16K alignment check')
    if not loads:
        errors.append('ELF executable/shared object has no PT_LOAD segments')
    return {'machine': machine, 'load_segments': loads, 'errors': errors,
            'hardware_status': 'NOT RUN'}


def package(path):
    path = Path(path)
    process = None
    raw = path.open('rb')
    if path.name.endswith('.zst'):
        process = subprocess.Popen(['zstd', '-dc', '--', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stream = process.stdout
    else:
        stream = raw
    members, info, errors, review, elf = {}, {}, [], [], {}
    total = 0
    try:
        with tarfile.open(fileobj=stream, mode='r|*') as archive:
            for member in archive:
                name = clean_name(member.name)
                if name == '.':
                    continue
                if name in members:
                    raise ValueError(f'duplicate archive member: {name}')
                if member.size > MAX_MEMBER or member.size < 0:
                    raise ValueError(f'oversized archive member: {name}')
                total += member.size
                if total > MAX_TOTAL:
                    raise ValueError('archive exceeds uncompressed size limit')
                if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise ValueError(f'special archive member forbidden: {name}')
                if member.mode & 0o6000:
                    errors.append(f'setuid/setgid path forbidden: {name}')
                if member.uid != 0 or member.gid != 0:
                    errors.append(f'non-root package ownership: {name}')
                content = archive.extractfile(member).read() if member.isfile() else b''
                if member.issym() or member.islnk():
                    if member.islnk():
                        clean_name(member.linkname)
                    elif member.linkname.startswith('/'):
                        review.append(f'absolute symlink requires target review: {name} -> {member.linkname}')
                    else:
                        depth = len(PurePosixPath(name).parts) - 1
                        for part in PurePosixPath(member.linkname).parts:
                            depth += -1 if part == '..' else 0 if part == '.' else 1
                            if depth < 0:
                                raise ValueError(f'escaping symlink: {name}')
                members[name] = {'type': member.type.decode('ascii'), 'mode': member.mode,
                                 'uid': member.uid, 'gid': member.gid, 'size': member.size,
                                 'mtime': member.mtime, 'link': member.linkname,
                                 'sha256': hashlib.sha256(content).hexdigest() if member.isfile() else None}
                if name in ('.PKGINFO', '.BUILDINFO'):
                    info[name] = metadata(content.decode('utf-8'))
                if name == '.INSTALL' or name.endswith('.hook'):
                    errors.append(f'hook requires explicit review outside automated gate: {name}')
                if name.startswith(PROTECTED):
                    errors.append(f'protected platform path: {name}')
                if name.startswith(('etc/', 'usr/lib/systemd/')):
                    review.append(f'system configuration/service requires installation review: {name}')
                result = elf_check(content)
                if result:
                    elf[name] = result
                    errors.extend(f'{name}: {error}' for error in result['errors'])
    finally:
        raw.close()
        if process:
            process.stdout.close()
            diagnostic = process.stderr.read().decode(errors='replace')
            if process.wait() != 0:
                raise ValueError(f'zstd decompression failed: {diagnostic[:500]}')
    for name, member in members.items():
        for ancestor in PurePosixPath(name).parents:
            if str(ancestor) in members and members[str(ancestor)]['type'] != '5':
                errors.append(f'archive path has non-directory ancestor: {name}')
        if member['type'] == '1':
            target = clean_name(member['link'])
            if target not in members or members[target]['type'] != '0':
                errors.append(f'hardlink target must be a regular archive member: {name}')
    for field in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
        if field not in members:
            errors.append(f'missing {field}')
    pkginfo = info.get('.PKGINFO', {})
    for field in ('pkgname', 'pkgver', 'arch', 'license'):
        if not pkginfo.get(field):
            errors.append(f'missing .PKGINFO {field}')
        elif field != 'license' and len(pkginfo[field]) != 1:
            errors.append(f'duplicate .PKGINFO {field}')
    if pkginfo.get('arch') not in (['any'], ['aarch64']):
        errors.append('package architecture must be any or aarch64')
    errors.extend(platform_relations(pkginfo, artifact=True))
    buildinfo = info.get('.BUILDINFO', {})
    if buildinfo.get('format') != ['2']:
        errors.append('only .BUILDINFO format 2 is supported')
    for field in ('pkgname', 'pkgver', 'pkgarch', 'pkgbuild_sha256sum'):
        if len(buildinfo.get(field, [])) != 1:
            errors.append(f'missing/duplicate .BUILDINFO {field}')
    if not re.fullmatch(r'[0-9a-f]{64}', buildinfo.get('pkgbuild_sha256sum', [''])[0]):
        errors.append('invalid .BUILDINFO PKGBUILD SHA-256')
    for source, target in (('pkgname', 'pkgname'), ('pkgver', 'pkgver'), ('pkgarch', 'arch')):
        if buildinfo.get(source) != pkginfo.get(target):
            errors.append(f'.BUILDINFO/.PKGINFO mismatch: {source}')
    if pkginfo.get('arch') == ['any'] and elf:
        errors.append('arch=any package contains ELF')
    return {'artifact': path.name, 'sha256': digest(path), 'metadata': info,
            'members': members, 'elf': elf, 'errors': errors, 'review': sorted(set(review)),
            'status': 'fail' if errors else 'artifact-static-pass'}


def conflicts(reports):
    owners, findings = {}, []
    for report in reports:
        for path, member in report['members'].items():
            if path in PACKAGE_METADATA or member['type'] == '5':
                continue
            if path in owners:
                findings.append(f"{path}: {owners[path]} conflicts with {report['artifact']}")
            owners[path] = report['artifact']
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    recipes = commands.add_parser('recipes')
    recipes.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    recipes.add_argument('--require-recipes', action='store_true')
    artifacts = commands.add_parser('artifacts')
    artifacts.add_argument('paths', nargs='+', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'recipes':
            reports = [recipe(path) for path in discover(args.root)]
            result = {'recipes': reports, 'errors': ['no recipes found'] if not reports else []}
        else:
            reports = [package(path) for path in args.paths]
            result = {'artifacts': reports, 'errors': conflicts(reports)}
        print(json.dumps(result, indent=2, sort_keys=True))
        return int(bool(result['errors'] or any(report['errors'] for report in reports)))
    except (OSError, ValueError, tarfile.TarError, UnicodeError) as error:
        print(json.dumps({'errors': [str(error)]}, indent=2))
        return 1


if __name__ == '__main__':
    sys.exit(main())
