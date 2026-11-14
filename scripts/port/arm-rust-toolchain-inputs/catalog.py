#!/usr/bin/env python3
"""Finite offline ALARM Rust input inspection. Never extract or execute payloads."""
import argparse
import hashlib
import json
from pathlib import Path
import posixpath
import re
import struct
import subprocess
import tarfile
import tempfile
import time

HERE = Path(__file__).resolve().parent
MAX_FILE = 512 * 1024 * 1024
MAX_PACKAGE = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 50000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def pin(path, expected):
    require(path.is_file() and not path.is_symlink(), f"missing/nonregular input: {path.name}")
    require(path.stat().st_size == expected['bytes'], f"size mismatch: {path.name}")
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    require(h.hexdigest() == expected['sha256'], f"hash mismatch: {path.name}")


def snapshot(source, target, expected, deadline):
    require(source.is_file() and not source.is_symlink(), 'nonregular snapshot input')
    total, h = 0, hashlib.sha256()
    with source.open('rb') as src, target.open('xb') as dst:
        while chunk := src.read(min(1024 * 1024, expected['bytes'] + 1 - total)):
            require(time.monotonic() < deadline, 'snapshot deadline exceeded')
            total += len(chunk)
            require(total <= expected['bytes'], 'snapshot input grew')
            h.update(chunk)
            dst.write(chunk)
    target.chmod(0o600)
    require(total == expected['bytes'] and h.hexdigest() == expected['sha256'], 'snapshot input changed')


def canonical(name):
    require(name and not name.startswith('/') and '\\' not in name and '\x00' not in name,
            f"unsafe archive path: {name!r}")
    parts = name.rstrip('/').split('/')
    require(all(p not in ('', '.', '..') for p in parts), f"noncanonical archive path: {name!r}")
    return '/' + '/'.join(parts)


def link_target(path, target, hard=False):
    require(target and '\\' not in target and '\x00' not in target, 'unsafe link target')
    # Absolute symlinks are interpreted inside the catalog namespace only.
    joined = target if target.startswith('/') else posixpath.join('/' if hard else posixpath.dirname(path), target)
    depth = 0
    for part in joined.split('/'):
        depth += -1 if part == '..' else int(part not in ('', '.'))
        require(depth >= 0, 'link escapes catalog root')
    return posixpath.normpath(joined)


def fields(data):
    result = {}
    for line in data.decode('utf-8', errors='strict').splitlines():
        if not line or line.startswith('#'):
            continue
        require(' = ' in line, 'malformed package metadata')
        key, value = line.split(' = ', 1)
        result.setdefault(key, []).append(value)
    return result


def elf(data, allow_bpf=False):
    if not data.startswith(b'\x7fELF'):
        return None
    require(len(data) >= 64 and data[4:7] == b'\x02\x01\x01', 'require ELF64 little endian v1')
    machine = struct.unpack_from('<H', data, 18)[0]
    require(machine == 183 or (allow_bpf and machine == 247), f"non-AArch64 ELF machine: {machine}")
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', data, 54)
    require(phnum < 4096 and (not phnum or phsize == 56), 'unsupported ELF program headers')
    require(phoff + phsize * phnum <= len(data), 'truncated program headers')
    if machine == 247:
        require(struct.unpack_from('<H', data, 16)[0] == 1 and phnum == 0,
                'BPF data must be relocatable with no program headers')
        return {'machine': machine, 'payload_kind': 'BPF_RELOCATABLE_DATA', 'interpreter': None,
                'needed': [], 'soname': None, 'rpath': [], 'runpath': []}
    loads, dynamic, interpreter = [], None, None
    for i in range(phnum):
        typ, flags, off, va, pa, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
        require(off + filesz <= len(data), 'truncated segment')
        if typ == 1:
            loads.append((off, va, filesz))
        elif typ == 2:
            dynamic = (off, filesz)
        elif typ == 3:
            raw = data[off:off + filesz]
            require(raw.endswith(b'\0') and b'\0' not in raw[:-1], 'malformed interpreter')
            interpreter = raw[:-1].decode('ascii')
    result = {'machine': machine, 'interpreter': interpreter, 'needed': [], 'soname': None,
              'rpath': [], 'runpath': []}
    if dynamic:
        off, size = dynamic
        require(size % 16 == 0, 'malformed dynamic segment')
        tags, terminated = [], False
        for at in range(off, off + size, 16):
            tag, val = struct.unpack_from('<qQ', data, at)
            if tag == 0:
                terminated = True
                break
            tags.append((tag, val))
        require(terminated, 'unterminated dynamic segment')
        for singleton in (5, 10, 14, 15, 29):
            require(sum(tag == singleton for tag, val in tags) <= 1, 'duplicate dynamic singleton')
        strings = dict(tags).get(5)
        strsize = dict(tags).get(10, 0)
        if any(t in (1, 14, 15, 29) for t, v in tags):
            require(strings is not None and strsize > 0, 'missing dynamic string table')
            offsets = [o + strings - v for o, v, s in loads if v <= strings and strings + strsize <= v + s]
            require(len(offsets) == 1, 'unmapped dynamic strings')
            table = data[offsets[0]:offsets[0] + strsize]
            for tag, val in tags:
                if tag not in (1, 14, 15, 29):
                    continue
                require(val < len(table) and b'\0' in table[val:], 'invalid dynamic string')
                value = table[val:table.index(b'\0', val)].decode('utf-8')
                if tag == 1:
                    result['needed'].append(value)
                elif tag == 14:
                    result['soname'] = value
                else:
                    result['rpath' if tag == 15 else 'runpath'] = value.split(':')
    return result


def inspect_archive(path, expected, deadline):
    entries, metadata, total, count = {}, {}, 0, 0
    # Stream decompression; no extract(), filesystem links or package code.
    with tarfile.open(path, mode='r|*') as archive:
        for member in archive:
            require(time.monotonic() < deadline, 'inspection deadline exceeded')
            count += 1
            require(count <= MAX_MEMBERS, 'member count bound exceeded')
            name = canonical(member.name)
            require(name not in entries, f"duplicate archive member: {name}")
            record = {'mode': member.mode, 'type': 'directory'}
            if member.isfile():
                require(0 <= member.size <= MAX_FILE, 'file size bound exceeded')
                total += member.size
                require(total <= MAX_PACKAGE, 'expanded package bound exceeded')
                with archive.extractfile(member) as stream:
                    data = stream.read(MAX_FILE + 1)
                require(len(data) == member.size, 'truncated archive file')
                record.update(digest(data), type='file')
                if name in ('/.PKGINFO', '/.BUILDINFO'):
                    metadata[name] = fields(data)
                elif not name.startswith('/.'):
                    bpf_pin = expected.get('non_aarch64_elf_data', {}).get(name)
                    if bpf_pin is not None:
                        require(all(record[k] == bpf_pin[k] for k in ('bytes', 'sha256')), 'BPF data pin mismatch')
                    parsed = elf(data, allow_bpf=bpf_pin is not None)
                    if bpf_pin is not None:
                        require(parsed is not None and parsed.get('payload_kind') == 'BPF_RELOCATABLE_DATA',
                                'listed BPF input is not BPF data')
                    if parsed is not None:
                        record['elf'] = parsed
            elif member.issym() or member.islnk():
                record.update(type='hardlink' if member.islnk() else 'symlink', target=member.linkname,
                              resolved=link_target(name, member.linkname, member.islnk()))
            else:
                require(member.isdir(), f"special archive node: {name}")
            entries[name] = record
    info = metadata.get('/.PKGINFO', {})
    for key, wanted in [('pkgname', expected['name']), ('pkgver', expected['version']), ('arch', expected['arch'])]:
        require(info.get(key) == [wanted], f"package identity mismatch: {key}")
    for key, wanted in [('depend', expected['depends']), ('provides', expected['provides'])]:
        require(sorted(info.get(key, [])) == sorted(wanted), f"package catalog mismatch: {expected['name']} {key}")
    # No member may be placed under a regular file or a link, even though nothing is extracted.
    for name in entries:
        parent = posixpath.dirname(name)
        while parent != '/':
            require(parent not in entries or entries[parent]['type'] == 'directory', 'non-directory member ancestor')
            parent = posixpath.dirname(parent)
        item, seen = entries[name], set()
        while item['type'] == 'hardlink':
            target = item['resolved']
            require(target not in seen, 'archive hardlink cycle')
            seen.add(target)
            require(target in entries, 'archive hardlink target missing')
            item = entries[target]
            require(item['type'] in ('file', 'hardlink'), 'hardlink target must be a regular file')
    for path in expected.get('non_aarch64_elf_data', {}):
        require(entries.get(path, {}).get('elf', {}).get('payload_kind') == 'BPF_RELOCATABLE_DATA',
                'listed BPF input missing or not BPF data')
    return {'metadata': metadata, 'entries': entries, 'expanded_bytes': total, 'member_count': count}


def signatures(archive, signature, keyring, primary):
    with tempfile.TemporaryDirectory(prefix='rust-input-gpgv-') as home:
        run = subprocess.run(['/usr/bin/gpgv', '--homedir', home, '--keyring', str(keyring),
                              '--status-fd', '1', str(signature), str(archive)],
                             env={'PATH': '/usr/bin', 'LC_ALL': 'C'}, capture_output=True, timeout=20)
    require(len(run.stdout) + len(run.stderr) < 65536, 'signature output bound exceeded')
    lines = run.stdout.decode('utf-8').splitlines()
    valid = [s.split()[2:] for s in lines if s.startswith('[GNUPG:] VALIDSIG ')]
    require(run.returncode == 0 and len(valid) == 1, f"signature mathematics failed: {archive.name}")
    require(valid[0][0] == primary and valid[0][-1] == primary, 'unexpected signature signer')
    return {'status': 'VALID_SIGNATURE_MATHEMATICS', 'signer': valid[0][0],
            'creation_timestamp': int(valid[0][2]), 'status_lines': lines,
            'key_freshness': 'NOT_ESTABLISHED', 'source_acceptance': 'NOT_ESTABLISHED'}


def resolve(path, entries):
    seen = set()
    for _ in range(64):
        require(path not in seen, 'catalog link cycle')
        seen.add(path)
        parts = path.strip('/').split('/')
        changed = False
        for i in range(1, len(parts) + 1):
            prefix = '/' + '/'.join(parts[:i])
            item = entries.get(prefix)
            if item and item['type'] in ('symlink', 'hardlink'):
                path = posixpath.normpath(posixpath.join(item['resolved'], *parts[i:]))
                changed = True
                break
        if not changed:
            return path if path in entries and entries[path]['type'] == 'file' else None
    raise ValueError('catalog link depth exceeded')


def elf_joins(entries):
    joins, missing = [], []
    for path, entry in sorted(entries.items()):
        obj = entry.get('elf')
        if not obj:
            continue
        # This is a direct structural join, not a complete dynamic-loader simulation.
        search = obj['runpath'] or obj['rpath']
        dirs = [d.replace('${ORIGIN}', posixpath.dirname(path)).replace('$ORIGIN', posixpath.dirname(path)) for d in search]
        unsupported = any(not d.startswith('/') or '$' in d for d in dirs)
        dirs += ['/usr/lib', '/lib']
        for needed in obj['needed'] + ([obj['interpreter']] if obj['interpreter'] else []):
            require(needed and ('/' not in needed or needed.startswith('/')), 'unsafe ELF dependency')
            choices = [needed] if needed.startswith('/') else [posixpath.join(d, needed) for d in dirs if d.startswith('/') and '$' not in d]
            found = next((v for candidate in choices if (v := resolve(posixpath.normpath(candidate), entries))), None)
            record = {'consumer': path, 'needed': needed, 'provider': found}
            if found:
                require(entries[found].get('elf', {}).get('machine') == 183, 'ELF dependency resolves to non-AArch64 ELF')
                joins.append(record)
            else:
                missing.append(record)
        if unsupported:
            missing.append({'consumer': path, 'search_path': search, 'reason': 'unsupported loader search expression'})
    return joins, missing


def find_input(filename, caches, expected):
    found = None
    for cache in caches:
        path = cache / filename
        if path.exists() or path.is_symlink():
            pin(path, expected)  # A corrupt duplicate is an error, not silently skipped.
            found = found or path
    return found


def package_joins(lock):
    packages = lock['packages']
    expected = {(n, d) for n, p in packages.items() for d in p['depends']}
    actual, result = set(), []
    for join in lock['dependency_joins']:
        key = join['package'], join['dependency']
        require(key in expected and key not in actual, 'extra/duplicate package dependency join')
        actual.add(key)
        provider = join['provider']
        require(provider in packages, 'missing dependency provider')
        spec = packages[provider]
        match = re.fullmatch(r'([^<>=]+)(?:(>=|=)([^<>=]+))?', join['dependency'])
        require(match is not None, 'unsupported dependency expression')
        name, op, version = match.groups()
        offered = spec['version'] if name == provider else None
        for provide in spec['provides']:
            if provide == name:
                offered = ''
            elif provide.startswith(name + '='):
                offered = provide[len(name) + 1:]
        require(offered is not None, 'provider name mismatch')
        if op == '=':
            require(offered == version or offered.rsplit('-', 1)[0] == version, 'dependency equality mismatch')
        elif op == '>=':
            # Four historical numeric lower bounds only. Ambiguous equal-prefix
            # release comparisons are refused; this is not a pacman version solver.
            a, b = re.match(r'\d+(?:\.\d+)*', offered), re.match(r'\d+(?:\.\d+)*', version)
            require(a and b, 'unsupported lower-bound version')
            av, bv = tuple(map(int, a[0].split('.'))), tuple(map(int, b[0].split('.')))
            width = max(len(av), len(bv))
            av, bv = av + (0,) * (width - len(av)), bv + (0,) * (width - len(bv))
            require(offered == version or av > bv, 'unsupported/unsatisfied lower bound')
        result.append(dict(join, offered_version=offered))
    require(actual == expected, 'unjoined package dependency')
    return result


def source_joins(packages, facts):
    recipes, licenses = [], []
    for fact in facts['recipes']:
        name = 'llvm-libs' if fact['package'] == 'llvm' else fact['package']
        if name not in packages:
            continue
        recorded = packages[name]['metadata'].get('/.BUILDINFO', {}).get('pkgbuild_sha256sum', [])
        require(recorded == [fact['retained_pkgbuild_sha256']], 'recorded recipe hash changed')
        recipes.append({'package': name, 'official_revision': fact['revision'], 'official_recipe_sha256': fact['sha256'],
                        'recorded_recipe_sha256': recorded[0], 'exact_match': recorded == [fact['sha256']]})
    for fact in facts['upstream']['llvm']['licenses']:
        name = {'llvm': 'llvm-libs', 'compiler-rt': 'compiler-rt', 'lld': 'lld'}[fact['path'].split('/')[0]]
        path = f'/usr/share/licenses/{name}/LICENSE'
        if name in packages:
            observed = packages[name]['entries'].get(path, {})
            licenses.append({'package': name, 'path': path, 'upstream_url': fact['url'],
                             'exact_match': all(observed.get(k) == fact[k] for k in ('bytes', 'sha256'))})
    return {'recipes': recipes, 'license_notices': licenses, 'corresponding_source_acceptance': 'NOT_ESTABLISHED'}


def preserve_original_inputs(lock):
    descriptor = lock['prior_inputs']
    path = HERE / descriptor['filename']
    pin(path, descriptor)
    prior = json.loads(path.read_text())
    require(len(prior['packages']) == 84, 'unexpected historical input count')
    require(all(lock['packages'].get(n) == spec for n, spec in prior['packages'].items()),
            'historical package descriptor changed or removed')
    return 'EXACT_84_PACKAGE_DESCRIPTORS'


def auxiliary_joins(lock, packages, entries, joins):
    results = []
    for required in lock['auxiliary_requirements']:
        consumer, provider = required['consumer_package'], required['provider_package']
        require(lock['packages'][provider]['version'] == required['provider_version'],
                'auxiliary provider version differs from frozen selection')
        if consumer not in packages or provider not in packages:
            results.append(dict(required, status='INPUTS_MISSING'))
            continue
        info = packages[consumer]['metadata']['/.PKGINFO']
        require(required['optional_dependency'] in info.get('optdepend', []),
                'auxiliary optional-dependency association changed')
        matched = [j for j in joins if j['consumer'] == required['consumer'] and j['needed'] == required['needed']]
        require(len(matched) == 1 and matched[0]['provider'] == required['provider_elf'],
                'auxiliary ELF provider path mismatch')
        target = entries[required['provider_elf']]
        require(target['package'] == provider and target.get('elf', {}).get('soname') == required['needed'],
                'auxiliary ELF provider identity mismatch')
        buildinfo = packages[consumer]['metadata'].get('/.BUILDINFO', {}).get('installed', [])
        results.append(dict(required, status='EXACT_STRUCTURAL_JOIN',
                            consumer_buildinfo_provider=[v for v in buildinfo if re.match(re.escape(provider) + r'-\d', v)],
                            runtime_compatibility='NOT_RUN'))
    return results


def verify(lock, caches, rust_files, deadline):
    keyring = HERE / lock['public_keyring']['filename']
    pin(keyring, lock['public_keyring'])
    preserved = preserve_original_inputs(lock)
    supplemental_path, remaining_path = HERE / 'supplemental-inputs.json', HERE / 'remaining-inputs.json'
    pin(supplemental_path, lock['supplemental_provenance'])
    pin(remaining_path, lock['remaining_provider_inputs'])
    supplemental, remaining = json.loads(supplemental_path.read_text()), json.loads(remaining_path.read_text())
    prior = json.loads((HERE / lock['prior_inputs']['filename']).read_text())
    require(set(supplemental['packages']) == set(lock['packages']) - set(prior['packages']),
            'supplemental provenance coverage mismatch')
    for name, source in supplemental['packages'].items():
        require(all(source[key] == lock['packages'][name][key] for key in ('filename', 'version', 'archive', 'signature')),
                'supplemental provenance descriptor mismatch')
    dependencies = package_joins(lock)
    facts_path = HERE / 'source-facts.json'
    pin(facts_path, lock['source_facts'])
    facts = json.loads(facts_path.read_text())
    packages, entries, missing, inputs = {}, {}, [], []
    for name, spec in sorted(lock['packages'].items()):
        require(time.monotonic() < deadline, 'verification deadline exceeded')
        spec = dict(spec, name=name)
        archive = find_input(spec['filename'], caches, spec['archive'])
        signature = find_input(spec['filename'] + '.sig', caches, spec['signature'])
        if archive is None or signature is None:
            missing.append({'package': name, 'archive_missing': archive is None, 'signature_missing': signature is None})
            continue
        # A cache may be concurrently modified. Bind GPG and payload inspection
        # to identical byte-pinned private snapshots, never separate mutable opens.
        with tempfile.TemporaryDirectory(prefix='rust-input-data-') as temporary:
            copied_archive, copied_sig = Path(temporary) / archive.name, Path(temporary) / signature.name
            snapshot(archive, copied_archive, spec['archive'], deadline)
            snapshot(signature, copied_sig, spec['signature'], deadline)
            checked = signatures(copied_archive, copied_sig, keyring, lock['signer_primary'])
            inspected = inspect_archive(copied_archive, spec, deadline)
        packages[name] = dict(inspected, signature=checked)
        inputs.extend([(archive, spec['archive']), (signature, spec['signature'])])
        for path, record in inspected['entries'].items():
            if path.startswith('/.'):
                continue
            if path in entries:
                require(record['type'] == entries[path]['type'] == 'directory', f"payload collision: {path}")
            else:
                entries[path] = dict(record, package=name)
    joins, unresolved = elf_joins(entries)
    tools = {}
    for role, path in {'rustc': '/usr/bin/rustc', 'cargo': '/usr/bin/cargo',
                       'cc': '/usr/bin/cc', 'ld': '/usr/bin/ld', 'lld': '/usr/bin/ld.lld'}.items():
        resolved = resolve(path, entries)
        if resolved:
            require(entries[resolved].get('elf', {}).get('machine') == 183, f'required tool is not an AArch64 ELF: {role}')
            tools[role] = dict(path=path, resolved=resolved,
                               **{k: entries[resolved][k] for k in ('bytes', 'sha256', 'package')})
    association = 'NOT_CHECKED'
    if rust_files:
        pin(rust_files, lock['bankstown_rust_association'])
        association = 'RUST_ARCHIVE_MISSING'
        if 'rust' in packages:
            expected = json.loads(rust_files.read_text())
            actual = {p: {k: r[k] for k in ('bytes', 'sha256')} for p, r in packages['rust']['entries'].items()
                      if not p.startswith('/.') and r['type'] == 'file'}
            require(actual == expected['files'], 'Bankstown 137-file Rust association mismatch')
            association = 'EXACT_137_FILE_ASSOCIATION'
    report = {'schema': 1, 'purpose': lock['purpose'], 'packages': packages, 'missing_inputs': missing,
              'package_dependency_joins': dependencies,
              'source_observations': source_joins(packages, facts),
              'prior_input_preservation': preserved,
              'supplemental_provenance': lock['supplemental_provenance'],
              'remaining_provider_inputs': remaining,
              'auxiliary_provider_joins': auxiliary_joins(lock, packages, entries, joins),
              'required_tool_elf_files': tools,
              'elf_dependency_joins': joins, 'unresolved_elf_dependencies': unresolved,
              'rust_association': association, 'input_checks': 'PASS' if not missing else 'INCOMPLETE',
              'structural_elf_closure': 'PASS' if not missing and not unresolved and not remaining['candidates'] else 'INCOMPLETE',
              'native_tools_profile': 'NOT_PRODUCED', 'key_freshness': 'NOT_ESTABLISHED',
              'corresponding_source_acceptance': 'NOT_ESTABLISHED', 'native_execution': 'NOT_RUN',
              'installation': 'NOT_RUN', 'M2': 'NOT_RUN'}
    return report, inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, action='append', required=True, help='nonrecursive exact-filename cache; repeatable')
    parser.add_argument('--output', type=Path, required=True, help='new private output directory')
    parser.add_argument('--rust-association', type=Path, default=HERE / 'rust-137-files.json', help='Bankstown native-rust-inputs.json; exact content pin required')
    parser.add_argument('--prepare', action='store_true', help='also copy verified archive/signature data into output/cache; never unpack')
    args = parser.parse_args()
    lock_path = HERE / 'inputs.lock.json'
    lock_data = lock_path.read_bytes()
    lock = json.loads(lock_data)
    require(not args.output.exists() and not args.output.is_symlink(), 'output already exists')
    # Output cannot overlap a source cache in either direction.
    output = args.output.resolve()
    caches = [c.resolve(strict=True) for c in args.cache]
    require(all(c.is_dir() and output != c and output not in c.parents and c not in output.parents for c in caches), 'output/cache overlap')
    report, inputs = verify(lock, caches, args.rust_association, time.monotonic() + 300)
    report['lock'] = digest(lock_data)
    # Preparation accepts exact verified bytes even when structural joins remain open.
    # Missing archive/signature inputs refuse preparation before creating output.
    require(not args.prepare or not report['missing_inputs'], 'cannot prepare missing inputs')
    args.output.mkdir(mode=0o700)
    if args.prepare:
        cache = args.output / 'cache'
        cache.mkdir(mode=0o700)
        for source, expected in inputs:
            target = cache / source.name
            snapshot(source, target, expected, time.monotonic() + 30)
    (args.output / 'catalog.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    (args.output / 'inputs.lock.json').write_bytes(lock_data)
    print(json.dumps({'input_checks': report['input_checks'], 'packages': len(report['packages']),
                      'structural_elf_closure': report['structural_elf_closure'],
                      'elf_joins': len(report['elf_dependency_joins']), 'unresolved': len(report['unresolved_elf_dependencies']),
                      'rust_association': report['rust_association'], 'prepared': args.prepare}, sort_keys=True))
    return 0 if report['input_checks'] == report['structural_elf_closure'] == 'PASS' else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        raise SystemExit(f'REFUSED: {error}')
