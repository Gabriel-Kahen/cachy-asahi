#!/usr/bin/env python3
"""Explicit optional Qt-base -3 input candidate; parent -2 catalog stays held."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent
sys.dont_write_bytecode = True
version_spec = importlib.util.spec_from_file_location('elf_versions', HERE / 'elf_versions.py')
elf_versions = importlib.util.module_from_spec(version_spec)
version_spec.loader.exec_module(elf_versions)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load():
    lock = json.loads((HERE / 'candidate.lock.json').read_text())
    binding = json.loads((HERE / 'parent-binding.json').read_text())
    source = None
    for name, pin in binding['files'].items():
        path = PARENT / name
        require(path.is_file() and not path.is_symlink(), 'parent file missing/nonregular')
        data = path.read_bytes()
        require(len(data) == pin['bytes'] and hashlib.sha256(data).hexdigest() == pin['sha256'],
                f'parent changed: {name}')
        if name == 'catalog.py':
            source = data
    spec = importlib.util.spec_from_file_location('retained_parent_catalog', PARENT / 'catalog.py')
    parent = importlib.util.module_from_spec(spec)
    require(source is not None, 'parent parser binding absent')
    exec(compile(source, str(PARENT / 'catalog.py'), 'exec'), parent.__dict__)
    baseline = json.loads((PARENT / 'inputs.lock.json').read_text())
    combined = combine(parent, lock, baseline)
    return parent, lock, combined


def combine(parent, lock, baseline):
    require(lock['purpose'] == 'bankstown-optional-qtbase6.12.0-3-input-candidate', 'wrong candidate purpose')
    require(lock['signer_primary'] == baseline['signer_primary'], 'candidate signer changed')
    protected = {n: p for n, p in baseline['packages'].items() if n != 'qt6-base'}
    require(len(protected) == 275 and baseline['packages']['qt6-base']['version'] == '6.12.0-2', 'wrong original catalog')
    require(not (set(lock['new_packages']) & set(protected)), 'protected package replacement')
    require(0 < len(lock['new_packages']) <= 100, 'new package count exceeds100')
    require(lock['new_packages']['qt6-base']['version'] == '6.12.0-3', 'wrong explicit Qt candidate')
    packages = dict(protected, **lock['new_packages'])
    combined = dict(baseline, packages=packages,
                    dependency_joins=baseline['dependency_joins'] + lock['new_dependency_joins'])
    parent.preserve_original_inputs(combined)
    parent.preserve_271_inputs(combined)
    return combined


def package_contracts(c, combined):
    known, missing = [], []
    for row in combined['dependency_joins']:
        (known if row['provider'] in combined['packages'] else missing).append(row)
    available = {(r['package'], r['dependency']) for r in known}
    # Validate every resolvable version/provides expression with the retained
    # parser. The manifest and report retain every missing expression separately.
    partial = {n: dict(p, depends=[d for d in p['depends'] if (n, d) in available])
               for n, p in combined['packages'].items()}
    checked = c.package_joins(dict(combined, packages=partial, dependency_joins=known))
    all_expected = {(n, d) for n, p in combined['packages'].items() for d in p['depends']}
    require({(r['package'], r['dependency']) for r in known + missing} == all_expected,
            'unrecorded declared dependency')
    return checked, missing


def below_tmp(path):
    result = path.resolve()
    require(Path('/tmp') in result.parents and not path.is_symlink(), 'cache/output must be below /tmp')
    return result


def archive_bytes(cache):
    return sum(p.stat().st_size for p in cache.glob('*.pkg.tar.xz'))


def acquire(c, lock, args):
    cache = below_tmp(args.destination)
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache.chmod(0o700)
    require(archive_bytes(cache) <= 512 * 1024 * 1024, 'archive cache exceeds512MiB')
    events, missing = [], []
    blocked = set()
    for name, package in sorted(lock['new_packages'].items()):
        for suffix, pin in [('', package['archive']), ('.sig', package['signature'])]:
            filename = package['filename'] + suffix
            target = cache / filename
            source = c.find_input(filename, args.cache + [cache], pin)
            if source is not None:
                if not target.exists():
                    require(archive_bytes(cache) + (pin['bytes'] if not suffix else 0) <= 512 * 1024 * 1024,
                            'archive copy exceeds512MiB')
                    c.snapshot(source, target, pin, time.monotonic() + 30)
                events.append({'filename': filename, 'result': 'EXACT_RETAINED_INPUT'})
                continue
            require(pin['bytes'] <= 64 * 1024 * 1024 and
                    archive_bytes(cache) + (pin['bytes'] if not suffix else 0) <= 512 * 1024 * 1024,
                    'archive transfer exceeds finite bounds')
            for route in lock['routes'][name]:
                url = route + suffix
                host = url.split('/')[2]
                if host in blocked:
                    continue
                try:
                    with urllib.request.urlopen(url, timeout=20) as response:
                        require(response.url == url, 'unreviewed redirect')
                        with tempfile.TemporaryDirectory(prefix='candidate-transfer-', dir=cache.parent) as tmp:
                            partial = Path(tmp) / filename
                            count, deadline = 0, time.monotonic() + 60
                            with partial.open('xb') as out:
                                while chunk := response.read(min(1048576, pin['bytes'] + 1 - count)):
                                    count += len(chunk)
                                    require(count <= pin['bytes'] and time.monotonic() < deadline, 'transfer bound exceeded')
                                    out.write(chunk)
                            c.pin(partial, pin)
                            partial.chmod(0o600)
                            require(not target.exists(), 'cache changed during transfer')
                            partial.rename(target)
                    events.append({'filename': filename, 'result': 'EXACT_TRANSFER', 'url': url})
                    break
                except urllib.error.HTTPError as error:
                    events.append({'url': url, 'HTTP': error.code})
                    if error.code == 429:
                        blocked.add(host)
            if not target.exists():
                missing.append(filename)
        if (cache / package['filename']).exists() and (cache / (package['filename'] + '.sig')).exists():
            c.signatures(cache / package['filename'], cache / (package['filename'] + '.sig'),
                         PARENT / 'alarm-public.gpg', lock['signer_primary'])
    return {'events': events, 'missing_inputs': missing, 'archive_cache_bytes': archive_bytes(cache),
            'complete': not missing, 'payload_execution': 'NOT_RUN'}


def versioned_inspection(c, archive, package, deadline):
    inspected = c.inspect_archive(archive, package, deadline)
    with tarfile.open(archive, mode='r|*') as stream:
        for member in stream:
            path = '/' + member.name.rstrip('/')
            entry = inspected['entries'].get(path, {})
            if entry.get('elf', {}).get('machine') == 183:
                require(time.monotonic() < deadline, 'ABI inspection deadline')
                with stream.extractfile(member) as data:
                    entry['gnu_versions'] = elf_versions.parse(data.read())
    return inspected


def verify(c, lock, combined, args):
    packages, entries, missing, inputs = {}, {}, [], []
    deadline = time.monotonic() + 600
    for name, package in sorted(combined['packages'].items()):
        archive = c.find_input(package['filename'], args.cache, package['archive'])
        sig = c.find_input(package['filename'] + '.sig', args.cache, package['signature'])
        if archive is None or sig is None:
            missing.append(name)
            continue
        with tempfile.TemporaryDirectory(prefix='candidate-verified-', dir=args.output.parent) as tmp:
            a, s = Path(tmp) / archive.name, Path(tmp) / sig.name
            c.snapshot(archive, a, package['archive'], deadline)
            c.snapshot(sig, s, package['signature'], deadline)
            math = c.signatures(a, s, PARENT / 'alarm-public.gpg', lock['signer_primary'])
            inspected = versioned_inspection(c, a, dict(package, name=name), deadline)
        packages[name] = dict(inspected, signature=math)
        inputs.extend([(archive, package['archive']), (sig, package['signature'])])
        for path, record in inspected['entries'].items():
            if path.startswith('/.'):
                continue
            if path in entries:
                require(record['type'] == entries[path]['type'] == 'directory', f'payload collision: {path}')
            else:
                entries[path] = dict(record, package=name)
    joins, unresolved = c.elf_joins(entries)
    versions, unresolved_versions = elf_versions.join(entries, joins)
    package_joins, unresolved_packages = package_contracts(c, combined)
    rust = json.loads((PARENT / 'rust-137-files.json').read_text())
    if 'rust' in packages:
        actual = {p: {k: r[k] for k in ('bytes', 'sha256')} for p, r in packages['rust']['entries'].items()
                  if not p.startswith('/.') and r['type'] == 'file'}
        require(actual == rust['files'], 'Rust137-file association changed')
    complete = not missing and not unresolved and not unresolved_versions and not unresolved_packages
    report = {'purpose': lock['purpose'], 'candidate': 'EXPLICIT_OPTIONAL_QT_BASE_6.12.0-3',
              'candidate_lock': c.digest((HERE / 'candidate.lock.json').read_bytes()),
              'parent_binding': c.digest((HERE / 'parent-binding.json').read_bytes()),
              'version_parser': c.digest((HERE / 'elf_versions.py').read_bytes()),
              'source_facts': c.digest((HERE / 'source-facts.json').read_bytes()),
              'original_minus2_hold': 'UNCHANGED', 'protected_input_count': 275,
              'packages': packages, 'missing_inputs': missing, 'elf_dependency_joins': joins,
              'package_dependency_joins': package_joins, 'unresolved_package_dependencies': unresolved_packages,
              'unresolved_elf_dependencies': unresolved, 'GNU_version_joins': versions,
              'unresolved_GNU_versions': unresolved_versions, 'complete': complete,
              'native_tools_profile': 'NOT_PRODUCED', 'source_legal_freshness_acceptance': 'HELD',
              'payload_execution': 'NOT_RUN', 'ABI_limit': 'Version-name contracts; not full symbol/interposition/runtime qualification'}
    require(not args.prepare or complete, 'refusing preparation with unresolved input/provider/ABI edges')
    args.output.mkdir(mode=0o700)
    if args.prepare:
        cache = args.output / 'cache'
        cache.mkdir(mode=0o700)
        require(sum(pin['bytes'] for source, pin in inputs if source.name.endswith('.xz')) <= 512 * 1024 * 1024,
                'complete archive bundle exceeds512MiB')
        for source, pin in inputs:
            c.snapshot(source, cache / source.name, pin, time.monotonic() + 30)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['acquire', 'verify'])
    parser.add_argument('--cache', type=Path, action='append', default=[])
    parser.add_argument('--destination', type=Path, help='new archive cache for acquisition')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--prepare', action='store_true')
    args = parser.parse_args()
    args.output = below_tmp(args.output)
    require(not args.output.exists(), 'output exists')
    require(args.output.parent.is_dir(), 'output parent missing')
    require(all(args.output != p.resolve() and args.output not in p.resolve().parents and p.resolve() not in args.output.parents
                for p in args.cache), 'output/cache overlap')
    require(os.statvfs('/tmp').f_bavail * os.statvfs('/tmp').f_frsize >= 1024**3, 'insufficient fresh/tmp space')
    available = next(int(s.split()[1]) * 1024 for s in Path('/proc/meminfo').read_text().splitlines()
                     if s.startswith('MemAvailable:'))
    require(available >= 512 * 1024 * 1024, 'insufficient fresh RAM')
    c, lock, combined = load()
    if args.operation == 'acquire':
        require(args.destination is not None and not args.prepare, 'acquisition requires destination')
        destination = below_tmp(args.destination)
        require(args.output != destination and args.output not in destination.parents and destination not in args.output.parents,
                'output/destination overlap')
        report = acquire(c, lock, args)
        report['selected_archive_inputs_complete'] = report['complete']
        report['unresolved_package_dependencies'] = package_contracts(c, combined)[1]
        report['complete'] = report['complete'] and not report['unresolved_package_dependencies']
        report['stage'] = 'ARCHIVE_ACQUISITION_ONLY_REQUIRES_CATALOG_VERIFICATION'
        args.output.mkdir(mode=0o700)
    else:
        require(args.cache and args.destination is None, 'verification requires caches')
        report = verify(c, lock, combined, args)
    (args.output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'complete': report['complete'], 'operation': args.operation,
                      'missing_inputs': report['missing_inputs'], 'unresolved_ELF': len(report.get('unresolved_elf_dependencies', [])),
                      'unresolved_GNU_versions': len(report.get('unresolved_GNU_versions', []))}, sort_keys=True))
    return 0 if report['complete'] else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, tarfile.TarError) as error:
        raise SystemExit(f'REFUSED: {error}')
