#!/usr/bin/env python3
"""Verify evidence before comparing two independently created build records."""
import argparse
import json
import sys
import tarfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'checks'))
from package_checks import digest, package, PACKAGE_METADATA
from build import bind_artifact


def verify(path):
    path = Path(path).resolve()
    record = json.loads((path / 'provenance.json').read_text())
    if not isinstance(record, dict):
        raise ValueError('provenance must be an object')
    if record.get('status') != 'built-package-static-pass':
        raise ValueError(f'{path}: build has not passed')
    for key in ('artifacts', 'files', 'recipe_inputs'):
        if not isinstance(record.get(key), dict) or not record[key]:
            raise ValueError(f'{path}: missing {key} evidence')
    required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
                'artifacts/makepkg.conf', 'artifacts/pacman.conf'}
    if not required <= set(record['files']):
        raise ValueError(f'{path}: required environment/log/validation evidence missing')
    for name, checksum in record['files'].items():
        item = (path / name).resolve()
        if not item.is_relative_to(path) or digest(item) != checksum:
            raise ValueError(f'{path}: missing/changed evidence {name}')
    actual = {p.name for p in (path / 'artifacts').glob('*.pkg.tar.*') if not p.name.endswith('.sig')}
    if actual != set(record['artifacts']):
        raise ValueError(f'{path}: unexpected/missing artifact set')
    reports = {}
    for name, checksum in record['artifacts'].items():
        if '/' in name or name in ('.', '..'):
            raise ValueError('invalid artifact basename')
        item = path / 'artifacts' / name
        if digest(item) != checksum:
            raise ValueError(f'{path}: artifact checksum mismatch {name}')
        report = package(item)
        if report['errors']:
            raise ValueError(f'{path}: artifact validation failed {name}')
        errors = bind_artifact(record['recipe_metadata'], report, record['recipe_inputs']['PKGBUILD'])
        if errors:
            raise ValueError(f'{path}: recorded artifact no longer matches reviewed metadata: {errors}')
        reports[name] = report
    # Snapshot is retained for review and must match the original input hashes.
    for name, checksum in record['recipe_inputs'].items():
        item = (path / 'inputs' / name).resolve()
        if not item.is_relative_to(path / 'inputs') or digest(item) != checksum:
            raise ValueError(f'{path}: changed recipe snapshot {name}')
    return record, reports


def compare(first, second):
    if Path(first).resolve() == Path(second).resolve():
        raise ValueError('second build must be a different evidence directory')
    left, a = verify(first)
    right, b = verify(second)
    mismatches = []
    if not left.get('clean_environment_id') or not right.get('clean_environment_id') or left['clean_environment_id'] == right['clean_environment_id']:
        mismatches.append('different recorded clean container IDs required')
    for key in ('image', 'image_id', 'mode', 'source_date_epoch', 'recipe_inputs',
                'recipe_metadata', 'expected_packages_sha256', 'entry_script_sha256'):
        if key not in left or key not in right or left[key] != right[key]:
            mismatches.append(f'input mismatch: {key}')
    if set(a) != set(b):
        mismatches.append('artifact set mismatch')
    comparisons = {}
    for name in sorted(set(a) & set(b)):
        # Explicitly compare the installed tree, retaining mtimes, modes and links.
        # Pacman build metadata is reported separately, never hidden as byte identity.
        tree_a = {k: v for k, v in a[name]['members'].items() if k not in PACKAGE_METADATA}
        tree_b = {k: v for k, v in b[name]['members'].items() if k not in PACKAGE_METADATA}
        equal = tree_a == tree_b
        meta = a[name]['metadata']['.PKGINFO'] == b[name]['metadata']['.PKGINFO']
        identical = a[name]['sha256'] == b[name]['sha256']
        comparisons[name] = {'installed_contents_equal': equal, 'pkginfo_equal': meta,
                             'bytes_equal': identical,
                             'buildinfo_equal': a[name]['metadata']['.BUILDINFO'] == b[name]['metadata']['.BUILDINFO']}
        if not equal or not meta:
            mismatches.append(f'package content/metadata mismatch: {name}')
    return {'status': 'fail' if mismatches else 'contents-reproduced', 'errors': mismatches,
            'packages': comparisons, 'hardware_status': 'NOT RUN',
            'independence_limit': 'Distinct recorded container runs; independent machine execution is not attested.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('first', type=Path)
    parser.add_argument('second', type=Path)
    parser.add_argument('--require-bytes', action='store_true')
    args = parser.parse_args()
    try:
        result = compare(args.first, args.second)
        if args.require_bytes and any(not p['bytes_equal'] for p in result['packages'].values()):
            result['errors'].append('byte identity required but not achieved')
            result['status'] = 'fail'
        print(json.dumps(result, indent=2, sort_keys=True))
        return int(bool(result['errors']))
    except (OSError, ValueError, KeyError, IndexError, tarfile.TarError) as error:
        print(json.dumps({'status': 'fail', 'errors': [str(error)]}, indent=2))
        return 1


if __name__ == '__main__':
    sys.exit(main())
