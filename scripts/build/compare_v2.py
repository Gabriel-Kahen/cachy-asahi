#!/usr/bin/env python3
"""Version 2: verify evidence before comparing two independently created build records."""
import argparse
import json
import re
import sys
import tarfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'checks'))
from package_checks import digest, metadata, package, recipe, PACKAGE_METADATA
from build_v2 import bind_artifact, bind_generated


# The container entry writes pacman -Q in C sort order.
LOCK_ROW = re.compile(r'([A-Za-z0-9_+@][A-Za-z0-9._+@-]*) (?:[0-9]+:)?[^\s:/\x00-\x1f\x7f-]+-[0-9]+(?:\.[0-9]+)?')


def verify_inventory(path):
    lock = path.read_bytes().decode('utf-8')
    if not lock.strip():
        raise ValueError(f'{path}: expected package lock is empty')
    previous = ''
    for line in lock.removesuffix('\n').split('\n'):
        match = LOCK_ROW.fullmatch(line)
        if not match:
            raise ValueError(f'{path}: invalid pacman -Q inventory row: {line[:100]!r}')
        name = match[1]
        if name <= previous:
            raise ValueError(f'{path}: pacman -Q inventory must be sorted with unique package names')
        previous = name
    if not lock.endswith('\n'):
        raise ValueError(f'{path}: pacman -Q inventory must end with a newline')


def srcinfo_lines(path):
    # glibc C.UTF-8 [[:space:]], as used by the builder's sed filter.
    space = ' \t\r\v\f\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2008\u2009\u200a\u2028\u2029\u205f\u3000'
    return [line for line in path.read_bytes().decode('utf-8').split('\n')
            if (body := line.lstrip(space)) and not body.startswith('#')]


def verify(path):
    path = Path(path).resolve()
    record = json.loads((path / 'provenance.json').read_text())
    if not isinstance(record, dict):
        raise ValueError('provenance must be an object')
    if record.get('status') != 'built-package-static-pass':
        raise ValueError(f'{path}: build has not passed')
    if type(record.get('exit_code')) is not int or record['exit_code'] != 0:
        raise ValueError(f'{path}: zero build exit code required')
    if record.get('network') not in ('none', 'bridge'):
        raise ValueError(f'{path}: recorded build network must be none or bridge')
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
    expected_lock = record['files']['expected-packages.lock']
    if record.get('expected_packages_sha256') != expected_lock:
        raise ValueError(f'{path}: recorded expected package lock checksum differs')
    if record['files']['artifacts/packages.lock'] != expected_lock:
        raise ValueError(f'{path}: observed builder package lock differs from expected lock')

    verify_inventory(path / 'expected-packages.lock')

    inputs = path / 'inputs'
    if inputs.is_symlink():
        raise ValueError(f'{path}: recipe snapshot must be a directory within the evidence')
    snapshot = recipe(inputs / 'PKGBUILD')
    if snapshot['input_sha256'] != record['recipe_inputs']:
        raise ValueError(f'{path}: changed recipe snapshot')
    if snapshot['errors']:
        raise ValueError(f"{path}: recipe snapshot fails builder preflight: {snapshot['errors']}")
    if snapshot['metadata'] != record.get('recipe_metadata'):
        raise ValueError(f'{path}: recorded recipe metadata differs from recipe snapshot')
    generated_path = path / 'artifacts/generated.SRCINFO'
    try:
        generated = metadata(generated_path.read_text())
        if len(generated.get('pkgbase', [])) != 1 or not generated['pkgbase'][0]:
            raise ValueError('single nonempty pkgbase required')
        bind_generated(snapshot['metadata'], generated)
    except ValueError as error:
        raise ValueError(f'{generated_path}: {error}') from error
    if '.SRCINFO' in snapshot['input_sha256'] and srcinfo_lines(inputs / '.SRCINFO') != srcinfo_lines(generated_path):
        raise ValueError(f'{generated_path}: differs from reviewed .SRCINFO')

    actual = {p.name for p in (path / 'artifacts').glob('*.pkg.tar.*') if not p.name.endswith('.sig')}
    if actual != set(record['artifacts']):
        raise ValueError(f'{path}: unexpected/missing artifact set')
    if len(actual) != 1:
        raise ValueError(f'{path}: single-package recipe must produce exactly one artifact')
    name, checksum = next(iter(record['artifacts'].items()))
    item = path / 'artifacts' / name
    if record['files'].get(f'artifacts/{name}') != checksum or item.is_symlink():
        raise ValueError(f'{path}: artifact missing/changed in evidence closure: {name}')
    report = package(item)
    if report['sha256'] != checksum:
        raise ValueError(f'{path}: artifact checksum mismatch {name}')
    if report['errors']:
        raise ValueError(f'{path}: artifact validation failed {name}')
    errors = bind_artifact(snapshot['metadata'], report, snapshot['input_sha256']['PKGBUILD'])
    if errors:
        raise ValueError(f'{path}: recorded artifact no longer matches reviewed metadata: {errors}')

    validation_path = path / 'validation.json'
    try:
        validation = json.loads(validation_path.read_text())
    except ValueError as error:
        raise ValueError(f'{validation_path}: {error}') from error
    expected = {'artifacts': [report], 'errors': []}
    # Compare JSON values without Python's bool/int coercion.
    if json.dumps(validation, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError(f'{validation_path}: recorded validation differs from archive inspection')
    return record, {name: report}


def compare(first, second):
    if Path(first).resolve() == Path(second).resolve():
        raise ValueError('second build must be a different evidence directory')
    left, a = verify(first)
    right, b = verify(second)
    mismatches = []
    if not left.get('clean_environment_id') or not right.get('clean_environment_id') or left['clean_environment_id'] == right['clean_environment_id']:
        mismatches.append('different recorded clean container IDs required')
    for key in ('image', 'image_id', 'mode', 'network', 'source_date_epoch', 'recipe_inputs',
                'recipe_metadata', 'expected_packages_sha256', 'entry_script_sha256'):
        if key not in left or key not in right or left[key] != right[key]:
            mismatches.append(f'input mismatch: {key}')
    if left.get('source_material') != right.get('source_material'):
        mismatches.append('input mismatch: source_material')
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
