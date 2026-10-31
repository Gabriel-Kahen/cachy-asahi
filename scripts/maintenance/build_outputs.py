#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect completed native rebuild pairs and write a local content-addressed candidate."""
import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import subprocess
import sys
import tempfile

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'scripts/build/build.py').is_file())
MAX_JSON = 16 * 1024**2
MAX_ARCHIVE = 512 * 1024**2
MAX_FILES = 65536
MAX_PACKAGES = 256
HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9@_+][A-Za-z0-9@_.+-]{0,127}\Z')
IMAGE = re.compile(r'(?:[A-Za-z0-9][A-Za-z0-9._:/-]*@)?sha256:[0-9a-f]{64}\Z')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path):
    path = Path(os.path.abspath(path))
    need(path == path.resolve() and path.is_file(), 'regular nonsymlink file required: ' + str(path))
    return path


def directory(path):
    path = Path(os.path.abspath(path))
    need(path == path.resolve() and path.is_dir(), 'nonsymlink directory required: ' + str(path))
    return path


def digest(path):
    value = hashlib.sha256()
    with regular(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            value.update(block)
    return value.hexdigest()


def read(path):
    with regular(path).open('rb') as stream:
        raw = stream.read(MAX_JSON + 1)
    need(len(raw) <= MAX_JSON, 'JSON byte bound')
    return raw


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('JSON floats/nonfinite numbers forbidden')
    result = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(result) is dict, 'JSON object required')
    return result


def fields(row, keys):
    need(type(row) is dict and set(row) == set(keys.split()), 'unexpected/missing fields: ' + keys)


def checksum(value):
    need(type(value) is str and HEX.fullmatch(value), 'SHA-256 required')
    return value


def named(value):
    need(type(value) is str and NAME.fullmatch(value), 'invalid name')
    return value


def relative(value):
    need(type(value) is str and value and '\\' not in value and '\x00' not in value, 'unsafe relative path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix() == value and not any(p in ('.', '..') for p in path.parts), 'unsafe relative path')
    return value


def selected(row):
    fields(row, 'path sha256')
    raw = read(row['path'])
    need(sha(raw) == checksum(row['sha256']), 'selected input checksum mismatch: ' + str(row['path']))
    return decode(raw)


def snapshot(path):
    path = directory(path)
    result = {}
    for item in path.rglob('*'):
        need(not item.is_symlink(), 'symlink evidence forbidden')
        if item.is_file():
            result[str(item.relative_to(path))] = digest(item)
        else:
            need(item.is_dir(), 'special evidence forbidden')
        need(len(result) <= MAX_FILES, 'evidence file count bound')
    return result


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILD = load_module('output_reviewed_build', ROOT / 'scripts/build/build.py')
TOOLS = ('scripts/build/build.py', 'scripts/checks/package_checks.py')


def child_limits():
    # The existing inspector never extracts files or runs package code. Bound its
    # memory, CPU and report size as well as its existing uncompressed-size cap.
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_JSON, MAX_JSON))


def inspect_archive(path, expected_sha):
    path = regular(path)
    need(0 < path.stat().st_size <= MAX_ARCHIVE, 'archive byte bound')
    need(digest(path) == checksum(expected_sha), 'archive checksum mismatch')
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/checks/package_checks.py'),
            'artifacts', str(path)], stdout=out, stderr=err, timeout=90, preexec_fn=child_limits)
        out.seek(0); raw = out.read(MAX_JSON + 1)
        need(len(raw) <= MAX_JSON, 'inspection report byte bound')
        need(result.returncode == 0, 'archive inspection failed: ' + raw[:1000].decode(errors='replace'))
    # Reports contain mtime numbers; the inspector is trusted, unlike input JSON.
    report = json.loads(raw)['artifacts'][0]
    need(report['sha256'] == expected_sha and not report['errors'], 'archive inspection/checksum failed')
    need(len(report['members']) <= 32768, 'archive member count bound')
    need(digest(path) == expected_sha, 'archive changed during inspection')
    return report


def source_tables(source):
    need(source.get('schema_version') == 1 and type(source['schema_version']) is int, 'source schema')
    tables = []
    for key, identity in (('packages', 'name'), ('sources', 'id'), ('build_dependencies', 'package')):
        rows = source[key]
        need(type(rows) is list and 0 < len(rows) <= 4096, 'finite source table required')
        table = {}
        for row in rows:
            need(type(row) is dict, 'source table row object required')
            name = named(row[identity])
            need(name not in table, 'duplicate source table identity: ' + name)
            table[name] = row
        tables.append(table)
    return tables


def build_evidence(path, expected_tree=None):
    """Reinspect retained build inputs and output bytes; no original recipe path needed."""
    path = directory(path)
    tree = snapshot(path)
    if expected_tree is not None:
        need(tree == expected_tree, 'completed output snapshot changed')
    record = decode(read(path / 'provenance.json'))
    need(record.get('schema_version') == 1 and type(record['schema_version']) is int and
         record.get('status') == 'built-package-static-pass' and record.get('exit_code') == 0,
         'successful build provenance required')
    need(record.get('mode') == 'native' and record.get('builder_host_arch') in ('arm64', 'aarch64'), 'native aarch64 result required')
    need(type(record.get('image')) is str and IMAGE.fullmatch(record['image']) and
         re.fullmatch(r'sha256:[0-9a-f]{64}', record.get('image_id', '')), 'pinned image and image ID required')
    need(record.get('network') == 'none', 'offline build record required')
    need(not record['image'].startswith('sha256:') or record['image'] == record['image_id'], 'image ID differs from selected local image')
    need(re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', record.get('clean_environment_id', '')), 'clean environment identity required')
    need(type(record.get('files')) is dict and record['files'], 'build files missing')
    for name, value in record['files'].items():
        need(tree.get(relative(name)) == checksum(value), 'build evidence checksum mismatch: ' + name)
    required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
        'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
        'artifacts/makepkg.conf', 'artifacts/pacman.conf'}
    need(required <= set(record['files']), 'build evidence incomplete')
    need(type(record.get('recipe_inputs')) is dict and 'PKGBUILD' in record['recipe_inputs'], 'recipe inputs missing')
    need(snapshot(path / 'inputs') == record['recipe_inputs'], 'retained recipe snapshot mismatch')
    recipe = BUILD.recipe(path / 'inputs/PKGBUILD')
    need(not recipe['errors'] and recipe['input_sha256'] == record['recipe_inputs'] and
         recipe['metadata'] == record['recipe_metadata'], 'retained recipe metadata mismatch')
    BUILD.bind_generated(record['recipe_metadata'], BUILD.metadata((path / 'artifacts/generated.SRCINFO').read_text()))
    lock = read(path / 'expected-packages.lock')
    need(sha(lock) == record.get('expected_packages_sha256') and read(path / 'artifacts/packages.lock') == lock, 'builder package lock mismatch')
    lines = lock.decode().splitlines()
    parts = [line.split(' ') for line in lines]
    need(lines and lock.endswith(b'\n') and lines == sorted(lines) and all(len(p) == 2 and all(p) for p in parts)
         and len({p[0] for p in parts}) == len(parts), 'malformed builder package lock')
    need(decode(read(path / 'validation.json')).get('errors') == [], 'recorded validation failure')
    artifacts = record.get('artifacts')
    need(type(artifacts) is dict and len(artifacts) == 1, 'single-package artifact completeness required')
    actual = {p.name for p in (path / 'artifacts').glob('*.pkg.tar.*') if not p.name.endswith('.sig')}
    need(actual == set(artifacts), 'unexpected/missing archive')
    filename, value = next(iter(artifacts.items()))
    need(relative(filename) == filename and '/' not in filename, 'artifact basename required')
    need(record['files'].get('artifacts/' + filename) == value, 'artifact absent from sealed evidence')
    report = inspect_archive(path / 'artifacts' / filename, value)
    installed = report['metadata']['.BUILDINFO'].get('installed', [])
    need(len(installed) == len(parts) and len(set(installed)) == len(installed), 'BUILDINFO dependency inventory incomplete/duplicate')
    used = set()
    for name, version in parts:
        stem = name + '-' + version
        matches = set(installed) & {stem, stem + '-aarch64', stem + '-any'}
        need(len(matches) == 1 and not (matches & used), 'BUILDINFO dependency inventory differs from package lock')
        used.update(matches)
    need(used == set(installed), 'BUILDINFO unexpected dependency inventory')
    need(not BUILD.bind_artifact(record['recipe_metadata'], report, record['recipe_inputs']['PKGBUILD']), 'archive differs from recipe metadata')
    need(snapshot(path) == tree, 'build evidence changed during inspection')
    return record, report, tree


def batch_open(row, stack, source_sha):
    fields(row, 'id path admission_sha256 state_sha256')
    named(row['id'])
    path = directory(row['path'])
    lock = stack.enter_context(regular(path / '.lock').open('rb'))
    try:
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        raise ValueError('batch is still owned by a runner/builder') from None
    admission = selected(dict(path=str(path / 'admission.json'), sha256=row['admission_sha256']))
    state = selected(dict(path=str(path / 'state.json'), sha256=row['state_sha256']))
    token = sha(encoded(admission))
    need(token == row['admission_sha256'] and state.get('admission_sha256') == token and
         read(path / '.build-batch-owner') == (token + '\n').encode(), 'batch admission/owner mismatch')
    need(type(admission.get('schema_version')) is int and admission['schema_version'] == 1 and admission.get('status') == 'ADMISSION_ONLY_NOT_BUILT' and
         admission.get('input_sha256') == source_sha, 'batch source/admission mismatch')
    need(type(state.get('schema_version')) is int and state['schema_version'] == 1 and state.get('kind') == 'PINNED_OCI_BUILD_PY', 'production batch evidence required')
    need(type(admission.get('tasks')) is dict and type(admission.get('groups')) is list and
         type(state.get('packages')) is dict, 'batch task/group/checkpoint objects required')
    need(all(type(p) is dict for p in state['packages'].values()), 'package checkpoint object required')
    statuses = {name: p['status'] for name, p in state['packages'].items()}
    need(state.get('status') == 'COMPLETE' and statuses and all(s == 'SUCCESS' for s in statuses.values()),
         'incomplete batch: ' + json.dumps(statuses, sort_keys=True))
    planned = admission['planned_packages']
    need(type(planned) is list and len(planned) == len(set(planned)) and len(planned) <= MAX_PACKAGES and
         set(planned) == set(admission['tasks']) == set(statuses), 'batch task coverage mismatch')
    need(all(type(g) is dict for g in admission['groups']), 'group object required')
    need(not admission.get('global_holds') and all(not g['held'] for g in admission['groups']), 'batch planner holds remain')
    need(not state.get('cleanup_errors'), 'batch cleanup uncertainty remains')
    need(type(admission.get('max_attempts')) is int and 1 <= admission['max_attempts'] <= 10, 'finite attempt bound required')
    for name, task in admission['tasks'].items():
        named(name)
        need(type(task) is dict, 'task object required')
        need(task['package'] == name and task['mode'] == 'native', 'batch task identity/mode mismatch')
        history = state['packages'][name]['attempts']
        need(type(history) is list and 0 < len(history) <= admission['max_attempts'] <= 10, 'invalid attempt history')
        for i, attempt in enumerate(history, 1):
            need(attempt['output'] == f'{name}/attempt-{i:03d}/build', 'attempt output identity mismatch')
            allowed = ('SUCCESS',) if i == len(history) else ('FAILED', 'INTERRUPTED')
            need(attempt['status'] in allowed, 'unresolved/duplicate successful attempt')
        need(history[-1].get('exit_code') == 0, 'successful attempt exit code required')
    return path, admission, state


def task_result(batch, name, source, sources, build_deps):
    path, admission, state = batch
    task = admission['tasks'][name]
    attempt = state['packages'][name]['attempts'][-1]
    output = path / attempt['output']
    record, report, tree = build_evidence(output, attempt['files'])
    need(attempt['artifact_sha256'] == report['sha256'], 'attempt archive checksum mismatch')
    for key in ('image', 'mode', 'source_date_epoch', 'recipe_inputs', 'expected_packages_sha256'):
        need(record.get(key) == task.get(key), 'task/build identity mismatch: ' + key)
    raw = read(output.parent / 'reviewed_inputs.reviewed')
    need(sha(raw) == task['reviewed_inputs_sha256'] and decode(raw) == record['recipe_inputs'], 'task reviewed-input binding mismatch')
    need(digest(output.parent / 'expected_packages.reviewed') == task['expected_packages_sha256'], 'task lock binding mismatch')
    entry = [v for k, v in admission.get('implementation', {}).items() if k.endswith('/scripts/build/container-entry.sh')]
    need(entry == [record.get('entry_script_sha256')], 'admitted container entry identity mismatch')
    metadata = BUILD.normalize_metadata(record['recipe_metadata'])
    pkg = report['metadata']['.PKGINFO']
    need(pkg['pkgname'] == [name] and pkg['pkgver'] == [source['version']] and pkg['arch'] == [source['arch']], 'source package identity mismatch')
    for actual, expected in ((metadata['depends'], source.get('depend', [])),
            (metadata['provides'], source.get('provides', [])),
            (metadata['makedepends'], build_deps['makedepend']), (metadata['checkdepends'], build_deps['checkdepend'])):
        need(sorted(actual) == sorted(expected), 'source dependency metadata mismatch')
    src = sources[build_deps['source_id']]
    need(src['recipe_sha256'] == record['recipe_inputs']['PKGBUILD'], 'source recipe hash mismatch')
    pins = []
    for url, value in zip(metadata['source'], metadata['sha256sums']):
        url = url.split('::', 1)[-1]
        pins.append(dict(url=url, commit=url.rsplit('#commit=', 1)[-1]) if url.startswith('git+') else dict(url=url, sha256=value))
    need(pins == [{k: v for k, v in p.items() if k in ('url', 'commit', 'sha256')} for p in src['sources']], 'source descriptor mismatch')
    return record, report, dict(batch_path=str(path), output=attempt['output'], attempts=state['packages'][name]['attempts'],
        task_sha256=sha(encoded(task)), provenance_sha256=tree['provenance.json'], clean_environment_id=record['clean_environment_id'], files=tree)


def candidate(spec_path, spec_sha):
    spec_path = regular(spec_path)
    spec = selected(dict(path=str(spec_path), sha256=spec_sha))
    fields(spec, 'schema_version purpose synthetic input batches pairs')
    need(type(spec['schema_version']) is int and spec['schema_version'] == 1 and
         spec['purpose'] == 'local-build-output-candidate' and type(spec['synthetic']) is bool, 'candidate schema/purpose/synthetic required')
    source = selected(spec['input'])
    packages, sources, build_deps = source_tables(source)
    need(type(spec['batches']) is list and 2 <= len(spec['batches']) <= MAX_PACKAGES * 2, 'finite independent batch list required')
    need(type(spec['pairs']) is list and 0 < len(spec['pairs']) <= MAX_PACKAGES, 'finite rebuild pair list required')
    tools = {p: digest(ROOT / p) for p in TOOLS}
    tools['build_outputs.py'] = digest(__file__)
    with ExitStack() as stack:
        batches = {}; paths = set()
        for row in spec['batches']:
            named(row['id'])
            need(row['id'] not in batches, 'duplicate batch ID')
            batch = batch_open(row, stack, spec['input']['sha256'])
            need(batch[0] not in paths, 'duplicate batch directory')
            paths.add(batch[0]); batches[row['id']] = batch
        consumed = set(); results = []; names = set(); environments = set(); reports = []
        for pair in spec['pairs']:
            fields(pair, 'package first second')
            name = named(pair['package'])
            need(name not in names and name in packages and name in build_deps, 'duplicate/unknown pair package')
            names.add(name)
            need(pair['first'] != pair['second'] and all(pair[k] in batches for k in ('first', 'second')), 'different selected batches required')
            evidence = []
            for side in ('first', 'second'):
                bid = pair[side]; batch = batches[bid]
                need(name in batch[1]['tasks'] and (bid, name) not in consumed, 'missing/duplicate pair task')
                consumed.add((bid, name))
                record, report, binding = task_result(batch, name, packages[name], sources, build_deps[name])
                need(record['clean_environment_id'] not in environments, 'distinct clean environment IDs required')
                environments.add(record['clean_environment_id']); evidence.append((record, report, binding))
            left, right = evidence
            for key in ('image', 'image_id', 'mode', 'source_date_epoch', 'recipe_inputs', 'recipe_metadata', 'expected_packages_sha256', 'entry_script_sha256'):
                need(key in left[0] and left[0][key] == right[0].get(key), 'independent rebuild input mismatch: ' + key)
            need(left[0]['artifacts'] == right[0]['artifacts'], 'independent rebuild bytes differ')
            reports.append(left[1])
            filename = left[1]['artifact']; record = left[0]
            results.append(dict(name=name, version=packages[name]['version'], arch=packages[name]['arch'],
                filename=filename, sha256=left[1]['sha256'], bytes=(Path(left[2]['batch_path']) / left[2]['output'] / 'artifacts' / filename).stat().st_size,
                artifact_path=str(Path(left[2]['batch_path']) / left[2]['output'] / 'artifacts' / filename),
                source=sources[build_deps[name]['source_id']], recipe_inputs=record['recipe_inputs'],
                image=record['image'], image_id=record['image_id'], source_date_epoch=record['source_date_epoch'],
                expected_packages_sha256=record['expected_packages_sha256'], metadata=left[1]['metadata'],
                review=left[1]['review'], rebuilds=[x[2] for x in evidence], bytes_equal=True))
        need(consumed == {(bid, name) for bid, batch in batches.items() for name in batch[1]['tasks']}, 'pair coverage omits completed tasks')
        need(not BUILD.conflicts(reports), 'candidate packages have conflicting installed paths')
        for result in results:
            for build in result['rebuilds']:
                need(snapshot(Path(build['batch_path']) / build['output']) == build['files'], 'build evidence changed before candidate completion')
        for row in spec['batches']:
            selected(dict(path=str(Path(row['path']) / 'state.json'), sha256=row['state_sha256']))
            selected(dict(path=str(Path(row['path']) / 'admission.json'), sha256=row['admission_sha256']))
        selected(spec['input']); selected(dict(path=str(spec_path), sha256=spec_sha))
        need(tools == {**{p: digest(ROOT / p) for p in TOOLS}, 'build_outputs.py': digest(__file__)}, 'inspector implementation drift')
    return dict(schema_version=1, status='SYNTHETIC_LOCAL_CANDIDATE' if spec['synthetic'] else 'LOCAL_BUILD_OUTPUT_CANDIDATE',
        synthetic=spec['synthetic'], authenticated=False, selection_sha256=spec_sha, input=spec['input'],
        batches=spec['batches'], implementation=tools, packages=sorted(results, key=lambda p: p['name']),
        batch_task_coverage='COMPLETE', full_overlay_accepted=False, dependency_solution='NOT_ESTABLISHED',
        source_delivery='NOT_CHECKED', licensing_approval='NOT_ESTABLISHED', installed='NOT RUN',
        hardware_status='NOT RUN', signed=False, staged=False, published=False,
        independence_limit='Distinct recorded clean container IDs; independent machines/authenticated execution not attested.')


def store(result, output):
    raw = encoded(result)
    need(len(raw) <= MAX_JSON, 'candidate JSON byte bound')
    output = directory(output)
    need(not any(output == Path(b['path']).resolve() or output.is_relative_to(Path(b['path']).resolve())
                 for b in result['batches']), 'candidate output overlaps retained batch')
    path = output / (sha(raw) + '.json')
    # Atomic create-if-absent; an existing digest name is checked, never replaced.
    with tempfile.NamedTemporaryFile(dir=output, prefix='.candidate-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                need(read(path) == raw, 'content-addressed candidate collision')
        finally:
            temporary.unlink()
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('candidate')
    p.add_argument('--spec', type=Path, required=True)
    p.add_argument('--spec-sha256', required=True)
    p.add_argument('--output', type=Path, required=True, help='existing local manifest directory')
    p = sub.add_parser('inspect-build', help='offline replay only; never creates a batch candidate')
    p.add_argument('--build', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'candidate':
            result = candidate(args.spec, args.spec_sha256)
            path = store(result, args.output)
            print(json.dumps(dict(status=result['status'], path=str(path), sha256=path.stem), sort_keys=True))
        else:
            record, report, _ = build_evidence(args.build)
            print(json.dumps(dict(status='RETAINED_BUILD_REINSPECTED', candidate=False, authenticated=False,
                package=report['metadata']['.PKGINFO'], sha256=report['sha256'],
                clean_environment_id=record['clean_environment_id'], hardware_status='NOT RUN'), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UnicodeError, subprocess.SubprocessError, RecursionError) as error:
        print('build outputs: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
