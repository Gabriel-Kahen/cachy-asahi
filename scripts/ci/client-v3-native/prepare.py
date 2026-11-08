#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Root-only DATA source emitter; planning and recipe inspection run no actors."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

HERE = Path(__file__).resolve().parent
LANE = 'scripts/ci/client-v3-native'
WORKFLOW = '.github/workflows/native-arm-build.yml'
ROLES = {'runtime': 'cachy-asahi-repository-runtime', 'client': 'cachy-asahi-repository-client-v3'}
ORIGINAL_CARRIER = '04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd'
def PIN(path):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('ordinary source path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or not 0 < before.st_size <= 16 * 1024**2:
            raise ValueError('bounded owned single-link source required')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(before.st_size + 1)
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if len(raw) != before.st_size or key(before) != key(os.fstat(fd)) or key(before) != key(path.lstat()):
            raise ValueError('complete stable source descriptor/path required')
        return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    finally:
        os.close(fd)

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def plan(source, candidate_source=None):
    if candidate_source is not None and not re.fullmatch('[a-f0-9]{40}', candidate_source):
        raise ValueError('explicit actual Main product-source commit required')
    infrastructure = json.loads((HERE / 'infrastructure-pins.json').read_bytes())
    for name, row in infrastructure.items():
        if PIN(source / name) != row:
            raise ValueError('original infrastructure differs: ' + name)
    checks = load('client_v3_native_package_metadata', source / 'scripts/checks/package_checks.py')
    products = {}
    for role, name in ROLES.items():
        directory = source / 'packages/tools' / name
        result = checks.recipe(directory / 'PKGBUILD')
        meta = result['metadata']
        if result['errors'] or meta['pkgname'] != [name] or meta['pkgver'] != ['0.1.0'] or meta['pkgrel'] != ['1'] or meta['arch'] != ['any'] or meta['license'] != ['MIT']:
            raise ValueError('exact two local MIT any-architecture recipes required')
        if role == 'client' and meta['depends'] != ['python>=3.11', 'cachy-asahi-repository-runtime=0.1.0-1']:
            raise ValueError('exact unchanged Runtime1 dependency required')
        if any(meta.get(k) for k in ('install', 'provides', 'conflicts', 'replaces', 'backup')):
            raise ValueError('no install hooks or namespace replacement')
        files = {n: PIN(directory / n) for n in result['input_sha256']}
        if role == 'runtime':
            old = json.loads((source / 'scripts/ci/apps-cache-native/input-policy.json').read_bytes())
            payload = old['products']['runtime']['payload']
            markers = ['PASS_EXACT_THREE_HELPERS_AND_STAGE']
        else:
            checker = load('client_v3_native_payload', directory / 'check_source.py')
            payload = {n: [f, mode] for n, (f, mode) in checker.payload().items()}
            if len(payload) != 7 or checker.HELPER != PIN(directory / 'client_v3.py'):
                raise ValueError('exact new seven-file v3 payload required')
            markers = ['PASS_EXACT_CLIENT_V3_COMPANION_SOURCE_AND_PAYLOAD', 'Ran 10 tests', 'Ran 6 tests', 'OK']
        products[role] = dict(name=name, version='0.1.0-1', recipe_directory='packages/tools/' + name,
            source_sha=candidate_source, recipe_sha256=PIN(directory / 'PKGBUILD')['sha256'], source_files=files,
            payload=payload, check_markers=markers)
    old = json.loads((source / 'scripts/ci/apps-cache-native/input-policy.json').read_bytes())
    return dict(schema_version=1, status='ROOT_BOUND_FINAL_PRODUCT_SOURCES' if candidate_source else 'UNBOUND_CLIENT_V3_COMPONENT',
        purpose='CLIENT_V3_RUNTIME_FRESH_COMPONENT_V1', candidate_source=candidate_source,
        base_inventory_sha256=old['base_inventory_sha256'], helper_pins=old['helper_pins'],
        dependency=None, dependency_source=None, products=products, retained_input_carrier=None, native_source=None, actual_run=None,
        native_authority=None, resource_authority=None, version_upgrade='NOT_RUN')

def emit(source, output, candidate_source=None, carrier_source=None):
    source, output = source.resolve(), output.absolute()
    if output.exists() or not output.parent.is_dir() or output.is_relative_to(source) or any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('fresh disjoint owned Source output required')
    policy = plan(source, candidate_source)
    if candidate_source is not None:
        if not re.fullmatch('[a-f0-9]{40}', carrier_source or ''):
            raise ValueError('Root must select/reconcile a genuine physical retained-input carrier')
        carrier = json.loads((HERE / 'retained-input-carrier.json').read_bytes())
        if carrier_source != carrier['actual_commit'] or carrier['tree'] != '2c13721dbe98f520c04a18b5362669bd5000923d':
            raise ValueError('exact separately Root-qualified physical carrier required')
        policy['retained_input_carrier'] = carrier_source
        git = lambda *a: subprocess.check_output(['git', '--no-replace-objects', '-C', str(source), *a], timeout=30)
        if git('rev-parse', ORIGINAL_CARRIER + '^{tree}') != git('rev-parse', carrier_source + '^{tree}'):
            raise ValueError('physical carrier must preserve the complete original tree')
        for row in policy['products'].values():
            for name in row['source_files']:
                path = row['recipe_directory'] + '/' + name
                if git('show', candidate_source + ':' + path) != (source / path).read_bytes():
                    raise ValueError('actual selected Main recipe/body differs: ' + path)
    elif carrier_source is not None:
        raise ValueError('unbound calibration does not select a physical carrier')
    names = set(json.loads((HERE / 'infrastructure-pins.json').read_bytes()))
    for row in policy['products'].values():
        names.update(row['recipe_directory'] + '/' + n for n in row['source_files'])
    output.mkdir(mode=0o700)
    def copy(src, dst):
        dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for parent in (dst.parent, *dst.parent.parents):
            if parent == output or parent.is_relative_to(output):
                parent.chmod(0o700)
        shutil.copyfile(src, dst)
        dst.chmod(0o644)
    for name in sorted(names):
        copy(source / name, output / name)
    lane = output / LANE
    lane.mkdir(mode=0o700, parents=True, exist_ok=True)
    for path in HERE.iterdir():
        if path.is_file() and path.name not in ('source-manifest.json', 'input-policy.json', 'workflow.yml.in'):
            copy(path, lane / path.name)
    (lane / 'input-policy.json').write_text(json.dumps(policy, sort_keys=True, indent=2) + '\n')
    rows = {p.relative_to(output).as_posix(): PIN(p) for p in output.rglob('*') if p.is_file()}
    if len(rows) > 128:
        raise ValueError('held source-row cap')
    manifest = dict(schema_version=1, status='FROZEN_ROOT_FINAL_SOURCES' if candidate_source else 'SOURCE_READY_UNBOUND_CLIENT_V3_COMPONENT',
                    files=rows, native='NOT_RUN', hardware='NOT_RUN')
    (lane / 'source-manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    text = (HERE / 'workflow.yml.in').read_text().replace('@JOB_SHA256@', PIN(lane / 'job.py')['sha256']).replace('@MANIFEST_SHA256@', PIN(lane / 'source-manifest.json')['sha256'])
    text = text.replace('@RETAINED_INPUT_SOURCE@', carrier_source or 'UNBOUND_RETAINED_INPUT_CARRIER')
    target = output / WORKFLOW
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for parent in (target.parent, *target.parent.parents):
        if parent == output or parent.is_relative_to(output):
            parent.chmod(0o700)
    target.write_text(text)
    return dict(status=policy['status'], source_files=len(rows), workflow=PIN(target), native_source=None, run=None, native='NOT_RUN')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--candidate-source')
    parser.add_argument('--retained-input-source')
    args = parser.parse_args()
    print(json.dumps(emit(args.source, args.output, args.candidate_source, args.retained_input_source), sort_keys=True))
