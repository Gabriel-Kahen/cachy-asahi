#!/usr/bin/env python3
"""Prepare actual setup4 inputs; stage only through the unchanged release/client APIs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace

SOURCE = '98fecf28a3cde63a9dd7531501c2187825349310'
PACKAGE = 'c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a'
RECIPE = 'ec816728a154f77723d34e56bcbf04bb39ef436be1d883fb90c1af8d43dae31e'
BUILD_LOCK = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
BEFORE = '2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
DESIRED = 'dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac'
NAME = 'cachy-asahi-setup'
BUILD_SNAPSHOT = 'inventory-sha256-' + BUILD_LOCK
ROOT_SNAPSHOT = 'inventory-sha256:' + BEFORE


class Error(ValueError): pass


def need(ok, message):
    if not ok: raise Error(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ordinary(path, directory=False):
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink input/output parent')
    need(path.is_dir() if directory else path.is_file(), 'missing ordinary input: ' + str(path))
    return path


def load_module(root, name, relative):
    path = ordinary(root / relative)
    spec = importlib.util.spec_from_file_location('root_construction_' + name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def apis(root):
    need(not sys.flags.optimize, 'existing asserted input validators require ordinary Python, not -O')
    root = ordinary(root, directory=True)
    paths = {'release': 'scripts/release/release.py', 'client': 'scripts/client/client.py',
             'checks': 'scripts/checks/package_checks.py', 'build': 'scripts/build/build.py',
             'composition': 'scripts/ci/full-development-composition/run.py',
             'setup': 'scripts/ci/full-development-composition/setup4_inputs.py'}
    return SimpleNamespace(**{name: load_module(root, name, path) for name, path in paths.items()})


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')


def locks(root, setup):
    directory = root / 'scripts/ci/full-development-composition'
    before, desired = directory / 'expected-updater-v2.lock', directory / 'expected-setup4-v2.lock'
    need(sha(ordinary(before)) == BEFORE and sha(ordinary(desired)) == DESIRED, 'exact587 lock pins differ')
    setup.expected_lock(before.read_bytes(), desired.read_bytes())
    return before, desired, dict(line.split() for line in before.read_text().splitlines()), dict(
        line.split() for line in desired.read_text().splitlines())


def validate_base(base, expected):
    need(base.get('schema_version') == 1 and base.get('target_arch') == 'aarch64'
         and base.get('kind') == 'complete-target-transaction' and not base.get('synthetic'),
         'actual complete-target-transaction base required')
    need(base.get('snapshot_id') == ROOT_SNAPSHOT, 'root snapshot_id must identify the exact before-lock, not the build341')
    rows = base.get('packages')
    need(type(rows) is list and len(rows) == 587, 'actual root-derived587 package records required')
    need(all(type(p) is dict and p.get('arch') in ('aarch64', 'any') and
             all(type(p.get(k)) is list and all(type(x) is str for x in p[k])
                 for k in ('depend', 'provides', 'conflict', 'files')) for p in rows),
         'base requires actual architecture/dependencies/providers/conflicts/non-directory ownership')
    need(len({p.get('name') for p in rows}) == 587 and
         {p.get('name'): p.get('version') for p in rows} == expected, 'root base differs from exact updater-v2/setup3 inventory')


def blockers(spec, provenance, release):
    result = []
    try:
        release.provenance_check(provenance['package'], provenance, PACKAGE, spec)
    except release.Error as error:
        result.append('release.provenance_check: ' + str(error))
    models = spec['policy']['supported_models']
    if not models or len(set(models)) != len(models) or not set(models) <= release.MODELS:
        result.append('release.stage requires explicit M2 Air model declarations; there is no generic-native model token')
    if not spec['policy']['protected_packages']:
        result.append('release.dependency_check requires a nonempty explicit protected-package selection')
    return result


def convert_provenance(pkg, native, copied, source, deployment_snapshot):
    """Adapt actual receipt fields without substituting the deployment inventory."""
    return {'schema_version': 1, 'artifact_sha256': PACKAGE,
        'package': {'name': NAME, 'version': '0.1.0-4', 'arch': pkg['arch'][0]},
        'source_commit': SOURCE, 'recipe_sha256': RECIPE, 'licenses': pkg['license'],
        'sources': [{'url': source['project_url'] + '/tree/' + SOURCE, 'commit': SOURCE}],
        'build': {'execution': 'native', 'architecture': 'aarch64', 'environment': native['image_id'],
                  'snapshot_id': BUILD_SNAPSHOT, 'inventory_sha256': BUILD_LOCK, 'inventory_count': 341},
        'retained_pair': {'attempt1_sha256': copied['native-build-1.json'],
                          'attempt2_sha256': copied['native-build-2.json'], 'new_build': 'NOT RUN'},
        'deployment_snapshot_id': deployment_snapshot}


def inspect_package(args, api=None):
    """Validate the actual retained text-only xz pair without signing or execution."""
    api = api or apis(ordinary(args.source_root, directory=True))
    need((api.setup.SOURCE, api.setup.PACKAGE, api.setup.RECIPE, api.composition.BASE) ==
         (SOURCE, PACKAGE, RECIPE, BUILD_LOCK), 'existing setup4 validator pins differ')
    pair = ordinary(args.setup4_pair, directory=True)
    try:
        retained, report, payload = api.setup.retained_pair(pair, api.checks, api.build, api.composition)
    except AssertionError as error:
        raise Error('retained actual setup4 pair refused: ' + str(error)) from None
    package, native = ordinary(args.package), ordinary(args.provenance)
    need(package.stat().st_size == 22632 and sha(package) == PACKAGE == sha(retained), 'actual setup4 archive differs')
    need(sha(native) == sha(pair / 'build-1/provenance.json'), 'explicit native provenance differs from retained attempt1')
    build_lock = ordinary(pair / 'build-1/expected-packages.lock')
    need(sha(build_lock) == BUILD_LOCK and len(build_lock.read_text().splitlines()) == 341, 'actual build341 inventory differs')
    return SimpleNamespace(pair=pair, retained=retained, report=report, payload=payload,
        package=package, native=native, native_record=api.client.decode(native.read_bytes()), build_lock=build_lock)


def prepare(args, *, base=None, protected=None, output=None):
    """Data inspection/copy only: never sign, run repo-add, or alter a target root."""
    root = ordinary(args.source_root, directory=True); api = apis(root)
    before, desired, expected, target = locks(root, api.setup)
    base_path = ordinary(base if base is not None else args.base_manifest)
    base_record = api.client.decode(base_path.read_bytes()); validate_base(base_record, expected)
    held = inspect_package(args, api)
    pair, retained, package, native, build_lock = held.pair, held.retained, held.package, held.native, held.build_lock
    protected = list(protected if protected is not None else getattr(args, 'protected_packages', []))
    need(len(set(protected)) == len(protected) and set(protected) <= set(expected) and NAME not in protected,
         'protected package selection differs from actual root')
    signer = api.release.fingerprint(args.signer)
    rid, repo = api.release.valid_name(args.release_id), api.release.valid_name(args.repo_name)
    out = Path(output if output is not None else args.output).absolute()
    ordinary(out.parent, directory=True)
    need(not out.exists() and not out.is_symlink(), 'fresh construction output required')
    out.mkdir(mode=0o700); inputs = out / 'inputs'; inputs.mkdir(mode=0o700)
    copied = {}
    for name, path in [('base.json', base_path), ('before.lock', before), ('desired.lock', desired),
                       (retained.name, package), ('native-build-1.json', native),
                       ('native-build-2.json', pair / 'build-2/provenance.json'), ('build341.lock', build_lock),
                       ('LICENSE', pair / 'build-1/inputs/LICENSE'),
                       ('source-provenance.json', pair / 'build-1/inputs/source-provenance.json')]:
        source = ordinary(path); shutil.copyfile(source, inputs / name); copied[name] = sha(inputs / name)
    pkg = held.report['metadata']['.PKGINFO']
    original = api.client.decode((inputs / 'source-provenance.json').read_bytes())
    provenance = convert_provenance(pkg, held.native_record, copied, original, base_record['snapshot_id'])
    write(inputs / 'provenance.json', provenance)
    ref = lambda name: {'path': name, 'sha256': sha(inputs / name)}
    spec = {'schema_version': 1, 'release_id': rid, 'repo_name': repo, 'synthetic': False,
        'target_arch': 'aarch64', 'source_commit': SOURCE,
        'base': dict(ref('base.json'), snapshot_id=base_record['snapshot_id']),
        'packages': [{'artifact': ref(retained.name), 'provenance': ref('provenance.json')}],
        'policy': {'supported_models': list(getattr(args, 'supported_models', [])), 'selected_packages': [NAME],
                   'protected_packages': protected,
                   'coordinated_sets': [{'name': 'exact-desired587', 'versions': target}]},
        'project_license': dict(ref('LICENSE'), spdx='MIT'),
        'evidence': [dict(ref(name), id=name) for name in ('before.lock', 'desired.lock', 'build341.lock',
                     'native-build-1.json', 'native-build-2.json', 'source-provenance.json')]}
    write(inputs / 'spec.json', spec)
    receipt = {'status': 'PREPARED', 'source_root': str(root), 'output': str(out), 'spec': str(inputs / 'spec.json'),
        'base': str(inputs / 'base.json'), 'provenance': str(inputs / 'provenance.json'),
        'package': str(inputs / retained.name), 'signer': signer, 'release_id': rid, 'repo_name': repo,
        'base_snapshot_id': base_record['snapshot_id'], 'build_snapshot_id': BUILD_SNAPSHOT,
        'before_sha256': BEFORE, 'desired_sha256': DESIRED, 'package_sha256': PACKAGE,
        'payload_files': len(held.payload), 'native_pair': 'MATCHED', 'stage_blockers': blockers(spec, provenance, api.release),
        'hardware': 'NOT RUN', 'source_completeness_accepted': False, 'publication': 'NOT ACCEPTED'}
    write(out / 'construction.json', receipt)
    return receipt


def stage(args, *, prepared):
    """Future actor path: unchanged stage/verify/build/sign APIs, never promote."""
    api = apis(Path(prepared['source_root']))
    spec_path = ordinary(prepared['spec']); spec = api.client.decode(spec_path.read_bytes())
    provenance = api.client.decode(ordinary(prepared['provenance']).read_bytes())
    blocked = blockers(spec, provenance, api.release)
    if blocked:
        return dict(prepared, status='REFUSED_API_CONTRACT', stage_blockers=blocked)
    base_path = api.release.file_ref(spec_path.parent, spec['base'])
    _, _, expected, _ = locks(Path(prepared['source_root']), api.setup)
    validate_base(api.client.decode(base_path.read_bytes()), expected)
    need(spec['source_commit'] == SOURCE and spec['base']['snapshot_id'] == ROOT_SNAPSHOT
         and provenance['source_commit'] == SOURCE and provenance['artifact_sha256'] == PACKAGE
         and provenance['recipe_sha256'] == RECIPE and provenance['build']['snapshot_id'] == BUILD_SNAPSHOT
         and provenance['build']['inventory_sha256'] == BUILD_LOCK
         and provenance['build']['inventory_count'] == 341
         and provenance['deployment_snapshot_id'] == ROOT_SNAPSHOT, 'prepared actual build/deployment provenance changed')
    out = ordinary(prepared['output'], directory=True)
    storage = out / 'repository'; storage.mkdir(mode=0o700)
    key = api.release.fingerprint(prepared['signer'])
    env = api.release.gpg_env(args.gpg_home, storage)
    with api.release.locked(storage):
        staged = api.release.stage(SimpleNamespace(spec=str(spec_path)), storage, key, env)
        bundle = Path(staged['path'])
        api.release.verify_release(bundle, key, env)
    metadata = out / 'metadata.json'
    envelope = api.client.build(SimpleNamespace(bundle=str(bundle), output=str(metadata), signer=key,
        namespace=args.namespace, sequence=args.sequence, issued_utc=args.issued_utc, expires_utc=args.expires_utc))
    api.release.sign(metadata, key, env)
    public = api.release.run(['gpg', '--batch', '--export', key], env=env)
    need(public, 'TEST public key export empty')
    keyring = out / 'TEST-public.gpg'
    with keyring.open('xb') as stream: stream.write(public)
    result = dict(prepared, status='SIGNED_DEVELOPMENT_CONSTRUCTION', bundle=str(bundle), metadata=str(metadata),
        signature=str(metadata) + '.sig', public_keyring=str(keyring), stage_result=staged, envelope_result=envelope)
    write(out / 'staged-construction.json', result)
    return result


def construct(args, *, base, protected, output):
    prepared = prepare(args, base=base, protected=protected, output=output)
    return stage(args, prepared=prepared)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'construct'))
    for name in ('source-root', 'base-manifest', 'setup4-pair', 'package', 'provenance', 'gpg-home', 'signer',
                 'output', 'release-id', 'repo-name', 'namespace', 'issued-utc', 'expires-utc'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--sequence', type=int, required=True)
    parser.add_argument('--protected-packages', action='append', default=[])
    parser.add_argument('--supported-models', action='append', default=[])
    args = parser.parse_args()
    result = prepare(args) if args.operation == 'prepare' else construct(
        args, base=Path(args.base_manifest), protected=args.protected_packages, output=Path(args.output))
    print(json.dumps(result, sort_keys=True))
    return 2 if result.get('stage_blockers') else 0


if __name__ == '__main__':
    raise SystemExit(main())
