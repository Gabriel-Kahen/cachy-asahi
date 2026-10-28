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

SOURCE = '135b8fb21941d0ea27da7d34b1fc7b9eb0939ee8'
PACKAGE = '319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'
RECIPE = '87f68df2e31b73f04ab1c96609cc2268b6251dd242de6080920e17c4fe90ce31'
BUILD_LOCK = '66c46d4645fa443d23df0e97765905555fe5bc2607787dca3f30ee2084cf597f'
BEFORE = '72818a8a2ae488281b08486b92c435ec244ef3b5313f23b97473d1684ecb68b4'
DESIRED = 'be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5'
NAME = 'cachy-asahi-apps'
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
    helper=load_module(root,'apps6_selected','scripts/ci/latest607-updater/selected_package.py')
    return helper.locks(root)


def validate_base(base, expected):
    need(base.get('schema_version') == 1 and base.get('target_arch') == 'aarch64'
         and base.get('kind') == 'complete-target-transaction' and not base.get('synthetic'),
         'actual complete-target-transaction base required')
    need(base.get('snapshot_id') == ROOT_SNAPSHOT, 'root snapshot_id must identify the exact before-lock, not the build574')
    rows = base.get('packages')
    need(type(rows) is list and len(rows) == 607, "actual root-derived604 package records required")
    need(all(type(p) is dict and p.get('arch') in ('aarch64', 'any') and
             all(type(p.get(k)) is list and all(type(x) is str for x in p[k])
                 for k in ('depend', 'provides', 'conflict', 'files')) for p in rows),
         'base requires actual architecture/dependencies/providers/conflicts/non-directory ownership')
    need(len({p.get('name') for p in rows}) == 607 and
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
        'package': {'name': NAME, 'version': '0.1.0-16', 'arch': pkg['arch'][0]},
        'source_commit': SOURCE, 'recipe_sha256': RECIPE, 'licenses': pkg['license'],
        'sources': [{'url': pkg['url'][0] + '/tree/' + SOURCE, 'commit': SOURCE}],
        'build': {'execution': 'native', 'architecture': 'aarch64', 'environment': native['image_id'],
                  'snapshot_id': BUILD_SNAPSHOT, 'inventory_sha256': BUILD_LOCK, 'inventory_count': 575, 'inventory_evidence': 'EXACT_ROOT_ACCEPTED_NATIVE_PAIR94_RAW575_AND_COMPLETE_BUILDINFO', 'raw_pacman_Q_lock': 'PRESENT_VERIFIED_NATIVE575_BUILD_DATA_ONLY'},
        'retained_pair': {'attempt1_sha256': copied['native-build-1.json'],
                          'attempt2_sha256': copied['native-build-2.json'], 'new_build': 'NOT RUN'},
        'deployment_snapshot_id': deployment_snapshot}


def inspect_package(args, api=None):
    api=api or apis(ordinary(args.source_root,directory=True))
    helper=load_module(Path(args.source_root),'apps6_selected','scripts/ci/latest607-updater/selected_package.py')
    return helper.inspect_package(args,api)



def prepare(args, *, base=None, protected=None, output=None):
    """Data inspection/copy only: never sign, run repo-add, or alter a target root."""
    root = ordinary(args.source_root, directory=True); api = apis(root)
    before, desired, expected, target = locks(root, api.setup)
    base_path = ordinary(base if base is not None else args.base_manifest)
    base_record = api.client.decode(base_path.read_bytes()); validate_base(base_record, expected)
    held = inspect_package(args, api)
    pair, retained, package, native, build_evidence = held.pair, held.retained, held.package, held.native, held.build_evidence
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
                       ('native-build-2.json', pair / 'public/runtime/cachy-asahi-apps-b/provenance.json'), ('public-build-evidence.json', build_evidence),
                       ('LICENSE', pair / 'public/source/cachy-asahi-apps/LICENSE'),
                       ('source-provenance.json', pair / 'public/source/cachy-asahi-apps/source-provenance.json')]:
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
                   'coordinated_sets': [{'name': "exact-desired604", 'versions': target}]},
        'project_license': dict(ref('LICENSE'), spdx='MIT'),
        'evidence': [dict(ref(name), id=name) for name in ('before.lock', 'desired.lock', 'public-build-evidence.json',
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


def fresh_test_metadata_window(api, args):
    """Issue this exact disposable TEST fixture at use with its unchanged lifetime."""
    need((args.issued_utc, args.expires_utc) == ('2026-10-16T00:00:00Z', '2026-10-18T00:00:00Z'),
         'exact original TEST fixture metadata window required')
    lifetime = api.client.stamp(args.expires_utc) - api.client.stamp(args.issued_utc)
    need(lifetime.total_seconds() == 172800, 'original two-day TEST metadata lifetime required')
    now = api.client.datetime.now(api.client.timezone.utc).replace(microsecond=0)
    return api.client.utc(now), api.client.utc(now + lifetime)


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
         and provenance['build']['inventory_count'] == 575
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
    issued_utc, expires_utc = fresh_test_metadata_window(api, args)
    envelope = api.client.build(SimpleNamespace(bundle=str(bundle), output=str(metadata), signer=key,
        namespace=args.namespace, sequence=args.sequence, issued_utc=issued_utc, expires_utc=expires_utc))
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
