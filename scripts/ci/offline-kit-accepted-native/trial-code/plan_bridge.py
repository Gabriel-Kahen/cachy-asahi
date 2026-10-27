#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Proposed authenticated kit-to-disposable-plan bridge; never commits packages.

The existing native local_transaction engine admits inert fixture names only.
This command produces a separately labelled, unadopted candidate contract rather
than changing that engine's profile, scope, custody or cleanup requirements.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True


def need(ok, message):
    if not ok:
        raise ValueError(message)


def kit_api():
    # Relocated receivers supply their already authenticated API to plan().
    source = Path(__file__).absolute()
    need(len(source.parents) > 2, 'relocated proposal requires an explicit authenticated kit API')
    path = source.parents[2] / 'scripts/release/offline_kit.py'
    spec = importlib.util.spec_from_file_location('trusted_offline_kit_plan_runtime', path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def root_path(value, kit, state):
    if value is None:
        return None
    path = Path(value)
    need(path.is_absolute() and path != Path('/') and '..' not in path.parts and
         str(path) == os.path.normpath(str(path)) and
         not any(p.is_symlink() for p in (path, *path.parents)),
         'canonical non-host disposable root required')
    for other in (kit, state):
        need(not path.is_relative_to(other) and not other.is_relative_to(path),
             'disposable root must be disjoint from kit and checkpoint state')
    return str(path)


def inventory(value, c):
    need(type(value) is dict and len(value) <= 4096, 'finite explicit before inventory required')
    for name, version in value.items():
        need(type(name) is str and c.NAME.fullmatch(name) and
             type(version) is str and c.NAME.fullmatch(version), 'before inventory identity invalid')
    return dict(value)


def derive(actual, release, sources, before, selected, operation, c):
    """Resolve a finite signed candidate set; preserve exact artifact identities."""
    need(operation in ('install', 'remove'), 'unsupported proposed operation')
    available = {row['name']: row for row in actual['targets']['packages']}
    need(type(selected) is list and selected and len(selected) == len(set(selected)) and
         all(type(name) is str and name in available for name in selected),
         'nonempty unique package selection from authenticated release required')
    associations = {row['package']['name']: row for row in sources['packages']}
    rows, after = [], dict(before)
    for name in sorted(selected):
        target = available[name]
        source = associations.get(name)
        identity = {key: target[key] for key in ('name', 'version', 'arch', 'sha256')}
        need(source is not None and source['package'] == identity,
             'exact candidate source-delivery association required')
        if operation == 'remove':
            need(before.get(name) == target['version'], 'remove requires exact installed candidate version')
            del after[name]
        else:
            need(name not in before, 'initial proposed install refuses existing candidate/upgrade')
            after[name] = target['version']
        rows.append(dict(package=identity, archive=target['path'],
            signature=target['path'] + '.sig', signature_sha256=release['files'][target['path'] + '.sig'],
            recipe_sha256=source['recipe']['sha256'], source_bundle_sha256=source['bundle']['sha256'],
            review_status=source['review_status']))
    return rows, after


def plan(args, *, api=None):
    k = kit_api() if api is None else api
    c = k.c
    kit, state = c.absolute(args.kit), c.absolute(args.state_dir)
    root = root_path(getattr(args, 'disposable_root', None), kit, state)
    before_arg = getattr(args, 'before', None)
    before = inventory({} if before_arg is None else before_arg, c)
    operation = getattr(args, 'operation', 'install')
    checked = k.inspect(args)
    fd = c.directory(kit / 'release')
    try:
        actual, release, raw = c.describe(fd)
        need(c.digest(raw) == checked['release_sha256'], 'release changed after kit authentication')
        spec_raw = c.read_member(fd, 'spec.json')
        need(c.digest(spec_raw) == release['files']['spec.json'], 'signed spec changed')
        sources = c.source_associations(fd, c.decode(spec_raw), release)
        need(sources is not None, 'declared source delivery required by proposed candidate bridge')
        selected = getattr(args, 'packages', None)
        if selected is None:
            selected = [row['name'] for row in actual['targets']['packages']]
        rows, after = derive(actual, release, sources, before, selected, operation, c)
    finally:
        os.close(fd)
    again = k.inspect(args)
    need(again['kit_sha256'] == checked['kit_sha256'] and
         again['metadata_sha256'] == checked['metadata_sha256'] and
         again['release_sha256'] == checked['release_sha256'], 'kit changed during planning')
    return dict(schema_version=1, purpose='proposed-offline-development-disposable-plan',
        status='BLOCKED_ENGINE_COMPATIBILITY', operation=operation,
        kit_sha256=args.kit_sha256, release_sha256=checked['release_sha256'],
        metadata_sha256=checked['metadata_sha256'], signer=args.signer,
        namespace=args.namespace, minimum_sequence=args.minimum_sequence,
        candidate_contract=dict(scope='unadopted-offline-development-candidate',
            architecture='aarch64', disposable_root=root, before=before, after=after,
            candidates=rows),
        before_inventory_authenticated=False, dependency_resolution='NOT_ESTABLISHED',
        root_isolation='NOT_ESTABLISHED', checkpoint_changed=False,
        packages_installed=False, packages_removed=False, transaction_authorized=False,
        native_execution='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED',
        missing_bridge='Existing scripts/install/local_transaction.py native contract admits only '
            'caa-install-fixture-* identities. This candidate plan is deliberately not that contract. '
            'A separately reviewed candidate profile must bind native tool/source closure, disposable '
            'namespace, real before inventory, prepared dependency/conflict set, signed package '
            'snapshots, post-commit payload and exported inventory before installation is supported.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('client-plan',))
    for name in ('kit', 'kit-sha256', 'signer', 'namespace', 'state-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--minimum-sequence', required=True, type=int)
    parser.add_argument('--operation', choices=('install', 'remove'), default='install')
    parser.add_argument('--package', action='append', dest='packages')
    parser.add_argument('--disposable-root')
    parser.add_argument('--before-json', type=Path)
    parser.add_argument('--before-sha256')
    args = parser.parse_args(argv)
    try:
        k = kit_api()
        need((args.before_json is None) == (args.before_sha256 is None), 'complete before input pin required')
        args.before = None
        if args.before_json is not None:
            raw = k.c.read_path(args.before_json, k.c.MAX_JSON)
            need(k.c.HEX.fullmatch(args.before_sha256) and k.c.digest(raw) == args.before_sha256,
                 'before inventory differs from external pin')
            args.before = k.c.decode(raw)
        print(json.dumps(plan(args, api=k), sort_keys=True))
        return 0  # Successful planning; result explicitly blocks transaction execution.
    except Exception as error:
        print('offline candidate plan refused: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
