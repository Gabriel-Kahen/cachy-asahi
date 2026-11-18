#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Export a local stable endpoint with verified archive-to-provenance lineage."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


E = load('export_repository')
C = load('compare_releases_v2')
R = E.r


def stable(directory, promotion, key, env, release_id, files, aliases):
    manifest, spec, _, digest = C.verified(directory, key, env)
    R.require(manifest['release_id'] == release_id, 'stable path/release identity mismatch')
    # The unchanged materializer requires the entire plan at the destination.
    # Export the same manifest and archive bytes that supplied the lineage proof.
    R.require(files['release.json'] == digest and manifest['files'] == {
        path: pin for path, pin in files.items() if path not in {'release.json', 'release.json.sig'}
    } and manifest['symlinks'] == aliases, 'verified release differs from export inventory')
    paths = {'promotion.json': promotion, 'promotion.json.sig': Path(str(promotion) + '.sig')}
    for path in paths.values():
        E.regular(path)
    pins = {name: R.sha(path) for name, path in paths.items()}
    R.verify_signature(promotion, key, env)
    saved = R.load(promotion)
    R.require(set(saved) == {'schema_version', 'release_id', 'release_sha256', 'gates', 'promoted_utc'}
              and saved['schema_version'] == 1 and saved['release_id'] == release_id
              and saved['release_sha256'] == digest, 'promotion record is not bound to this release')
    with tempfile.TemporaryDirectory(prefix='repository-export-gates-') as temporary:
        gates = Path(temporary) / 'gates.json'
        R.write(gates, saved['gates'])
        R.gates_check(directory, manifest, spec, gates)
    R.require(all(R.sha(path) == pins[name] for name, path in paths.items()),
              'promotion record changed during verification')
    return {name: (path, pins[name]) for name, path in paths.items()}


def describe(root, key, env):
    R.storage_check(root)
    for name in ('stable', 'promotions', 'withdrawals'):
        path = root / name
        if path.exists() or path.is_symlink():
            E.managed_directory(path)
    selected = root / 'stable/current'
    if not selected.is_symlink():
        # The existing path authenticates signed withdrawal-only generations.
        plan, sources = E.describe(root, key, env)
        R.require(plan['selected_release'] is None, 'source selection changed during export')
        return plan, sources
    release_id = R.valid_name(os.readlink(selected))
    directory = root / 'stable' / release_id
    withdrawals = root / 'withdrawals'
    R.require(not (withdrawals / (release_id + '.json')).exists(), 'selected release is withdrawn')
    observed, aliases = E.tree(directory)
    promoted = stable(directory, root / 'promotions' / (release_id + '.json'), key, env, release_id, observed, aliases)
    sources = {'release/' + name: directory / name for name in observed}
    files = {'release/' + name: pin for name, pin in observed.items()}
    for name, (path, pin) in promoted.items():
        sources[name], files[name] = path, pin
    if withdrawals.exists():
        add_withdrawals(withdrawals, key, env, sources, files)
    links = {'release/' + name: target for name, target in aliases.items()}
    R.require(len(files) + len(links) <= E.MAX_FILES and sum(path.stat().st_size for path in sources.values()) <= E.MAX_BYTES,
              'complete endpoint exceeds bound')
    plan = dict(schema_version=1, purpose='local-repository-endpoint', selected_release=release_id,
                signer=key, files=files, symlinks=links)
    return plan, sources


def add_withdrawals(directory, key, env, sources, files):
    entries = sorted(directory.iterdir())
    R.require(len(entries) <= E.MAX_FILES and all(path.name.endswith(('.json', '.json.sig')) for path in entries),
              'unexpected withdrawal member')
    records = [path for path in entries if path.name.endswith('.json')]
    R.require(set(entries) == {member for path in records for member in (path, Path(str(path) + '.sig'))},
              'partial withdrawal record')
    for path in records:
        pair = (path, Path(str(path) + '.sig'))
        for member in pair:
            E.regular(member)
        R.verify_signature(path, key, env)
        value = R.load(path)
        wid = R.valid_name(path.name[:-5])
        R.require(set(value) == {'schema_version', 'release_id', 'signer', 'withdrawn_utc', 'reason',
                                 'reason_sha256', 'packages_retained'} and value['schema_version'] == 1
                  and value['release_id'] == wid and value['signer'] == key and value['packages_retained'] is True
                  and isinstance(value['reason'], str) and value['reason'] and R.HEX.fullmatch(value['reason_sha256']),
                  'invalid withdrawal record')
        for member in pair:
            name = 'withdrawals/' + member.name
            sources[name], files[name] = member, R.sha(member)


def export(root, endpoint, home, key, apply=False):
    root, endpoint, home = map(E.canonical, (root, endpoint, home))
    E.managed_directory(root)
    E.managed_directory(endpoint)
    R.require(not root.is_relative_to(endpoint) and not endpoint.is_relative_to(root), 'source/endpoint overlap refused')
    R.require(not home.is_relative_to(endpoint), 'GPG home must stay outside endpoint')
    key, env = R.fingerprint(key), R.gpg_env(home, root)
    with E.locks(root, endpoint):
        previous = E.endpoint_state(endpoint)
        plan, sources = describe(root, key, env)

        def recheck():
            R.require(describe(root, key, env)[0] == plan, 'source selection changed during export')

        return E.materialize(root, endpoint, key, env, previous, plan, sources, recheck, apply)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ('root', 'endpoint', 'gpg-home', 'key'):
        parser.add_argument('--' + argument, required=True)
    parser.add_argument('--apply', action='store_true', help='materialize and atomically select the local generation')
    args = parser.parse_args()
    try:
        result = export(args.root, args.endpoint, args.gpg_home, args.key, args.apply)
    except (C.r.Error, R.Error, KeyError, TypeError, ValueError, OSError) as error:
        print(f'repository export error: {error}', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
