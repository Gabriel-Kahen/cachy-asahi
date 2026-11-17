#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Match an authenticated development kit's declared transaction to a pinned package lock."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
loader = importlib.util.spec_from_file_location(
    'install_inventory_kit', Path(__file__).absolute().parents[1] / 'offline_kit.py')
kit = importlib.util.module_from_spec(loader)
loader.loader.exec_module(kit)
client = kit.c

MAX_PACKAGES = 1024
MAX_LOCK_BYTES = MAX_PACKAGES * 256
MAX_BASE_BYTES = 32 * 1024**2


def target_lock(path, expected_sha256):
    client.need(client.HEX.fullmatch(expected_sha256 or ''), 'target lock SHA-256 required')
    raw = client.read_path(path, MAX_LOCK_BYTES)
    client.need(client.digest(raw) == expected_sha256, 'target lock SHA-256 mismatch')
    lines = raw.decode('ascii').split('\n')
    client.need(lines.pop() == '' and 0 < len(lines) <= MAX_PACKAGES,
                'target lock needs 1–1024 newline-terminated name/version records')
    result = {}
    for line in lines:
        name, sep, version = line.partition(' ')
        client.need(sep and client.NAME.fullmatch(name) and client.NAME.fullmatch(version),
                    'invalid target lock name/version record')
        client.need(name not in result, 'duplicate target lock package: ' + name)
        result[name] = version
    return result


def inventory(packages, label):
    client.need(type(packages) is list and 0 < len(packages) <= MAX_PACKAGES,
                'nonempty bounded ' + label + ' package inventory required')
    result = {}
    for package in packages:
        client.need(type(package) is dict, 'invalid ' + label + ' package record')
        name, version, arch = (package.get(key) for key in ('name', 'version', 'arch'))
        client.need(isinstance(name, str) and client.NAME.fullmatch(name) and
                    isinstance(version, str) and client.NAME.fullmatch(version) and
                    arch in ('any', 'aarch64'), 'invalid ' + label + ' package identity')
        client.need(name not in result, 'duplicate ' + label + ' package: ' + name)
        result[name] = version
    return result


def read_bound(root, name, expected, *, limit=client.MAX_JSON):
    client.need(isinstance(expected, str) and client.HEX.fullmatch(expected),
                'signed digest missing for ' + name)
    raw = client.read_member(root, name, limit)
    client.need(client.digest(raw) == expected, name + ' changed after authentication')
    return client.decode(raw)


def declared_transaction(root, release_sha256):
    release = read_bound(root, 'release.json', release_sha256)
    files = release['files']
    spec = read_bound(root, 'spec.json', files.get('spec.json'))
    base_pin = files.get('base.json')
    base_ref = spec.get('base')
    client.need(type(base_ref) is dict and base_ref.get('sha256') == base_pin,
                'signed base references disagree')
    base = read_bound(root, 'base.json', base_pin, limit=MAX_BASE_BYTES)
    client.need(type(base.get('schema_version')) is int and base['schema_version'] == 1 and
                base.get('kind') == 'complete-target-transaction' and base.get('target_arch') == 'aarch64' and
                isinstance(base.get('snapshot_id'), str) and bool(base['snapshot_id']) and
                base['snapshot_id'] == base_ref.get('snapshot_id'), 'invalid signed base transaction')
    base_versions = inventory(base.get('packages'), 'base')
    overlay = inventory(release['packages'], 'overlay')
    policy = spec.get('policy')
    client.need(type(policy) is dict, 'signed transaction policy missing')
    selected = policy.get('selected_packages')
    client.need(type(selected) is list and len(selected) == len(overlay) and set(selected) == overlay.keys(),
                'signed selected package set differs from the overlay')
    protected = policy.get('protected_packages')
    client.need(type(protected) is list and bool(protected) and len(protected) == len(set(protected)) and
                set(protected) <= base_versions.keys() and not overlay.keys() & set(protected),
                'signed overlay must preserve all declared protected base packages')
    return base_versions | overlay, base_pin, len(base_versions), len(overlay), spec['synthetic']


def verify(args):
    expected = target_lock(args.target_lock, args.target_lock_sha256)
    inspected = kit.inspect(args)
    root = client.directory(Path(args.kit) / 'release')
    try:
        actual, base_pin, base_count, overlay_count, synthetic = declared_transaction(root, inspected['release_sha256'])
    finally:
        os.close(root)
    missing = sorted(expected.keys() - actual.keys())
    extra = sorted(actual.keys() - expected.keys())
    mismatched = sorted(name for name in expected.keys() & actual.keys() if actual[name] != expected[name])
    client.need(not (missing or extra or mismatched),
                'target lock differs from signed declared transaction: ' + json.dumps({
                    'missing': missing, 'extra': extra, 'version_mismatches': mismatched}, separators=(',', ':')))
    return dict(inspected, status='matched-development-install-inventory', base_sha256=base_pin,
                target_lock_sha256=args.target_lock_sha256, target_package_count=len(actual),
                base_package_count=base_count, overlay_package_count=overlay_count, synthetic=synthetic,
                base_archives_authenticated=False, supported_asahi_installation=False, m2_validated=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('kit', 'kit-sha256', 'namespace', 'signer', 'state-dir', 'target-lock', 'target-lock-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--minimum-sequence', required=True, type=int)
    try:
        result = verify(parser.parse_args(argv))
    except (client.Error, OSError, ValueError, KeyError, TypeError) as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
