#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind observed disposable-root platform state to the existing Apple policy.

Only the locked transaction caller supplies inventories and kernel-owned paths.
Synthetic model/kernel context establishes no hardware or production acceptance.
"""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PURPOSE = 'disposable-generic-bound-update'


def _asahi():
    path = ROOT / 'packages/tools/cachy-asahi-update/asahi-policy.py'
    spec = importlib.util.spec_from_file_location('_bound_update_asahi_policy', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _need(ok, reason):
    if not ok:
        raise ValueError(reason)


def read_policy(path, expectedsha):
    """Read pinned policy bytes; full schema is checked with actual observations."""
    asahi = _asahi()
    policy = asahi.load_pinned(path, expectedsha, 1024**2)
    _need(type(policy) is dict and type(policy.get('schema_version')) is int
          and policy['schema_version'] == 1
          and policy.get('purpose') == 'cachy-asahi-apple-update-policy', 'invalid platform policy')
    protected_names(policy)
    return policy


def protected_names(policy):
    """Return names to observe/protect before any package mutation."""
    asahi = _asahi()
    _need(type(policy) is dict, 'platform policy required')
    roles = policy.get('platform_roles')
    asahi.exact(roles, asahi.ROLES)
    return set().union(*(asahi.identifiers(names, asahi.NAME) for names in roles.values()))


def authorize(policy, settings, snapshot, before_inventory, after_inventory,
              before_files, after_files, phase='pre-transaction'):
    """Authorize only an unchanged protected set in a disposable generic root.

    File maps contain actual package-owned module paths for every protected kernel.
    Settings are caller-validated synthetic context. Snapshot is the authenticated
    immutable release mapping, not a caller-provided platform observation.
    """
    asahi = _asahi()
    _need(type(settings) is dict and settings.get('purpose') == PURPOSE,
          'disposable generic update purpose required')
    _need(phase in ('pre-transaction', 'post-transaction'), 'invalid platform observation phase')
    _need(type(policy) is dict and policy.get('release_id') == settings.get('release_id'),
          'platform policy release mismatch')
    _need(type(snapshot) is dict and type(snapshot.get('release')) is dict,
          'authenticated release snapshot required')
    release_sha = asahi.text(snapshot.get('release_sha256'), asahi.SHA)
    release_files = snapshot['release'].get('files')
    _need(type(release_files) is dict and bool(release_files), 'authenticated release files required')
    evidence_digests = {asahi.text(value, asahi.SHA) for value in release_files.values()}
    names = protected_names(policy)
    for inventory in (before_inventory, after_inventory):
        _need(type(inventory) is dict and len(inventory) <= 128
              and names <= set(inventory), 'complete bounded protected inventory required')
    before = {name: before_inventory[name] for name in sorted(names)}
    after = {name: after_inventory[name] for name in sorted(names)}
    _need(before == after, 'protected package change refused')
    kernels = set(policy['platform_roles']['kernel'])
    # Use the existing strict module path parser before comparing ownership.
    asahi.owned_releases(before_files, kernels)
    asahi.owned_releases(after_files, kernels)
    _need(all(set(before_files[name]) == set(after_files[name]) for name in kernels),
          'protected kernel ownership change refused')
    observation = {
        'schema_version': 1, 'phase': phase, 'model': settings.get('model'),
        'running_kernel_release': settings.get('running_kernel_release'),
        'before_versions': before, 'after_versions': after,
        'before_kernel_files': {name: sorted(before_files[name]) for name in sorted(kernels)},
        'after_kernel_files': {name: sorted(after_files[name]) for name in sorted(kernels)},
    }
    action = 'transaction' if phase == 'pre-transaction' else 'kernel'
    decision = asahi.evaluate(policy, observation, action=action, operation='repository-update')
    expected = 'transaction-allowed' if phase == 'pre-transaction' else 'no-kernel-change'
    _need(decision['decision'] == expected, 'platform policy refused: ' + decision['reason'])
    transitions = [row for row in policy['transitions'] if row['id'] == decision['transition_id']]
    _need(len(transitions) == 1, 'unique platform transition required')
    evidence = transitions[0]['evidence_sha256']
    _need(evidence['release_manifest'] == release_sha,
          'platform transition release evidence mismatch')
    _need(evidence['transition_validation'] in evidence_digests,
          'platform transition validation absent from signed release')
    return {'observation': observation, 'decision': decision}
