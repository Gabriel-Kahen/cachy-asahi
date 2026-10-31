#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recover a local repository endpoint to an authenticated retained stable bundle.

Plan generation is read-only. Recovery requires a separately signed plan and
defaults to preview. Never installs packages, changes source stable/current,
weakens stable gates, uploads, changes trust or generates signing identities.
"""
import argparse
from datetime import datetime
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('recovery_export', HERE / 'export_repository.py')
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)
R = E.r
MAX_PLAN_BYTES = 4 * 1024**2


def locations(root, endpoint, home, key):
    root, endpoint, home = map(E.canonical, (root, endpoint, home))
    E.managed_directory(root)
    E.managed_directory(endpoint)
    R.require(not root.is_relative_to(endpoint) and not endpoint.is_relative_to(root), 'source/endpoint overlap refused')
    R.require(not home.is_relative_to(endpoint), 'GPG home must stay outside endpoint')
    return root, endpoint, R.fingerprint(key), R.gpg_env(home, root)


def bound_json(path, digest):
    raw = path.read_bytes()
    R.require(E.digest(raw) == digest, 'authenticated metadata changed: ' + path.name)
    return json.loads(raw)


def promoted_time(promotion):
    value = promotion['promoted_utc']
    R.require(isinstance(value, str), 'promotion needs an explicit timestamp')
    timestamp = datetime.fromisoformat(value)
    R.require(timestamp.utcoffset() is not None, 'promotion timestamp must have a timezone')
    return timestamp


def observe(root, endpoint, key, env, expected_current, target, reason):
    """Caller holds both existing export locks. Return a complete source view."""
    R.require(isinstance(expected_current, str) and E.GENERATION.fullmatch(expected_current),
              'explicit expected-current generation required')
    selected = endpoint / 'current'
    R.require(selected.is_symlink() and os.readlink(selected) == expected_current, 'expected endpoint selection differs')
    R.valid_name(target)
    R.require(isinstance(reason, str) and reason.strip() and len(reason) <= 4096, 'bounded nonempty recovery reason required')
    current = endpoint / expected_current
    current_plan = E.generation_plan(current)
    R.require(set(current_plan) == {'schema_version', 'purpose', 'selected_release', 'signer', 'files', 'symlinks'}
              and type(current_plan['schema_version']) is int and current_plan['schema_version'] == 1
              and current_plan['purpose'] == 'local-repository-endpoint' and current_plan['signer'] == key,
              'current generation schema/signer differs')
    current_id = R.valid_name(current_plan['selected_release'])
    R.require(current_id != target, 'recovery requires a distinct retained predecessor')
    current_manifest = E.stable(current / 'release', current / 'promotion.json', key, env, current_id)
    R.require(bound_json(current / 'release/release.json', current_plan['files']['release/release.json']) == current_manifest,
              'current manifest differs from authenticated generation')
    current_spec = bound_json(current / 'release/spec.json', current_manifest['files']['spec.json'])
    target_plan, sources = E.describe(root, key, env, release_id=target)
    target_directory = root / 'stable' / target
    target_manifest = bound_json(target_directory / 'release.json', target_plan['files']['release/release.json'])
    target_spec = bound_json(target_directory / 'spec.json', target_manifest['files']['spec.json'])
    R.require(current_spec['base']['sha256'] == target_spec['base']['sha256'],
              'recovery requires the identical complete base inventory')
    for name in ('target_arch', 'repo_name'):
        R.require(current_spec[name] == target_spec[name], 'recovery repository/architecture differs')
    for name in ('selected_packages', 'protected_packages', 'supported_models'):
        R.require(sorted(current_spec['policy'][name]) == sorted(target_spec['policy'][name]),
                  'recovery package/platform policy differs: ' + name)
    R.require(current_spec['policy']['coordinated_sets'] == target_spec['policy']['coordinated_sets'],
              'recovery coordinated compatibility set differs')
    target_promotion = bound_json(root / 'promotions' / (target + '.json'), target_plan['files']['promotion.json'])
    current_promotion = bound_json(current / 'promotion.json', current_plan['files']['promotion.json'])
    R.require(promoted_time(target_promotion) < promoted_time(current_promotion),
              'target must have an earlier authenticated promotion')
    versions = {package['name']: package['version'] for package in current_manifest['packages']}
    R.require(set(versions) == {package['name'] for package in target_manifest['packages']}, 'recovery package set differs')
    for package in target_manifest['packages']:
        R.require(int(R.run(['vercmp', package['version'], versions[package['name']]])) <= 0,
                  'retained predecessor contains a newer package')
    withdrawals = {name: pin for name, pin in target_plan['files'].items() if name.startswith('withdrawals/')}
    for name, pin in current_plan['files'].items():
        if name.startswith('withdrawals/'):
            R.require(withdrawals.get(name) == pin, 'previously advertised withdrawal disappeared or changed')
    proposal = dict(schema_version=1, purpose='local-retained-stable-recovery', signer=key,
                    expected_current=expected_current, current_release_id=current_id,
                    current_release_sha256=current_plan['files']['release/release.json'],
                    target_release_id=target, target_release_sha256=target_plan['files']['release/release.json'],
                    target_promotion_sha256=target_plan['files']['promotion.json'],
                    base_sha256=target_spec['base']['sha256'], withdrawal_files=withdrawals, reason=reason)
    return proposal, target_plan, sources


def prepare(root, endpoint, home, key, expected_current, target, reason):
    root, endpoint, key, env = locations(root, endpoint, home, key)
    with E.locks(root, endpoint):
        R.require(E.endpoint_state(endpoint) == expected_current, 'expected endpoint selection differs')
        proposal, _, _ = observe(root, endpoint, key, env, expected_current, target, reason)
        return proposal


def signed_plan(path, root, endpoint, key, env):
    path = E.canonical(path)
    R.require(not path.is_relative_to(root) and not path.is_relative_to(endpoint),
              'recovery plan must stay outside source and endpoint storage')
    signature = Path(str(path) + '.sig')
    for item in (path, signature):
        info = E.regular(item)
        R.require(0 < info.st_size <= MAX_PLAN_BYTES, 'recovery plan/signature size bound')
    raw, signature_raw = path.read_bytes(), signature.read_bytes()
    R.verify_signature(path, key, env)
    R.require(path.read_bytes() == raw and signature.read_bytes() == signature_raw, 'signed recovery plan changed')
    proposal = json.loads(raw)
    R.require(E.encoded(proposal) == raw and type(proposal) is dict
              and type(proposal.get('schema_version')) is int, 'canonical recovery plan required')
    return proposal, {'recovery-plan.json': E.digest(raw), 'recovery-plan.json.sig': E.digest(signature_raw)}


def recover(root, endpoint, home, key, plan_path, apply=False):
    root, endpoint, key, env = locations(root, endpoint, home, key)
    plan_path = E.canonical(plan_path)
    with E.locks(root, endpoint):
        E.endpoint_state(endpoint)
        proposal, plan_pins = signed_plan(plan_path, root, endpoint, key, env)
        expected = proposal['expected_current']
        def view():
            current, pins = signed_plan(plan_path, root, endpoint, key, env)
            R.require(current == proposal and pins == plan_pins, 'recovery authorization changed')
            observed, plan, sources = observe(root, endpoint, key, env, expected,
                                               proposal['target_release_id'], proposal['reason'])
            R.require(observed == proposal, 'signed recovery plan no longer matches authenticated source state')
            plan['files'].update(plan_pins)
            sources.update({'recovery-plan.json': plan_path, 'recovery-plan.json.sig': Path(str(plan_path) + '.sig')})
            R.require(len(plan['files']) + len(plan['symlinks']) <= E.MAX_FILES and
                      sum(path.stat().st_size for path in sources.values()) <= E.MAX_BYTES,
                      'recovery generation exceeds endpoint bounds')
            return plan, sources
        plan, sources = view()
        def recheck():
            R.require(view()[0] == plan, 'recovery source changed before selection')
        result = E.materialize(root, endpoint, key, env, expected, plan, sources, recheck, apply)
        result.update(operation='retained-stable-endpoint-recovery', authorization_sha256=plan_pins['recovery-plan.json'],
                      source_selection_changed=False, packages_installed=False, installed_system_recovered=False)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'endpoint', 'gpg-home', 'key'):
        parser.add_argument('--' + name, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    plan = sub.add_parser('plan', help='print an unsigned canonical proposal for external review/signing')
    plan.add_argument('--expected-current', required=True)
    plan.add_argument('--target-release-id', required=True)
    plan.add_argument('--reason', required=True)
    recovery = sub.add_parser('recover', help='verify a signed plan; --apply materializes and selects it')
    recovery.add_argument('--plan', required=True)
    recovery.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    common = (args.root, args.endpoint, args.gpg_home, args.key)
    try:
        if args.command == 'plan':
            value = prepare(*common, args.expected_current, args.target_release_id, args.reason)
        else:
            value = recover(*common, args.plan, args.apply)
        sys.stdout.buffer.write(E.encoded(value))
        return 0
    except (R.Error, OSError, KeyError, TypeError, ValueError) as error:
        print('repository recovery error: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
