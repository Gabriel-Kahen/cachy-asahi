#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual package payload checks; no installed package, native or M2 acceptance.

Genuine TEST signatures exercise the unchanged kit/recovery verifiers. Only the
fixed ALARM anchor is substituted in the TEST process. The source-context shim
intercepts the fixture's one exact Git query; it does not replace any verifier.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.dont_write_bytecode = True
PACKAGE = 'cachy-asahi-install-handoff'
PRIVATE = 'usr/lib/cachy-asahi/install-handoff'
META = {'.PKGINFO', '.BUILDINFO', '.MTREE'}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def run(argv, *, expect=0, **kwargs):
    process = subprocess.run(list(map(str, argv)), capture_output=True, timeout=90, **kwargs)
    assert process.returncode == expect, process.stdout.decode(errors='replace') + process.stderr.decode(errors='replace')
    return process


def tree(root, aliases=False):
    result = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            assert aliases, 'package aliases are not selected: ' + str(path)
            target = os.readlink(path)
            raw = os.fsencode(target)
            assert 0 < len(raw) <= 4096 and not Path(target).is_absolute(), 'unsafe caller alias'
            assert (path.parent/target).resolve(strict=True).is_relative_to(root.resolve()), 'escaping caller alias'
            result[path.relative_to(root).as_posix()] = ('symlink', raw)
        elif path.is_file():
            result[path.relative_to(root).as_posix()] = path.read_bytes()
    return result


def descriptor(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=path.stat().st_mode & 0o777)


def hidden_roots(paths):
    roots = {path.resolve() for path in paths}
    return sorted((path for path in roots if not any(path != other and path.is_relative_to(other) for other in roots)), key=str)


def stage(recipe, srcdir, output, archive):
    if archive is None:
        run(['bash', '--noprofile', '--norc', '-c',
             'set -eu; umask 022; source "$1/PKGBUILD"; srcdir=$2; pkgdir=$3; package',
             'stage-install-handoff', recipe, srcdir, output])
    else:
        names = run(['bsdtar', '-tf', archive]).stdout.decode().splitlines()
        for name in names:
            clean = name.removeprefix('./').rstrip('/')
            assert clean and not Path(clean).is_absolute() and '..' not in Path(clean).parts, 'unsafe archive path'
        assert '.INSTALL' not in names and not any(name.endswith('.hook') for name in names), 'unsolicited lifecycle hook'
        output.mkdir(mode=0o700)
        run(['bsdtar', '-xpf', archive, '-C', output])


def check(recipe, srcdir, hide, archive=None):
    assert shutil.which('bwrap'), 'existing bubblewrap required; no dependency installation/fallback'
    with tempfile.TemporaryDirectory(prefix='install-handoff-package-TEST-') as temporary:
        work = Path(temporary)
        work.chmod(0o700)
        staged, moved = work/'staged', work/'moved prefix'
        stage(recipe, srcdir, staged, archive)
        staged.rename(moved)
        actual = tree(moved)
        payload = {name: raw for name, raw in actual.items() if name not in META}
        metadata = {name: raw for name, raw in actual.items() if name in META}
        mapping = json.loads((srcdir/'payload-map.json').read_bytes())
        provenance = json.loads((srcdir/'source-provenance.json').read_bytes())
        assert set(mapping) == {'schema_version', 'purpose', 'files', 'unlisted_self'}
        assert mapping['schema_version'] == 1 and mapping['purpose'] == 'install-handoff-package-payload'
        self_row = mapping['unlisted_self']
        assert self_row == {'path': 'usr/share/doc/'+PACKAGE+'/payload-map.json', 'mode': 0o644}
        expected = set(mapping['files']) | {self_row['path']}
        assert set(payload) == expected, (set(payload)-expected, expected-set(payload))
        for name, row in mapping['files'].items():
            assert descriptor(moved/name) == row, name
        assert (moved/self_row['path']).stat().st_mode & 0o777 == self_row['mode']
        assert payload[self_row['path']] == (srcdir/'payload-map.json').read_bytes()
        cli = moved/'usr/bin'/PACKAGE
        runtime = moved/PRIVATE
        pin = provenance['runtime_sha256']
        D = load('packaged_fresh_runtime', runtime/'scripts/install/fresh_handoff/runtime.py')
        lock = D.verify(runtime, pin)
        assert provenance['source_revision'] == lock['source_commit']
        assert len(D.RUNTIME) == 17 and len(D.inventory(runtime)) == 33
        assert set(provenance['runtime_files']) == set(D.inventory(runtime))
        for name, row in provenance['runtime_files'].items():
            assert descriptor(runtime/name) == row
            assert (runtime/name).read_bytes() == (srcdir/'private'/name).read_bytes()
        assert cli.stat().st_mode & 0o777 == 0o755
        assert not any(name.startswith(('etc/', 'var/', 'boot/')) or name.endswith(('.hook', '.service')) for name in payload)
        assert not any('signed_fixture' in name or 'test_release' in name for name in payload)
        run([cli], expect=2)
        run([cli, '--runtime-sha256', pin, '--', '--help'])

        # Check-only source is never part of installed payload. Its fixture
        # bodies remain byte-identical; only the one source-context query uses
        # the externally pinned package source lock instead of Git discovery.
        checks = srcdir/'checks'
        F = load('packaged_signed_fixture', checks/'scripts/install/fresh_handoff/signed_fixture.py')
        context_query = ['git', '-C', str(F.ROOT), 'rev-parse', 'HEAD']
        def source_context(argv, **kwargs):
            if list(argv) == context_query:
                value = lock['source_commit'] + '\n'
                return value if kwargs.get('text') else value.encode()
            return subprocess.check_output(argv, **kwargs)
        F.subprocess = SimpleNamespace(check_output=source_context)
        H = load('packaged_fresh_handoff', runtime/'scripts/install/fresh_handoff/handoff.py')
        H.DELIVERED_SOURCE_LOCK = lock
        F.T.ReleaseTests.setUpClass()
        owner = unittest.TestCase(methodName='runTest')
        original = H.R.P.auth.KEYS
        try:
            fixture = F.SignedFixture(owner, H)
            H.R.P.auth.KEYS = {**original, 'alarm': fixture.anchor}
            fixture.materialize()
            caller = work/'caller data'
            caller.mkdir(mode=0o700)
            selection = caller/'selection.json'
            selection.write_bytes(H.C.encoded(fixture.chosen))
            selection_pin = H.C.digest(selection.read_bytes())
            state = caller/'state'
            state.mkdir(mode=0o700)
            output = caller/'handoff'
            prepared = H.prepare(argparse.Namespace(selection=selection, selection_sha256=selection_pin,
                candidate=fixture.candidate, recovery=fixture.recovery, output=output, state_dir=state))
            assert prepared['fresh_recovery_signature_verification'] and not prepared['packages_installed']
            caller_before = tree(caller, aliases=True)
            arguments = ['verify', '--workspace', str(output), '--receipt-sha256', prepared['receipt_sha256'],
                         '--selection-sha256', selection_pin, '--state-dir', str(state)]
            poison = work/'hostile python'
            poison.mkdir()
            for name in ('json.py', 'argparse.py', 'sitecustomize.py', 'pathlib.py'):
                (poison/name).write_text('raise RuntimeError("TEST ambient Python must not execute")\n')
            environment = dict(os.environ, PYTHONPATH=str(poison), PYTHONHOME=str(poison), HOME='/TEST-no-home')
            prefix = ['bwrap', '--unshare-net', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
                      '--tmpfs', '/tmp', '--bind', str(work), str(work), '--chdir', str(poison)]
            hidden = hidden_roots((hide, recipe, srcdir, fixture.root, fixture.home))
            assert not any(work.is_relative_to(path) for path in hidden), 'check workspace must remain outside hidden source roots'
            for path in hidden:
                prefix += ['--tmpfs', str(path)]
            run([*prefix, '/usr/bin/python3', '-I', '-B', '-c',
                 'import pathlib,socket,sys; assert all(not list(pathlib.Path(p).iterdir()) for p in sys.argv[1:]); '
                 'assert [name for _,name in socket.if_nameindex()]==["lo"]', *hidden], env=environment)
            run([*prefix, cli, '--runtime-sha256', pin, '--', '--help'], env=environment)
            product = run([*prefix, cli, '--runtime-sha256', pin, '--', *arguments], expect=1, env=environment)
            assert b'PREDECESSOR_AUTH_REFUSED' in product.stderr and b'pinned ALARM certificate required' in product.stderr

            driver = work/'TEST-only-explicit-anchor.py'
            driver.write_text('''import importlib.util,pathlib,sys
root=pathlib.Path(sys.argv[1])
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
runtime=load('TEST_packaged_runtime',root/'scripts/install/fresh_handoff/runtime.py')
lock=runtime.verify(root,sys.argv[2])
handoff=load('TEST_packaged_handoff',root/'scripts/install/fresh_handoff/handoff.py')
handoff.DELIVERED_SOURCE_LOCK=lock
# TEST-only anchor substitution; every authentication/verifier body is unchanged.
handoff.R.P.auth.KEYS={**handoff.R.P.auth.KEYS,'alarm':(sys.argv[3],sys.argv[4])}
raise SystemExit(handoff.main(sys.argv[5:]))
''')
            complete = run([*prefix, '/usr/bin/python3', '-I', '-B', driver, runtime, pin,
                            fixture.key, fixture.anchor[1], *arguments], env=environment)
            result = json.loads(complete.stdout)
            assert result['status'] == 'HELD_DEVELOPMENT_HANDOFF' and result['fresh_recovery_signature_verification']
            assert result['runtime_sha256'] == prepared['runtime_sha256']
            assert not result['packages_installed'] and not result['trust_enrolled'] and not result['release_accepted']
            assert result['native_arm'] == result['m2_air_13'] == result['m2_air_15'] == 'NOT RUN'
            assert tree(caller, aliases=True) == caller_before and not list(state.iterdir())
            assert len(list((output/'recovery/recovery/packages').iterdir())) == 16

            changed = runtime/'scripts/platform/recovery_inputs.py'
            body = changed.read_bytes()
            changed.chmod(0o600)
            changed.write_bytes(body+b'\nraise RuntimeError("TEST changed helper must not execute")\n')
            refused = run([*prefix, cli, '--runtime-sha256', pin, '--', '--help'], expect=1, env=environment)
            assert b'runtime closure incomplete or changed' in refused.stderr
            assert b'TEST changed helper must not execute' not in refused.stderr
            changed.unlink()
            refused = run([*prefix, cli, '--runtime-sha256', pin, '--', '--help'], expect=1, env=environment)
            assert b'runtime closure incomplete or changed' in refused.stderr
            changed.write_bytes(body)
            changed.chmod(0o644)
            assert tree(moved) == actual and not list(moved.rglob('__pycache__'))
            foreign = moved/'usr/share/caller-owned-data'
            foreign.write_bytes(b'preserve caller data\n')
            for name in payload:
                (moved/name).unlink()
            assert tree(moved) == {**metadata, 'usr/share/caller-owned-data': b'preserve caller data\n'}
            assert tree(caller, aliases=True) == caller_before
            return dict(status='PASS_HOST_PACKAGE_PAYLOAD_ONLY', package_archive_extracted=archive is not None,
                actual_package_function_staged=archive is None, payload_files=len(payload), runtime_python_files=17,
                runtime_payload_files=33, exact_runtime_bytes=True, source_hidden=True, moved_prefix=True,
                loopback_only=True, python_environment_poisoned=True, signing_home_hidden=True,
                candidate_predecessor_and_all16_recovery_signatures='GENUINE_TEST_KEYS_NO_VERIFIER_MOCKS',
                TEST_anchor='Explicit TEST-process fingerprint/certificate substitution only; not shipped',
                product_policy='UNCHANGED_FIXED_ALARM_ANCHOR_REFUSES_TEST_CERTIFICATE',
                tampered_runtime='REFUSED_BEFORE_HELPER_IMPORT', missing_runtime='REFUSED_BEFORE_HELPER_IMPORT',
                caller_state_unchanged=True, removal='EXACT_PAYLOAD_FILE_INVERSE_CALLER_DATA_PRESERVED',
                installed_package='NOT RUN', native_arm='NOT RUN', M2='NOT RUN', release_accepted=False)
        finally:
            H.R.P.auth.KEYS = original
            owner.doCleanups()
            F.T.ReleaseTests.tearDownClass()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, required=True)
    parser.add_argument('--srcdir', type=Path, required=True)
    parser.add_argument('--hide-checkout', type=Path, required=True)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.recipe_root.resolve(), args.srcdir.resolve(), args.hide_checkout.resolve(),
                           args.archive.resolve() if args.archive else None), sort_keys=True))
