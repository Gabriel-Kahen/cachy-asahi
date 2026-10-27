#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tiny private LOCAL Git delivery controls; no remote Git or native credit."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import retained_git_transport as m


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class RetainedGitTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='LOCAL-git-DATA-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / 'private-source'
        self.repo.mkdir(mode=0o700)
        self.env = dict(PATH=os.defpath, HOME=str(self.base), LANG='C', LC_ALL='C',
                        GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                        GIT_TERMINAL_PROMPT='0')
        self.git('init', '--template=', str(self.repo), outside=True)
        self.bodies = {
            'LICENSE': b'LOCAL FIXTURE notice data; not license acceptance\n',
            'packages/tiny.pkg': b'\0\xffLOCAL-PACKAGE-DATA\n',
            'packages/tiny.pkg.sig': b'LOCAL-NOT-A-VALID-SIGNATURE\n',
            '.gitattributes': b'packages/* filter=must-not-run\n',
            'bin/never-run': b'#!/bin/sh\necho SOURCE-EXECUTION-WOULD-BE-A-BUG\n',
        }
        for name, raw in self.bodies.items():
            target = self.repo/name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o755 if name == 'bin/never-run' else 0o644)
        self.commit()
        self.destination = self.base/'delivered-DATA'
        self.code_root = Path(m.__file__).resolve().parents[2]
        self.policy = dict(fetch_seconds=5, transport_seconds=20, outer_seconds=25,
                           reason='LOCAL fixture only; finite test policy')

    def git(self, *args, outside=False):
        command = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null']
        if not outside:
            command += ['-C', str(self.repo)]
        result = subprocess.run([*command, *map(str, args)], env=self.env,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def commit(self, *, add=True):
        if add:
            self.git('add', '--all')
        self.git('-c', 'user.name=LOCAL Fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '--no-verify', '-m', 'LOCAL retained DATA fixture')
        self.source = self.git('rev-parse', 'HEAD').decode().strip()
        self.profile = dict(schema=1, actual=None, source=self.source, ref='LOCAL-fixture-only',
                            modes=dict(fixture=len(self.bodies)),
                            files={name: dict(bytes=len(raw), sha256=sha(raw))
                                   for name, raw in self.bodies.items()})

    def deliver(self, **overrides):
        raw = (json.dumps(self.profile, sort_keys=True, indent=2)+'\n').encode()
        options = dict(url=self.repo.as_uri(), expected_source=self.source, profile_raw=raw,
                       profile_sha256=sha(raw), destination=self.destination,
                       executable_root=self.code_root, policy=self.policy, fixture_local=True)
        options.update(overrides)
        return m.deliver(**options)

    def failed_receipt(self):
        receipt = self.destination/'receipt.json'
        self.assertTrue(receipt.is_file(), 'failure evidence must be retained')
        return json.loads(receipt.read_bytes())

    def assert_no_delivery(self):
        self.assertFalse(self.destination.exists())

    def test_actual_local_delivery_full_bytes_modes_git_and_receipt(self):
        receipt = self.deliver()
        self.assertIsInstance(receipt, dict)
        self.assertTrue((self.destination/'receipt.json').is_file())
        data = self.destination/'data'
        self.assertTrue((data/'.git').is_dir())
        for name, body in self.bodies.items():
            target = data/name
            self.assertEqual(target.read_bytes(), body)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),
                             0o755 if name == 'bin/never-run' else 0o644)
            self.assertEqual(target.stat().st_nlink, 1)
        env = dict(self.env, GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1')
        source = subprocess.check_output(['/usr/bin/git', '--git-dir='+str(data/'.git'),
                                          'rev-parse', 'HEAD'], env=env, timeout=10).decode().strip()
        self.assertEqual(source, self.source)
        self.assertIn('fixture', json.dumps(receipt).lower())

    def test_one_fetch_no_checkout_or_carrier_execution(self):
        real = subprocess.Popen
        commands = []
        class ObservedPopen(real):
            def __init__(self, argv, *args, **kwargs):
                commands.append(list(argv))
                super().__init__(argv, *args, **kwargs)
        with patch.object(m.subprocess, 'Popen', ObservedPopen):
            self.deliver()
        self.assertEqual(sum('fetch' in row for row in commands), 1)
        self.assertFalse(any('checkout' in row or 'checkout-index' in row for row in commands))
        self.assertTrue(all(Path(row[0]).name == 'git' for row in commands), commands)

    def test_profile_checksum_refused_before_destination(self):
        with self.assertRaises(m.Error):
            self.deliver(profile_sha256='0'*64)
        self.assert_no_delivery()

    def test_commit_and_profile_must_match(self):
        with self.assertRaises(m.Error):
            self.deliver(expected_source='0'*40)
        self.assert_no_delivery()

    def test_unavailable_exact_commit_retains_failure_no_resume(self):
        self.source = self.profile['source'] = '1'*40
        with self.assertRaises(m.Error):
            self.deliver()
        before = self.failed_receipt()
        with self.assertRaises(m.Error):
            self.deliver()
        self.assertEqual(self.failed_receipt(), before)

    def test_wrong_manifest_sha256_retains_failure(self):
        self.profile['files']['packages/tiny.pkg']['sha256'] = '0'*64
        with self.assertRaises(m.Error):
            self.deliver()
        self.failed_receipt()
        self.assertTrue((self.destination/'data/.git').is_dir())

    def test_wrong_manifest_length_retains_failure(self):
        self.profile['files']['packages/tiny.pkg']['bytes'] += 1
        with self.assertRaises(m.Error):
            self.deliver()
        self.failed_receipt()

    def test_underreported_length_caps_actual_child_stdout(self):
        expected = self.profile['files']['packages/tiny.pkg']['bytes'] - 1
        self.profile['files']['packages/tiny.pkg']['bytes'] = expected
        with self.assertRaises(m.Error):
            self.deliver()
        receipt = self.failed_receipt()
        row = receipt['commands'][-1]
        self.assertEqual(row['argv'][-2], 'blob')
        self.assertFalse(row['supervision']['passed'])
        self.assertLessEqual((self.destination/row['raw_stdout']).stat().st_size, expected)

    def test_empty_ordinary_blob_is_delivered_exactly(self):
        # Tree leaf names must never collide with proof implementation fields.
        self.bodies['metadata/oid'] = b''
        (self.repo/'metadata').mkdir(mode=0o700)
        (self.repo/'metadata/oid').write_bytes(b'')
        self.commit()
        self.deliver()
        self.assertEqual((self.destination/'data/metadata/oid').read_bytes(), b'')

    def test_git_payload_larger_than_diagnostic_cap_still_delivers(self):
        # Incompressible LOCAL data makes fetch's pack/loose Git files exceed the
        # diagnostic-output cap. Diagnostic limits must not become packfile caps.
        raw = os.urandom(256*1024)
        self.bodies['packages/incompressible.bin'] = raw
        (self.repo/'packages/incompressible.bin').write_bytes(raw)
        self.commit()
        with patch.object(m, 'MAX_LOG', 65536):
            self.deliver()
        self.assertEqual((self.destination/'data/packages/incompressible.bin').read_bytes(), raw)
        object_files = [p for p in (self.destination/'data/.git/objects').rglob('*') if p.is_file()]
        self.assertTrue(any(p.stat().st_size > 65536 for p in object_files),
                        'actual fetched Git object storage must exceed the diagnostic cap')

    def test_missing_manifest_member_fails_full_tree_closure(self):
        del self.profile['files']['LICENSE']
        with self.assertRaises(m.Error):
            self.deliver()
        self.failed_receipt()

    def test_extra_manifest_member_fails_full_tree_closure(self):
        self.profile['files']['not-in-commit'] = dict(bytes=1, sha256=sha(b'x'))
        with self.assertRaises(m.Error):
            self.deliver()
        self.failed_receipt()

    def test_duplicate_json_key_refused(self):
        raw = b'{"schema":1,"schema":1}'
        with self.assertRaises(m.Error):
            self.deliver(profile_raw=raw, profile_sha256=sha(raw))
        self.assert_no_delivery()

    def test_unsafe_manifest_paths_refused(self):
        original = copy.deepcopy(self.profile)
        for name in ('../escape', '/absolute', 'a//b', './a', '.git/config', 'x/../../outside'):
            self.profile = copy.deepcopy(original)
            self.profile['files'][name] = dict(bytes=1, sha256=sha(b'x'))
            with self.subTest(name=name):
                with self.assertRaises(m.Error):
                    self.deliver()
                self.assert_no_delivery()

    def test_manifest_metadata_type_bounds(self):
        original = copy.deepcopy(self.profile)
        for key, value in (('bytes', True), ('bytes', -1), ('sha256', 'A'*64)):
            self.profile = copy.deepcopy(original)
            self.profile['files']['LICENSE'][key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(m.Error):
                    self.deliver()
                self.assert_no_delivery()

    def test_manifest_leaf_directory_collision_refused(self):
        self.profile['files']['collision'] = dict(bytes=1, sha256=sha(b'x'))
        self.profile['files']['collision/child'] = dict(bytes=1, sha256=sha(b'y'))
        with self.assertRaises(m.Error):
            self.deliver()
        self.assert_no_delivery()

    def test_symlink_git_blob_mode_refused(self):
        (self.repo/'alias').symlink_to('LICENSE')
        self.bodies['alias'] = b'LICENSE'
        self.commit()
        with self.assertRaises(m.Error):
            self.deliver()
        self.failed_receipt()

    def test_gitlink_submodule_mode_refused(self):
        self.git('update-index', '--add', '--cacheinfo', '160000,'+self.source+',vendor')
        self.bodies['vendor'] = b''
        self.commit(add=False)
        with self.assertRaises(m.Error):
            self.deliver()
        self.failed_receipt()

    def test_existing_destination_is_never_adopted(self):
        self.destination.mkdir(mode=0o700)
        marker = self.destination/'keep'
        marker.write_bytes(b'unchanged')
        with self.assertRaises(m.Error):
            self.deliver()
        self.assertEqual(marker.read_bytes(), b'unchanged')
        self.assertFalse((self.destination/'receipt.json').exists())

    def test_destination_symlink_ancestry_refused(self):
        alias = self.base/'alias'
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(m.Error):
            self.deliver(destination=alias/'fresh')
        self.assertFalse((self.base/'fresh').exists())

    def test_destination_parent_public_writable_refused(self):
        public = self.base/'public'
        public.mkdir(mode=0o777); public.chmod(0o777)
        with self.assertRaises(m.Error):
            self.deliver(destination=public/'fresh')
        self.assertFalse((public/'fresh').exists())

    def test_local_transport_requires_explicit_fixture_label(self):
        with self.assertRaises(m.Error):
            self.deliver(fixture_local=False)
        self.assert_no_delivery()

    def test_nonpublic_or_credential_bearing_urls_refused_before_git(self):
        for url in ('http://example.invalid/repo.git', 'https://user:pass@example.invalid/repo.git',
                    'https://example.invalid/repo.git?token=x', 'https://example.invalid/repo.git#ref',
                    'ssh://example.invalid/repo', 'ext::sh -c echo', '/tmp/repo'):
            with self.subTest(url=url):
                with patch.object(m.subprocess, 'Popen', side_effect=AssertionError('Git launched')):
                    with self.assertRaises(m.Error):
                        self.deliver(url=url, fixture_local=False)
                self.assert_no_delivery()

    def test_nonfinite_or_nonordered_policy_refused(self):
        for changes in (dict(fetch_seconds=float('nan')), dict(transport_seconds=float('inf')),
                        dict(fetch_seconds=True), dict(fetch_seconds=0),
                        dict(fetch_seconds=30), dict(transport_seconds=30), dict(reason='')):
            with self.subTest(changes=changes):
                with self.assertRaises(m.Error):
                    self.deliver(policy=dict(self.policy, **changes))
                self.assert_no_delivery()

    def test_hostile_global_filters_and_hooks_never_execute(self):
        marker = self.base/'must-not-exist'
        hook = self.base/'hook.sh'
        hook.write_text('#!/bin/sh\ntouch '+str(marker)+'\n')
        hook.chmod(0o755)
        config = self.base/'hostile.gitconfig'
        config.write_text('[filter "must-not-run"]\n\tsmudge = '+str(hook)+'\n\trequired = true\n'
                          '[core]\n\thooksPath = '+str(self.base)+'\n')
        (self.base/'post-checkout').write_bytes(hook.read_bytes())
        (self.base/'post-checkout').chmod(0o755)
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL':str(config), 'GIT_CONFIG_SYSTEM':str(config),
                                    'GIT_CONFIG_COUNT':'1', 'GIT_CONFIG_KEY_0':'filter.must-not-run.smudge',
                                    'GIT_CONFIG_VALUE_0':str(hook)}):
            self.deliver()
        self.assertFalse(marker.exists())
        self.assertEqual((self.destination/'data/packages/tiny.pkg').read_bytes(), self.bodies['packages/tiny.pkg'])

    def test_actual_stalled_owned_child_timeout_retains_partial_evidence(self):
        original = m.Delivery.command
        def stall_fetch(actor, argv, seconds=30, stdout_limit=m.MAX_LOG, material=None):
            if 'fetch' in argv:
                argv = [sys.executable, '-B', '-c', 'import time; time.sleep(10)']
                seconds = .12
            return original(actor, argv, seconds=seconds,
                            stdout_limit=stdout_limit, material=material)
        started = time.monotonic()
        with patch.object(m.Delivery, 'command', new=stall_fetch):
            with self.assertRaises(m.Error):
                self.deliver()
        self.assertLess(time.monotonic()-started, 3)
        receipt = self.failed_receipt()
        self.assertTrue(any(row['supervision']['timeout'] for row in receipt['commands']))
        self.assertTrue((self.destination/'data/.git').is_dir())

    def test_actual_external_reap_fails_closed_without_numeric_operations(self):
        original = m.op.supervise
        calls = []
        def stolen(child, **kwargs):
            # Deliberate custody violation on our newly created tiny Git child.
            # The real supervisor must observe ECHILD and never probe/signal it.
            os.waitpid(child.pid, 0)
            calls.append(child.pid)
            with patch.object(m.op.os, 'killpg', side_effect=AssertionError('signal after ECHILD')), \
                 patch.object(m.op.os, 'kill', side_effect=AssertionError('signal after ECHILD')), \
                 patch.object(m.op, '_stat', side_effect=AssertionError('probe after ECHILD')):
                return original(child, **kwargs)
        with patch.object(m.op, 'supervise', side_effect=stolen):
            with self.assertRaises(m.Error):
                self.deliver()
        self.assertEqual(len(calls), 1)
        receipt = self.failed_receipt()
        result = receipt['commands'][0]['supervision']
        self.assertEqual(result['ownership'], 'UNKNOWN')
        self.assertFalse(result['reaped'])
        self.assertEqual(result['signals'], [])

    def test_replaced_delivery_root_retains_original_receipt_only(self):
        victim = self.base/'private-victim'
        victim.mkdir(mode=0o700)
        marker = victim/'keep'
        marker.write_bytes(b'victim unchanged')
        retained = self.base/'renamed-original-DATA'
        original = m.Delivery.command
        def replace_after_fetch(actor, argv, *, seconds=30, stdout_limit=m.MAX_LOG, material=None):
            result = original(actor, argv, seconds=seconds, stdout_limit=stdout_limit, material=material)
            if 'fetch' in argv:
                actor.path.rename(retained)
                actor.path.symlink_to(victim, target_is_directory=True)
            return result
        with patch.object(m.Delivery, 'command', new=replace_after_fetch):
            with self.assertRaises(m.Error):
                self.deliver()
        self.assertEqual(marker.read_bytes(), b'victim unchanged')
        self.assertEqual({p.name for p in victim.iterdir()}, {'keep'})
        self.assertTrue(self.destination.is_symlink())
        receipt = json.loads((retained/'receipt.json').read_bytes())
        self.assertIn('FAIL', receipt['status'])
        self.assertEqual(len(receipt['commands']), 2)
        self.assertTrue((retained/'data/.git').is_dir())


if __name__ == '__main__':
    unittest.main(verbosity=2)
