#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure observations only: no package, namespace, trust or service actors."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
ROOT = next(parent for parent in HERE.parents
            if (parent / 'packages/tools/cachy-asahi-update/asahi-policy.py').is_file())
adapter = load('update_platform_policy', HERE / 'platform_policy.py')
adapter.ROOT = ROOT  # Also support the owned proposed/scripts/update preparation tree.
fixtures = load('existing_asahi_policy_fixtures',
                ROOT / 'packages/tools/cachy-asahi-update/test-asahi-policy.py')


class PlatformPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy, observation = fixtures.fixture(phase='pre-transaction')
        self.before = dict(observation['before_versions'], unrelated='1-1')
        self.after = dict(observation['after_versions'], unrelated='2-1')
        self.before_files = observation['before_kernel_files']
        self.after_files = observation['after_kernel_files']
        self.settings = {'purpose': adapter.PURPOSE, 'release_id': self.policy['release_id'],
                         'model': observation['model'],
                         'running_kernel_release': observation['running_kernel_release']}
        evidence = self.policy['transitions'][0]['evidence_sha256']
        self.snapshot = {'metadata': {}, 'release_sha256': evidence['release_manifest'],
                         'release': {'files': {'validation.json': evidence['transition_validation']}}}

    def authorize(self, **kwargs):
        return adapter.authorize(self.policy, self.settings, self.snapshot, self.before,
                                 self.after, self.before_files, self.after_files, **kwargs)

    def test_actual_observation_maps_exclude_unprotected_delta_and_accept_both_phases(self):
        pre = self.authorize()
        post = self.authorize(phase='post-transaction')
        self.assertEqual(pre['decision']['decision'], 'transaction-allowed')
        self.assertEqual(post['decision']['decision'], 'no-kernel-change')
        self.assertNotIn('unrelated', pre['observation']['before_versions'])
        self.assertEqual(set(pre['observation']['before_versions']), adapter.protected_names(self.policy))
        self.assertEqual(pre['observation']['before_kernel_files'], self.before_files)

    def test_read_policy_uses_pin_and_rejects_missing_duplicate_or_invalid_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            raw = json.dumps(self.policy).encode()
            path.write_bytes(raw)
            self.assertEqual(adapter.read_policy(path, hashlib.sha256(raw).hexdigest()), self.policy)
            with self.assertRaises(ValueError):
                adapter.read_policy(path, '0' * 64)
            duplicate = b'{"schema_version":1,"schema_version":1}'
            path.write_bytes(duplicate)
            with self.assertRaises(ValueError):
                adapter.read_policy(path, hashlib.sha256(duplicate).hexdigest())
            path.write_bytes(b'null')
            with self.assertRaises(ValueError):
                adapter.read_policy(path, hashlib.sha256(b'null').hexdigest())
            path.unlink()
            with self.assertRaises(OSError):
                adapter.read_policy(path, '0' * 64)

    def test_observed_stable_versions_must_match_known_policy_transition(self):
        self.before['fixture-graphics'] = self.after['fixture-graphics'] = 'unknown-2'
        with self.assertRaisesRegex(ValueError, 'unknown-transition'):
            self.authorize()

    def test_every_protected_version_change_is_refused_even_coordinated_kernel_transition(self):
        for name in adapter.protected_names(self.policy):
            with self.subTest(name=name):
                original = self.after[name]
                self.after[name] = 'changed-2'
                with self.assertRaisesRegex(ValueError, 'protected package change'):
                    self.authorize()
                self.after[name] = original
        policy, observed = fixtures.fixture('kernel', 'pre-transaction')
        self.policy, self.before, self.after = policy, observed['before_versions'], observed['after_versions']
        self.before_files, self.after_files = observed['before_kernel_files'], observed['after_kernel_files']
        with self.assertRaisesRegex(ValueError, 'protected package change'):
            self.authorize()

    def test_protected_addition_removal_and_missing_inventory_are_refused(self):
        for field in ('before', 'after'):
            with self.subTest(field=field):
                saved = getattr(self, field)
                setattr(self, field, {key: value for key, value in saved.items() if key != 'speakersafetyd'})
                with self.assertRaisesRegex(ValueError, 'protected inventory'):
                    self.authorize()
                setattr(self, field, saved)
        self.before.update({f'fixture-extra-{i}': '1' for i in range(129)})
        with self.assertRaisesRegex(ValueError, 'bounded'):
            self.authorize()

    def test_missing_invalid_or_changed_actual_kernel_ownership_refuses(self):
        kernel = 'fixture-asahi-kernel'
        original = self.after_files
        invalid = [{}, {kernel: []}, {kernel: ['/usr/lib/modules/6.99.synthetic-asahi/vmlinuz']},
                   {kernel: ['/usr/lib/modules/6.99.synthetic-asahi/kernel/../escape.ko']},
                   {kernel: ['usr/lib/modules/6.99.synthetic-asahi/kernel/fixture.ko']},
                   {kernel: [self.before_files[kernel][0]] * 2}]
        for files in invalid:
            with self.subTest(files=files), self.assertRaises(ValueError):
                self.after_files = files
                self.authorize()
        self.after_files = {kernel: ['/usr/lib/modules/6.99.synthetic-asahi/kernel/different.ko']}
        with self.assertRaisesRegex(ValueError, 'ownership change'):
            self.authorize()
        self.after_files = original

    def test_policy_release_and_both_transition_evidence_bindings_are_required(self):
        mutations = [lambda: self.settings.update(release_id='other-release'),
                     lambda: self.snapshot.update(release_sha256='a' * 64),
                     lambda: self.snapshot['release'].update(files={'other.json': 'b' * 64})]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.setUp()
                mutate()
                with self.assertRaises(ValueError):
                    self.authorize()

    def test_only_the_used_transition_requires_release_evidence_binding(self):
        unrelated = deepcopy(self.policy['transitions'][0])
        unrelated['id'] = 'unused-other-transition'
        unrelated['before_versions']['fixture-graphics'] = 'different-1'
        unrelated['evidence_sha256'] = {'release_manifest': 'a' * 64,
                                         'transition_validation': 'b' * 64}
        self.policy['transitions'].append(unrelated)
        self.assertEqual(self.authorize()['decision']['decision'], 'transaction-allowed')
        unrelated['before_versions']['fixture-graphics'] = self.before['fixture-graphics']
        with self.assertRaisesRegex(ValueError, 'unknown-transition'):
            self.authorize()

    def test_wrong_context_model_running_release_and_nontransaction_phases_refuse(self):
        for key, value in [('purpose', 'production'), ('model', 'apple,j415'),
                           ('running_kernel_release', 'unknown.synthetic')]:
            with self.subTest(key=key):
                saved = self.settings[key]
                self.settings[key] = value
                with self.assertRaises(ValueError):
                    self.authorize()
                self.settings[key] = saved
        for phase in ('services', 'restart', 'aur-update', 'orphan-removal'):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                self.authorize(phase=phase)
        self.policy['permitted_operations'].remove('repository-update')
        with self.assertRaisesRegex(ValueError, 'operation-not-declared'):
            self.authorize()

    def test_invalid_policy_cannot_elide_protected_roles_or_required_audio(self):
        del self.policy['platform_roles']['firmware']
        with self.assertRaises(ValueError):
            self.authorize()
        self.setUp()
        self.policy['platform_roles']['audio'] = ['speakersafetyd']
        with self.assertRaises(ValueError):
            self.authorize()


if __name__ == '__main__':
    unittest.main()
