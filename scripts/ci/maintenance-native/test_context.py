#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Real constructor checks plus bounded negative source, cleanup and admission controls."""
import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import contract as C
import job as J
import prepare as P
import run as R

SOURCE = next(p for p in HERE.parents if (p / 'scripts/ci/maintained_desktop574.py').is_file())
RECIPE = SOURCE / 'packages/tools/cachy-asahi-maintenance'
if not RECIPE.exists():
    RECIPE = SOURCE / 'artifacts/development/maintenance-package-implementation-20261027/proposed/packages/tools/cachy-asahi-maintenance'


class ContextControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='maintenance-source-controls-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.context = cls.root / 'context'
        cls.result = P.prepare(SOURCE, cls.context, RECIPE)

    def clone(self, name):
        target = self.root / name
        shutil.copytree(self.context, target)
        return target

    def manifest(self, source=None):
        return json.loads(((source or self.context) / C.LANE / 'source-manifest.json').read_bytes())

    def test_complete_constructor_manifest_and_both_workflows(self):
        manifest = self.manifest()
        J.manifest_files(self.context, manifest)
        self.assertIn(C.ACTOR, manifest['files'])
        self.assertIn(C.ALIAS, manifest['files'])
        self.assertEqual((self.context / C.ACTOR).read_bytes(), (self.context / C.ALIAS).read_bytes())
        self.assertLess(self.result['bytes'], 2 * 1024**2)
        self.assertLess(self.result['files'], 128)

    def test_defaults_null_and_registered_dispatcher(self):
        policy = json.loads((self.context / C.LANE / 'input-policy.json').read_bytes())
        for key in ('candidate_source', 'actual_source', 'actual_ref', 'actual_run'):
            self.assertIsNone(policy[key])
        self.assertEqual(policy['dispatcher_workflow_id'], 381664314)

    def test_null_candidate_source_refuses_before_hosted_authority(self):
        with patch.object(C, 'HERE', self.context / C.LANE):
            with self.assertRaisesRegex(ValueError, 'Root-bound published candidate'):
                J.prove(self.context, self.manifest(), {})

    def test_closed_frozen_recipe_and_pins(self):
        with patch.object(C, 'HERE', self.context / C.LANE):
            C.verify_source(self.context)
            recipe = C.recipe(self.context, C.NAMES[0])
            self.assertEqual(len(recipe['input_sha256']), 20)
            self.assertEqual(len(recipe['metadata']['source']), 18)
            self.assertEqual(len(C.files(C.NAMES[0])), 16)

    def test_alias_byte_mutation_refused(self):
        target = self.clone('alias-mutated')
        (target / C.ALIAS).write_bytes((target / C.ALIAS).read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'source pin differs'):
            J.manifest_files(target, self.manifest())

    def test_alias_omission_even_with_other_valid_pins_refused(self):
        manifest = self.manifest()
        del manifest['files'][C.ALIAS]
        with self.assertRaisesRegex(ValueError, 'complete closed'):
            J.manifest_files(self.context, manifest)

    def test_unmanifested_source_file_refused(self):
        target = self.clone('extra-source')
        (target / 'unexpected.py').write_text('raise RuntimeError("extra")\n')
        with self.assertRaisesRegex(ValueError, 'unmanifested'):
            J.manifest_files(target, self.manifest())

    def test_source_symlink_refused(self):
        target = self.clone('symlink-source')
        (target / 'alias.py').symlink_to('scripts/ci/maintenance-native/run.py')
        with self.assertRaisesRegex(ValueError, 'symlinks refused'):
            J.manifest_files(target, self.manifest())

    def test_frozen_package_drift_refused_before_output(self):
        recipe = self.root / 'bad-recipe'
        shutil.copytree(RECIPE, recipe)
        (recipe / 'health.py').write_bytes((recipe / 'health.py').read_bytes() + b'\n# drift\n')
        output = self.root / 'must-not-exist'
        with self.assertRaisesRegex(ValueError, 'frozen package byte drift'):
            P.prepare(SOURCE, output, recipe)
        self.assertFalse(output.exists())

    def test_infrastructure_drift_refused_before_output(self):
        source = self.root / 'bad-infrastructure'
        for name in json.loads((HERE / 'infrastructure-pins.json').read_bytes()):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / name, path)
        path = source / 'scripts/build/container-entry.sh'
        path.write_bytes(path.read_bytes() + b'\n# drift\n')
        output = self.root / 'must-not-exist-two'
        with self.assertRaisesRegex(ValueError, 'infrastructure drift'):
            P.prepare(source, output, RECIPE)
        self.assertFalse(output.exists())

    def test_constructor_never_overwrites(self):
        with self.assertRaisesRegex(ValueError, 'fresh separate'):
            P.prepare(SOURCE, self.context, RECIPE)

    def test_exact_acyclic_workflow_bootstrap(self):
        text = (self.context / C.ACTOR).read_text()
        self.assertIn(C.digest(self.context / C.LANE / 'job.py'), text)
        self.assertNotIn('@JOB_SHA256@', text)
        self.assertNotIn('@MANIFEST_SHA256@', text)
        self.assertIn('cancel-in-progress: false', text)
        self.assertIn('retention-days: 3', text)

    def test_pair_requires_archive_and_buildinfo_identity(self):
        good = dict(status='contents-reproduced', errors=[], packages={'fixture': dict(
            installed_contents_equal=True, pkginfo_equal=True, bytes_equal=True, buildinfo_equal=True)})
        R.pair_gate(good)
        for key in good['packages']['fixture']:
            bad = copy.deepcopy(good)
            bad['packages']['fixture'][key] = False
            with self.assertRaisesRegex(ValueError, 'archive bytes must reproduce'):
                R.pair_gate(bad)

    def test_installed_actor_refuses_host_before_any_mutation(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'installed.py')],
                                capture_output=True, timeout=10, cwd='/tmp')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'dedicated owned native ARM PID1 required', result.stderr)

    def test_actual_time_package_signer_uses_private_keyring(self):
        spec = importlib.util.spec_from_file_location('maintenance_package_signer_subject', HERE / 'installed.py')
        installed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installed)
        source = self.root / 'synthetic-signature-transport.pkg.tar.zst'
        source.write_bytes(b'SYNTHETIC SIGNATURE TRANSPORT ONLY; NOT AN ALPM PACKAGE\n')
        private = self.root / 'private-package-signer'
        class Commands:
            @staticmethod
            def command(argv, timeout=35):
                result = subprocess.run(argv, capture_output=True, timeout=timeout)
                if result.returncode:
                    raise ValueError(result.stderr.decode())
                return result.stdout.decode()
        def fixture_path(value):
            return private if str(value) == '/tmp/maintenance-package-signing' else Path(value)
        before = int(time.time())
        try:
            with patch.object(installed, 'Path', fixture_path):
                result = installed.sign_package(Commands, C, source)
            self.assertTrue(result['signature_verified_at_actual_time'])
            self.assertEqual(result['alpm_local_signature_policy'], 'Required')
            self.assertEqual(result['production_trust'], 'UNTOUCHED')
            self.assertFalse(result['fake_signature_time_used'])
            self.assertLessEqual(before, result['created_epoch'])
            self.assertLessEqual(result['created_epoch'], result['verified_epoch'])
            self.assertTrue((private / 'keyring/private-keys-v1.d').is_dir())
            self.assertEqual(C.digest(source), C.digest(Path(result['archive'])))
        finally:
            keyring = private / 'keyring'
            if keyring.exists():
                subprocess.run(['/usr/bin/gpgconf', '--homedir', str(keyring), '--kill', 'all'],
                               capture_output=True, check=True, timeout=15)
                shutil.rmtree(keyring)
        self.assertFalse((private / 'keyring').exists())

    def owner(self, name):
        runtime = self.root / name
        runtime.mkdir()
        (runtime / 'consumer.lock').touch()
        base = self.root / (name + '-base')
        base.mkdir()
        image = 'sha256:' + '1' * 64
        (base / 'report.json').write_text(json.dumps(dict(image=image)))
        containers = ['cachy-asahi-product-' + ('%032x' % n) for n in range(4)]
        owner = dict(schema_version=1, token='2' * 32, image=image, label=C.LABEL, containers=containers)
        (runtime / 'owner.json').write_text(json.dumps(owner))
        return runtime, base, owner

    def test_foreign_cleanup_actor_is_preserved(self):
        runtime, base, owner = self.owner('foreign-owner')
        calls = []
        def observer(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, json.dumps([dict(Id='3' * 64, Image=owner['image'],
                Name='/' + argv[-1], Config=dict(Labels={C.LABEL: 'f' * 32}))]).encode(), b'')
        with self.assertRaisesRegex(ValueError, 'foreign consumer preserved'):
            J.retire_consumers(runtime, base, dict(consumer_token=owner['token']), observer)
        self.assertEqual(len(calls), 1)

    def test_active_consumer_lease_blocks_retirement(self):
        runtime, base, owner = self.owner('leased-owner')
        with (runtime / 'consumer.lock').open('r+') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                J.retire_consumers(runtime, base, dict(consumer_token=owner['token']), lambda _: self.fail('no daemon call'))

    def test_owned_cleanup_uses_confirmed_id_and_verifies_absence(self):
        runtime, base, owner = self.owner('valid-owner')
        removed, present = [], set(owner['containers'])
        ids = {name: ('%064x' % (index + 4)) for index, name in enumerate(owner['containers'])}
        def observer(argv):
            if argv[1:3] == ['rm', '-f']:
                name = next(name for name, identity in ids.items() if identity == argv[-1])
                present.remove(name)
                removed.append(argv[-1])
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            name = argv[-1]
            if name not in present:
                return subprocess.CompletedProcess(argv, 1, b'', ('No such container: ' + name).encode())
            row = dict(Id=ids[name], Image=owner['image'], Name='/' + name, Config=dict(Labels={C.LABEL: owner['token']}))
            return subprocess.CompletedProcess(argv, 0, json.dumps([row]).encode(), b'')
        result = J.retire_consumers(runtime, base, dict(consumer_token=owner['token']), observer)
        self.assertEqual(result['status'], 'PASS_CONSUMERS_RETIRED')
        self.assertEqual(removed, [ids[name] for name in reversed(owner['containers'])])
        self.assertTrue(all(row['absence_verified'] for row in result['containers']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
