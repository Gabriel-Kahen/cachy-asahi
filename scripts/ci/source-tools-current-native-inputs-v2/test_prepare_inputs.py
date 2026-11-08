#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Current source bindings and held integration policy; no native actors."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('current_package_input_factory', HERE / 'prepare_inputs.py')
factory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factory)


class InputFactoryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.selection_raw = (HERE / 'selection-v2.json').read_bytes()
        cls.selection = factory.package.decode(cls.selection_raw)
        cls.selection_sha256 = hashlib.sha256(cls.selection_raw).hexdigest()
        cls.integration_raw = (HERE / 'native-integration-v2.json').read_bytes()
        cls.integration = factory.package.decode(cls.integration_raw)
        cls.bundle = (HERE / 'recipe-inputs-v2.tar').read_bytes()
        cls.files = factory.package.verify_bundle(cls.bundle, cls.selection)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='current-package-input-data-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.recipe = self.root / 'recipe'
        self.recipe.mkdir(mode=0o700)
        for name, raw in self.files.items():
            path = self.recipe / name
            path.write_bytes(raw)
            path.chmod(self.selection['recipe']['files'][name]['mode'])

    def prepared(self, **kwargs):
        return factory.prepare(self.recipe, kwargs.get('selection_raw', self.selection_raw),
            kwargs.get('selection_sha256', self.selection_sha256),
            kwargs.get('integration_raw', self.integration_raw), directory=kwargs.get('directory', HERE))

    def refused_policy(self, changed):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            factory.policy(self.selection, changed)

    def test_actual_current_recipe_component_roundtrip_and_null_admission(self):
        bodies = self.prepared()
        self.assertEqual(tuple(bodies), factory.OUTPUTS)
        self.assertEqual(bodies['source-tools-sources-v2.tar'], self.bundle)
        self.assertEqual(len(self.files), 16)
        self.assertEqual(len(self.selection['recipe']['sources']), 14)
        self.assertEqual(len(self.selection['recipe']['payload_files']), 18)
        contract = factory.package.decode(bodies['source-tools-inputs-v2.json'])
        self.assertTrue(all(value is None for value in contract['actual'].values()))
        self.assertFalse(contract['future_integration']['dispatch_allowed'])
        output = self.root / 'component'
        factory.write_component(output, bodies)
        self.assertEqual({path.name for path in output.iterdir()}, set(factory.OUTPUTS))
        self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, bodies)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o644 for path in output.iterdir()))
        self.assertFalse((output / 'native/source-map.json').exists())
        self.assertFalse((output / 'native/owner.py').exists())

    def test_selection_authentication_and_current_source_tamper_refuse(self):
        with self.assertRaises(ValueError):
            self.prepared(selection_sha256='0'*64)
        path = self.recipe / 'source_mirror_catalog.py'
        path.write_bytes(path.read_bytes()+b'\n# altered\n')
        with self.assertRaises(ValueError):
            self.prepared()

    def test_v1_version_source_count_and_payload_cannot_substitute(self):
        for key, value in (('package', dict(self.integration['package'], version='0.1.0-1')),
                           ('checks', dict(self.integration['checks'], payload_files=17))):
            changed = copy.deepcopy(self.integration); changed[key] = value; self.refused_policy(changed)
        changed = copy.deepcopy(self.integration)
        changed['recipe']['files'].pop('source_mirror_catalog.py')
        self.refused_policy(changed)

    def test_no_native_selector_or_root_admission_can_be_inferred(self):
        for key in self.integration['actual']:
            changed = copy.deepcopy(self.integration); changed['actual'][key] = 'not-authorized'
            self.refused_policy(changed)
        for key, value in (('status', 'READY'), ('namespace_cause', 'FIXED'), ('native', 'PASS')):
            changed = copy.deepcopy(self.integration); changed['admission'][key] = value
            self.refused_policy(changed)
        changed = copy.deepcopy(self.integration); changed['future_integration']['dispatch_allowed'] = True
        self.refused_policy(changed)

    def test_signed_alpm_required_and_restore_controls_are_not_optional(self):
        for key, value in (('SigLevel', 'Optional'), ('LocalFileSigLevel', 'Optional'),
                           ('architecture', 'x86_64'), ('target', 'HOST_SYSTEM'),
                           ('release_key_use', True), ('verify_both_archives', False),
                           ('required_negative_controls', []), ('restore', [])):
            changed = copy.deepcopy(self.integration); changed['signed_ALPM'][key] = value
            self.refused_policy(changed)

    def test_two_clean_builds_cannot_disable_checks_or_rebind_inventory_implicitly(self):
        for key, value in (('labels', ['a']), ('separate_clean_sources', False),
                           ('ordinary_build_user', 'root'), ('makepkg_flags', ['--nocheck']),
                           ('target_architecture', 'x86_64'), ('namespace_policy', 'SKIP'),
                           ('expected_check_rows', 3), ('check_result_format', 'ONE_JSON_OBJECT_PER_LINE'),
                           ('new_environment_requires_fresh_Root_inventory_binding', False),
                           ('compare', ['ARCHIVE_BYTES'])):
            changed = copy.deepcopy(self.integration); changed['build_pair'][key] = value
            self.refused_policy(changed)

    def test_current_catalog_must_be_exercised_in_both_locations(self):
        for key, value in (('locations', ['system']), ('global_version', 'cachy-asahi-source-tools 0.1.0'),
                           ('additional_catalog_commands', []), ('additional_command_count_per_location', 0)):
            changed = copy.deepcopy(self.integration); changed['installed_workflow'][key] = value
            self.refused_policy(changed)

    def test_module_and_config_bodies_are_joined_not_just_described(self):
        library = self.root / 'library'; library.mkdir()
        for name in ('makepkg-v2.conf', 'check_current_makepkg.py', 'current_package_inputs.py'):
            (library / name).write_bytes((HERE / name).read_bytes())
        path = library / 'check_current_makepkg.py'; path.write_bytes(path.read_bytes()+b'\n# tamper\n')
        with self.assertRaises(ValueError):
            self.prepared(directory=library)

    def test_component_is_finite_fresh_and_not_an_arbitrary_source_writer(self):
        bodies = self.prepared()
        with self.assertRaises(ValueError):
            factory.write_component(self.root / 'bad', {**bodies, 'native/owner.py': b'not allowed'})
        output = self.root / 'fresh'; factory.write_component(output, bodies)
        with self.assertRaises(FileExistsError):
            factory.write_component(output, bodies)
        alias = self.root / 'alias'; alias.symlink_to(output, target_is_directory=True)
        with self.assertRaises(ValueError):
            factory.write_component(alias, bodies)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(InputFactoryControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(dict(status='PASS' if result.wasSuccessful() else 'FAIL', tests=result.testsRun,
        failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
        evidence='CURRENT_PACKAGE_INPUT_DATA_ONLY_NOT_SOURCE_OR_NATIVE',
        native='NOT_RUN', ALPM='NOT_RUN', Source_constructor=False), sort_keys=True))
    raise SystemExit(not result.wasSuccessful() or bool(result.skipped))
