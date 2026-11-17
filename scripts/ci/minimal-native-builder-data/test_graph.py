# SPDX-License-Identifier: MIT
"""Genuine fixed catalogs plus bounded metadata adversaries; no Root profiles."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

CI = None  # The fenced driver supplies its already verified helper module.


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.D = json.loads((CI.SOURCE / 'builder.lock.json').read_bytes())
        cls.P = CI.module(CI.SOURCE / 'plan.py', 'minimal206_fixed_plan')
        cls.E = CI.module(CI.SOURCE / 'export.py', 'minimal206_exact_export')
        cls.R = cls.P.resolver()
        cls.regenerated, cls.signatures = cls.P.plan(CI.verify_catalogs(CI.HERE / 'catalogs'))

    def graph(self, rows, extra_anchors=()):
        view = copy.deepcopy(rows)
        for binding in self.D['explicit_provider_bindings']:
            consumer = next(r for r in view if self.R.identity(r) == binding['consumer'])
            consumer['depends'] = [binding['solver_constraint'] if q == binding['requirement'] else q for q in consumer['depends']]
        base_names = {r['name'][0] for r in self.D['rootfs_original_inventory']}
        anchors = [r for r in view if r['name'] in base_names] + list(extra_anchors)
        return self.R.resolve(anchors, view, self.D['roots'], {}, limits=self.R.Limits(max_packages=256, max_edges=4096, max_depth=128, max_seconds=60))

    def test_genuine_full_catalog_regeneration_is_byte_identical(self):
        self.assertEqual(self.P.encoded(self.regenerated), (CI.SOURCE / 'builder.lock.json').read_bytes())
        self.assertEqual(len(self.regenerated['packages']), 206); self.assertEqual(len(self.regenerated['edges']), 869)
        self.assertEqual(len(self.regenerated['resolver_remaining_review_holds']), 1236)
        self.assertEqual(len(self.regenerated['catalog_unselectable']), 7)
        self.assertEqual(len(self.signatures), 206)
        for row in self.regenerated['packages']:
            archive = row['archive']; self.assertEqual(CI.pin(self.signatures[archive['filename'] + '.sig']), dict(bytes=archive['signature_bytes'], sha256=archive['signature_sha256']))
        for key in ('all_inputs_retrieved', 'signature_authentication', 'Root_selection', 'native', 'M2', 'distribution_release'):
            self.assertIsNone(self.regenerated[key])
        self.assertTrue(all(not row['signed'] for row in self.regenerated['catalogs']))

    def test_native_operand_and_expected206_inventory_regenerate_exact(self):
        native = self.E.project(self.regenerated)
        self.assertEqual(self.E.encoded(native), (CI.SOURCE / 'native-inputs.lock.json').read_bytes())
        inventory = ''.join(r['name'] + ' ' + r['version'] + '\n' for r in self.regenerated['packages']).encode()
        self.assertEqual(inventory, (CI.SOURCE / 'expected206.lock').read_bytes())
        self.assertEqual(len(native['packages']), 206); self.assertEqual(native['status'], 'UNISSUED_BUILD_ONLY_INPUTS')
        self.assertEqual(native['native_build'], 'NOT RUN'); self.assertEqual(native['installation'], 'NOT RUN')
        self.assertEqual(len(native['rootfs_packages']), 165)
        old_inventory = CI.checked(CI.OLD349_PATH, CI.OLD349_PIN).decode().splitlines()
        old_names = {line.split()[0] for line in old_inventory}
        self.assertEqual(len(old_inventory), 349); self.assertEqual(len(old_names), 349)
        self.assertNotEqual({row['name'] for row in native['packages']}, old_names)
        self.assertEqual(self.D['scope'], 'BUILDER_ONLY_NOT_FROZEN349_OR_FULL_PORT_OR_RUNTIME_OR_M2')

    def test_every_selected_edge_and_explicit_binding_satisfies_original_declaration(self):
        by_identity = {(r['repo'], r['name'], r['version']): r for r in self.regenerated['packages']}
        for edge in self.regenerated['edges']:
            identity = edge['selected']; provider = by_identity[(identity['repo'], identity['name'], identity['version'])]
            self.assertEqual(edge['status'], 'SATISFIED'); self.assertTrue(self.R.witnesses(provider, edge['requirement']))
        for binding in self.regenerated['explicit_provider_bindings']:
            provider = next(r for r in self.regenerated['packages'] if self.R.identity(r) == binding['provider'])
            consumer = next(r for r in self.regenerated['packages'] if self.R.identity(r) == binding['consumer'])
            self.assertIn(binding['requirement'], consumer['depends'])
            self.assertTrue(self.R.witnesses(provider, binding['requirement']))
            self.assertEqual([self.R.identity(r) for r in self.regenerated['packages'] if self.R.witnesses(r, binding['solver_constraint'])], [binding['provider']])

    def test_missing_normal_dependency_conflict_and_replacement_refuse(self):
        self.assertEqual(self.graph(self.D['packages'])['metadata_graph_status'], 'PASS')
        for field, value, code in [('depends', 'MODEL-missing-provider>=1', 'unsatisfied-dependency'),
                                   ('conflicts', 'glibc', 'declared-conflict'), ('replaces', 'glibc', 'declared-replacement')]:
            rows = copy.deepcopy(self.D['packages']); row = next(r for r in rows if r['name'] == 'curl'); row[field].append(value)
            with self.subTest(field=field):
                result = self.graph(rows); self.assertEqual(result['metadata_graph_status'], 'FAIL')
                self.assertIn(code, {b['code'] for b in result['blockers'] if b['scope'] == 'graph'})

    def test_unexpected_versioned_provider_alternative_refuses(self):
        binding = self.D['explicit_provider_bindings'][0]
        provider = next(r for r in self.D['packages'] if self.R.identity(r) == binding['provider'])
        wrong = copy.deepcopy(provider); wrong['version'] = '0-1'
        self.assertFalse(self.R.witnesses(wrong, binding['solver_constraint']))
        alternate = copy.deepcopy(provider); alternate.update(name='MODEL-extra-provider', version='1-1', depends=[],
                                                             provides=[binding['solver_constraint']], conflicts=[], replaces=[])
        self.assertTrue(self.R.witnesses(alternate, binding['solver_constraint']))
        result = self.graph(self.D['packages'] + [alternate], [alternate])
        self.assertEqual(result['metadata_graph_status'], 'FAIL')
        self.assertIn('ambiguous-provider', {b['code'] for b in result['blockers'] if b['scope'] == 'graph'})

    def test_catalog_namespace_alias_and_body_tampering_refuse(self):
        with tempfile.TemporaryDirectory(prefix='minimal206-catalog-refusal-') as name:
            root = Path(name)
            for row in self.D['catalogs']: (root / (row['repo'] + '.db')).symlink_to(CI.HERE / 'catalogs' / (row['repo'] + '.db'))
            with self.assertRaises(ValueError): CI.verify_catalogs(root)
            (root / 'unlisted').write_bytes(b'MODEL-not-a-catalog')
            with self.assertRaises(ValueError): CI.verify_catalogs(root)
            for path in root.iterdir(): path.unlink()
            for row in self.D['catalogs']: (root / (row['repo'] + '.db')).write_bytes(b'MODEL-not-real-catalog-data')
            with self.assertRaises(ValueError): CI.verify_catalogs(root)
