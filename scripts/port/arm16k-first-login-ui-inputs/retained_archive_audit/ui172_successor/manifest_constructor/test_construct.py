#!/usr/bin/env python3
"""Pinned metadata mutation controls; no original material reads or actors."""
import builtins
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('ui172_manifest_constructor_under_test', HERE/'construct.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class ConstructControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = C.parse((HERE/'inputs.json').read_bytes())
        pins = C.parse((HERE/'control-inputs.pin.json').read_bytes())
        stored = C.read_pinned(pins['stored'], {'remaining': 1024**2}, 1024**2)
        with gzip.GzipFile(fileobj=io.BytesIO(stored)) as stream:
            decoded = stream.read(8*1024**2+1)
        if len(decoded)>8*1024**2 or C.digest(decoded)!=pins['decoded']:
            raise AssertionError('pinned metadata fixture decoded cap/digest')
        cls.fixture = C.parse(decoded)

    def setUp(self):
        self.data = copy.deepcopy(self.fixture)

    def build(self):
        return C.build(self.data, self.config['documents'], self.config['keyring_sources'])

    def test_valid_exact_counts_roles_full_metadata_and_proof(self):
        manifest, plan = self.build()
        self.assertEqual(len(manifest['archives']), 172)
        self.assertEqual(len(manifest['baseline_metadata']), 111)
        self.assertEqual(len(manifest['required_namespace']), 14)
        self.assertEqual(len(manifest['fixed_baseline_namespace']), 7)
        self.assertEqual(len(manifest['original_file_pins']), 7)
        self.assertEqual(len(plan['files']), 348)
        roles = [r['signer_role'] for r in manifest['archives'].values()]
        self.assertEqual((roles.count('official'),roles.count('project')), (169,3))
        for name,row in manifest['archives'].items():
            self.assertEqual(row['metadata'], self.data['ledger']['archives'][name]['metadata'])
        self.assertEqual(manifest['metadata_prepare'], self.data['proposal']['metadata_prepare'])
        self.assertEqual(manifest['fixed_baseline_namespace'], self.data['baseline']['required_namespace'])
        self.assertEqual(manifest['original_file_pins'], self.data['baseline']['original_file_pins'])
        self.assertFalse(plan['copy_or_archive_reads_performed'])

    def test_root_approval_never_copied_and_gate_refuses(self):
        self.assertEqual(self.data['lower155']['issued_by'], 'Root')
        manifest,_ = self.build()
        for key in ['issued_by','issued_at','Root_review','actual_runtime_qualification','runtime_authority']:
            self.assertIsNone(manifest[key])
        for key in ['valid_until_utc','issued_by','Root_TEST_trust_issuance']:
            self.assertIsNone(manifest['trust'][key])
        self.assertNotEqual(manifest['status'], 'ROOT_REVIEWED_COMPLETE_UI283_CLOSURE')
        with self.assertRaisesRegex(C.Refused, 'external Root'):
            C.refuse_unissued(manifest)
        manifest['issued_by'] = 'Root'
        manifest['status'] = 'ROOT_REVIEWED_COMPLETE_UI283_CLOSURE'
        with self.assertRaises(C.Refused):
            C.refuse_unissued(manifest)

    def test_pure_build_opens_nothing_and_preserves_inputs(self):
        before = copy.deepcopy(self.data)
        with patch.object(builtins,'open',side_effect=AssertionError('unexpected open')), \
             patch.object(io,'open',side_effect=AssertionError('unexpected io.open')), \
             patch.object(C.os,'open',side_effect=AssertionError('unexpected os.open')):
            manifest,plan = self.build()
        self.assertEqual(self.data,before)
        manifest['archives']['cachy-asahi-first-login']['metadata']['pkgname'].append('output-only')
        manifest['baseline_metadata']['glib2']['files'].append('output-only')
        self.assertEqual(self.data,before)

    def test_role_confusion_and_fixed_project_hash_refused(self):
        name = 'cachy-asahi-first-login'
        self.data['ledger']['archives'][name]['signer_role'] = 'official'
        with self.assertRaisesRegex(C.Refused, 'roles'):
            self.build()
        self.data = copy.deepcopy(self.fixture)
        self.data['ledger']['archives'][name]['archive']['sha256'] = '0'*64
        next(r for r in self.data['proposal']['materials'] if r['name']==name)['archive']['sha256'] = '0'*64
        with self.assertRaisesRegex(C.Refused, 'fixed3 project'):
            self.build()
        self.data = copy.deepcopy(self.fixture)
        official = next(n for n,r in self.data['ledger']['archives'].items() if r['signer_role']=='official')
        self.data['ledger']['archives'][official]['expected_signer'] = self.data['ledger']['trust']['keyrings']['project']['primary']
        with self.assertRaisesRegex(C.Refused, 'signer/keyring'):
            self.build()

    def test_official_any_arch_is_retained(self):
        names = [n for n,r in self.data['ledger']['archives'].items()
                 if r['signer_role']=='official' and r['metadata']['arch']==['any']]
        self.assertTrue(names)
        manifest,_ = self.build()
        self.assertTrue(all(manifest['archives'][n]['metadata']['arch']==['any'] for n in names))

    def test_pkginfo_duplicate_identity_and_dependency_order_refused(self):
        row = self.data['ledger']['archives']['cachy-asahi-first-login']
        row['metadata']['pkgname'].append('cachy-asahi-first-login')
        with self.assertRaisesRegex(C.Refused, 'PKGINFO'):
            self.build()
        self.data = copy.deepcopy(self.fixture)
        row = next(r for r in self.data['ledger']['archives'].values() if len(r['metadata'].get('depend',[]))>1)
        row['metadata']['depend'] = list(reversed(row['metadata']['depend']))
        with self.assertRaisesRegex(C.Refused, 'PKGINFO'):
            self.build()

    def test_baseline_association_and_pam_payload_pin_refused(self):
        self.data['baseline']['baseline_metadata']['glib2']['files'].append('usr/share/forged')
        with self.assertRaisesRegex(C.Refused, 'association'):
            self.build()
        self.data = copy.deepcopy(self.fixture)
        self.data['baseline']['required_namespace']['etc/pam.d/login']['payload']['sha256'] = '0'*64
        with self.assertRaisesRegex(C.Refused, 'baseline ownership/payload/pin'):
            self.build()
        self.data = copy.deepcopy(self.fixture)
        for name in ['baseline','lower155']:
            self.data[name]['original_file_pins']['/etc/pam.d/login'] = '0'*64
        with self.assertRaisesRegex(C.Refused, 'baseline ownership/payload/pin'):
            self.build()

    def test_alpm_and_selected_edge_witness_tamper_refused(self):
        self.data['ledger']['metadata_prepare']['prepare']['remove'].append('glibc')
        with self.assertRaisesRegex(C.Refused, 'ALPM'):
            self.build()
        self.data = copy.deepcopy(self.fixture)
        self.data['ledger']['actual_dependency_joins'][0]['provider'] = 'forged'
        with self.assertRaisesRegex(C.Refused, 'edge witnesses'):
            self.build()
        self.data = copy.deepcopy(self.fixture)
        self.data['ledger']['actual_dependency_joins'][0]['status'] = 'HOLD'
        with self.assertRaisesRegex(C.Refused, 'edge witnesses'):
            self.build()

    def test_namespace_owner_mode_policy_and_template_refused(self):
        mutations = [
            lambda d:d['ledger']['required_namespace']['usr/bin/Xvfb'].__setitem__('owner','fish'),
            lambda d:d['ledger']['required_namespace']['usr/bin/Xvfb']['payload'].__setitem__('mode',0o644),
            lambda d:d['ledger']['required_namespace']['usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy']['payload'].__setitem__('sha256','0'*64),
            lambda d:d['ledger']['templates']['fish']['pin'].__setitem__('sha256','0'*64),
        ]
        for mutate in mutations:
            self.data = copy.deepcopy(self.fixture)
            mutate(self.data)
            with self.subTest(mutation=mutate),self.assertRaises(C.Refused):
                self.build()

    def test_missing_exact_input_and_archive_pair_refused(self):
        del self.data['ledger']['archives']['xorg-server-xvfb']
        with self.assertRaisesRegex(C.Refused, 'unique172'):
            self.build()
        self.data = copy.deepcopy(self.fixture)
        self.data['ledger']['archives']['xorg-server-xvfb']['signature']['sha256'] = '0'*64
        with self.assertRaisesRegex(C.Refused, 'proposal archive/signature'):
            self.build()
        self.data = copy.deepcopy(self.fixture)
        self.data['ledger']['archives']['xorg-server-xvfb']['filename'] = '../forged.pkg.tar.xz'
        with self.assertRaisesRegex(C.Refused, 'filename'):
            self.build()

    def test_duplicate_json_nonfinite_and_fixture_pin_caps_refused(self):
        for body in [b'{"x":1,"x":2}', b'{"nested":{"x":1,"x":2}}', b'{"x":NaN}', b'{"x":Infinity}']:
            with self.subTest(body=body),self.assertRaises(C.Refused):
                C.parse(body)
        ref = C.parse((HERE/'control-inputs.pin.json').read_bytes())['stored']
        with self.assertRaisesRegex(C.Refused, 'byte cap'):
            C.read_pinned(ref,{'remaining':ref['bytes']-1},1024**2)
        wrong = {**ref,'sha256':'0'*64}
        budget = {'remaining':1024**2}
        with self.assertRaisesRegex(C.Refused, 'full pin/identity'):
            C.read_pinned(wrong,budget,1024**2)
        self.assertEqual(budget['remaining'],1024**2-ref['bytes'])


if __name__ == '__main__':
    unittest.main()
