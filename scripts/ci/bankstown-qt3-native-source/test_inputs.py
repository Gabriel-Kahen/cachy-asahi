#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fenced finite MODEL metadata; no delivered archive or Root grant is invented."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {
            'os.system', 'os.exec', 'os.posix_spawn', 'os.fork', 'fcntl.flock'}:
        raise AssertionError('MODEL operational event forbidden: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('qt3_inputs_model', HERE / 'inputs.py')
I = importlib.util.module_from_spec(spec)
spec.loader.exec_module(I)


class Fixture:
    """Actual maintained metadata, fictional unselected delivery paths (no bodies)."""
    def __init__(self, directory):
        self.root = directory / 'source'
        self.root.mkdir()
        for name in I.HELD:
            self.copy(I.NATIVE + name)
        self.copy(I.NATIVE + 'build_tools_tools_v2.py')
        for name in I.LOCKS:
            self.copy(name)
        self.copy('scripts/ci/first-login-enrollment-native-source/profile.json')
        base_raw = (ROOT / 'scripts/ci/inputs.lock.json').read_bytes()
        profile_raw = (ROOT / 'scripts/ci/desktop-current011-native-source/fixtures/native/input-profile.json').read_bytes()
        base, profile = json.loads(base_raw), json.loads(profile_raw)
        self.baseline = dict(profile['original341']['packages'])
        self.baseline.update({r['name']: r['version'] for r in profile['additions']['rows']})
        inventory = ''.join(n + ' ' + v + '\n' for n, v in sorted(self.baseline.items())).encode()
        self.baseline_ref = self.put('inputs/stages/baseline349.expected.lock', inventory)
        self.request = {'base_lock': self.put('MODEL/base-lock.json', base_raw),
                        'bootstrap_profile': self.put('MODEL/supplement-profile.json', profile_raw),
                        'baseline_inventory': self.baseline_ref, 'official_trust': None}
        for group, rows, signed in (
            ('base_materials', [base['rootfs'], *base['packages']], True),
            ('supplemental_materials', profile['additions']['rows'], True),
            ('keyring_materials', base['keyring_files'], False)):
            self.request[group] = {}
            for row in rows:
                for suffix in ('', '.sig') if signed else ('',):
                    name = row['filename'] + suffix
                    self.request[group][name] = dict(path=str(directory / 'UNSELECTED-MODEL-BASE' / name),
                        bytes=row['signature_size'] if suffix else row['size'],
                        sha256=row['signature_sha256'] if suffix else row['sha256'])
        provider = I.held(self.root, 'base_inputs_current_v3.py')
        self.selected = I.selected_packages(self.root, provider)
        self.expected = self.baseline | {n: r['version'] for n, r in self.selected.items()}
        refs = {}
        for name in sorted(self.selected.keys() - self.baseline.keys()):
            row = self.selected[name]
            for suffix, key in (('', 'archive'), ('.sig', 'signature')):
                filename = row['filename'] + suffix
                refs[filename] = dict(path=str(directory / 'UNSELECTED-MODEL-CANDIDATE' / filename), **row[key])
        self.request['candidate_materials'] = refs
        catalog = dict(purpose='bankstown-optional-qtbase6.12.0-3-input-candidate',
            candidate='EXPLICIT_OPTIONAL_QT_BASE_6.12.0-3', complete=True, original_minus2_hold='UNCHANGED',
            native_tools_profile='NOT_PRODUCED', source_legal_freshness_acceptance='HELD',
            candidate_lock=dict(bytes=88821, sha256=list(I.LOCKS.values())[1][1]),
            packages={n: {'metadata': {'/.PKGINFO': dict(pkgname=[n], pkgver=[r['version']], arch=[r['arch']])}}
                      for n, r in self.selected.items()}, missing_inputs=[], unresolved_package_dependencies=[],
            unresolved_elf_dependencies=[], unresolved_GNU_versions=[])
        self.request['catalog'] = self.put('MODEL/catalog.json', I.encoded(catalog))
        self.rows = {}
        for name in ('scripts/ci/first-login-enrollment-native-source/profile.json', 'inputs/stages/baseline349.expected.lock'):
            self.rows[name] = dict(I.pin((self.root / name).read_bytes()), mode=0o644)

    def put(self, name, raw):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
        p.chmod(0o644)
        return dict(path=str(p), **I.pin(raw))

    def copy(self, name):
        return self.put(name, (ROOT / name).read_bytes())

    def plan(self, request=None, verify=False):
        return I.plan_inputs(source_root=self.root, source_rows=self.rows,
                             request=self.request if request is None else request, verify_archives=verify)


class InputControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='qt3-inputs-MODEL-')
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(Path(self.tmp.name))

    def test_actual_base_apis_exact477_metadata_only(self):
        p = self.f.plan()
        self.assertEqual((len(p['base_rows']), len(p['additions']), len(p['expected'])), (257, 128, 477))
        self.assertEqual(p['expected'], self.f.expected)
        self.assertFalse(p['verified_archives'])
        self.assertIsNone(p['Root_acceptance'])
        self.assertEqual(p['prospective_inventory_pin'], dict(bytes=9102,
            sha256='64f9c67795bd16f4cf3704dc0a050d2d17d1baa6e42b4e4fa254507b15183c49'))

    def test_null_request_refused(self):
        with self.assertRaisesRegex(ValueError, 'CLOSED_QT3'):
            I.plan_inputs(source_root=self.f.root, source_rows=self.f.rows, request=None)

    def test_real_verification_cannot_adopt_fictional_paths(self):
        with self.assertRaises(FileNotFoundError):
            self.f.plan(verify=True)

    def test_missing_selected_signature_refused(self):
        r = copy.deepcopy(self.f.request)
        del r['candidate_materials'][next(k for k in r['candidate_materials'] if k.endswith('.sig'))]
        with self.assertRaisesRegex(ValueError, 'EXACT256'):
            self.f.plan(r)

    def test_wrong_archive_pin_refused(self):
        r = copy.deepcopy(self.f.request)
        r['candidate_materials'][next(iter(r['candidate_materials']))]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'EXACT_CANDIDATE_WHOLE_PIN'):
            self.f.plan(r)

    def test_alias_material_roles_refused(self):
        r = copy.deepcopy(self.f.request)
        rows = list(r['candidate_materials'].values())
        rows[1]['path'] = rows[0]['path']
        with self.assertRaisesRegex(ValueError, 'DISTINCT_COMPLETE773'):
            self.f.plan(r)

    def test_catalog_identity_and_unresolved_hold(self):
        for mutation in ('identity', 'unresolved'):
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(self.f.request)
                c = json.loads(Path(r['catalog']['path']).read_bytes())
                if mutation == 'identity':
                    c['packages']['rust']['metadata']['/.PKGINFO']['pkgver'] = ['1:1.98.0-1']
                else:
                    c['unresolved_elf_dependencies'] = ['MODEL missing provider']
                r['catalog'] = self.f.put('MODEL/' + mutation + '.json', I.encoded(c))
                with self.assertRaisesRegex(ValueError, 'CATALOG_SELECTED_IDENTITY|CATALOG_CLOSURE_HOLD'):
                    self.f.plan(r)

    def test_frozen_candidate_or_helper_drift_refuses(self):
        (self.f.root / I.NATIVE / 'image_current_v3.py').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'HELD_HELPER_'):
            self.f.plan()

    def test_base_inventory_replacement_refused(self):
        self.f.rows['inputs/stages/baseline349.expected.lock']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.f.plan()

    def test_provider_null_does_not_issue_complete_inputs(self):
        with self.assertRaisesRegex(ValueError, 'complete517_reference_result'):
            I.provider_fields(None, source_root=self.f.root)


if __name__ == '__main__':
    unittest.main()
