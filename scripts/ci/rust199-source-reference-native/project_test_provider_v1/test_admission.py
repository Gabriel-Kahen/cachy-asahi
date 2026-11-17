# SPDX-License-Identifier: MIT
"""MODEL Root/signature/native boundary; actual metadata/archive/source predicates.

No real signature, native package, Root approval or Source identity is generated.
Native receipt replay has its own unmocked synthetic controls in test_native.py.
"""
import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ATTEMPTS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event in ('os.system', 'fcntl.flock'):
        ATTEMPTS.append(event)
        raise AssertionError('MODEL_ADMISSION_NO_OPERATIONAL_ROLE: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('project_admission_controls', HERE / 'admission.py')
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
D = A.D
ELF = b'\x7fELF\x02\x01\x01' + bytes(9) + b'\x03\x00\xb7\x00' + bytes(44) + b'MODEL_NOT_EXECUTABLE'
RECIPE = b'# MODEL original recipe bytes, never execute\n'
SMOKE = b'/* MODEL source only */\n'
LICENSE = b'MODEL source-license DATA, not a license grant\n'
KEY_BODY = b'\x04\0\0\0\x01\x01MODEL_NOT_A_REAL_KEY'
KEY = bytes([0xc6, len(KEY_BODY)]) + KEY_BODY
SIGNATURE = b'\xc2\x01\x04'  # Deliberately NOT a cryptographically valid signature.
FPR = hashlib.sha1(b'\x99' + len(KEY_BODY).to_bytes(2, 'big') + KEY_BODY).hexdigest().upper()


class Controls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='project-admission-MODEL-'); self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name); self.root = self.base / 'source'; self.root.mkdir()
        (self.root / 'expected349.lock').write_bytes((HERE.parent / 'expected349.lock').read_bytes())
        self.specs = copy.deepcopy(A.SPECS); self.packages = []
        self.key = self.put('project-test/public.gpg', KEY)
        for name, selected in self.specs.items():
            prefix = 'dependency-provenance/' + name + '/'
            selected['known_recipe_files'] = {'PKGBUILD': D.pin(RECIPE), 'smoke.c': D.pin(SMOKE)}
            recipe = self.put(prefix + 'PKGBUILD', RECIPE); self.put(prefix + 'smoke.c', SMOKE)
            license_files = {}
            for leaf in selected['license_files']:
                self.put(prefix + 'licenses/' + leaf, LICENSE); license_files[prefix + 'licenses/' + leaf] = D.pin(LICENSE)
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w:gz') as tar:
                for leaf in selected['license_files']:
                    entry = tarfile.TarInfo(selected['source']['archive_prefix'] + '/' + leaf)
                    entry.size = len(LICENSE); tar.addfile(entry, io.BytesIO(LICENSE))
            source = archive.getvalue(); selected['source'].update(D.pin(source))
            src = prefix + 'sources/' + selected['source']['filename']; self.put(src, source)
            short = 'llhttp' if 'llhttp' in name else 'git2'; provider = 'usr/lib/lib' + short + '.so.1'
            metadata = dict(pkgname=[name], pkgver=[selected['version']], arch=['aarch64'], license=selected['licenses'],
                depend=selected['dependencies'], provides=[*selected['required_provides'], 'lib' + short + '.so'],
                conflict=selected['conflicts'], replaces=[])
            buildinfo = ('format = 2\npkgname = ' + name + '\npkgver = ' + selected['version'] + '\npkgarch = aarch64\npkgbuild_sha256sum = ' + recipe['sha256'] + '\n').encode()
            row = dict(name=name, version=selected['version'], filename=name + '-' + selected['version'].split(':')[-1] + '-aarch64.pkg.tar.xz',
                archive={}, signature=D.pin(SIGNATURE), url='https://MODEL.invalid/' + name,
                metadata=metadata, providers={provider: dict(kind='file', mode=0o755, **D.pin(ELF)),
                    'usr/lib/lib' + short + '.so': dict(kind='symlink', mode=0o777, target=Path(provider).name)},
                license_provenance=dict(url='https://github.com/Gabriel-Kahen/cachy-asahi/blob/' + selected['recipe_revision'] + '/' + selected['recipe_path'] + '/PKGBUILD',
                    revision=selected['recipe_revision'], licenses=selected['licenses'], pkgbuild=recipe, buildinfo=D.pin(buildinfo),
                    license_files=license_files, recipe_files={recipe['path']: D.pin(RECIPE), prefix + 'smoke.c': D.pin(SMOKE)},
                    sources={src: {k: selected['source'][k] for k in ('url', 'revision', 'bytes', 'sha256')}}),
                native=dict(builds=[{}, {}], comparison={}))
            path = self.root / 'build-dependencies' / row['filename']; path.parent.mkdir(exist_ok=True)
            with tarfile.open(path, 'w:xz') as tar:
                items = [('.PKGINFO', ''.join(k + ' = ' + v + '\n' for k, values in metadata.items() for v in values).encode(), 0o644),
                         ('.BUILDINFO', buildinfo, 0o644), (provider, ELF, 0o755)]
                items += [('usr/share/licenses/' + name + '/' + leaf, LICENSE, 0o644) for leaf in selected['license_files']]
                for relative, body, mode in items:
                    entry = tarfile.TarInfo(relative); entry.size = len(body); entry.mode = mode; tar.addfile(entry, io.BytesIO(body))
                entry = tarfile.TarInfo('usr/lib/lib' + short + '.so'); entry.type = tarfile.SYMTYPE
                entry.mode = 0o777; entry.linkname = Path(provider).name; tar.addfile(entry)
            row['archive'] = D.pin(path.read_bytes()); path.with_name(path.name + '.sig').write_bytes(SIGNATURE)
            self.packages.append(row)
        self.patch = patch.object(A, 'SPECS', self.specs); self.patch.start(); self.addCleanup(self.patch.stop)
        self.p = dict(schema=1, kind='PROJECT_TEST_NATIVE_BUILD_DEPENDENCIES_V1', predecessor=A.PREDECESSOR,
            parent350=D.PARENT350, trust=dict(scope='PROJECT_TEST_ONLY', public_key=self.key,
                primary_fingerprint=FPR, signing_fingerprint=FPR, ALARM_authentication=False),
            packages=self.packages, qualification=A.QUALIFICATION, actual=A.ACTUAL)

    def put(self, name, body):
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body)
        return dict(path=name, **D.pin(body))

    def decision(self, p=None):
        p = self.p if p is None else p
        return dict(schema=1, kind='ROOT_ACCEPTED_NATIVE_PROJECT_TEST_PROVIDER_TUPLES_V1', issuer='Root', approved=True,
            scope='PROJECT_TEST_ONLY', policy_pin=D.pin(D.encode(p)), accepted_tuples={row['name']: D.pin(D.encode(row)) for row in p['packages']},
            reviews=dict(native_execution=True, clean_pair=True, normal_dependency_checks=True, complete_inventories=True, exact_source_license_bytes=True),
            issued_at=900, expires_at=1100, Root_acceptance=None, release_acceptance=False)

    def admit(self, p=None, decision=None, *, model_native=True, now=1000):
        p = self.p if p is None else p; decision = self.decision(p) if decision is None else decision
        original = A.module
        def modules(path, *args):
            if model_native and Path(path).name == 'native.py':
                return SimpleNamespace(validate=lambda root, row, tick: {'MODEL_NATIVE_BOUNDARY': True})
            return original(path, *args)
        with patch.object(A, 'module', side_effect=modules):
            return A.admit(self.root, D.encode(p), D.pin(D.encode(p))['sha256'], D.encode(decision), D.pin(D.encode(decision))['sha256'], now=now)

    def test_model_selection_runs_real_policy_source_inventory_and_public_key_gates(self):
        state = self.admit(); self.assertEqual(state['status'], 'ROOT_SELECTED_PROJECT_TEST_INPUT_DATA_ONLY')
        self.assertFalse(state['signature_mathematics_verified']); self.assertFalse(state['native_acceptance'])
        self.assertEqual(len(D.inventory(state['expected_inventory'])), 352)
        self.assertIsNone(state['Root_acceptance'])

    def test_real_native_evidence_gate_refuses_missing_receipts_despite_model_root_approval(self):
        with self.assertRaises((ValueError, KeyError)): self.admit(model_native=False)

    def test_root_hash_expiry_reapproval_and_unchanged_tuple_are_mandatory(self):
        decision = self.decision()
        for change in (lambda d: d.update(approved=False), lambda d: d.update(expires_at=999),
                       lambda d: d['reviews'].update(native_execution=False), lambda d: d.update(scope='ALARM'),
                       lambda d: d.update(Root_acceptance=True), lambda d: d['accepted_tuples'].clear()):
            value = copy.deepcopy(decision); change(value)
            with self.subTest(value=value), self.assertRaises(ValueError): self.admit(decision=value)
        with self.assertRaisesRegex(ValueError, 'external Root decision SHA'):
            A.root_decision(D.encode(decision), '0' * 64, self.p, D.pin(D.encode(self.p)), 1000)

    def test_official_scope_unsigned_host_and_baseline_replacement_policy_refuse(self):
        for change in (lambda p: p.update(schema=18), lambda p: p['trust'].update(ALARM_authentication=True),
                       lambda p: p['trust'].update(primary_fingerprint=D.SIGNER), lambda p: p['packages'][0]['signature'].update(bytes=0),
                       lambda p: p['packages'][0]['metadata'].update(arch=['x86_64']),
                       lambda p: p['packages'][0]['metadata'].update(replaces=['openssl']),
                       lambda p: p['packages'][0]['providers'][next(iter(p['packages'][0]['providers']))].update(mode=True)):
            value = copy.deepcopy(self.p); change(value)
            with self.subTest(value=value), self.assertRaises(ValueError): A.validate_policy(value)
        with self.assertRaises(ValueError): D.validate_policy(self.p)

    def test_source_license_recipe_and_private_keyhome_substitutions_refuse(self):
        row = self.packages[0]
        for name in (row['license_provenance']['pkgbuild']['path'], next(iter(row['license_provenance']['license_files'])), next(iter(row['license_provenance']['sources']))):
            path = self.root / name; raw = path.read_bytes(); path.write_bytes(raw + b'CHANGED')
            try:
                with self.assertRaises(ValueError): self.admit()
            finally: path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'private keyhome'):
            A.reference(dict(path='.gnupg/key', bytes=1, sha256='0' * 64))

    def test_public_key_packets_reject_secret_and_wrong_fingerprint(self):
        A.public_key(KEY, self.p['trust'])
        for body in (b'\xc5\x01X', b'-----BEGIN PGP PRIVATE KEY BLOCK-----', b'\xc6\xff\0'):
            with self.assertRaises(ValueError): A.public_key(body, self.p['trust'])
        with self.assertRaises(ValueError): A.public_key(KEY, dict(self.p['trust'], primary_fingerprint='F' * 40))

    def good_status(self):
        return ('[GNUPG:] VALIDSIG ' + FPR + ' 1970-01-01 900 0 4 0 1 10 00 ' + FPR + '\n').encode()

    def test_signature_mathematics_boundary_keeps_exact_signer_and_time_refusals(self):
        A.signature_status(self.good_status(), self.p, 1000)
        for bad in (self.good_status() + b'[GNUPG:] KEYEXPIRED 1\n', self.good_status() * 2,
                    self.good_status().replace(FPR.encode(), D.SIGNER.encode()), self.good_status().replace(b'900 0', b'900 999'), b''):
            with self.assertRaises(ValueError): A.signature_status(bad, self.p, 1000)

    def test_context_requires_public_verifier_before_archive_and_retains_exact_inputs(self):
        state = self.admit(); context = self.base / 'context'; output = self.base / 'output'
        context.mkdir(mode=0o700); output.mkdir(mode=0o700); calls = []
        def call(argv, timeout):
            calls.append(argv); self.assertEqual(timeout, 30); self.assertEqual(argv[0], '/usr/bin/gpgv')
            self.assertNotIn('--import', argv)
            return SimpleNamespace(returncode=0, stdout=self.good_status())
        result = A.prepare_context(state, context, output, call, now=1000)
        self.assertEqual(len(calls), 2); self.assertEqual(result['trust_scope'], 'PROJECT_TEST_ONLY')
        self.assertIs(result['ALARM_authentication'], False); self.assertFalse(result['native_acceptance'])
        for row in self.packages:
            self.assertEqual((context / 'project-test-dependencies' / row['filename']).read_bytes(), (self.root / 'build-dependencies' / row['filename']).read_bytes())
        self.assertEqual((context / 'project-test-dependencies/expected-qualified.lock').read_bytes(), state['expected_inventory'])
        original = b'MODEL_PARENT\nUSER alarm\nWORKDIR /tmp\n'
        with self.assertRaisesRegex(ValueError, 'verified complete TEST context'):
            A.image_dockerfile(state, original, {}, now=1000)
        text = A.image_dockerfile(state, original, result, now=1000)
        self.assertIn(b'--gpgdir /tmp/rust-project-test-gpg', text)
        self.assertIn(b'LocalFileSigLevel = Required', text)
        self.assertIn(b' -T ', text); self.assertNotIn(b'--nodeps', text)
        self.assertNotIn(b'/etc/pacman.d/gnupg', text[len(original):])
        changed = copy.deepcopy(result)
        changed['verified_signatures'][self.packages[0]['name']]['signing_fingerprint'] = D.SIGNER
        with self.assertRaisesRegex(ValueError, 'separate TEST signer'):
            A.image_dockerfile(state, original, changed, now=1000)

    def test_expired_selection_cannot_create_context_or_run_verifier(self):
        state = self.admit(); context = self.base / 'context'; output = self.base / 'output'
        context.mkdir(mode=0o700); output.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            A.prepare_context(state, context, output, lambda *a, **k: self.fail('NO_VERIFIER_ON_EXPIRED_SELECTION'), now=1200)
        self.assertFalse((context / 'project-test-dependencies').exists())

    def test_missing_real_package_or_signature_never_passes(self):
        path = self.root / 'build-dependencies' / (self.packages[0]['filename'] + '.sig'); path.unlink()
        with self.assertRaises(FileNotFoundError): self.admit()

    def test_duplicate_noninteger_json_and_unbound_record_refuse(self):
        for raw in (b'{"schema":1,"schema":1}', b'{"bytes":1.0}', b'{"bytes":NaN}'):
            with self.assertRaises(ValueError): D.decode(raw)
        with self.assertRaises(ValueError): A.validate_policy({'kind': 'UNBOUND_PROJECT_TEST_PROVIDER_INPUTS'})

    def test_no_actor_attempt(self):
        self.assertEqual(ATTEMPTS, [])


if __name__ == '__main__': unittest.main(verbosity=2)
