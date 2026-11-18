#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the development-only relation join with inert synthetic fixtures."""

import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('supported_reviewed_soname', HERE / 'compose_reviewed_soname.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
fixtures = R.module('reviewed_soname_composition_fixtures', HERE / 'test_compose.py')
elf = R.module('reviewed_soname_elf_fixtures', R.ROOT / 'scripts/platform/test_elf_audit.py').elf


class SonameTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix='reviewed-soname-test-')
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)

    def write(self, name, raw):
        path = self.root / name
        path.write_bytes(raw if isinstance(raw, bytes) else R.S.encoded(raw))
        return dict(path=str(path), **R.pin(path.read_bytes()))

    def fixture(self, *, needed='libfixture.so.2', machine=183, source='libfixture.so',
                archived='libfixture.so=2-64', provider='libfixture.so=2-64', dual=True, implicit=False):
        package = fixtures.package
        before = [package(name) for name in R.C.t.tuple_audit.BOOT]
        provider_row = package('provider', provides=[provider])
        before += [provider_row, package('baseline')]
        image = self.write('image.json', dict(kind='observed-image-local-package-metadata',
                                             packages=[dict(metadata=row) for row in before]))
        protected = self.write('tuple.json', dict(kind='offline-platform-metadata-witnesses',
                               input_sha256={'image': image['sha256']},
                               proposed_installed_dependency_graph=[dict(name=row['NAME'][0], version=row['VERSION'][0])
                                                                    for row in before]))
        recipe = self.write('PKGBUILD', b"pkgname=fixture\npkgver=1\npkgrel=1\n"
                            b"depends=('libfixture.so')\n")
        arch = b'arch = aarch64\n' + (b'arch = x86_64\n' if dual else b'')
        info = self.write('.SRCINFO', b'pkgbase = fixture\npkgver = 1\npkgrel = 1\n'
                          + arch + b'license = MIT\n' + f'depends = {source}\npkgname = fixture\n'.encode())
        body = bytes(elf(needed=(needed,), machine=machine))
        member = 'usr/lib/fixture.so'
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            for name, raw, mode in (
                ('.PKGINFO', ('pkgname = fixture\npkgbase = fixture\npkgver = 1-1\narch = aarch64\n'
                              f'license = MIT\ndepend = {archived}\n').encode(), 0o644),
                ('.BUILDINFO', ('pkgname = fixture\npkgbase = fixture\npkgver = 1-1\npkgarch = aarch64\n'
                                f"buildtool = makepkg\npkgbuild_sha256sum = {recipe['sha256']}\n").encode(), 0o644),
                (member, body, 0o755),
            ):
                node = tarfile.TarInfo(name)
                node.size = len(raw)
                node.mode = mode
                archive.addfile(node, io.BytesIO(raw))
        ref = self.write('fixture-1-1-aarch64.pkg.tar.gz', data.getvalue())
        candidate = dict(srcinfo=info, archive=ref, archive_scope='synthetic-test-only')
        catalogs = {'asahi-alarm': [], 'core': [package('implicit', depends=['fixture'])] if implicit else [], 'extra': []}
        contract = dict(schema_version=1, kind='supported-Asahi-composition-inputs-v1', workflow='project-extension',
                        image_inventory=image, protected_tuple=protected,
                        catalogs=[dict(name=name, **self.write(name + '.db', fixtures.database(rows)))
                                  for name, rows in catalogs.items()], candidate_srcinfo=[candidate],
                        roots=[dict(name='implicit' if implicit else 'baseline', version='1-1',
                                    repo='core' if implicit else 'observed-Asahi-base')],
                        providers=[], allowed_base_changes=[])
        contract_ref = self.write('contract.json', contract)
        data = dict(kind=R.KIND, schema_version=1, approval_status='UNAPPROVED',
                    composition_contract=contract_ref, candidate=candidate, recipe=recipe,
                    member=dict(path=member, **R.pin(body)), declared='libfixture.so', generated='libfixture.so=2-64',
                    provider=dict(name='provider', version='1-1', repo='observed-Asahi-base', inventory=image,
                                  metadata_sha256=R.C.sha(R.S.encoded(provider_row))))
        return contract_ref, data

    def run_data(self, contract, operand):
        return R.run(contract, self.write('proof.json', operand), self.root / 'output')

    def test_exact_relation_admits_metadata_with_no_candidate_selected(self):
        result = self.run_data(*self.fixture())
        self.assertEqual((result['status'], result['approval_status'], result['metadata_prepare_status']),
                         ('HOLD', 'UNAPPROVED', 'PASS'))
        self.assertEqual(result['relation']['needed'], 'libfixture.so.2')
        self.assertFalse(result['abi_qualified'])
        self.assertFalse(result['project_candidate_selected'])
        self.assertEqual(result['prepared_add'], [])
        self.assertEqual([path.name for path in (self.root / 'output').iterdir()], ['reviewed-composition.DATA.json'])
        with self.assertRaises(ValueError):
            R.A.plan(result)

    def test_elf_member_pin_architecture_and_needed_are_mandatory(self):
        for change in ({'machine': 62}, {'needed': 'libfixture.so.3'}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'actual AArch64 ELF SONAME dependency'):
                self.run_data(*self.fixture(**change))
        contract, operand = self.fixture()
        operand['member']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'reviewed ELF member differs'):
            self.run_data(contract, operand)

    def test_provider_identity_and_declaration_cannot_drift(self):
        with self.assertRaisesRegex(ValueError, 'exact frozen AArch64 SONAME provider differs'):
            self.run_data(*self.fixture(provider='libfixture.so=4-64'))
        contract, operand = self.fixture()
        operand['provider']['metadata_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'exact frozen AArch64 SONAME provider differs'):
            self.run_data(contract, operand)

    def test_source_recipe_and_unrelated_archive_drift_refuse(self):
        with self.assertRaisesRegex(ValueError, 'unversioned SRCINFO dependency'):
            self.run_data(*self.fixture(source='libfixture.so=2-64'))
        with self.assertRaisesRegex(ValueError, 'beyond the reviewed mapping'):
            self.run_data(*self.fixture(archived='libfixture.so=3-64'))
        contract, operand = self.fixture()
        operand['recipe'] = self.write('PKGBUILD', b"depends=('other.so')\n")
        with self.assertRaisesRegex(ValueError, 'literal PKGBUILD and SRCINFO dependencies differ'):
            self.run_data(contract, operand)
        operand['recipe'] = self.write('PKGBUILD', b"depends=('libfixture.so')\n")
        with self.assertRaisesRegex(ValueError, 'BUILDINFO recipe binding differs'):
            self.run_data(contract, operand)

    def test_unreviewed_legacy_equality_and_implicit_project_selection_refuse(self):
        contract, _ = self.fixture(dual=False)
        reader = R.C.Reader()
        with self.assertRaisesRegex(ValueError, 'SRCINFO/archive relations differ'):
            R.C.compose(reader.document(contract), self.root / 'legacy', reader)
        with self.assertRaisesRegex(ValueError, 'reviewed candidate entered a proposed transaction'):
            self.run_data(*self.fixture(implicit=True))
        self.assertFalse((self.root / 'output' / 'reviewed-composition.DATA.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
