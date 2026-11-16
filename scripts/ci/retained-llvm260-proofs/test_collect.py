#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic DATA joins and tiny temporary Git controls; no network/package execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('trusted_collector', HERE / 'collect.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def raw(value):
    return json.dumps(value, sort_keys=True).encode()


def fixture():
    actual = {k: c.CASE[k] for k in ('source', 'ref', 'run', 'job', 'artifact', 'attempt')}
    binding = dict(actual=actual, source_map_sha256=c.CASE['map_sha256'],
                   package_sha256=c.CASE['package_sha256'])
    raws = dict(llvm_signature=b'synthetic inert signature',
                public_test_key=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----\n',
                reader_binding=raw(binding), source_audit=raw(dict(language='Rust', legal_review='synthetic')))
    raws['reader_result'] = raw(dict(actual=actual, status=c.STATUS,
                                    binding_sha256=c.pin(raws['reader_binding'])['sha256']))
    key = dict(c.pin(raws['public_test_key']), fingerprint='A' * 40, trust_scope='TEST_ONLY')
    archive = dict(bytes=c.CASE['package_bytes'], sha256=c.CASE['package_sha256'])
    raws['verification_proof'] = raw(dict(schema=1, Root_issuer='Root', status='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE',
                                        verified=True, archive=archive, signature=c.pin(raws['llvm_signature']),
                                        public_test_key=key, trust_scope='TEST_ONLY'))
    raws['root_decision'] = raw(dict(schema=1, issuer='Root', accepted=True, holds_preserved=True,
                                    status='ACCEPTED_PRIVATE_LLVM23_PACKAGE_TEST_ONLY',
                                    source=dict(sha=c.CASE['source'], ref=c.CASE['ref'], run=c.CASE['run'], job=c.CASE['job']),
                                    original=dict(source=c.CASE['source'], run=c.CASE['run'], job=c.CASE['job'], artifact_id=c.CASE['artifact']),
                                    artifact=dict(id=c.CASE['artifact']), signature=c.pin(raws['llvm_signature']), public_test_key=key,
                                    archive=dict(archive, package='cachy-asahi-llvm23-source-reference', version='23.1.1-1', arch='aarch64'),
                                    verification_proof_sha256=c.pin(raws['verification_proof'])['sha256']))
    return raws


def manifest(raws):
    return dict(schema=1, scope=c.SCOPE, case=c.CASE, reader_expected_status=c.STATUS,
                files={role: dict(name=name, **c.pin(raws[role])) for role, name in c.NAMES.items()})


class DataControls(unittest.TestCase):
    def setUp(self):
        self.raws = fixture()

    def validate(self, value=None):
        body = raw(manifest(self.raws) if value is None else value)
        return c.validate(body, c.pin(body)['sha256'], self.raws)

    def change(self, role, key, value):
        body = json.loads(self.raws[role])
        body[key] = value
        self.raws[role] = raw(body)

    def test_valid_synthetic_joins_and_rust_audit(self):
        self.assertLess(self.validate(), c.ZIP_LIMIT)

    def test_external_manifest_hash_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            body = raw(manifest(self.raws))
            with self.assertRaises(ValueError):
                c.validate(body, '0' * 64, self.raws)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_safe_ref_commit_and_external_sha(self):
        c.inputs('refs/heads/codex/proofs-r1', 'a' * 40, 'b' * 64)
        for ref in ('main', 'refs/tags/codex/p', 'refs/heads/codex/a/../b', 'refs/heads/codex/a.lock',
                    'refs/heads/codex/.secret', 'refs/heads/codex/a//b', 'refs/heads/codex/a\nb',
                    'refs/heads/codex/a;', 'refs/heads/codex/-x'):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                c.inputs(ref, 'a' * 40, 'b' * 64)
        for commit, sha in [('a'*39, 'b'*64), ('A'*40, 'b'*64), ('a'*40, None), ('a'*40, 'b'*63)]:
            with self.assertRaises(ValueError):
                c.inputs('refs/heads/codex/p', commit, sha)

    def test_duplicate_json_keys_nonfinite_arrays_and_empty_refuse(self):
        for body in (b'{"x":1,"x":2}', b'{"x":NaN}', b'[]', b'', b'\xff', b'{"x":Infinity}'):
            with self.subTest(body=body), self.assertRaises((ValueError, UnicodeError)):
                c.decode(body)

    def test_fixed_manifest_contract_and_names(self):
        for key, value in [('schema', True), ('scope', 'production'), ('reader_expected_status', 'PASS_OLD')]:
            data = manifest(self.raws)
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(data)
        for name in ('../llvm260-source-audit.json', 'LLVM260-source-audit.json', 'other.py'):
            data = manifest(self.raws)
            data['files']['source_audit']['name'] = name
            with self.assertRaises(ValueError):
                self.validate(data)

    def test_missing_extra_roles_or_body_and_pin_drift(self):
        for change in ('extra', 'missing', 'sha', 'length', 'bool_length'):
            data = manifest(self.raws)
            if change == 'extra': data['files']['extra'] = data['files']['source_audit']
            if change == 'missing': del data['files']['source_audit']
            if change == 'sha': data['files']['source_audit']['sha256'] = '0' * 64
            if change == 'length': data['files']['source_audit']['bytes'] += 1
            if change == 'bool_length': data['files']['source_audit']['bytes'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(data)
        self.raws['extra'] = b'inert'
        with self.assertRaises(ValueError): self.validate(manifest(fixture()))

    def test_private_key_markers_refuse_in_any_leaf(self):
        for role in c.NAMES:
            for marker in (b'-----BEGIN PGP PRIVATE KEY BLOCK-----', b'-----BEGIN OPENSSH PRIVATE KEY-----'):
                self.raws = fixture()
                self.raws[role] += marker
                with self.subTest(role=role), self.assertRaises(ValueError): self.validate()

    def test_public_armor_required_and_no_second_block(self):
        for body in (b'not armored', b'-----BEGIN PGP PRIVATE KEY BLOCK-----\nx',
                     fixture()['public_test_key'] * 2):
            self.raws['public_test_key'] = body
            with self.assertRaises(ValueError): self.validate()

    def test_source_audit_only_requires_pinned_json_object(self):
        self.raws['source_audit'] = b'{"Rust_license_review":{"status":"reviewed"}}'
        self.validate()
        for body in (b'[]', b'{"a":1,"a":2}', b'invalid'):
            self.raws['source_audit'] = body
            with self.assertRaises(ValueError): self.validate()

    def test_reader_fixed_original_map_package_and_attempt(self):
        for key in ('source', 'ref', 'run', 'job', 'artifact', 'attempt'):
            self.raws = fixture()
            value = json.loads(self.raws['reader_binding'])
            value['actual'][key] = 'wrong'
            self.raws['reader_binding'] = raw(value)
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate()
        for key in ('source_map_sha256', 'package_sha256'):
            self.raws = fixture()
            self.change('reader_binding', key, '0' * 64)
            with self.assertRaises(ValueError): self.validate()

    def test_reader_success_binding_hash_and_actual_join(self):
        for key, value in [('status', 'PASS_OLD'), ('binding_sha256', '0'*64), ('actual', {})]:
            self.raws = fixture()
            self.change('reader_result', key, value)
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate()

    def test_verification_is_actual_root_test_signature_join(self):
        for key, value in [('verified', None), ('verified', False), ('Root_issuer', 'model'),
                           ('trust_scope', 'PRODUCTION'), ('signature', {}), ('archive', {}),
                           ('public_test_key', {}), ('status', 'PROPOSED')]:
            self.raws = fixture()
            self.change('verification_proof', key, value)
            with self.subTest(key=key), self.assertRaises((ValueError, KeyError)): self.validate()

    def test_final_root_decision_refuses_unset_or_unjoined_fields(self):
        for key, value in [('accepted', None), ('issuer', 'worker'), ('holds_preserved', False),
                           ('verification_proof_sha256', '0'*64), ('signature', {}), ('archive', {}),
                           ('public_test_key', {}), ('original', {}), ('source', {}), ('artifact', {'id':'other'})]:
            self.raws = fixture()
            self.change('root_decision', key, value)
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate()

    def test_leaf_and_whole_zip_budgets_include_headers(self):
        self.raws['llvm_signature'] = b'x' * (c.LEAF_LIMIT + 1)
        with self.assertRaises(ValueError): self.validate()
        self.raws = fixture()
        for role in ('llvm_signature', 'reader_binding', 'reader_result', 'source_audit'):
            self.raws[role] = b'x' * c.LEAF_LIMIT
        with self.assertRaisesRegex(ValueError, 'whole uploaded ZIP'): self.validate()

    def test_fresh_stage_has_only_seven_ordinary_public_files(self):
        self.validate()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            output = c.stage(parent, self.raws)
            self.assertEqual(set(p.name for p in output.iterdir()), set(c.NAMES.values()))
            for role, name in c.NAMES.items():
                self.assertEqual((output / name).read_bytes(), self.raws[role])
                self.assertFalse((output / name).is_symlink())
            self.assertNotEqual(output, c.stage(parent, self.raws))

    def test_stage_refuses_writable_or_symlink_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / 'target'
            target.mkdir(mode=0o777)
            target.chmod(0o777)
            with self.assertRaises(ValueError): c.stage(target, self.raws)
            link = parent / 'link'
            link.symlink_to(parent, target_is_directory=True)
            with self.assertRaises(ValueError): c.stage(link, self.raws)


class GitDataControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.raws = fixture()
        self.git('init', '--quiet')
        self.git('config', 'user.email', 'test@test.invalid')
        self.git('config', 'user.name', 'DATA test')
        for role, name in c.NAMES.items():
            (self.repo / name).write_bytes(self.raws[role])
        (self.repo / 'manifest.json').write_bytes(raw(manifest(self.raws)))

    def git(self, *args):
        result = subprocess.run(['git', '-C', str(self.repo), *args], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null'))
        return result.stdout.decode().strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'synthetic DATA only')
        return self.git('rev-parse', 'HEAD')

    def test_tiny_git_blobs_validate_without_checkout_execution(self):
        body, raws = c.read_source(self.repo, self.commit())
        self.assertEqual(raws, self.raws)
        c.validate(body, c.pin(body)['sha256'], raws)

    def test_extra_namespace_even_inert_source_code_refuses(self):
        (self.repo / 'evil.py').write_text('raise RuntimeError("must never execute")')
        with self.assertRaises(ValueError): c.read_source(self.repo, self.commit())

    def test_nested_path_refuses(self):
        name = c.NAMES['source_audit']
        nested = self.repo / 'nested'
        nested.mkdir()
        (self.repo / name).rename(nested / name)
        with self.assertRaises(ValueError): c.read_source(self.repo, self.commit())

    def test_executable_and_symlink_modes_refuse(self):
        name = c.NAMES['source_audit']
        (self.repo / name).chmod(0o755)
        with self.assertRaises(ValueError): c.read_source(self.repo, self.commit())
        (self.repo / name).unlink()
        (self.repo / name).symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): c.read_source(self.repo, self.commit())

    def test_missing_leaf_refuses(self):
        (self.repo / c.NAMES['source_audit']).unlink()
        with self.assertRaises(ValueError): c.read_source(self.repo, self.commit())


if __name__ == '__main__':
    unittest.main()
