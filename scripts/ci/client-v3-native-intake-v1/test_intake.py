# SPDX-License-Identifier: MIT
"""NEW focused MODELED DATA controls; no actual reader/original/native replay."""
import argparse
import base64
import copy
import hashlib
import io
import json
import lzma
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import client_v3_common as C
import package_data as P
import projection
import reader as R
import model_data
from types import SimpleNamespace

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--input-root', type=Path, default=R.CODE_ROOT)
args, rest = parser.parse_known_args()

def selected():
    # Schema-only selectors. They are not a source publication or a native run.
    return dict(schema=1, source_sha='a' * 40, ref='codex/MODELED_DATA_ONLY', run=123, attempt=1, job=456, artifact=789,
        artifact_name='client-v3-native-component-123-1', artifact_bytes=5, artifact_sha256='b' * 64, source_authorization_sha256='c' * 64)

def zip_data(files, extra=None):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, 'w') as archive:
        for n, value in files.items():
            row = zipfile.ZipInfo(n)
            row.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(row, value)
        if extra:
            extra(archive)
    return raw.getvalue()

def retained(files):
    rows = {n: C.pin(raw) for n, raw in files.items()}
    return {**files, 'retention.json': C.encoded(dict(status='MODELED_SCHEMA_DATA_NOT_NATIVE', files=rows, bytes=sum(len(b) for b in files.values()), errors=[]))}

def package_model(change=None):
    source = {'PKGBUILD': b'# INERT SOURCE DATA; NOT AN EXECUTED RECIPE\n', 'payload.txt': b'MODELED PAYLOAD\n'}
    recipe = dict(pkgname=['fixture'], pkgver=['0.1.0'], pkgrel=['1'], arch=['any'], license=['MIT'], depends=['python>=3.11'])
    files = {'.PKGINFO': b'pkgname = fixture\npkgver = 0.1.0-1\narch = any\nlicense = MIT\ndepend = python>=3.11\n',
             '.BUILDINFO': ('format = 2\npkgname = fixture\npkgver = 0.1.0-1\npkgarch = any\npkgbuild_sha256sum = ' + C.pin(source['PKGBUILD'])['sha256'] + '\n').encode(),
             '.MTREE': b'OPAQUE MODELED MTREE DATA\n', 'usr/share/fixture/payload.txt': source['payload.txt']}
    if change:
        change(files)
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for n, raw in files.items():
            row = tarfile.TarInfo(n)
            row.size = len(raw)
            row.mode = 0o644
            row.mtime = 1791748800
            archive.addfile(row, io.BytesIO(raw))
    return lzma.compress(tar.getvalue()), recipe, {'usr/share/fixture/payload.txt': ['payload.txt', 0o644]}, source

class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='client-v3-intake-DATA-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.assertEqual(C.ATTEMPTS, [])
        self.assertEqual(C.ACTIVE, 0)

    def test_default_null_refuses_before_any_source_metadata_archive_open(self):
        value = {k: (1 if k == 'schema' else None) for k in selected()}
        path = self.root / 'binding.json'
        raw = C.encoded(value)
        path.write_bytes(raw)
        with patch.object(R, 'qualify', side_effect=AssertionError('must not reach evidence')):
            with self.assertRaisesRegex(ValueError, 'NULL'):
                R.read_component(binding_path=path, binding_sha256=C.pin(raw)['sha256'], authorization_path=self.root / 'absent-auth',
                    source_root=self.root / 'absent-source', run_path=self.root / 'absent-run', jobs_path=self.root / 'absent-jobs',
                    artifact_metadata_path=self.root / 'absent-artifact', archive_path=self.root / 'absent-zip')

    def test_explicit_typed_schema_selector_and_artifact_name(self):
        self.assertEqual(R.binding(C.encoded(selected())), selected())
        for key, wrong in [('schema', True), ('attempt', 2), ('artifact_bytes', 0), ('run', True), ('artifact_name', 'old-apps7-123')]:
            value = selected()
            value[key] = wrong
            with self.assertRaises((ValueError, TypeError)):
                R.binding(C.encoded(value))

    def test_duplicate_json_nonfinite_float_and_overflow_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1.0}', b'{"a":9223372036854775808}'):
            with self.assertRaises(ValueError):
                C.decode(raw)

    def test_whole_zip_retention_pins_and_no_supplement(self):
        files = retained({'proof.json': b'MODELED DATA\n'})
        observed, _ = R.archive(zip_data(files))
        self.assertEqual(observed, files)
        with self.assertRaises(ValueError):
            R.archive(zip_data({**files, 'unbound.py': b'raise RuntimeError("NEVER EXECUTE")'}))

    def test_zip_changed_body_and_total_refused(self):
        files = retained({'proof.json': b'A'})
        files['proof.json'] = b'B'
        with self.assertRaises(ValueError):
            R.archive(zip_data(files))
        files = retained({'proof.json': b'A'})
        value = C.decode(files['retention.json'])
        value['bytes'] += 1
        files['retention.json'] = C.encoded(value)
        with self.assertRaises(ValueError):
            R.archive(zip_data(files))

    def test_duplicate_zip_and_symlink_refused(self):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as archive:
            archive.writestr('a', b'A')
            # zipfile warns before writing duplicate DATA; keep that warning outside the parser contract.
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                archive.writestr('a', b'A')
        with self.assertRaises(ValueError):
            C.zip_files(raw.getvalue())
        def link(archive):
            info = zipfile.ZipInfo('link')
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b'outside')
        with self.assertRaises(ValueError):
            C.zip_files(zip_data({}, link))

    def test_zip_path_alias_and_file_parent_refused(self):
        for files in ({'../outside': b'A'}, {'a//b': b'A'}, {'a': b'A', 'a/b': b'B'}):
            with self.assertRaises(ValueError):
                C.zip_files(zip_data(files))

    def test_literal_package_payload_and_buildinfo_verified_without_actor(self):
        raw, recipe, payload, source = package_model()
        with C.passive():
            value = P.package(raw, 'fixture-0.1.0-1-any.pkg.tar.xz', recipe, payload, source.__getitem__)
        self.assertEqual(value['payload']['usr/share/fixture/payload.txt']['sha256'], C.pin(source['payload.txt'])['sha256'])

    def test_package_payload_and_recipe_buildinfo_tamper_refused(self):
        for mutate in (lambda f: f.__setitem__('usr/share/fixture/payload.txt', b'CHANGED'),
                       lambda f: f.__setitem__('.BUILDINFO', f['.BUILDINFO'].replace(b'format = 2', b'format = 1'))):
            raw, recipe, payload, source = package_model(mutate)
            with C.passive(), self.assertRaises(ValueError):
                P.package(raw, 'fixture-0.1.0-1-any.pkg.tar.xz', recipe, payload, source.__getitem__)

    def test_package_extra_leaf_and_unsupported_format_refused(self):
        raw, recipe, payload, source = package_model(lambda f: f.__setitem__('usr/bin/unbound', b'DATA'))
        with C.passive(), self.assertRaises(ValueError):
            P.package(raw, 'fixture-0.1.0-1-any.pkg.tar.xz', recipe, payload, source.__getitem__)
        with C.passive(), self.assertRaisesRegex(ValueError, 'XZ'):
            P.package(raw, 'fixture.pkg.tar.zst', recipe, payload, source.__getitem__)

    def test_truncated_or_appended_xz_refused(self):
        raw, recipe, payload, source = package_model()
        for changed in (raw[:-8], raw + lzma.compress(b'UNBOUND')):
            with C.passive(), self.assertRaises(ValueError):
                P.package(changed, 'fixture.pkg.tar.xz', recipe, payload, source.__getitem__)

    def test_ordinary_descriptor_refuses_symlink_and_hardlink(self):
        original = self.root / 'original'
        original.write_bytes(b'DATA')
        alias = self.root / 'alias'
        alias.symlink_to(original)
        with self.assertRaises(ValueError):
            C.ordinary(alias, 16)
        import os
        os.link(original, self.root / 'hardlink')
        with self.assertRaises(ValueError):
            C.ordinary(original, 16)

    def test_actor_and_write_fence_resets_after_refusal(self):
        for event, values in [('subprocess.Popen', (None, None, None, None)), ('socket.__new__', (None,)), ('open', ('MODELED', 'w', 1))]:
            with self.assertRaises(RuntimeError), C.passive():
                sys.audit(event, *values)
            self.assertEqual(C.ATTEMPTS.pop(), event)
        self.assertEqual(C.ACTIVE, 0)

    def test_projection_omits_code_and_logs_without_rewriting_original(self):
        files = retained({'harness/evil.py': b'raise RuntimeError("NEVER EXECUTE")', 'runtime/build.log': b'UNSHARED LOG', 'runtime/lifecycle.json': b'{"DATA":true}'})
        before = copy.deepcopy(files)
        with C.passive():
            value = projection.project_files(dict(status='MODELED_DATA_ONLY'), files, {}, selected())
        self.assertEqual(files, before)
        self.assertNotIn('harness/evil.py', value['selected'])
        self.assertIn('harness/evil.py', value['omitted_originals'])
        self.assertFalse(value['native_admission'])
        self.assertFalse(value['Doc315_qualification'])

    def test_projection_refuses_private_marker(self):
        files = retained({'runtime/report.json': b'-----BEGIN PGP PRIVATE KEY BLOCK-----'})
        with self.assertRaises(ValueError), C.passive():
            projection.project_files({}, files, {}, selected())

    def test_genuine_metadata_shape_requires_exact_sole_hosted_job(self):
        value = selected()
        run = dict(id=123, run_attempt=1, head_sha='a' * 40, head_branch=value['ref'], workflow_id=381664314,
            path='.github/workflows/native-arm-build.yml', name='native-arm-client-v3-component', event='workflow_dispatch',
            repository=dict(full_name='Gabriel-Kahen/cachy-asahi'), status='completed', conclusion='success')
        job = dict(id=456, run_id=123, run_attempt=1, head_sha='a' * 40, status='completed', conclusion='success', labels=['ubuntu-24.04-arm'])
        artifact = dict(id=789, name=value['artifact_name'], size_in_bytes=5, expired=False, digest='sha256:' + value['artifact_sha256'],
                        workflow_run=dict(id=123, head_sha='a' * 40, head_branch=value['ref']))
        self.assertTrue(R.run_metadata(run, dict(total_count=1, jobs=[job]), artifact, value))
        for changed in (dict(total_count=2, jobs=[job, job]), dict(total_count=1, jobs=[{**job, 'labels': ['self-hosted']}])):
            with self.assertRaises(ValueError):
                R.run_metadata(run, changed, artifact, value)

    def test_complete_git_tree_changes_when_mode_or_body_changes(self):
        raw = b'DATA'
        row = dict(mode='100644', oid=hashlib.sha1(b'blob 4\0' + raw).hexdigest())
        before = C.git_tree({'a/b': row})
        self.assertNotEqual(before, C.git_tree({'a/b': {**row, 'mode': '100755'}}))
        with self.assertRaises(ValueError):
            C.git_tree({'a': row, 'a/b': row})

    def test_current_producer_forwards_actual_both_runner_contexts(self):
        path = R.CODE_ROOT / R.LANE / 'adapter.py'
        raw = path.read_text()
        self.assertIn("len(rows) != 12", raw)
        self.assertIn("('runtime-dependency',runtime/'runtime-context')", raw)
        self.assertIn("('lifecycle',runtime/'lifecycle-inputs')", raw)
        self.assertIn("copy(path,'emitted/'+role+'/runner/'+name", raw)

    def runner_model(self):
        # MODELED forwarding bytes only; this is not a Source construction or a native observation.
        import importlib.util
        path = R.CODE_ROOT / R.LANE / 'adapter.py'
        spec = importlib.util.spec_from_file_location('_trusted_DATA_runner_model', path)
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        class Source:
            root = args.input_root.resolve()
            def read(self, n):
                origin = R.CODE_ROOT if n.startswith(R.LANE + '/') else self.root
                return (origin / n).read_bytes()
        source = Source()
        names = {n: source.read(R.LANE + '/' + n) for n in ('lifecycle.py', 'installed.py', 'runtime_image.py', 'rules.py', 'installed_v3.py', 'rename_after_real_verification.py', 'input-policy.json')}
        names['contract.py'] = adapter.text(source.root, 'contract.py').encode()
        for n, original in [('accepted/lifecycle.py', 'scripts/ci/welcome-native/lifecycle.py'), ('accepted/root_upgrade.py', 'scripts/ci/full-root-upgrade/root_upgrade.py'),
                            ('fixture-client/test_client_v2.py', 'scripts/client/test_client_v2.py'), ('fixture-client/client_v2.py', 'scripts/client/client_v2.py')]:
            names[n] = source.read(original)
        files = {}
        for role in ('runtime-dependency', 'lifecycle'):
            prefix = 'emitted/' + role + '/'
            files[prefix + 'runner-derivations.json'] = C.encoded(dict(schema=1, status='SOURCE_CLOSED_ACTUAL_RUNTIME_RUNNER_DATA',
                files={n: dict(**C.pin(raw), mode=0o644) for n, raw in names.items()}))
            files.update({prefix + 'runner/' + n: raw for n, raw in names.items()})
        return source, files

    def test_both_complete_modeled_runner_transports_join_without_source_import(self):
        source, files = self.runner_model()
        with C.passive():
            R.runner_data(files, source)

    def test_missing_or_conflicting_runner_refused_without_reconstruction(self):
        source, files = self.runner_model()
        n = 'emitted/lifecycle/runner/contract.py'
        changed = dict(files)
        changed.pop(n)
        with C.passive(), self.assertRaises(ValueError):
            R.runner_data(changed, source)
        changed[n] = b'raise RuntimeError("COLLECTED CODE MUST NEVER RUN")'
        with C.passive(), self.assertRaises(ValueError):
            R.runner_data(changed, source)

    def lifecycle_model(self):
        # Deliberately synthetic schema vectors, never emitted as actual native receipts.
        stdout = b'[GNUPG:] VALIDSIG MODELED_SCHEMA_ONLY\n'
        full = dict(bytes=len(stdout), sha256=C.pin(stdout)['sha256'], base64=base64.b64encode(stdout).decode())
        empty = dict(bytes=0, sha256=C.pin(b'')['sha256'], base64='')
        witness = dict(completed_bundle_targets=3, state_renamed_after_all_real_signatures=True, crypto_success_mocks=0,
                       actual_verified_signatures=[{} for _ in range(5)], actual_GPG_commands=[dict(exit=0, stdout=full, stderr=empty) for _ in range(5)])
        transcript = [dict(real_rebind_verifier=witness)]
        raw = C.encoded(transcript)
        control = dict(status='PASS_INSTALLED_V3_REAL_SIGNED_APPLY_AND_REBIND', actual_cli_readonly=True, actual_cli_apply=True,
            idempotent_readonly=True, rename_after_real_verification=True, refused_before_checkpoint_write=True, checkpoint_preserved=True,
            private_agent_retired=True, real_signature_checks_before_rebind=5, crypto_success_mocks=0, collected_code_imports=0,
            installed_source=True, transcript_bytes=len(raw), transcript_sha256=C.pin(raw)['sha256'], transcript=transcript)
        events = []
        for phase, count in [('install', 576), ('same-version-reinstall', 576), ('remove', 574), ('reinstall-after-removal', 576), ('final-remove', 574)]:
            row = dict(phase=phase, count=count, base574_preserved=True, user_preserved=True)
            if count == 574:
                row['payloads_absent'] = True
            else:
                row['observations'] = [dict(home='client-v3-home-' + n, client_v3=copy.deepcopy(control)) for n in ('fresh', 'existing')]
            events.append(row)
        return dict(status='PASS_RUNTIME_CLIENT_V3_FRESH_LIFECYCLE', base_count=574, installed_count=576, architecture='aarch64', page_size=4096,
            base574_preserved=True, user_preserved=True, hardware='NOT_RUN', release='NOT_ADMITTED', version_upgrade='NOT_RUN',
            removal_order=[R.ROLES['client'], R.ROLES['runtime']], events=events)

    def test_trusted_lifecycle_rules_validate_model_without_resource_grant(self):
        value = self.lifecycle_model()
        with C.passive():
            R.lifecycle_rules.validate(SimpleNamespace(need=C.need, re=R.re, ROLES=R.ROLES), value)
        self.assertEqual(value['version_upgrade'], 'NOT_RUN')

    def test_old577_upgrade_and_incomplete_gpg_model_refused(self):
        for field, bad in [('installed_count', 577), ('version_upgrade', 'PASS'), ('page_size', 16384)]:
            value = self.lifecycle_model()
            value[field] = bad
            with C.passive(), self.assertRaises(ValueError):
                R.lifecycle_rules.validate(SimpleNamespace(need=C.need, re=R.re, ROLES=R.ROLES), value)
        value = self.lifecycle_model()
        value['events'][0]['observations'][0]['client_v3']['real_signature_checks_before_rebind'] = 4
        with C.passive(), self.assertRaises(ValueError):
            R.lifecycle_rules.validate(SimpleNamespace(need=C.need, re=R.re, ROLES=R.ROLES), value)

    def test_complete_modeled_component_validates_with_no_native_admission(self):
        values = model_data.component(self)
        with C.passive():
            result = R.validate(*values)
        self.assertEqual(result['products'], 2)
        self.assertEqual(result['clean_builds'], 4)
        self.assertEqual(result['installed_inventory'], 576)
        self.assertFalse(result['native_admission'])
        self.assertFalse(result['Doc315_qualification'])
        self.assertIsNone(result['Root_acceptance'])

    def test_complete_component_refuses_actual_runner_omission_and_supplement(self):
        files, retention, source, selected = model_data.component(self)
        files.pop('emitted/lifecycle/runner/contract.py')
        with C.passive(), self.assertRaises(ValueError):
            R.validate(files, retention, source, selected)
        files, retention, source, selected = model_data.component(self)
        files['unbound-supplement.json'] = b'{}'
        with C.passive(), self.assertRaises(ValueError):
            R.validate(files, retention, source, selected)

    def test_complete_component_refuses_archive_pair_and_retirement_tamper(self):
        files, retention, source, selected = model_data.component(self)
        n = next(n for n in files if n.startswith('packages/') and '-b/' in n)
        files[n] = files[n][:-1] + bytes([files[n][-1] ^ 1])
        with C.passive(), self.assertRaises(ValueError):
            R.validate(files, retention, source, selected)

    def test_complete_component_refuses_empty_signature_transport(self):
        files, retention, source, selected = model_data.component(self)
        n = next(n for n in files if n.startswith('trust/') and n.endswith('.sig'))
        files[n] = b''
        with C.passive(), self.assertRaises(ValueError):
            R.validate(files, retention, source, selected)
        files, retention, source, selected = model_data.component(self)
        value = C.decode(files['ordered-cleanup.json'])
        value['authority'] = 'UNKNOWN'
        files['ordered-cleanup.json'] = C.encoded(value)
        with C.passive(), self.assertRaises(ValueError):
            R.validate(files, retention, source, selected)

if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *rest])
