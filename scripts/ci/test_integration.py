#!/usr/bin/env python3
"""Controller boundary tests: no actual Docker, key or package operations."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import integration as i


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tripwire = patch.object(i.subprocess, 'run', side_effect=AssertionError('unexpected subprocess'))
        self.tripwire.start()
        self.process_tripwire = patch.object(i.subprocess, 'Popen', side_effect=AssertionError('unexpected launcher'))
        self.process_tripwire.start()
        i.CANCEL_REQUESTED = False

    def tearDown(self):
        self.process_tripwire.stop(); self.tripwire.stop(); self.temporary.cleanup()

    def test_relative_refusals(self):
        for value in ('/tmp/foo', '../foo', 'a/../b', 'a//b', 'a\\b', 'a\nb', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                i.relative(value)

    def source_tree(self):
        for name in i.SOURCE_ROOTS:
            (self.root / name).mkdir()
            (self.root / name / 'README.md').write_text('reviewed subtree')
        paths = list(i.SOURCE_FILES)
        for name in ('fixtures', 'lifecycle', 'repository', 'onboarding', 'desktop'):
            paths += [f'scripts/integration/{name}.py', f'scripts/integration/test_{name}.py']
        for name in ('integration', 'integration_export', 'sign_fixture', 'installed_handoff', 'source_suites', 'verify_derived'):
            paths += [f'scripts/ci/{name}.py', f'scripts/ci/test_{name}.py']
        for name in paths:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('reviewed source')
        (self.root / 'scripts/ci/recipes.lock.json').write_text('{}')

    def test_independent_followup_sources_are_excluded_from_initial_snapshot(self):
        self.source_tree()
        for directory in ('scripts/virtual', 'scripts/client', 'scripts/experiments', 'scripts/port', 'scripts/platform', 'packages/tools'):
            path = self.root / directory; path.mkdir(parents=True); (path / 'moving.py').write_text('active independent source')
        result = i.scan(self.root)
        self.assertFalse(any(name.endswith('moving.py') for name in result))

    def test_generated_package_evidence_does_not_change_clean_source_snapshot(self):
        self.source_tree()
        recipe = self.root / 'packages/desktop/recipe'; recipe.mkdir(parents=True)
        (recipe / 'PKGBUILD').write_text('reviewed recipe bytes')
        (recipe / 'PKGBUILD').chmod(0o755)
        evidence = self.root / 'packages/desktop/evidence'; evidence.mkdir()
        receipt = evidence / 'original-receipt.json'; receipt.write_text('{"status":"historical"}')
        nested = recipe / 'evidence'; nested.mkdir()
        locked_log = nested / 'reviewed.log'; locked_log.write_text('locked historical evidence')
        i.native.save(self.root / 'scripts/ci/recipes.lock.json', {'packages/desktop/recipe': {
            'evidence/reviewed.log': i.native.sha(locked_log)}})
        clean = i.scan(self.root)
        archive = evidence / 'host-package-1.pkg.tar.zst'; archive.write_bytes(b'local generated binary')
        (nested / 'generated.log').write_text('local diagnostic')
        self.assertEqual(i.scan(self.root), clean)
        self.assertEqual(archive.read_bytes(), b'local generated binary')
        self.assertEqual(receipt.read_text(), '{"status":"historical"}')
        target = self.root.parent / (self.root.name + '-clean-snapshot')
        self.addCleanup(lambda: shutil.rmtree(target, ignore_errors=True))
        i.snapshot(self.root, target, clean)
        self.assertEqual(i.scan(target), clean)
        self.assertEqual((target / 'packages/desktop/evidence/original-receipt.json').read_text(), receipt.read_text())
        self.assertEqual((target / 'packages/desktop/recipe/evidence/reviewed.log').read_text(), locked_log.read_text())
        self.assertFalse((target / 'packages/desktop/evidence/host-package-1.pkg.tar.zst').exists())
        self.assertEqual(i.native.sha(target / 'packages/desktop/recipe/PKGBUILD'), clean['packages/desktop/recipe/PKGBUILD']['sha256'])
        self.assertEqual((target / 'packages/desktop/recipe/PKGBUILD').stat().st_mode & 0o777, 0o755)

    def test_missing_locked_evidence_fails_source_scan(self):
        self.source_tree()
        i.native.save(self.root / 'scripts/ci/recipes.lock.json', {'packages/desktop/recipe': {
            'evidence/required.log': 'a' * 64}})
        with self.assertRaisesRegex(ValueError, 'reviewed recipe inputs missing'):
            i.scan(self.root)

    def test_preflight_generates_from_copied_tree_with_locked_evidence(self):
        self.source_tree()
        evidence = self.root / 'packages/desktop/recipe/evidence/required.log'
        evidence.parent.mkdir(parents=True); evidence.write_text('mandatory input')
        recipe_lock = self.root / 'scripts/ci/recipes.lock.json'
        i.native.save(recipe_lock, {'packages/desktop/recipe': {'evidence/required.log': i.native.sha(evidence)}})
        pin = i.native.sha(recipe_lock)
        rows = {'fixture': {'sha256': 'd' * 64, 'mode': 0o644}}
        lock = {'schema_version': 1, 'purpose': i.PURPOSE, 'development_only': True, 'selected_for_release': False,
                'recipes_sha256': pin, 'source_date_epoch': 1, 'recipe_source_commit': 'b' * 40,
                'source_files': i.scan(self.root), 'generated_fixture_files': rows}
        def generate(copied, output, *args):
            self.assertNotEqual(copied, self.root)
            self.assertEqual((copied / evidence.relative_to(self.root)).read_text(), 'mandatory input')
            self.assertEqual(i.scan(copied), lock['source_files'])
        with patch.object(i.native, 'load_pinned', return_value=lock), patch.object(i, 'generate', side_effect=generate), \
             patch.object(i, 'files', return_value=rows):
            self.assertEqual(i.preflight(self.root, self.root / 'lock', 'c' * 64, pin, 1), lock)

    def test_snapshot_drift_diagnostic_is_bounded_and_contains_only_relative_paths(self):
        actual = {'scripts/new.py': {'sha256': 'a'}, 'scripts/changed.py': {'mode': 0o755}}
        expected = {'scripts/changed.py': {'mode': 0o644}, **{f'scripts/missing-{n:02d}.py': {'sha256': 'b'} for n in range(25)}}
        with self.assertRaises(ValueError) as raised:
            i.require_source_snapshot(actual, expected, 'source drift')
        report = json.loads(str(raised.exception).split(': ', 1)[1])
        self.assertEqual(report['counts'], {'missing': 25, 'extra': 1, 'changed': 1})
        self.assertEqual(len(report['missing']), 20)
        self.assertEqual(report['changed'], ['scripts/changed.py'])
        self.assertNotIn('sha256', str(raised.exception))
        self.assertNotIn(str(self.root), str(raised.exception))

    def test_mount_contract_nonroot(self):
        command = i.command('sha256:' + 'a' * 64, 'unique', [(self.root, '/source', True), (self.root, '/out', False)],
                            tmpfs={'/tmp': i.owned_tmpfs('2g')})
        for value in ('--read-only', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pull=never'):
            self.assertIn(value, command)
        self.assertNotIn('--rm', command)
        self.assertFalse(any(arg.startswith('--cap-add') for arg in command))
        self.assertIn(f'uid={os.getuid()}', command[command.index('--tmpfs') + 1])

    def test_mount_contract_root_only_reviewed_caps(self):
        command = i.command('sha256:' + 'a' * 64, 'unique', [(self.root, '/inputs', True)], root=True, writable=True)
        self.assertEqual(set(x.removeprefix('--cap-add=') for x in command if x.startswith('--cap-add=')), set(i.CAPS))
        self.assertNotIn('--read-only', command)
        self.assertIn('0:0', command)

    def test_lifecycle_kill_cap_does_not_broaden_repository_default(self):
        base = dict(image='sha256:' + 'a' * 64, name='unique', binds=[(self.root, '/inputs', True)], root=True)
        lifecycle = i.command(**base, rootcaps=(*i.CAPS, 'KILL'))
        repository = i.command(**base)
        self.assertIn('--cap-add=KILL', lifecycle)
        self.assertNotIn('--cap-add=KILL', repository)
        with self.assertRaises(ValueError):
            i.command(**base, rootcaps=('SYS_ADMIN',))

    def test_mount_refuses_host_system_and_tags(self):
        for image, target in [('latest', '/inputs'), ('sha256:' + 'a' * 64, '/etc')]:
            with self.assertRaises(ValueError):
                i.command(image, 'unique', [(self.root, target, True)])

    def test_output_roots_are_disjoint_before_system_operations(self):
        source, native, cache = [self.root / name for name in ('source', 'native', 'cache')]
        for path in (source, native, cache):
            path.mkdir()
        i.output_boundaries(source, native, cache, self.root / 'integration')
        for output in (source / 'integration', native / 'work', cache / 'integration', self.root, native):
            with self.subTest(output=output), self.assertRaises(ValueError):
                i.output_boundaries(source, native, cache, output)

    def test_snapshot_rechecks_copy(self):
        (self.root / 'one').write_text('frozen')
        rows = {'one': {'sha256': i.native.sha(self.root / 'one'), 'mode': 0o644}}
        out = self.root / 'snapshot'
        with patch.object(i, 'scan', return_value=rows):
            i.snapshot(self.root, out, rows)
        self.assertEqual((out / 'one').read_text(), 'frozen')
        (self.root / 'one').write_text('drift')
        with self.assertRaises(ValueError):
            i.snapshot(self.root, self.root / 'second', rows)

    def test_regular_refuses_symlink_and_hardlink(self):
        source = self.root / 'one'; source.write_text('bytes')
        linked = self.root / 'linked'; linked.symlink_to(source)
        with self.assertRaises(ValueError):
            i.regular(linked)
        linked.unlink(); os.link(source, linked)
        with self.assertRaises(ValueError):
            i.regular(source)

    def test_preflight_refuses_source_before_fixture_execution(self):
        lock = {'schema_version': 1, 'purpose': i.PURPOSE, 'development_only': True,
                'selected_for_release': False, 'recipes_sha256': 'a' * 64, 'source_date_epoch': 1,
                'recipe_source_commit': 'b' * 40, 'source_files': {}, 'generated_fixture_files': {}}
        with patch.object(i.native, 'load_pinned', return_value=lock), patch.object(i, 'scan', return_value={'drift': {}}), \
             patch.object(i, 'generate') as generator, self.assertRaises(ValueError):
            i.preflight(self.root, self.root / 'lock', 'c' * 64, 'a' * 64, 1)
        generator.assert_not_called()

    def test_preflight_refuses_generated_drift(self):
        rows = {'fixture': {'sha256': 'd' * 64, 'mode': 0o644}}
        lock = {'schema_version': 1, 'purpose': i.PURPOSE, 'development_only': True,
                'selected_for_release': False, 'recipes_sha256': 'a' * 64, 'source_date_epoch': 1,
                'recipe_source_commit': 'b' * 40, 'source_files': {}, 'generated_fixture_files': rows}
        with patch.object(i.native, 'load_pinned', return_value=lock), patch.object(i, 'scan', return_value={}), \
             patch.object(i, 'generate'), patch.object(i, 'files', return_value={}), self.assertRaises(ValueError):
            i.preflight(self.root, self.root / 'lock', 'c' * 64, 'a' * 64, 1)

    def test_failure_removes_only_unique_container(self):
        command = ['docker', 'run', '--name', 'cachy-asahi-owned-unique']
        with patch.object(i, 'guarded_run', side_effect=ValueError('failed')), \
             patch.object(i, 'remove_container', return_value={'status': 'PASS'}) as removal:
            with self.assertRaises(ValueError):
                i.execute_container(command, self.root / 'log', keep=True)
        self.assertEqual(removal.call_args.args[0], 'cachy-asahi-owned-unique')

    def test_handoff_keeps_successful_container_for_verified_commit(self):
        with patch.object(i, 'guarded_run'), patch.object(i, 'remove_container') as removal:
            i.execute_container(['docker', 'run', '--name', 'cachy-asahi-owned-unique'], self.root / 'log', keep=True)
        removal.assert_not_called()

    def test_cleanup_requires_daemon_verified_absence(self):
        occupied = SimpleNamespace(returncode=0, stdout=b'container-id\n')
        failed = SimpleNamespace(returncode=1, stdout=b'')
        with patch.object(i.subprocess, 'run', side_effect=[occupied, failed, occupied, occupied, failed, occupied]):
            result = i.remove_container('cachy-asahi-owned-unique')
        self.assertEqual(result['status'], 'FAIL')
        absent = SimpleNamespace(returncode=0, stdout=b'')
        with patch.object(i.subprocess, 'run', side_effect=[absent]):
            result = i.remove_container('cachy-asahi-owned-unique')
        self.assertEqual(result['status'], 'PASS')
        with patch.object(i.subprocess, 'run', side_effect=[occupied, failed, absent]):
            result = i.remove_container('cachy-asahi-owned-unique')
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['absence_verified'])

    def test_successful_container_with_failed_cleanup_cannot_pass(self):
        with patch.object(i, 'guarded_run'), patch.object(i, 'remove_container', return_value={'status': 'FAIL'}), \
             self.assertRaises(ValueError):
            i.execute_container(['docker', 'run', '--name', 'cachy-asahi-owned-unique'], self.root / 'log')
        self.assertEqual(json.loads((self.root / 'log.cleanup.json').read_text())['status'], 'FAIL')

    def test_outer_diagnostics_retain_cleanup_and_launcher_results(self):
        log = self.root / 'external-container.log'; log.write_text('container guard failure')
        i.native.save(log.with_suffix('.cleanup.json'), {'status': 'FAIL'})
        i.native.save(log.with_suffix('.launcher.json'), {'status': 'PASS'})
        raw = self.root / 'raw'; raw.mkdir()
        i.retain_outer_log(log, raw)
        self.assertEqual((raw / 'container.log').read_text(), 'container guard failure')
        self.assertEqual(json.loads((raw / 'container-cleanup.json').read_text())['status'], 'FAIL')
        self.assertEqual(json.loads((raw / 'container-launcher.json').read_text())['status'], 'PASS')

    def test_cancellation_preserves_failure_and_verified_cleanup(self):
        with patch.object(i, 'guarded_run', side_effect=i.Cancelled('interrupted')), \
             patch.object(i, 'remove_container', return_value={'status': 'PASS'}) as removal, self.assertRaises(i.Cancelled):
            i.execute_container(['docker', 'run', '--name', 'cachy-asahi-owned-unique'], self.root / 'log')
        removal.assert_called_once_with('cachy-asahi-owned-unique')

    def test_committed_config_restores_base_values_and_refuses_test_env(self):
        base = {'User': 'alarm', 'WorkingDir': '/tmp', 'Cmd': None, 'Entrypoint': None, 'Env': ['PATH=/usr/bin']}
        command = i.commit_command('cachy-asahi-owned-unique', base)
        self.assertIn('USER alarm', command)
        self.assertIn('WORKDIR /tmp', command)
        self.assertIn('CMD []', command)
        self.assertIn('ENTRYPOINT []', command)
        clean = {**base, 'Cmd': [], 'Entrypoint': []}
        self.assertEqual(i.image_config(base), i.image_config(clean))
        dirty = {**clean, 'Env': [*base['Env'], 'CACHY_ASAHI_IMAGE_ID=old-image']}
        self.assertNotEqual(i.image_config(base), i.image_config(dirty))

    def test_export_rejects_private_text_and_does_not_copy_archives(self):
        raw, work = self.root / 'raw', self.root / 'work'; raw.mkdir(); work.mkdir()
        (raw / 'safe.json').write_text('{"status":"PASS"}')
        (raw / 'public.pkg.tar.xz').write_bytes(b'public archive')
        i.safe_public(raw, self.root / 'public', work)
        self.assertFalse((self.root / 'public/public.pkg.tar.xz').exists())
        excluded = json.loads((self.root / 'public/excluded-public-material.json').read_text())
        self.assertEqual(len(excluded['excluded']), 1)
        (raw / 'bad.txt').write_text('-----BEGIN PGP PRIVATE KEY BLOCK-----')
        other = self.root / 'other'; other.mkdir()
        with self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'rejected', other)
        self.assertFalse((self.root / 'rejected/bad.txt').exists())

    def test_export_never_reads_or_hashes_sensitive_state(self):
        raw, work = self.root / 'raw', self.root / 'work'; raw.mkdir(); work.mkdir()
        private = raw / '.gnupg/private-keys-v1.d'; private.mkdir(parents=True)
        (private / 'key.bin').write_bytes(b'private test material')
        with patch.object(i.native, 'sha', side_effect=AssertionError('private bytes hashed')), self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'public', work)
        report = (self.root / 'public/export-manifest.json').read_text()
        self.assertIn('sensitive', report)
        self.assertNotIn('key.bin', report)
        self.assertNotIn('private test material', report)

    def repository_status(self, raw):
        spec = importlib.util.spec_from_file_location('integration_test_repository_producer',
                                                     Path(__file__).resolve().parents[1] / 'integration/repository.py')
        producer = importlib.util.module_from_spec(spec); spec.loader.exec_module(producer)
        owner = producer.Integration({'source_commit': 'a' * 40}); owner.out = raw
        output = b'[GNUPG:] BADSIG 0123456789ABCDEF TEST ONLY\ngpg: bad signature\n'
        with patch.object(i.subprocess, 'run', return_value=type('Result', (), {'returncode': 1, 'stdout': output})()):
            for label in i.REPOSITORY_PUBLIC_LOGS:
                owner.command(label, ['gpg', '--status-fd', '1', '--verify', 'TEST.sig', 'TEST.pkg'],
                              expected=1, signature_failure=True)
        i.native.save(raw / 'result.json', owner.result)
        return owner

    def test_actual_repository_public_status_names_project_without_relaxing_exporter(self):
        raw, work = self.root / 'raw', self.root / 'work'; raw.mkdir(); work.mkdir()
        owner = self.repository_status(raw)
        self.assertTrue((raw / '000-gpg-untrusted-A-status.txt').is_file())
        i.safe_public(raw, self.root / 'public', work)
        for index, label in enumerate(i.REPOSITORY_PUBLIC_LOGS):
            projected = f'{index:03d}-{i.REPOSITORY_PUBLIC_LOGS[label]}.txt'
            self.assertTrue((self.root / 'public' / projected).is_file())
            self.assertEqual(i.native.sha(self.root / 'public' / projected), owner.receipts[index]['sha256'])
        self.assertFalse((self.root / 'public/000-gpg-untrusted-A-status.txt').exists())

    def test_repository_status_projection_requires_exact_receipt_hash_and_label(self):
        raw = self.root / 'raw'; raw.mkdir(); owner = self.repository_status(raw)
        (raw / owner.receipts[0]['log']).write_text('drift')
        with self.assertRaises(ValueError):
            i.repository_public_logs(raw)
        owner.receipts[0]['log'] = '.gnupg/status.txt'
        i.native.save(raw / 'result.json', owner.result)
        with self.assertRaises(ValueError):
            i.repository_public_logs(raw)

    def test_unlisted_gpg_log_remains_rejected(self):
        raw, work = self.root / 'raw', self.root / 'work'; raw.mkdir(); work.mkdir()
        (raw / '000-gpg-unreviewed-status.txt').write_text('public-looking but unbound')
        with self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'public', work)
        self.assertFalse((self.root / 'public/000-gpg-unreviewed-status.txt').exists())

    def test_explicit_public_signature_export_rehashes_and_rejects_secret_paths(self):
        raw = self.root / 'raw'; raw.mkdir()
        signature = raw / 'TEST.sig'; signature.write_bytes(b'\x88\x00public-detached-signature-fixture')
        expected = {'TEST.sig': i.native.sha(signature)}
        i.export_material(raw, self.root / 'public', expected, {'purpose': 'TEST-ONLY'})
        self.assertEqual((self.root / 'public/TEST.sig').read_bytes(), signature.read_bytes())
        signature.write_bytes(b'drift')
        with self.assertRaises(ValueError):
            i.export_material(raw, self.root / 'drift', expected, {})
        with self.assertRaises(ValueError):
            i.export_material(raw, self.root / 'denied', {'.gnupg/private.key': 'a' * 64}, {})

    def test_repository_public_export_only_receipt_bound_allowed_material(self):
        import sign_fixture
        controller = self.controller(); controller.commit = 'a' * 40
        raw = self.root / 'raw'; raw.mkdir()
        names = ['TEST-signer-A-public.asc', 'TEST-signer-B-public.asc', 'TEST-verifier-public.asc',
                 'TEST-signer-A-revoked-public.asc', 'TEST-repository-aliases.json',
                 'TEST-repositories/baseline-A/integration.db.tar.gz',
                 'TEST-repositories/updated-B/integration.db.tar.gz']
        hashes = {}
        for name in names:
            path = raw / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'public fixture data')
            hashes[name] = i.native.sha(path)
        hashes['.gnupg/private-key.bin'] = 'b' * 64
        i.native.save(raw / 'result.json', {'status': 'PASS', 'purpose': 'disposable-generic-repository-test',
                                         'evidence_sha256': hashes, 'cases': []})
        with patch.object(sign_fixture, 'public_certificate'):
            controller.export_repository(raw)
        output = controller.public / 'repository-public-artifacts'
        manifest = json.loads((output / 'public-artifact-manifest.json').read_text())
        self.assertEqual(set(manifest['files']), set(names))
        self.assertFalse((output / '.gnupg').exists())
        self.assertTrue((output / 'TEST-repositories/baseline-A/integration.db.tar.gz').is_file())

    def controller(self):
        controller = object.__new__(i.Controller)
        controller.out = self.root / 'controller'; controller.out.mkdir()
        controller.work = controller.out / 'work'; controller.work.mkdir()
        controller.public = controller.out / 'public'; controller.public.mkdir()
        controller.report = {'stages': {}}
        controller.cancelled = False
        return controller

    def test_fixture_failure_preserves_provenance_validation_and_build_log(self):
        controller = self.controller()
        controller.source = self.root / 'source'; controller.source.mkdir()
        controller.native_out = self.root / 'native'; controller.native_out.mkdir()
        controller.image = 'sha256:' + 'a' * 64
        controller.lock = {'recipes_sha256': 'b' * 64, 'recipe_source_commit': 'c' * 40,
                           'source_date_epoch': 1, 'generated_fixture_files': {}}
        name = 'cachy-asahi-fish-config'
        def generate(root, output, *args):
            output.mkdir()
            i.native.save(output / 'fixture-manifest.json', {'packages': {name: {
                'upgrade_recipe': 'upgrade/recipe', 'reviewed_inputs': {'upgrade': 'upgrade-review.json'}}}})
        def failed_build(command, log, timeout):
            output = Path(command[command.index('--output') + 1]); output.mkdir()
            (output / 'build.log').write_text('meaningful compiler failure')
            i.native.save(output / 'provenance.json', {'status': 'failed'})
            i.native.save(output / 'validation.json', {'errors': ['fixture mismatch']})
            raise ValueError('build failed')
        raw = self.root / 'raw'; raw.mkdir()
        with patch.object(i, 'generate', side_effect=generate), patch.object(i, 'files', return_value={}), \
             patch.object(i.native, 'RECIPES', (name,)), patch.object(i, 'guarded_run', side_effect=failed_build), self.assertRaises(ValueError):
            controller.fixtures(raw)
        self.assertIn('meaningful compiler failure', (raw / f'{name}-1-build.log').read_text())
        self.assertTrue((raw / f'{name}-1-provenance.json').is_file())
        self.assertTrue((raw / f'{name}-1-validation.json').is_file())

    def test_stage_exception_cannot_leak_credentials_through_summary(self):
        controller = self.controller()
        def failed(raw):
            raise ValueError('password=deliberately-sensitive-test-value')
        self.assertFalse(controller.stage('unit-stage', failed))
        for path in controller.public.rglob('*.json'):
            self.assertNotIn('deliberately-sensitive-test-value', path.read_text())
        self.assertEqual(controller.report['stages']['unit-stage']['status'], 'FAIL')

    def test_export_failure_has_failed_public_controller_status(self):
        controller = self.controller()
        def failed_export(raw):
            (raw / 'bad.txt').write_text('-----BEGIN PGP PRIVATE KEY BLOCK-----')
        self.assertFalse(controller.stage('unit-stage', failed_export))
        status = json.loads((controller.public / 'unit-stage/control/stage-status.json').read_text())
        self.assertEqual(status['status'], 'FAIL')
        self.assertIn('export_error', status)

    def test_cancellation_during_summary_export_finalizes_failed_evidence(self):
        controller = self.controller()
        controller.report['stages'] = {name: {'status': 'PASS'} for name in
            ('fixtures', 'signer', 'lifecycle', 'repository', 'onboarding', 'desktop', 'source-suites')}
        original = i.export_evidence
        def cancelled_export(raw, output):
            result = original(raw, output)
            i.CANCEL_REQUESTED = True
            return result
        with patch.object(i, 'export_evidence', side_effect=cancelled_export):
            self.assertFalse(controller.finish())
        summary = json.loads((controller.public / 'summary/result.json').read_text())
        self.assertEqual(summary['status'], 'FAIL')
        self.assertTrue(summary['cancelled'])

    def test_summary_publication_failure_cannot_leave_pass_results(self):
        controller = self.controller()
        controller.report['stages'] = {name: {'status': 'PASS'} for name in
            ('fixtures', 'signer', 'lifecycle', 'repository', 'onboarding', 'desktop', 'source-suites')}
        original = i.export_evidence
        def refused(raw, output):
            result = original(raw, output)
            result['evidence_export'] = 'FAIL'
            return result
        with patch.object(i, 'export_evidence', side_effect=refused):
            self.assertFalse(controller.finish())
        self.assertEqual(controller.report['status'], 'FAIL')
        self.assertEqual(json.loads((controller.out / 'result.json').read_text())['status'], 'FAIL')
        self.assertEqual(json.loads((controller.public / 'summary/result.json').read_text())['status'], 'FAIL')

    def commit_inputs(self):
        base, installed = self.root / 'base.lock', self.root / 'installed.lock'
        base.write_text('base 1-1\n')
        baseline = [{'name': name, 'version': '1-1', 'payload_sha256': {'usr/share/' + name: 'a' * 64}}
                    for name in i.native.RECIPES]
        installed.write_text(''.join(f'{name} {version}\n' for name, version in sorted({'base': '1-1', **{r['name']: r['version'] for r in baseline}}.items())))
        commit = {'schema_version': 1, 'purpose': 'sanitized-baseline-image-handoff', 'source_commit': 'b' * 40,
                  'lifecycle_contract_sha256': 'c' * 64, 'lifecycle_script_sha256': 'd' * 64,
                  'base_packages_sha256': i.native.sha(base), 'baseline': baseline}
        contract = {'image_id': 'sha256:' + 'e' * 64, 'nonce': 'f' * 32, 'baseline': baseline}
        required = ('successful-lifecycle-handoff', 'lifecycle-receipt-binding', 'exact-base-plus-originals-inventory',
                    'complete-pacman-owned-payload', 'original-payload-hash', 'private-keyring-removed',
                    'only-empty-alarm-home', 'system-gnupg-state-removed', 'image-tmp-view-empty')
        receipt = {key: commit[key] for key in ('purpose', 'source_commit', 'lifecycle_contract_sha256', 'lifecycle_script_sha256', 'base_packages_sha256')}
        receipt.update(schema_version=1, status='READY', image_id=contract['image_id'], nonce=contract['nonce'],
                       commit_contract_sha256=hashlib.sha256((json.dumps(commit, indent=2, sort_keys=True) + '\n').encode()).hexdigest(),
                       package_versions={r['name']: r['version'] for r in baseline},
                       payload_sha256={r['name']: r['payload_sha256'] for r in baseline},
                       private_cleanup='PASS; no private contents or hashes recorded',
                       checks=[{'check': name, 'status': 'PASS'} for name in required],
                       installed_packages_sha256=i.native.sha(installed), installed_package_count=5)
        return receipt, commit, contract, installed, base

    def test_verified_commit_contract(self):
        i.verify_commit(*self.commit_inputs())

    def test_commit_refuses_failed_partial_or_wrong_binding(self):
        for key, value in [('status', 'FAIL'), ('private_cleanup', 'NOT RUN'), ('checks', []), ('nonce', '0' * 32),
                           ('package_versions', {}), ('payload_sha256', {}), ('installed_packages_sha256', '0' * 64)]:
            values = list(self.commit_inputs()); values[0] = copy.deepcopy(values[0]); values[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                i.verify_commit(*values)

    def test_commit_refuses_upgrade_left_installed(self):
        values = self.commit_inputs(); values[3].write_text(values[3].read_text().replace('cachy-asahi-setup 1-1', 'cachy-asahi-setup 2-1'))
        with self.assertRaises(ValueError):
            i.verify_commit(*values)


if __name__ == '__main__':
    unittest.main()
