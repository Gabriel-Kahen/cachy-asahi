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
        for name in ('integration', 'integration_export', 'sign_fixture', 'installed_handoff', 'source_suites', 'verify_derived', 'lifecycle_inventory', 'commit_image', 'repository_projection', 'desktop_projection'):
            paths += [f'scripts/ci/{name}.py', f'scripts/ci/test_{name}.py']
        for name in paths:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('reviewed source')
        (self.root / 'scripts/ci/recipes.lock.json').write_text('{}')

    def test_independent_followup_sources_are_excluded_from_initial_snapshot(self):
        self.source_tree()
        for directory in ('scripts/virtual', 'scripts/client', 'scripts/experiments', 'scripts/port', 'scripts/platform', 'scripts/ci/development', 'packages/tools', 'packages/libraries'):
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

    def test_repository_ldconfig_adds_only_chroot_and_preserves_isolation(self):
        base = dict(image='sha256:' + 'a' * 64, name='cachy-asahi-repository-' + 'b' * 32,
                    binds=[(self.root, '/inputs', True)], root=True)
        default = i.command(**base)
        repository = i.command(**base, repository_ldconfig=True)
        self.assertEqual([arg for arg in repository if arg != '--cap-add=SYS_CHROOT'], default)
        self.assertEqual(repository.count('--cap-add=SYS_CHROOT'), 1)
        self.assertNotIn('--cap-add=KILL', repository)
        for arg in ('--read-only', '--network=none', '--cap-drop=ALL',
                    '--security-opt=no-new-privileges', '--cgroupns=private', '--pids-limit=512'):
            self.assertIn(arg, repository)

    def test_repository_ldconfig_refuses_other_launches_and_custom_caps(self):
        base = dict(image='sha256:' + 'a' * 64, name='cachy-asahi-repository-' + 'b' * 32,
                    binds=[(self.root, '/inputs', True)], root=True)
        for change in ({'root': False}, {'name': 'cachy-asahi-lifecycle-' + 'b' * 32},
                       {'rootcaps': (*i.CAPS, 'KILL')}, {'repository_ldconfig': 'yes'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                i.command(**(base | {'repository_ldconfig': True} | change))
        with self.assertRaises(ValueError):
            i.command(**base, rootcaps=(*i.CAPS, 'SYS_CHROOT'))

    def test_repository_controller_launch_matches_exact_owner_privilege_guard(self):
        controller = self.controller()
        controller.archives = self.root / 'archives'; controller.archives.mkdir()
        controller.source = self.root / 'source'
        runner = controller.source / 'scripts/integration/repository.py'
        runner.parent.mkdir(parents=True)
        shutil.copyfile(Path(__file__).resolve().parents[1] / 'integration/repository.py', runner)
        controller.native_out = self.root / 'native'; controller.native_out.mkdir()
        (controller.native_out / 'packages.lock').write_text('base 1-1\n')
        controller.image = 'sha256:' + 'a' * 64
        controller.commit = 'b' * 40
        controller.rows = {'baseline': [], 'upgrade': []}
        raw = self.root / 'raw'; raw.mkdir()
        def execute(command, log):
            bits = {'CHOWN': 0, 'DAC_OVERRIDE': 1, 'FOWNER': 3, 'SETGID': 6, 'SETUID': 7, 'SYS_CHROOT': 18}
            capabilities = [arg.removeprefix('--cap-add=') for arg in command if arg.startswith('--cap-add=')]
            self.assertEqual(set(capabilities), set(bits))
            self.assertEqual(len(capabilities), 6)
            mask = sum(1 << bits[name] for name in capabilities)
            owner_spec = importlib.util.spec_from_file_location('repository_guard', runner)
            owner = importlib.util.module_from_spec(owner_spec); owner_spec.loader.exec_module(owner)
            observed = ''.join(f'{name}:\t{mask if name in ("CapEff", "CapPrm", "CapBnd") else 0:x}\n'
                               for name in owner.CAP_FIELDS) + 'NoNewPrivs:\t1\n'
            self.assertEqual(owner.privileges(observed)['CapEff'], 0x400cb)
            for arg in ('--read-only', '--network=none', '--security-opt=no-new-privileges'):
                self.assertIn(arg, command)
            i.native.save(raw / 'result.json', {'status': 'PASS'})
        with patch.object(i, 'execute_container', side_effect=execute) as launched, \
             patch.object(i, 'retain_outer_log'), patch.object(i.repository_projection, 'project', return_value={'status': 'PASS'}):
            controller.repository(raw)
        launched.assert_called_once()

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
        clean = {**base, 'Cmd': [], 'Entrypoint': []}
        self.assertEqual(i.image_config(base), i.image_config(clean))
        sentinel = {**clean, 'Entrypoint': [''], 'Labels': {}}
        self.assertEqual(i.image_config(base), i.image_config(sentinel))
        for changed in ({'Entrypoint': ['/usr/bin/env']}, {'Cmd': ['/runner/installed_handoff.py']},
                        {'Labels': {'execution': 'lifecycle'}}, {'Entrypoint': ['', 'runtime-argument']}):
            self.assertNotEqual(i.image_config(base), i.image_config({**sentinel, **changed}))
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

    def test_bound_desktop_sgr_logs_project_without_changing_receipt(self):
        from test_desktop_projection import write_bound_fixture
        raw = self.root / 'raw'; raw.mkdir()
        receipt, authority = write_bound_fixture(raw)
        original = (raw / 'desktop/desktop.json').read_bytes()
        rejected_work = self.root / 'before'; rejected_work.mkdir()
        with self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'rejected', rejected_work)
        work = self.root / 'after'; work.mkdir()
        public = self.root / 'public'
        i.safe_public(raw, public, work, desktop_authority=authority)
        self.assertEqual((public / 'desktop/desktop.json').read_bytes(), original)
        self.assertEqual(json.loads((public / 'desktop/desktop.json').read_text())['status'], receipt['status'])
        index = json.loads((public / 'desktop-terminal-projections.json').read_text())
        self.assertEqual(len(index['files']), 2)
        for row in index['files']:
            raw_data, projected = (raw / row['path']).read_bytes(), (public / row['path']).read_bytes()
            self.assertEqual(hashlib.sha256(raw_data).hexdigest(), row['raw_sha256'])
            self.assertEqual(hashlib.sha256(projected).hexdigest(), row['public_sha256'])
            self.assertNotIn(b'\x1b', projected)
            self.assertIn(b'config ok', projected)

    def test_desktop_projection_does_not_allow_unknown_terminal_logs(self):
        from test_desktop_projection import write_bound_fixture
        raw = self.root / 'raw'; raw.mkdir()
        _, authority = write_bound_fixture(raw)
        (raw / 'desktop/command-24.txt').write_bytes(b'\x1b[1;32munknown\x1b[0m')
        work = self.root / 'work'; work.mkdir()
        with self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'public', work, desktop_authority=authority)
        rejected = json.loads((self.root / 'public/export-manifest.json').read_text())['rejected']
        self.assertTrue(any(row['path'] == 'desktop/command-24.txt' for row in rejected))

    def test_desktop_receipt_replacement_after_projection_is_refused(self):
        from test_desktop_projection import write_bound_fixture
        raw = self.root / 'raw'; raw.mkdir()
        receipt, authority = write_bound_fixture(raw)
        original = i.desktop_projection.project
        def replacing(*args):
            projected = original(*args)
            receipt['hardware_validation'] = 'PASS'
            (raw / 'desktop/desktop.json').write_text(json.dumps(receipt))
            return projected
        work = self.root / 'work'; work.mkdir()
        with patch.object(i.desktop_projection, 'project', side_effect=replacing), self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'public', work, desktop_authority=authority)
        self.assertFalse((self.root / 'public/desktop/desktop.json').exists())

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

    def test_lifecycle_inventory_projection_retains_full_rows_original_and_public_hashes(self):
        raw, work = self.root / 'raw', self.root / 'work'; raw.mkdir(); work.mkdir()
        base = {'base': '1-1', 'libsecret': '0.21.8.2-1'}
        original = [{'name': name, 'version': '1-1'} for name in i.native.RECIPES]
        upgrade = [{'name': name, 'version': '2-1'} for name in i.native.RECIPES]
        authority = {'base': base, 'baseline': base | {r['name']: r['version'] for r in original},
                     'upgrade': base | {r['name']: r['version'] for r in upgrade}}
        original_hashes = {}
        for stage, kind in i.lifecycle_inventory.STAGES.items():
            path = raw / 'lifecycle' / (stage + '-inventory.json'); path.parent.mkdir(exist_ok=True)
            i.native.save(path, authority[kind]); original_hashes[path.relative_to(raw).as_posix()] = i.native.sha(path)
        i.safe_public(raw, self.root / 'public', work, lifecycle_authority=(base, original, upgrade))
        receipt = json.loads((self.root / 'public/inventory-projections.json').read_text())
        self.assertEqual(set(receipt['files']), set(original_hashes))
        for name, digest in original_hashes.items():
            target = self.root / 'public' / name
            projected = json.loads(target.read_text())
            self.assertEqual(projected['original_sha256'], digest)
            self.assertEqual({r['name']: r['version'] for r in projected['packages']}, authority[projected['authority']])
            self.assertEqual(receipt['files'][name]['projected_sha256'], i.native.sha(target))
            self.assertEqual(i.native.sha(raw / name), digest)
        self.assertEqual(json.loads((self.root / 'public/export-manifest.json').read_text())['evidence_export'], 'PASS')

    def test_unknown_inventory_and_malformed_known_content_do_not_bypass_generic_guard(self):
        raw, work = self.root / 'raw', self.root / 'work'; raw.mkdir(); work.mkdir()
        path = raw / 'lifecycle/unlisted-inventory.json'; path.parent.mkdir(); path.write_text('{"password":"credential-fixture"}')
        original = [{'name': name, 'version': '1-1'} for name in i.native.RECIPES]
        upgrade = [{'name': name, 'version': '2-1'} for name in i.native.RECIPES]
        with self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'public', work, lifecycle_authority=({'base':'1-1'}, original, upgrade))
        self.assertFalse((self.root / 'public/lifecycle/unlisted-inventory.json').exists())

    def repository_contract(self):
        return {'schema_version':1,'purpose':i.repository_projection.PURPOSE,'source_commit':'a'*40,
                'nonce':'c'*32,'image_id':'sha256:'+'b'*64,'daemon_arch':'aarch64',
                'script_sha256':'d'*64,'upgrade_kind':'synthetic-changed-package-fixtures'}

    def operation_evidence(self):
        from test_repository_projection import operation_fixture
        raw, work = self.root / 'raw', self.root / 'work'
        work.mkdir()
        result, contract = operation_fixture(raw)
        return raw, work, result, contract

    def legacy_log_evidence(self, case, *, with_operations):
        from test_repository_projection import operation_fixture
        raw, work, public = case / 'raw', case / 'work', case / 'public'
        raw.mkdir(); work.mkdir()
        if with_operations:
            result, contract = operation_fixture(raw)
            labels = {row['label'] for row in result['commands']}
            for label in i.REPOSITORY_PUBLIC_LOGS:
                if label in labels:
                    continue
                name = f'{len(result["commands"]):03d}-{label}.txt'
                data = b'[GNUPG:] BADSIG 0123456789ABCDEF TEST ONLY\n'
                (raw / name).write_bytes(data)
                result['commands'].append({'label': label, 'log': name, 'sha256': hashlib.sha256(data).hexdigest(),
                                           'exit_code': 1, 'expected': 1})
                result['evidence_sha256'][name] = hashlib.sha256(data).hexdigest()
            i.native.save(raw / 'result.json', result)
            authority = (result['base_versions'], contract)
        else:
            self.repository_status(raw)
            authority = None
        captures = {}
        i.repository_public_logs(raw, captured=captures)
        self.assertEqual(len(captures), 6)
        return raw, work, public, authority, captures

    def test_all_six_legacy_aliases_survive_capture_deletion_with_and_without_operations(self):
        logs, operations = i.repository_public_logs, i.repository_projection.operation_files
        for with_operations in (False, True):
            for number in range(7):
                case = self.root / f'{with_operations}-{number}'; case.mkdir()
                raw, work, public, authority, captures = self.legacy_log_evidence(case, with_operations=with_operations)
                names = list(captures)
                removed = names if number == 6 else [names[number]]
                def capture_then_delete(*args, **kwargs):
                    value = (operations if with_operations else logs)(*args, **kwargs)
                    for name in removed:
                        (raw / name).unlink()
                    return value
                target, attribute = (i.repository_projection, 'operation_files') if with_operations else (i, 'repository_public_logs')
                with self.subTest(with_operations=with_operations, removed=removed), \
                        patch.object(target, attribute, side_effect=capture_then_delete):
                    i.safe_public(raw, public, work, repository_authority=authority)
                manifest = json.loads((public / 'export-manifest.json').read_bytes())
                result = json.loads((public / 'result.json').read_bytes())
                accepted = {row['path']: row for row in manifest['accepted']}
                self.assertEqual(manifest['evidence_export'], 'PASS')
                for name, (alias, data) in captures.items():
                    self.assertEqual((public / alias).read_bytes(), data)
                    self.assertEqual(accepted[alias]['sha256'], hashlib.sha256(data).hexdigest())
                    row = next(row for row in result['commands'] if row['log'] == name)
                    self.assertEqual(row['public_log'], alias)

    def test_missing_exported_legacy_aliases_refuse_even_without_operation_index(self):
        exporter = i.export_evidence
        for with_operations in (False, True):
            for number in range(6):
                case = self.root / f'{with_operations}-{number}'; case.mkdir()
                raw, work, public, authority, captures = self.legacy_log_evidence(case, with_operations=with_operations)
                alias = list(captures.values())[number][0]
                def omit_alias(selected, target):
                    (selected / alias).unlink()
                    receipt = exporter(selected, target)
                    self.assertEqual(receipt['evidence_export'], 'PASS')
                    return receipt
                with self.subTest(with_operations=with_operations, alias=alias), \
                        patch.object(i, 'export_evidence', side_effect=omit_alias), \
                        self.assertRaisesRegex(ValueError, 'reference missing from manifest'):
                    i.safe_public(raw, public, work, repository_authority=authority)

    def test_legacy_alias_capture_never_allows_unknown_sensitive_path_or_collision(self):
        for name in ('unlisted-gpg-status.txt', 'unlisted-cache.json', '000-signature-untrusted-A-status.txt'):
            case = self.root / name; case.mkdir()
            raw, work, public, authority, _ = self.legacy_log_evidence(case, with_operations=False)
            (raw / name).write_text('{"password":"DO-NOT-PUBLISH"}')
            with self.subTest(name=name), self.assertRaises(ValueError):
                i.safe_public(raw, public, work, repository_authority=authority)
            self.assertFalse((public / name).exists())

    def test_repository_exact_operations_export_neutral_names_with_coherent_references(self):
        raw, work, result, contract = self.operation_evidence()
        original = {path.name: path.read_bytes() for path in raw.iterdir()}
        public = self.root / 'public'
        i.safe_public(raw, public, work, repository_authority=(result['base_versions'], contract))
        index = json.loads((public / 'repository-operation-aliases.json').read_bytes())
        self.assertEqual(len(index['files']), 9)
        projected = json.loads((public / 'result.json').read_bytes())
        self.assertEqual(projected['sync_cache_reset']['receipt'], 'revoked-A-sync-cache-reset.json')
        self.assertEqual(projected['sync_cache_reset']['public_receipt'], 'revoked-A-sync-reset.json')
        self.assertEqual(projected['public_operation_index'], 'repository-operation-aliases.json')
        for row in projected['commands']:
            for field, public_field in (('log', 'public_log'), ('stderr_log', 'public_stderr_log')):
                if row.get(field) in index['files']:
                    self.assertEqual(row[public_field], index['files'][row[field]]['public_path'])
        for name, row in index['files'].items():
            path = public / row['public_path']
            self.assertEqual(path.read_bytes(), original[name])
            self.assertEqual(i.native.sha(path), row['original_sha256'])
            self.assertEqual(i.native.sha(path), projected['evidence_sha256'][name])
            self.assertFalse((public / name).exists())
        self.assertEqual(json.loads((public / 'export-manifest.json').read_bytes())['evidence_export'], 'PASS')
        self.assertEqual(original, {path.name: path.read_bytes() for path in raw.iterdir()})

    def test_repository_operation_alias_collision_refused_before_export(self):
        raw, work, result, contract = self.operation_evidence()
        (raw / 'revoked-A-sync-reset.json').write_text('public-looking collision')
        with self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'public', work, repository_authority=(result['base_versions'], contract))
        self.assertFalse((self.root / 'public').exists())

    def test_repository_captured_nine_publish_after_each_original_or_all_originals_disappear(self):
        from test_repository_projection import operation_fixture
        original = i.repository_projection.operation_files
        probe = self.root / 'probe'; result, contract = operation_fixture(probe)
        names = list(original(probe, result, contract)[0])
        for number, removed in enumerate([[name] for name in names] + [names]):
            case = self.root / str(number); case.mkdir()
            raw, work, public = case / 'raw', case / 'work', case / 'public'; work.mkdir()
            result, contract = operation_fixture(raw)
            captures, _ = original(raw, result, contract)
            def capture_then_delete(*args):
                value = original(*args)
                for name in removed:
                    (raw / name).unlink()
                return value
            with self.subTest(removed=removed), patch.object(i.repository_projection, 'operation_files',
                                                           side_effect=capture_then_delete):
                i.safe_public(raw, public, work, repository_authority=(result['base_versions'], contract))
            index = json.loads((public / 'repository-operation-aliases.json').read_bytes())
            manifest = json.loads((public / 'export-manifest.json').read_bytes())
            self.assertEqual(manifest['evidence_export'], 'PASS')
            accepted = {row['path']: row for row in manifest['accepted']}
            self.assertEqual(len(index['files']), 9)
            for name, (alias, data) in captures.items():
                self.assertEqual((public / alias).read_bytes(), data)
                self.assertEqual(accepted[alias]['sha256'], index['files'][name]['public_sha256'])
                self.assertEqual(accepted[alias]['bytes'], len(data))

    def test_repository_missing_public_operation_never_returns_success_even_if_generic_export_passes(self):
        from test_repository_projection import operation_fixture
        exporter = i.export_evidence
        probe = self.root / 'probe'; result, contract = operation_fixture(probe)
        aliases = [alias for alias, _ in i.repository_projection.operation_files(probe, result, contract)[0].values()]
        for number, alias in enumerate(aliases):
            case = self.root / str(number); case.mkdir()
            raw, work, public = case / 'raw', case / 'work', case / 'public'; work.mkdir()
            result, contract = operation_fixture(raw)
            def omit_public_reference(selected, target):
                (selected / alias).unlink()
                receipt = exporter(selected, target)
                self.assertEqual(receipt['evidence_export'], 'PASS')
                return receipt
            with self.subTest(alias=alias), patch.object(i, 'export_evidence', side_effect=omit_public_reference), \
                    self.assertRaisesRegex(ValueError, 'reference missing from manifest'):
                i.safe_public(raw, public, work, repository_authority=(result['base_versions'], contract))

    def test_repository_missing_result_after_capture_refuses_before_export(self):
        raw, work, result, contract = self.operation_evidence()
        original = i.repository_projection.operation_files
        def missing_result(*args):
            value = original(*args); (raw / 'result.json').unlink(); return value
        with patch.object(i.repository_projection, 'operation_files', side_effect=missing_result), \
                self.assertRaisesRegex(ValueError, 'result missing'):
            i.safe_public(raw, self.root / 'public', work, repository_authority=(result['base_versions'], contract))
        self.assertFalse((self.root / 'public').exists())

    def test_repository_selected_index_cannot_invent_missing_public_reference(self):
        raw, work, result, contract = self.operation_evidence()
        save = i.native.save
        def forge_index(path, value):
            if path.name == 'repository-operation-aliases.json':
                value = copy.deepcopy(value)
                next(iter(value['files'].values()))['public_path'] = 'missing-reference.json'
            save(path, value)
        with patch.object(i.native, 'save', side_effect=forge_index), self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'public', work, repository_authority=(result['base_versions'], contract))
        self.assertFalse((self.root / 'public').exists())

    def test_repository_operation_index_collision_cannot_drop_unknown_credentials(self):
        raw, work, result, contract = self.operation_evidence()
        (raw / 'repository-operation-aliases.json').write_text('{"password":"DO-NOT-PUBLISH"}')
        with self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'public', work, repository_authority=(result['base_versions'], contract))
        self.assertFalse((self.root / 'public').exists())

    def test_repository_operation_aliases_never_allow_other_sensitive_paths(self):
        raw, work, result, contract = self.operation_evidence()
        (raw / 'unreviewed-cache.json').write_text('{"public":"looking"}')
        with self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'public', work, repository_authority=(result['base_versions'], contract))
        manifest = json.loads((self.root / 'public/export-manifest.json').read_bytes())
        self.assertEqual(manifest['evidence_export'], 'FAIL')
        self.assertEqual([row['path'] for row in manifest['rejected']], ['unreviewed-cache.json'])

    def test_repository_operation_aliases_preserve_unknown_credentials_for_generic_refusal(self):
        raw, work, result, contract = self.operation_evidence()
        result['unknown'] = {'password': 'DO-NOT-PUBLISH'}
        i.native.save(raw / 'result.json', result)
        with self.assertRaises(ValueError):
            i.safe_public(raw, self.root / 'public', work, repository_authority=(result['base_versions'], contract))
        self.assertFalse((self.root / 'public/result.json').exists())
        self.assertEqual(json.loads((self.root / 'public/export-manifest.json').read_bytes())['evidence_export'], 'FAIL')

    def test_repository_inventory_projection_preserves_failure_and_all_rows(self):
        raw, work = self.root / 'raw', self.root / 'work'; raw.mkdir(); work.mkdir()
        base = {'base':'1-1', 'libsecret':'0.21.8.2-1'}
        value = {'schema_version':1, 'purpose':i.repository_projection.PURPOSE, 'status':'FAIL',
                 'source_commit':'a'*40, 'input_contract':{key:self.repository_contract()[key] for key in i.repository_projection.CONTRACT_FIELDS},
                 'commands':[], 'base_versions':base, 'error':'repo-add-baseline-A failed'}
        i.native.save(raw/'result.json',value); original=i.native.sha(raw/'result.json')
        i.safe_public(raw,self.root/'public',work,repository_authority=(base,self.repository_contract()))
        result=json.loads((self.root/'public/result.json').read_text())
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual({r['name']:r['version'] for r in result['base_versions']},base)
        receipt=json.loads((self.root/'public/repository-inventory-projection.json').read_text())
        self.assertEqual(receipt['original_sha256'],original)
        self.assertEqual(receipt['projected_sha256'],i.native.sha(self.root/'public/result.json'))
        self.assertEqual(i.native.sha(raw/'result.json'),original)

    def test_repository_projection_refuses_wrong_image_or_source_authority(self):
        for field in ('source_commit','image_id','nonce','script_sha256'):
            raw=self.root/field;raw.mkdir();work=self.root/(field+'-work');work.mkdir()
            value={'schema_version':1,'purpose':i.repository_projection.PURPOSE,'source_commit':'a'*40,
                   'input_contract':{key:self.repository_contract()[key] for key in i.repository_projection.CONTRACT_FIELDS},'base_versions':{'base':'1-1'}}
            if field=='source_commit':value[field]='c'*40
            else:value['input_contract'][field]='sha256:'+'c'*64
            i.native.save(raw/'result.json',value)
            with self.assertRaises(ValueError):
                i.safe_public(raw,self.root/(field+'-public'),work,repository_authority=({'base':'1-1'},self.repository_contract()))

    def test_unknown_repository_credentials_never_publish_original_or_projected_hashes(self):
        raw,work=self.root/'raw',self.root/'work';raw.mkdir();work.mkdir()
        value={'schema_version':1,'purpose':i.repository_projection.PURPOSE,'source_commit':'a'*40,
               'input_contract':{key:self.repository_contract()[key] for key in i.repository_projection.CONTRACT_FIELDS},
               'base_versions':{'libsecret':'1-1'},'password':'private-repository-fixture'}
        i.native.save(raw/'result.json',value)
        with self.assertRaises(ValueError):
            i.safe_public(raw,self.root/'public',work,repository_authority=({'libsecret':'1-1'},self.repository_contract()))
        self.assertFalse((self.root/'public/repository-inventory-projection.json').exists())
        self.assertFalse((self.root/'public/result.json').exists())

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
        controller.desktop_contract = None
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

    def test_handoff_refusal_code_is_explicit_and_unknown_codes_cannot_be_published(self):
        values = self.commit_inputs(); values[0]['status'] = 'FAIL'
        with self.assertRaises(i.HandoffRefusal) as raised:
            i.verify_commit(*values)
        self.assertEqual(raised.exception.code, 'handoff-ready')
        with self.assertRaises(ValueError):
            i.HandoffRefusal('untrusted-credential-value')
        controller = self.controller()
        def refused(raw):
            i.handoff_need(False, 'lifecycle-config')
        self.assertFalse(controller.stage('lifecycle', refused))
        self.assertEqual(controller.report['stages']['lifecycle']['refusal_code'], 'lifecycle-config')

    def test_handoff_lock_regularity_has_a_safe_specific_refusal_code(self):
        values = self.commit_inputs()
        os.link(values[3], self.root / 'installed-link')
        with self.assertRaises(i.HandoffRefusal) as raised:
            i.verify_commit(*values)
        self.assertEqual(raised.exception.code, 'handoff-installed-lock-regular')
        self.assertNotIn(str(self.root), str(raised.exception))

    def lifecycle_fixture(self):
        controller = self.controller(); controller.commit = 'b' * 40
        controller.image = 'sha256:' + 'e' * 64; controller.installed = None
        controller.native_out = self.root / 'native'; controller.native_out.mkdir()
        (controller.native_out / 'packages.lock').write_text('base 1-1\n')
        controller.source = self.root / 'source'
        for name in ('integration/lifecycle.py', 'ci/installed_handoff.py', 'ci/verify_derived.py'):
            path = controller.source / 'scripts' / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('reviewed source')
        controller.archives = self.root / 'archives'; controller.archives.mkdir()
        controller.rows = {stage: [{'name': name, 'version': '1-1' if stage == 'baseline' else '2-1',
                                   'archive': f'{stage}/{name}.pkg.tar.xz', 'sha256': 'a' * 64,
                                   'payload_sha256': {f'usr/share/{name}': 'b' * 64}}
                                  for name in i.native.RECIPES] for stage in ('baseline', 'upgrade')}
        controller.signed = self.root / 'signed'
        certificate = controller.signed / 'public/public-key.asc'; certificate.parent.mkdir(parents=True); certificate.write_text('TEST-only fixture')
        for rows in controller.rows.values():
            for row in rows:
                archive = controller.archives / row['archive']; archive.parent.mkdir(parents=True, exist_ok=True); archive.write_bytes(b'TEST-only archive')
                path = controller.signed / 'public/signatures' / (row['archive'] + '.sig')
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'TEST-only signature')
        controller.sign_receipt = {'fingerprint': 'f' * 40}
        raw = self.root / 'raw'; raw.mkdir()
        def execute(command, log, *args, **kwargs):
            log.write_text('')
            i.native.save(raw / 'commit-receipt.json', {'installed_packages_sha256': 'a' * 64})
        return controller, raw, execute

    def test_lifecycle_failed_observer_cannot_replace_primary_or_skip_cleanup(self):
        controller, raw, execute = self.lifecycle_fixture()
        original = ValueError('private operand fixture')
        order = []
        def failed(*args, **kwargs):
            order.append('execute')
            raise original
        with patch.object(i, 'execute_container', side_effect=failed), \
             patch.object(i.native, 'run', return_value=json.dumps([{'Config': {'User': 'alarm'}}])), \
             patch.object(i, 'remove_container', side_effect=lambda *a: order.append('container-cleanup') or {'status': 'PASS'}), \
             patch.object(i, 'remove_derivative', side_effect=lambda *a: order.append('derivative-cleanup') or {'status': 'PASS'}), \
             patch.object(i, 'retain_handoff_diagnostic', side_effect=lambda *a: order.append('observation') or (_ for _ in ()).throw(KeyboardInterrupt())), \
             self.assertRaises(ValueError) as raised:
            controller.lifecycle(raw)
        self.assertIs(raised.exception, original)
        self.assertEqual(order, ['execute', 'container-cleanup', 'derivative-cleanup', 'observation'])
        self.assertEqual(json.loads((raw / 'handoff-controller.json').read_text())['status'], 'FAIL')
        self.assertIsNone(controller.installed)

    def test_lifecycle_config_refusal_retains_only_changed_key_names_and_cleanup(self):
        controller, raw, execute = self.lifecycle_fixture()
        base_config = {'User': 'alarm', 'Env': ['PUBLIC=1'], 'Cmd': ['/bin/bash']}
        private = 'deliberately-sensitive-config-fixture'
        derived_config = {**base_config, 'Env': ['password=' + private], 'Cmd': ['/bin/sh']}
        derived = 'sha256:' + 'a' * 64
        def query(command, *args, **kwargs):
            if command[:3] == ['docker', 'container', 'inspect']:
                return json.dumps([{'State': {'Status': 'exited', 'ExitCode': 0}, 'Image': controller.image}])
            if command[:2] == ['docker', 'commit']:
                return derived
            return json.dumps([{'Id': command[-1], 'Architecture': 'arm64',
                                'Config': base_config if command[-1] == controller.image else derived_config}])
        with patch.object(i, 'execute_container', side_effect=execute), patch.object(i, 'verify_commit'), patch.object(i, 'commit_image', return_value=derived), \
             patch.object(i.native, 'run', side_effect=query), patch.object(i, 'remove_container', return_value={'status': 'PASS'}), \
             patch.object(i, 'remove_derivative', return_value={'status': 'PASS'}) as derivative_cleanup, \
             self.assertRaises(i.HandoffRefusal):
            controller.lifecycle(raw)
        diagnostic = json.loads((raw / 'handoff-controller.json').read_text())
        self.assertEqual(diagnostic['refusal_code'], 'lifecycle-config')
        self.assertEqual(diagnostic['config_difference_fields'], ['Cmd', 'Env'])
        self.assertEqual(diagnostic['phase'], 'derived-config-verification')
        self.assertFalse((raw / 'committed-config.json').exists())
        self.assertNotIn(private, ''.join(path.read_text() for path in raw.glob('*.json')))
        self.assertNotIn(hashlib.sha256(private.encode()).hexdigest(), (raw / 'handoff-controller.json').read_text())
        self.assertEqual(json.loads((raw / 'container-removal.json').read_text())['status'], 'PASS')
        self.assertEqual(derivative_cleanup.call_args.args[0]['image_id'], derived)
        self.assertEqual(json.loads((raw / 'derivative-cleanup.json').read_text())['status'], 'PASS')

    def test_failed_derivative_cleanup_removes_only_owned_identity_and_verifies_absence(self):
        image, base = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64
        tag = 'cachy-asahi-private-installed:' + 'c' * 32
        observed = [image + '\n', image+'\n'+base+'\n', '', base + '\n', '']
        calls = []
        def run(command, **kwargs):
            calls.append(command); return SimpleNamespace(returncode=0, stdout=observed.pop(0).encode())
        with patch.object(i.subprocess, 'run', side_effect=run):
            result = i.remove_derivative({'tag': tag, 'image_id': image, 'reply_valid': True}, base)
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['absence_verified'])
        self.assertIn(['docker', 'image', 'rm', image], calls)
        self.assertFalse(any(base in command for command in calls))

    def test_ambiguous_commit_recovers_tag_but_never_claims_certain_cleanup(self):
        image, base = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64
        tag = 'cachy-asahi-private-installed:' + 'c' * 32
        responses = [image + '\n', image+'\n'+base+'\n', '', base + '\n', '']
        with patch.object(i.subprocess, 'run', side_effect=lambda *a, **k: SimpleNamespace(returncode=0, stdout=responses.pop(0).encode())):
            result = i.remove_derivative({'tag': tag, 'image_id': None, 'reply_valid': False}, base)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['cleanup_uncertain'])
        self.assertTrue(result['absence_verified'])

    def test_derivative_cleanup_refuses_base_or_conflicting_recovery_identity(self):
        image, base = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64
        tag = 'cachy-asahi-private-installed:' + 'c' * 32
        for found in (base, 'sha256:' + 'd' * 64):
            with patch.object(i.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=(found+'\n').encode())) as run:
                result = i.remove_derivative({'tag': tag, 'image_id': image, 'reply_valid': True}, base)
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(run.call_count, 1)

    def test_api_response_failure_and_cancellation_preserve_recovery_ownership(self):
        for error in (ValueError('malformed response'), i.Cancelled('cancelled')):
            controller, raw, execute = self.lifecycle_fixture()
            tag = 'cachy-asahi-private-installed:' + 'c' * 32
            def failed(container, config, on_submit):
                on_submit(tag); raise error
            with patch.object(i, 'execute_container', side_effect=execute), patch.object(i, 'verify_commit'), \
                 patch.object(i.native, 'run', return_value=json.dumps([{'Config': {'User':'alarm'}, 'State': {'Status':'exited','ExitCode':0}, 'Image':controller.image}])), \
                 patch.object(i, 'commit_image', side_effect=failed), patch.object(i, 'remove_container', return_value={'status':'PASS'}), \
                 patch.object(i, 'remove_derivative', return_value={'status':'FAIL','cleanup_uncertain':True}) as cleanup, self.assertRaises(ValueError):
                controller.lifecycle(raw)
            self.assertEqual(cleanup.call_args.args[0]['tag'], tag)
            self.assertFalse(cleanup.call_args.args[0]['reply_valid'])
            self.assertIsNone(controller.installed)
            # Fresh independent fixture for the next error path.
            shutil.rmtree(controller.out); shutil.rmtree(raw)
            for name in ('native', 'source', 'archives', 'signed'):
                shutil.rmtree(self.root / name)

    def test_same_job_consumers_finish_before_final_owned_image_cleanup_and_summary(self):
        controller=self.controller();controller.image='sha256:'+'b'*64
        controller.installed='sha256:'+'a'*64
        controller.installed_owned={'tag':'cachy-asahi-private-installed:'+'c'*32,'image_id':controller.installed,'reply_valid':True}
        order=[]
        def consumer(current):
            self.assertEqual(current.installed,'sha256:'+'a'*64);order.append('consumer')
        with patch.object(controller,'run_stages',side_effect=lambda:order.append('stages')), \
             patch.object(i,'remove_derivative',side_effect=lambda *a:order.append('cleanup') or {'status':'PASS'}), \
             patch.object(controller,'finish',side_effect=lambda:order.append('summary') or True):
            self.assertTrue(controller.run(consumers=consumer))
        self.assertEqual(order,['stages','consumer','cleanup','summary'])
        self.assertIsNone(controller.installed)

    def test_final_owned_image_cleanup_failure_and_consumer_failure_cannot_preserve_pass(self):
        controller=self.controller();controller.image='sha256:'+'b'*64;controller.installed=None
        for stage in ('fixtures','signer','lifecycle','repository','onboarding','desktop','source-suites'):
            controller.report['stages'][stage]={'status':'PASS'}
        with patch.object(controller,'run_stages'),patch.object(i,'remove_derivative',return_value={'status':'FAIL'}):
            self.assertFalse(controller.run())
        self.assertEqual(controller.report['status'],'FAIL')

    def test_consumer_exception_and_cancellation_still_remove_owned_image_and_fail(self):
        for error in (RuntimeError('password=private-consumer-fixture'),i.Cancelled('cancelled')):
            controller=self.controller();controller.image='sha256:'+'b'*64;controller.installed=None
            for stage in ('fixtures','signer','lifecycle','repository','onboarding','desktop','source-suites'):
                controller.report['stages'][stage]={'status':'PASS'}
            def consumer(current):
                raise error
            with patch.object(controller,'run_stages'),patch.object(i,'remove_derivative',return_value={'status':'PASS'}) as cleanup:
                self.assertFalse(controller.run(consumers=consumer))
            cleanup.assert_called_once()
            self.assertNotIn('private-consumer-fixture',(controller.public/'summary/result.json').read_text())
            shutil.rmtree(controller.out)

    def test_fresh_verifier_refusal_removes_registered_derivative(self):
        controller,raw,initial_execute=self.lifecycle_fixture()
        derived='sha256:'+'a'*64;tag='cachy-asahi-private-installed:'+'c'*32
        config={'User':'alarm','WorkingDir':'/tmp','Cmd':None,'Entrypoint':None}
        def execute(command,log,*args,**kwargs):
            if '/runner/verify_derived.py' in command:
                i.native.save(raw/'committed-image/result.json',{'status':'FAIL','image_id':derived})
            else:
                initial_execute(command,log)
                (raw/'installed-packages.lock').write_text('base 1-1\n')
        def commit(container,base,on_submit):
            on_submit(tag);return derived
        def query(command,*args,**kwargs):
            if command[:3]==['docker','container','inspect']:
                return json.dumps([{'State':{'Status':'exited','ExitCode':0},'Image':controller.image}])
            if command[-1]==derived:
                self.assertEqual(controller.installed_owned['image_id'],derived)
            return json.dumps([{'Id':command[-1],'Architecture':'arm64','Config':config}])
        with patch.object(i,'execute_container',side_effect=execute),patch.object(i,'verify_commit'), \
             patch.object(i,'commit_image',side_effect=commit),patch.object(i.native,'run',side_effect=query), \
             patch.object(i,'remove_container',return_value={'status':'PASS'}), \
             patch.object(i,'remove_derivative',return_value={'status':'PASS'}) as cleanup,self.assertRaises(i.HandoffRefusal) as refused:
            controller.lifecycle(raw)
        self.assertEqual(refused.exception.code,'lifecycle-derived-verification')
        self.assertEqual(cleanup.call_args.args[0]['image_id'],derived)
        self.assertEqual(cleanup.call_args.args[0]['tag'],tag)
        self.assertIsNone(controller.installed)

    def test_derivative_cleanup_is_idempotent_for_an_already_absent_owned_image(self):
        image,base='sha256:'+'a'*64,'sha256:'+'b'*64
        responses=['',base+'\n',base+'\n',''];calls=[]
        def query(command,**kwargs):
            calls.append(command);return SimpleNamespace(returncode=0,stdout=responses.pop(0).encode())
        with patch.object(i.subprocess,'run',side_effect=query):
            result=i.remove_derivative({'tag':'cachy-asahi-private-installed:'+'c'*32,'image_id':image,'reply_valid':True},base)
        self.assertEqual(result['status'],'PASS')
        self.assertFalse(any(command[:3]==['docker','image','rm'] for command in calls))

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



class HandoffDiagnosticBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='handoff-observer-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.value = {'schema_version': 1, 'operation': 'COMMIT', 'refusal': 'LOAD_01', 'cancelled': False}
        self.frame = i.HANDOFF_DIAGNOSTIC_PREFIX + json.dumps(self.value).encode() + b'\n'

    def test_closed_record_and_ambiguous_or_malformed_records(self):
        self.assertEqual(i.handoff_diagnostic_record(b'held public output\n' + self.frame), self.value)
        invalid = [b'', self.frame * 2, self.frame[:-3], b'x' * (1024**2 + 1)]
        for key, value in (('schema_version', True), ('operation', 'foreign'), ('refusal', '/private'),
                           ('cancelled', 1), ('extra', 'private')):
            row = dict(self.value, **{key: value})
            invalid.append(i.HANDOFF_DIAGNOSTIC_PREFIX + json.dumps(row).encode())
        invalid.append(i.HANDOFF_DIAGNOSTIC_PREFIX + b'{"schema_version":1,"schema_version":1}')
        for data in invalid:
            with self.subTest(data=data[:80]):
                try:
                    result = i.handoff_diagnostic_record(data)
                except (ValueError, UnicodeError):
                    result = None
                self.assertIsNone(result)

    def test_collector_fresh_output_is_private_and_exclusive(self):
        (self.root / 'container.log').write_bytes(self.frame)
        i.retain_handoff_diagnostic(self.root)
        output = self.root / 'handoff-diagnostic.json'
        self.assertEqual(json.loads(output.read_bytes()), self.value)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        before = output.read_bytes()
        with self.assertRaises(FileExistsError):
            i.retain_handoff_diagnostic(self.root)
        self.assertEqual(output.read_bytes(), before)

    def test_collector_refuses_input_symlink_hardlink_fifo_and_large_file(self):
        target = self.root / 'owned-target'; target.write_bytes(self.frame)
        log = self.root / 'container.log'; output = self.root / 'handoff-diagnostic.json'
        log.symlink_to(target)
        with self.assertRaises(OSError):
            i.retain_handoff_diagnostic(self.root)
        self.assertFalse(output.exists()); log.unlink()
        os.link(target, log)
        i.retain_handoff_diagnostic(self.root)
        self.assertFalse(output.exists()); log.unlink()
        os.mkfifo(log)
        i.retain_handoff_diagnostic(self.root)
        self.assertFalse(output.exists()); log.unlink()
        log.write_bytes(b'x' * (1024**2 + 1))
        i.retain_handoff_diagnostic(self.root)
        self.assertFalse(output.exists())

    def test_collector_never_follows_existing_output_symlink(self):
        (self.root / 'container.log').write_bytes(self.frame)
        target = self.root / 'owned-target'; target.write_bytes(b'held')
        (self.root / 'handoff-diagnostic.json').symlink_to(target)
        with self.assertRaises(FileExistsError):
            i.retain_handoff_diagnostic(self.root)
        self.assertEqual(target.read_bytes(), b'held')

    def test_collector_unstable_read_is_not_projected_and_fd_closes(self):
        (self.root / 'container.log').write_bytes(self.frame)
        original = i.os.read
        def changed(fd, size):
            data = original(fd, size)
            if data:
                with (self.root / 'container.log').open('ab') as stream:
                    stream.write(b'x')
            return data
        # A finite first read mutates the file; the second read is forced EOF.
        calls = 0
        def read(fd, size):
            nonlocal calls
            calls += 1
            return changed(fd, size) if calls == 1 else b''
        with patch.object(i.os, 'read', side_effect=read), patch.object(i.os, 'close', wraps=i.os.close) as closed:
            i.retain_handoff_diagnostic(self.root)
        self.assertEqual(closed.call_count, 2)
        self.assertFalse((self.root / 'handoff-diagnostic.json').exists())

    def handoff(self):
        spec = importlib.util.spec_from_file_location('diagnostic_handoff_fixture', Path(__file__).with_name('installed_handoff.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_main_failure_observer_cannot_replace_refusal_or_execute_constructor(self):
        h = self.handoff()
        for secondary in (RuntimeError(), KeyboardInterrupt(), SystemExit(), BaseException()):
            with self.subTest(kind=type(secondary)), patch.object(h, 'Handoff', side_effect=ValueError('private operand')) as factory, \
                 patch.object(h.lifecycle, 'handoff_diagnostic_failure', side_effect=secondary), \
                 patch.object(h.lifecycle, 'handoff_diagnostic_emit', side_effect=secondary), \
                 patch.object(h.sys, 'stderr'):
                self.assertEqual(h.main(['--contract', 'fixture', '--contract-sha256', 'unit']), 1)
                self.assertEqual(factory.call_count, 1)

    def test_main_success_observation_control_exceptions_cannot_become_pass(self):
        h = self.handoff()
        for hook in ('handoff_diagnostic_start', 'handoff_diagnostic_emit'):
            for secondary in (KeyboardInterrupt(), SystemExit(), h.Cancelled()):
                with self.subTest(hook=hook, kind=type(secondary)), patch.object(h, 'Handoff') as factory, \
                     patch.object(h.lifecycle, hook, side_effect=secondary), patch.object(h.sys, 'stderr'):
                    factory.return_value.execute.return_value = 0
                    if type(secondary) is SystemExit:
                        with self.assertRaises(SystemExit):
                            h.main(['--contract', 'fixture', '--contract-sha256', 'unit'])
                    elif hook.endswith('start'):
                        self.assertEqual(h.main(['--contract', 'fixture', '--contract-sha256', 'unit']), 1)
                        factory.assert_not_called()
                    else:
                        with self.assertRaises(type(secondary)):
                            h.main(['--contract', 'fixture', '--contract-sha256', 'unit'])

    def test_execute_hostile_errors_keep_cleanup_and_real_cancel_subclasses_sticky(self):
        h = self.handoff()
        class Hostile(ValueError):
            @property
            def __class__(self):
                raise AssertionError('foreign class inspected')
        class Interrupt(KeyboardInterrupt):
            pass
        class Cancel(h.Cancelled):
            pass
        for n, error in enumerate((Hostile(), Interrupt(), Cancel())):
            current = object.__new__(h.Handoff)
            current.receipt = self.root / ('receipt-' + str(n) + '.json')
            current.report = {'status': 'FAIL'}; current.cancelled = False
            current.commit = {'lifecycle_contract_sha256': 'unit'}
            order = []
            current.command = lambda *a: (_ for _ in ()).throw(error)
            current.stop_child = lambda: order.append('stop')
            with patch.object(h.signal, 'signal', return_value='previous') as signals, \
                 patch.object(h.lifecycle, 'handoff_diagnostic_failure', side_effect=BaseException()):
                self.assertEqual(current.execute(), 1)
            self.assertEqual(order, ['stop'])
            self.assertEqual(signals.call_count, 6)
            self.assertEqual(current.cancelled, n != 0)
            self.assertEqual(json.loads(current.receipt.read_bytes()).get('cancelled', False), n != 0)

if __name__ == '__main__':
    unittest.main()
