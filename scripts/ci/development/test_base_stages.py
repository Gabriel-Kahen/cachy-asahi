"""Development base-stage regressions: command/download/package execution mocked."""
import copy
from contextlib import ExitStack, contextmanager
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import base_stages as b


class BaseStages(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'checkout'; self.root.mkdir()
        self.native = self.base / 'native'; self.native.mkdir()
        self.cache = self.base / 'cache'; self.cache.mkdir()
        self.controller = SimpleNamespace(native_out=self.native, image='sha256:' + 'a' * 64,
                                          commit='b' * 40, report={'stages': {'lifecycle': {'status': 'FAIL'}}})
        self.output = self.base / 'stage'
        self.lock = ''.join(f'base-{n:03d} 1-1\n' for n in range(341))
        (self.native / 'packages.lock').write_text(self.lock)
        (self.native / 'image-id').write_text(self.controller.image)
        inputs = {'rootfs_packages': [], 'packages': [{'name': f'base-{n:03d}', 'version': '1-1'} for n in range(341)]}
        b.save(self.native / 'inputs.lock.json', inputs)
        b.save(self.native / 'result.json', {'native_build': 'PASS', 'status': 'native-builds-and-byte-comparison-pass',
                                           'reviewed_inputs_sha256': b.digest(self.native / 'inputs.lock.json')})
        b.save(self.native / 'bootstrap.json', {'status': 'image-provisioned', 'image_id': self.controller.image,
                                               'packages_lock_sha256': b.digest(self.native / 'packages.lock'),
                                               'inputs_sha256': b.digest(self.native / 'inputs.lock.json')})
        self.real_root = HERE.resolve().parents[2]
        self.addCleanup(patch.stopall)
        self.command = patch.object(b, 'command', side_effect=AssertionError('real command forbidden')).start()
        self.fetch = patch.object(b, 'open_zlib', side_effect=AssertionError('real network forbidden')).start()
        patch.object(b, 'cleanup_endpoint', return_value='unix:///run/docker.sock').start()

    def write_export(self, directory, files):
        directory.mkdir(parents=True)
        records = []
        for name, value in files.items():
            path = directory / name; path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, dict):
                b.save(path, value)
            else:
                path.write_bytes(value)
            records.append({'path': name, 'bytes': path.stat().st_size, 'sha256': b.digest(path)})
        b.save(directory / 'export-manifest.json', {'evidence_export': 'PASS', 'accepted': records, 'rejected': []})

    def ksm_inputs(self):
        recipe = self.root / 'packages/tools' / b.KSM
        shutil.copytree(self.real_root / 'packages/tools' / b.KSM, recipe)
        path = self.root / 'manifests/reviewed'; path.mkdir(parents=True)
        shutil.copyfile(self.real_root / 'manifests/reviewed/ksmctl.json', path / 'ksmctl.json')
        checks = self.root / 'scripts/checks'; checks.mkdir(parents=True)
        shutil.copyfile(self.real_root / 'scripts/checks/package_checks.py', checks / 'package_checks.py')
        ci = self.root / 'scripts/ci'; ci.mkdir()
        shutil.copyfile(self.real_root / 'scripts/ci/integration_export.py', ci / 'integration_export.py')
        self.recipe, self.reviewed = b.ksm_recipe(self.root)
        self.package = {'errors': [], 'elf': [], 'metadata': {'.PKGINFO': {'pkgname': [b.KSM], 'pkgver': ['0.1.0-1'],
            'arch': ['any'], 'license': ['GPL-2.0-or-later'], 'depend': ['python>=3.11']},
            '.BUILDINFO': {'pkgbuild_sha256sum': [self.reviewed['PKGBUILD']]}},
            'members': {name: {'type': '0', 'uid': 0, 'gid': 0, 'mode': 0o755 if name.startswith('usr/bin/') else 0o644,
                                'sha256': self.reviewed[source]} for name, source in b.PAYLOAD.items()}}
        self.package['members'].update({name: {'type': '0', 'uid': 0, 'gid': 0, 'mode': 0o644,
                                               'sha256': hashlib.sha256(b'pacman metadata fixture').hexdigest()}
                                        for name in b.PACMAN_METADATA})
        real_checker = b.checker(self.root)
        real_checker.package = Mock(side_effect=lambda _: copy.deepcopy(self.package))
        patch.object(b, 'checker', return_value=real_checker).start()
        self.calls = []
        self.compare = {'status': 'contents-reproduced', 'errors': [], 'packages': {b.KSM + '-0.1.0-1-any.pkg.tar.zst':
                         {name: True for name in ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal')}}}
        self.docker_calls = []
        def command(argv, log, timeout, **options):
            if argv[0] == 'docker':
                self.docker_calls.append(argv); Path(log).write_text(''); return 0
            self.calls.append((argv, timeout))
            if Path(argv[2]).name == 'compare.py':
                b.save(log, self.compare)
                return 0
            attempt = Path(argv[argv.index('--output') + 1]); self.attempt(attempt)
            Path(log).write_text('bounded driver output')
            return 0
        self.command.side_effect = command

    def attempt(self, path):
        path.mkdir(); artifacts = path / 'artifacts'; artifacts.mkdir()
        shutil.copytree(self.recipe, path / 'inputs')
        name = b.KSM + '-0.1.0-1-any.pkg.tar.zst'
        (artifacts / name).write_bytes(b'fixture; inspector mocked')
        for item in ('environment.txt', 'config.sha256', 'makepkg.conf', 'pacman.conf', 'generated.SRCINFO'):
            (artifacts / item).write_text('fixture')
        (artifacts / 'packages.lock').write_text(self.lock)
        (path / 'expected-packages.lock').write_text(self.lock)
        (path / 'build.log').write_text('safe build log')
        b.save(path / 'validation.json', {'errors': [], 'artifacts': [self.package]})
        files = {p.relative_to(path).as_posix(): b.digest(p) for p in path.rglob('*') if p.is_file()}
        name_container = 'cachy-asahi-' + f'{int(path.name[-1]):016x}'
        b.save(path / 'provenance.json', {'status': 'built-package-static-pass', 'mode': 'native',
            'image': self.controller.image, 'image_id': self.controller.image, 'source_date_epoch': b.EPOCH,
            'recipe_inputs': self.reviewed, 'expected_packages_sha256': b.digest(self.native / 'packages.lock'),
            'clean_environment_id': name_container,
            'command': b.build_container_command(self.root, path, self.controller.image, name_container),
            'artifacts': {name: b.digest(artifacts / name)}, 'files': files})

    def arm_inputs(self):
        experiment = self.root / 'scripts/experiments'; experiment.mkdir(parents=True)
        for name in (*b.ARM_FILES, 'stage.lock.json'):
            shutil.copyfile(self.real_root / 'scripts/experiments' / name, experiment / name)
        ci = self.root / 'scripts/ci'; ci.mkdir()
        shutil.copyfile(self.real_root / 'scripts/ci/integration_export.py', ci / 'integration_export.py')
        for path in (*experiment.iterdir(), ci / 'integration_export.py'):
            path.chmod(0o644)
        self.source = self.cache / 'zlib-1.3.2.tar.gz'; self.source.write_bytes(b'fixture; pin fixture patched')
        patch.object(b, 'fetch_zlib', return_value=self.source).start()
        self.calls = []
        def command(argv, log, timeout, **options):
            self.calls.append((argv, timeout)); Path(log).write_text('driver output')
            self.owner = Path(argv[argv.index('--output') + 1]); self.owner.mkdir()
            self.arm_receipts(self.owner)
            return 0
        self.command.side_effect = command

    def arm_receipts(self, owner):
        # Actual source producer/graph/exporter with synthetic binaries and source.
        # No native commands, network, host transaction or build is performed.
        fixture = b.load_module(self.real_root / 'scripts/experiments/test_arm_c01.py', 'development_arm_fixture')
        with patch.dict(sys.modules, {'arm_c01': fixture.a}):
            stage = b.load_module(self.real_root / 'scripts/experiments/stage.py', 'development_arm_stage_fixture')
        raw_root = owner / 'fixture'; raw_root.mkdir()
        with ExitStack() as stack:
            context = SimpleNamespace(root=raw_root, enterContext=stack.enter_context)
            raw, contract, native, _, commands = fixture.ReceiverTests.receipt(context)
            contract.update(image=self.controller.image, source_commit=self.controller.commit,
                            packages_sha256=b.digest(self.native / 'packages.lock'))
            (raw_root / 'inputs/packages.lock').write_text(self.lock)
            commands[0].update(log_sha256=hashlib.sha256(self.lock.encode()).hexdigest(), log_bytes=len(self.lock))
            (raw / commands[0]['log']).write_text(self.lock)
            fixture.a.save(raw / 'commands.json', commands)
            fixture.a.save(raw / 'result.json', native)
            verified = fixture.a.verify_result(raw, contract)
            manifest = stage.export_artifacts(raw, owner / 'public-artifacts', verified)
            # Only the archive/source constant is mocked by the fixture. Restore
            # the externally pinned source label for this mocked producer handoff.
            native['contract']['source_sha256'] = b.ZLIB_SHA
            manifest['source_sha256'] = b.ZLIB_SHA
            fixture.a.save(raw / 'result.json', native)
            fixture.a.save(raw_root / 'result.json', {'purpose': fixture.a.PURPOSE, 'status': 'PASS',
                'image': self.controller.image, 'contract': contract,
                'controller_group_cleanup': 'PASS', 'container_cleanup': 'PASS',
                'receiver_verification': {**verified['receiver_verification'], 'source_sha256': b.ZLIB_SHA},
                'hardware_validation': 'NOT RUN', 'performance_acceptance': 'NOT RUN', 'selected_for_release': False})
            (raw_root / '004-container.log').write_bytes(b'synthetic successful container log; no execution')
            selected = owner / 'selected'
            stage.project_evidence(raw_root, selected)
        patch.object(b, 'ARM_README_SHA', hashlib.sha256((raw / 'corpus/heldout-source.bin').read_bytes()).hexdigest()).start()
        patch.object(b, 'ARM_LICENSE_SHA', hashlib.sha256((raw / 'baseline-1/LICENSE.txt').read_bytes()).hexdigest()).start()
        self.assertTrue(b.text_public(self.real_root, selected, owner / 'public'))
        b.save(owner / 'public-artifacts/archive-manifest.json', manifest)
        result = {'purpose': 'ARM-C01-same-job-followup', 'status': 'PASS', 'source_commit': self.controller.commit,
            'source_lock_sha256': b.ARM_PIN, 'source_sha256': b.ZLIB_SHA, 'evidence_export': 'PASS', 'launcher_cleanup': 'PASS',
            'image_handoff': {'kind': 'accepted-base-image', 'image_id': self.controller.image, 'package_count': 341},
            'container_cleanup': {'status': 'PASS', 'absence_verified': True}, 'development_artifacts': manifest,
            'receiver_verification': {**verified['receiver_verification'], 'source_sha256': b.ZLIB_SHA}}
        b.save(owner / 'result.json', result)
        self.write_export(owner / 'public-status', {'result.json': result})

    def test_base_failure_refuses_both_stages_before_commands_or_fetch(self):
        b.save(self.native / 'result.json', {'native_build': 'NOT RUN'})
        for run in (lambda: b.run_ksm(self.controller, self.root, self.output),
                    lambda: b.run_arm(self.controller, self.root, self.output, self.cache)):
            result = run(); self.assertEqual(result['status'], 'FAIL'); self.assertFalse(self.output.exists())
        self.command.assert_not_called(); self.fetch.assert_not_called()

    def test_ksm_success_two_native_attempts_complete_metadata_and_separate_gpl_material(self):
        self.ksm_inputs()
        result = b.run_ksm(self.controller, self.root, self.output)
        self.assertEqual(result['status'], 'PASS'); self.assertEqual(len(self.calls), 3)
        self.assertEqual([row[1] for row in self.calls], [360, 360, 120])
        for argv, _ in self.calls[:2]:
            self.assertIn('--mode', argv); self.assertEqual(argv[argv.index('--image') + 1], self.controller.image)
            self.assertEqual(argv[argv.index('--timeout') + 1], '300')
            self.assertEqual(argv[argv.index('--network') + 1], 'none')
        self.assertEqual(len(list((self.output / 'public-material/source').iterdir())), 15)
        self.assertFalse(any(p.name.endswith('.zst') for p in (self.output / 'public').rglob('*')))
        self.assertEqual(self.controller.report['stages']['lifecycle']['status'], 'FAIL')

    def test_ksm_recipe_missing_extra_or_symlink_inputs_refuse_before_build(self):
        for drift in ('extra', 'missing', 'symlink'):
            with self.subTest(drift=drift):
                self.ksm_inputs()
                path = self.recipe / 'README.md'
                if drift == 'extra':
                    (self.recipe / 'unreviewed').write_text('extra')
                elif drift == 'missing':
                    path.unlink()
                else:
                    path.unlink(); path.symlink_to(self.native / 'result.json')
                self.assertEqual(b.run_ksm(self.controller, self.root, self.output)['status'], 'FAIL')
                self.assertEqual(self.calls, [])
                shutil.rmtree(self.root); self.root.mkdir(); shutil.rmtree(self.output)

    def test_ksm_each_comparison_boolean_is_required(self):
        self.ksm_inputs()
        for key in ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal'):
            with self.subTest(key=key):
                self.compare['packages'][b.KSM + '-0.1.0-1-any.pkg.tar.zst'][key] = False
                self.assertEqual(b.run_ksm(self.controller, self.root, self.output)['status'], 'FAIL')
                self.compare['packages'][b.KSM + '-0.1.0-1-any.pkg.tar.zst'][key] = True
                shutil.rmtree(self.output)

    def test_ksm_gpl_dependency_payload_owner_modes_and_no_hooks_are_checked(self):
        self.ksm_inputs()
        original = copy.deepcopy(self.package)
        changes = [lambda: self.package['metadata']['.PKGINFO'].update(license=['MIT']),
                   lambda: self.package['metadata']['.PKGINFO'].update(depend=['python']),
                   lambda: self.package['members']['usr/bin/' + b.KSM].update(uid=1000),
                   lambda: self.package['members']['usr/bin/' + b.KSM].update(mode=0o777),
                   lambda: self.package['members'].update({'.INSTALL': {'type': '0', 'uid': 0, 'gid': 0}})]
        for change in changes:
            self.package = copy.deepcopy(original); change()
            self.assertEqual(b.run_ksm(self.controller, self.root, self.output)['status'], 'FAIL')
            shutil.rmtree(self.output)

    def test_ksm_unknown_hidden_files_changelog_and_directories_never_reach_public_archive(self):
        self.ksm_inputs(); original = copy.deepcopy(self.package)
        for name, kind, mode in (('.gnupg/private', '0', 0o644), ('.newdotfoo', '0', 0o644),
                                 ('.Changelog', '0', 0o644), ('.gnupg', '5', 0o755),
                                 ('unexpected', '5', 0o755), ('usr', '5', 0o777)):
            self.package = copy.deepcopy(original)
            self.package['members'][name] = {'type': kind, 'uid': 0, 'gid': 0, 'mode': mode,
                                              'sha256': hashlib.sha256(b'credential fixture').hexdigest()}
            with self.subTest(name=name):
                result = b.run_ksm(self.controller, self.root, self.output)
                self.assertEqual(result['status'], 'FAIL')
                self.assertFalse(list((self.output / 'public-material').glob('attempt-*/*.pkg.tar.*')))
            shutil.rmtree(self.output)

    def test_ksm_recovery_reinspection_rejects_hidden_payload_and_keeps_safe_text(self):
        self.ksm_inputs(); b.run_ksm(self.controller, self.root, self.output)
        self.package['members']['.hidden-credential'] = {'type': '0', 'uid': 0, 'gid': 0, 'mode': 0o644,
                                                         'sha256': hashlib.sha256(b'credential fixture').hexdigest()}
        paths = b.recovery_public('ksm', self.output)
        self.assertNotIn(str(self.output / 'public-material'), paths)
        self.assertIn(str(self.output / 'public'), paths)
        self.assertIn(str(self.output / 'adapter-status'), paths)
        self.assertEqual(b.read_json(self.output / 'recovery-status/failure-retention.json')['failure_retention'], 'FAIL')

    def test_nonzero_commands_and_private_exceptions_are_fail_not_stale_pass(self):
        self.ksm_inputs(); self.command.return_value = 1; self.command.side_effect = None
        result = b.run_ksm(self.controller, self.root, self.output)
        self.assertEqual(result['status'], 'FAIL')
        shutil.rmtree(self.output)
        self.command.side_effect = ValueError('PRIVATE_FIXTURE')
        result = b.run_ksm(self.controller, self.root, self.output)
        self.assertEqual(result['status'], 'FAIL'); self.assertNotIn('PRIVATE_FIXTURE', json.dumps(result))

    def test_second_build_failure_retains_only_approved_first_archive_and_sources(self):
        self.ksm_inputs(); producer = self.command.side_effect
        def failed(argv, log, timeout, **options):
            if argv[0] == 'docker':
                return producer(argv, log, timeout, **options)
            if argv[argv.index('--output') + 1].endswith('attempt-2'):
                Path(log).write_text('second attempt failed'); return 1
            return producer(argv, log, timeout)
        self.command.side_effect = failed
        result = b.run_ksm(self.controller, self.root, self.output)
        self.assertEqual(result['status'], 'FAIL')
        manifest = b.read_json(self.output / 'public-material/manifest.json')
        self.assertEqual(set(manifest['artifacts']), {'1'})
        self.assertIn(str(self.output / 'public-material'), result['public'])
        self.assertEqual(len(manifest['reviewed_sources']), 15)

    def test_private_driver_log_refused_but_safe_failure_manifest_is_retained(self):
        self.ksm_inputs()
        def failed(argv, log, timeout):
            Path(log).write_text('password=PRIVATE_FIXTURE'); return 1
        self.command.side_effect = failed
        result = b.run_ksm(self.controller, self.root, self.output)
        self.assertEqual(result['status'], 'FAIL')
        public = self.output / 'public'
        self.assertIn(str(public), result['public'])
        self.assertEqual(b.read_json(public / 'export-manifest.json')['evidence_export'], 'FAIL')
        self.assertFalse((public / 'attempt-1-driver.log').exists())
        self.assertFalse(any(b'PRIVATE_FIXTURE' in p.read_bytes() for p in public.rglob('*') if p.is_file()))

    def test_arm_success_uses_explicit_base_mode_and_retains_only_owner_public_bundles(self):
        self.arm_inputs()
        result = b.run_arm(self.controller, self.root, self.output, self.cache)
        self.assertEqual(result['status'], 'PASS'); argv, timeout = self.calls[0]
        self.assertEqual(timeout, 1000); self.assertNotIn('--handoff-dir', argv)
        self.assertEqual(argv[argv.index('--base-packages') + 1], argv[argv.index('--expected-packages') + 1])
        self.assertEqual(result['execution'], 'base-only-correctness')
        self.assertEqual(set(result['public']), {str(self.owner / name) for name in ('public', 'public-status', 'public-artifacts')}
                         | {str(self.output / name) for name in ('public', 'adapter-status')})
        self.assertEqual(self.controller.report['stages']['lifecycle']['status'], 'FAIL')

    def test_arm_source_hash_and_mode_drift_refused_before_fetch_or_command(self):
        self.arm_inputs()
        for drift in ('mode', 'bytes'):
            path = self.root / 'scripts/experiments/stage.py'; saved = path.read_bytes()
            if drift == 'mode':
                path.chmod(0o755)
            else:
                path.write_bytes(saved + b'\n# drift\n')
            self.assertEqual(b.run_arm(self.controller, self.root, self.output, self.cache)['status'], 'FAIL')
            self.assertEqual(self.calls, [])
            path.write_bytes(saved); path.chmod(0o644); shutil.rmtree(self.output)

    def test_arm_failed_receipt_cleanup_receiver_or_manifest_never_pass(self):
        self.arm_inputs()
        producer = self.command.side_effect
        cases = [('status', 'FAIL'), ('launcher_cleanup', 'FAIL'), ('evidence_export', 'FAIL'),
                 ('container_cleanup', {'status': 'PASS', 'absence_verified': False}),
                 ('receiver_verification', {'status': 'PASS', 'cross_decode_count': 335})]
        for key, value in cases:
            def changed(argv, log, timeout):
                producer(argv, log, timeout)
                result = b.read_json(self.owner / 'result.json'); result[key] = value
                b.save(self.owner / 'result.json', result); return 0
            self.command.side_effect = changed
            self.assertEqual(b.run_arm(self.controller, self.root, self.output, self.cache)['status'], 'FAIL')
            shutil.rmtree(self.output)

    def test_arm_nonzero_launcher_cannot_accept_a_passing_owner_fixture(self):
        self.arm_inputs(); producer = self.command.side_effect
        self.command.side_effect = lambda *args: (producer(*args), 1)[1]
        self.assertEqual(b.run_arm(self.controller, self.root, self.output, self.cache)['status'], 'FAIL')

    def test_arm_archive_duplicate_and_wrong_mode_refused_with_updated_outer_hash(self):
        self.arm_inputs(); prerequisite = b.base_prerequisite(self.controller)
        for mutation in ('duplicate', 'mode'):
            owner = self.base / mutation; owner.mkdir(); self.arm_receipts(owner)
            archive = owner / 'public-artifacts/development-ARM-C01-outputs.tar.gz'
            with tarfile.open(archive, 'r:gz') as source:
                contents = [(member, source.extractfile(member).read()) for member in source]
            if mutation == 'duplicate':
                contents.append(contents[0])
            else:
                contents[0][0].mode = 0o777
            with tarfile.open(archive, 'w:gz') as target:
                for member, data in contents:
                    target.addfile(member, io.BytesIO(data))
            manifest = b.read_json(owner / 'public-artifacts/archive-manifest.json')
            manifest.update(bundle_sha256=b.digest(archive), bundle_bytes=archive.stat().st_size)
            b.save(owner / 'public-artifacts/archive-manifest.json', manifest)
            result = b.read_json(owner / 'result.json'); result['development_artifacts'] = manifest
            b.save(owner / 'result.json', result); shutil.rmtree(owner / 'public-status')
            self.write_export(owner / 'public-status', {'result.json': result})
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                b.verify_arm(owner, self.controller, prerequisite)

    def seal_arm(self, owner, result=None, manifest=None):
        """Reseal outer hashes so rejection must come from semantic verification."""
        if result is None:
            result = b.read_json(owner / 'result.json')
        if manifest is not None:
            b.save(owner / 'public-artifacts/archive-manifest.json', manifest)
            result['development_artifacts'] = manifest
        b.save(owner / 'result.json', result)
        shutil.rmtree(owner / 'public-status')
        self.write_export(owner / 'public-status', {'result.json': result})
        public = owner / 'public'
        projection = b.read_json(public / 'projection.json')
        projection['files'] = {name: b.digest(public / name) for name in projection['files'] if (public / name).exists()}
        b.save(public / 'projection.json', projection)
        files = {path.relative_to(public).as_posix(): path.read_bytes() for path in public.rglob('*')
                 if path.is_file() and path.name != 'export-manifest.json'}
        shutil.rmtree(public); self.write_export(public, files)

    def change_arm_archive(self, owner, name, value=None, mode=None, remove=False):
        archive = owner / 'public-artifacts/development-ARM-C01-outputs.tar.gz'
        with tarfile.open(archive, 'r:gz') as source:
            contents = [(member, source.extractfile(member).read()) for member in source]
        manifest = b.read_json(owner / 'public-artifacts/archive-manifest.json')
        changed = []
        for member, data in contents:
            if member.name == name:
                if remove:
                    manifest['files'].pop(name); continue
                if value is not None:
                    data = value; member.size = len(data)
                    manifest['files'][name] = hashlib.sha256(data).hexdigest()
                if mode is not None:
                    member.mode = mode
            changed.append((member, data))
        with tarfile.open(archive, 'w:gz') as target:
            for member, data in changed:
                target.addfile(member, io.BytesIO(data))
        manifest.update(bundle_sha256=b.digest(archive), bundle_bytes=archive.stat().st_size,
                        uncompressed_bytes=sum(len(data) for _, data in changed), member_count=len(changed))
        self.seal_arm(owner, manifest=manifest)

    def test_corrected_arm_archive_requires_all_79_members_and_505_commands(self):
        self.arm_inputs(); b.run_arm(self.controller, self.root, self.output, self.cache)
        result = b.read_json(self.owner / 'result.json')
        self.assertEqual(result['receiver_verification']['command_count'], 505)
        manifest = result['development_artifacts']
        self.assertEqual(manifest['member_count'], 79)
        self.assertEqual(len(manifest['strict_driver_evidence']['builds']), 4)
        self.assertEqual(len(manifest['strict_driver_evidence']['outputs']), 36)
        self.assertEqual(b.verify_arm(self.owner, self.controller, b.base_prerequisite(self.controller)), result)

    def test_arm_strict_members_cannot_be_omitted_substituted_or_made_nonexecutable(self):
        self.arm_inputs(); prerequisite = b.base_prerequisite(self.controller)
        cases = [('strict-gzip.c', b'changed C source', None, False),
                 ('baseline-1/strict-gzip', b'changed binary', None, False),
                 ('baseline-1/strict-gzip', None, 0o644, False),
                 ('baseline-1-strict-valid.bin', b'wrong decoded bytes', None, False),
                 ('baseline-1-reject-truncated-trailer-baseline-1.bin', None, None, True)]
        for number, (name, data, mode, remove) in enumerate(cases):
            owner = self.base / ('strict-member-' + str(number)); owner.mkdir(); self.arm_receipts(owner)
            self.change_arm_archive(owner, name, data, mode, remove)
            with self.subTest(name=name, mode=mode), self.assertRaises(ValueError):
                b.verify_arm(owner, self.controller, prerequisite)

    def test_arm_strict_compiler_elf_manifest_and_command_bindings_refuse_resealed_forgery(self):
        self.arm_inputs(); prerequisite = b.base_prerequisite(self.controller)
        for mutation in ('compiler-flag', 'declared-flags', 'effective-flags', 'elf', 'driver-source', 'output-input', 'output-exit', 'manifest-extra'):
            owner = self.base / mutation; owner.mkdir(); self.arm_receipts(owner)
            manifest = b.read_json(owner / 'public-artifacts/archive-manifest.json')
            driver = manifest['strict_driver_evidence']['builds'][0]
            output = manifest['strict_driver_evidence']['outputs'][0]
            if mutation == 'compiler-flag':
                driver['compile']['argv'].append('-O3')
            elif mutation == 'declared-flags':
                driver['cflags'] += ' -O3'
            elif mutation == 'effective-flags':
                driver['configured_flags']['CFLAGS'] += ' -O3'
            elif mutation == 'elf':
                driver['elf']['loads'][0]['alignment'] = 4096
            elif mutation == 'driver-source':
                driver['source_sha256'] = '0' * 64
            elif mutation == 'output-input':
                output['stdin']['sha256'] = '0' * 64
            elif mutation == 'output-exit':
                output['command']['exit_code'] = 3
            else:
                manifest['extra'] = 'unapproved'
            self.seal_arm(owner, manifest=manifest)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                b.verify_arm(owner, self.controller, prerequisite)

    def test_arm_resource_exit3_cannot_substitute_for_strict_corruption_exit2(self):
        self.arm_inputs(); prerequisite = b.base_prerequisite(self.controller)
        owner = self.base / 'api-error'; owner.mkdir(); self.arm_receipts(owner)
        commands = json.loads((owner / 'public/commands.json').read_text())
        row = next(row for row in commands if '-reject-' in row['name'])
        row.update(exit_code=3, allowed_exit_codes=[3])
        b.save(owner / 'public/commands.json', commands)
        native = b.read_json(owner / 'public/native-result.json')
        native['correctness'][0]['rejected_exit'] = 3
        b.save(owner / 'public/native-result.json', native)
        manifest = b.read_json(owner / 'public-artifacts/archive-manifest.json')
        manifest['strict_driver_evidence']['outputs'][0]['command']['exit_code'] = 3
        self.seal_arm(owner, manifest=manifest)
        with self.assertRaisesRegex(ValueError, 'arm-command-exit-failed'):
            b.verify_arm(owner, self.controller, prerequisite)

    def test_arm_changed_projected_command_log_or_dataflow_refused_after_rehash(self):
        self.arm_inputs(); prerequisite = b.base_prerequisite(self.controller)
        for mutation in ('log-bytes', 'stdin', 'command-order', 'command-flag', 'native-source', 'old-count', 'sample-promoted'):
            owner = self.base / ('graph-' + mutation); owner.mkdir(); self.arm_receipts(owner)
            commands = json.loads((owner / 'public/commands.json').read_text())
            native = b.read_json(owner / 'public/native-result.json')
            result = b.read_json(owner / 'result.json')
            if mutation == 'log-bytes':
                row = next(row for row in commands if row['name'].endswith('-strict-compile'))
                (owner / 'public' / row['log']).write_bytes(b'changed compile log')
            elif mutation == 'stdin':
                next(row for row in commands if '-reject-' in row['name'])['stdin']['sha256'] = '0' * 64
            elif mutation == 'command-order':
                commands[0], commands[1] = commands[1], commands[0]
            elif mutation == 'command-flag':
                next(row for row in commands if row['name'].endswith('-strict-compile'))['argv'].append('-O3')
            elif mutation == 'native-source':
                native['contract']['runner_sha256'] = '0' * 64
            elif mutation == 'old-count':
                result['receiver_verification']['command_count'] = 485
            else:
                native['sample_truncation'][0].update(status='PASS', rejection_acceptance='PASS')
            b.save(owner / 'public/commands.json', commands)
            b.save(owner / 'public/native-result.json', native)
            self.seal_arm(owner, result=result)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                b.verify_arm(owner, self.controller, prerequisite)

    def test_arm_source_derived_readme_and_license_pins_reject_resealed_substitution(self):
        self.arm_inputs(); prerequisite = b.base_prerequisite(self.controller)
        for name in ('corpus/heldout-source.bin', 'baseline-1/LICENSE.txt'):
            owner = self.base / ('source-pin-' + Path(name).name); owner.mkdir(); self.arm_receipts(owner)
            self.change_arm_archive(owner, name, b'substituted pinned source bytes')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'arm-source-(readme|license)-failed'):
                b.verify_arm(owner, self.controller, prerequisite)

    def test_arm_public_json_duplicates_nonfinite_and_overflow_refused(self):
        self.arm_inputs(); prerequisite = b.base_prerequisite(self.controller)
        for value in ('"status":"FAIL","status":"PASS"', '"unchecked":NaN', '"unchecked":1e400'):
            owner = self.base / ('json-' + str(len(list(self.base.iterdir())))); owner.mkdir(); self.arm_receipts(owner)
            path = owner / 'public/native-result.json'
            path.write_bytes(b'{' + value.encode() + b',' + path.read_bytes().lstrip()[1:])
            self.seal_arm(owner)
            with self.subTest(value=value), self.assertRaises(ValueError):
                b.verify_arm(owner, self.controller, prerequisite)

    def test_arm_complete_environment_and_global_archive_metadata_refused_when_forged(self):
        self.arm_inputs(); prerequisite = b.base_prerequisite(self.controller)
        for mutation in ('tool-missing', 'tool-path', 'empty-release', 'global-pax'):
            owner = self.base / ('environment-' + mutation); owner.mkdir(); self.arm_receipts(owner)
            manifest = b.read_json(owner / 'public-artifacts/archive-manifest.json')
            result = b.read_json(owner / 'result.json')
            if mutation == 'global-pax':
                archive = owner / 'public-artifacts/development-ARM-C01-outputs.tar.gz'
                with tarfile.open(archive, 'r:gz') as source:
                    contents = [(member, source.extractfile(member).read()) for member in source]
                with tarfile.open(archive, 'w:gz', pax_headers={'comment': 'unapproved global text'}) as target:
                    for member, data in contents:
                        target.addfile(member, io.BytesIO(data))
                manifest.update(bundle_sha256=b.digest(archive), bundle_bytes=archive.stat().st_size)
            else:
                path = owner / 'public/environment.json'; env = b.read_json(path)
                if mutation == 'tool-missing':
                    env['tool_files'].pop(next(iter(env['tool_files'])))
                elif mutation == 'tool-path':
                    next(iter(env['tool_files'].values()))['path'] = '/tmp/foreign-tool'
                else:
                    env['kernel']['release'] = ''
                b.save(path, env)
                native = b.read_json(owner / 'public/native-result.json')
                native['environment_sha256'] = b.digest(path)
                result['receiver_verification']['environment_sha256'] = b.digest(path)
                b.save(owner / 'public/native-result.json', native)
            self.seal_arm(owner, result=result, manifest=manifest)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                b.verify_arm(owner, self.controller, prerequisite)

    def test_arm_launcher_missing_failed_foreign_or_changed_contract_is_refused(self):
        self.arm_inputs(); prerequisite = b.base_prerequisite(self.controller)
        for mutation in ('missing', 'status', 'image', 'contract', 'cleanup'):
            owner = self.base / ('launcher-' + mutation); owner.mkdir(); self.arm_receipts(owner)
            path = owner / 'public/launcher-result.json'
            launcher = b.read_json(path)
            if mutation == 'missing':
                path.unlink()
            elif mutation == 'status':
                launcher['status'] = 'FAIL'
            elif mutation == 'image':
                launcher['image'] = 'sha256:' + 'f' * 64
            elif mutation == 'contract':
                launcher['contract']['source_commit'] = 'f' * 40
            else:
                launcher['controller_group_cleanup'] = 'FAIL'
            if mutation != 'missing':
                b.save(path, launcher)
            self.seal_arm(owner)
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, FileNotFoundError)):
                b.verify_arm(owner, self.controller, prerequisite)

    def test_arm_extra_self_manifested_log_or_configuration_drift_is_refused(self):
        self.arm_inputs(); prerequisite = b.base_prerequisite(self.controller)
        for mutation in ('extra-log', 'config'):
            owner = self.base / ('selector-' + mutation); owner.mkdir(); self.arm_receipts(owner)
            if mutation == 'extra-log':
                (owner / 'public/unrecorded.log').write_bytes(b'unapproved self manifested log')
            else:
                (owner / 'public/baseline-1/Makefile.txt').write_bytes(b'changed configuration')
            self.seal_arm(owner)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                b.verify_arm(owner, self.controller, prerequisite)

    def test_ksm_cancellation_retains_failed_status_and_bounded_diagnostics(self):
        self.ksm_inputs()
        def cancelled(argv, log, timeout, **options):
            Path(log).write_text('owner interrupted'); raise KeyboardInterrupt()
        self.command.side_effect = cancelled
        with self.assertRaises(KeyboardInterrupt):
            b.run_ksm(self.controller, self.root, self.output)
        result = b.read_json(self.output / 'result.json')
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(result['error_code'], 'ksm-cancelled')
        self.assertTrue((self.output / 'public/attempt-1-driver.log').exists())

    def test_cancelled_owner_still_retains_failure_and_propagates_for_initial_cleanup(self):
        self.arm_inputs()
        self.command.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            b.run_arm(self.controller, self.root, self.output, self.cache)
        result = b.read_json(self.output / 'result.json')
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(result['error_code'], 'arm-cancelled')

    def test_manifest_missing_extra_symlink_and_file_drift_are_refused(self):
        public = self.base / 'public'; self.write_export(public, {'receipt.json': {'status': 'PASS'}})
        b.verify_export(public)
        (public / 'extra.txt').write_text('unexpected')
        with self.assertRaises(ValueError):
            b.verify_export(public)
        (public / 'extra.txt').unlink(); (public / 'receipt.json').write_text('changed')
        with self.assertRaises(ValueError):
            b.verify_export(public)
        (public / 'receipt.json').unlink(); (public / 'receipt.json').symlink_to(self.native / 'result.json')
        with self.assertRaises(ValueError):
            b.verify_export(public)

    def cleanup_fixture(self, mutation=None, removal_reply=True, absent=True):
        self.ksm_inputs(); self.output.mkdir()
        attempt = self.output / 'attempt-1'; self.attempt(attempt)
        provenance = b.read_json(attempt / 'provenance.json')
        name = provenance['clean_environment_id']; identity = 'c' * 64
        mounts = [{'Type': 'bind', 'Destination': target, 'Source': str(source), 'RW': writable}
                  for target, source, writable in (('/inputs', attempt / 'inputs', False),
                      ('/out', attempt / 'artifacts', True),
                      ('/builder-entry.sh', self.root / 'scripts/build/container-entry.sh', False),
                      ('/expected-packages.lock', attempt / 'expected-packages.lock', False))]
        observed = {'id': identity, 'name': '/' + name, 'image': self.controller.image, 'mounts': mounts}
        if mutation:
            mutation(observed)
        calls, lists = [], []
        def query(argv, log, timeout, **options):
            self.assertEqual(argv[:3], ['docker', '--host', 'unix:///run/docker.sock'])
            self.assertEqual(options, {'cleanup_grace': 5}); self.assertLessEqual(timeout, 15)
            calls.append(argv)
            if argv[4] == 'ls':
                lists.append(argv)
                Path(log).write_text(identity if len(lists) == 1 or not absent else '')
            elif argv[4] == 'inspect':
                b.save(Path(log), observed)
            else:
                self.assertEqual(argv[4:], ['rm', '-f', identity])
                Path(log).write_text(identity if removal_reply else 'ambiguous')
            return 0
        self.command.side_effect = query
        return calls, provenance, query

    def test_cleanup_removes_only_bound_immutable_container_and_verifies_absence(self):
        calls, _, _ = self.cleanup_fixture()
        result = b.cleanup_ksm(self.root, self.output, self.controller.image)
        self.assertEqual(result['status'], 'PASS'); self.assertTrue(result['containers'][0]['absence_verified'])
        self.assertEqual([argv[4] for argv in calls], ['ls', 'inspect', 'rm', 'ls'])

    def test_cleanup_wrong_image_name_mount_or_duplicate_never_removes(self):
        for change in (lambda row: row.update(image='sha256:' + 'd' * 64),
                       lambda row: row.update(name='/foreign'),
                       lambda row: row['mounts'][0].update(Source='/home/foreign'),
                       lambda row: row['mounts'][0].update(RW=True),
                       lambda row: row['mounts'].append(row['mounts'][0])):
            calls, _, _ = self.cleanup_fixture(change)
            result = b.cleanup_ksm(self.root, self.output, self.controller.image)
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(any(argv[4] == 'rm' for argv in calls))
            shutil.rmtree(self.output); shutil.rmtree(self.root); self.root.mkdir()

    def test_cleanup_missing_provenance_and_foreign_record_cannot_authorize_removal(self):
        self.output.mkdir()
        result = b.cleanup_ksm(self.root, self.output, self.controller.image)
        self.assertEqual(result['status'], 'PASS'); self.command.assert_not_called()
        shutil.rmtree(self.output)
        calls, provenance, _ = self.cleanup_fixture()
        for field, value in (('clean_environment_id', 'cachy-asahi-foreign'), ('image_id', 'sha256:' + 'd' * 64),
                             ('command', ['docker', 'run', '--name', provenance['clean_environment_id']])):
            changed = {**provenance, field: value}
            b.save(self.output / 'attempt-1/provenance.json', changed)
            shutil.rmtree(self.output / 'cleanup', ignore_errors=True)
            self.assertEqual(b.cleanup_ksm(self.root, self.output, self.controller.image)['status'], 'FAIL')
            self.assertEqual(calls, [])

    def test_cleanup_ambiguous_removal_and_failed_absence_cannot_pass(self):
        for reply, absent in ((False, True), (True, False)):
            calls, _, _ = self.cleanup_fixture(removal_reply=reply, absent=absent)
            result = b.cleanup_ksm(self.root, self.output, self.controller.image)
            self.assertEqual(result['status'], 'FAIL')
            self.assertTrue(any(argv[4] == 'rm' for argv in calls))
            self.assertGreaterEqual(sum(argv[4] == 'ls' for argv in calls), 2)
            shutil.rmtree(self.output); shutil.rmtree(self.root); self.root.mkdir()

    def test_killed_parent_build_leak_is_checked_and_removed_before_cancel_propagates(self):
        calls, _, query = self.cleanup_fixture()
        shutil.rmtree(self.output)
        def command(argv, log, timeout, **options):
            if argv[0] == 'docker':
                return query(argv, log, timeout, **options)
            self.attempt(Path(argv[argv.index('--output') + 1])); Path(log).write_text('cancelled owner')
            raise KeyboardInterrupt()
        self.command.side_effect = command
        with self.assertRaises(KeyboardInterrupt):
            b.run_ksm(self.controller, self.root, self.output)
        result = b.read_json(self.output / 'result.json')
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(result['cleanup']['status'], 'PASS')
        self.assertTrue(any(argv[4] == 'rm' for argv in calls))
        self.assertTrue((self.output / 'public/cleanup-result.json').exists())

    def test_recovery_selector_ignores_private_trees_and_rechecks_fixed_bundles(self):
        self.ksm_inputs(); result = b.run_ksm(self.controller, self.root, self.output)
        private = self.output / 'scratch-private'; private.mkdir(); (private / 'key').write_text('PRIVATE_FIXTURE')
        self.assertEqual(set(b.recovery_public('ksm', self.output)), set(result['public']))
        (self.output / 'public-material/extra').write_text('unapproved')
        kept = b.recovery_public('ksm', self.output)
        self.assertIn(str(self.output / 'adapter-status'), kept); self.assertIn(str(self.output / 'public'), kept)
        self.assertNotIn(str(self.output / 'public-material'), kept)
        self.assertEqual(b.read_json(self.output / 'recovery-status/failure-retention.json')['failure_retention'], 'FAIL')

    def test_recovery_rejects_private_accepted_text_even_with_updated_self_hash(self):
        self.arm_inputs(); b.run_arm(self.controller, self.root, self.output, self.cache)
        path = self.owner / 'public/result.json'; path.write_text('password=PRIVATE_FIXTURE')
        manifest = b.read_json(self.owner / 'public/export-manifest.json')
        manifest['accepted'][0].update(bytes=path.stat().st_size, sha256=b.digest(path))
        b.save(self.owner / 'public/export-manifest.json', manifest)
        kept = b.recovery_public('arm-c01-base', self.output)
        self.assertNotIn(str(self.owner / 'public'), kept)
        self.assertIn(str(self.output / 'adapter-status'), kept)

    def test_recovery_policy_refuses_sensitive_components_and_binary_suffix_with_consistent_manifest(self):
        for name in ('nested.gnupg/public.json', 'safe.bin'):
            public = self.base / 'public'; self.write_export(public, {name: b'harmless utf8'})
            with self.subTest(name=name), self.assertRaises(ValueError):
                b.verify_export(public, allow_failure=True)
            shutil.rmtree(public)


    def test_parent_deadline_invalid_or_expired_refuses_before_output_and_actors(self):
        with patch.object(b.time, 'monotonic', return_value=100):
            for deadline in (True, float('nan'), float('inf'), '200', 100, 99):
                for owner in ('ksm', 'arm'):
                    with self.subTest(deadline=deadline, owner=owner):
                        result = b.run_ksm(self.controller, self.root, self.output, deadline=deadline) if owner == 'ksm' else \
                            b.run_arm(self.controller, self.root, self.output, self.cache, deadline=deadline)
                        self.assertEqual(result['status'], 'FAIL')
                        self.assertEqual(result['error_code'], 'stage-deadline-exceeded')
                        self.assertFalse(self.output.exists())
            self.command.assert_not_called(); self.fetch.assert_not_called()

    def test_both_owners_forward_exact_parent_deadline_without_renewal(self):
        self.ksm_inputs(); original = self.command.side_effect; observed = []
        def command(argv, log, timeout, **options):
            observed.append((timeout, options.copy()))
            return original(argv, log, timeout, **options)
        self.command.side_effect = command
        with patch.object(b.time, 'monotonic', return_value=100):
            result = b.run_ksm(self.controller, self.root, self.output, deadline=2000)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual([timeout for timeout, _ in observed[:3]], [360, 360, 120])
        self.assertTrue(all(options['deadline'] == 2000 for _, options in observed))
        shutil.rmtree(self.output); shutil.rmtree(self.root); self.root.mkdir()
        self.arm_inputs(); original = self.command.side_effect; observed.clear()
        def arm_command(argv, log, timeout, **options):
            observed.append((timeout, options.copy()))
            return original(argv, log, timeout, **options)
        self.command.side_effect = arm_command
        with patch.object(b.time, 'monotonic', return_value=100):
            result = b.run_arm(self.controller, self.root, self.output, self.cache, deadline=2000)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(observed, [(1000, {'deadline': 2000})])
        b.fetch_zlib.assert_called_once_with(self.cache, deadline=2000)

    def test_expiry_after_native_child_keeps_first_cause_and_stops_later_work(self):
        self.ksm_inputs(); original = self.command.side_effect; now = [100]
        def command(argv, log, timeout, **options):
            self.assertEqual(options['deadline'], 500)
            result = original(argv, log, timeout, **options)
            now[0] = 500
            return result
        self.command.side_effect = command
        with patch.object(b.time, 'monotonic', side_effect=lambda: now[0]):
            result = b.run_ksm(self.controller, self.root, self.output, deadline=500)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['error_code'], 'stage-deadline-exceeded')
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.docker_calls, [])
        self.assertEqual(result['cleanup']['status'], 'FAIL')

    def test_cleanup_publication_faults_preserve_original_business_failure(self):
        self.ksm_inputs(); self.command.side_effect = lambda *args, **kwargs: 1
        with patch.object(b, 'cleanup_ksm', side_effect=ValueError('cleanup fault')), \
             patch.object(b, 'text_public', side_effect=ValueError('publication fault')):
            result = b.run_ksm(self.controller, self.root, self.output)
        self.assertEqual(result['error_code'], 'ksm-stage-failed')
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['cleanup']['status'], 'FAIL')

    def test_cleanup_clips_local120_to_parent_and_attempts_second_owned_disposal(self):
        _, _, original = self.cleanup_fixture()
        self.attempt(self.output / 'attempt-2')
        now, observed = [100], []
        def command(argv, log, timeout, **options):
            self.assertEqual(options, {'cleanup_grace': 5, 'deadline': 130})
            self.assertLessEqual(timeout, 130 - now[0] - 15)
            observed.append((Path(log).name, timeout))
            now[0] += 1
            if Path(log).name.startswith('1-'):
                raise ValueError('first disposal fault')
            return original(argv, log, timeout, cleanup_grace=5)
        self.command.side_effect = command
        with patch.object(b.time, 'monotonic', side_effect=lambda: now[0]):
            result = b.cleanup_ksm(self.root, self.output, self.controller.image, deadline=130)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['containers'][0]['status'], 'FAIL')
        self.assertTrue(any(name.startswith('2-') for name, _ in observed))

    def test_hash_and_recovery_helpers_refuse_expiry_before_file_access(self):
        self.ksm_inputs()
        with patch.object(b.time, 'monotonic', return_value=100), \
             patch.object(b, 'digest', side_effect=AssertionError('hash after expiry')) as hashed:
            with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                b.ksm_recipe(self.root, deadline=100)
            with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                b.recovery_public('ksm', self.output, deadline=100)
            hashed.assert_not_called()

    def test_bounded_stream_checks_same_deadline_after_each_chunk(self):
        now = [100]
        source = Mock()
        def read(size):
            self.assertEqual(size, 65536)
            now[0] = 101
            return b'x' * size
        source.read.side_effect = read
        with patch.object(b.time, 'monotonic', side_effect=lambda: now[0]), \
             self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
            b.stream_bytes(source, 100000, deadline=101)
        source.read.assert_called_once()


    def test_deferred_restoration_attempts_all_handlers_pending_and_mask_keeps_first_cause(self):
        previous = {b.signal.SIGTERM: object(), b.signal.SIGINT: object()}
        for first in (KeyboardInterrupt('first control'), ValueError('first business')):
            calls = []
            def restore(sig, handler):
                calls.append((sig, handler))
                if handler is previous[b.signal.SIGTERM]: raise OSError('ordinary TERM restore fault')
            with patch.object(b.signal, 'getsignal', side_effect=lambda sig: previous[sig]), \
                 patch.object(b.signal, 'signal', side_effect=restore), \
                 patch.object(b.signal, 'pthread_sigmask', return_value=set()) as mask, \
                 patch.object(b.signal, 'sigpending', return_value={b.signal.SIGINT}), \
                 patch.object(b.signal, 'sigwait') as pending:
                try:
                    with b.defer_cleanup(): raise first
                except BaseException as error: self.assertIs(error, first)
                else: self.fail('first cause was lost')
                self.assertIn((b.signal.SIGINT, previous[b.signal.SIGINT]), calls)
                pending.assert_called_once_with({b.signal.SIGINT})
                self.assertEqual(mask.call_args.args, (b.signal.SIG_SETMASK, set()))

    def test_deferred_uncertainty_is_typed_and_owner_saved_pass_is_retracted(self):
        previous = {b.signal.SIGTERM: object(), b.signal.SIGINT: object()}
        def restore(sig, handler):
            if handler is previous[b.signal.SIGTERM]: raise OSError('TERM restore fault')
        self.ksm_inputs()
        with patch.object(b.signal, 'getsignal', side_effect=lambda sig: previous[sig]), \
             patch.object(b.signal, 'signal', side_effect=restore), \
             patch.object(b.signal, 'pthread_sigmask', return_value=set()), \
             patch.object(b.signal, 'sigpending', return_value=set()):
            with self.assertRaises(b.CleanupFailure):
                with b.defer_cleanup(): pass
            result = b.run_ksm(self.controller, self.root, self.output)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['error_code'], 'stage-cleanup-failed')
        self.assertEqual(result['cleanup']['status'], 'FAIL')
        self.assertEqual(b.read_json(self.output / 'result.json')['status'], 'FAIL')


    def test_owner_expiry_during_context_restoration_cannot_return_pass(self):
        self.ksm_inputs(); clock = [0]
        @contextmanager
        def restored(*args):
            yield []
            clock[0] = 1000
        with patch.object(b, 'defer_cleanup', restored), \
             patch.object(b.time, 'monotonic', side_effect=lambda: clock[0]):
            result = b.run_ksm(self.controller, self.root, self.output, deadline=1000)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['error_code'], 'stage-deadline-exceeded')


class SourceFetch(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name)
        self.data = b'pinned zlib fixture'
        self.addCleanup(patch.stopall)
        patch.object(b, 'ZLIB_SIZE', len(self.data)).start()
        patch.object(b, 'ZLIB_SHA', hashlib.sha256(self.data).hexdigest()).start()

    def response(self, data=None, url=None):
        source = io.BytesIO(self.data if data is None else data)
        source.status = 200; source.headers = {'Content-Length': str(len(self.data))}
        source.geturl = lambda: url or b.ZLIB_URL
        return source

    def test_exact_https_owned_download_and_verified_cache_reuse(self):
        with patch.object(b, 'open_zlib', return_value=self.response()) as fetch:
            path = b.fetch_zlib(self.cache)
        fetch.assert_called_once_with(b.ZLIB_URL, timeout=15)
        self.assertEqual(path.read_bytes(), self.data)
        cached = self.cache / 'zlib-1.3.2.tar.gz'; cached.write_bytes(self.data)
        with patch.object(b, 'open_zlib', side_effect=AssertionError('cache must be used')):
            self.assertEqual(b.fetch_zlib(self.cache), cached)

    def test_redirect_oversize_hash_drift_and_cancel_remove_only_owned_temporary(self):
        unrelated = self.cache / 'unrelated.partial'; unrelated.write_bytes(b'preserve')
        for response in (self.response(url='https://other.example/zlib.tar.gz'), self.response(self.data + b'x'),
                         self.response(b'x' * len(self.data))):
            with patch.object(b, 'open_zlib', return_value=response), self.assertRaises(ValueError):
                b.fetch_zlib(self.cache)
            self.assertEqual(list(self.cache.iterdir()), [unrelated])
        with patch.object(b, 'open_zlib', side_effect=KeyboardInterrupt()), self.assertRaises(KeyboardInterrupt):
            b.fetch_zlib(self.cache)
        self.assertEqual(list(self.cache.iterdir()), [unrelated])

    def test_symlink_cache_file_is_refused_before_network(self):
        path = self.cache / 'zlib-1.3.2.tar.gz'; path.symlink_to('/no-such-file')
        with patch.object(b, 'open_zlib') as fetch, self.assertRaises(ValueError):
            b.fetch_zlib(self.cache)
        fetch.assert_not_called()

    def test_redirect_handler_rejects_before_any_destination_request(self):
        with self.assertRaisesRegex(ValueError, 'redirect-refused'):
            b.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://localhost/private')


    def test_fetch_clips_open_and_socket_read_to_same_parent_deadline(self):
        now, source = [100], self.response()
        source.fp = SimpleNamespace(raw=SimpleNamespace(_sock=Mock()))
        original = source.read
        def read(size):
            data = original(size); now[0] = 101
            return data
        source.read1 = Mock(side_effect=read)
        with patch.object(b.time, 'monotonic', side_effect=lambda: now[0]), \
             patch.object(b, 'open_zlib', return_value=source) as opened, \
             self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
            b.fetch_zlib(self.cache, deadline=101)
        opened.assert_called_once_with(b.ZLIB_URL, timeout=1)
        source.fp.raw._sock.settimeout.assert_called_once_with(1)
        source.read1.assert_called_once()
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_cached_source_hash_receives_parent_deadline_without_network(self):
        cached = self.cache / 'zlib-1.3.2.tar.gz'; cached.write_bytes(self.data)
        with patch.object(b.time, 'monotonic', return_value=100), \
             patch.object(b, 'digest', wraps=b.digest) as hashed, \
             patch.object(b, 'open_zlib') as opened:
            self.assertEqual(b.fetch_zlib(self.cache, deadline=200), cached)
        hashed.assert_called_once_with(cached, deadline=200)
        opened.assert_not_called()


    def test_fetch_expiry_after_allocation_closes_actual_owned_raw_descriptor(self):
        now, captured = [0], []
        allocate = tempfile.mkstemp
        def allocated(*args, **kwargs):
            fd, name = allocate(*args, **kwargs)
            captured.append(fd); now[0] = 5
            return fd, name
        with patch.object(b.time, 'monotonic', side_effect=lambda: now[0]), \
             patch.object(b.tempfile, 'mkstemp', side_effect=allocated), \
             patch.object(b, 'open_zlib') as opened, \
             self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
            b.fetch_zlib(self.cache, deadline=5)
        with self.assertRaises(OSError): b.os.fstat(captured[0])
        self.assertEqual(list(self.cache.iterdir()), [])
        opened.assert_not_called()

    def test_fetch_raw_close_fault_still_unlinks_owned_partial_and_keeps_first_refusal(self):
        now, captured = [0], []
        allocate, close = tempfile.mkstemp, b.os.close
        def allocated(*args, **kwargs):
            fd, name = allocate(*args, **kwargs)
            captured.append(fd); now[0] = 5
            return fd, name
        try:
            with patch.object(b.time, 'monotonic', side_effect=lambda: now[0]), \
                 patch.object(b.tempfile, 'mkstemp', side_effect=allocated), \
                 patch.object(b.os, 'close', side_effect=OSError('ordinary close fault')) as closing, \
                 self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                b.fetch_zlib(self.cache, deadline=5)
            closing.assert_called_once_with(captured[0])
            self.assertEqual(list(self.cache.iterdir()), [])
        finally:
            for fd in captured: close(fd)

    def test_fetch_control_after_fdopen_transfer_closes_owner_once_without_raw_close(self):
        allocated, captured = tempfile.mkstemp, []
        fdopen, owners = b.os.fdopen, []
        mask, restores = b.signal.pthread_sigmask, [0]
        first = KeyboardInterrupt('first transfer control')
        def allocation(*args, **kwargs):
            fd, name = allocated(*args, **kwargs); captured.append(fd)
            return fd, name
        def restored(how, signals):
            value = mask(how, signals)
            if how == b.signal.SIG_SETMASK:
                restores[0] += 1
                if restores[0] == 2: raise first
            return value
        def transfer(fd, mode):
            stream = fdopen(fd, mode)
            def close():
                stream.close()
                raise OSError('ordinary owner close fault')
            owner = SimpleNamespace(close=Mock(side_effect=close)); owners.append(owner)
            return owner
        with patch.object(b.time, 'monotonic', return_value=0), \
             patch.object(b.tempfile, 'mkstemp', side_effect=allocation), \
             patch.object(b.signal, 'pthread_sigmask', side_effect=restored), \
             patch.object(b.os, 'fdopen', side_effect=transfer), \
             patch.object(b.os, 'close', wraps=b.os.close) as closing, \
             patch.object(b, 'open_zlib') as opened:
            try:
                b.fetch_zlib(self.cache, deadline=5)
            except KeyboardInterrupt as error: self.assertIs(error, first)
            else: self.fail('original control was lost')
            closing.assert_not_called()
            owners[0].close.assert_called_once()
        with self.assertRaises(OSError): b.os.fstat(captured[0])
        self.assertEqual(list(self.cache.iterdir()), [])
        opened.assert_not_called()


    def test_fetch_first_control_or_ordinary_survives_source_and_target_disposal_faults(self):
        fdopen = b.os.fdopen
        for deadline in (None, 5):
            for first in (KeyboardInterrupt('first control'), ValueError('first business')):
                owners = []
                source = self.response()
                source.fp = SimpleNamespace(raw=SimpleNamespace(_sock=Mock()))
                source.read = source.read1 = Mock(side_effect=first)
                source_close = source.close
                def close_source():
                    source_close(); raise OSError('source disposal fault')
                source.close = Mock(side_effect=close_source)
                def transfer(fd, mode):
                    stream = fdopen(fd, mode)
                    def close_target():
                        stream.close(); raise OSError('target disposal fault')
                    owner = SimpleNamespace(close=Mock(side_effect=close_target), write=stream.write)
                    owners.append(owner); return owner
                with patch.object(b.time, 'monotonic', return_value=0), \
                     patch.object(b.os, 'fdopen', side_effect=transfer), \
                     patch.object(b, 'open_zlib', return_value=source), \
                     patch.object(b.signal, 'setitimer'):
                    try: b.fetch_zlib(self.cache, deadline=deadline)
                    except BaseException as error: self.assertIs(error, first)
                    else: self.fail('first cause was lost')
                source.close.assert_called_once(); owners[0].close.assert_called_once()
                self.assertTrue(source.closed); self.assertEqual(list(self.cache.iterdir()), [])

    def test_fetch_healthy_body_with_source_close_uncertainty_is_typed_failure(self):
        source = self.response(); source_close = source.close
        first = OSError('source disposal uncertainty')
        def close_source():
            source_close(); raise first
        source.close = Mock(side_effect=close_source)
        with patch.object(b, 'open_zlib', return_value=source):
            with self.assertRaises(b.CleanupFailure) as caught:
                b.fetch_zlib(self.cache)
        self.assertIs(caught.exception.__cause__, first)
        self.assertIsNone(caught.exception.natural_returncode)
        source.close.assert_called_once(); self.assertEqual(list(self.cache.iterdir()), [])


    def test_fetch_clock_caps_existing90_parent_and_earlier_timer_without_renewal(self):
        now, handler = [100], Mock()
        with patch.object(b.time, 'monotonic', side_effect=lambda: now[0]), \
             patch.object(b.signal, 'getitimer', return_value=(8, 0)), \
             patch.object(b.signal, 'getsignal', return_value=handler), \
             patch.object(b.signal, 'signal') as signals, \
             patch.object(b.signal, 'setitimer') as timers:
            with b.zlib_clock(50, 130):
                self.assertEqual(timers.call_args.args, (b.signal.ITIMER_REAL, 8))
                now[0] = 103
            self.assertEqual(timers.call_args.args, (b.signal.ITIMER_REAL, 5, 0))
            self.assertEqual(signals.call_args.args, (b.signal.SIGALRM, handler))
        with patch.object(b.time, 'monotonic', return_value=100), \
             patch.object(b.signal, 'getitimer', return_value=(0, 0)), \
             patch.object(b.signal, 'getsignal', return_value=b.signal.SIG_DFL), \
             patch.object(b.signal, 'signal'), patch.object(b.signal, 'setitimer') as timers:
            with b.zlib_clock(50, 130):
                self.assertEqual(timers.call_args.args, (b.signal.ITIMER_REAL, 30))
            with b.zlib_clock(50, 200):
                self.assertEqual(timers.call_args.args, (b.signal.ITIMER_REAL, 40))

    def test_fetch_clock_bounds_blocked_open_and_preserves_body_error_on_restore_fault(self):
        now = [100]
        with patch.object(b.time, 'monotonic', side_effect=lambda: now[0]), \
             patch.object(b.signal, 'getitimer', return_value=(0, 0)), \
             patch.object(b.signal, 'getsignal', return_value=b.signal.SIG_DFL), \
             patch.object(b.signal, 'signal') as signals, \
             patch.object(b.signal, 'setitimer') as timers:
            with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                with b.zlib_clock(100, 101):
                    callback = signals.call_args.args[1]
                    now[0] = 101
                    callback(b.signal.SIGALRM, None)
            self.assertEqual(signals.call_args.args, (b.signal.SIGALRM, b.signal.SIG_DFL))
            now[0] = 100
            with self.assertRaisesRegex(ValueError, 'first business fault'):
                with b.zlib_clock(100, 101):
                    timers.side_effect = OSError('restore fault')
                    raise ValueError('first business fault')
        with patch.object(b.signal, 'pthread_sigmask', return_value={b.signal.SIGALRM}), \
             patch.object(b.time, 'monotonic', return_value=100), \
             self.assertRaisesRegex(ValueError, 'alarm-unavailable'):
            with b.zlib_clock(100, 101):
                self.fail('blocked alarm cannot authorize network')


if __name__ == '__main__':
    unittest.main()
