"""Development base-stage regressions: command/download/package execution mocked."""
import copy
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
        def command(argv, log, timeout):
            self.calls.append((argv, timeout)); Path(log).write_text('driver output')
            self.owner = Path(argv[argv.index('--output') + 1]); self.owner.mkdir()
            self.arm_receipts(self.owner)
            return 0
        self.command.side_effect = command

    def arm_receipts(self, owner):
        files = {f'{variant}-{attempt}/{name}': b'public fixture' for variant in ('baseline', 'lto') for attempt in (1, 2)
                 for name in ('libz.a', 'example', 'minigzip', 'Makefile.txt', 'zconf.h.txt', 'configure.log.txt', 'LICENSE.txt')}
        files.update({'corpus/' + name: b'public corpus' for name in ('empty.bin', 'onebyte.bin', 'repeated.txt', 'allbytes.bin',
             'incompressible.bin', 'heldout-source.bin', 'gzip-reference.gz', 'corrupt-crc.gz', 'truncated-trailer.gz', 'manifest.json')})
        artifacts = owner / 'public-artifacts'; artifacts.mkdir()
        archive = artifacts / 'development-ARM-C01-outputs.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name, data in files.items():
                member = tarfile.TarInfo(name); member.size = len(data)
                member.mode = 0o755 if name.endswith(('/example', '/minigzip')) else 0o644
                tar.addfile(member, io.BytesIO(data))
        manifest = {'image_id': self.controller.image, 'source_commit': self.controller.commit, 'source_sha256': b.ZLIB_SHA,
                    'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                    'uncompressed_bytes': sum(map(len, files.values())), 'bundle_sha256': b.digest(archive), 'bundle_bytes': archive.stat().st_size}
        b.save(artifacts / 'archive-manifest.json', manifest)
        result = {'purpose': 'ARM-C01-same-job-followup', 'status': 'PASS', 'source_commit': self.controller.commit,
            'source_lock_sha256': b.ARM_PIN, 'source_sha256': b.ZLIB_SHA, 'evidence_export': 'PASS', 'launcher_cleanup': 'PASS',
            'image_handoff': {'kind': 'accepted-base-image', 'image_id': self.controller.image, 'package_count': 341},
            'container_cleanup': {'status': 'PASS', 'absence_verified': True}, 'development_artifacts': manifest,
            'receiver_verification': {'status': 'PASS', 'command_count': 485, 'build_count': 4, 'cross_decode_count': 336,
                'rejection_count': 32, 'source_sha256': b.ZLIB_SHA, 'packages_sha256': b.digest(self.native / 'packages.lock')}}
        b.save(owner / 'result.json', result)
        self.write_export(owner / 'public', {'result.json': {'status': 'PASS'}})
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


if __name__ == '__main__':
    unittest.main()
