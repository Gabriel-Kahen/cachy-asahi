"""Guarded handoff tests; temporary filesystem/mocked commands only."""
import copy
import hashlib
import importlib.util
import json
import io
import os
from pathlib import Path
import tempfile
import signal
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('installed_handoff', Path(__file__).with_name('installed_handoff.py'))
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.system, self.inputs, self.runner, self.output = (self.root / p for p in ('system', 'inputs', 'runner', 'out'))
        for path in (self.system, self.inputs, self.runner, self.output):
            path.mkdir()
        for name in ('etc/pacman.d/gnupg/private-keys-v1.d', 'root/.gnupg', 'home/alarm/.config',
                     'home/fixture', 'tmp/fixture-keyring', 'var/cache/pacman/pkg', 'var/lib/gnupg',
                     'var/lib/pacman/local/libsecret-1-1', 'var/log'):
            (self.system / name).mkdir(parents=True, exist_ok=True)
        self.private = self.system / 'etc/pacman.d/gnupg/private-keys-v1.d/key'
        self.private.write_bytes(b'PRIVATE_PAYLOAD_NEVER_HASHED')
        for name in ('root/.gnupg/state', 'home/fixture/config.json', 'home/alarm/.config/state',
                     'tmp/fixture-keyring/key', 'var/cache/pacman/pkg/dependency.pkg.tar.xz', 'var/log/pacman.log'):
            (self.system / name).write_bytes(b'private or transaction residue')
        self.owner = {}
        self.alarm_uid = os.getuid() or 1000
        self.alarm_gid = os.getgid() or 1000
        self.patches = []
        for key, value in (('SYSTEM', self.system), ('INPUTS', self.inputs), ('RUNNER', self.runner), ('OUTPUT', self.output)):
            self.start(patch.object(handoff, key, value))
        self.start(patch.object(handoff.lifecycle, '__file__', str(self.runner / 'lifecycle.py')))
        self.probe = {'uid': 0, 'arch': 'aarch64', 'caps': handoff.lifecycle.SAFE_CAPS,
                      'privileges': {'NoNewPrivs': 1, **{name: handoff.lifecycle.SAFE_CAPS
                                     for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')}},
                      'device_exposure': False, 'docker_marker': True, 'interfaces': ['lo'], 'docker_socket': False,
                      'nonce': 'a' * 32, 'image_id': 'sha256:' + 'b' * 64,
                      'mounts': {'/': {'fs': 'overlay', 'options': ['rw']},
                                 '/inputs': {'fs': 'ext4', 'options': ['ro']},
                                 '/out': {'fs': 'ext4', 'options': ['rw']},
                                 '/runner': {'fs': 'ext4', 'options': ['ro']}}}
        secured = ['nosuid', 'nodev', 'noexec']
        self.probe['mounts'].update({
            '/proc': {'fs': 'proc', 'options': ['rw', *secured]},
            '/sys': {'fs': 'sysfs', 'options': ['ro', *secured]},
            '/sys/fs/cgroup': {'fs': 'cgroup2', 'options': ['ro', *secured]},
            '/dev': {'fs': 'tmpfs', 'options': ['rw', 'nosuid']},
            '/dev/pts': {'fs': 'devpts', 'options': ['rw', 'nosuid', 'noexec']},
            '/dev/shm': {'fs': 'tmpfs', 'options': ['rw', *secured]},
            '/dev/mqueue': {'fs': 'mqueue', 'options': ['rw', *secured]},
            **{name: {'fs': 'ext4', 'options': ['rw']} for name in
               ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf')},
            **{name: {'fs': 'proc', 'options': ['ro', *secured]} for name in handoff.lifecycle.PROC_READONLY},
            **{name: {'fs': 'tmpfs', 'options': ['rw', 'nosuid']} for name in handoff.lifecycle.NULL_MASKS},
            **{name: {'fs': 'tmpfs', 'options': ['ro']} for name in handoff.lifecycle.DIRECTORY_MASKS},
        })
        self.probe['mask_nodes'] = {
            **{name: {'symlink': False, 'kind': 'char', 'device': [1, 3]} for name in handoff.lifecycle.NULL_MASKS},
            **{name: {'symlink': False, 'kind': 'directory', 'device': None} for name in handoff.lifecycle.DIRECTORY_MASKS},
        }
        self.probe['privileges'].update(CapInh=0, CapAmb=0)
        self.start(patch.object(handoff.lifecycle, 'actual_environment', side_effect=lambda: copy.deepcopy(self.probe)))
        original_stat, original_lstat = Path.stat, Path.lstat

        def observed(original, path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path in self.owner:
                values = list(result); values[4], values[5] = self.owner[path]
                return os.stat_result(values)
            return result

        self.start(patch.object(Path, 'stat', lambda path, *a, **k: observed(original_stat, path, *a, **k)))
        self.start(patch.object(Path, 'lstat', lambda path, *a, **k: observed(original_lstat, path, *a, **k)))

        def chown(path, uid, gid):
            self.assertTrue(Path(path).is_relative_to(self.system))
            self.owner[Path(path)] = (uid, gid)

        self.start(patch.object(handoff.os, 'chown', side_effect=chown))
        self.start(patch.object(handoff.pwd, 'getpwnam', return_value=SimpleNamespace(
            pw_uid=self.alarm_uid, pw_gid=self.alarm_gid, pw_dir='/home/alarm')))
        self.commands = []
        self.command_envs = []
        self.start(patch.object(handoff.subprocess, 'run', side_effect=AssertionError('host command forbidden')))
        self.command_patch = self.start(patch.object(handoff.subprocess, 'Popen', side_effect=self.child))
        self.killpg = self.start(patch.object(handoff.os, 'killpg'))
        self.signal_handlers = {signal.SIGTERM: signal.SIG_DFL, signal.SIGINT: signal.default_int_handler}

        def change_signal(sig, handler):
            previous = self.signal_handlers[sig]
            self.signal_handlers[sig] = handler
            return previous

        self.start(patch.object(handoff.signal, 'signal', side_effect=change_signal))
        self.signal_mask = self.start(patch.object(handoff.signal, 'pthread_sigmask', return_value=set()))
        self.children = []
        self.child_failure = None
        self.wait_failures = []
        helper_data = b'original helper fixture'
        self.start(patch.object(handoff.lifecycle, 'BASELINE_HELPER_SHA256', hashlib.sha256(helper_data).hexdigest()))
        self.lifecycle = {'schema_version': 1, 'execution': 'native-aarch64-disposable-docker',
                          'allow_system_mutation': True, 'daemon_arch': 'aarch64',
                          'nonce': self.probe['nonce'], 'image_id': self.probe['image_id'],
                          'source_commit': 'c' * 40, 'signing_key_fingerprint': 'D' * 40,
                          'pacman_conf': 'pacman.conf', 'pacman_conf_sha256': 'e' * 64,
                          'public_cert': 'signing/test-key.asc', 'public_cert_sha256': 'f' * 64,
                          'baseline_handoff': True, 'baseline': [], 'upgrade': []}
        for name, component in handoff.lifecycle.PACKAGES.items():
            relative = handoff.lifecycle.PRIMARY_FILES[name]
            path = self.system / relative; path.parent.mkdir(parents=True, exist_ok=True)
            content = helper_data if component == 'setup' else ('original ' + component).encode()
            path.write_bytes(content); path.chmod(0o644); self.owner[path] = (0, 0)
            digest = hashlib.sha256(content).hexdigest()
            for stage, version, pin in (('baseline', '1-1', '1'), ('upgrade', '1-2', '2')):
                self.lifecycle[stage].append({'name': name, 'version': version, 'archive': stage + '/' + name + '.pkg.tar.gz',
                                             'sha256': pin * 64, 'signature_sha256': '3' * 64,
                                             'payload_sha256': {relative: digest if stage == 'baseline' else '4' * 64}})
        (self.runner / 'lifecycle.py').write_bytes(b'# pinned isolated lifecycle snapshot fixture\n')
        self.base = {'glibc': '2-1', 'pacman': '7-1'}
        (self.inputs / 'base-packages.lock').write_bytes(handoff.inventory_bytes(self.base))
        self.refresh()
        self.installed = {**self.base, **{row['name']: row['version'] for row in self.lifecycle['baseline']}}
        self.result_override = {}
        self.list_override = {}
        self.nonzero = False

    def start(self, patcher):
        value = patcher.start(); self.addCleanup(patcher.stop); return value

    def refresh(self):
        path = self.inputs / 'lifecycle.json'; path.write_text(json.dumps(self.lifecycle))
        self.commit = {'schema_version': 1, 'purpose': handoff.PURPOSE, 'source_commit': self.lifecycle['source_commit'],
                       'lifecycle_contract_sha256': handoff.lifecycle.sha(path),
                       'lifecycle_script_sha256': handoff.lifecycle.sha(self.runner / 'lifecycle.py'),
                       'base_packages_sha256': handoff.lifecycle.sha(self.inputs / 'base-packages.lock'),
                       'baseline': copy.deepcopy(self.lifecycle['baseline'])}
        self.commit_path = self.inputs / 'commit.json'; self.commit_path.write_text(json.dumps(self.commit))
        self.digest = handoff.lifecycle.sha(self.commit_path)

    def command(self, argv, **kwargs):
        self.commands.append(argv)
        self.command_envs.append(kwargs['env'])
        self.assertIn(argv[0], ('/usr/bin/python3', '/usr/bin/pacman'))
        if self.nonzero:
            return SimpleNamespace(returncode=1, stdout=b'', stderr=b'PRIVATE_FAILURE_NOT_EXPORTED')
        if argv[0] == '/usr/bin/python3':
            # Exercise the real child guard using identity from its actual
            # subprocess environment, rather than the parent's mocked probe.
            child_probe = copy.deepcopy(self.probe)
            child_probe.update(nonce=kwargs['env'].get('CACHY_ASAHI_DISPOSABLE_LIFECYCLE'),
                               image_id=kwargs['env'].get('CACHY_ASAHI_IMAGE_ID'))
            handoff.lifecycle.environment_guard(child_probe, self.lifecycle['nonce'], self.lifecycle['image_id'])
            self.assertIn('--baseline-handoff', argv)
            self.assertIn('--execute-disposable-container', argv)
            root = self.output / 'lifecycle'; root.mkdir()
            result = {'status': 'PASS', 'baseline_handoff_ready': True,
                      'source_commit': self.lifecycle['source_commit'], 'image_id': self.lifecycle['image_id'],
                      'contract_sha256': self.commit['lifecycle_contract_sha256'],
                      'handoff_package_versions': {r['name']: r['version'] for r in self.lifecycle['baseline']},
                      'handoff_payload_sha256': {r['name']: r['payload_sha256'] for r in self.lifecycle['baseline']}}
            result.update(self.result_override)
            (root / 'result.json').write_text(json.dumps(result))
            return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
        if argv[1] == '-Q':
            return SimpleNamespace(returncode=0, stdout=handoff.inventory_bytes(self.installed), stderr=b'')
        if argv[1] == '-Ql':
            row = next(r for r in self.lifecycle['baseline'] if r['name'] == argv[2])
            text = self.list_override.get(argv[2], ''.join(f"{row['name']} /{path}\n" for path in row['payload_sha256']))
            return SimpleNamespace(returncode=0, stdout=text.encode(), stderr=b'')
        self.assertEqual(argv[1], '-Qk')
        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

    def child(self, argv, **kwargs):
        self.assertTrue(kwargs['start_new_session'])
        self.assertTrue(callable(kwargs['preexec_fn']))
        owner = self

        class Child:
            pid = 12345
            returncode = None
            stdout = io.BytesIO()
            stderr = io.BytesIO()

            def communicate(self, timeout):
                owner.assertGreater(timeout, 0)
                if owner.child_failure is not None:
                    raise owner.child_failure
                result = owner.command(argv, **kwargs)
                self.returncode = result.returncode
                return result.stdout, result.stderr

            def wait(self, timeout):
                owner.assertEqual(timeout, 3)
                if owner.wait_failures:
                    raise owner.wait_failures.pop(0)
                self.returncode = -15
                return self.returncode

        result = Child()
        self.children.append(result)
        return result

    def run_handoff(self):
        return handoff.main(['--contract', str(self.commit_path), '--contract-sha256', self.digest])

    def receipt(self):
        return json.loads((self.output / 'commit-receipt.json').read_text())

    def test_ready_requires_exact_inventory_payloads_and_private_cleanup(self):
        self.assertEqual(self.run_handoff(), 0)
        result = self.receipt()
        self.assertEqual(result['status'], 'READY')
        self.assertEqual(result['installed_package_count'], 6)
        self.assertEqual(result['installed_packages_sha256'], handoff.lifecycle.sha(self.output / 'installed-packages.lock'))
        self.assertEqual(handoff.inventory((self.output / 'installed-packages.lock').read_text()), self.installed)
        self.assertFalse((self.system / 'etc/pacman.d/gnupg').exists())
        self.assertFalse(any((self.system / 'root').iterdir()))
        self.assertEqual(list((self.system / 'home').iterdir()), [self.system / 'home/alarm'])
        self.assertFalse(any((self.system / 'home/alarm').iterdir()))
        self.assertTrue((self.system / 'var/lib/pacman/local/libsecret-1-1').is_dir())
        self.assertNotIn('PRIVATE_PAYLOAD', json.dumps(result))

    def test_child_guard_receives_only_explicit_bound_environment(self):
        with patch.dict(os.environ, {'CACHY_ASAHI_DISPOSABLE_LIFECYCLE': 'f' * 32,
                                     'CACHY_ASAHI_IMAGE_ID': 'sha256:' + 'f' * 64,
                                     'UNRELATED_HOST_CREDENTIAL': 'must-not-inherit'}):
            self.assertEqual(self.run_handoff(), 0)
        expected = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LC_ALL': 'C',
                    'PYTHONDONTWRITEBYTECODE': '1',
                    'CACHY_ASAHI_DISPOSABLE_LIFECYCLE': self.lifecycle['nonce'],
                    'CACHY_ASAHI_IMAGE_ID': self.lifecycle['image_id']}
        self.assertTrue(self.command_envs)
        self.assertTrue(all(env == expected for env in self.command_envs))

    def test_child_guard_reproduces_missing_forwarded_identity_refusal(self):
        child_probe = copy.deepcopy(self.probe)
        child_probe.update(nonce=None, image_id=None)
        with self.assertRaises(handoff.lifecycle.Error):
            handoff.lifecycle.environment_guard(child_probe, self.lifecycle['nonce'], self.lifecycle['image_id'])

    def test_host_environment_spoof_refused_before_inputs_outputs_or_commands(self):
        self.probe.update(docker_marker=False, arch='x86_64')
        with patch.dict(os.environ, {'CACHY_ASAHI_DISPOSABLE_LIFECYCLE': 'a' * 32,
                                     'CACHY_ASAHI_IMAGE_ID': 'sha256:' + 'b' * 64}), \
                patch.object(handoff, 'load', side_effect=AssertionError('input parsing before guard')):
            self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.commands, [])
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertTrue(self.private.exists())

    def test_invalid_kernel_runtime_refused_before_commit_contract_read(self):
        original = copy.deepcopy(self.probe)
        for point, mutation in (('/proc', {'fs': 'ext4', 'options': ['rw']}),
                                ('/sys', {'fs': 'sysfs', 'options': ['rw', 'nosuid', 'nodev', 'noexec']}),
                                ('/dev', {'fs': 'tmpfs', 'options': ['rw']})):
            self.probe.clear(); self.probe.update(copy.deepcopy(original))
            self.probe['mounts'][point] = mutation
            with self.subTest(point=point), patch.object(handoff, 'load', side_effect=AssertionError('guard bypassed')):
                self.assertEqual(self.run_handoff(), 1)
            self.assertEqual(self.commands, [])
            self.assertEqual(list(self.output.iterdir()), [])
        self.probe.clear(); self.probe.update(original)

    def test_wrong_null_mask_identity_refused_before_commit_contract_read(self):
        point = next(iter(handoff.lifecycle.NULL_MASKS))
        self.probe['mask_nodes'][point]['device'] = [1, 5]
        with patch.object(handoff, 'load', side_effect=AssertionError('guard bypassed')):
            self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.commands, [])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_contract_hash_failure_precedes_all_output_and_cleanup_writes(self):
        self.digest = '0' * 64
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.commands, [])
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertTrue(self.private.exists())

    def test_lifecycle_script_and_base_inventory_drift_refused_before_execution(self):
        for path in (self.runner / 'lifecycle.py', self.inputs / 'base-packages.lock', self.inputs / 'lifecycle.json'):
            original = path.read_bytes(); path.write_bytes(b'changed')
            with self.subTest(path=path):
                self.assertEqual(self.run_handoff(), 1)
                self.assertEqual(self.commands, [])
                self.assertEqual(list(self.output.iterdir()), [])
            path.write_bytes(original)

    def test_baseline_and_source_cross_binding_required(self):
        self.commit['source_commit'] = 'f' * 40
        self.commit_path.write_text(json.dumps(self.commit)); self.digest = handoff.lifecycle.sha(self.commit_path)
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.commands, [])
        self.assertTrue(self.private.exists())

    def test_pass_without_handoff_or_exact_receipt_binding_is_failure(self):
        self.result_override['baseline_handoff_ready'] = False
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertTrue(self.private.exists())
        self.assertFalse((self.output / 'installed-packages.lock').exists())

    def test_inventory_surprise_package_refused_before_cleanup(self):
        self.installed['surprise'] = '1-1'
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertTrue(self.private.exists())

    def test_wrong_installed_version_refused(self):
        row = self.lifecycle['baseline'][0]
        self.installed[row['name']] = 'wrong-1'
        self.assertEqual(self.run_handoff(), 1)
        self.assertTrue(self.private.exists())

    def test_unowned_or_unreviewed_pacman_payload_refused(self):
        row = self.lifecycle['baseline'][0]
        self.list_override[row['name']] = f"{row['name']} /etc/unreviewed\n"
        self.assertEqual(self.run_handoff(), 1)
        self.assertTrue(self.private.exists())

    def test_changed_payload_refused_even_when_lifecycle_receipt_passes(self):
        row = self.lifecycle['baseline'][0]
        (self.system / next(iter(row['payload_sha256']))).write_bytes(b'changed')
        self.assertEqual(self.run_handoff(), 1)
        self.assertTrue(self.private.exists())

    def test_payload_symlink_refused_without_reading_target(self):
        row = self.lifecycle['baseline'][0]
        path = self.system / next(iter(row['payload_sha256']))
        path.unlink(); path.symlink_to(self.private)
        self.assertEqual(self.run_handoff(), 1)
        self.assertTrue(self.private.exists())

    def test_missing_owned_payload_refused(self):
        row = self.lifecycle['baseline'][0]
        self.list_override[row['name']] = ''
        self.assertEqual(self.run_handoff(), 1)
        self.assertTrue(self.private.exists())

    def test_nonroot_or_writable_payload_refused(self):
        row = self.lifecycle['baseline'][0]
        path = self.system / next(iter(row['payload_sha256']))
        self.owner[path] = (1000, 1000)
        self.assertEqual(self.run_handoff(), 1)
        self.assertTrue(self.private.exists())

    def test_symlink_directory_ancestor_refused(self):
        row = self.lifecycle['baseline'][0]
        path = self.system / next(iter(row['payload_sha256']))
        original = path.parent
        renamed = original.with_name('retained-original')
        original.rename(renamed)
        original.symlink_to(renamed, target_is_directory=True)
        self.assertEqual(self.run_handoff(), 1)
        self.assertTrue(self.private.exists())

    def test_lifecycle_handoff_payload_map_must_match_every_reviewed_hash(self):
        self.result_override['handoff_payload_sha256'] = {}
        self.assertEqual(self.run_handoff(), 1)
        self.assertTrue(self.private.exists())

    def test_unreviewed_pacman_owned_directory_refused(self):
        row = self.lifecycle['baseline'][0]
        self.list_override[row['name']] = (f"{row['name']} /etc/\n" +
                                          ''.join(f"{row['name']} /{p}\n" for p in row['payload_sha256']))
        self.assertEqual(self.run_handoff(), 1)
        self.assertTrue(self.private.exists())

    def test_cleanup_symlinks_unlinked_without_touching_outside_state(self):
        outside = self.root / 'outside'; outside.mkdir()
        marker = outside / 'secret'; marker.write_bytes(b'keep')
        (self.system / 'root/escape').symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.run_handoff(), 0)
        self.assertEqual(marker.read_bytes(), b'keep')

    def test_bad_cleanup_root_cannot_produce_ready(self):
        directory = self.system / 'root'
        # Replace private root with a symlink; never follow or clear its target.
        import shutil
        shutil.rmtree(directory)
        outside = self.root / 'outside'; outside.mkdir()
        marker = outside / 'preserved'; marker.write_bytes(b'keep')
        directory.symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertEqual(marker.read_bytes(), b'keep')

    def test_guard_rechecked_before_commands_and_cleanup(self):
        runner = handoff.Handoff(self.commit_path, self.digest)
        self.probe['interfaces'] = ['eth0', 'lo']
        self.assertEqual(runner.execute(), 1)
        self.assertEqual(self.commands, [])
        self.assertTrue(self.private.exists())

    def test_command_failure_retains_public_failure_receipt_without_private_stderr(self):
        self.nonzero = True
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertNotIn('PRIVATE_FAILURE', (self.output / 'commit-receipt.json').read_text())
        self.assertTrue(self.private.exists())

    def test_existing_ready_receipt_never_reused(self):
        (self.output / 'commit-receipt.json').write_text('{"status":"READY"}')
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.commands, [])
        self.assertTrue(self.private.exists())

    def test_duplicate_json_and_inventory_entries_refused(self):
        self.commit_path.write_text('{"schema_version":1,"schema_version":1}')
        self.digest = handoff.lifecycle.sha(self.commit_path)
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.commands, [])
        with self.assertRaises(handoff.lifecycle.Error):
            handoff.inventory('pacman 7-1\npacman 7-1\n')

    def test_tmpfs_view_refused_before_any_input_parsing_or_output(self):
        self.probe['mounts']['/tmp'] = {'fs': 'tmpfs', 'options': ['rw']}
        with patch.object(handoff, 'load', side_effect=AssertionError('parsed masked image input')):
            self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.children, [])
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertTrue(self.private.exists())

    def test_tmp_mount_added_after_preflight_refused_before_cleanup_or_ready(self):
        runner = handoff.Handoff(self.commit_path, self.digest)
        self.probe['mounts']['/tmp'] = {'fs': 'tmpfs', 'options': ['rw']}
        self.assertEqual(runner.execute(), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertTrue(self.private.exists())
        self.assertEqual(self.children, [])

    def test_underlying_image_tmp_residue_removed_before_ready(self):
        (self.system / 'tmp/disabled-hooks.txt').write_text('base-layer hook inventory')
        self.assertEqual(self.run_handoff(), 0)
        self.assertFalse(any((self.system / 'tmp').iterdir()))
        self.assertIn({'check': 'image-tmp-view-empty', 'status': 'PASS'}, self.receipt()['checks'])

    def test_keyboard_interrupt_terminates_group_and_finalizes_fail_receipt(self):
        self.child_failure = KeyboardInterrupt()
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertEqual(self.receipt()['child_group_cleanup']['status'], 'PASS')
        self.assertEqual([call.args for call in self.killpg.call_args_list],
                         [(12345, signal.SIGTERM), (12345, signal.SIGKILL)])
        self.assertTrue(self.private.exists())
        self.assertEqual(self.signal_handlers[signal.SIGTERM], signal.SIG_DFL)
        self.assertEqual(self.signal_handlers[signal.SIGINT], signal.default_int_handler)

    def test_sigterm_handler_stops_child_and_records_cancelled_fail(self):
        original_child = self.child

        def cancelling(argv, **kwargs):
            child = original_child(argv, **kwargs)

            def communicate(timeout):
                self.signal_handlers[signal.SIGTERM](signal.SIGTERM, None)

            child.communicate = communicate
            return child

        self.command_patch.side_effect = cancelling
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertTrue(self.receipt()['cancelled'])
        self.assertTrue(self.private.exists())
        self.assertEqual(self.killpg.call_count, 2)

    def test_timeout_escalates_to_kill_with_bounded_waits(self):
        self.child_failure = subprocess.TimeoutExpired('mock lifecycle', 1800)
        self.wait_failures = [subprocess.TimeoutExpired('mock child', 3)]
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertEqual(self.receipt()['child_group_cleanup']['signals'], ['SIGTERM', 'SIGKILL'])

    def test_cleanup_failure_cannot_suppress_final_failure_receipt(self):
        self.child_failure = KeyboardInterrupt()
        self.killpg.side_effect = PermissionError('mock group permission')
        self.wait_failures = [subprocess.TimeoutExpired('mock child', 3), subprocess.TimeoutExpired('mock child', 3)]
        self.assertEqual(self.run_handoff(), 1)
        result = self.receipt()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['child_group_cleanup']['status'], 'FAIL')
        self.assertNotIn('mock group permission', json.dumps(result))

    def test_repeat_interrupt_during_child_wait_still_finalizes_fail(self):
        self.child_failure = KeyboardInterrupt()
        self.wait_failures = [KeyboardInterrupt(), KeyboardInterrupt()]
        self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertEqual(self.receipt()['child_group_cleanup']['status'], 'FAIL')

    def test_creation_mask_restored_before_communicate_and_child_mask_restored(self):
        original_child = self.child

        def inspect_creation(argv, **kwargs):
            self.assertEqual(self.signal_mask.call_args.args,
                             (signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}))
            kwargs['preexec_fn']()
            self.assertEqual(self.signal_mask.call_args.args, (signal.SIG_SETMASK, set()))
            return original_child(argv, **kwargs)

        self.command_patch.side_effect = inspect_creation
        self.assertEqual(self.run_handoff(), 0)
        self.assertEqual(self.signal_mask.call_args.args, (signal.SIG_SETMASK, set()))

    def test_sigterm_during_filesystem_cleanup_never_leaves_ready_receipt(self):
        def interrupt(_relative):
            self.signal_handlers[signal.SIGTERM](signal.SIGTERM, None)

        with patch.object(handoff.Handoff, 'empty', side_effect=interrupt):
            self.assertEqual(self.run_handoff(), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertTrue(self.receipt()['cancelled'])
        self.assertFalse((self.output / 'installed-packages.lock').exists())
        self.assertEqual(self.signal_handlers[signal.SIGTERM], signal.SIG_DFL)


if __name__ == '__main__':
    unittest.main()
