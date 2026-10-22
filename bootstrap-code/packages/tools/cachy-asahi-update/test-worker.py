#!/usr/bin/env python3
"""Pure guard and private Python subprocess fixtures; no Cargo/compiler calls."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import os
import stat
import subprocess
import time
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('worker', Path(__file__).with_name('worker-metadata.py'))
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def facts():
    return {'uid': 1001, 'arch': 'aarch64', 'marker': True,
            'caps': dict.fromkeys(('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd'), 0),
            'nnp': '1', 'interfaces': ['lo'], 'devices': False, 'socket': False,
            'image_id': 'sha256:' + 'a' * 64, 'nonce': 'b' * 32,
            'pids': '512', 'memory': str(4 * 1024**3), 'cpu': '400000 100000',
            'mounts': {'/': {'fs': 'overlay', 'flags': ['ro']},
                       '/inputs': {'fs': 'ext4', 'flags': ['ro']},
                       '/out': {'fs': 'ext4', 'flags': ['rw']},
                       '/tmp': {'fs': 'tmpfs', 'flags': ['rw']},
                       '/expected-packages.lock': {'fs': 'ext4', 'flags': ['ro']}}}


class WorkerTests(unittest.TestCase):
    def test_valid_bounded_worker_observation(self):
        worker.guard(facts())

    def test_host_privilege_network_and_identity_refusal(self):
        for key, value in [('uid', 0), ('arch', 'x86_64'), ('marker', False), ('nnp', '0'),
                           ('interfaces', ['lo', 'eth0']), ('devices', True), ('socket', True),
                           ('image_id', 'latest'), ('nonce', '')]:
            data = facts()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                worker.guard(data)
        for key in facts()['caps']:
            data = facts()
            data['caps'][key] = 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                worker.guard(data)

    def test_nested_and_runtime_host_mounts_refused(self):
        for point in ('/inputs/archive', '/out/receipt', '/tmp/source', '/run/user/1000', '/proc/self/status'):
            data = facts()
            data['mounts'][point] = {'fs': 'ext4', 'flags': ['ro']}
            with self.subTest(point=point), self.assertRaises(ValueError):
                worker.guard(data)

    def test_readwrite_root_unbounded_resources_and_fake_proc_refused(self):
        for key, value in [('pids', 'max'), ('memory', 'max'), ('cpu', 'max 100000')]:
            data = facts()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                worker.guard(data)
        data = facts()
        data['mounts']['/']['flags'] = ['rw']
        with self.assertRaises(ValueError):
            worker.guard(data)
        data = facts()
        data['mounts']['/proc'] = {'fs': 'ext4', 'flags': ['ro']}
        with self.assertRaises(ValueError):
            worker.guard(data)

    def test_standard_mask_is_observed_null_or_readonly(self):
        data = facts()
        data['mounts']['/proc/kcore'] = {'fs': 'tmpfs', 'flags': ['rw']}
        with self.assertRaises(ValueError):
            worker.guard(data)
        data['masked_null'] = {'/proc/kcore': True}
        worker.guard(data)

    def test_source_backed_default_mounts(self):
        data = facts()
        data['mounts']['/dev/mqueue'] = {'fs': 'mqueue', 'flags': ['rw', 'nosuid', 'noexec', 'nodev']}
        for point in ('/proc/timer_stats', '/proc/sched_debug'):
            data['mounts'][point] = {'fs': 'tmpfs', 'flags': ['rw', 'nosuid']}
        data['masked_null'] = dict.fromkeys(('/proc/timer_stats', '/proc/sched_debug'), True)
        for cpu in (0, 1, 8191):
            data['mounts'][f'/sys/devices/system/cpu/cpu{cpu}/thermal_throttle'] = {
                'fs': 'tmpfs', 'flags': ['ro']}
        worker.guard(data)

    def test_mqueue_wrong_filesystem_or_safety_flags_refused(self):
        flags = ['rw', 'nosuid', 'noexec', 'nodev']
        cases = [('tmpfs', flags), ('ext4', flags)]
        cases += [('mqueue', [f for f in flags if f != missing])
                  for missing in ('nosuid', 'noexec', 'nodev', 'rw')]
        cases += [('mqueue', flags + [unsafe]) for unsafe in ('suid', 'exec', 'dev', 'ro')]
        for fs, mount_flags in cases:
            data = facts()
            data['mounts']['/dev/mqueue'] = {'fs': fs, 'flags': mount_flags}
            with self.subTest(fs=fs, flags=mount_flags), self.assertRaisesRegex(ValueError, 'mqueue'):
                worker.guard(data)

    def test_new_file_masks_exact_null_or_readonly_tmpfs(self):
        for point in ('/proc/timer_stats', '/proc/sched_debug'):
            for flags, observed in [(['ro'], False), (['rw', 'nosuid'], True)]:
                data = facts()
                data['mounts'][point] = {'fs': 'tmpfs', 'flags': flags}
                data['masked_null'] = {point: observed}
                with self.subTest(point=point, flags=flags):
                    worker.guard(data)
            for fs, flags, observed in [('proc', ['ro'], False), ('ext4', ['ro'], True),
                    ('tmpfs', ['rw', 'nosuid'], False), ('tmpfs', ['rw', 'nosuid'], 1),
                    ('tmpfs', ['rw'], True), ('tmpfs', ['nosuid'], True),
                    ('tmpfs', ['rw', 'nosuid', 'suid'], True),
                    ('tmpfs', ['ro', 'rw', 'nosuid'], True)]:
                data = facts()
                data['mounts'][point] = {'fs': fs, 'flags': flags}
                data['masked_null'] = {point: observed}
                with self.subTest(point=point, fs=fs, flags=flags, observed=observed), \
                        self.assertRaisesRegex(ValueError, 'default file mask'):
                    worker.guard(data)

    def test_cpu_mask_has_no_null_bypass(self):
        point = '/sys/devices/system/cpu/cpu0/thermal_throttle'
        for fs, flags in [('sysfs', ['ro']), ('ext4', ['ro']), ('tmpfs', ['rw']),
                          ('tmpfs', ['rw', 'nosuid', 'noexec', 'nodev']), ('tmpfs', ['ro', 'rw'])]:
            data = facts()
            data['mounts'][point] = {'fs': fs, 'flags': flags}
            data['masked_null'] = {point: True}
            with self.subTest(fs=fs, flags=flags), self.assertRaisesRegex(ValueError, 'CPU thermal mask'):
                worker.guard(data)

    def test_cpu_mask_canonical_path_and_finite_cap(self):
        points = ['/sys/devices/system/cpu/cpu' + cpu + '/thermal_throttle'
                  for cpu in ('00', '01', '-1', '+1', '8192', '9999', '10000', '1.0', '１')]
        points += ['/sys/devices/system/cpu/cpu0//thermal_throttle',
                   '/sys/devices/system/cpu/cpu0/./thermal_throttle',
                   '/sys/devices/system/cpu/cpu0/thermal_throttle/',
                   '/sys/devices/system/cpu/cpu0/thermal_throttle/child',
                   '/sys/devices/system/cpu/cpu0', '/sys/devices/system/cpu/online']
        for point in points:
            data = facts()
            data['mounts'][point] = {'fs': 'tmpfs', 'flags': ['ro']}
            with self.subTest(point=point), self.assertRaisesRegex(ValueError, 'unexpected worker mount'):
                worker.guard(data)

    def test_default_mount_names_do_not_allow_nested_or_unknown_mounts(self):
        for point in ('/dev/mqueue/child', '/proc/timer_stats/child', '/proc/sched_debug/child',
                      '/sys/devices/system/cpu/cpu0/thermal_throttle/child', '/proc/arbitrary-mask'):
            data = facts()
            data['mounts'][point] = {'fs': 'tmpfs', 'flags': ['ro']}
            with self.subTest(point=point), self.assertRaisesRegex(ValueError, 'unexpected worker mount'):
                worker.guard(data)

    def test_default_mount_stacking_refused(self):
        for point in ('/dev/mqueue', '/proc/timer_stats', '/proc/sched_debug',
                      '/sys/devices/system/cpu/cpu0/thermal_throttle'):
            line = f'7 1 0:1 / {point} ro - tmpfs tmpfs ro\n'
            with self.subTest(point=point), self.assertRaisesRegex(ValueError, 'stacked mount'):
                worker.mount_table(line + line)

    def test_entry_mount_must_be_readonly(self):
        data = facts()
        data['mounts']['/builder-entry.sh'] = {'fs': 'ext4', 'flags': ['rw']}
        with self.assertRaisesRegex(ValueError, 'entry mount'):
            worker.guard(data)
        data['mounts']['/builder-entry.sh']['flags'] = ['ro']
        worker.guard(data)

    def test_exact_character_device_allowlist(self):
        for path, pair in worker.CHAR_DEVICES.items():
            self.assertFalse(worker.unsafe_device(path, stat.S_IFCHR, os.makedev(*pair)))
            self.assertTrue(worker.unsafe_device(path, stat.S_IFCHR, os.makedev(10, 1)))
        self.assertFalse(worker.unsafe_device('/dev/pts/0', stat.S_IFCHR, os.makedev(136, 0)))
        for path in ('/dev/ttyUSB0', '/dev/vfio/0', '/dev/console', '/dev/hidden'):
            self.assertTrue(worker.unsafe_device(path, stat.S_IFCHR, os.makedev(10, 1)))
        self.assertTrue(worker.unsafe_device('/dev/pts/0', stat.S_IFCHR, os.makedev(10, 1)))
        self.assertTrue(worker.unsafe_device('/dev/null', stat.S_IFBLK, os.makedev(1, 3)))

    def test_private_python_success_and_failure_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            data = worker.run([sys.executable, '-c', 'print("fixture")'], output, {}, output, 'good')
            self.assertEqual(data, b'fixture\n')
            with self.assertRaises(ValueError):
                worker.run([sys.executable, '-c', 'print("partial",flush=True);raise SystemExit(4)'], output, {}, output, 'bad')
            self.assertEqual((output / 'bad.stdout').read_bytes(), b'partial\n')
            self.assertEqual(json.loads((output / 'bad.command.json').read_text())['exit_code'], 4)

    def test_private_python_timeout_retains_partial_stdout(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            with self.assertRaisesRegex(ValueError, 'timeout'):
                worker.run([sys.executable, '-c', 'import time;print("partial",flush=True);time.sleep(2)'],
                           output, {}, output, 'timeout', timeout=.1)
            self.assertEqual((output / 'timeout.stdout').read_bytes(), b'partial\n')

    def test_cleanup_timeout_preserves_original_failure_and_receipt(self):
        child = mock.MagicMock()
        child.pid = 123456789
        child.stdout.fileno.return_value = 10
        child.stderr.fileno.return_value = 11
        child.returncode = None
        child.wait.side_effect = [subprocess.TimeoutExpired(['original'], 60),
                                  subprocess.TimeoutExpired(['cleanup'], 2)]
        selector = mock.MagicMock()
        selector.get_map.return_value = {}
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(worker.subprocess, 'Popen', return_value=child), \
                mock.patch.object(worker.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(worker.os, 'set_blocking'), mock.patch.object(worker.os, 'killpg'):
            output = Path(temp)
            with self.assertRaises(subprocess.TimeoutExpired) as error:
                worker.run(['fixture'], output, {}, output, 'cleanup')
            self.assertEqual(error.exception.cmd, ['original'])
            receipt = json.loads((output / 'cleanup.command.json').read_text())
            self.assertIn('original', receipt['failure'])
            self.assertIn('cleanup', receipt['cleanup_errors'][0])
            self.assertEqual((output / 'cleanup.stdout').read_bytes(), b'')
            selector.close.assert_called_once()

    def test_spawn_failure_also_records_evidence(self):
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(worker.subprocess, 'Popen', side_effect=OSError('fixture spawn')):
            output = Path(temp)
            with self.assertRaises(OSError):
                worker.run(['fixture'], output, {}, output, 'spawn')
            receipt = json.loads((output / 'spawn.command.json').read_text())
            self.assertIn('fixture spawn', receipt['failure'])
            self.assertIsNone(receipt['exit_code'])

    def test_output_limit_retains_only_bounded_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            with self.assertRaisesRegex(ValueError, 'output bound'):
                worker.run([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(b"x"*(17*1024*1024))'],
                           output, {}, output, 'large')
            self.assertEqual((output / 'large.stdout').stat().st_size, 16 * 1024 * 1024)
            self.assertIn('output bound', json.loads((output / 'large.command.json').read_text())['failure'])

    def test_timeout_stops_same_group_descendant(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            sentinel = output / 'descendant-action'
            child = 'import time;time.sleep(.4);open(' + repr(str(sentinel)) + ',"w").write("ran")'
            parent = 'import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",' + repr(child) + ']);time.sleep(2)'
            with self.assertRaisesRegex(ValueError, 'timeout'):
                worker.run([sys.executable, '-c', parent], output, {}, output, 'group', timeout=.1)
            time.sleep(.45)
            self.assertFalse(sentinel.exists())


def controller_fixture():
    blobs = {Path('/expected-packages.lock'): b'fixture inventory\n',
             Path('/builder-entry.sh'): b'fixture entry\n',
             Path('/inputs/recipe/PKGBUILD'): b'fixture recipe\n'}
    pins = {'schema_version': 1, 'builder_inventory_sha256': worker.digest(blobs[Path('/expected-packages.lock')]),
            'tools': {}}
    for tool in worker.TOOLS:
        resolved = '/usr/lib/fixture-' + tool
        blobs[Path(resolved)] = ('fixture tool ' + tool).encode()
        pins['tools']['/usr/bin/' + tool] = {'resolved_path': resolved,
                                          'sha256': worker.digest(blobs[Path(resolved)])}
    contract = {'schema_version': 1, 'image_id': facts()['image_id'], 'nonce': facts()['nonce'],
                'builder_inventory_sha256': pins['builder_inventory_sha256'], 'tool_pins': pins,
                'tool_pins_sha256': worker.digest(json.dumps(pins, sort_keys=True, separators=(',', ':')).encode()),
                'recipe_input_sha256': {'PKGBUILD': worker.digest(blobs[Path('/inputs/recipe/PKGBUILD')])},
                'entry_script_sha256': worker.digest(blobs[Path('/builder-entry.sh')])}
    return contract, blobs


class ControllerTests(unittest.TestCase):
    def verify(self, contract, blobs, expected=None, resolution=None):
        path = Path('/inputs/controller-input.json')
        data = json.dumps(contract).encode()
        blobs = dict(blobs, **{})
        blobs[path] = data
        def resolve(alias, strict=True):
            return Path(resolution or contract['tool_pins']['tools'][str(alias)]['resolved_path'])
        with mock.patch.object(worker, 'regular', side_effect=lambda path, limit, **kwargs: blobs[path]), \
                mock.patch.object(Path, 'resolve', resolve), \
                mock.patch.object(worker.subprocess, 'Popen') as execute:
            result = worker.verify_controller(path, expected or worker.digest(data), facts())
            execute.assert_not_called()
            return result

    def test_controller_validates_alias_target_and_returns_unchanged_dict(self):
        contract, blobs = controller_fixture()
        self.assertEqual(self.verify(contract, blobs), contract)

    def test_controller_external_digest_identity_and_tool_drift(self):
        contract, blobs = controller_fixture()
        with self.assertRaisesRegex(ValueError, 'controller digest'):
            self.verify(contract, blobs, expected='0' * 64)
        contract['nonce'] = '0' * 32
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.verify(contract, blobs)
        contract['nonce'] = facts()['nonce']
        with self.assertRaisesRegex(ValueError, 'resolution'):
            self.verify(contract, blobs, resolution='/usr/lib/unreviewed')
        blobs[Path('/usr/lib/fixture-cargo')] = b'changed cargo'
        with self.assertRaisesRegex(ValueError, 'content'):
            self.verify(contract, blobs)

    def test_controller_entry_recipe_and_inventory_drift(self):
        for path, message in ((Path('/builder-entry.sh'), 'entry script'),
                              (Path('/inputs/recipe/PKGBUILD'), 'recipe input'),
                              (Path('/expected-packages.lock'), 'builder lock')):
            contract, blobs = controller_fixture()
            blobs[path] = b'changed'
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, message):
                self.verify(contract, blobs)

    def test_controller_tool_ledger_hash_missing_tool_and_unsafe_recipe(self):
        contract, blobs = controller_fixture()
        contract['tool_pins_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'tool-pin'):
            self.verify(contract, blobs)
        contract, blobs = controller_fixture()
        del contract['tool_pins']['tools']['/usr/bin/bash']
        contract['tool_pins_sha256'] = worker.digest(json.dumps(contract['tool_pins'], sort_keys=True, separators=(',', ':')).encode())
        with self.assertRaisesRegex(ValueError, 'tool-pin'):
            self.verify(contract, blobs)
        contract, blobs = controller_fixture()
        contract['recipe_input_sha256'] = {'../outside': '0' * 64}
        with self.assertRaisesRegex(ValueError, 'recipe input'):
            self.verify(contract, blobs)


class VendorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vendor = self.root / 'vendor'
        self.vendor.mkdir()
        self.manifest = {'package': {'name': 'fixture', 'version': '0.1.0'}}
        self.lock = {'version': 4, 'package': [dict(self.manifest['package'])]}
        self.audit = {'registry_sources': [], 'locked_packages': 168, 'registry_packages': 167,
                      'failures': [], 'source_checksum_closure': 'PASS'}
        for i in range(167):
            name = 'fixture-' + str(i)
            data = ('[package]\nname="' + name + '"\nversion="1.0.0"\n').encode()
            files = {'Cargo.toml': worker.digest(data)}
            checksum = worker.digest(('archive' + str(i)).encode())
            directory = self.vendor / (name + '-1.0.0')
            directory.mkdir()
            (directory / 'Cargo.toml').write_bytes(data)
            (directory / '.cargo-checksum.json').write_text(json.dumps({'package': checksum, 'files': files}))
            self.lock['package'].append({'name': name, 'version': '1.0.0', 'source': worker.REGISTRY,
                                         'checksum': checksum})
            self.audit['registry_sources'].append({'name': name, 'version': '1.0.0',
                'registry': worker.REGISTRY, 'checksum': 'PASS', 'archive_sha256': checksum,
                'source_files_sha256': worker.digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()),
                'normalized_manifest_sha256': files['Cargo.toml']})

    def verify(self):
        return worker.vendor_preflight(self.vendor, self.audit, self.lock, self.manifest)

    def test_full_167_package_ledger(self):
        self.assertEqual(self.verify()['registry_packages'], 167)

    def test_altered_missing_extra_and_unsafe_sources(self):
        file = self.vendor / 'fixture-0-1.0.0/Cargo.toml'
        original = file.read_bytes()
        file.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'hash'):
            self.verify()
        file.unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.verify()
        file.write_bytes(original)
        extra = file.with_name('unreviewed.rs')
        extra.write_bytes(b'not allowed')
        with self.assertRaisesRegex(ValueError, 'extra'):
            self.verify()
        extra.unlink()
        file.unlink()
        file.symlink_to(self.root / 'outside')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.verify()

    def test_vendor_archive_ledger_and_extra_directory_drift(self):
        self.lock['package'][1]['checksum'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'archive'):
            self.verify()
        self.lock['package'][1]['checksum'] = self.audit['registry_sources'][0]['archive_sha256']
        (self.vendor / 'extra-package').mkdir()
        with self.assertRaisesRegex(ValueError, 'directory set'):
            self.verify()

    def test_data_pin_failure_precedes_tools_and_output(self):
        manifest = self.root / 'Cargo.toml'
        manifest.write_bytes(b'[package]\nname="fixture"\nversion="0.1.0"\n')
        manifest.with_name('Cargo.lock').write_bytes(b'version=4\n')
        audit = self.root / 'audit.json'
        audit.write_bytes(b'{}')
        with mock.patch.object(worker, 'observe', return_value=facts()), \
                mock.patch.object(worker, 'verify_controller', return_value={'builder_inventory_sha256': '0' * 64}), \
                mock.patch.object(worker, 'run') as run, mock.patch.object(Path, 'mkdir') as mkdir:
            with self.assertRaisesRegex(ValueError, 'source pin'):
                worker.metadata(manifest, self.vendor, audit, '0' * 64, Path('/out/target-metadata'),
                                Path('/inputs/controller-input.json'), '0' * 64)
            run.assert_not_called()
            mkdir.assert_not_called()

    def test_regular_rejects_links_and_allows_pinned_image_hardlink(self):
        original = self.root / 'input'
        original.write_bytes(b'fixture')
        alias = self.root / 'alias'
        alias.symlink_to(original)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            worker.regular(alias, 1024)
        alias.unlink()
        os.link(original, alias)
        with self.assertRaisesRegex(ValueError, 'singly-linked'):
            worker.regular(original, 1024)
        self.assertEqual(worker.regular(original, 1024, singly_linked=False), b'fixture')


class DiagnosticProbe:
    def __init__(self):
        self.first = None
        self.commands = []
        self.starts = []
        self.operation = None
        self.validated = False

    @worker.contextlib.contextmanager
    def step(self, operation):
        previous, self.operation = self.operation, operation
        try:
            yield
        except BaseException as error:
            self.fail('UNKNOWN', error)
            raise
        finally:
            self.operation = previous

    def fail(self, predicate, error):
        if self.first is None:
            self.first = (self.operation, predicate, error)

    def controller_validated(self):
        self.validated = True

    def command_start(self, stem):
        self.starts.append(stem)

    def command_result(self, stem, attempted, returned, returncode, failure_code=None, error=None):
        self.commands.append((stem, attempted, returned, returncode, failure_code))
        if failure_code:
            self.fail(failure_code, error)


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.recorder = DiagnosticProbe()
        worker.set_diagnostic(self.recorder)
        self.addCleanup(worker.set_diagnostic, None)

    def test_guard_issues_exact_predicate_before_unknown_context(self):
        bad = facts()
        bad['uid'] = 0
        with self.assertRaisesRegex(ValueError, 'host execution refused') as error:
            with worker.diagnostic_step('metadata-guard'):
                worker.guard(bad)
        self.assertEqual(self.recorder.first[:2], ('metadata-guard', 'worker-boundary'))
        self.assertIs(self.recorder.first[2], error.exception)
        self.assertFalse(self.recorder.starts)
        try:
            worker.refuse('later outer failure', 'command-cleanup')
        except ValueError:
            pass
        self.assertIs(self.recorder.first[2], error.exception)

    def test_controller_validation_is_after_existing_checks(self):
        contract, blobs = controller_fixture()
        test = ControllerTests()
        self.assertEqual(test.verify(contract, blobs), contract)
        self.assertTrue(self.recorder.validated)
        self.recorder.validated = False
        with self.assertRaisesRegex(ValueError, 'controller digest'):
            test.verify(contract, blobs, expected='0' * 64)
        self.assertFalse(self.recorder.validated)
        self.assertEqual(self.recorder.first[1], 'controller-digest')

    def test_regular_diagnostic_failure_never_masks_business(self):
        with mock.patch.object(self.recorder, 'fail', side_effect=RuntimeError('diagnostic unavailable')):
            with self.assertRaisesRegex(ValueError, 'fresh worker identity'):
                bad = facts()
                bad['nonce'] = ''
                worker.guard(bad)
        with mock.patch.object(self.recorder, 'step', side_effect=OSError('diagnostic unavailable')):
            with self.assertRaisesRegex(KeyError, 'business'):
                with worker.diagnostic_step('metadata-observe'):
                    raise KeyError('business')

    def test_diagnostic_control_interrupt_propagates(self):
        with mock.patch.object(self.recorder, 'command_start', side_effect=KeyboardInterrupt('signal')), \
                mock.patch.object(worker.subprocess, 'Popen') as spawn:
            with tempfile.TemporaryDirectory() as temp, self.assertRaises(KeyboardInterrupt):
                worker.run(['fixture'], Path(temp), {}, Path(temp), 'inventory')
            spawn.assert_not_called()
        self.assertEqual(self.recorder.commands[-1][1:4], (True, False, None))

    def test_real_local_return_and_nonzero_precede_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            self.assertEqual(worker.run([sys.executable, '-c', 'print("fixture")'], out, {}, out, 'inventory'), b'fixture\n')
            self.assertEqual(self.recorder.commands[-1], ('inventory', True, True, 0, None))
            with self.assertRaisesRegex(ValueError, 'worker command failed'):
                worker.run([sys.executable, '-c', 'raise SystemExit(4)'], out, {}, out, 'cargo-build')
            self.assertEqual(self.recorder.commands[-1], ('cargo-build', True, True, 4, 'command-nonzero'))
            self.assertEqual(self.recorder.first[1], 'command-nonzero')

    def test_real_local_timeout_never_counts_cleanup_reap_return(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            with self.assertRaisesRegex(ValueError, 'worker command timeout'):
                worker.run([sys.executable, '-c', 'import time;print("partial",flush=True);time.sleep(2)'],
                           out, {}, out, 'cargo-build', timeout=.05)
            self.assertEqual((out / 'cargo-build.stdout').read_bytes(), b'partial\n')
        self.assertEqual(self.recorder.commands[-1], ('cargo-build', True, False, None, 'command-timeout'))

    def test_spawn_failure_records_attempt_without_return(self):
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(worker.subprocess, 'Popen', side_effect=OSError('fixture spawn')):
            with self.assertRaises(OSError):
                worker.run(['fixture'], Path(temp), {}, Path(temp), 'inventory')
        self.assertEqual(self.recorder.starts, ['inventory'])
        self.assertEqual(self.recorder.commands[-1], ('inventory', True, False, None, 'command-spawn'))

    def test_original_wait_timeout_and_cleanup_failure_preserve_first(self):
        child = mock.MagicMock()
        child.pid = 123456789
        child.stdout.fileno.return_value = 10
        child.stderr.fileno.return_value = 11
        child.returncode = -9
        child.wait.side_effect = [subprocess.TimeoutExpired(['original'], 60),
                                  subprocess.TimeoutExpired(['cleanup'], 2)]
        selector = mock.MagicMock()
        selector.get_map.return_value = {}
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(worker.subprocess, 'Popen', return_value=child), \
                mock.patch.object(worker.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(worker.os, 'set_blocking'), mock.patch.object(worker.os, 'killpg'):
            with self.assertRaises(subprocess.TimeoutExpired) as error:
                worker.run(['fixture'], Path(temp), {}, Path(temp), 'cargo-build')
        self.assertEqual(error.exception.cmd, ['original'])
        self.assertEqual(self.recorder.commands[-1], ('cargo-build', True, False, None, 'command-wait-timeout'))
        self.assertIs(self.recorder.first[2], error.exception)

    def test_unknown_business_cancellation_preserves_first(self):
        with self.assertRaises(KeyboardInterrupt) as error:
            with worker.diagnostic_step('metadata-observe'):
                raise KeyboardInterrupt('fixture signal')
        self.assertEqual(self.recorder.first[:2], ('metadata-observe', 'UNKNOWN'))
        self.assertIs(self.recorder.first[2], error.exception)

    def test_source_pin_precedes_commands_and_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / 'Cargo.toml'
            manifest.write_text('[package]\nname="fixture"\nversion="0.1.0"\n')
            manifest.with_name('Cargo.lock').write_text('version=4\n')
            audit = root / 'audit.json'
            audit.write_text('{}')
            vendor = root / 'vendor'
            vendor.mkdir()
            with mock.patch.object(worker, 'observe', return_value=facts()), \
                    mock.patch.object(worker, 'verify_controller', return_value={'builder_inventory_sha256':'0'*64}), \
                    mock.patch.object(worker, 'run') as commands, mock.patch.object(Path, 'mkdir') as mkdir:
                with self.assertRaisesRegex(ValueError, 'source pin'):
                    worker.metadata(manifest, vendor, audit, '0'*64, Path('/out/target-metadata'),
                                    Path('/inputs/controller-input.json'), '0'*64)
                commands.assert_not_called()
                mkdir.assert_not_called()
        self.assertEqual(self.recorder.first[:2], ('metadata-source', 'source-pins'))


    def test_real_local_cancellation_never_counts_cleanup_return(self):
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(worker.selectors.DefaultSelector, 'select', side_effect=KeyboardInterrupt('signal')):
            out = Path(temp)
            with self.assertRaises(KeyboardInterrupt):
                worker.run([sys.executable, '-c', 'import time;time.sleep(2)'], out, {}, out, 'cargo-build')
        self.assertEqual(self.recorder.commands[-1], ('cargo-build', True, False, None, 'UNKNOWN'))
        self.assertIsInstance(self.recorder.first[2], KeyboardInterrupt)

    def test_real_local_output_limit_is_exact_and_retains_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            with self.assertRaisesRegex(ValueError, 'output bound'):
                worker.run([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(b"x"*(17*1024*1024))'],
                           out, {}, out, 'inventory')
            self.assertEqual((out / 'inventory.stdout').stat().st_size, 16*1024*1024)
        self.assertEqual(self.recorder.commands[-1], ('inventory', True, False, None, 'command-output-limit'))

    def test_real_local_success_followed_by_cleanup_error_is_not_unknown(self):
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(worker.os, 'killpg', side_effect=OSError('fixture cleanup')):
            out = Path(temp)
            with self.assertRaisesRegex(ValueError, 'worker command cleanup failed'):
                worker.run([sys.executable, '-c', 'pass'], out, {}, out, 'inventory')
        self.assertEqual(self.recorder.commands[-1], ('inventory', True, True, 0, 'command-cleanup'))

    def test_final_source_drift_is_reported_before_metadata_receipt(self):
        # Isolate the original final equality gate; controller/source/tool commands
        # are synthetic here. The separate source-pin test uses actual preflight.
        expected = b'fixture inventory\n'
        builder = worker.digest(expected)
        blobs = {'manifest':b'manifest', 'lock':b'lock', 'audit':b'audit'}
        changed = dict(blobs, manifest=b'changed')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, vendor = root/'Cargo.toml', root/'vendor'
            manifest.write_bytes(b'fixture')
            vendor.mkdir()
            with mock.patch.object(worker, 'observe', return_value=facts()), \
                    mock.patch.object(worker, 'verify_controller', return_value={'builder_inventory_sha256':builder}), \
                    mock.patch.object(worker, 'preflight', side_effect=[(blobs, {}), (changed, {})]), \
                    mock.patch.object(worker, 'regular', return_value=expected), \
                    mock.patch.object(worker, 'run', side_effect=[expected,
                        b'release: 1.92.0\nhost: aarch64-unknown-linux-gnu\n', b'cfg', b'{}']) as commands, \
                    mock.patch.object(Path, 'exists', return_value=False), \
                    mock.patch.object(Path, 'mkdir'), mock.patch.object(Path, 'write_text') as writes:
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    worker.metadata(manifest, vendor, root/'audit', builder, Path('/out/target-metadata'),
                                    Path('/inputs/controller-input.json'), '0'*64)
                self.assertEqual(commands.call_count, 4)
                self.assertEqual(writes.call_count, 1)  # Cargo config; worker receipt absent.
        self.assertEqual(self.recorder.first[:2], ('metadata-recheck', 'source-drift'))

    def test_real_vendor_hash_gate_issues_source_predicate(self):
        fixture = VendorTests()
        fixture.setUp()
        try:
            (fixture.vendor/'fixture-0-1.0.0/Cargo.toml').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'hash'):
                with worker.diagnostic_step('metadata-source'):
                    fixture.verify()
        finally:
            fixture.doCleanups()
        self.assertEqual(self.recorder.first[:2], ('metadata-source', 'vendor-file'))


    def test_ordinary_diagnostic_bridge_error_is_not_a_control_exception(self):
        actual_diagnose = worker.diagnose
        for code in (0,7):
            self.recorder = DiagnosticProbe()
            worker.set_diagnostic(self.recorder)
            def unavailable(method, *args, **kwargs):
                result = actual_diagnose(method, *args, **kwargs)
                if method == 'command_result': raise OSError('ordinary bridge unavailable')
                return result
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temp, \
                    mock.patch.object(worker, 'diagnose', side_effect=unavailable):
                out = Path(temp)
                with self.assertRaisesRegex(ValueError, 'worker command failed' if code else 'worker command cleanup failed'):
                    worker.run([sys.executable,'-c','raise SystemExit('+str(code)+')'],out,{},out,'cargo-build')
            self.assertEqual(self.recorder.first[1],'command-nonzero' if code else 'command-cleanup')
            self.assertIsInstance(self.recorder.first[2],ValueError)
            self.assertEqual(self.recorder.commands[-1][1:4],(True,True,code))


class ActualRecorderTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('actual_worker_diagnostic',
            Path(__file__).with_name('worker-diagnostic.py'))
        self.diagnostic = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.diagnostic)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.recorder = self.diagnostic.Recorder(self.root, bindings={
            'controller_sha256':'a'*64, 'image_id':'sha256:'+'b'*64, 'entry_script_sha256':'c'*64})
        worker.set_diagnostic(self.recorder)
        self.addCleanup(worker.set_diagnostic, None)

    def public_row(self):
        return self.diagnostic.loads((self.root/'worker-diagnostic.json').read_bytes())

    def failed_diagnostic(self):
        # Failure may invalidate durable evidence or recover a finite FAIL.
        row = self.public_row() if (self.root/'worker-diagnostic.json').exists() else self.recorder.snapshot()
        self.assertNotEqual(row['status'], 'PASS')
        self.assertTrue(row['diagnostic_write_failed'])
        self.assertEqual(row['first_failure'],self.recorder.snapshot()['first_failure'])
        return row

    def output(self):
        out = self.root/'target-metadata'
        out.mkdir(mode=0o700)
        return out

    def test_actual_premetadata_guard_records_source_predicate(self):
        bad = facts()
        bad['uid'] = 0
        with self.assertRaisesRegex(ValueError, 'host execution refused'):
            with worker.diagnostic_step('metadata-guard'):
                worker.guard(bad)
        row = self.public_row()
        self.assertEqual(row['first_failure']['predicate'], 'worker-boundary')
        self.assertEqual(row['first_failure']['operation'], 'metadata-guard')
        self.assertEqual(row['status'], 'FAIL')
        self.assertFalse(row['compiler_launch_attempted'])
        self.assertFalse(row['controller_validated'])
        self.assertNotIn('host execution refused', json.dumps(row))

    def test_default_mount_refusals_keep_source_issued_finite_predicate(self):
        cases = [('/dev/mqueue', 'tmpfs', ['rw', 'nosuid', 'noexec', 'nodev'], 'runtime-filesystem'),
                 ('/proc/timer_stats', 'tmpfs', ['rw', 'nosuid'], 'mask-readonly'),
                 ('/sys/devices/system/cpu/cpu0/thermal_throttle', 'tmpfs', ['rw'], 'mask-readonly')]
        for index, (point, fs, flags, predicate) in enumerate(cases):
            destination = self.root / str(index)
            destination.mkdir(mode=0o700)
            recorder = self.diagnostic.Recorder(destination, bindings=self.recorder.bindings)
            worker.set_diagnostic(recorder)
            bad = facts()
            bad['mounts'][point] = {'fs': fs, 'flags': flags}
            with self.subTest(point=point), self.assertRaises(ValueError):
                with worker.diagnostic_step('metadata-guard'):
                    worker.guard(bad)
            row = self.diagnostic.loads((destination/'worker-diagnostic.json').read_bytes())
            self.assertEqual(row['first_failure']['predicate'], predicate)
            self.assertEqual(row['first_failure']['operation'], 'metadata-guard')
            self.assertEqual(row['status'], 'FAIL')
            self.assertFalse(row['compiler_launch_attempted'])
            self.assertFalse(row['diagnostic_write_failed'])
            self.assertNotIn(point, json.dumps(row))
        worker.set_diagnostic(self.recorder)

    def test_actual_source_pin_failure_precedes_output_and_commands(self):
        manifest = self.root/'Cargo.toml'
        manifest.write_bytes(b'fixture manifest')
        manifest.with_name('Cargo.lock').write_bytes(b'fixture lock')
        audit = self.root/'audit.json'
        audit.write_bytes(b'{}')
        vendor = self.root/'vendor'
        vendor.mkdir()
        with mock.patch.object(worker, 'observe', return_value=facts()), \
                mock.patch.object(worker, 'verify_controller', return_value={'builder_inventory_sha256':'0'*64}), \
                mock.patch.object(worker, 'run') as commands, mock.patch.object(Path, 'mkdir') as mkdir:
            with self.assertRaisesRegex(ValueError, 'source pin'):
                worker.metadata(manifest, vendor, audit, '0'*64, Path('/out/target-metadata'),
                                Path('/inputs/controller-input.json'), '0'*64)
            commands.assert_not_called()
            mkdir.assert_not_called()
        row = self.public_row()
        self.assertEqual(row['first_failure']['predicate'], 'source-pins')
        self.assertEqual(row['first_failure']['operation'], 'metadata-source')
        self.assertFalse(row['compiler_launch_attempted'])

    def test_actual_harmless_child_natural_return_and_log_binding(self):
        out = self.output()
        with worker.diagnostic_step('compile-cargo'):
            data = worker.run([sys.executable, '-c', 'print("fixture")'], out, {}, out, 'cargo-build')
        row = self.public_row()
        self.assertTrue(row['compiler_launch_attempted'])
        self.assertTrue(row['compiler_return_observed'])
        self.assertEqual(row['compiler_returncode'], 0)
        self.assertFalse(row['compilation_accepted'])
        self.assertEqual(row['command']['stdout'], {'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()})
        self.assertIsNone(row['first_failure'])
        self.assertEqual(row['status'], 'RUNNING')  # Synthetic return is not compile proof.

    def test_actual_timeout_cleanup_reap_never_claims_compiler_return(self):
        out = self.output()
        with self.assertRaisesRegex(ValueError, 'worker command timeout'):
            with worker.diagnostic_step('compile-cargo'):
                worker.run([sys.executable, '-c', 'import time;print("partial",flush=True);time.sleep(2)'],
                           out, {}, out, 'cargo-build', timeout=.05)
        row = self.public_row()
        self.assertTrue(row['compiler_launch_attempted'])
        self.assertFalse(row['compiler_return_observed'])
        self.assertIsNone(row['compiler_returncode'])
        self.assertEqual(row['first_failure']['predicate'], 'command-timeout')
        self.assertFalse(row['first_failure']['command']['return_observed'])
        self.assertEqual(row['command']['stdout']['sha256'], hashlib.sha256(b'partial\n').hexdigest())

    def test_actual_ordinary_write_failure_keeps_first_cause_and_exception(self):
        with worker.diagnostic_step('metadata-source'):
            with self.assertRaisesRegex(ValueError, 'source first'):
                worker.refuse('source first', 'source-pins')
        first = self.public_row()['first_failure']
        with mock.patch.object(self.diagnostic.os, 'replace', side_effect=OSError('diagnostic write unavailable')):
            with self.assertRaisesRegex(ValueError, 'cleanup later'):
                worker.refuse('cleanup later', 'command-cleanup')
            self.assertEqual(self.recorder.snapshot()['first_failure'], first)
            self.assertTrue(self.recorder.snapshot()['diagnostic_write_failed'])
        self.recorder.finish(False)
        row = self.failed_diagnostic()
        self.assertEqual(row['first_failure'], first)
        self.assertTrue(row['diagnostic_write_failed'])
        self.assertEqual(row['status'], 'FAIL')

    def test_actual_log_hash_failure_keeps_original_nonzero_predicate(self):
        out = self.output()
        regular = self.diagnostic.regular
        def unreadable_log(path, limit):
            if Path(path).name == 'cargo-build.stderr':
                raise OSError('private diagnostic log unavailable')
            return regular(path, limit)
        with mock.patch.object(self.diagnostic, 'regular', side_effect=unreadable_log):
            with self.assertRaisesRegex(ValueError, 'worker command failed'):
                with worker.diagnostic_step('compile-cargo'):
                    worker.run([sys.executable, '-c', 'raise SystemExit(4)'], out, {}, out, 'cargo-build')
        row = self.failed_diagnostic()
        self.assertTrue(row['diagnostic_write_failed'])
        self.assertEqual(row['first_failure']['predicate'], 'command-nonzero')
        self.assertTrue(row['compiler_return_observed'])
        self.assertEqual(row['compiler_returncode'], 4)
        self.assertIsNone(row['first_failure']['command']['stdout'])
        first = row['first_failure']
        with self.assertRaisesRegex(ValueError, 'outer makepkg'):
            worker.refuse('outer makepkg', 'command-nonzero')
        self.assertEqual(self.failed_diagnostic()['first_failure'], first)


    def test_actual_uninstrumented_makepkg_result_is_unknown_with_exact_return(self):
        # These fixed stems still invoke harmless Python, never actual makepkg.
        for stem in ('makepkg', 'source-verification'):
            with self.subTest(stem=stem):
                out = self.root/stem
                out.mkdir(mode=0o700)
                recorder = self.diagnostic.Recorder(out, bindings=self.recorder.bindings)
                worker.set_diagnostic(recorder)
                with self.assertRaisesRegex(ValueError, 'worker command failed'):
                    with worker.diagnostic_step('entry-makepkg' if stem == 'makepkg' else 'entry-verifysource'):
                        worker.run([sys.executable, '-c', 'raise SystemExit(4)'], out, {}, out, stem)
                row = self.diagnostic.loads((out/'worker-diagnostic.json').read_bytes())
                self.assertEqual(row['first_failure']['predicate'], 'UNKNOWN')
                self.assertEqual(row['first_failure']['command']['kind'], stem)
                self.assertTrue(row['first_failure']['command']['launch_attempted'])
                self.assertTrue(row['first_failure']['command']['return_observed'])
                self.assertEqual(row['first_failure']['command']['returncode'], 4)
        worker.set_diagnostic(self.recorder)
        with self.assertRaisesRegex(ValueError, 'known nested source failure'):
            with worker.diagnostic_step('metadata-source'):
                worker.refuse('known nested source failure', 'source-pins')
        first = self.public_row()['first_failure']
        with self.assertRaisesRegex(ValueError, 'worker command failed'):
            with worker.diagnostic_step('entry-makepkg'):
                worker.run([sys.executable, '-c', 'raise SystemExit(4)'], self.root, {}, self.root, 'makepkg')
        row = self.public_row()
        self.assertEqual(row['first_failure'], first)
        self.assertEqual(row['command']['kind'], 'makepkg')
        self.assertTrue(row['command']['return_observed'])
        self.assertEqual(row['command']['returncode'], 4)


    def cleanup_control(self, point, code, control_type=KeyboardInterrupt, before_wait=False):
        out = self.root/('control-'+point+'-'+str(code)+'-'+control_type.__name__)
        out.mkdir(mode=0o700)
        (out/'target-metadata').mkdir(mode=0o700)
        recorder = self.diagnostic.Recorder(out, bindings=self.recorder.bindings)
        worker.set_diagnostic(recorder)
        interrupted = control_type('fixture cleanup control')
        fired, children = [], []
        actual_popen, actual_kill = worker.subprocess.Popen, worker.os.killpg
        actual_selector_close = worker.selectors.DefaultSelector.close
        actual_write_bytes, actual_write_text = Path.write_bytes, Path.write_text
        actual_log = self.diagnostic.regular
        def interrupt():
            if not fired:
                fired.append(point)
                raise interrupted
        class Stream:
            def __init__(self, pipe): self.pipe = pipe
            def fileno(self): return self.pipe.fileno()
            def close(self):
                self.pipe.close()
                if point == 'stream-close': interrupt()
        class Child:
            def __init__(self, child):
                self.child, self.waits = child, 0
                self.stdout, self.stderr = Stream(child.stdout), Stream(child.stderr)
            @property
            def pid(self): return self.child.pid
            @property
            def returncode(self): return self.child.returncode
            def wait(self, **kwargs):
                self.waits += 1
                if (before_wait and self.waits == 1) or (point == 'wait' and self.waits == 2): interrupt()
                return self.child.wait(**kwargs)
        def spawn(*args, **kwargs):
            child = Child(actual_popen(*args, **kwargs)); children.append(child); return child
        def kill(*args):
            if point == 'kill': interrupt()
            return actual_kill(*args)
        def selector_close(selector):
            actual_selector_close(selector)
            if point == 'selector': interrupt()
        def write_bytes(path, data):
            result = actual_write_bytes(path, data)
            if point == 'log-write' and path.name == 'cargo-build.stdout': interrupt()
            return result
        def write_text(path, data, **kwargs):
            result = actual_write_text(path, data, **kwargs)
            if point == 'receipt' and path.name == 'cargo-build.command.json': interrupt()
            return result
        def log(path, limit):
            if point == 'log-hash' and path.name == 'cargo-build.stderr': interrupt()
            return actual_log(path, limit)
        with mock.patch.object(worker.subprocess, 'Popen', side_effect=spawn), \
                mock.patch.object(worker.os, 'killpg', side_effect=kill), \
                mock.patch.object(worker.selectors.DefaultSelector, 'close', selector_close), \
                mock.patch.object(Path, 'write_bytes', write_bytes), mock.patch.object(Path, 'write_text', write_text), \
                mock.patch.object(self.diagnostic, 'regular', side_effect=log):
            with self.assertRaises(control_type) as caught:
                with worker.diagnostic_step('compile-cargo'):
                    worker.run([sys.executable, '-c', 'print("fixture",flush=True);raise SystemExit('+str(code)+')'],
                               out/'target-metadata', {}, out/'target-metadata', 'cargo-build')
        self.assertIs(caught.exception, interrupted)
        self.assertEqual(fired,[point])
        self.assertEqual(len(children),1)
        self.assertIsNotNone(children[0].child.returncode)
        self.assertTrue(children[0].child.stdout.closed)
        self.assertTrue(children[0].child.stderr.closed)
        row = self.diagnostic.loads((out/'worker-diagnostic.json').read_bytes())
        self.assertTrue(row['cancelled'])
        self.assertTrue(row['compiler_launch_attempted'])
        self.assertEqual(row['compiler_return_observed'],not before_wait)
        self.assertEqual(row['compiler_returncode'],None if before_wait else code)
        first = row['first_failure']
        self.assertEqual(first['predicate'],'command-nonzero' if code and not before_wait else 'UNKNOWN')
        self.assertEqual(first['error_kind'],'ValueError' if code and not before_wait else 'Cancelled')
        self.assertFalse(row['compilation_accepted'])
        self.assertNotIn('fixture cleanup control',json.dumps(row))
        return row

    def test_actual_cleanup_keyboardinterrupt_at_all_owned_points_keeps_natural_return(self):
        for point in ('kill','wait','selector','stream-close','log-write','receipt','log-hash'):
            for code in (0,7):
                with self.subTest(point=point,code=code):
                    self.cleanup_control(point,code)

    def test_actual_cleanup_systemexit_at_all_owned_points_keeps_natural_return(self):
        for point in ('kill','wait','selector','stream-close','log-write','receipt','log-hash'):
            with self.subTest(point=point):
                self.cleanup_control(point,7,SystemExit)

    def test_actual_interrupt_before_original_wait_never_invents_natural_return(self):
        for code in (0,7):
            with self.subTest(code=code):
                self.cleanup_control('before-wait',code,before_wait=True)


class RegularElfLeafTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'binary'; self.path.write_bytes(b'abcd')

    def refused(self, tag):
        with self.assertRaises(ValueError) as caught: worker.regular(self.path, 4, elf_observation=True)
        self.assertEqual(caught.exception.updater_elf_predicate, tag)
        return caught.exception

    def test_symlink_tag_only_in_explicit_elf_read(self):
        held = self.path.with_name('held'); self.path.rename(held); self.path.symlink_to(held)
        self.refused('elf-read-symlink')
        with self.assertRaises(ValueError) as caught: worker.regular(self.path, 4)
        self.assertFalse(hasattr(caught.exception, 'updater_elf_predicate'))

    def test_type_link_size_tag_preserves_original_checks(self):
        alias = self.path.with_name('alias'); os.link(self.path, alias)
        self.refused('elf-read-type-link-size')
        self.assertEqual(worker.regular(self.path, 4, singly_linked=False), b'abcd')
        alias.unlink(); self.path.write_bytes(b'oversized')
        self.refused('elf-read-type-link-size')
        self.path.unlink(); self.path.mkdir()
        self.refused('elf-read-type-link-size')

    def test_read_bound_tag_on_growth_after_initial_stat(self):
        read = worker.os.read; first = []
        def grow(fd, count):
            if not first: self.path.write_bytes(b'abcde'); first.append(True)
            return read(fd, count)
        with mock.patch.object(worker.os, 'read', side_effect=grow): self.refused('elf-read-bound')

    def test_read_drift_tag_after_same_length_read(self):
        read = worker.os.read; calls = []
        def drift(fd, count):
            calls.append(True)
            if len(calls) == 2:
                before = self.path.stat(); os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns + 1))
            return read(fd, count)
        with mock.patch.object(worker.os, 'read', side_effect=drift): self.refused('elf-read-drift')


if __name__ == '__main__':
    unittest.main()
