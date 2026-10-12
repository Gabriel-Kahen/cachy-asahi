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


if __name__ == '__main__':
    unittest.main()
