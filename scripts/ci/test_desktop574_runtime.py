#!/usr/bin/env python3
"""Focused data/launch checks; no network, Docker, package or guest execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location('runtime', Path(__file__).with_name('desktop574_runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class RuntimeTests(unittest.TestCase):
    def test_inventory_rejects_duplicate_and_malformed_rows(self):
        for text in ('', 'a 1\na 2\n', 'a 1 extra\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                runtime.inventory(text)
        self.assertEqual(runtime.inventory('a 1\nb 2\n'), {'a': '1', 'b': '2'})

    def test_tooling_preserves_existing_newer_snappy(self):
        rows = [{'name': 'snappy', 'version': 'old'}, {'name': 'qemu-common', 'version': 'pin'}]
        self.assertEqual(runtime.additions({'snappy': 'new'}, {'packages': rows}), [rows[1]])
        with self.assertRaises(ValueError):
            runtime.additions({}, {'packages': [rows[0], rows[0]]})

    def test_qmp_frame_rejects_truncated_uniform_and_wrong_geometry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'frame.ppm'
            for data in (b'P6\n1024 768\n255\n\x00', b'P6\n1 1\n255\n123',
                         b'P6\n1024 768\n255\n' + b'\xff\x00\xff' * (1024 * 768)):
                path.write_bytes(data)
                with self.assertRaises(ValueError): runtime.ppm(path)
            path.write_bytes(b'P6\n1024 768\n255\n' + b'123' * (1024 * 768 - 1) + b'456')
            result = runtime.ppm(path)
            self.assertEqual((result['width'], result['height']), (1024, 768))
            self.assertEqual(len(result['sha256']), 64)

    def test_vm_launch_has_no_host_device_or_privilege_and_nonroot_uid(self):
        with patch.object(runtime.os, 'getuid', return_value=1001), patch.object(runtime.os, 'getgid', return_value=1001):
            args = runtime.docker_args('sha256:' + 'a' * 64, 'owned', Path('/task/out'), Path('/task/src'), Path('/task/runner'))
        self.assertIn('1001:1001', args)
        for flag in ('--network=none', '--cap-drop=ALL', '--read-only', '--security-opt=no-new-privileges'):
            self.assertIn(flag, args)
        self.assertFalse(any(arg.startswith(('--device', '--privileged', '--cap-add')) for arg in args))
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == '--mount']
        self.assertEqual(len(mounts), 3)
        self.assertTrue(all('readonly' in mount for mount in mounts if 'dst=/out' not in mount))

    def test_exited_process_final_serial_bytes_are_consumed_before_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'guest.log'
            path.write_bytes(b'initial\n')
            collector = Mock()
            collector.process.poll.return_value = 0
            def flush_final():
                with path.open('ab') as stream:
                    stream.write(b'DESKTOP574_EVENT {"event":"complete","status":"PASS"}\n')
            # Model the drain writing final bytes during finish(), after caller read.
            path.write_bytes(b'initial\n')
            collector.finish.side_effect = flush_final
            self.assertFalse(runtime.log_complete(collector, path, len(b'initial\n')))
            collector.finish.side_effect = None
            self.assertTrue(runtime.log_complete(collector, path, path.stat().st_size))
            self.assertIn(b'"complete"', path.read_bytes())

    def test_root_fixture_capabilities_are_metadata_only(self):
        args = runtime.docker_args('sha256:' + 'a' * 64, 'owned', Path('/task/out'), Path('/task/src'), Path('/task/runner'), root=True)
        self.assertEqual({arg for arg in args if arg.startswith('--cap-add')},
                         {'--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE', '--cap-add=FOWNER', '--cap-add=FSETID'})
        self.assertNotIn('--privileged', args)
        self.assertNotIn('--cap-add=SYS_ADMIN', args)


if __name__ == '__main__': unittest.main()
