#!/usr/bin/env python3
"""Focused data/launch checks; no network, Docker, package or guest execution."""
import ast
import copy
import importlib.util
from pathlib import Path
import os
import stat
import subprocess
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

    def test_named_build_base_is_bound_to_exact_local_image(self):
        image = 'sha256:' + 'a' * 64
        reference = 'cachy-asahi-desktop574-base:' + 'b' * 32
        execute = Mock()
        inspect = Mock(return_value=image)
        self.assertEqual(runtime.bind_local_base(image, reference, execute, inspect), reference)
        execute.assert_called_once_with(['docker', 'image', 'tag', image, reference], 'base-reference', 30)
        inspect.assert_called_once_with(['docker', 'image', 'inspect', '--format', '{{.Id}}', reference])
        inspect.return_value = 'sha256:' + 'c' * 64
        with self.assertRaises(ValueError):
            runtime.bind_local_base(image, reference, execute, inspect)
        with self.assertRaises(ValueError):
            runtime.bind_local_base(image, image, execute, inspect)

    def test_base_alias_cleanup_refuses_changed_binding_and_removes_only_owned_tag(self):
        image = 'sha256:' + 'a' * 64
        reference = 'cachy-asahi-desktop574-base:' + 'b' * 32
        changed = Mock(return_value=('sha256:' + 'c' * 64 + '\n').encode())
        self.assertFalse(runtime.release_local_base(image, reference, changed)['ok'])
        self.assertFalse(any('rm' in call.args[0] for call in changed.call_args_list))
        cleanup = Mock(side_effect=[(image + '\n').encode(), b'untagged', b'', b''])
        result = runtime.release_local_base(image, reference, cleanup)
        self.assertEqual(result, {'ok': True, 'base_image_present': False})
        self.assertEqual(cleanup.call_args_list[1].args[0], ['docker', 'image', 'rm', '--no-prune', reference])
        self.assertFalse(any('--force' in call.args[0] or '-f' in call.args[0] for call in cleanup.call_args_list))

    def test_qemu_snapshot_uses_the_private_writable_tmpfs(self):
        image = 'sha256:' + 'a' * 64
        cmd = runtime.qemu_command(image, 'owned', Path('/task/out'), Path('/task/src'), Path('/task/runner'))
        self.assertIn('--env=TMPDIR=/tmp/desktop574-qemu', cmd[:cmd.index(image)])
        self.assertIn('/tmp:rw,nosuid,nodev,exec,size=1g', cmd)
        self.assertIn('snapshot=on', cmd[-1])
        for flag in ('--network=none', '--read-only', '--cap-drop=ALL'):
            self.assertIn(flag, cmd)
        self.assertFalse(any(flag.startswith(('--device', '--privileged')) for flag in cmd))
        ordinary = runtime.docker_args(image, 'config', Path('/task/out'), Path('/task/src'), Path('/task/runner'))
        self.assertFalse(any(arg.startswith('--env=TMPDIR=') for arg in ordinary))

    def test_qemu_private_temp_directory_exists_before_exec(self):
        cmd = runtime.qemu_command('sha256:' + 'a' * 64, 'owned', Path('/task/out'), Path('/task/src'), Path('/task/runner'))
        selected = next(arg.split('=', 2)[2] for arg in cmd if arg.startswith('--env=TMPDIR='))
        # Pinned QEMU rewrites the exact /tmp path to /var/tmp; a child is retained.
        self.assertNotEqual(selected, '/tmp')
        self.assertEqual(Path(selected).parent, Path('/tmp'))
        prefix, separator, executable = cmd[-1].partition(' && exec ')
        self.assertTrue(separator)
        self.assertTrue(executable.startswith('qemu-system-aarch64 '))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'qemu-private'
            env = {'PATH': '/usr/bin:/bin', 'TMPDIR': str(target)}
            done = subprocess.run(['/bin/sh', '-c', prefix], env=env, capture_output=True, timeout=5)
            self.assertEqual(done.returncode, 0, done.stderr.decode())
            self.assertTrue(target.is_dir())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertEqual(target.stat().st_uid, os.getuid())
            # An unexpected preexisting entry refuses startup rather than reuse.
            repeated = subprocess.run(['/bin/sh', '-c', prefix], env=env, capture_output=True, timeout=5)
            self.assertNotEqual(repeated.returncode, 0)

    def test_actual_cleanup_loop_keeps_base_identity_for_alias_release(self):
        # Execute the production finally statements together: helper-only tests
        # missed the outer variable being overwritten before alias release.
        module = ast.parse(Path(runtime.__file__).read_text())
        main = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        final = next(node.finalbody for node in main.body if isinstance(node, ast.Try) and node.finalbody)
        loop = next(node for node in final if isinstance(node, ast.For) and isinstance(node.iter, ast.Name) and node.iter.id == 'images')
        release = next(node for node in final if isinstance(node, ast.If) and
                       any(isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'release_local_base'
                           for call in ast.walk(node)))
        image = 'sha256:' + 'a' * 64
        derived = 'sha256:' + 'b' * 64
        reference = 'cachy-asahi-desktop574-base:' + 'c' * 32
        cleanup = Mock(return_value=b'')
        releaser = Mock(return_value={'ok': True, 'base_image_present': False})
        scope = dict(image=image, images=[derived], base_reference=reference,
                     cleanup=cleanup, release_local_base=releaser, report={'status': 'PASS'})
        statements = ast.Module(body=copy.deepcopy([loop, release]), type_ignores=[])
        exec(compile(ast.fix_missing_locations(statements), '<production cleanup>', 'exec'), scope)
        releaser.assert_called_once_with(image, reference, cleanup)
        cleanup.assert_called_once_with(['docker', 'image', 'rm', derived], 'remove-image:' + derived)
        self.assertEqual(scope['image'], image)

    def test_root_fixture_capabilities_are_metadata_only(self):
        args = runtime.docker_args('sha256:' + 'a' * 64, 'owned', Path('/task/out'), Path('/task/src'), Path('/task/runner'), root=True)
        self.assertEqual({arg for arg in args if arg.startswith('--cap-add')},
                         {'--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE', '--cap-add=FOWNER', '--cap-add=FSETID'})
        self.assertNotIn('--privileged', args)
        self.assertNotIn('--cap-add=SYS_ADMIN', args)


if __name__ == '__main__': unittest.main()
