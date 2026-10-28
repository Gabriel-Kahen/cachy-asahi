#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Meaningful moved-prefix CLI controls plus the unchanged static source suite."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parent
sys.path[:0] = [str(SOURCE), str(SOURCE / 'payload/lib/cachy-asahi-desktop-tools')]
import assemble
import test_desktop_applications as original


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='desktop-tools-package-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        staged = assemble.assemble(SOURCE, self.base / 'dest')
        self.prefix = self.base / 'moved prefix'
        staged.rename(self.prefix)
        self.command = self.prefix / 'bin/cachy-asahi-desktop-tools'
        self.root = self.base / 'root'
        self.root.mkdir()
        self.envfile = self.base / 'environment.json'
        self.envfile.write_text(json.dumps(original.ENV))
        self.inventory = self.base / 'inventory.json'
        self.marker = self.base / 'MUST-NOT-EXIST'
        self.write('/usr/bin/tool', '#!/usr/bin/interpreter\ntouch ' + str(self.marker) + '\n', 0o755)
        self.write('/usr/bin/interpreter', original.elf(), 0o755)
        self.write('/usr/bin/terminal', original.elf(), 0o755)
        (self.root / 'usr/bin/tool-link').symlink_to('/usr/bin/tool')
        self.entry = ('[Desktop Entry]\nType=Application\nName=Original Offline Fixture\nExec=tool-link %F\n'
                      'TryExec=tool\nTerminal=true\nNoDisplay=true\nIcon=fixture\nMimeType=text/plain;\n')
        self.write('/usr/share/applications/tool.desktop', self.entry)
        self.write('/usr/share/icons/hicolor/index.theme', '[Icon Theme]\nName=Hicolor\nComment=Original fixture\nDirectories=48x48/apps\n[48x48/apps]\nSize=48\nType=Fixed\n')
        self.write('/usr/share/icons/hicolor/48x48/apps/fixture.png', b'INERT ORIGINAL IMAGE FIXTURE')
        self.write('/etc/xdg/mimeapps.list', '[Default Applications]\ntext/plain=tool.desktop;\n')
        self.args = ['--root', str(self.root), '--environment', str(self.envfile), '--select', 'tool.desktop', '--mime', 'text/plain']
        self.capture()

    def write(self, logical, raw, mode=0o644):
        path = self.root / logical.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
        path.chmod(mode)
        return path

    def call(self, *args, timeout=5):
        # Host desktop variables cannot create an execution path in this static command.
        env = dict(os.environ, PYTHONPATH='/does/not/exist', DISPLAY=':0', WAYLAND_DISPLAY='wayland-0',
                   DBUS_SESSION_BUS_ADDRESS='unix:path=/does/not/exist')
        result = subprocess.run([str(self.command), *args], cwd=self.base, env=env, capture_output=True, text=True, timeout=timeout)
        self.assertFalse(self.marker.exists(), 'desktop payload must never execute')
        return result

    def capture(self):
        result = self.call('capture', *self.args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.inventory.write_text(result.stdout)
        self.sha = hashlib.sha256(self.inventory.read_bytes()).hexdigest()

    def audit(self, *extra):
        return self.call('audit', *self.args, '--inventory', str(self.inventory), '--inventory-sha256', self.sha, *extra)

    def assert_refused(self, result, reason):
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'REFUSED')
        self.assertIn(reason, json.loads(result.stdout)['error'])

    def test_moved_prefix_exact_binding_and_nontrivial_fields(self):
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['inventory_binding'], 'EXACT_STATIC_INVENTORY')
        self.assertEqual(report['status'], 'PASS_STAGED_CHECKS')
        self.assertGreaterEqual(len(report['pins']), 7)
        self.assertEqual(report['applications'][0]['visibility'], 'NO_DISPLAY_HANDLER')
        self.assertEqual(report['mime'][0]['effective_explicit_exec_fallback'], 'tool.desktop')

    def test_moved_staged_root_and_environment_path(self):
        moved = self.base / 'moved root'; self.root.rename(moved)
        self.args[1] = str(moved)
        renamed = self.base / 'renamed environment.json'; self.envfile.rename(renamed)
        self.args[3] = str(renamed)
        self.assertEqual(self.audit().returncode, 0)

    def test_no_checkout_import_in_payload(self):
        for path in (self.prefix / 'lib').rglob('*.py'):
            self.assertNotIn(str(SOURCE), path.read_text())
        self.assertEqual(self.call('--version').returncode, 0)
        self.assertFalse(list(self.prefix.rglob('__pycache__')))

    def test_inventory_tamper(self):
        self.inventory.write_bytes(self.inventory.read_bytes() + b' ')
        self.assert_refused(self.audit(), 'byte pin mismatch')

    def test_inventory_mismatch_precedes_missing_root_and_environment(self):
        self.args[1] = str(self.base / 'absent-root')
        self.args[3] = str(self.base / 'absent-environment')
        self.inventory.write_bytes(self.inventory.read_bytes() + b' ')
        self.assert_refused(self.audit(), 'byte pin mismatch')

    def test_inventory_unknown_schema_refused(self):
        value = json.loads(self.inventory.read_text()); value['unexpected'] = True
        self.inventory.write_text(json.dumps(value))
        self.sha = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
        self.assert_refused(self.audit(), 'exact inventory schema')

    def test_inventory_duplicate_key_refused(self):
        self.inventory.write_text('{"schema":1,"schema":1}')
        self.sha = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
        self.assert_refused(self.audit(), 'duplicate JSON')

    def test_shell_exec_capture_cannot_execute_or_emit_inventory(self):
        self.write('/usr/share/applications/tool.desktop', self.entry.replace('tool-link %F', 'tool-link;touch sentinel'))
        result = self.call('capture', *self.args)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['status'], 'FAIL_STAGED_CHECKS')

    def test_retyped_inventory_byte_count_refused(self):
        value = json.loads(self.inventory.read_text())
        path = next(iter(value['files']))
        value['files'][path]['bytes'] = float(value['files'][path]['bytes'])
        self.inventory.write_text(json.dumps(value))
        self.sha = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
        self.assert_refused(self.audit(), 'staged inventory differs')

    def test_program_bytes_drift(self):
        self.write('/usr/bin/tool', '#!/usr/bin/interpreter\nDIFFERENT\n', 0o755)
        self.assert_refused(self.audit(), 'staged inventory differs')

    def test_program_mode_drift(self):
        (self.root / 'usr/bin/tool').chmod(0o700)
        self.assert_refused(self.audit(), 'staged inventory differs')

    def test_symlink_retarget_same_bytes(self):
        self.write('/usr/bin/other', (self.root / 'usr/bin/tool').read_bytes(), 0o755)
        link = self.root / 'usr/bin/tool-link'; link.unlink(); link.symlink_to('/usr/bin/other')
        self.assert_refused(self.audit(), 'staged inventory differs')

    def test_shadowing_added(self):
        self.write('/home/fixture/.local/share/applications/tool.desktop', self.entry)
        self.assert_refused(self.audit(), 'staged inventory differs')

    def test_terminal_missing(self):
        (self.root / 'usr/bin/terminal').unlink()
        self.assert_refused(self.audit(), 'staged inventory differs')

    def test_icon_drift(self):
        self.write('/usr/share/icons/hicolor/48x48/apps/fixture.png', b'CHANGED')
        self.assert_refused(self.audit(), 'staged inventory differs')

    def test_mime_drift(self):
        self.write('/etc/xdg/mimeapps.list', '[Default Applications]\ntext/plain=missing.desktop;\n')
        self.assert_refused(self.audit(), 'staged inventory differs')

    def test_environment_bytes_drift(self):
        self.envfile.write_bytes(self.envfile.read_bytes() + b' ')
        self.assert_refused(self.audit(), 'environment or selection differs')

    def test_selection_drift(self):
        self.assert_refused(self.audit('--select', 'other.desktop'), 'environment or selection differs')

    def test_bad_static_capture_does_not_emit_inventory(self):
        (self.root / 'usr/bin/tool').unlink()
        result = self.call('capture', *self.args)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['status'], 'FAIL_STAGED_CHECKS')
        self.assertNotIn('kind', json.loads(result.stdout))

    def test_active_root_refused(self):
        self.args[1] = '/tmp/..'
        self.assert_refused(self.audit(), 'active host')

    def test_environment_fifo_refused_without_blocking(self):
        self.envfile.unlink(); os.mkfifo(self.envfile)
        self.assert_refused(self.audit(), 'regular JSON')

    def test_inventory_fifo_refused_without_blocking(self):
        self.inventory.unlink(); os.mkfifo(self.inventory)
        self.assert_refused(self.audit(), 'regular JSON')

    def test_environment_symlink_refused(self):
        actual = self.base / 'actual.json'; self.envfile.rename(actual); self.envfile.symlink_to(actual)
        self.assert_refused(self.audit(), 'Too many levels')

    def test_duplicate_key_refused(self):
        self.envfile.write_text('{"HOME":"/a","HOME":"/b"}')
        self.assert_refused(self.audit(), 'duplicate JSON')

    def test_no_runtime_or_window_entrypoints(self):
        for name in ('runtime', 'window', 'launch'):
            result = self.call(name)
            self.assertEqual(result.returncode, 2)
            self.assertIn('invalid choice', result.stderr)

    def test_assembler_tamper_before_output(self):
        copied = self.base / 'source-copy'
        shutil.copytree(SOURCE, copied, ignore=shutil.ignore_patterns('__pycache__', '*.log', '*.logpipe'))
        (copied / 'payload/lib/cachy-asahi-desktop-tools/cli.py').write_text('CHANGED')
        destination = self.base / 'should-not-exist'
        with self.assertRaisesRegex(ValueError, 'payload bytes|bounded ordinary payload'):
            assemble.assemble(copied, destination)
        self.assertFalse(destination.exists())

    def test_reversible_file_removal_preserves_unowned_file(self):
        sentinel = self.prefix / 'user-owned'; sentinel.write_text('preserve')
        rows = json.loads((SOURCE / 'payload-map.json').read_text())['files']
        for row in rows:
            (self.prefix / row['path']).unlink()
        self.assertEqual(sentinel.read_text(), 'preserve')
        self.assertFalse(self.command.exists())
        self.assertEqual([p for p in self.prefix.rglob('*') if p.is_file()], [sentinel])


if __name__ == '__main__':
    suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(original),
                                unittest.defaultTestLoader.loadTestsFromTestCase(PackageTests)])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
