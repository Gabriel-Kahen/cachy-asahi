#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real bounded private executable fixtures; no live display or bus."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import desktop_application_runtime as runtime


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='desktop-exec-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.stage = self.base / 'stage'
        self.work = self.base / 'work'
        self.work.mkdir(mode=0o700)
        self.env = dict(HOME='/home/fixture', XDG_DATA_HOME='/home/fixture/data', XDG_DATA_DIRS='/usr/share',
                        XDG_CONFIG_HOME='/home/fixture/config', XDG_CONFIG_DIRS='/etc/xdg',
                        XDG_CURRENT_DESKTOP='Hyprland', PATH='/usr/bin:/bin', icon_theme='hicolor',
                        icon_size=32, icon_scale=1, terminal_argv=[], locale='C.UTF-8')
        self.env_path = self.base / 'env.json'
        self.context_path = self.base / 'context.json'
        self.context = dict(mode='fixture', work=str(self.work), display='none')
        self.interpreter = str(Path(sys.executable).resolve())
        self.install_host(self.interpreter)
        loader = runtime.desktop.elf_interpreter(Path(self.interpreter).read_bytes())
        if loader:
            self.install_host(loader)
        self.write('usr/bin/fixture', '#!' + self.interpreter + '\nprint("READY", flush=True)\n', 0o755)
        self.entry = self.write('usr/share/applications/fixture.desktop',
                                '[Desktop Entry]\nType=Application\nName=Fixture Name\nExec=fixture %f\n')
        self.args = argparse.Namespace(root=self.stage, environment=self.env_path, context=self.context_path,
                   select='fixture.desktop', entry_sha256='', exec_fallback=False,
                   ready_marker='READY', ready_seconds=.4, run_seconds=.7)
        self.save()

    def install_host(self, source):
        target = self.stage / source.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755)

    def write(self, path, text, mode=0o644):
        target = self.stage / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        target.chmod(mode)
        return target

    def save(self):
        self.env_path.write_text(json.dumps(self.env))
        self.context_path.write_text(json.dumps(self.context))
        self.args.entry_sha256 = hashlib.sha256(self.entry.read_bytes()).hexdigest()

    def script(self, body):
        self.write('usr/bin/fixture', '#!' + self.interpreter + '\n' + body, 0o755)

    def run_case(self):
        self.save()
        return runtime.run(self.args)

    def test_natural_close(self):
        row = self.run_case()
        self.assertEqual(row['status'], 'PASS_EXEC_WORKFLOW')
        self.assertEqual(row['exit'], 0)
        self.assertEqual(row['signals'], [])
        self.assertTrue(row['reaped'])
        self.assertEqual(row['group_census'], 'EMPTY_TWICE')
        self.assertEqual(row['gui'][:7], 'NOT_RUN')

    def test_literal_arguments_and_field_codes(self):
        self.entry.write_text('[Desktop Entry]\nType=Application\nName=Fixture Name\n'
                              'Exec=fixture %c %k %% %F "literal;touch /unwanted"\n')
        self.script('import json,sys\nprint("READY", json.dumps(sys.argv[1:]), flush=True)\n')
        row = self.run_case()
        self.assertEqual(row['status'], 'PASS_EXEC_WORKFLOW')
        self.assertEqual(row['argv'][1:], ['Fixture Name', str(self.entry), '%', 'literal;touch /unwanted'])

    def test_icon_expansion(self):
        self.write('usr/share/pixmaps/demo.png', 'icon')
        self.entry.write_text(self.entry.read_text().replace('Exec=fixture %f', 'Icon=demo\nExec=fixture %i %u'))
        row = self.run_case()
        self.assertEqual(row['argv'][1:], ['--icon', 'demo'])

    def test_missing_tryexec(self):
        self.entry.write_text(self.entry.read_text() + 'TryExec=absent\n')
        with self.assertRaisesRegex(ValueError, 'TryExec unavailable'):
            self.run_case()

    def test_missing_program(self):
        self.entry.write_text(self.entry.read_text().replace('Exec=fixture', 'Exec=absent'))
        with self.assertRaisesRegex(ValueError, 'executable unavailable'):
            self.run_case()

    def test_hash_mismatch(self):
        self.save()
        self.args.entry_sha256 = '0' * 64
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            runtime.run(self.args)

    def test_hidden_entry(self):
        self.entry.write_text(self.entry.read_text() + 'Hidden=true\n')
        with self.assertRaisesRegex(ValueError, 'entry unavailable'):
            self.run_case()

    def test_desktop_exclusion(self):
        self.entry.write_text(self.entry.read_text() + 'OnlyShowIn=GNOME;\n')
        with self.assertRaisesRegex(ValueError, 'entry unavailable'):
            self.run_case()

    def test_dbus_fallback_requires_opt_in(self):
        self.entry.write_text(self.entry.read_text() + 'DBusActivatable=true\n')
        with self.assertRaisesRegex(ValueError, 'exec-fallback'):
            self.run_case()
        self.args.exec_fallback = True
        self.assertEqual(self.run_case()['status'], 'PASS_EXEC_WORKFLOW')

    def test_terminal_absent(self):
        self.entry.write_text(self.entry.read_text() + 'Terminal=true\n')
        with self.assertRaisesRegex(runtime.NotRun, 'no explicit terminal'):
            self.run_case()

    def test_terminal_prefix(self):
        self.entry.write_text(self.entry.read_text() + 'Terminal=true\n')
        self.write('usr/bin/fixture-terminal', '#!' + self.interpreter + '\n'
                   'import os,sys\nassert sys.argv[1]=="--"\nos.execv(sys.argv[2],sys.argv[2:])\n', 0o755)
        self.env['terminal_argv'] = ['fixture-terminal', '--']
        row = self.run_case()
        self.assertEqual(row['status'], 'PASS_EXEC_WORKFLOW')
        self.assertEqual(row['argv'][1], '--')

    def test_missing_display(self):
        self.context['display'] = 'wayland'
        with self.assertRaisesRegex(runtime.NotRun, 'GUI fixture'):
            self.run_case()

    def test_guest_host_refused(self):
        self.context['mode'] = 'guest'
        with self.assertRaisesRegex(ValueError, 'ARM guest'):
            self.run_case()

    def test_private_path_symlink(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.work)
        self.context['work'] = str(alias)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.run_case()

    def test_inherited_environment_scrubbed(self):
        self.script('import os,json\nprint("READY",json.dumps(dict(os.environ)),flush=True)\n')
        with mock.patch.dict(os.environ, {'DISPLAY': ':0', 'WAYLAND_DISPLAY': 'wayland-live',
                                        'WAYLAND_SOCKET': '19', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/live'}):
            row = self.run_case()
        env = json.loads(row['output'].split('READY ', 1)[1])
        self.assertNotIn('DISPLAY', env)
        self.assertNotIn('WAYLAND_SOCKET', env)
        self.assertNotIn('WAYLAND_DISPLAY', env)
        self.assertEqual(env['HOME'], str(self.work / 'home'))
        self.assertIn(str(self.work), env['DBUS_SESSION_BUS_ADDRESS'])

    def test_start_failure(self):
        self.script('import sys\nprint("failed",file=sys.stderr)\nsys.exit(7)\n')
        row = self.run_case()
        self.assertEqual(row['status'], 'START_FAILED')
        self.assertEqual(row['exit'], 7)

    def test_readiness_absent(self):
        self.script('print("not ready")\n')
        self.assertEqual(self.run_case()['status'], 'READINESS_NOT_OBSERVED')

    def test_late_readiness(self):
        self.args.ready_seconds = .05
        self.script('import time\ntime.sleep(.2)\nprint("READY",flush=True)\n')
        self.assertEqual(self.run_case()['status'], 'READINESS_NOT_OBSERVED')

    def test_timeout(self):
        self.script('import time\nprint("READY",flush=True)\ntime.sleep(20)\n')
        row = self.run_case()
        self.assertEqual(row['status'], 'RUN_TIMEOUT')
        self.assertTrue(row['reaped'])
        self.assertIn('SIGTERM', row['signals'])
        self.assertLess(row['seconds'], 1.7)

    def test_output_cap(self):
        self.script('print("READY"+"x"*200000,flush=True)\n')
        row = self.run_case()
        self.assertEqual(row['status'], 'OUTPUT_LIMIT')
        self.assertLessEqual(len(row['output']), runtime.CAP)

    def test_signal_cancellation_cli(self):
        self.script('import time\nprint("READY",flush=True)\ntime.sleep(20)\n')
        self.save()
        command = [sys.executable, '-B', runtime.__file__, '--root', str(self.stage),
                   '--environment', str(self.env_path), '--context', str(self.context_path),
                   '--select', 'fixture.desktop', '--entry-sha256', self.args.entry_sha256,
                   '--ready-marker', 'READY', '--ready-seconds', '.4', '--run-seconds', '.7']
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(.25)
            child.send_signal(signal.SIGTERM)
            stdout, stderr = child.communicate(timeout=3)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
        row = json.loads(stdout)
        self.assertEqual(row['status'], 'CANCELLED', stderr)
        self.assertEqual(row['signals_received'], ['SIGTERM'])
        self.assertTrue(row['reaped'])

    def test_sigpipe_prelaunch_refusal(self):
        with mock.patch.object(signal, 'getsignal', side_effect=lambda sig: signal.SIG_DFL):
            with mock.patch.object(runtime.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(ValueError, 'SIGPIPE'):
                    self.run_case()
                spawn.assert_not_called()

    def test_disabled_bus_endpoint_refused(self):
        (self.work / 'no-session-bus').symlink_to('/run/user/absent/bus')
        with self.assertRaisesRegex(ValueError, 'endpoint already exists'):
            self.run_case()

    def test_headless_default_wayland_endpoint_refused(self):
        folder = self.work / 'runtime'
        folder.mkdir(mode=0o700)
        (folder / 'wayland-0').write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'runtime directory must be empty'):
            self.run_case()

    def test_terminal_cannot_hide_env_wrapper(self):
        self.install_host('/usr/bin/env')
        self.entry.write_text(self.entry.read_text().replace('Exec=fixture', 'Exec=env fixture') + 'Terminal=true\n')
        self.env['terminal_argv'] = ['fixture', '--']
        with self.assertRaisesRegex(ValueError, 'env/shell'):
            self.run_case()

    def test_symlink_invocation_basename_preserved(self):
        (self.stage / 'usr/bin/alias').symlink_to('fixture')
        self.entry.write_text(self.entry.read_text().replace('Exec=fixture', 'Exec=alias'))
        self.script('import sys,os\nprint("READY",os.path.basename(sys.argv[0]),flush=True)\n')
        row = self.run_case()
        self.assertEqual(row['status'], 'PASS_EXEC_WORKFLOW')
        self.assertIn('READY alias', row['output'])

    def test_sigchld_prelaunch_refusal(self):
        with mock.patch.object(signal, 'getsignal', return_value=signal.SIG_IGN):
            with mock.patch.object(runtime.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(ValueError, 'SIGCHLD'):
                    self.run_case()
                spawn.assert_not_called()

    def test_os_launch_error_reported(self):
        with mock.patch.object(runtime.subprocess, 'Popen', side_effect=OSError('execution refused')):
            row = self.run_case()
        self.assertEqual(row['status'], 'START_FAILED')
        self.assertEqual(row['retirement'], 'NOT_LAUNCHED')

    def test_shell_alias_refused(self):
        target = self.stage / 'usr/bin/sh'
        shutil.copyfile('/bin/sh', target)
        target.chmod(0o755)
        loader = runtime.desktop.elf_interpreter(target.read_bytes())
        if loader:
            self.install_host(loader)
        (self.stage / 'usr/bin/alias').symlink_to('sh')
        self.entry.write_text(self.entry.read_text().replace('Exec=fixture %f', 'Exec=alias -c true'))
        with self.assertRaisesRegex(ValueError, 'env/shell'):
            self.run_case()

    def test_private_wayland_socket_absent_after_mocked_guest_admission(self):
        # Unit routing only: this does not execute or establish a guest.
        self.context.update(mode='guest', display='wayland', wayland_display='wayland-test')
        with mock.patch.object(runtime.platform, 'machine', return_value='aarch64'), \
             mock.patch.dict(os.environ, {'CACHY_ASAHI_VIRTUAL_GUEST': '1'}), \
             mock.patch.object(Path, 'read_text', return_value='cachy_asahi_virtual_proof=1'):
            with self.assertRaisesRegex(runtime.NotRun, 'display missing'):
                runtime.context(self.context)

    def test_fifo_json_refused_without_blocking(self):
        fifo = self.base / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            runtime.data(fifo)

    def test_fifo_runtime_file_refused_without_blocking(self):
        fifo = self.base / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            runtime.read_file(fifo, 1024)

    def test_cli_missing_program_report(self):
        self.entry.write_text(self.entry.read_text().replace('Exec=fixture', 'Exec=absent'))
        self.save()
        with mock.patch('builtins.print') as output:
            code = runtime.main(['--root', str(self.stage), '--environment', str(self.env_path),
                  '--context', str(self.context_path), '--select', 'fixture.desktop',
                  '--entry-sha256', self.args.entry_sha256, '--ready-marker', 'READY'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.call_args.args[0])['status'], 'REFUSED')


if __name__ == '__main__':
    unittest.main()
