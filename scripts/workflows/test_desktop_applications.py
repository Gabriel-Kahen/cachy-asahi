#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Selected integration fixtures; no fixture commands or desktop apps execute."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import desktop_applications as desktop


def elf(loader=None, machine=183):
    """Original non-runnable ELF metadata fixture, never executed."""
    raw = bytearray(64)
    raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', raw, 16, 2, machine, 1)
    struct.pack_into('<HHH', raw, 52, 64, 56, int(loader is not None))
    if loader is not None:
        struct.pack_into('<Q', raw, 32, 64)
        data = loader.encode() + b'\0'
        header = bytearray(56)
        struct.pack_into('<I', header, 0, 3)
        struct.pack_into('<Q', header, 8, 120)
        struct.pack_into('<Q', header, 32, len(data))
        raw += header + data
    return bytes(raw)


ENV = dict(HOME='/home/fixture', XDG_DATA_HOME='/home/fixture/.local/share',
           XDG_DATA_DIRS='/usr/local/share:/usr/share',
           XDG_CONFIG_HOME='/home/fixture/.config', XDG_CONFIG_DIRS='/etc/xdg',
           XDG_CURRENT_DESKTOP='Hyprland', PATH='/usr/local/bin:/usr/bin',
           icon_theme='hicolor', icon_size=48, icon_scale=1,
           terminal_argv=['terminal', '-e'], locale='C')


class ExecTests(unittest.TestCase):
    def test_whole_quoted_argument_and_executable(self):
        self.assertEqual(desktop.exec_argv('"/usr/bin/an app" "two words" ""')['argv_without_file_inputs'],
                         ['/usr/bin/an app', 'two words', ''])

    def test_two_escaping_layers_preserve_literals(self):
        command_layer = 'app "cash \\$HOME and \\\\ literal \\"quote\\""'
        raw = command_layer.replace('\\', '\\\\')
        self.assertEqual(desktop.exec_argv(raw)['argv_without_file_inputs'],
                         ['app', 'cash $HOME and \\ literal "quote"'])

    def test_fields_are_expanded_once_without_shell_splitting(self):
        result = desktop.exec_argv('app %c %i %k %F %%', 'Name %u with space',
                                   'icon with space', '/usr/share/applications/a.desktop')
        self.assertEqual(result['argv_without_file_inputs'],
                         ['app', 'Name %u with space', '--icon', 'icon with space',
                          '/usr/share/applications/a.desktop', '%'])
        self.assertEqual(result['field_codes'], ['%c', '%i', '%k', '%F'])

    def test_file_and_deprecated_fields_removed_with_no_input(self):
        self.assertEqual(desktop.exec_argv('app %f %d %D %n %N %v %m')['argv_without_file_inputs'], ['app'])
        self.assertEqual(desktop.exec_argv('app --file=%f')['argv_without_file_inputs'], ['app', '--file='])

    def test_missing_icon_code_removed(self):
        self.assertEqual(desktop.exec_argv('app %i')['argv_without_file_inputs'], ['app'])

    def test_literal_percent_in_executable_is_not_field_expansion(self):
        self.assertEqual(desktop.exec_argv('app%% --flag')['argv_without_file_inputs'], ['app%', '--flag'])

    def test_malformed_commands_are_refused(self):
        for value in ('', 'A=B app', 'app "unterminated', 'app prefix"quote"',
                      'app "quote"suffix', 'app %Q', 'app %', 'app %f %U',
                      'app --files=%F', 'app --icon=%i', 'app "%c"',
                      'app $HOME', 'app $(touch sentinel)', 'app ~',
                      "app 'shell quote'", 'app x;y', 'app | cat',
                      'app "unescaped $HOME"', 'app "`touch sentinel`"',
                      'app \\q', 'app trailing\\', '%c arg'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                desktop.exec_argv(value)

    def test_value_list_escaped_semicolon_and_backslash(self):
        self.assertEqual(desktop.values(r'a\;b;c\\;d;'), ['a;b', 'c\\', 'd'])
        self.assertEqual(desktop.unescape(r'hello\sworld'), 'hello world')


class FixtureTests(unittest.TestCase):
    def test_active_host_root_alias_refused(self):
        for root in ('/', '/tmp/..', '//'):
            with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'active host'):
                desktop.Stage(root)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='desktop-integration-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'root'
        self.root.mkdir()
        self.env = copy.deepcopy(ENV)
        self.write('/usr/bin/app', elf(), 0o755)
        self.write('/usr/bin/terminal', elf(), 0o755)
        self.desktop()

    def write(self, logical, raw, mode=0o644):
        path = self.root / logical.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
        path.chmod(mode)
        return path

    def desktop(self, ident='app.desktop', extra='', base='/usr/share', body=None):
        if body is None:
            body = '[Desktop Entry]\nType=Application\nName=Fixture\nExec=app %U\n' + extra
        return self.write(base + '/applications/' + ident, body)

    @contextlib.contextmanager
    def audit(self):
        audit = desktop.Audit(self.root, self.env)
        try:
            yield audit
        finally:
            audit.stage.close()

    def run_audit(self, selected=None, mimes=()):
        with self.audit() as audit:
            return audit.run(selected or ['app.desktop'], mimes)

    def theme(self, name, directories, inherits=''):
        text = '[Icon Theme]\nName=Fixture\nComment=Original test data\nDirectories=' + ','.join(x[0] for x in directories) + '\n'
        if inherits:
            text += 'Inherits=' + inherits + '\n'
        for sub, size, kind, extra in directories:
            text += f'[{sub}]\nSize={size}\nType={kind}\n{extra}'
        self.write('/usr/share/icons/' + name + '/index.theme', text)

    def test_clean_selected_entry_passes_staged_checks(self):
        report = self.run_audit()
        self.assertEqual(report['status'], 'PASS_STAGED_CHECKS')
        app = report['applications'][0]
        self.assertEqual(app['visibility'], 'MENU_CANDIDATE')
        self.assertEqual(app['exec']['argv_without_file_inputs'], ['app'])
        self.assertEqual(app['exec']['resolution']['elf_machine'], 183)
        self.assertIn('/usr/bin/app', report['pins'])

    def test_user_override_wins_and_pins_exact_source(self):
        self.desktop(extra='TryExec=missing\n', base=self.env['XDG_DATA_HOME'])
        report = self.run_audit()
        app = report['applications'][0]
        self.assertEqual(app['origin'], 'user_override')
        self.assertEqual(app['shadowed'][0]['path'], '/usr/share/applications/app.desktop')
        self.assertEqual(report['pins'][app['path']]['sha256'], desktop.pin((self.root / app['path'].lstrip('/')).read_bytes())['sha256'])
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')

    def test_user_hidden_tombstone_does_not_fall_back(self):
        self.desktop(base=self.env['XDG_DATA_HOME'], body='[Desktop Entry]\nHidden=true\n')
        report = self.run_audit()
        app = report['applications'][0]
        self.assertEqual(app['visibility'], 'HIDDEN_TOMBSTONE')
        self.assertNotIn('exec', app)
        self.assertIn('selected_hidden', [x['code'] for x in report['issues']])

    def test_nodisplay_is_available_handler_not_visible_menu(self):
        self.desktop(extra='NoDisplay=true\nMimeType=text/plain;\n')
        self.write('/home/fixture/.config/mimeapps.list', '[Default Applications]\ntext/plain=app.desktop;\n')
        report = self.run_audit(mimes=['text/plain'])
        self.assertEqual(report['status'], 'PASS_STAGED_CHECKS')
        self.assertEqual(report['applications'][0]['visibility'], 'NO_DISPLAY_HANDLER')
        self.assertEqual(report['mime'][0]['effective_explicit_exec_fallback'], 'app.desktop')

    def test_only_show_in_chosen_desktop(self):
        self.desktop(extra='OnlyShowIn=Hyprland;\n')
        self.assertEqual(self.run_audit()['status'], 'PASS_STAGED_CHECKS')
        self.env['XDG_CURRENT_DESKTOP'] = 'GNOME'
        report = self.run_audit()
        self.assertEqual(report['applications'][0]['visibility'], 'DESKTOP_EXCLUDED')
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')

    def test_not_show_in_multi_desktop_and_invalid_combination(self):
        self.env['XDG_CURRENT_DESKTOP'] = 'Hyprland:GNOME'
        self.desktop(extra='NotShowIn=GNOME;\n')
        self.assertFalse(self.run_audit()['applications'][0]['desktop_eligible'])
        self.desktop(extra='OnlyShowIn=Hyprland;\nNotShowIn=GNOME;\n')
        self.assertIn('mutually exclusive', self.run_audit()['applications'][0]['error'])

    def test_malformed_boolean_and_duplicate_key_fail(self):
        for extra in ('Terminal=yes\n', 'Hidden=1\n', 'NoDisplay=False\n', 'Name=second\n'):
            with self.subTest(extra=extra):
                self.desktop(extra=extra)
                report = self.run_audit()
                self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')
                self.assertIn('error', report['applications'][0])

    def test_action_group_does_not_override_main_exec(self):
        self.desktop(extra='[Desktop Action Bad]\nName=Bad\nExec=does-not-exist\n')
        report = self.run_audit()
        self.assertEqual(report['status'], 'PASS_STAGED_CHECKS')
        self.assertEqual(report['applications'][0]['exec']['argv_without_file_inputs'], ['app'])

    def test_nested_desktop_id_is_flattened(self):
        self.desktop('vendor/test.desktop')
        report = self.run_audit(['vendor-test.desktop'])
        self.assertEqual(report['applications'][0]['path'], '/usr/share/applications/vendor/test.desktop')

    def test_colliding_flattened_desktop_ids_refused(self):
        self.desktop('vendor/test.desktop')
        self.desktop('vendor-test.desktop')
        with self.assertRaisesRegex(ValueError, 'ambiguous desktop ID'):
            with self.audit():
                pass

    def test_missing_exec_and_tryexec_report_exact_staged_paths(self):
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Missing\nExec=missing %f\nTryExec=missing\n')
        report = self.run_audit()
        resolution = report['applications'][0]['exec']['resolution']
        self.assertEqual([x['path'] for x in resolution['search_misses']], ['/usr/local/bin/missing', '/usr/bin/missing'])
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')

    def test_nonexecutable_first_path_candidate_allows_later_binary(self):
        self.write('/usr/local/bin/app', elf(), 0o644)
        report = self.run_audit()
        value = report['applications'][0]['exec']['resolution']
        self.assertEqual(value['file']['path'], '/usr/bin/app')
        self.assertEqual(value['search_misses'][0]['reason'], 'no_execute_mode_bit')

    def test_missing_shebang_interpreter_is_not_available(self):
        self.write('/usr/bin/app', '#!/usr/bin/python3\nprint("never executed")\n', 0o755)
        report = self.run_audit()
        value = report['applications'][0]['exec']['resolution']
        self.assertFalse(desktop.command_ok(value))
        self.assertEqual(value['interpreter']['requested'], '/usr/bin/python3')
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')

    def test_shebang_and_elf_loader_chain_is_pinned(self):
        self.write('/usr/bin/app', '#!/usr/bin/python3\n', 0o755)
        self.write('/usr/bin/python3', elf('/lib/ld-linux-aarch64.so.1'), 0o755)
        self.write('/lib/ld-linux-aarch64.so.1', elf(), 0o755)
        report = self.run_audit()
        self.assertEqual(report['status'], 'PASS_STAGED_CHECKS')
        self.assertIn('/lib/ld-linux-aarch64.so.1', report['pins'])

    def test_missing_elf_loader_fails(self):
        self.write('/usr/bin/app', elf('/lib/ld-linux-aarch64.so.1'), 0o755)
        report = self.run_audit()
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')
        self.assertEqual(report['applications'][0]['exec']['resolution']['interpreter']['error'], 'executable unavailable')

    def test_malformed_elf_header_and_interp_refused(self):
        for raw in (b'\x7fELF', elf('/lib/loader')[:-1], b'not executable'):
            with self.subTest(raw=raw[:12]):
                self.write('/usr/bin/app', raw, 0o755)
                self.assertEqual(self.run_audit()['status'], 'FAIL_STAGED_CHECKS')

    def test_env_wrapper_nested_target_checked(self):
        self.write('/usr/bin/env', elf(), 0o755)
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Env\nExec=env LANG=C missing %F\n')
        self.assertEqual(self.run_audit()['status'], 'FAIL_STAGED_CHECKS')
        self.write('/usr/bin/missing', elf(), 0o755)
        self.assertEqual(self.run_audit()['status'], 'PASS_STAGED_CHECKS')

    def test_env_empty_environment_does_not_reuse_supplied_path(self):
        self.write('/usr/bin/env', elf(), 0o755)
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Env\nExec=env -i app\n')
        self.assertEqual(self.run_audit()['status'], 'FAIL_STAGED_CHECKS')
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Env\nExec=env -i PATH=/usr/bin app\n')
        self.assertEqual(self.run_audit()['status'], 'PASS_STAGED_CHECKS')
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Env\nExec=env -u PATH /usr/bin/app\n')
        self.assertEqual(self.run_audit()['status'], 'PASS_STAGED_CHECKS')

    def test_env_assignment_after_end_of_options_is_honored(self):
        self.write('/usr/bin/env', elf(), 0o755)
        self.write('/chosen/bin/tool', elf(), 0o755)
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Env\nExec=env -- PATH=/chosen/bin tool\n')
        report = self.run_audit()
        self.assertEqual(report['status'], 'PASS_STAGED_CHECKS')
        self.assertEqual(report['applications'][0]['exec']['resolution']['env_target']['file']['path'], '/chosen/bin/tool')

    def test_env_wrapped_shell_payload_is_unresolved(self):
        self.write('/usr/bin/env', elf(), 0o755)
        self.write('/usr/bin/sh', elf(), 0o755)
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Env shell\nExec=env sh -c "touch sentinel"\n')
        report = self.run_audit()
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')
        self.assertIn('NOT_AUDITED', report['applications'][0]['exec']['resolution']['env_target']['error'])
        self.write('/usr/bin/app', '#!/usr/bin/env -S sh -c "touch sentinel"\n', 0o755)
        self.desktop()
        report = self.run_audit()
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')
        self.assertIn('NOT_AUDITED', report['applications'][0]['exec']['resolution']['env_target']['error'])
        self.assertFalse((self.root / 'sentinel').exists())

    def test_env_shebang_needs_split_mode_for_multiple_arguments(self):
        self.write('/usr/bin/env', elf(), 0o755)
        self.write('/usr/bin/python3', elf(), 0o755)
        self.write('/usr/bin/app', '#!/usr/bin/env python3 -I\n', 0o755)
        self.assertEqual(self.run_audit()['status'], 'FAIL_STAGED_CHECKS')
        self.write('/usr/bin/app', '#!/usr/bin/env -S python3 -I\n', 0o755)
        self.assertEqual(self.run_audit()['status'], 'PASS_STAGED_CHECKS')

    def test_shell_payload_is_not_claimed_audited_or_executed(self):
        self.write('/usr/bin/sh', elf(), 0o755)
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Shell\nExec=sh -c "touch sentinel"\n')
        with mock.patch('os.system', side_effect=AssertionError('must not execute')):
            report = self.run_audit()
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')
        self.assertFalse((self.root / 'sentinel').exists())

    def test_terminal_entry_requires_configured_available_terminal(self):
        self.desktop(extra='Terminal=true\n')
        self.assertEqual(self.run_audit()['status'], 'PASS_STAGED_CHECKS')
        self.env['terminal_argv'] = []
        report = self.run_audit()
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')
        self.assertIn('unconfigured', report['applications'][0]['terminal_command']['error'])

    def test_terminal_mime_default_not_usable_when_terminal_missing(self):
        self.desktop(extra='Terminal=true\nMimeType=text/plain;\n')
        self.env['terminal_argv'] = []
        self.write('/home/fixture/.config/mimeapps.list', '[Default Applications]\ntext/plain=app.desktop;\n')
        report = self.run_audit(mimes=['text/plain'])
        self.assertIsNone(report['mime'][0]['effective_explicit_exec_fallback'])

    def test_absolute_symlink_targets_are_staged(self):
        (self.root / 'usr/bin/app').unlink()
        self.write('/opt/bin/app', elf(), 0o755)
        (self.root / 'usr/bin/app').symlink_to('/opt/bin/app')
        report = self.run_audit()
        resolved = report['applications'][0]['exec']['resolution']['file']
        self.assertEqual(resolved['resolved'], '/opt/bin/app')
        self.assertEqual(resolved['symlinks'], [{'path': '/usr/bin/app', 'target': '/opt/bin/app'}])
        self.assertEqual(report['status'], 'PASS_STAGED_CHECKS')

    def test_symlink_then_parent_component_uses_target_namespace(self):
        (self.root / 'usr/bin/app').unlink()
        self.write('/opt/actual/tool', elf(), 0o755)
        self.write('/usr/wrong/tool', b'wrong', 0o755)
        (self.root / 'usr/bin/link').symlink_to('/opt/actual/subdir')
        (self.root / 'opt/actual/subdir').mkdir()
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Link\nExec=/usr/bin/link/../tool\n')
        report = self.run_audit()
        self.assertEqual(report['status'], 'PASS_STAGED_CHECKS')
        self.assertEqual(report['applications'][0]['exec']['resolution']['file']['resolved'], '/opt/actual/tool')

    def test_symlink_target_nested_symlink_then_parent_uses_target_namespace(self):
        (self.root / 'usr/bin/app').unlink()
        self.write('/opt/actual/tool', elf(), 0o755)
        (self.root / 'opt/actual/subdir').mkdir()
        (self.root / 'opt/links').mkdir()
        (self.root / 'opt/links/nested').symlink_to('/opt/actual/subdir')
        (self.root / 'usr/bin/app').symlink_to('/opt/links/nested/../tool')
        report = self.run_audit()
        self.assertEqual(report['status'], 'PASS_STAGED_CHECKS')
        value = report['applications'][0]['exec']['resolution']['file']
        self.assertEqual(value['resolved'], '/opt/actual/tool')
        self.assertEqual(len(value['symlinks']), 2)

    def test_relative_symlink_cannot_escape_root(self):
        (self.root / 'usr/bin/app').unlink()
        (self.root / 'usr/bin/app').symlink_to('../../../outside')
        report = self.run_audit()
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')
        self.assertIn('escapes staged root', report['applications'][0]['error'])

    def test_desktop_symlink_escape_never_reads_host_source(self):
        source = self.root / 'usr/share/applications/app.desktop'
        source.unlink()
        host = Path(self.temporary.name) / 'outside.desktop'
        host.write_text('[Desktop Entry]\nName=HOST SECRET\n')
        source.symlink_to('../../../../outside.desktop')
        report = self.run_audit()
        self.assertIn('escapes staged root', report['applications'][0]['error'])
        self.assertNotIn('HOST SECRET', json.dumps(report))

    def test_absolute_host_symlink_does_not_read_host_file(self):
        source = self.root / 'usr/share/applications/app.desktop'
        source.unlink()
        host = Path(self.temporary.name) / 'outside.desktop'
        host.write_text('[Desktop Entry]\nName=HOST SECRET\n')
        source.symlink_to(host)
        report = self.run_audit()
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')
        self.assertNotIn('HOST SECRET', json.dumps(report))

    def test_fifo_and_symlink_loop_refused_without_blocking(self):
        (self.root / 'usr/bin/app').unlink()
        os.mkfifo(self.root / 'usr/bin/app')
        self.assertIn('not a regular', self.run_audit()['applications'][0]['error'])
        (self.root / 'usr/bin/app').unlink()
        (self.root / 'usr/bin/app').symlink_to('app')
        self.assertIn('symlink loop/limit', self.run_audit()['applications'][0]['error'])

    def test_icon_exact_size_before_closest_and_theme_inheritance(self):
        self.env['icon_theme'] = 'selected'
        self.desktop(extra='Icon=fixture\n')
        self.theme('selected', [('16x16/apps', 16, 'Fixed', ''), ('48x48/apps', 48, 'Fixed', '')], 'parent')
        self.theme('parent', [('48x48/apps', 48, 'Fixed', '')])
        self.write('/usr/share/icons/selected/16x16/apps/fixture.png', b'original fixture')
        self.write('/usr/share/icons/selected/48x48/apps/fixture.png', b'exact fixture')
        self.write('/usr/share/icons/parent/48x48/apps/fixture.png', b'parent fixture')
        report = self.run_audit()
        icon = report['applications'][0]['icon']
        self.assertEqual(icon['file']['path'], '/usr/share/icons/selected/48x48/apps/fixture.png')
        (self.root / icon['file']['path'].lstrip('/')).unlink()
        self.assertEqual(self.run_audit()['applications'][0]['icon']['file']['path'], '/usr/share/icons/selected/16x16/apps/fixture.png')

    def test_icon_parent_hicolor_and_unthemed_fallback(self):
        self.env['icon_theme'] = 'selected'
        self.desktop(extra='Icon=fixture\n')
        self.theme('selected', [], 'parent')
        self.theme('parent', [('48x48/apps', 48, 'Fixed', '')])
        self.theme('hicolor', [('48x48/apps', 48, 'Fixed', '')])
        parent = self.write('/usr/share/icons/parent/48x48/apps/fixture.png', b'parent')
        hicolor = self.write('/usr/share/icons/hicolor/48x48/apps/fixture.png', b'hicolor')
        fallback = self.write('/usr/share/pixmaps/fixture.png', b'fallback')
        self.assertEqual(self.run_audit()['applications'][0]['icon']['file']['path'], '/usr/share/icons/parent/48x48/apps/fixture.png')
        parent.unlink()
        self.assertEqual(self.run_audit()['applications'][0]['icon']['file']['path'], '/usr/share/icons/hicolor/48x48/apps/fixture.png')
        hicolor.unlink()
        self.assertEqual(self.run_audit()['applications'][0]['icon']['file']['path'], '/usr/share/pixmaps/fixture.png')
        fallback.unlink()
        self.assertEqual(self.run_audit()['status'], 'FAIL_STAGED_CHECKS')

    def test_icon_user_base_and_scale_selection(self):
        self.desktop(extra='Icon=fixture\n')
        self.theme('hicolor', [('48x48/apps', 48, 'Fixed', ''), ('48x48@2/apps', 48, 'Fixed', 'Scale=2\n')])
        self.env['icon_scale'] = 2
        self.write('/usr/share/icons/hicolor/48x48/apps/fixture.png', b'1x')
        self.write('/usr/share/icons/hicolor/48x48@2/apps/fixture.png', b'2x')
        self.write('/home/fixture/.local/share/icons/hicolor/48x48@2/apps/fixture.png', b'user 2x')
        report = self.run_audit()
        self.assertEqual(report['applications'][0]['icon']['file']['path'], '/home/fixture/.local/share/icons/hicolor/48x48@2/apps/fixture.png')

    def test_absolute_icon_symlink_escape_fails(self):
        self.desktop(extra='Icon=/usr/share/pixmaps/fixture.png\n')
        target = self.root / 'usr/share/pixmaps/fixture.png'
        target.parent.mkdir(parents=True)
        target.symlink_to('../../../../outside')
        self.assertIn('escapes staged root', self.run_audit()['applications'][0]['error'])

    def test_mime_defaults_skip_missing_then_use_existing(self):
        self.desktop(extra='MimeType=text/plain;\n')
        self.write('/home/fixture/.config/mimeapps.list', '[Default Applications]\ntext/plain=missing.desktop;app.desktop;\n')
        report = self.run_audit(mimes=['text/plain'])
        self.assertEqual(report['status'], 'PASS_STAGED_CHECKS')
        self.assertEqual(report['mime'][0]['effective_explicit_exec_fallback'], 'app.desktop')
        self.assertIn('mime_reference_unavailable', [x['code'] for x in report['issues']])

    def test_mime_desktop_specific_defaults_precede_generic(self):
        self.desktop(extra='MimeType=text/plain;\n')
        self.desktop('other.desktop', extra='MimeType=text/plain;\n')
        self.write('/home/fixture/.config/mimeapps.list', '[Default Applications]\ntext/plain=app.desktop;\n')
        self.write('/home/fixture/.config/hyprland-mimeapps.list', '[Default Applications]\ntext/plain=other.desktop;\n')
        report = self.run_audit(mimes=['text/plain'])
        self.assertEqual(report['mime'][0]['effective_explicit_exec_fallback'], 'other.desktop')

    def test_mime_removed_association_disqualifies_declared_default(self):
        self.desktop(extra='MimeType=text/plain;\n')
        self.desktop('other.desktop', extra='MimeType=text/plain;\n')
        self.write('/home/fixture/.config/mimeapps.list', '[Default Applications]\ntext/plain=app.desktop;other.desktop;\n[Removed Associations]\ntext/plain=app.desktop;\n')
        self.assertEqual(self.run_audit(mimes=['text/plain'])['mime'][0]['effective_explicit_exec_fallback'], 'other.desktop')

    def test_mime_added_association_allows_explicit_default(self):
        self.write('/home/fixture/.config/mimeapps.list', '[Default Applications]\ntext/plain=app.desktop;\n[Added Associations]\ntext/plain=app.desktop;\n')
        self.assertEqual(self.run_audit(mimes=['text/plain'])['mime'][0]['effective_explicit_exec_fallback'], 'app.desktop')

    def test_lower_priority_data_mime_removal_cannot_change_user_override(self):
        self.desktop(extra='MimeType=text/plain;\n', base=self.env['XDG_DATA_HOME'])
        self.write('/usr/share/applications/mimeapps.list', '[Removed Associations]\ntext/plain=app.desktop;\n[Default Applications]\ntext/plain=app.desktop;\n')
        self.assertEqual(self.run_audit(mimes=['text/plain'])['mime'][0]['effective_explicit_exec_fallback'], 'app.desktop')

    def test_desktop_specific_mime_association_edits_refused(self):
        self.write('/home/fixture/.config/hyprland-mimeapps.list', '[Added Associations]\ntext/plain=app.desktop;\n')
        with self.assertRaisesRegex(ValueError, 'desktop-specific mimeapps'):
            self.run_audit(mimes=['text/plain'])

    def test_required_mime_without_explicit_default_is_unresolved(self):
        self.desktop(extra='MimeType=text/plain;\n')
        report = self.run_audit(mimes=['text/plain'])
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')
        self.assertIsNone(report['mime'][0]['effective_explicit_exec_fallback'])
        self.assertEqual(report['mime'][0]['implicit_fallback_and_subclasses'], 'NOT_INFERRED')

    def test_cli_success_failure_and_refusal_are_distinct(self):
        environment_path = Path(self.temporary.name) / 'environment.json'
        environment_path.write_text(json.dumps(self.env))
        arguments = ['--root', str(self.root), '--environment', str(environment_path), '--select', 'app.desktop']
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = desktop.main(arguments)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())['status'], 'PASS_STAGED_CHECKS')
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Bad\nExec=missing\n')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = desktop.main(arguments)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())['status'], 'FAIL_STAGED_CHECKS')
        environment_path.write_text('{"PATH":"/usr/bin","PATH":"/bin"}')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = desktop.main(arguments)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())['status'], 'REFUSED')

    def test_host_environment_never_supplies_missing_staged_binary(self):
        self.desktop(body='[Desktop Entry]\nType=Application\nName=Bad\nExec=host-only\n')
        outside = Path(self.temporary.name) / 'outside-bin'
        outside.mkdir()
        (outside / 'host-only').write_bytes(elf())
        (outside / 'host-only').chmod(0o755)
        with mock.patch.dict(os.environ, {'PATH': str(outside), 'XDG_DATA_HOME': '/host/secret'}):
            report = self.run_audit()
        self.assertEqual(report['status'], 'FAIL_STAGED_CHECKS')
        self.assertNotIn(str(outside), json.dumps(report))

    def test_environment_requires_explicit_safe_paths(self):
        for update in ({'PATH': 'relative'}, {'XDG_DATA_DIRS': '/usr/share:'},
                       {'XDG_CONFIG_HOME': '/../escape'}, {'icon_size': True},
                       {'terminal_argv': 'terminal -e'}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                desktop.environment(dict(self.env, **update))
        with self.assertRaises(ValueError):
            desktop.Stage('/')


if __name__ == '__main__':
    unittest.main()
