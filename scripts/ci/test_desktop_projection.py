"""Historical records and synthetic current-product projection fixtures; no actors."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


projection = module('desktop_projection')
exporter = module('integration_export')
# Metadata and the two exact stdout/argv/hash records from native run 38212287407.
# Other stdout values are synthetic: they are not projected by this helper.
ACTUAL_METADATA = {'application_runtime': {'mako': {'installed': False,
                                  'reason': 'no bar/notifier session launched; optional app not in '
                                            'frozen lock',
                                  'status': 'NOT RUN'},
                         'waybar': {'installed': False,
                                    'reason': 'no bar/notifier session launched; optional app not '
                                              'in frozen lock',
                                    'status': 'NOT RUN'}},
 'archive_sha256': '5d33320b55c2b3c778b94c128980c2d07d3fbcf466b3ab91ad8a706ff538ee81',
 'checks': {'GTK3_CSS_parser': {'display_created': False,
                                'parser': 'GTK3 CssProvider',
                                'status': 'PASS'},
            'Hyprland_default_and_optional_verifier': 'PASS',
            'installed_payload': 'PASS',
            'lua_syntax': 'PASS',
            'mako_source_audited_subset_only': 'PASS',
            'runtime_inventory': 'PASS',
            'waybar_strict_JSON_syntax_only': 'PASS'},
 'container_arch': 'aarch64',
 'container_facts': {'arch': 'aarch64',
                     'capabilities': {'CapBnd': 0, 'CapEff': 0, 'CapPrm': 0},
                     'image_id': 'sha256:24f41b02bfad714dfe862ea986f412ff05c20166016804eefaeaece3b895f81b',
                     'interfaces': ['lo'],
                     'marker': True,
                     'marker_env': '1',
                     'mounts': {'/': {'flags': ['ro', 'relatime'], 'type': 'overlay'},
                                '/dev': {'flags': ['rw', 'nosuid'], 'type': 'tmpfs'},
                                '/dev/mqueue': {'flags': ['rw',
                                                          'nosuid',
                                                          'nodev',
                                                          'noexec',
                                                          'relatime'],
                                                'type': 'mqueue'},
                                '/dev/pts': {'flags': ['rw', 'nosuid', 'noexec', 'relatime'],
                                             'type': 'devpts'},
                                '/dev/shm': {'flags': ['rw',
                                                       'nosuid',
                                                       'nodev',
                                                       'noexec',
                                                       'relatime'],
                                             'type': 'tmpfs'},
                                '/etc/hostname': {'flags': ['ro', 'relatime'], 'type': 'ext4'},
                                '/etc/hosts': {'flags': ['ro', 'relatime'], 'type': 'ext4'},
                                '/etc/resolv.conf': {'flags': ['ro', 'relatime'], 'type': 'ext4'},
                                '/inputs': {'flags': ['ro', 'relatime'], 'type': 'ext4'},
                                '/out': {'flags': ['rw', 'relatime'], 'type': 'ext4'},
                                '/proc': {'flags': ['rw', 'nosuid', 'nodev', 'noexec', 'relatime'],
                                          'type': 'proc'},
                                '/proc/acpi': {'flags': ['ro', 'relatime'], 'type': 'tmpfs'},
                                '/proc/bus': {'flags': ['ro',
                                                        'nosuid',
                                                        'nodev',
                                                        'noexec',
                                                        'relatime'],
                                              'type': 'proc'},
                                '/proc/fs': {'flags': ['ro',
                                                       'nosuid',
                                                       'nodev',
                                                       'noexec',
                                                       'relatime'],
                                             'type': 'proc'},
                                '/proc/interrupts': {'flags': ['rw', 'nosuid'], 'type': 'tmpfs'},
                                '/proc/irq': {'flags': ['ro',
                                                        'nosuid',
                                                        'nodev',
                                                        'noexec',
                                                        'relatime'],
                                              'type': 'proc'},
                                '/proc/kcore': {'flags': ['rw', 'nosuid'], 'type': 'tmpfs'},
                                '/proc/keys': {'flags': ['rw', 'nosuid'], 'type': 'tmpfs'},
                                '/proc/latency_stats': {'flags': ['rw', 'nosuid'], 'type': 'tmpfs'},
                                '/proc/scsi': {'flags': ['ro', 'relatime'], 'type': 'tmpfs'},
                                '/proc/sys': {'flags': ['ro',
                                                        'nosuid',
                                                        'nodev',
                                                        'noexec',
                                                        'relatime'],
                                              'type': 'proc'},
                                '/proc/sysrq-trigger': {'flags': ['ro',
                                                                  'nosuid',
                                                                  'nodev',
                                                                  'noexec',
                                                                  'relatime'],
                                                        'type': 'proc'},
                                '/proc/timer_list': {'flags': ['rw', 'nosuid'], 'type': 'tmpfs'},
                                '/runner': {'flags': ['ro', 'relatime'], 'type': 'ext4'},
                                '/sys': {'flags': ['ro', 'nosuid', 'nodev', 'noexec', 'relatime'],
                                         'type': 'sysfs'},
                                '/sys/firmware': {'flags': ['ro', 'relatime'], 'type': 'tmpfs'},
                                '/sys/fs/cgroup': {'flags': ['ro',
                                                             'nosuid',
                                                             'nodev',
                                                             'noexec',
                                                             'relatime'],
                                                   'type': 'cgroup2'},
                                '/tmp': {'flags': ['rw', 'nosuid', 'nodev', 'relatime'],
                                         'type': 'tmpfs'}},
                     'namespaces': {'mnt': 'mnt:[4026532263]',
                                    'net': 'net:[4026532270]',
                                    'pid': 'pid:[4026532268]',
                                    'user': 'user:[4026531837]'},
                     'no_new_privileges': '1',
                     'nonce': 'f33ec1fcad41512d89a6e0b283afd96c',
                     'runner': '/runner/desktop.py',
                     'uid': 1001},
 'graphics_acceleration': 'NOT RUN',
 'hardware_validation': 'NOT RUN',
 'headless_compositor': {'attempted': False,
                         'reason': 'pinned Aquamarine 0.15.1 requires a DRM-backed GBM allocator; '
                                   '/dev/dri is excluded',
                         'status': 'BLOCKED'},
 'installed_payload_sha256': {'usr/share/cachy-asahi/hyprland/hyprland.lua': 'f900ffbfdea86acc686299fd9ef88a235fb4822f7177afe75a43369ca48d158b',
                              'usr/share/cachy-asahi/hyprland/mako.conf': 'c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504',
                              'usr/share/cachy-asahi/hyprland/waybar.css': 'a97930965a4e622adc920491c7d433a803173bb6e644c4c3c88efb79187e11d5',
                              'usr/share/cachy-asahi/hyprland/waybar.json': '4c7adb2deb0403fefc4562d39105635cebfc44ce88e44fe84c4a90a00b2be3c0',
                              'usr/share/doc/cachy-asahi-hyprland-settings/README.md': '3edac178cb92d6d06b21fe4832bbbce5f7a55ed4dde8925ac0815c5350e2c525',
                              'usr/share/licenses/cachy-asahi-hyprland-settings/LICENSE': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7',
                              'usr/share/licenses/cachy-asahi-hyprland-settings/NOTICE': '7c108a66b5a4807f8fe7696ef1b1011386b37774fb94e674dd37c7e1dec7b9e4'},
 'optimization_acceptance': 'NOT RUN',
 'portal_audio_session': 'NOT RUN',
 'record_type': 'desktop-container-verification',
 'runtime_lock_sha256': '89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f',
 'schema_version': 1,
 'status': 'desktop-container-verifier-pass'}
ACTUAL_ARGV = [['/usr/bin/pacman', '-Q'],
 ['/usr/bin/bsdtar',
  '-xOf',
  '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz',
  '.PKGINFO'],
 ['/usr/bin/bsdtar', '-tf', '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz'],
 ['/usr/bin/bsdtar',
  '-xOf',
  '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz',
  'usr/share/cachy-asahi/hyprland/hyprland.lua'],
 ['/usr/bin/pacman', '-Qoq', '/usr/share/cachy-asahi/hyprland/hyprland.lua'],
 ['/usr/bin/bsdtar',
  '-xOf',
  '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz',
  'usr/share/cachy-asahi/hyprland/mako.conf'],
 ['/usr/bin/pacman', '-Qoq', '/usr/share/cachy-asahi/hyprland/mako.conf'],
 ['/usr/bin/bsdtar',
  '-xOf',
  '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz',
  'usr/share/cachy-asahi/hyprland/waybar.css'],
 ['/usr/bin/pacman', '-Qoq', '/usr/share/cachy-asahi/hyprland/waybar.css'],
 ['/usr/bin/bsdtar',
  '-xOf',
  '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz',
  'usr/share/cachy-asahi/hyprland/waybar.json'],
 ['/usr/bin/pacman', '-Qoq', '/usr/share/cachy-asahi/hyprland/waybar.json'],
 ['/usr/bin/bsdtar',
  '-xOf',
  '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz',
  'usr/share/doc/cachy-asahi-hyprland-settings/README.md'],
 ['/usr/bin/pacman', '-Qoq', '/usr/share/doc/cachy-asahi-hyprland-settings/README.md'],
 ['/usr/bin/bsdtar',
  '-xOf',
  '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz',
  'usr/share/licenses/cachy-asahi-hyprland-settings/LICENSE'],
 ['/usr/bin/pacman', '-Qoq', '/usr/share/licenses/cachy-asahi-hyprland-settings/LICENSE'],
 ['/usr/bin/bsdtar',
  '-xOf',
  '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz',
  'usr/share/licenses/cachy-asahi-hyprland-settings/NOTICE'],
 ['/usr/bin/pacman', '-Qoq', '/usr/share/licenses/cachy-asahi-hyprland-settings/NOTICE'],
 ['/usr/bin/Hyprland', '--version'],
 ['/usr/bin/luac', '-p', '/usr/share/cachy-asahi/hyprland/hyprland.lua'],
 ['/usr/bin/Hyprland',
  '--verify-config',
  '--config',
  '/usr/share/cachy-asahi/hyprland/hyprland.lua'],
 ['/usr/bin/Hyprland',
  '--verify-config',
  '--config',
  '/tmp/cachy-asahi-desktop-verify-60tzycfp/optional-startup.lua'],
 ['/usr/bin/python3',
  '/runner/desktop.py',
  '--gtk-css',
  '/usr/share/cachy-asahi/hyprland/waybar.css']]
ACTUAL_ROWS = {19: {'argv': ['/usr/bin/Hyprland',
               '--verify-config',
               '--config',
               '/usr/share/cachy-asahi/hyprland/hyprland.lua'],
      'error': None,
      'log_sha256': '6eb6aeeff4fe9770851e25252b70b8dcaabffccbe8e2eb6d28e7836f3bce248d',
      'returncode': 0,
      'stdout': '\x1b[1;32mDEBUG \x1b[0m]: User-specified config location: '
                "'/usr/share/cachy-asahi/hyprland/hyprland.lua'\n"
                '\x1b[1;32mDEBUG \x1b[0m]: [cfg] Config is either explicit or special.\n'
                '\x1b[1;32mDEBUG \x1b[0m]: [cfg] Config is lua, loading lua mgr\n'
                '\x1b[1;32mDEBUG \x1b[0m]: Disabling stdout logs (debug.enable_stdout_logs = 0). '
                'Further logs will be written to /hyprland.log\n'
                '\n'
                '\n'
                '======== Config parsing result:\n'
                '\n'
                'config ok\n'},
 20: {'argv': ['/usr/bin/Hyprland',
               '--verify-config',
               '--config',
               '/tmp/cachy-asahi-desktop-verify-60tzycfp/optional-startup.lua'],
      'error': None,
      'log_sha256': '040c8b52c64a471ec581a259592459a36165c7a8f4251a642051e7e8dff9a7f6',
      'returncode': 0,
      'stdout': '\x1b[1;32mDEBUG \x1b[0m]: User-specified config location: '
                "'/tmp/cachy-asahi-desktop-verify-60tzycfp/optional-startup.lua'\n"
                '\x1b[1;32mDEBUG \x1b[0m]: [cfg] Config is either explicit or special.\n'
                '\x1b[1;32mDEBUG \x1b[0m]: [cfg] Config is lua, loading lua mgr\n'
                '\x1b[1;32mDEBUG \x1b[0m]: Disabling stdout logs (debug.enable_stdout_logs = 0). '
                'Further logs will be written to /hyprland.log\n'
                '\n'
                '\n'
                '======== Config parsing result:\n'
                '\n'
                'config ok\n'}}


def make_receipt():
    """Actual metadata/argv and exact selected logs; other stdout is synthetic."""
    value = copy.deepcopy(ACTUAL_METADATA)
    value['commands'] = [
        {'argv': copy.deepcopy(argv), 'returncode': 0, 'error': None,
         'stdout': 'synthetic fixture\n', 'log_sha256': hashlib.sha256(b'synthetic fixture\n').hexdigest()}
        for argv in ACTUAL_ARGV]
    for index, row in ACTUAL_ROWS.items():
        value['commands'][index] = copy.deepcopy(row)
    return value


def make_current_product_receipt():
    """SYNTHETIC desktop2 contract using copied historical verifier log text.

    This is not native evidence: archive/helper hashes and new command stdout
    are synthetic. ACTUAL_* remain the unchanged historical0.1.0-1 records.
    """
    value = make_receipt()
    archive = '/inputs/cachy-asahi-hyprland-settings-0.1.0-2-any.pkg.tar.xz'
    old_archive = '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz'
    for row in value['commands']:
        row['argv'] = [archive if item == old_archive else item for item in row['argv']]
    helper = 'usr/bin/cachy-asahi-screenshot'
    value['installed_payload_sha256'][helper] = hashlib.sha256(b'SYNTHETIC screenshot helper').hexdigest()
    value['archive_sha256'] = hashlib.sha256(b'SYNTHETIC desktop0.1.0-2 archive').hexdigest()
    extra = []
    for argv in (['/usr/bin/bsdtar', '-xOf', archive, helper], ['/usr/bin/pacman', '-Qoq', '/' + helper]):
        stdout = 'SYNTHETIC current-product helper command\n'
        extra.append({'argv': argv, 'returncode': 0, 'error': None, 'stdout': stdout,
                      'log_sha256': hashlib.sha256(stdout.encode()).hexdigest()})
    value['commands'][3:3] = extra
    return value


def write_bound_fixture(raw):
    """Write a SYNTHETIC current-product fixture and matching test authority."""
    raw = Path(raw)
    (raw / 'desktop').mkdir(parents=True, exist_ok=True)
    value = make_current_product_receipt()
    facts = value['container_facts']
    authority = {'source_commit': 'a' * 40, 'image_id': facts['image_id'], 'nonce': facts['nonce'],
                 'archive_sha256': value['archive_sha256'], 'runtime_lock_sha256': value['runtime_lock_sha256']}
    (raw / 'desktop/desktop.json').write_text(json.dumps(value, indent=2) + '\n')
    for index in (21, 22):
        (raw / f'desktop/command-{index}.txt').write_bytes(value['commands'][index]['stdout'].encode())
    return value, authority


class DesktopProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.raw = self.root / 'raw'
        self.value, self.authority = write_bound_fixture(self.raw)
        for name in ('Popen', 'run', 'check_output'):
            guard = patch.object(subprocess, name, side_effect=AssertionError('subprocess tripwire'))
            guard.start(); self.addCleanup(guard.stop)
        guard = patch.object(socket.socket, 'connect', side_effect=AssertionError('socket tripwire'))
        guard.start(); self.addCleanup(guard.stop)
        self.write()

    def write(self):
        (self.raw / 'desktop/desktop.json').write_text(json.dumps(self.value, indent=2) + '\n')
        for index in (21, 22):
            (self.raw / f'desktop/command-{index}.txt').write_bytes(self.value['commands'][index]['stdout'].encode())

    def altered_log(self, text, index=21):
        row = self.value['commands'][index]
        row['stdout'] = text
        row['log_sha256'] = hashlib.sha256(text.encode()).hexdigest()
        self.write()

    def refused(self):
        with self.assertRaises(projection.Refused) as error:
            projection.project(self.raw, self.authority)
        self.assertLess(len(str(error.exception)), 100)

    def test_synthetic_current_fixture_copied_logs_reproduce_refusal_and_bound_projection(self):
        rejected = exporter.export_evidence(self.raw, self.root / 'before')
        self.assertEqual(rejected['evidence_export'], 'FAIL')
        self.assertEqual({row['path'] for row in rejected['rejected']},
                         {'desktop/command-21.txt', 'desktop/command-22.txt'})
        original = {path: path.read_bytes() for path in (self.raw / 'desktop').iterdir()}
        projected, index = projection.project(self.raw, self.authority)
        self.assertEqual(set(projected), {'desktop/command-21.txt', 'desktop/command-22.txt'})
        self.assertEqual(index['authority'], self.authority)
        self.assertEqual(index['receipt_status'], 'desktop-container-verifier-pass')
        self.assertEqual(index['hardware_validation'], 'NOT RUN')
        for item in index['files']:
            self.assertEqual(item['raw_sha256'], ACTUAL_ROWS[item['command_index'] - 2]['log_sha256'])
            self.assertEqual(item['raw_bytes'], len(original[self.raw / item['path']]))
            self.assertEqual(item['public_sha256'], hashlib.sha256(projected[item['path']]).hexdigest())
            self.assertEqual(item['public_bytes'], len(projected[item['path']]))
            self.assertEqual(projected[item['path']], original[self.raw / item['path']].replace(
                b'\x1b[1;32m', b'').replace(b'\x1b[0m', b''))
        self.assertEqual(original, {path: path.read_bytes() for path in original})
        selected = self.root / 'selected'; (selected / 'desktop').mkdir(parents=True)
        (selected / 'desktop/desktop.json').write_bytes(original[self.raw / 'desktop/desktop.json'])
        for path, data in projected.items():
            (selected / path).write_bytes(data)
        (selected / 'desktop-terminal-projections.json').write_text(json.dumps(index))
        self.assertEqual(exporter.export_evidence(selected, self.root / 'after')['evidence_export'], 'PASS')
        self.assertEqual(json.loads(original[self.raw / 'desktop/desktop.json']), self.value)

    def test_authority_missing_extra_bad_types_and_values(self):
        original = copy.deepcopy(self.authority)
        for key in original:
            for bad in (None, True, 123, 'bad', '', 'A' * len(original[key])):
                self.authority = {**original, key: bad}; self.refused()
            self.authority = dict(original); del self.authority[key]; self.refused()
        self.authority = {**original, 'unaccepted': 'x'}; self.refused()

    def test_image_nonce_archive_runtime_bindings(self):
        for target, key in ((self.value['container_facts'], 'nonce'),
                            (self.value['container_facts'], 'image_id'),
                            (self.value, 'archive_sha256'), (self.value, 'runtime_lock_sha256')):
            old = target[key]
            target[key] = ('sha256:' if key == 'image_id' else '') + 'b' * (32 if key == 'nonce' else 64)
            self.write(); self.refused(); target[key] = old

    def test_source_commit_is_external_authority_without_invented_receipt_field(self):
        self.authority['source_commit'] = 'b' * 40
        _, index = projection.project(self.raw, self.authority)
        self.assertEqual(index['authority']['source_commit'], 'b' * 40)
        self.assertNotIn('source_commit', self.value)
        self.value['source_commit'] = 'b' * 40; self.write(); self.refused()

    def test_failure_receipts_and_acceptance_flags_are_never_rewritten(self):
        original = copy.deepcopy(self.value)
        for key, bad in (('status', 'FAILED'), ('schema_version', True), ('record_type', 'other'),
                         ('container_arch', 'x86_64'), ('hardware_validation', 'PASS'),
                         ('optimization_acceptance', 'PASS'), ('graphics_acceleration', 'PASS')):
            self.value = {**copy.deepcopy(original), key: bad}; self.write(); self.refused()
            self.assertEqual(json.loads((self.raw / 'desktop/desktop.json').read_bytes())[key], bad)
        self.value = copy.deepcopy(original); self.value['checks']['lua_syntax'] = 'FAIL'
        self.write(); self.refused()

    def test_missing_extra_nested_fields_and_wrong_container_isolation(self):
        original = copy.deepcopy(self.value)
        for key, bad in (('nonce', 'wrong'), ('uid', 0), ('uid', True), ('marker', False),
                         ('interfaces', ['lo', 'eth0']), ('no_new_privileges', '0'),
                         ('runner', '/tmp/desktop.py'), ('capabilities', {'CapEff': 0}),
                         ('capabilities', {'CapEff': 0, 'CapPrm': 1, 'CapBnd': 0}),
                         ('namespaces', {'mnt': 'mnt:[1]'})):
            self.value = copy.deepcopy(original); self.value['container_facts'][key] = bad
            self.write(); self.refused()
        for key in original['container_facts']:
            self.value = copy.deepcopy(original); del self.value['container_facts'][key]
            self.write(); self.refused()
        self.value = copy.deepcopy(original); self.value['container_facts']['extra'] = True
        self.write(); self.refused()

    def test_mount_payload_application_and_headless_contract(self):
        original = copy.deepcopy(self.value)
        for mutate in (lambda v: v['container_facts']['mounts'].update({'/dev/dri': {'type': 'ext4', 'flags': ['rw']}}),
                       lambda v: v['container_facts']['mounts']['/']['flags'].append('rw'),
                       lambda v: v['installed_payload_sha256'].pop(projection.PAYLOAD[0]),
                       lambda v: v['application_runtime']['waybar'].update(status='PASS'),
                       lambda v: v['headless_compositor'].update(attempted=True),
                       lambda v: v['checks']['GTK3_CSS_parser'].update(display_created=0)):
            self.value = copy.deepcopy(original); mutate(self.value); self.write(); self.refused()

    def test_exact_command_count_order_schema_and_all_statuses(self):
        original = copy.deepcopy(self.value)
        for index in range(24):
            self.value = copy.deepcopy(original); self.value['commands'][index]['returncode'] = 1
            self.write(); self.refused()
        for mutate in (lambda rows: rows.pop(), lambda rows: rows.append(copy.deepcopy(rows[0])),
                       lambda rows: rows[21].update(error='timeout'), lambda rows: rows[22].update(returncode=True),
                       lambda rows: rows[21].update(extra='unknown'),
                       lambda rows: rows[20]['argv'].append('--unaccepted'),
                       lambda rows: rows.reverse()):
            self.value = copy.deepcopy(original); mutate(self.value['commands']); self.write(); self.refused()

    def test_exact_default_and_safe_optional_argv(self):
        original = copy.deepcopy(self.value)
        for path in ('/tmp/cachy-asahi-desktop-verify-../optional-startup.lua',
                     '/tmp/cachy-asahi-desktop-verify-a/../optional-startup.lua',
                     '/tmp/cachy-asahi-desktop-verify-a\\b/optional-startup.lua',
                     '/tmp/other/optional-startup.lua', '/tmp/cachy-asahi-desktop-verify-a/other.lua'):
            self.value = copy.deepcopy(original); self.value['commands'][22]['argv'][3] = path
            self.write(); self.refused()
        for index, change in ((21, '/usr/bin/other'), (22, '/usr/bin/other')):
            self.value = copy.deepcopy(original); self.value['commands'][index]['argv'][0] = change
            self.write(); self.refused()
        self.value = copy.deepcopy(original); self.value['commands'][21]['argv'][3] = '/tmp/hyprland.lua'
        self.write(); self.refused()

    def test_log_hash_and_full_stdout_must_match_original_bytes(self):
        path = self.raw / 'desktop/command-21.txt'
        original = path.read_bytes()
        path.write_bytes(original + b'altered\n'); self.refused()
        path.write_bytes(original)
        self.value['commands'][21]['stdout'] += 'altered\n'
        (self.raw / 'desktop/desktop.json').write_text(json.dumps(self.value)); self.refused()
        self.value['commands'][21] = copy.deepcopy(ACTUAL_ROWS[19])
        self.value['commands'][21]['log_sha256'] = '0' * 64
        self.write(); self.refused()

    def test_only_sgr_is_removed_and_line_structure_preserved(self):
        context = "DEBUG ]: User-specified config location: '" + projection.DEFAULT + "'\n"
        self.altered_log('\x1b[32;1m' + context + 'config ok\x1b[0m\r\n\tUnicode café\n')
        logs, _ = projection.project(self.raw, self.authority)
        self.assertEqual(logs['desktop/command-21.txt'], (context + 'config ok\r\n\tUnicode café\n').encode())

    def test_stdout_config_context_and_standalone_success_are_bound(self):
        original = ACTUAL_ROWS[19]['stdout']
        for text in (original.replace(projection.DEFAULT, '/tmp/different.lua'),
                     original.replace('config ok\n', 'not config ok\n')):
            self.altered_log(text); self.refused()

    def test_osc_cursor_controls_del_format_and_missing_success_refused(self):
        for text in ('\x1b]8;;https://example.test\x07config ok', '\x1b[2Jconfig ok',
                     '\x1b[1Aconfig ok', 'config ok\x00', 'config ok\x08', 'config ok\x7f',
                     'config ok\u200b', 'config ok\u202e', '\x1b[31config ok', 'config failed'):
            self.altered_log(text); self.refused()

    def test_raw_plain_and_encoded_credentials_refused_without_redaction(self):
        for text in ('config ok\npassword=DO-NOT-PUBLISH',
                     'config ok\npass\x1b[32mword\x1b[0m=DO-NOT-PUBLISH',
                     'config ok\n-----BEGIN PGP PRIVATE KEY BLOCK-----',
                     'config ok\nBearer DO-NOT-PUBLISH', 'config ok\npassword%3dDO-NOT-PUBLISH',
                     r'config ok password\u003dDO-NOT-PUBLISH', 'config ok password&#61;DO-NOT-PUBLISH',
                     'config ok pass%1b%5b32mword%1b%5b0m=DO-NOT-PUBLISH',
                     r'config ok pass\u200bword=DO-NOT-PUBLISH'):
            self.altered_log(text); self.refused()
            self.assertEqual((self.raw / 'desktop/command-21.txt').read_bytes(), text.encode())

    def test_unknown_logs_remain_unprojected_and_generic_export_refuses(self):
        extra = self.raw / 'desktop/command-24.txt'; extra.write_bytes(b'\x1b[32munknown\x1b[0m\n')
        logs, _ = projection.project(self.raw, self.authority)
        self.assertNotIn('desktop/command-24.txt', logs)
        for relative, data in logs.items():
            (self.raw / relative).write_bytes(data)
        exported = exporter.export_evidence(self.raw, self.root / 'unknown')
        self.assertEqual(exported['evidence_export'], 'FAIL')
        self.assertEqual(exported['rejected'][0]['path'], 'desktop/command-24.txt')

    def test_duplicate_nonfinite_nonobject_and_invalid_utf8_receipts(self):
        path = self.raw / 'desktop/desktop.json'
        for data in (b'[]', b'null', b'\xff', b'{"status":1,"status":2}',
                     b'{"nested":{"key":1,"key":2}}', b'{"value":NaN}'):
            path.write_bytes(data); self.refused()

    def test_regular_single_link_bounded_files_and_ancestors_required(self):
        for relative in ('desktop/desktop.json', 'desktop/command-21.txt', 'desktop/command-22.txt'):
            path = self.raw / relative; data = path.read_bytes()
            path.unlink(); path.symlink_to(self.root / 'missing'); self.refused()
            path.unlink(); path.write_bytes(data)
            linked = self.root / 'hardlinked'; os.link(path, linked); self.refused(); linked.unlink()
            path.write_bytes(b''); self.refused()
            path.write_bytes(b'x' * (projection.LIMIT + 1)); self.refused()
            path.unlink(); os.mkfifo(path); self.refused()
            path.unlink(); path.write_bytes(data)
        moved = self.root / 'moved'; (self.raw / 'desktop').rename(moved)
        (self.raw / 'desktop').symlink_to(moved, target_is_directory=True); self.refused()

    def test_file_replacement_during_open_and_read_refused(self):
        original_open = projection.os.open
        swapped = [False]
        def replacing(name, flags, **kwargs):
            if name == 'command-21.txt' and not swapped[0]:
                swapped[0] = True
                path = self.raw / 'desktop/command-21.txt'; path.unlink()
                path.symlink_to(self.root / 'missing')
            return original_open(name, flags, **kwargs)
        with patch.object(projection.os, 'open', side_effect=replacing):
            self.refused()

    def test_invalid_log_bytes_refused_even_if_hash_matches(self):
        path = self.raw / 'desktop/command-21.txt'; path.write_bytes(b'config ok\xff')
        self.value['commands'][21]['log_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.raw / 'desktop/desktop.json').write_text(json.dumps(self.value)); self.refused()
        with self.assertRaises(projection.Refused):
            projection._plain(b'config ok\xff')


    def test_historical_receipt_is_not_current_product_acceptance(self):
        historical = make_receipt()
        self.assertEqual(len(historical['commands']), 22)
        self.assertNotIn('usr/bin/cachy-asahi-screenshot', historical['installed_payload_sha256'])
        authority = {**self.authority, 'archive_sha256': historical['archive_sha256'],
                     'runtime_lock_sha256': historical['runtime_lock_sha256']}
        (self.raw / 'desktop/desktop.json').write_text(json.dumps(historical))
        for index in (19, 20):
            (self.raw / f'desktop/command-{index}.txt').write_bytes(historical['commands'][index]['stdout'].encode())
        with self.assertRaisesRegex(projection.Refused, 'payload-schema'):
            projection.project(self.raw, authority)




class DesktopLocalPayloadTests(unittest.TestCase):
    """Only fake command results and owned files: no packaging or session actors."""
    def check(self, change=None):
        source=Path(__file__).resolve().parents[2]/'packages/desktop/check-local.py'
        spec=importlib.util.spec_from_file_location('desktop_local_payload_fixture',source)
        checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
        recipe=source.parent/'cachy-asahi-hyprland-settings'
        expected={
            **{'usr/share/cachy-asahi/hyprland/'+n:(recipe/n).read_bytes()
               for n in ('hyprland.lua','waybar.json','waybar.css','mako.conf')},
            'usr/share/doc/cachy-asahi-hyprland-settings/README.md':(recipe/'README.md').read_bytes(),
            **{'usr/share/licenses/cachy-asahi-hyprland-settings/'+n:(recipe/n).read_bytes()
               for n in ('NOTICE','LICENSE')},
            'usr/bin/cachy-asahi-screenshot':(recipe/'cachy-asahi-screenshot').read_bytes()}
        if change is not None:change(expected)
        calls=[]
        def run(argv,cwd):
            calls.append(tuple(argv))
            if argv[0]=='makepkg' and '--nodeps' in argv:
                (Path(cwd)/'owned-fixture.pkg.tar.zst').write_bytes(b'inert mocked package fixture')
            return 0,b'owned command fixture'
        def output(argv,**kwargs):
            calls.append(tuple(argv))
            if argv[:2]==['bsdtar','-tf']:
                return '\n'.join(['.PKGINFO','.BUILDINFO','.MTREE','usr/',*expected])+'\n'
            if argv[:2]==['bsdtar','-xOf']:
                name=argv[-1]
                return expected[name] if name in expected else b'owned metadata fixture'
            if argv==['Hyprland','--version']:return 'owned version fixture'
            raise AssertionError(argv)
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp)/'evidence'
            with patch.object(checker,'EVIDENCE',evidence),patch.object(checker,'run',side_effect=run), \
                 patch.object(checker.subprocess,'check_output',side_effect=output):
                # Suppress only this command's JSON report in the unit test.
                import contextlib,io
                with contextlib.redirect_stdout(io.StringIO()):checker.main()
            record=json.loads((evidence/'host-packaging.json').read_text())
        return record,calls

    def test_exact_current_eight_file_payload_passes_both_mocked_runs(self):
        record,calls=self.check()
        self.assertEqual(len(record['runs']),2)
        for row in record['runs']:
            self.assertEqual(len(row['payload_sha256']),8)
            self.assertEqual(row['payload_sha256']['usr/bin/cachy-asahi-screenshot'],
                hashlib.sha256((Path(__file__).resolve().parents[2]/
                    'packages/desktop/cachy-asahi-hyprland-settings/cachy-asahi-screenshot').read_bytes()).hexdigest())
        self.assertTrue(record['payload_matches']);self.assertTrue(record['artifact_bytes_match'])
        self.assertEqual(record['installed'],'NOT RUN');self.assertEqual(record['hardware_tested'],'NOT RUN')
        self.assertEqual(calls.count(('makepkg','--nodeps','--noconfirm')),2)
        self.assertNotIn(('Hyprland','--version'),calls[:-1])

    def test_missing_changed_extra_or_hook_payloads_are_still_refused(self):
        cases=(lambda p:p.pop('usr/bin/cachy-asahi-screenshot'),
               lambda p:p.update({'usr/bin/cachy-asahi-screenshot':b'changed'}),
               lambda p:p.update({'usr/bin/unreviewed':b'extra'}),
               lambda p:p.update({'.INSTALL':b'owned inert hook marker'}))
        for change in cases:
            with self.subTest(change=change),self.assertRaisesRegex(RuntimeError,'package payload differs'):
                self.check(change)


if __name__ == '__main__':
    unittest.main()
