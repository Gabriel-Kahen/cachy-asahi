#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert guest controls. ALPM, codec and ARM actor execution is forbidden."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('c01_install16k_guest', HERE / 'guest.py')
G = importlib.util.module_from_spec(spec); spec.loader.exec_module(G)


def selected():
    return {'schema': 1, 'nonce': 'a' * 32, 'source_commit': 'b' * 40,
            'accepted_origin': copy.deepcopy(G.ORIGIN), 'host_page_size': 4096,
            'helper_sha256': G.HELPER, 'inventory_sha256': G.INVENTORY,
            'packages': copy.deepcopy(G.PACKAGES), 'base_sentinels': copy.deepcopy(G.BASE_SENTINELS)}


class Fixture:
    """Private fake filesystem/backend, never an alternate runtime entrypoint."""
    VARIANTS = ('baseline', 'lto')
    META = {'.PKGINFO', '.BUILDINFO', '.MTREE'}
    name = staticmethod(lambda v: 'cachy-asahi-zlib-' + v)
    prefix = staticmethod(lambda v: Path('/usr/lib/cachy-asahi/experiments/zlib-' + v))
    read = staticmethod(lambda p: Path(p).read_bytes())
    sha = staticmethod(lambda b: hashlib.sha256(b).hexdigest())

    def __init__(self, root):
        self.root = root; self.active = {}; self.rows = []; self.calls = []
        self.initial = {'fixture%03d' % i: '1' for i in range(341)}
        self.lock = ''.join(k + ' ' + v + '\n' for k, v in sorted(self.initial.items())).encode()
        self.c01 = root / 'c01'; (self.c01 / 'output').mkdir(parents=True)
        (self.c01 / 'packages.lock').write_bytes(self.lock)
        (root / 'builder-disabled-hooks').mkdir()
        for path in G.SENTINELS:
            target = self.placed(path); target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(path.encode())
        self.members = {}
        for filename in G.PACKAGES:
            v = filename.split('-')[0]
            self.members[filename] = {str(self.prefix(v).relative_to('/')) + '/bin/probe': filename.encode(),
                                     'usr/share/licenses/' + self.name(v) + '/LICENSE.zlib': b'fake notice',
                                     '.PKGINFO': b'explicitly fake metadata'}
        self.corrupt_sentinel = self.corrupt_payload = self.leave_license = self.inventory_drift = False
        self.short_workload = False

    def placed(self, path):
        return self.root / Path(path).relative_to('/')

    def record(self, label, argv=()):
        self.rows.append({'label': label, 'argv': list(argv), 'status': 'PASS', 'group_absent': True,
                          'leader_held_until_group_inspection': True})

    def run(self, label, argv, timeout):
        self.calls.append((label, argv, timeout)); self.record(label, argv)
        if '-U' in argv:
            for path in argv[argv.index('-U') + 1:]:
                filename = Path(path).name; v = filename.split('-')[0]; self.active[v] = int(filename.split('-')[1][1:])
                for relative, data in self.members[filename].items():
                    if relative in self.META: continue
                    target = self.placed('/' + relative); target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
            if self.corrupt_sentinel: self.placed(G.SENTINELS[0]).write_bytes(b'changed system library')
            if self.corrupt_payload: self.placed(self.prefix('baseline') / 'bin/probe').write_bytes(b'changed package probe')
        else:
            for package in argv[argv.index('-R') + 1:]:
                v = package.removeprefix('cachy-asahi-zlib-'); self.active.pop(v)
                shutil.rmtree(self.placed(self.prefix(v)))
                if not self.leave_license: shutil.rmtree(self.placed('/usr/share/licenses/' + package))
        return b''

    def inventory(self, runner, label):
        self.record(label)
        rows = {**self.initial, **{self.name(v): '1.3.2-' + str(r) for v, r in self.active.items()}}
        if self.inventory_drift and label != 'initial-inventory': rows['unselected-system-change'] = '2'
        return rows

    def workload(self, runner, variants, phase):
        n = len(variants)
        for i in range(25 * n + 21 * n * n): self.record(phase + '-synthetic-' + str(i))
        return {'encodes': 21 * n - int(self.short_workload), 'cross_decodes': 21 * n * n,
                'strict_rejections': 3 * n, 'probe': {v: {'explicit_fixture': True} for v in variants}}

    def execute(self, report=None):
        s = selected(); s['base_sentinels'] = {p: self.sha(self.placed(p).read_bytes()) for p in G.SENTINELS}
        with patch.object(G, 'INVENTORY', self.sha(self.lock)), \
             patch.object(G, 'archives', return_value=(self.members, copy.deepcopy(G.PACKAGES))):
            return G.lifecycle(s, self, self, self.c01, self.root, report=report)


class GuestControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.launch = patch('subprocess.Popen', side_effect=AssertionError('source controls cannot execute actors'))
        self.launch.start(); self.addCleanup(self.launch.stop)

    def facts(self):
        return {'sysname': 'Linux', 'machine': 'aarch64', 'kernel': G.RELEASE,
                'page_size': 16384, 'auxv_page_size': 16384, 'uid': 0, 'euid': 0,
                'cmdline': ['console=ttyAMA0', 'c01install16k=' + 'a' * 32], 'network': ['lo']}

    def test_closed_exact_selection_and_origin(self):
        self.assertEqual(G.selection(selected()), selected())
        for key, value in [('host_page_size', 16384), ('host_page_size', True), ('host_page_size', None),
                           ('schema', True), ('source_commit', 'HEAD'), ('helper_sha256', '0' * 64),
                           ('inventory_sha256', '0' * 64), ('base_sentinels', {}), ('extra', 1)]:
            bad = selected(); bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises((ValueError, TypeError)):
                G.selection(bad)
        for key in G.ORIGIN:
            bad = selected(); bad['accepted_origin'][key] = 'foreign'
            with self.subTest(origin=key), self.assertRaises(ValueError): G.selection(bad)

    def test_changed_missing_or_extra_archive_selection_refused(self):
        for kind in ('changed', 'missing', 'extra'):
            value = selected(); first = next(iter(value['packages']))
            if kind == 'changed': value['packages'][first]['sha256'] = '0' * 64
            elif kind == 'missing': del value['packages'][first]
            else: value['packages']['replacement.pkg.tar.xz'] = value['packages'][first]
            with self.subTest(kind=kind), self.assertRaises(ValueError): G.selection(value)

    def test_separate_guest_sysconf_auxv_kernel_root_and_boot_nonce(self):
        self.assertEqual(G.require_facts(selected(), self.facts())['page_size'], 16384)
        for key, value in [('page_size', 4096), ('auxv_page_size', 4096), ('auxv_page_size', True),
                           ('machine', 'x86_64'), ('kernel', 'stock4k'), ('uid', 1000), ('euid', 1000),
                           ('sysname', 'Darwin'), ('network', ['lo', 'eth0'])]:
            facts = self.facts(); facts[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): G.require_facts(selected(), facts)
        for tokens in ([], ['c01install16k=' + 'b' * 32], ['c01install16k=' + 'a' * 32] * 2,
                       ['c01install16k=' + 'a' * 32, 'c01install16k']):
            facts = self.facts(); facts['cmdline'] = tokens
            with self.subTest(tokens=tokens), self.assertRaises(ValueError): G.require_facts(selected(), facts)

    def test_real_host_facts_are_observed_without_changing_pages(self):
        facts = G.actual_facts()
        self.assertEqual(facts['page_size'], __import__('os').sysconf('SC_PAGE_SIZE'))
        self.assertEqual(facts['auxv_page_size'], facts['page_size'])
        if facts['machine'] != 'aarch64' or facts['page_size'] != 16384 or facts['uid'] != 0 or facts['kernel'] != G.RELEASE:
            with self.assertRaises(ValueError): G.require_facts(selected(), facts)

    def test_orchestration_eight_ordered_phases_and_645_command_slots(self):
        fixture = Fixture(self.root); result = fixture.execute()
        self.assertEqual([(p['phase'], p['versions']) for p in result['phases']], G.PHASES)
        self.assertEqual(len(fixture.rows), 645)
        self.assertEqual([p[0].removeprefix('pacman-') for p in fixture.calls], [p[0] for p in G.PHASES])
        self.assertTrue(all(timeout == 60 and '--noscriptlet' in argv for _, argv, timeout in fixture.calls))
        self.assertEqual(fixture.active, {})
        self.assertTrue(result['original_packages_preserved'] and result['system_sentinels_preserved'])

    def test_system_sentinel_or_inventory_change_stops_first_transaction(self):
        for flag, reason in [('corrupt_sentinel', 'sentinel'), ('inventory_drift', 'inventory')]:
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as td:
                fixture = Fixture(Path(td)); setattr(fixture, flag, True)
                with self.assertRaisesRegex(ValueError, reason): fixture.execute()
                self.assertEqual(len(fixture.calls), 1)

    def test_wrong_initial_sentinel_refused_before_mutation(self):
        fixture = Fixture(self.root)
        s = selected(); s['base_sentinels'] = {}
        with patch.object(G, 'INVENTORY', fixture.sha(fixture.lock)), \
             patch.object(G, 'archives', return_value=(fixture.members, G.PACKAGES)), \
             self.assertRaisesRegex(ValueError, 'accepted system sentinels'):
            G.lifecycle(s, fixture, fixture, fixture.c01, fixture.root)
        self.assertEqual(fixture.calls, [])

    def test_payload_or_missing_codec_coverage_cannot_pass(self):
        for flag, reason in [('corrupt_payload', 'payload'), ('short_workload', 'workload count')]:
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as td:
                fixture = Fixture(Path(td)); setattr(fixture, flag, True)
                with self.assertRaisesRegex(ValueError, reason): fixture.execute()

    def test_license_removal_and_completed_phase_failure_diagnostics(self):
        fixture = Fixture(self.root); fixture.leave_license = True; report = {'phases': []}
        with self.assertRaisesRegex(ValueError, 'license remains'): fixture.execute(report)
        self.assertEqual([p['phase'] for p in report['phases']], [p[0] for p in G.PHASES[:4]])

    def test_corrupt_archive_and_helper_refused_before_code_or_unpack(self):
        c01 = self.root / 'c01'; (c01 / 'packages').mkdir(parents=True)
        for filename in G.PACKAGES: (c01 / 'packages' / filename).write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'archive bytes differ'):
            G.archives(selected(), SimpleNamespace(package_members=lambda *_: self.fail('unpack before pin')), c01)
        (c01 / 'package_variants.py').write_text('raise AssertionError("must never import")')
        with self.assertRaisesRegex(ValueError, 'helper before import'): G.helper(c01)

    def test_symlink_oversized_input_or_nonregular_log_refused(self):
        real = self.root / 'real'; real.write_bytes(b'a')
        link = self.root / 'link'; link.symlink_to(real)
        with self.assertRaises(ValueError): G.ordinary(link)
        with self.assertRaises(ValueError): G.ordinary(real, 0)
        out = self.root / 'out'; out.mkdir(); (out / 'directory').mkdir()
        with self.assertRaisesRegex(ValueError, 'log namespace'): G.log_bound(out)

    def test_single_frame_nonce_base64_json_and_bound(self):
        report = {'nonce': 'a' * 32, 'status': G.PASS, 'guest': self.facts()}
        sink = io.BytesIO(); stream = SimpleNamespace(buffer=sink)
        with patch.object(G.sys, 'stdout', stream): G.emit(report)
        prefix, nonce, data = sink.getvalue().strip().split(b' ', 2)
        self.assertEqual((prefix, nonce), (b'C01_INSTALL16K', b'a' * 32))
        self.assertEqual(json.loads(base64.b64decode(data, validate=True)), report)
        report['oversized'] = 'x' * (2 * 1024**2)
        with patch.object(G.sys, 'stdout', stream), self.assertRaisesRegex(ValueError, 'guest frame'): G.emit(report)


if __name__ == '__main__':
    unittest.main()
