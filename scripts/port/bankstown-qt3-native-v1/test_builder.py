#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fenced MODEL controls; the admission/engine boundary is synthetic.

Real builder, frozen recipe/package predicates and entry body are used. No
container, compiler, executable artifact or genuine Root authority is exercised.
"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import struct
import tarfile
import tempfile
import time
import types
import unittest
from unittest.mock import patch


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {
            'os.system', 'os.exec', 'os.posix_spawn', 'os.fork', 'fcntl.flock'}:
        raise AssertionError('MODEL forbids operational event: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CHECKER = 'scripts/checks/package_checks.py'
BUILD = 'scripts/build/build.py'
HELD_FIXTURES = {
    CHECKER: (ROOT / 'scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source'
              / 'scripts/ci/llhttp-reference-native-source/base/runtime' / CHECKER),
    BUILD: ROOT / 'scripts/ci/maintained-native/native' / BUILD,
}
spec = importlib.util.spec_from_file_location('bankstown_builder_model', HERE / 'builder.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class Executor:
    def __init__(self, f, mutation=None):
        self.f = f
        self.facts = {**f.d['owned_executor'], 'uid': 1000, 'gid': 1000}
        self.calls = []
        self.row = None
        self.present = False
        self.mutation = mutation

    def run(self, step, argv, timeout, expected=0):
        self.calls.append((step, argv, timeout))
        data = b''
        if step == 'image':
            data = B.encode([{'Id': self.f.d['image']['id'], 'Architecture': 'arm64', 'Os': 'linux'}])
        elif step == 'daemon':
            data = B.encode({'ID': 'MODEL-engine', 'Architecture': 'aarch64', 'OSType': 'linux',
                             'NCPU': 4, 'MemTotal': 8 * 1024**3, 'MemoryLimit': True,
                             'SwapLimit': True, 'PidsLimit': True, 'CgroupVersion': '2'})
        elif step == 'create':
            args = argv[3:]
            values = lambda key: [args[i + 1] for i, a in enumerate(args[:-1]) if a == key]
            labels = dict(v.split('=', 1) for v in values('--label'))
            mounts = []
            for v in values('--mount'):
                fields = v.split(',')
                pairs = dict(part.split('=', 1) for part in fields if '=' in part)
                mounts.append({'Type': 'bind', 'Source': pairs['src'], 'Destination': pairs['dst'],
                               'RW': 'readonly' not in fields})
            self.row = {'Id': 'c' * 64, 'Name': '/' + values('--name')[0], 'Image': self.f.d['image']['id'],
                        'Config': {'User': values('--user')[0], 'Labels': labels,
                                   'Entrypoint': ['/bin/bash'], 'Cmd': [args[-1]], 'Env': values('--env')},
                        'HostConfig': {'ReadonlyRootfs': True, 'NetworkMode': 'none', 'Privileged': False,
                                       'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
                                       'Memory': int(values('--memory')[0]), 'MemorySwap': int(values('--memory-swap')[0]),
                                       'NanoCpus': int(values('--cpus')[0]) * 10**9,
                                       'PidsLimit': int(values('--pids-limit')[0]),
                                       'Tmpfs': {'/tmp': 'rw,nosuid,nodev,exec,size=4g'}},
                        'Mounts': mounts, 'State': {'Running': False, 'ExitCode': 0, 'OOMKilled': False}}
            self.present = True
            data = b'c' * 64 + b'\n'
        elif step.startswith('inspect') or step == 'retire-inspect':
            data = B.encode([self.row])
        elif step == 'attach':
            self.f.outputs()
        elif step == 'retire-query':
            data = b'c' * 64 + b'\n' if self.present else b''
        elif step == 'retire-remove':
            self.present = False
        stderr = b'MODEL diagnostic\n' if step == 'attach' else b''
        row = {'step': step, 'argv': argv, 'expected': expected, 'exit': expected,
               'output_pin': B.pin(data), 'stderr_pin': B.pin(stderr), 'timeout_seconds': timeout,
               'supervision_cap_seconds': timeout, 'passed': True,
               'supervision': {'exit': expected, 'reaped': True, 'ownership': 'REAPED',
                               'group_census': 'EMPTY_TWICE', 'output_complete': True,
                               'timeout': False, 'signals': [], 'error': None, 'seconds': 0.001}}
        if self.mutation:
            self.mutation(step, row, self)
        return {'stdout': data, 'stderr': stderr, 'receipt': row}


class Fixture:
    def __init__(self, root):
        self.source, self.output = root / 'source', root / 'output'
        self.source.mkdir()
        self.materials = {}
        for path, expected in B.HELD.items():
            source = HELD_FIXTURES.get(path, ROOT / path)
            pin = self.add(path, source.read_bytes())
            B.need(pin['sha256'] == expected, 'MODEL held helper pin differs: ' + path)
        for name in ('admission.py', 'profile.py', 'builder.py', 'entry.sh'):
            self.add(B.PREFIX + name, (HERE / name).read_bytes())
        guard = self.materials[B.RECIPE + 'build_guard.py']['sha256']
        self.srcinfo = (f'pkgbase = bankstown\npkgname = bankstown\npkgver = 1.1.0\npkgrel = 5\n'
                        f'arch = aarch64\nlicense = MIT\nsource = build_guard.py\nsha256sums = {guard}\n').encode()
        self.add(B.RECIPE + '.SRCINFO', self.srcinfo)
        self.pkgbuild = b'# inert MODEL PKGBUILD, never sourced\n'
        self.add(B.RECIPE + 'PKGBUILD', self.pkgbuild)
        self.add(B.RECIPE + 'PACKAGING.LICENSE', b'MODEL notice\n')
        self.add(B.RECIPE + 'SOURCE-CANDIDATE.md', b'MODEL document\n')
        for name in ('native-rust-inputs.json', 'native-toolchain-requirements.json', 'COMPONENTS.json', 'cargo-vendor-117.tar.xz'):
            self.add(B.RECIPE + name, b'MODEL admitted data\n')
        for filename, prefix, names in (
            ('bankstown-1.1.0.tar.gz', 'bankstown-1.1.0/', ('LICENSE', 'bankstown.ttl', 'manifest.ttl')),
            ('audio-rust-notices-v1.tar.xz', 'audio-rust-notices/bankstown/',
             ('THIRD-PARTY.md', 'THIRD-PARTY-LICENSES.txt', 'SOURCE.md'))):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                for name in names:
                    body = b'MODEL TTL\n' if name.endswith('.ttl') else b'MODEL notice\n'
                    row = tarfile.TarInfo(prefix + name)
                    row.size = len(body)
                    archive.addfile(row, io.BytesIO(body))
            self.add(B.RECIPE + filename, stream.getvalue())
        packages = {p: '1' for p in ('make', 'pacman', 'fakeroot', 'gcc', 'binutils', 'python', 'rust', 'bash', 'coreutils')}
        self.inventory = ''.join(f'{n} {v}\n' for n, v in sorted(packages.items())).encode()
        inventory_pin = self.add('model/inventory.lock', self.inventory)
        catalog_pin = self.add('model/catalog.json', B.encode({'packages': {
            'rust': {'metadata': {'/.PKGINFO': {'pkgver': ['1']}}}}}))
        self.d = {'materials': self.materials, 'catalog': catalog_pin,
                  'expires_at': int(time.time()) + 3600,
                  'image': {'id': 'sha256:' + 'a' * 64, 'inventory': inventory_pin},
                  'owned_executor': {'code_pin': B.pin(b'MODEL executor bytes'),
                                     'docker_endpoint': 'unix:///MODEL/docker.sock', 'engine_id': 'MODEL-engine'},
                  'source': {'commit': 'b' * 40, 'ref': 'refs/heads/MODEL'},
                  'tool_paths': {'cargo': '/usr/bin/cargo', 'rustc': '/usr/bin/rustc', 'cc': '/usr/bin/cc', 'ld': '/usr/bin/ld'},
                  'selected_files': {'/usr/bin/MODEL': B.pin(b'MODEL tool DATA')},
                  'resources': {'wall_seconds': 60, 'command_seconds': 10, 'cpus': 4,
                                'memory_bytes': 4 * 1024**3, 'pids': 512, 'max_output_bytes': 4 * 1024**2}}
        self.admission = b'MODEL boundary, not a Root trial'
        self.profile = root / 'profile.json'
        self.profile.write_bytes(B.encode(dict(schema=1, purpose='bankstown-1.1.0-5-native-toolchain',
            compiler_version='1.99.0', target='aarch64-unknown-linux-gnu', tools=self.d['tool_paths'],
            files=self.d['selected_files'], admission_pin=B.pin(self.admission), catalog_pin=catalog_pin,
            image=self.d['image'], legal='HELD', key_freshness='HELD', **B.FINAL)))

    def add(self, relative, body):
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        self.materials[relative] = B.pin(body)
        return self.materials[relative]

    def outputs(self):
        p = self.output / 'artifacts'
        (p / 'packages.lock').write_bytes(self.inventory)
        for name in ('environment.txt', 'config.sha256', 'makepkg.conf', 'pacman.conf'):
            (p / name).write_bytes(b'MODEL data\n')
        (p / 'generated.SRCINFO').write_bytes(self.srcinfo)
        elf = bytearray(376)
        struct.pack_into('<16sHHIQQQIHHHHHH', elf, 0, b'\x7fELF\x02\x01' + b'\0' * 10,
                         3, 183, 1, 0, 64, 128, 0, 64, 56, 1, 64, 3, 0)
        struct.pack_into('<IIQQQQQQ', elf, 64, 1, 5, 0, 0, 0, len(elf), len(elf), 16384)
        strings = b'\0lv2_descriptor\0'
        elf[320:320 + len(strings)] = strings
        struct.pack_into('<IIQQQQIIQQ', elf, 192, 0, 3, 0, 0, 320, len(strings), 0, 0, 1, 0)
        struct.pack_into('<IIQQQQIIQQ', elf, 256, 0, 11, 0, 0, 352, 24, 1, 0, 8, 24)
        struct.pack_into('<IBBHQQ', elf, 352, 1, 0x12, 0, 1, 0, 0)
        guard = B.load(HERE.parents[2] / B.RECIPE / 'build_guard.py', 'model_held_guard')
        receipt = guard.receipt(bytes(elf), 'aarch64-unknown-linux-gnu',
                                B.pin(self.profile.read_bytes())['sha256'], 'NATIVE_SOURCE_BUILD')
        members = {'.PKGINFO': b'pkgname = bankstown\npkgbase = bankstown\npkgver = 1.1.0-5\narch = aarch64\nlicense = MIT\n',
                   '.BUILDINFO': ('format = 2\npkgname = bankstown\npkgver = 1.1.0-5\npkgarch = aarch64\n'
                                  'pkgbuild_sha256sum = ' + B.pin(self.pkgbuild)['sha256'] + '\n').encode(),
                   '.MTREE': b'MODEL mtree\n',
                   'usr/lib/lv2/bankstown.lv2/bankstown.so': bytes(elf),
                   'usr/share/doc/bankstown/BUILD-INPUTS.json': B.encode(receipt)}
        members.update({'usr/lib/lv2/bankstown.lv2/' + n: b'MODEL TTL\n' for n in ('bankstown.ttl', 'manifest.ttl')})
        members.update({'usr/share/licenses/bankstown/' + n: b'MODEL notice\n' for n in (
            'LICENSE', 'THIRD-PARTY.md', 'THIRD-PARTY-LICENSES.txt', 'SOURCE.md', 'PACKAGING.LICENSE')})
        members['usr/share/doc/bankstown/SOURCE-CANDIDATE.md'] = b'MODEL document\n'
        with tarfile.open(p / 'bankstown-1.1.0-5-aarch64.pkg.tar.gz', 'w:gz') as archive:
            for name, body in members.items():
                row = tarfile.TarInfo(name)
                row.size, row.mode = len(body), 0o755 if name.endswith('.so') else 0o644
                archive.addfile(row, io.BytesIO(body))

    def run(self, executor):
        actual_load = B.load
        fake = types.SimpleNamespace(validate_trial=lambda *a, **k: self.d, pin=B.pin,
                                     decoded=lambda raw, *a: json.loads(raw))
        with patch.object(B, 'load', side_effect=lambda path, name: fake if name == 'bankstown_trial_admission_v1' else actual_load(path, name)), \
                patch.object(B.os, 'uname', return_value=types.SimpleNamespace(sysname='Linux', machine='aarch64')), \
                patch.object(B.os, 'getuid', return_value=1000), patch.object(B.os, 'geteuid', return_value=1000), \
                patch.object(B.os, 'getgid', return_value=1000), patch.object(B.os, 'getegid', return_value=1000):
            return B.build_private_test(admission_raw=self.admission,
                admission_sha256=B.pin(self.admission)['sha256'], profile_path=self.profile,
                profile_sha256=B.pin(self.profile.read_bytes())['sha256'], executor=executor,
                source_root=self.source, output=self.output)


class BuilderControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bankstown-qt3-MODEL-')
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name))

    def test_real_builder_static_checks_and_finite_forwarding(self):
        e = Executor(self.f)
        result = self.f.run(e)
        self.assertEqual(result['status'], 'PASS_PRIVATE_TEST_BUILD_DATA_ONLY')
        self.assertIsNone(result['Root_acceptance'])
        self.assertFalse(result['hardware_acceptance'])
        self.assertTrue(result['owned_container_absence_verified'])
        self.assertFalse(e.present)
        create = next(argv for step, argv, _ in e.calls if step == 'create')
        self.assertIn('BANKSTOWN_NATIVE_TOOLS_PROFILE=/bankstown-qt3-control/profile.json', create)
        self.assertIn('BANKSTOWN_NATIVE_TOOLS_SHA256=' + B.pin(self.f.profile.read_bytes())['sha256'], create)
        self.assertFalse(any(str(self.f.source) in a for a in create))
        self.assertFalse((self.f.output / 'control/source/.git').exists())
        rows = json.loads((self.f.output / 'commands/commands.json').read_bytes())
        self.assertEqual(rows, result['commands'])
        self.assertEqual((self.f.output / 'commands/attach.stderr').read_bytes(), b'MODEL diagnostic\n')

    def test_null_admission_refuses_before_executor(self):
        e = Executor(self.f)
        with self.assertRaises((ValueError, TypeError)):
            B.build_private_test(admission_raw=b'null', admission_sha256=B.pin(b'null')['sha256'],
                profile_path=self.f.profile, profile_sha256='0' * 64, executor=e,
                source_root=self.f.source, output=self.f.output)
        self.assertEqual(e.calls, [])

    def test_executor_binding_refuses_before_commands(self):
        e = Executor(self.f)
        e.facts['docker_endpoint'] = 'unix:///wrong.sock'
        with self.assertRaisesRegex(ValueError, 'ACTUAL_EXECUTOR'):
            self.f.run(e)
        self.assertEqual(e.calls, [])

    def test_changed_material_refuses_before_commands(self):
        (self.f.source / 'model/catalog.json').write_bytes(b'{}')
        e = Executor(self.f)
        with self.assertRaisesRegex(ValueError, 'FILE_PIN_DIFFERS'):
            self.f.run(e)
        self.assertEqual(e.calls, [])

    def test_symlink_material_refuses_before_commands(self):
        path = self.f.source / 'model/catalog.json'
        path.unlink()
        path.symlink_to('/dev/null')
        e = Executor(self.f)
        with self.assertRaisesRegex(ValueError, 'UNALIASED'):
            self.f.run(e)
        self.assertEqual(e.calls, [])

    def test_non_natural_attach_retires_and_refuses(self):
        def mutate(step, row, e):
            if step == 'attach':
                row['supervision']['signals'] = ['TERM']
        e = Executor(self.f, mutate)
        with self.assertRaisesRegex(ValueError, 'NATURAL_COMMAND'):
            self.f.run(e)
        self.assertFalse(e.present)
        self.assertFalse((self.f.output / 'result.json').exists())

    def test_receipt_pin_drift_retires_and_refuses(self):
        def mutate(step, row, e):
            if step == 'attach':
                row['stderr_pin'] = B.pin(b'wrong')
        e = Executor(self.f, mutate)
        with self.assertRaisesRegex(ValueError, 'ACTUAL_RECEIPT_JOIN'):
            self.f.run(e)
        self.assertFalse(e.present)

    def test_unsafe_container_limits_never_remove_unknown(self):
        def mutate(step, row, e):
            if step == 'create':
                e.row['HostConfig']['MemorySwap'] += 1
        e = Executor(self.f, mutate)
        with self.assertRaisesRegex(ValueError, 'EXACT_CONTAINER_LIMITS'):
            self.f.run(e)
        self.assertNotIn('retire-remove', [step for step, _, _ in e.calls])

    def test_empty_query_does_not_invent_absence(self):
        def mutate(step, row, e):
            if step == 'attach':
                e.present = False
        with self.assertRaisesRegex(ValueError, 'OWNED_CONTAINER_RECOVERY'):
            self.f.run(Executor(self.f, mutate))

    def test_inventory_drift_refuses_after_owned_cleanup(self):
        def mutate(step, row, e):
            if step == 'attach':
                (self.f.output / 'artifacts/packages.lock').write_bytes(b'wrong 1\n')
        e = Executor(self.f, mutate)
        with self.assertRaisesRegex(ValueError, 'ACTUAL_IMAGE_INVENTORY_DIFFERS'):
            self.f.run(e)
        self.assertFalse(e.present)
        self.assertFalse((self.f.output / 'result.json').exists())

    def test_profile_mount_mutation_refuses_ownership_mutation(self):
        def mutate(step, row, e):
            if step == 'create':
                e.row['Mounts'][0]['RW'] = True
        e = Executor(self.f, mutate)
        with self.assertRaisesRegex(ValueError, 'EXACT_CONTAINER_MOUNTS'):
            self.f.run(e)
        self.assertNotIn('retire-remove', [step for step, _, _ in e.calls])

    def test_create_handoff_failure_recovers_exact_owned_present_container(self):
        def mutate(step, row, e):
            if step == 'create':
                raise ValueError('MODEL interrupted create handoff')
        e = Executor(self.f, mutate)
        with self.assertRaisesRegex(ValueError, 'interrupted create'):
            self.f.run(e)
        self.assertFalse(e.present)
        self.assertIn('retire-after-cid', [step for step, _, _ in e.calls])

    def test_finite_deadline_refuses_before_dispatch(self):
        e = Executor(self.f)
        with patch.object(B.time, 'monotonic', side_effect=[0, 61]):
            with self.assertRaisesRegex(ValueError, 'MATERIAL_DEADLINE'):
                self.f.run(e)
        self.assertEqual(e.calls, [])

    def test_genuine_tmpfs_inspection_row_is_accepted(self):
        def mutate(step, row, e):
            if step == 'create':
                e.row['Mounts'].append({'Type': 'tmpfs', 'Destination': '/tmp', 'RW': True})
        self.assertEqual(self.f.run(Executor(self.f, mutate))['status'], 'PASS_PRIVATE_TEST_BUILD_DATA_ONLY')

    def test_original_attach_exception_survives_cleanup_hold(self):
        def mutate(step, row, e):
            if step == 'attach':
                row['supervision']['signals'] = ['TERM']
                e.present = False
        with self.assertRaisesRegex(ValueError, 'NATURAL_COMMAND_REQUIRED') as held:
            self.f.run(Executor(self.f, mutate))
        self.assertIn('Owned cleanup also held', held.exception.__notes__[0])
        self.assertEqual(json.loads((self.f.output / 'cleanup-HOLD.json').read_bytes())['status'], 'HOLD')

    def test_wrong_profile_inside_native_receipt_is_refused(self):
        actual = B.validate_outputs
        def wrong(*args):
            args = list(args)
            args[-2] = '0' * 64
            return actual(*args)
        with patch.object(B, 'validate_outputs', side_effect=wrong):
            with self.assertRaisesRegex(ValueError, 'PAYLOAD_ROOT_PROFILE_ASSOCIATION'):
                self.f.run(Executor(self.f))

    def test_notice_drift_from_admitted_source_refuses(self):
        def mutate(step, row, e):
            if step == 'attach':
                (self.f.output / 'inputs/PACKAGING.LICENSE').write_bytes(b'changed notice')
        with self.assertRaisesRegex(ValueError, 'SOURCE_OR_NOTICE_PAYLOAD_DIFFERS'):
            self.f.run(Executor(self.f, mutate))

    def test_entry_verifies_profile_then_guard_then_normal_makepkg_entry(self):
        text = (HERE / 'entry.sh').read_text()
        self.assertLess(text.index('profile.py verify'), text.index('/inputs/build_guard.py native-tools'))
        self.assertLess(text.index('/inputs/build_guard.py native-tools'), text.index('exec /bin/bash'))
        self.assertIn('--root /', text)
        self.assertNotIn('--nodeps', text)


if __name__ == '__main__':
    unittest.main()
