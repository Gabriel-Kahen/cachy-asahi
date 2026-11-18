# SPDX-License-Identifier: MIT
"""Actor-fenced exact config controls and a synthetic result envelope."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ACTORS = []


def fence(event, unused):
    if event.startswith(('socket.', 'subprocess.', 'os.fork', 'os.posix_spawn', 'os.exec', 'os.system', 'os.kill')):
        ACTORS.append(event)
        raise AssertionError('actor forbidden: ' + event)


sys.addaudithook(fence)


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


V = load('verify')
H = load('build_kernel')
L = load('lane')


def actor(temp):
    return {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': L.REPO, 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a'*40, 'KERNEL_SOURCE_SHA': 'a'*40,
            'GITHUB_RUN_ID': '834917', 'RUNNER_TEMP': str(temp)}


class Controls(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=HERE)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def fixture(self):
        for name in V.PINS.keys() - {'diagnostic.fragment'}:
            shutil.copyfile(HERE/name, self.root/name)
        pins, config, diagnostic, base = V.source(self.root)
        out = self.root/'built'
        (out/'build/arch/arm64/boot').mkdir(parents=True)

        def seal(path, body):
            path.write_bytes(body)
            return dict(path=str(path), **V.pin(body))

        prefix = ['/usr/bin/make', '-C', str(out/'linux-asahi-7.1.13-3'), 'O='+str(out/'build'), 'ARCH=arm64', 'LLVM=1']
        commands = []
        for target, name in ((['allnoconfig'], 'configure.log'), (['-j2', 'Image'], 'build.log')):
            path = out/name
            body = b'Model command log, no run performed.\n'
            proof = seal(path, body)
            commands.append(dict(argv=prefix+target, log=str(path), returncode=0,
                                 log_sha256=proof['sha256'], log_bytes=len(body)))
        header = bytearray(64)
        header[56:60] = b'ARM\x64'
        struct.pack_into('<Q', header, 24, 4)
        receipt = dict(status='BUILT_ONLY', kernel_build='PASS', guest_boot='NOT RUN', hardware='NOT RUN',
                       performance='NOT RUN', profile=V.PROFILE, kernel_release=V.RELEASE, source_commit=V.SOURCE,
                       boot_diagnostics=True, tools=base['tools'], build_environment=base['build_environment'],
                       archive=dict(path='/wild/held/archive', **V.ARCHIVE),
                       module_policy={'CONFIG_MODULES': 'n', 'external_modules_allowed': False},
                       config_check={'page_size': 16384, 'modules': 'DISABLED', 'all_fragment_values_match': True,
                                     'explicit_fragment_delta': V.DELTA},
                       helper=dict(path=str(self.root/'build_kernel.py'), **pins['build_kernel.py']),
                       fragment=dict(path=str(self.root/'kernel.fragment'), **pins['kernel.fragment']),
                       diagnostic_fragment=seal(out/'diagnostic.fragment', diagnostic), commands=commands,
                       config=seal(out/'build/.config', config),
                       image=seal(out/'build/arch/arm64/boot/Image', bytes(header)),
                       image_check={'header_page_size': 16384, 'flags': 4, 'boot': 'NOT RUN'},
                       system_map=seal(out/'build/System.map', b'ffff11 t virtinput_probe\nffff25 d virtio_input_driver\nffff31 t inet6_init\n'))
        (out/'build-receipt.json').write_text(json.dumps(receipt))
        return out, receipt, seal

    def test_source_and_helper_agree_on_byte_exact_config(self):
        _, expected, _, base = V.source(HERE)
        self.assertEqual(H.expected_tools(), base['tools'])
        self.assertEqual(H.expected_config(), expected)
        config = self.root/'config'
        config.write_bytes(expected)
        self.assertEqual(H.config_check(config, True)['explicit_fragment_delta'], V.DELTA)
        with self.assertRaisesRegex(ValueError, 'must equal the exact reviewed'):
            H.config_check(config, False)

    def test_refuse_changed_ksm_module_input_or_compiler_facts(self):
        cfg = self.root/'config'
        orig = H.expected_config()
        for before, after in ((b'CONFIG_KSM=y', b'# CONFIG_KSM is not set'),
                              (b'CONFIG_VIRTIO_INPUT=y', b'CONFIG_VIRTIO_INPUT=m'),
                              (b'CONFIG_IPV6=y', b'# CONFIG_IPV6 is not set'),
                              (b'CONFIG_PROC_FS=y', b'# CONFIG_PROC_FS is not set'),
                              (b'# CONFIG_MODULES is not set', b'CONFIG_MODULES=y'),
                              (b'CONFIG_CLANG_VERSION=180103', b'CONFIG_CLANG_VERSION=220108')):
            self.assertIn(before, orig)
            cfg.write_bytes(orig.replace(before, after))
            with self.assertRaisesRegex(ValueError, 'must equal the exact reviewed'):
                H.config_check(cfg, True)

    def test_complete_reader_emits_same_contract_family(self):
        out, receipt, _ = self.fixture()
        profile = V.complete(out)
        self.assertEqual(set(profile), {'schema_version', 'profile', 'release', 'architecture', 'page_size',
                         'source_revision', 'archive_sha256', 'helper_sha256', 'fragment_sha256',
                         'diagnostic_fragment_sha256', 'Image', 'config', 'modules'})
        self.assertEqual(profile['config'], V.EXPECTED_CONFIG)
        self.assertEqual(profile['profile'], V.PROFILE)
        self.assertEqual(profile['Image']['sha256'], receipt['image']['sha256'])

    def test_refuse_resealed_unlinked_symbol_map(self):
        out, receipt, seal = self.fixture()
        receipt['system_map'] = seal(out/'build/System.map', b'ffff11 t unrelated_probe\n')
        (out/'build-receipt.json').write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'linked virtio-input driver'):
            V.complete(out)

    def test_refuse_resealed_missing_ipv6_init(self):
        out, receipt, seal = self.fixture()
        receipt['system_map'] = seal(out/'build/System.map', b'ffff11 t virtinput_probe\nffff25 d virtio_input_driver\n')
        (out/'build-receipt.json').write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'linked built-in IPv6 initialization'):
            V.complete(out)

    def test_refuse_resealed_collateral_config_change(self):
        out, receipt, seal = self.fixture()
        cfg = out/'build/.config'
        receipt['config'] = seal(cfg, cfg.read_bytes().replace(b'CONFIG_KSM=y', b'CONFIG_KSM=n'))
        (out/'build-receipt.json').write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'differs from the exact reviewed'):
            V.complete(out)

    def test_refuse_receipt_tool_drift(self):
        out, receipt, _ = self.fixture()
        receipt['tools']['clang']['sha256'] = '0'*64
        (out/'build-receipt.json').write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'exact source, tools'):
            V.complete(out)

    def test_refuse_source_fragment_drift(self):
        out, _, _ = self.fixture()
        frag = self.root/'kernel.fragment'
        frag.write_bytes(frag.read_bytes().replace(b'CONFIG_KSM=y', b'CONFIG_KSM=n'))
        with self.assertRaisesRegex(ValueError, 'exact combined kernel source pins'):
            V.complete(out)


    def test_ci_admission_joins_first_attempt_and_exact_source(self):
        env = actor(self.root)
        self.assertEqual(L.identity(env), dict(repository=L.REPO, source='a'*40, run='834917', attempt=1))
        for wrong in ({'GITHUB_RUN_ATTEMPT': '2'}, {'GITHUB_EVENT_NAME': 'push'},
                      {'KERNEL_SOURCE_SHA': 'b'*40}, {'GITHUB_REPOSITORY': 'unrelated/project'}):
            with self.assertRaisesRegex(ValueError, 'exact first, manually selected'):
                L.identity(env | wrong)

    def test_original_acquisition_keeps_receipt_private(self):
        receipt = self.root/'acquisition.json'
        value = {'status': 'FETCHED_HASH_VERIFIED', 'fixture': True}
        def acquire(path):
            raw = json.dumps(value)
            path.write_text(raw)
            print(raw)
            return value
        screen = io.StringIO()
        with redirect_stdout(screen):
            self.assertEqual(L.acquire_private(SimpleNamespace(acquire=acquire), receipt), value)
        self.assertEqual(screen.getvalue(), '')
        self.assertEqual(json.loads(receipt.read_text()), value)

    def test_owned_stage_does_not_acquire_with_tool_drift(self):
        screen = io.StringIO()
        out = self.root/'keyboard-kernel'
        with patch.dict(os.environ, actor(self.root), clear=True), patch.object(os, 'uname',
                return_value=SimpleNamespace(machine='aarch64')), patch.object(os, 'geteuid', return_value=4242),                 patch.object(os, 'getuid', return_value=4242), patch.object(shutil, 'which', return_value=None),                 redirect_stdout(screen):
            self.assertEqual(L.build(out, None), 1)
        roles, status = screen.getvalue().splitlines()
        differences = json.loads(roles.removeprefix('HOLD_KERNEL_TOOL_ROLES '))
        self.assertEqual(set(differences), set(H.TOOLS))
        self.assertTrue(all(row['status'] == 'MISSING_OR_UNREADABLE' for row in differences.values()))
        self.assertEqual(status, 'HOLD_KERNEL_BUILD_TOOLS')
        self.assertEqual({p.name for p in out.iterdir()}, {'owner.json', 'tools.json', 'failure.json'})
        self.assertEqual(json.loads((out/'failure.json').read_text())['stage'], 'TOOLS')


    def test_only_perl_drift_requests_the_private_recovery(self):
        screen = io.StringIO()
        out = self.root/'keyboard-kernel'
        host = dict(H.expected_tools(), perl=None)
        with patch.dict(os.environ, actor(self.root), clear=True), \
                patch.object(os, 'uname', return_value=SimpleNamespace(machine='aarch64')), \
                patch.object(os, 'geteuid', return_value=4242), patch.object(os, 'getuid', return_value=4242), \
                patch.object(L, 'load', return_value=H), patch.object(H, 'tool_inventory', return_value=host), \
                patch.object(H, 'recover_perl', side_effect=ValueError('modeled recovery stop')) as recover, \
                redirect_stdout(screen):
            self.assertEqual(L.build(out, None), 1)
        recover.assert_called_once_with(out)
        self.assertEqual(json.loads((out/'failure.json').read_text())['stage'], 'TOOLS_PERL_BASE_RECOVERY')
        self.assertIn('KERNEL_TOOL_HOST_PERL_REPLACED ', screen.getvalue())
        self.assertFalse((out/'inputs').exists())

    def test_only_historical_perl_path_can_move(self):
        held = H.expected_tools()
        expected = H.expected_tools({'perl': dict(held['perl'], path='/owned/perl-base/usr/bin/perl')})
        self.assertEqual({role for role in held if held[role] != expected[role]}, {'perl'})
        self.assertEqual(held['perl']['sha256'], expected['perl']['sha256'])
        self.assertEqual(H.tool_environment({'perl': expected['perl']}),
                         dict(PATH='/owned/perl-base/usr/bin:/usr/lib/llvm-18/bin:/usr/bin:/bin',
                              PERL5LIB='/owned/perl-base/usr/lib/aarch64-linux-gnu/perl-base'))
        altered = dict(expected, perl=dict(expected['perl'], sha256='0'*64))
        differences = H.tool_difference(altered, expected)
        self.assertEqual(differences['perl']['status'], 'IDENTITY_DIFFERS')
        self.assertTrue(differences['perl']['same_path'])
        self.assertNotIn('/owned/', json.dumps(differences))

    def test_reject_ambient_private_perl_claim_with_no_archive(self):
        out, receipt, _ = self.fixture()
        receipt['private_perl'] = {'archive': H.PERL_DEB}
        (out/'build-receipt.json').write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'exact source, tools'):
            V.complete(out)


if __name__ == '__main__':
    outcome = unittest.main(exit=False)
    assert not ACTORS, ACTORS
    raise SystemExit(not outcome.result.wasSuccessful())
