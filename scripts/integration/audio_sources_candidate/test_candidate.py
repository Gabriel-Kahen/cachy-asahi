#!/usr/bin/python3 -IB
# SPDX-License-Identifier: MIT
"""DATA/ingress/cleanup controls; never substitute for an installed pacman result."""
import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


D = load('audio_candidate_driver_tests', HERE / 'run.py')
G = load('audio_candidate_guest_tests', HERE / 'journey.py')
C = D.C
P = C.profile(HERE)
R = C.held(D.CHECKOUT / 'scripts/integration/repository.py', P['held_apis']['scripts/integration/repository.py'], 'audio_repository_control_api')
L = C.held(D.CHECKOUT / 'scripts/integration/lifecycle.py', P['held_apis']['scripts/integration/lifecycle.py'], 'audio_lifecycle_control_api')


def mount_fixture():
    row = lambda fs, access, root='/': dict(fs=fs, options={access}, root=root)
    result = {'/': row('overlay', 'ro'), '/inputs': row('ext4', 'ro'), '/runner': row('ext4', 'ro'),
        '/out': row('ext4', 'rw'),
        **{p: dict(fs='tmpfs', options={'rw', 'nosuid', 'nodev'}, root='/') for p in ('/scratch', '/test-home')},
        **{p: row('ext4', 'rw') for p in R.RUNTIME_FILES}}
    result.update({p: dict(fs=fs, options=set(flags), root='/null' if p in R.MASKED_NULL else
        p.removeprefix('/proc') if fs == 'proc' and p != '/proc' else '/') for p, (fs, flags) in R.STANDARD_MOUNTS.items()})
    return result


class CandidateBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='audio-candidate-data-control-')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)

    def test_pinned_original_apis_and_exact_payload_profile(self):
        self.assertEqual(len(P['payload']), 17)
        self.assertEqual(R.SAFE_CAPS, 0x400cb)
        for name, pin in P['held_apis'].items():
            raw = C.read(D.CHECKOUT / name, 128 * 1024)
            self.assertEqual(C.digest(raw), pin['sha256'])
        self.assertEqual(P['package']['sha256'], '9c5332015a0dca27469021fdfe7cda135ba2de62f7a60e1b969be03ab0ad6ec8')

    def test_rootless_identity_map_requires_real_nonroot_outer_identity(self):
        self.assertEqual(G.mappings('0 1000 1\n1 100000 65536\n', 1000)[0], (0, 1000, 1))
        for raw, uid in (('0 0 1', 0), ('0 1001 1', 1000), ('0 1000 65536', 1000), ('', 1000)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                G.mappings(raw, uid)

    def test_changed_api_and_profile_cannot_be_loaded(self):
        path = self.root / 'api.py'; path.write_text('raise RuntimeError("MUST_NOT_EXECUTE")\n')
        with self.assertRaisesRegex(ValueError, 'HELD_API_PIN'):
            C.held(path, P['held_apis']['scripts/integration/lifecycle.py'], 'untrusted_api')
        (self.root / 'profile.json').write_bytes(C.read(HERE / 'profile.json') + b' ')
        with self.assertRaisesRegex(ValueError, 'PROFILE_PIN'):
            C.profile(self.root)

    def test_read_rejects_links_hardlinks_special_and_oversize(self):
        source = self.root / 'source'; source.write_bytes(b'original')
        alias = self.root / 'alias'; alias.symlink_to(source)
        with self.assertRaises(ValueError): C.read(alias)
        alias.unlink(); os.link(source, alias)
        with self.assertRaises(ValueError): C.read(source)
        alias.unlink()
        with self.assertRaises(ValueError): C.read(source, 1)
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): C.read(fifo)

    def test_original_packet_alias_overlap_refuses_before_output_or_actor(self):
        packet = self.root / 'packet'; packet.mkdir(mode=0o700)
        sentinel = packet / 'sentinel'; sentinel.write_bytes(b'preserve original'); sentinel.chmod(0o600)
        archive = self.root / 'archive'; archive.write_bytes(b'inert')
        parent = self.root / 'other'; parent.mkdir()
        options = [(packet, parent / '..' / 'packet' / 'new-output'),
                   (parent / '..' / 'packet', self.root / 'outside-output'),
                   (packet, packet / 'nested-output')]
        for source, output in options:
            with self.subTest(output=output), mock.patch('subprocess.Popen', side_effect=AssertionError('actor forbidden')):
                with self.assertRaisesRegex(ValueError, 'ALIASED_OPERAND|OUTPUT_OVERLAPS_PACKET'):
                    D.execute(argparse.Namespace(archive=archive, packet=source, output=output))
            self.assertEqual(list(packet.iterdir()), [sentinel]); self.assertEqual(sentinel.read_bytes(), b'preserve original')
            self.assertFalse(output.exists())

    def test_inherited_dev_zero_mount_refusal_remains_unchanged(self):
        observed = mount_fixture(); R.validate_mounts(observed)
        observed['/dev/zero'] = dict(fs='tmpfs', options={'rw'}, root='/zero')
        with self.assertRaisesRegex(R.Refused, 'unexpected/nested.*dev/zero'):
            R.validate_mounts(observed)

    def test_host_only_exact_standard_devices_admitted_and_other_mounts_refuse(self):
        observed = mount_fixture()
        for path in G.STANDARD_DEVICE_MOUNTS:
            observed[path] = dict(fs='tmpfs', options={'rw', 'nosuid'}, root='/' + Path(path).name)
        self.assertEqual(set(G.host_mount_guard(R, observed)), set(G.STANDARD_DEVICE_MOUNTS))
        for path in ('/dev/mem', '/inputs/private-child', '/usr'):
            bad = dict(observed); bad[path] = dict(fs='tmpfs', options={'ro'}, root='/')
            with self.subTest(path=path), self.assertRaises((ValueError, R.Refused)):
                G.host_mount_guard(R, bad)
        observed['/dev/zero'] = dict(fs='tmpfs', options={'rw'}, root='/foreign')
        with self.assertRaisesRegex(ValueError, 'STANDARD_DEVICE_MOUNT_IDENTITY'):
            G.host_mount_guard(R, observed)

    def test_standard_device_alias_or_different_major_minor_refuses(self):
        observed = mount_fixture(); observed['/dev/zero'] = dict(fs='tmpfs', options={'rw'}, root='/zero')
        for mode, device in ((0o120777, os.makedev(1, 5)), (0o20666, os.makedev(1, 3))):
            with mock.patch.object(G.Path, 'lstat', return_value=type('Node', (), dict(st_mode=mode, st_rdev=device))()):
                with self.assertRaisesRegex(ValueError, 'STANDARD_DEVICE_NODE_IDENTITY'):
                    G.host_mount_guard(R, observed)

    def test_exact_capabilities_and_nnp_remain_required(self):
        status = '\n'.join(f'{name}: {R.SAFE_CAPS if name in ("CapEff", "CapPrm", "CapBnd") else 0:x}' for name in R.CAP_FIELDS) + '\nNoNewPrivs: 1\n'
        self.assertEqual(R.privileges(status)['CapEff'], R.SAFE_CAPS)
        for bad in (status.replace('NoNewPrivs: 1', 'NoNewPrivs: 0'), status.replace('400cb', '200400cb'),
                    status.replace('400cb', 'cb')):
            with self.assertRaises(R.Refused): R.privileges(bad)

    def test_noexec_copied_root_refuses_before_any_transaction(self):
        observed = mount_fixture(); G.executable_copied_root(observed)
        observed['/scratch']['options'].add('noexec')
        with self.assertRaisesRegex(ValueError, 'EXECUTABLE_PRIVATE_ALPM_ROOT_REQUIRED'):
            G.executable_copied_root(observed)

    def test_initial_guard_refusal_prevents_copy_signer_and_pacman(self):
        journey = G.Journey(P, {}, L, R)
        with mock.patch.object(G, 'observe', return_value={}), \
             mock.patch.object(G, 'guard', side_effect=R.Refused('unexpected/nested repository mount refused: /dev/zero')), \
             mock.patch.object(R, 'Integration') as copy_base, mock.patch.object(L, 'bounded_process') as commands:
            with self.assertRaises(R.Refused): journey.run()
            copy_base.assert_not_called(); commands.assert_not_called()
        self.assertEqual(journey.keydirs, [])
        for field in ('package_installation', 'reinstallation', 'removal'):
            self.assertEqual(journey.report[field], 'NOT_RUN')

    def test_cleanup_census_and_removal_failure_keep_structured_refusal(self):
        for failure in ('cleanup-census', 'remove-owned-container'):
            report = dict(status='initial')
            def command(step, argv):
                if step == failure: raise ValueError('injected DATA failure')
                return b'owned\n' if step == 'cleanup-census' else b'nonce\n'
            D.retire(report, command, True, 'owned', 'fixture=nonce', 'nonce')
            self.assertFalse(report['owned_container_retired'])
            self.assertEqual(report['status'], 'REFUSED_OR_FAILED_HOST_AUDIO_CANDIDATE')
            self.assertEqual(C.decode(C.encoded(report)), report)

    def test_cleanup_does_not_delete_label_collisions_or_wrong_owner(self):
        for names, owner in ((b'foreign\n', b'nonce\n'), (b'owned\n', b'wrong\n')):
            calls = []
            def command(step, argv):
                calls.append(step); return names if step == 'cleanup-census' else owner
            report = {}; D.retire(report, command, True, 'owned', 'fixture=nonce', 'nonce')
            self.assertFalse(report['owned_container_retired'])
            self.assertNotIn('remove-owned-container', calls)

    def test_unacknowledged_create_does_not_become_retired_from_empty_census(self):
        report = {}
        D.retire(report, lambda step, argv: b'', True, 'owned', 'fixture=nonce', 'nonce', acknowledged=False)
        self.assertFalse(report['owned_container_retired'])
        self.assertEqual(report['cleanup_state'], 'CREATE_OUTCOME_UNKNOWN')
        report = {}
        D.retire(report, lambda step, argv: b'', True, 'owned', 'fixture=nonce', 'nonce', acknowledged=True)
        self.assertTrue(report['owned_container_retired'])

    def test_zero_exit_with_pacman_ancillary_error_is_not_success(self):
        journey = G.Journey(P, {}, L, R)
        result = dict(reason='exit', returncode=0, stdout=b'error: could not execute ldconfig\n', stderr=b'', cleanup=dict(reaped=True, errors=[]))
        def path(value):
            return self.root if value == '/out' else Path(value)
        with mock.patch.object(G, 'guard'), mock.patch.object(G, 'Path', side_effect=path), \
             mock.patch.object(L, 'bounded_process', return_value=result):
            with self.assertRaisesRegex(ValueError, 'ANCILLARY_TRANSACTION_ERROR'):
                journey.command('synthetic-error', ['pacman', '-U', 'inert'], clean=True)
        self.assertEqual(len(journey.report['commands']), 1)

    def test_real_packet_copy_relocation_and_size_schema(self):
        source = Path(ARGS.packet).absolute(); snapshot = C.packet(source)
        index = C.read(source / 'delivery.json'); self.assertEqual(C.digest(index), P['packet_index_sha256'])
        files = {n: dict(size=r['bytes'], sha256=r['sha256']) for n, r in snapshot.items() if r['kind'] == 'file' and n != 'delivery.json'}
        self.assertEqual(files, C.decode(index)['files'])
        output = self.root / 'copied'; D.copy_packet(source, output, snapshot)
        moved = self.root / 'moved'; output.rename(moved)
        self.assertEqual(C.packet(moved), snapshot)
        target = moved / 'registry/crates/wmidi-3.1.0.crate'; target.write_bytes(target.read_bytes() + b'tamper')
        self.assertNotEqual(C.packet(moved), snapshot)
        self.assertEqual(C.packet(source), snapshot)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--packet', required=True)
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
