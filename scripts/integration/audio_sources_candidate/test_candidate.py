#!/usr/bin/python3 -IB
# SPDX-License-Identifier: MIT
"""DATA/ingress/cleanup controls; never substitute for an installed pacman result."""
import argparse
import importlib.util
import json
import os
import sys
import copy
import stat
from contextlib import contextmanager
from types import SimpleNamespace
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
V2 = C.host_contract(HERE)
H = G.H
R = C.held(D.CHECKOUT / 'scripts/integration/repository.py', P['held_apis']['scripts/integration/repository.py'], 'audio_repository_control_api')
L = C.held(D.CHECKOUT / 'scripts/integration/lifecycle.py', P['held_apis']['scripts/integration/lifecycle.py'], 'audio_lifecycle_control_api')


def mount_fixture(v2=False):
    row = lambda fs, access, root='/': dict(fs=fs, options={access}, root=root)
    result = {'/': row('overlay', 'ro'), '/inputs': row('ext4', 'ro'), '/runner': row('ext4', 'ro'),
        '/out': row('ext4', 'rw'),
        **{p: dict(fs='tmpfs', options={'rw', 'nosuid', 'nodev'}, root='/') for p in ('/scratch', '/test-home')},
        **{p: row('ext4', 'rw') for p in R.RUNTIME_FILES}}
    result.update({p: dict(fs=fs, options=set(flags), root='/null' if p in R.MASKED_NULL else
        p.removeprefix('/proc') if fs == 'proc' and p != '/proc' else '/') for p, (fs, flags) in R.STANDARD_MOUNTS.items()})
    if v2:
        for path in ('/scratch', '/test-home'):
            result[path]['options'].add('noexec')
        result['/alpm'] = dict(fs='tmpfs', root='/', options={'rw', 'nodev', 'nosuid'})
    return result


def engine_fixture():
    return copy.deepcopy(dict(V2['engine_host_config'], MaskedPaths=V2['engine_masked_paths'], ReadonlyPaths=V2['engine_readonly_paths']))


def node_fixture(path):
    identity = G.STANDARD_DEVICE_MOUNTS.get(str(path), (1, 3))
    return type('Node', (), dict(st_mode=stat.S_IFCHR | 0o666, st_rdev=os.makedev(*identity)))()


@contextmanager
def synthetic_nodes():
    with mock.patch.object(H.Path, 'exists', return_value=True), \
         mock.patch.object(H.Path, 'is_symlink', return_value=False), \
         mock.patch.object(H.Path, 'lstat', autospec=True, side_effect=node_fixture):
        yield


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
        observed = mount_fixture(v2=True)
        for path in G.STANDARD_DEVICE_MOUNTS:
            observed[path] = dict(fs='tmpfs', options={'rw', 'nosuid'}, root='/' + Path(path).name)
        with synthetic_nodes():
            admitted = H.mounts(R, observed, engine_fixture(), V2)
        self.assertTrue(set(G.STANDARD_DEVICE_MOUNTS) <= set(admitted))
        for path in ('/dev/mem', '/inputs/private-child', '/usr'):
            bad = dict(observed); bad[path] = dict(fs='tmpfs', options={'ro'}, root='/')
            with self.subTest(path=path), synthetic_nodes(), self.assertRaises((ValueError, R.Refused)):
                H.mounts(R, bad, engine_fixture(), V2)
        observed['/dev/zero'] = dict(fs='tmpfs', options={'rw'}, root='/foreign')
        with synthetic_nodes(), self.assertRaisesRegex(ValueError, 'STANDARD_DEVICE_MOUNT_IDENTITY'):
            H.mounts(R, observed, engine_fixture(), V2)

    def test_standard_device_alias_or_different_major_minor_refuses(self):
        observed = mount_fixture(v2=True); observed['/dev/zero'] = dict(fs='tmpfs', options={'rw', 'nosuid'}, root='/zero')
        for mode, device in ((0o120777, os.makedev(1, 5)), (0o20666, os.makedev(1, 3))):
            with synthetic_nodes(), mock.patch.object(H.Path, 'lstat', return_value=type('Node', (), dict(st_mode=mode, st_rdev=device))()):
                with self.assertRaisesRegex(ValueError, 'HOST_CHARACTER_DEVICE_IDENTITY'):
                    H.mounts(R, observed, engine_fixture(), V2)

    def test_exact_capabilities_and_nnp_remain_required(self):
        status = '\n'.join(f'{name}: {R.SAFE_CAPS if name in ("CapEff", "CapPrm", "CapBnd") else 0:x}' for name in R.CAP_FIELDS) + '\nNoNewPrivs: 1\n'
        self.assertEqual(R.privileges(status)['CapEff'], R.SAFE_CAPS)
        for bad in (status.replace('NoNewPrivs: 1', 'NoNewPrivs: 0'), status.replace('400cb', '200400cb'),
                    status.replace('400cb', 'cb')):
            with self.assertRaises(R.Refused): R.privileges(bad)

    def test_noexec_copied_root_refuses_before_any_transaction(self):
        observed = mount_fixture(v2=True)
        with synthetic_nodes(): H.mounts(R, observed, engine_fixture(), V2)
        observed['/alpm']['options'].add('noexec')
        with synthetic_nodes(), self.assertRaisesRegex(ValueError, 'EXECUTABLE_OWNED_ALPM_VOLUME_REQUIRED'):
            H.mounts(R, observed, engine_fixture(), V2)

    def test_scratch_noexec_and_separate_work_mount_are_both_required(self):
        for path in ('/scratch', '/test-home'):
            observed = mount_fixture(v2=True); observed[path]['options'].remove('noexec')
            with self.subTest(path=path), synthetic_nodes(), self.assertRaisesRegex(ValueError, 'PRIVATE_NOEXEC_DATA_VOLUME'):
                H.mounts(R, observed, engine_fixture(), V2)
        observed = mount_fixture(v2=True); observed['/alpm/host'] = dict(fs='ext4', root='/foreign', options={'rw'})
        with synthetic_nodes(), self.assertRaises(R.Refused): H.mounts(R, observed, engine_fixture(), V2)

    def test_complete_declared_mask_profile_and_null_identity(self):
        observed = mount_fixture(v2=True)
        for path in V2['null_mask_paths']:
            observed[path]['fs'] = 'devtmpfs'
        with synthetic_nodes(): H.mounts(R, observed, engine_fixture(), V2)
        observed['/proc/timer_list']['root'] = '/foreign'
        with synthetic_nodes(), self.assertRaisesRegex(ValueError, 'PROTECTED_NULL_MOUNT_IDENTITY'):
            H.mounts(R, observed, engine_fixture(), V2)
        observed = mount_fixture(v2=True); del observed['/proc/timer_list']
        with synthetic_nodes(), self.assertRaisesRegex(ValueError, 'ENGINE_MASK_NOT_ACTUALLY_MOUNTED'):
            H.mounts(R, observed, engine_fixture(), V2)

    def test_changed_engine_masks_capabilities_and_seccomp_refuse(self):
        for key, value in (('MaskedPaths', ['/proc/extra']), ('ReadonlyPaths', []),
                           ('CapAdd', ['CAP_SYS_ADMIN']), ('SecurityOpt', ['seccomp=unconfined'])):
            declaration = engine_fixture(); declaration[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): H.engine(declaration, V2)

    def test_parsed_bind_roots_cannot_expose_other_host_sources(self):
        roots = {'/inputs': ('/private/copy/inputs', True), '/runner': ('/private/copy/runner', True), '/out': ('/private/copy/out', False)}
        value = dict(Binds=None, Mounts=[dict(Type='bind', Source=source, Target=target, ReadOnly=ro)
                                       for target, (source, ro) in roots.items()])
        H.binds(value, roots)
        for field, replacement in (('Source', '/host'), ('ReadOnly', False), ('Target', '/usr')):
            bad = copy.deepcopy(value); bad['Mounts'][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): H.binds(bad, roots)
        value['Mounts'].append(dict(Type='bind', Source='/host', Target='/other', ReadOnly=True))
        with self.assertRaises(ValueError): H.binds(value, roots)

    def test_actual_created_only_engine_contract_observation_matches(self):
        actual = C.decode(C.read(Path(ARGS.engine_observation), 65536))
        self.assertFalse(actual['container_started'])
        self.assertEqual(actual['state']['Status'], 'created')
        H.engine(actual['contract'], V2)

    def test_work_resource_size_mode_distinctness_and_freshness_refuse(self):
        roles = {V2['work_volume']['path']: V2['work_volume'], **V2['data_volumes']}
        for failure in (None, 'size', 'mode', 'shared-device', 'nonempty'):
            def info(path):
                return SimpleNamespace(st_mode=stat.S_IFDIR | (0o755 if failure == 'mode' else 0o700),
                    st_uid=0, st_gid=0, st_dev=1 if failure == 'shared-device' else list(roles).index(str(path)) + 1)
            def usage(path):
                return SimpleNamespace(f_frsize=4096, f_blocks=roles[str(path)]['bytes'] // 4096 + (1 if failure == 'size' else 0))
            with self.subTest(failure=failure), mock.patch.object(H.Path, 'lstat', autospec=True, side_effect=info), \
                 mock.patch.object(H.os, 'statvfs', side_effect=usage), \
                 mock.patch.object(H.Path, 'iterdir', return_value=iter([Path('foreign')] if failure == 'nonempty' else [])):
                if failure is None:
                    H.volumes(V2, 'a' * 32, initial=True)
                else:
                    with self.assertRaises(ValueError): H.volumes(V2, 'a' * 32, initial=True)

    def test_work_owner_marker_is_bounded_single_link_and_nonce_bound(self):
        roles = {V2['work_volume']['path']: V2['work_volume'], **V2['data_volumes']}
        actual_owner = self.root / 'owner'; original_open = os.open
        for failure in (None, 'nonce', 'symlink', 'hardlink', 'oversize'):
            actual_owner.write_bytes((('b' if failure == 'nonce' else 'a') * 32 + '\n').encode())
            def info(path):
                if str(path).endswith(V2['work_volume']['owner_marker']):
                    return SimpleNamespace(st_mode=(stat.S_IFLNK if failure == 'symlink' else stat.S_IFREG) | 0o600,
                        st_uid=0, st_gid=0, st_nlink=2 if failure == 'hardlink' else 1, st_size=999999 if failure == 'oversize' else 33)
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0, st_dev=list(roles).index(str(path)) + 1)
            with self.subTest(failure=failure), mock.patch.object(H.Path, 'lstat', autospec=True, side_effect=info), \
                 mock.patch.object(H.os, 'statvfs', side_effect=lambda p: SimpleNamespace(f_frsize=4096, f_blocks=roles[str(p)]['bytes'] // 4096)), \
                 mock.patch.object(H.os, 'open', side_effect=lambda p, flags: original_open(actual_owner, flags)) as opened:
                if failure is None:
                    H.volumes(V2, 'a' * 32)
                else:
                    with self.assertRaises(ValueError): H.volumes(V2, 'a' * 32)
                    if failure != 'nonce': opened.assert_not_called()

    def test_engine_managed_metadata_cannot_be_link_foreign_or_writable(self):
        for kind, uid, mode in ((stat.S_IFREG, 0, 0o644), (stat.S_IFLNK, 0, 0o777),
                                (stat.S_IFREG, 1000, 0o644), (stat.S_IFREG, 0, 0o666)):
            with self.subTest(kind=kind, uid=uid, mode=mode), mock.patch.object(H.Path, 'lstat',
                return_value=SimpleNamespace(st_mode=kind | mode, st_uid=uid)):
                if kind == stat.S_IFREG and uid == 0 and mode == 0o644:
                    H.runtime_metadata(R)
                else:
                    with self.assertRaises(ValueError): H.runtime_metadata(R)

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

    def test_parent_temp_is_the_declared_noexec_data_mount_before_commands(self):
        contract = dict(nonce='a' * 32, image_id=P['image_id'])
        for value in (None, '/tmp', '/producer'):
            env = dict(CACHY_ASAHI_AUDIO_CANDIDATE=contract['nonce'], CACHY_ASAHI_IMAGE_ID=contract['image_id'])
            if value is not None: env['TMPDIR'] = value
            with self.subTest(value=value), mock.patch.object(G.platform, 'machine', return_value='x86_64'), \
                 mock.patch.object(G.os, 'geteuid', return_value=0), mock.patch.object(G.Path, 'is_file', return_value=True), \
                 mock.patch.object(G.Path, 'is_symlink', return_value=False), \
                 mock.patch.object(G.Path, 'stat', return_value=SimpleNamespace(st_uid=0)), \
                 mock.patch.dict(G.os.environ, env, clear=True), mock.patch.object(R, 'mounts') as mounted:
                with self.assertRaisesRegex(ValueError, 'PARENT_PRIVATE_DATA_TMP_REQUIRED'):
                    G.guard(R, contract)
                mounted.assert_not_called()

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
    parser.add_argument('--engine-observation', required=True)
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
