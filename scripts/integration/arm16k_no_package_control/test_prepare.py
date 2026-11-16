# SPDX-License-Identifier: MIT
"""Owned synthetic public DATA only; no image, credential, actor or quota use."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def module(name, directory=HERE):
    spec = importlib.util.spec_from_file_location('control_prepare_test_'+name, directory/(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


K, P = module('contracts'), module('prepare')
MODEL_READER = (HERE/'metadata_raw_reader.py').read_bytes()


def pin(label='MODEL'):
    return K.bytes_pin(('PUBLIC_MODEL_'+label).encode())


def modeled(now=1000000, uid=1000):
    source = pin('new-source')
    r = dict.fromkeys(K.LIMITS, 1)
    r.update(prepare_seconds=30, boot_seconds=800, cleanup_seconds=60,
        baseline_raw_bytes=K.local('plan').BASELINE['raw']['bytes'], baseline_allocated_bytes=1024**2,
        clone_allocated_cap_bytes=1024**2, overlay_cap_bytes=8*1024**2,
        readback_allocated_cap_bytes=8*1024**2, logs_cap_bytes=1024**2,
        reserve_bytes=1024**2, physical_free_bytes=32*1024**2,
        quota_initial_headroom_bytes=32*1024**2, quota_live_reserve_bytes=1024**2,
        guest_memory_bytes=128*1024**2, owner_memory_bytes=256*1024**2,
        host_reserve_bytes=128*1024**2, host_MemAvailable_bytes=512*1024**2,
        cpus=2, pids=128, output_device=54, host_uid=uid)
    r['quota_guard'] = dict(issued_by='Root', method='READ_ONLY_Q_GETQUOTA', whole_actor=True,
        read_only=True, uid=uid, device=54, initial_headroom_bytes=r['quota_initial_headroom_bytes'],
        live_reserve_bytes=r['quota_live_reserve_bytes'], on_unknown_or_exhausted='HOLD_AND_OWNED_CLEANUP')
    baseline = dict(kind='ROOT_ACCEPTED_ORIGINAL_PAM_BASELINE_DECLARATION_V1', issued_by='Root',
        accepted=True, **copy.deepcopy(K.local('plan').BASELINE))
    kernel = dict(kind='ROOT_ACCEPTED_CASE14_KERNEL_DECLARATION_V1', issued_by='Root',
        accepted=True, Image=pin('case14-Image'), config=pin('case14-config'))
    packet = dict(kind='ROOT_NO_PACKAGE_CONTROL_INPUTS_V1', nonce='a'*32, baseline_nonce='b'*32,
        baseline=baseline, kernel=kernel, tool_image='sha256:'+'c'*64, reader=K.bytes_pin(MODEL_READER),
        actor_tools={name: pin(name) for name in K.TOOLS}, resources=r, idle_seconds=5,
        source_lock=source, comparison_source65=copy.deepcopy(K.local('plan').SOURCE65['lock']),
        timing=dict(login_seconds=20, proof_seconds=10, probe_seconds=10, logout_seconds=10))
    out = '/home/gabe/PUBLIC_MODEL/control-output'
    shared = dict(issued_by='Root', accepted=True, operation=K.OP, packet=K.json_pin(packet),
        source_lock=source, output=out, uid=uid, created_utc=now-1, expires_utc=now+1200,
        resources=K.json_pin(r))
    admission = dict(kind='ROOT_NO_PACKAGE_CONTROL_ADMISSION_V1', enforcement=K.ENFORCEMENT, **shared)
    authority = dict(kind='ROOT_NO_PACKAGE_CONTROL_AUTHORITY_V1', **shared,
        reader=packet['reader'], image=packet['tool_image'], kernel=packet['kernel'], baseline=packet['baseline'],
        credentials=pin('PAM_PIN_ONLY_NEVER_READ'), docker_endpoint='unix:///run/user/'+str(uid)+'/docker.sock',
        docker_cli=dict(path='/PUBLIC_MODEL/docker', **pin('cli'), uid=uid, gid=uid, mode=0o755, device=54, inode=2, nlink=1),
        quota_device='/dev/PUBLIC_MODEL', actor_tools=packet['actor_tools'], external_admission=K.json_pin(admission))
    return packet, source, admission, authority, out


class Contracts(unittest.TestCase):
    def test_closed_joined_inputs_and_root_grants(self):
        packet, source, admitted, authority, out = modeled()
        before = copy.deepcopy((packet, source, admitted, authority))
        self.assertIs(K.inputs(packet, source, 1000000), packet)
        self.assertIs(K.admission(admitted, K.json_pin(packet), packet, source, out, 1000000, 1000), admitted)
        self.assertIs(K.authority(authority, K.json_pin(packet), packet, source, out, 1000000, 1000), authority)
        self.assertEqual((packet, source, admitted, authority), before)

    def test_unknown_private_paths_cannot_enter_packet_or_resource_schema(self):
        for location in ('packet', 'resources', 'baseline', 'kernel', 'timing'):
            packet, source, *_ = modeled()
            target = packet if location == 'packet' else packet[location]
            target['unreviewed_path'] = '/MODEL_PRIVATE_NEVER_OPEN'
            with self.assertRaises(ValueError) as caught:
                K.inputs(packet, source)
            self.assertNotIn('MODEL_PRIVATE_NEVER_OPEN', str(caught.exception))

    def test_exact_original_baseline_and_fresh_nonce_are_required(self):
        for change in ('raw', 'prepared', 'certificate', 'accepted', 'nonce', 'comparison'):
            packet, source, *_ = modeled()
            if change in ('raw', 'prepared', 'certificate'):
                packet['baseline'][change] = pin('substitute')
            elif change == 'accepted':
                packet['baseline'][change] = 1
            elif change == 'nonce':
                packet['nonce'] = packet['baseline_nonce']
            else:
                packet['comparison_source65'] = pin('other-policy')
            with self.assertRaises(ValueError):
                K.inputs(packet, source)

    def test_kernel_and_reader_are_pins_not_paths_or_runtime_claims(self):
        for field, value in (('accepted', False), ('Image', '/MODEL_IMAGE_NEVER_OPEN'), ('config', dict(bytes=True, sha256='a'*64))):
            packet, source, *_ = modeled()
            packet['kernel'][field] = value
            with self.assertRaises(ValueError):
                K.inputs(packet, source)
        packet, source, *_ = modeled()
        packet['reader']['bytes'] = 1024**2+1
        with self.assertRaises(ValueError):
            K.inputs(packet, source)

    def test_api_compatible_alternate_reader_pin_cannot_replace_integrated_source(self):
        self.assertEqual(K.bytes_pin(MODEL_READER), K.READER_PIN)
        alternate = b'def observe(raw_path, debugfs_pin, deadline, *, legacy_root, guard):\n    return {"MODEL_ONLY": True}\n'
        self.assertIs(P.reader_shape(alternate), alternate)
        packet, source, *_ = modeled()
        packet['reader'] = K.bytes_pin(alternate)
        with self.assertRaisesRegex(ValueError, 'exact integrated public metadata reader pin'):
            K.inputs(packet, source)

    def test_finite_ram_storage_quota_and_schedule_checks(self):
        cases = [('cpus', 0), ('cpus', True), ('pids', 4097), ('cleanup_seconds', 1), ('cleanup_seconds', 59),
            ('physical_free_bytes', 1), ('quota_initial_headroom_bytes', 1),
            ('quota_live_reserve_bytes', 1), ('readback_allocated_cap_bytes', 1),
            ('host_MemAvailable_bytes', 1), ('guest_memory_bytes', 128*1024**2+1),
            ('boot_seconds', 70), ('logs_cap_bytes', 65535)]
        for field, value in cases:
            packet, source, *_ = modeled()
            packet['resources'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                K.inputs(packet, source)

    def test_boot_envelope_reserves_two_fixed_metadata_slots(self):
        packet, source, *_ = modeled()
        timing, resources = packet['timing'], packet['resources']
        self.assertEqual(K.METADATA_SECONDS, 120)
        old = (3*timing['login_seconds']+timing['proof_seconds']+2*timing['probe_seconds']+
            timing['logout_seconds']+packet['idle_seconds']+3*resources['cleanup_seconds']+30)
        for seconds in (old, old+2*K.METADATA_SECONDS-1):
            resources['boot_seconds'] = seconds
            with self.assertRaisesRegex(ValueError, 'whole boot covers two metadata reads'):
                K.inputs(packet, source)
        resources['boot_seconds'] = old+2*K.METADATA_SECONDS
        K.inputs(packet, source)

    def test_six_tools_and_exact_authority_joins(self):
        packet, source, *_ = modeled()
        packet['actor_tools'].pop(K.TOOLS[0])
        with self.assertRaises(ValueError):
            K.inputs(packet, source)
        for field, value in (('image', 'sha256:'+'f'*64), ('reader', pin('different-reader')),
                             ('kernel', {}), ('baseline', {}), ('actor_tools', {}),
                             ('packet', pin('other-packet')), ('resources', pin('other-resources')),
                             ('source_lock', pin('other-source')), ('output', '/home/gabe/PUBLIC_MODEL/other')):
            packet, source, _, authority, out = modeled()
            authority[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                K.authority(authority, K.json_pin(packet), packet, source, out, 1000000, 1000)

    def test_grants_are_closed_accepted_root_and_at_most_one_hour(self):
        cases = [('created_utc', 1000001), ('created_utc', 996399), ('expires_utc', 1000000), ('expires_utc', 1000859),
            ('expires_utc', 1003601), ('created_utc', True), ('accepted', 1),
            ('issued_by', 'MODEL_OTHER'), ('uid', True), ('operation', 'PACKAGE_INSTALL'), ('extra', True)]
        for role in ('authority', 'admission'):
            for field, value in cases:
                packet, source, admitted, authority, out = modeled()
                grant = authority if role == 'authority' else admitted
                grant[field] = value
                with self.subTest(role=role, field=field), self.assertRaises(ValueError):
                    getattr(K, role)(grant, K.json_pin(packet), packet, source, out, 1000000, 1000)

    def test_external_custody_is_an_exact_required_assertion_not_execution(self):
        packet, source, admitted, authority, out = modeled()
        admitted['enforcement'] = 'BEST_EFFORT'
        with self.assertRaises(ValueError):
            K.admission(admitted, K.json_pin(packet), packet, source, out, 1000000, 1000)
        authority['external_admission'] = None
        with self.assertRaises(ValueError):
            K.authority(authority, K.json_pin(packet), packet, source, out, 1000000, 1000)

    def test_completion_revalidates_freshness_without_requesting_second_full_run(self):
        packet, source, admitted, authority, out = modeled()
        for name, grant in (('authority', authority), ('admission', admitted)):
            validate = getattr(K, name)
            with self.assertRaises(ValueError):
                validate(grant, K.json_pin(packet), packet, source, out, 1001100, 1000)
            self.assertIs(validate(grant, K.json_pin(packet), packet, source, out,
                1001100, 1000, starting=False), grant)
            with self.assertRaises(ValueError):
                validate(grant, K.json_pin(packet), packet, source, out, 1001200, 1000, starting=False)

    def test_templates_remain_closed_unissued_root_choices(self):
        packet, _, admitted, authority, _ = modeled()
        for template, model in ((K.input_template(), packet), (K.admission_template(), admitted),
                                (K.authority_template(), authority)):
            self.assertEqual(set(template), set(model))
        self.assertIsNone(K.input_template()['baseline']['accepted'])
        self.assertIsNone(K.input_template()['kernel']['Image'])
        self.assertIsNone(K.authority_template()['credentials'])
        self.assertIsNone(K.admission_template()['accepted'])

    def test_docker_endpoint_cli_and_quota_paths_are_canonical_closed_data(self):
        cases = [('docker_endpoint', 'tcp://remote:2375'), ('docker_endpoint', 'unix:///run/user/0/docker.sock'),
            ('docker_endpoint', 'unix:///run/user/1000/../docker.sock'), ('quota_device', '/dev/../tmp'),
            ('credentials', None), ('output', 'relative')]
        for field, value in cases:
            packet, source, _, authority, out = modeled()
            authority[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                K.authority(authority, K.json_pin(packet), packet, source, value if field == 'output' else out, 1000000, 1000)
        for field, value in (('path', '/MODEL/../docker'), ('mode', 0o777), ('nlink', 2), ('uid', 2), ('inode', 0)):
            packet, source, _, authority, out = modeled()
            authority['docker_cli'][field] = value
            with self.subTest(cli=field), self.assertRaises(ValueError):
                K.authority(authority, K.json_pin(packet), packet, source, out, 1000000, 1000)

    def test_home_profile_binds_real_constructor_and_boot_outputs_without_sampling(self):
        home = module('home_btrfs', HERE.parent/'arm16k_perl5423_vm')
        packet, source, admitted, authority, out = modeled()
        r = packet['resources']
        r['quota_initial_headroom_bytes'] = r['quota_live_reserve_bytes'] = None
        r['quota_guard'] = dict(issued_by='Root', method=home.METHOD, whole_actor=True, read_only=True,
            uid=1000, device=54, filesystem=copy.deepcopy(home.FS), quota_query=copy.deepcopy(home.QUERY),
            inode_counters='ZERO_FILES_FFREE_FAVAIL_MEANS_UNREPORTED', output_node_cap=150000,
            initial_inode_headroom=16384, live_inode_headroom=4096, other_quota_availability='UNCLAIMED',
            capacity_reservation=False, outputs=dict(prepare='/home/gabe/PUBLIC_MODEL/packet', boot=out),
            source_lock=source, created_utc=999999, expires_utc=1000100, on_unknown_or_exhausted='HOLD_AND_OWNED_CLEANUP')
        original = K.local
        support = type('Support', (), {'legacy': staticmethod(lambda name: home if name == 'home_btrfs' else None)})
        with patch.object(K, 'local', side_effect=lambda name: support if name == 'support' else original(name)), \
             patch.object(home, 'sample', side_effect=AssertionError('quota sampling forbidden')), \
             patch.object(home, 'query_enosys', side_effect=AssertionError('quota query forbidden')):
            K.inputs(packet, source, 1000000)
            K.resources(r, source, 1000000, 'prepare', '/home/gabe/PUBLIC_MODEL/packet')
            K.resources(r, source, 1000000, 'boot', out)
            with self.assertRaises(ValueError):
                K.resources(r, source, 1000000, 'prepare', out)
            with self.assertRaises(ValueError):
                K.resources(r, source, 1000200)


class Constructor(unittest.TestCase):
    def fixture(self, base):
        packet, source, *_ = modeled(uid=os.getuid())
        inputs, reader, out = base/'public-inputs.json', base/'public-reader.py', base/'snapshot'
        inputs.write_bytes(K.canonical(packet))
        reader.write_bytes(MODEL_READER)
        return packet, source, inputs, reader, out

    def test_snapshot_rewinds_same_held_fd_before_exact_membership(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, source, inputs, reader, out = self.fixture(Path(temporary))
            seek, listing = os.lseek, os.listdir
            calls = []
            rewound = []
            def rewind(fd, offset, whence):
                self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
                self.assertEqual((offset, whence), (0, os.SEEK_SET))
                calls.append(('rewind', fd));rewound.append(fd)
                return seek(fd, offset, whence)
            def members(fd):
                self.assertIs(type(fd), int)  # A pathname fallback is forbidden.
                calls.append(('members', fd))
                return listing(fd) if rewound == [fd] else []
            with patch.object(P.os, 'lseek', side_effect=rewind), \
                 patch.object(P.os, 'listdir', side_effect=members):
                result = P.prepare(inputs, source['sha256'], reader, out,
                                   now=1000000, source_loader=lambda _: source)
            try:
                self.assertEqual(calls, [('rewind', rewound[0]), ('members', rewound[0])])
                self.assertEqual(result['status'], 'PUBLIC_PACKET_AND_READER_SNAPSHOTTED_NOT_EXECUTED')
                self.assertEqual(set(x.name for x in out.iterdir()), {'control-packet.json', 'raw_metadata.py'})
            finally:
                out.chmod(0o700)

    def test_snapshot_rewind_error_refuses_without_path_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, source, inputs, reader, out = self.fixture(Path(temporary))
            with patch.object(P.os, 'lseek', side_effect=OSError('MODEL directory seek refused')), \
                 patch.object(P.os, 'listdir') as listing:
                with self.assertRaises(OSError):
                    P.prepare(inputs, source['sha256'], reader, out,
                              now=1000000, source_loader=lambda _: source)
                listing.assert_not_called()
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)

    def test_snapshot_extra_member_after_rewind_still_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, source, inputs, reader, out = self.fixture(Path(temporary))
            listing = os.listdir
            def extra(fd):
                self.assertIs(type(fd), int)
                return listing(fd)+['MODEL_UNREVIEWED_EXTRA']
            with patch.object(P.os, 'listdir', side_effect=extra):
                with self.assertRaisesRegex(ValueError, 'exact constructor snapshot membership'):
                    P.prepare(inputs, source['sha256'], reader, out,
                              now=1000000, source_loader=lambda _: source)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)

    def test_snapshot_held_identity_substitution_refuses_before_or_after_listing(self):
        for change_at in (2, 3):
            with self.subTest(change_at=change_at), tempfile.TemporaryDirectory() as temporary:
                _, source, inputs, reader, out = self.fixture(Path(temporary))
                opened, fstat, names = os.open, os.fstat, os.listdir
                target, counts = [], []
                def opening(name, flags, *args, **kwargs):
                    fd = opened(name, flags, *args, **kwargs)
                    if name == out.name and flags & os.O_DIRECTORY:
                        self.assertTrue(flags & os.O_NOFOLLOW)
                        target.append(fd)
                    return fd
                def identity(fd):
                    result = fstat(fd)
                    if target == [fd]:
                        counts.append(fd)
                        if len(counts) >= change_at:
                            changed = list(result);changed[1] += 1
                            return os.stat_result(changed)
                    return result
                with patch.object(P.os, 'open', side_effect=opening), \
                     patch.object(P.os, 'fstat', side_effect=identity), \
                     patch.object(P.os, 'listdir', side_effect=names) as listing:
                    with self.assertRaisesRegex(ValueError, 'same held constructor directory'):
                        P.prepare(inputs, source['sha256'], reader, out,
                                  now=1000000, source_loader=lambda _: source)
                    self.assertEqual(listing.call_count, change_at-2)

    def test_snapshot_path_replacement_cannot_replace_held_fd_membership(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, source, inputs, reader, out = self.fixture(Path(temporary))
            parked = out.with_name('original-held-snapshot')
            chmod = os.fchmod
            def substituted(fd, mode):
                self.assertIs(type(fd), int)
                result = chmod(fd, mode)
                if mode == 0o500:
                    out.rename(parked);out.mkdir(mode=0o700)
                return result
            try:
                with patch.object(P.os, 'fchmod', side_effect=substituted):
                    with self.assertRaisesRegex(ValueError, 'stable read-only constructor snapshot directory'):
                        P.prepare(inputs, source['sha256'], reader, out,
                                  now=1000000, source_loader=lambda _: source)
            finally:
                if parked.exists():parked.chmod(0o700)

    def test_pin_streams_owned_public_scratch_without_read_bytes_or_large_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            public = Path(temporary)/'public-model-stream.bin'
            raw = b'PUBLIC_MODEL_ONLY'*(1024*128)
            public.write_bytes(raw)
            original = os.read
            chunks = []
            def bounded(fd, size):
                self.assertLessEqual(size, 65536)
                result = original(fd, size)
                chunks.append(len(result))
                return result
            with patch.object(K, 'read_bytes', side_effect=AssertionError('pin must not buffer DATA')), \
                 patch.object(K.os, 'read', side_effect=bounded):
                self.assertEqual(K.pin(public, len(raw)), K.bytes_pin(raw))
            self.assertGreater(len(chunks), 2)

    def test_only_two_public_operands_read_exact_readonly_snapshot_and_no_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            packet, source, inputs, reader, out = self.fixture(Path(temporary))
            seen = []
            original = P.K.read_bytes
            def observe(path, cap=4*1024**2):
                seen.append(Path(path))
                self.assertIn(Path(path), (inputs, reader))
                return original(path, cap)
            with patch.object(P.K, 'read_bytes', side_effect=observe):
                report = P.prepare(inputs, source['sha256'], reader, out, now=1000000, source_loader=lambda _: source)
            try:
                self.assertEqual(seen, [inputs, reader])
                self.assertEqual(set(p.name for p in out.iterdir()), {'control-packet.json', 'raw_metadata.py'})
                self.assertEqual((out/'control-packet.json').read_bytes(), K.canonical(packet))
                self.assertEqual((out/'raw_metadata.py').read_bytes(), MODEL_READER)
                self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o500)
                self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o400 for p in out.iterdir()))
                self.assertEqual(report['packet'], K.json_pin(packet))
                self.assertIsNone(report['actual_VM'])
                self.assertIsNone(report['Root_acceptance'])
                with self.assertRaises(ValueError):
                    P.prepare(inputs, source['sha256'], reader, out, now=1000000, source_loader=lambda _: source)
            finally:
                out.chmod(0o700)

    def test_reader_is_parsed_never_imported_and_bad_api_or_pin_creates_no_output(self):
        signature = b'def observe(raw_path, debugfs_pin, deadline, *, legacy_root, guard):\n    pass\n'
        for raw in (b'raise RuntimeError("MODEL_MUST_NOT_EXECUTE")\n'+signature, signature):
            self.assertIs(P.reader_shape(raw), raw)
        invalid = (
            b'def scan(path, deadline, guard):\n    pass\n',
            b'def observe(raw_path, debugfs_pin, deadline, legacy_root, guard):\n    pass\n',
            b'def observe(raw_path, debugfs_pin, deadline, *, legacy_root):\n    pass\n',
            b'def observe(raw_path, debugfs_pin, deadline, *, legacy_root, guard=None):\n    pass\n',
            b'def observe(raw_path, debugfs_pin, deadline, *, guard, legacy_root):\n    pass\n',
            b'def observe(raw_path, debugfs_pin, deadline, *args, legacy_root, guard):\n    pass\n',
            b'def observe(raw_path, debugfs_pin, deadline, /, *, legacy_root, guard):\n    pass\n',
            b'async '+signature, signature+signature, b'not Python!')
        for raw in invalid:
            with self.assertRaises(ValueError):
                P.reader_shape(raw)
        with tempfile.TemporaryDirectory() as temporary:
            _, source, inputs, reader, out = self.fixture(Path(temporary))
            reader.write_bytes(signature)
            with self.assertRaises(ValueError):
                P.prepare(inputs, source['sha256'], reader, out, now=1000000, source_loader=lambda _: source)
            self.assertFalse(out.exists())

    def test_json_duplicate_noninteger_noncanonical_and_unknown_are_refused(self):
        bodies = (b'{"a":1,"a":2}', b'{"a":1.5}', b'{"a":NaN}', b'{"a": 1}',
                  K.canonical(dict(MODEL_PRIVATE_PATH='/never/open')))
        with tempfile.TemporaryDirectory() as temporary:
            _, source, inputs, reader, out = self.fixture(Path(temporary))
            for raw in bodies:
                inputs.write_bytes(raw)
                with self.assertRaises(ValueError):
                    P.prepare(inputs, source['sha256'], reader, out, now=1000000, source_loader=lambda _: source)
                self.assertFalse(out.exists())

    def test_nofollow_aliases_hardlinks_and_writable_output_parent_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            _, source, inputs, reader, out = self.fixture(base)
            alias = base/'alias.py'
            alias.symlink_to(reader)
            with self.assertRaises((ValueError, OSError)):
                P.prepare(inputs, source['sha256'], alias, out, now=1000000, source_loader=lambda _: source)
            alias.unlink()
            os.link(reader, alias)
            with self.assertRaises(ValueError):
                P.prepare(inputs, source['sha256'], reader, out, now=1000000, source_loader=lambda _: source)
            alias.unlink()
            base.chmod(0o777)
            try:
                with self.assertRaises(ValueError):
                    P.prepare(inputs, source['sha256'], reader, out, now=1000000, source_loader=lambda _: source)
            finally:
                base.chmod(0o700)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
