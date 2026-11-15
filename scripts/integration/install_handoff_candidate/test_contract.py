#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic contract/guard controls only; no container or installation credit."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('handoff_candidate_controls', Path(__file__).with_name('controls.py'))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def contract():
    payload = {C.LAUNCHER: dict(sha256='a'*64, bytes=1, mode=0o755)}
    payload.update({f'usr/lib/cachy-asahi/install-handoff/test-{number}':
                    dict(sha256='b'*64, bytes=10, mode=0o644) for number in range(38)})
    return dict(schema_version=1, purpose='TEST-signed-install-handoff-host-container',
        execution='host-x86_64-disposable-docker', image_id='sha256:'+'c'*64, nonce='d'*32,
        package=dict(path='package.pkg.tar.zst', sha256=C.PACKAGE_SHA, bytes=C.PACKAGE_BYTES,
                     signature_sha256='e'*64, signature_bytes=128),
        signer=dict(fingerprint='A'*40, certificate_sha256='f'*64, certificate_bytes=512),
        handoff=dict(receipt_sha256='1'*64, selection_sha256='2'*64, runtime_sha256=C.RUNTIME_SHA,
                     archive_certificate_fingerprint='B'*40, archive_certificate_sha256='3'*64,
                     files={'handoff.json':'4'*64, 'candidate/repo/database.tar.gz':'5'*64},
                     symlinks={'candidate/repo/database':'database.tar.gz'}),
        payload=payload, source_files={name:'6'*64 for name in ('guest.py', 'controls.py', 'lifecycle.py')})


def probe():
    def mount(fs, *flags): return dict(fs=fs, options=list(flags))
    mounts = {
        '/': mount('overlay', 'rw', 'relatime'),
        '/inputs': mount('ext4', 'ro', 'relatime'),
        '/runner': mount('ext4', 'ro', 'relatime'),
        '/out': mount('ext4', 'rw', 'relatime'),
        '/tmp': mount('tmpfs', 'rw', 'nosuid', 'nodev'),
        '/proc': mount('proc', 'rw', 'nosuid', 'nodev', 'noexec'),
        '/sys': mount('sysfs', 'ro', 'nosuid', 'nodev', 'noexec'),
        '/dev': mount('tmpfs', 'rw', 'nosuid'),
        '/dev/pts': mount('devpts', 'rw', 'nosuid', 'noexec'),
        '/dev/shm': mount('tmpfs', 'rw', 'nosuid', 'nodev', 'noexec'),
        '/dev/mqueue': mount('mqueue', 'rw', 'nosuid', 'nodev', 'noexec'),
        '/sys/fs/cgroup': mount('cgroup2', 'ro', 'nosuid', 'nodev', 'noexec'),
        '/etc/hosts': mount('ext4', 'rw', 'relatime'),
        '/etc/hostname': mount('ext4', 'rw', 'relatime'),
        '/etc/resolv.conf': mount('ext4', 'rw', 'relatime'),
    }
    masks = {}
    for path in C.L.PROC_READONLY:
        mounts[path] = mount('proc', 'ro', 'nosuid', 'nodev', 'noexec')
    for path in C.L.NULL_MASKS:
        mounts[path] = mount('tmpfs', 'rw', 'nosuid')
        masks[path] = dict(symlink=False, kind='char', device=[1, 3])
    for path in C.L.DIRECTORY_MASKS:
        mounts[path] = mount('tmpfs', 'ro')
        masks[path] = dict(symlink=False, kind='directory', device=None)
    value = contract()
    return dict(uid=0, arch='x86_64', docker_marker=True, caps=C.L.SAFE_CAPS,
        privileges={**{name:C.L.SAFE_CAPS for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')}, 'NoNewPrivs':1},
        device_exposure=False, docker_socket=False, interfaces=['lo'], mounts=mounts, mask_nodes=masks,
        nonce=value['nonce'], image_id=value['image_id'])


class ContractTests(unittest.TestCase):
    def test_exact_closed_host_scope_contract_accepts_synthetic_valid_shape(self):
        value = contract()
        self.assertIs(C.validate_contract(value), value)

    def test_extra_missing_boolean_schema_and_native_claim_refused(self):
        rows = []
        for field, val in (('schema_version', True), ('execution', 'native-aarch64-disposable-docker'),
                           ('purpose', 'production-install'), ('unexpected', True)):
            value = contract(); value[field] = val; rows.append(value)
        value = contract(); del value['nonce']; rows.append(value)
        for value in rows:
            with self.subTest(value=value.get('execution')):
                with self.assertRaises(C.Error): C.validate_contract(value)

    def test_mutable_image_and_invalid_nonce_refused(self):
        for field, val in (('image_id', 'archlinux:latest'), ('image_id', 'sha256:'+'A'*64),
                           ('nonce', 'd'*31), ('nonce', None)):
            value = contract(); value[field] = val
            with self.subTest(field=field, value=val), self.assertRaises(C.Error): C.validate_contract(value)

    def test_package_exact_archive_and_bounded_signature_required(self):
        for field, val in (('path', '../package.pkg.tar.zst'), ('sha256', '0'*64), ('bytes', C.PACKAGE_BYTES+1),
                           ('signature_bytes', True), ('signature_bytes', 0), ('signature_bytes', 65537),
                           ('signature_sha256', 'G'*64)):
            value = contract(); value['package'][field] = val
            with self.subTest(field=field, value=val), self.assertRaises(C.Error): C.validate_contract(value)

    def test_full_signer_and_finite_certificate_required(self):
        for field, val in (('fingerprint', 'A'*16), ('fingerprint', 'a'*40), ('certificate_bytes', 0),
                           ('certificate_bytes', 1024**2+1), ('certificate_sha256', 'g'*64)):
            value = contract(); value['signer'][field] = val
            with self.subTest(field=field, value=val), self.assertRaises(C.Error): C.validate_contract(value)

    def test_handoff_external_pins_and_fixed_runtime_required(self):
        for field, val in (('runtime_sha256', '0'*64), ('receipt_sha256', '0'*63),
                           ('archive_certificate_fingerprint', 'b'*40), ('selection_sha256', None)):
            value = contract(); value['handoff'][field] = val
            with self.subTest(field=field), self.assertRaises(C.Error): C.validate_contract(value)

    def test_handoff_paths_alias_scope_and_file_pins_refused(self):
        for name in ('../escape', '/absolute', '.', 'a/../b', 'a\\b', 'a\nb'):
            value = contract(); value['handoff']['files'][name] = '0'*64
            with self.subTest(name=name), self.assertRaises(C.Error): C.validate_contract(value)
        for target in ('../escape', '/absolute', 'directory/target', 'missing', '.'):
            value = contract(); value['handoff']['symlinks']['candidate/repo/database'] = target
            with self.subTest(target=target), self.assertRaises(C.Error): C.validate_contract(value)
        value = contract(); value['handoff']['files']['handoff.json'] = '0'*63
        with self.assertRaises(C.Error): C.validate_contract(value)
        value = contract(); value['handoff']['symlinks']['handoff.json'] = 'handoff.json'
        with self.assertRaises(C.Error): C.validate_contract(value)

    def test_handoff_member_and_alias_budgets_are_finite(self):
        value = contract(); value['handoff']['files'] = {f'file-{n}':'0'*64 for n in range(4097)}
        with self.assertRaises(C.Error): C.validate_contract(value)
        value = contract(); value['handoff']['symlinks'] = {f'alias-{n}':'handoff.json' for n in range(1025)}
        with self.assertRaises(C.Error): C.validate_contract(value)

    def test_payload_count_scope_modes_and_source_closure_are_closed(self):
        value = contract(); del value['payload'][C.LAUNCHER]
        with self.assertRaises(C.Error): C.validate_contract(value)
        for path in ('etc/pacman.conf', 'usr/bin/other', 'boot/loader', 'usr/lib/cachy-asahi/install-handoff/../escape'):
            value = contract(); value['payload'][path] = value['payload'].pop(next(n for n in value['payload'] if n != C.LAUNCHER))
            with self.subTest(path=path), self.assertRaises(C.Error): C.validate_contract(value)
        for field, val in (('mode', 0o4755), ('mode', True), ('bytes', -1), ('bytes', 4*1024**2+1), ('sha256', 'f'*63)):
            value = contract(); value['payload'][C.LAUNCHER][field] = val
            with self.subTest(field=field, value=val), self.assertRaises(C.Error): C.validate_contract(value)
        value = contract(); value['source_files']['extra.py'] = '0'*64
        with self.assertRaises(C.Error): C.validate_contract(value)


class GuardTests(unittest.TestCase):
    def test_host_x86_guard_accepts_observed_shape_without_native_admission(self):
        facts = probe()
        C.guard(facts, contract())
        self.assertEqual(facts['arch'], 'x86_64')
        with self.assertRaises(C.L.Error): C.L.environment_guard(facts)

    def test_host_execution_wrong_arch_user_and_identity_refused(self):
        for field, val in (('docker_marker', False), ('uid', 1000), ('uid', False), ('arch', 'aarch64'),
                           ('nonce', '0'*32), ('image_id', 'sha256:'+'0'*64)):
            facts = probe(); facts[field] = val
            with self.subTest(field=field, value=val), self.assertRaises(C.Error): C.guard(facts, contract())

    def test_capabilities_nnp_and_cleanup_cap_are_required(self):
        for field in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'):
            facts = probe(); facts['privileges'][field] |= 1 << 21
            with self.subTest(field=field), self.assertRaises(C.Error): C.guard(facts, contract())
        for value in (0, True, None):
            facts = probe(); facts['privileges']['NoNewPrivs'] = value
            with self.subTest(nnp=value), self.assertRaises(C.Error): C.guard(facts, contract())
        facts = probe(); facts['privileges']['CapEff'] &= ~(1 << 5); facts['caps'] = facts['privileges']['CapEff']
        with self.assertRaisesRegex(C.Error, 'ENV_CAP_KILL'): C.guard(facts, contract())
        facts = probe(); facts['caps'] ^= 1
        with self.assertRaises(C.Error): C.guard(facts, contract())

    def test_network_socket_and_device_exposure_refused(self):
        for field, val in (('interfaces', ['eth0', 'lo']), ('docker_socket', True), ('docker_socket', None),
                           ('device_exposure', True), ('device_exposure', None)):
            facts = probe(); facts[field] = val
            with self.subTest(field=field, value=val), self.assertRaises(C.Error): C.guard(facts, contract())

    def test_writable_input_runner_readonly_output_and_nonoverlay_root_refused(self):
        for point, flags in (('/inputs', ['rw']), ('/runner', ['rw']), ('/out', ['ro']), ('/', ['ro'])):
            facts = probe(); facts['mounts'][point]['options'] = flags
            with self.subTest(point=point), self.assertRaises(C.Error): C.guard(facts, contract())
        facts = probe(); facts['mounts']['/']['fs'] = 'ext4'
        with self.assertRaises(C.Error): C.guard(facts, contract())

    def test_tmpfs_and_required_mounts_refused_when_missing_or_unsafe(self):
        for field, val in (('fs', 'ext4'), ('options', ['rw', 'nosuid']), ('options', ['rw', 'nodev'])):
            facts = probe(); facts['mounts']['/tmp'][field] = val
            with self.subTest(field=field, value=val), self.assertRaises(C.Error): C.guard(facts, contract())
        for point in ('/inputs', '/runner', '/out', '/proc', '/sys', '/dev', '/tmp'):
            facts = probe(); del facts['mounts'][point]
            with self.subTest(point=point), self.assertRaises(C.Error): C.guard(facts, contract())

    def test_unknown_nested_and_host_system_mounts_refused(self):
        for point in ('/inputs/nested', '/runner/source', '/out/nested', '/usr', '/home/gabe', '/unexpected'):
            facts = probe(); facts['mounts'][point] = dict(fs='ext4', options=['ro'])
            with self.subTest(point=point), self.assertRaises(C.Error): C.guard(facts, contract())

    def test_bad_standard_runtime_roles_and_mask_identities_refused(self):
        for point in ('/proc', '/sys', '/dev', '/dev/pts', '/dev/shm', '/sys/fs/cgroup'):
            facts = probe(); facts['mounts'][point]['fs'] = 'ext4'
            with self.subTest(point=point), self.assertRaises(C.Error): C.guard(facts, contract())
        null = next(iter(C.L.NULL_MASKS)); directory = next(iter(C.L.DIRECTORY_MASKS))
        for point, field, value in ((null, 'device', [1, 5]), (null, 'symlink', True),
                                   (null, 'kind', 'file'), (directory, 'kind', 'char')):
            facts = probe(); facts['mask_nodes'][point][field] = value
            with self.subTest(point=point, field=field), self.assertRaises(C.Error): C.guard(facts, contract())
        facts = probe(); facts['mask_nodes'] = None
        with self.assertRaises(C.Error): C.guard(facts, contract())

    def test_contradictory_duplicate_or_malformed_mount_options_refused(self):
        for flags in (['ro', 'rw'], ['ro', 'ro'], ['ro', None], ['ro', 'exec', 'noexec']):
            facts = probe(); facts['mounts']['/inputs']['options'] = flags
            with self.subTest(flags=flags), self.assertRaises(C.Error): C.guard(facts, contract())

    def test_optional_standard_devtmpfs_mounts_accept_only_observed_identities(self):
        facts = probe()
        facts['standard_devices'] = {}
        for point, identity in C.STANDARD_DEVICES.items():
            facts['mounts'][point] = dict(fs='devtmpfs', options=['rw', 'nosuid'])
            facts['standard_devices'][point] = dict(symlink=False, kind='char', device=list(identity))
        C.guard(facts, contract())
        self.assertEqual(facts['arch'], 'x86_64')
        self.assertEqual(facts['privileges']['CapEff'], C.L.SAFE_CAPS)
        # Conventional Docker without the individual bind mounts still passes.
        C.guard(probe(), contract())

    def test_standard_device_wrong_identity_symlink_and_mount_role_refused(self):
        for point, identity in C.STANDARD_DEVICES.items():
            original = probe()
            original['mounts'][point] = dict(fs='devtmpfs', options=['rw', 'nosuid'])
            original['standard_devices'] = {point: dict(symlink=False, kind='char', device=list(identity))}
            for field, value in (('device', [99, identity[1]]), ('device', [True, identity[1]]),
                                 ('symlink', True), ('kind', 'file')):
                facts = copy.deepcopy(original); facts['standard_devices'][point][field] = value
                with self.subTest(point=point, field=field, value=value), self.assertRaises(C.Error):
                    C.guard(facts, contract())
            for field, value in (('fs', 'tmpfs'), ('options', ['ro', 'nosuid']), ('options', ['rw'])):
                facts = copy.deepcopy(original); facts['mounts'][point][field] = value
                with self.subTest(point=point, field=field, value=value), self.assertRaises(C.Error):
                    C.guard(facts, contract())
            facts = copy.deepcopy(original); del facts['standard_devices'][point]
            with self.subTest(point=point, missing=True), self.assertRaises(C.Error):
                C.guard(facts, contract())

    def test_unknown_device_path_or_identity_field_is_not_a_standard_device(self):
        facts = probe()
        facts['mounts']['/dev/nonstandard'] = dict(fs='devtmpfs', options=['rw', 'nosuid'])
        facts['standard_devices'] = {'/dev/nonstandard': dict(symlink=False, kind='char', device=[1, 3])}
        with self.assertRaisesRegex(C.Error, 'ENV_STANDARD_DEVICE_SET'): C.guard(facts, contract())
        del facts['standard_devices']
        with self.assertRaisesRegex(C.Error, 'ENV_UNKNOWN_MOUNT'): C.guard(facts, contract())
        facts = probe()
        facts['standard_devices'] = {'/dev/null': dict(symlink=False, kind='char', device=[1, 3], extra=True)}
        with self.assertRaisesRegex(C.Error, 'ENV_STANDARD_DEVICE_IDENTITY'): C.guard(facts, contract())

    def test_rootless_devtmpfs_null_masks_accept_exact_known_null_devices(self):
        facts = probe()
        for point in ('/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/timer_list'):
            self.assertIn(point, C.L.NULL_MASKS)
            facts['mounts'][point] = dict(fs='devtmpfs', options=['rw', 'nosuid'])
            self.assertEqual(facts['mask_nodes'][point], dict(symlink=False, kind='char', device=[1, 3]))
        C.guard(facts, contract())
        self.assertEqual(facts['privileges']['CapEff'], C.L.SAFE_CAPS)
        self.assertEqual(facts['arch'], 'x86_64')

    def test_devtmpfs_null_mask_wrong_device_path_mode_or_missing_identity_refused(self):
        point = '/proc/kcore'
        original = probe()
        original['mounts'][point] = dict(fs='devtmpfs', options=['rw', 'nosuid'])
        for field, value in (('device', [1, 5]), ('device', [True, 3]), ('symlink', True), ('kind', 'file')):
            facts = copy.deepcopy(original); facts['mask_nodes'][point][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(C.Error): C.guard(facts, contract())
        for flags in (['ro', 'nosuid'], ['rw'], ['rw', 'suid']):
            facts = copy.deepcopy(original); facts['mounts'][point]['options'] = flags
            with self.subTest(flags=flags), self.assertRaises(C.Error): C.guard(facts, contract())
        facts = copy.deepcopy(original); del facts['mask_nodes'][point]
        with self.assertRaisesRegex(C.Error, 'ENV_MASK_IDENTITY'): C.guard(facts, contract())
        facts = copy.deepcopy(original); facts['mask_nodes'][point]['extra'] = True
        with self.assertRaisesRegex(C.Error, 'ENV_MASK_IDENTITY'): C.guard(facts, contract())
        facts = probe()
        facts['mounts']['/proc/nonstandard-mask'] = dict(fs='devtmpfs', options=['rw', 'nosuid'])
        facts['mask_nodes']['/proc/nonstandard-mask'] = dict(symlink=False, kind='char', device=[1, 3])
        with self.assertRaisesRegex(C.Error, 'ENV_UNKNOWN_MOUNT'): C.guard(facts, contract())


if __name__ == '__main__':
    unittest.main()
