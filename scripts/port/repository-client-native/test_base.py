"""Parser/control fixtures are synthetic; real CLI tests establish local bounds only."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('native_base_tested', Path(__file__).with_name('base.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def fixture():
    """Explicit fabricated 341-package ALPM control inputs, never native evidence."""
    lock = ''.join(f'base-{i:03d} 1-1\n' for i in range(341)).encode()
    records = {}
    for i in range(341):
        name = f'base-{i:03d}'
        records[name + '-1-1'] = {
            'desc': f'%NAME%\n{name}\n\n%VERSION%\n1-1\n\n%ARCH%\naarch64\n\n'.encode(),
            'files': f'%FILES%\nusr/\nusr/bin/\nusr/bin/{name}\n\n'.encode()}
    return records, lock


class BaseParserTests(unittest.TestCase):
    def setUp(self):
        self.records, self.lock = fixture()
        self.first = 'base-000-1-1'

    def test_exact_generic_metadata_and_shared_directories(self):
        result = base.parse_local(self.records, self.lock)
        self.assertEqual(result['package_count'], 341)
        self.assertEqual(result['supported_models'], [])
        self.assertEqual(result['packages'][0], {'name': 'base-000', 'version': '1-1', 'arch': 'aarch64',
                                               'depend': [], 'provides': [], 'conflict': [], 'files': ['usr/bin/base-000']})
        self.assertEqual(len(result['local_records']), 682)

    def test_relations_and_symlink_ownership_retained(self):
        self.records[self.first]['desc'] += b'%DEPENDS%\nbase-001>=1-1\nlibfoo.so=2-64\n\n%PROVIDES%\nvirtual-base=1\n\n%CONFLICTS%\nold-base\n\n'
        self.records[self.first]['files'] += b'%BACKUP%\nusr/bin/base-000\t0123456789abcdef0123456789abcdef\n\n'
        row = base.parse_local(self.records, self.lock)['packages'][0]
        self.assertEqual(row['depend'], ['base-001>=1-1', 'libfoo.so=2-64'])
        self.assertIn('usr/bin/base-000', row['files'])  # Metadata does not dereference symlink payloads.
        self.assertEqual(row['provides'], ['virtual-base=1'])

    def test_any_arch_and_empty_files_allowed(self):
        self.records[self.first]['desc'] = self.records[self.first]['desc'].replace(b'aarch64', b'any')
        self.records[self.first]['files'] = b'%FILES%\n\n'
        self.assertEqual(base.parse_local(self.records, self.lock)['packages'][0]['files'], [])

    def test_wrong_package_count(self):
        for change in ('missing', 'extra'):
            with self.subTest(change=change):
                records = copy.deepcopy(self.records)
                if change == 'missing':
                    records.pop(self.first)
                else:
                    records['extra-1-1'] = records[self.first]
                with self.assertRaises(base.Refused):
                    base.parse_local(records, self.lock)

    def test_lock_unsorted_duplicate_short_or_no_lf(self):
        lines = self.lock.splitlines(keepends=True)
        for lock in (b''.join(reversed(lines)), lines[0] + b''.join(lines[:-1]), b''.join(lines[:-1]), self.lock[:-1]):
            with self.subTest(lock=lock[:35]):
                with self.assertRaises(base.Refused):
                    base.parse_local(self.records, lock)

    def test_identity_architecture_and_optional_relation_poison(self):
        original = self.records[self.first]['desc']
        for raw in (original.replace(b'base-000', b'base-999'), original.replace(b'1-1', b'2-1'),
                    original.replace(b'aarch64', b'x86_64'), original + b'%DEPENDS%\n../escape\n\n',
                    original + b'%PROVIDES%\nfoo =1\n\n'):
            with self.subTest(raw=raw[-45:]):
                self.records[self.first]['desc'] = raw
                with self.assertRaises(base.Refused):
                    base.parse_local(self.records, self.lock)

    def test_missing_duplicate_unknown_stray_sections(self):
        original = self.records[self.first]['desc']
        for raw in (original.replace(b'%ARCH%\naarch64\n\n', b''), original + b'%NAME%\nbase-000\n\n',
                    original + b'%UNKNOWN%\nfoo\n\n', b'stray\n' + original,
                    original.replace(b'base-000\n\n', b'base-000\n'), original + b'%DEPENDS%\nfoo\nfoo\n\n'):
            with self.subTest(raw=raw[-45:]):
                self.records[self.first]['desc'] = raw
                with self.assertRaises(base.Refused):
                    base.parse_local(self.records, self.lock)

    def test_unsafe_file_paths(self):
        for path in ('/root/file', '../file', 'usr/../file', 'usr//file', './file', 'usr/./file', 'usr\\file', '.', 'usr/\tfile'):
            with self.subTest(path=path):
                self.records[self.first]['files'] = ('%FILES%\n' + path + '\n\n').encode()
                with self.assertRaises(base.Refused):
                    base.parse_local(self.records, self.lock)

    def test_duplicate_file_ownership_and_bad_backup(self):
        self.records['base-001-1-1']['files'] = self.records[self.first]['files']
        with self.assertRaisesRegex(base.Refused, 'ownership'):
            base.parse_local(self.records, self.lock)
        self.records, self.lock = fixture()
        self.records[self.first]['files'] += b'%BACKUP%\nnot-owned\t0123456789abcdef0123456789abcdef\n\n'
        with self.assertRaises(base.Refused):
            base.parse_local(self.records, self.lock)

    def test_unbounded_and_invalid_text(self):
        for raw in (b'\xff\n', b'%NAME%\nfoo\x00\n', b'x' * (base.RECORD_LIMIT + 1)):
            self.records[self.first]['desc'] = raw
            with self.assertRaises(base.Refused):
                base.parse_local(self.records, self.lock)

    def test_local_record_extra_fields_or_unsafe_dir(self):
        self.records[self.first]['install'] = b'bad'
        with self.assertRaises(base.Refused):
            base.parse_local(self.records, self.lock)
        self.records, self.lock = fixture()
        self.records['../evil'] = self.records.pop(self.first)
        with self.assertRaises(base.Refused):
            base.parse_local(self.records, self.lock)

    def test_actual_query_bindings_require_complete_directories_and_files(self):
        result = base.parse_local(self.records, self.lock)
        listing = ''.join(f'base-{i:03d} /{path}\n' for i in range(341)
                          for path in ('usr/', 'usr/bin/', f'usr/bin/base-{i:03d}')).encode()
        base.validate_queries(result, self.records, self.lock, listing)
        for query, files in ((self.lock[:-1] + b'broken\n', listing), (self.lock, listing + listing[:15]),
                             (self.lock, listing.replace(b'/usr/bin/base-000', b'/usr/bin/other'))):
            with self.assertRaises(base.Refused):
                base.validate_queries(result, self.records, query, files)


class HostControlFixtures(unittest.TestCase):
    """Mocked container control only; PASS here is NOT actual native execution."""
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.records, self.lock = fixture()
        self.inputs = base.encoded({'snapshot_id': 'SYNTHETIC-reviewed-inputs-not-native'})
        self.image = 'sha256:' + '1' * 64
        self.boot = base.encoded({'status': 'image-provisioned', 'image_id': self.image,
            'inputs_sha256': base.digest(self.inputs), 'packages_lock_sha256': base.digest(self.lock)})
        source = Path(base.__file__).parent
        self.pins = {name: {'sha256': base.digest(base.nofollow_read(source / name)),
                           'mode': (source / name).stat().st_mode & 0o777}
                     for name in ('base.py', 'common.py', 'worker.py')}
        self.common = base.authenticated_common(self.pins)
        self.cleanup = {'status': 'PASS', 'cleanup': 'PASS', 'container_id': '2' * 64,
                        'container': 'cachy-asahi-repository-client-' + '3' * 32, 'image_id': self.image,
                        'ownership_verified': True, 'commands': [], 'tool_sha256': {'docker': '4' * 64},
                        'name_absence_verified': True, 'id_absence_verified': True, 'absence_verified': True,
                        'fixture_scope': 'MOCK-CONTROL-NOT-NATIVE'}

    def tearDown(self):
        self.directory.cleanup()

    def fake_worker(self, image, source, inputs, output, argv, expected_arch):
        self.assertEqual(argv[0], '/source/base.py')
        self.assertEqual(expected_arch, 'aarch64')
        metadata = base.bind_inputs(base.parse_local(self.records, self.lock), self.inputs)
        local = output / 'local'
        local.mkdir()
        for name, row in self.records.items():
            target = local / name
            target.mkdir()
            for kind, data in row.items():
                (target / kind).write_bytes(data)
        query = self.lock
        listing = ''.join(f'base-{i:03d} /{path}\n' for i in range(341)
                          for path in ('usr/', 'usr/bin/', f'usr/bin/base-{i:03d}')).encode()
        observations = {'schema_version': 1, 'purpose': 'actual-immutable-generic-base-metadata', 'status': 'PASS',
                       'architecture': 'aarch64', 'root_readonly': True, 'packages_lock_sha256': base.digest(self.lock),
                       'package_count': 341, 'inputs_sha256': base.digest(self.inputs),
                       'snapshot_id': 'SYNTHETIC-reviewed-inputs-not-native', 'hardware_validation': 'NOT RUN',
                       'commands': [{'argv': ['/usr/bin/pacman', '-Q'], 'exit_code': 0,
                                     'stdout_sha256': base.digest(query), 'stderr_sha256': base.digest(b'')},
                                    {'argv': ['/usr/bin/pacman', '-Ql'], 'exit_code': 0,
                                     'stdout_sha256': base.digest(listing), 'stderr_sha256': base.digest(b'')}]}
        for name, raw in {'base.json': base.encoded(metadata), 'observations.json': base.encoded(observations),
                          'pacman-Q.stdout': query, 'pacman-Q.stderr': b'', 'pacman-Ql.stdout': listing,
                          'pacman-Ql.stderr': b''}.items():
            (output / name).write_bytes(raw)
        receipt = dict(self.cleanup)
        cid, name = receipt['container_id'], receipt['container']
        # Fabricated Docker observations exercise receiver controls only.
        create = ['create', '--name', name, '--cidfile', '/tmp/SYNTHETIC-control/container-id', '--pull=never',
            '--platform=linux/arm64', '--user', '1000:1000', '--network=none', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--read-only', '--pids-limit=128', '--memory=2g', '--cpus=2',
            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777', '--mount',
            'type=bind,src=' + str(source) + ',dst=/source,readonly', '--mount',
            'type=bind,src=' + str(inputs) + ',dst=/inputs,readonly', '--mount',
            'type=bind,src=' + str(output) + ',dst=/out', '--entrypoint=/usr/bin/python3', image, '-I', '-B',
            '/source/worker.py', '--source-map-sha256', base.digest(base.encoded(self.pins)), '--module', 'base',
            *argv[1:]]
        operations = [(['info', '--format', '{{.Architecture}}'], b'aarch64\n'),
            (['image', 'inspect', image], b'SYNTHETIC-image-observation\n'), (create, (str(cid) + '\n').encode()),
            (['container', 'inspect', cid], b'SYNTHETIC-ownership-observation\n'),
            (['start', '--attach', cid], b''), (['container', 'inspect', cid], b'SYNTHETIC-terminal-observation\n'),
            (['container', 'inspect', cid], b'SYNTHETIC-removal-observation\n'),
            (['container', 'rm', '-f', cid], (str(cid) + '\n').encode()),
            (['container', 'ls', '-a', '--no-trunc', '--format', '{{.ID}} {{.Names}}'], b'')]
        receipt['commands'] = [{'argv': ['/usr/bin/docker', *args], 'exit_code': 0,
            'stdout_sha256': base.digest(raw), 'stderr_sha256': base.digest(b''), 'stdout_bytes': len(raw), 'stderr_bytes': 0}
            for args, raw in operations]
        return receipt

    def execute(self, **changes):
        args = dict(image_id=self.image, bootstrap_raw=self.boot, bootstrap_pin=base.digest(self.boot),
                    packages_raw=self.lock, packages_pin=base.digest(self.lock), source_map=self.pins,
                    output=self.root / 'output', inputs_raw=self.inputs, inputs_pin=base.digest(self.inputs))
        args.update(changes)
        with mock.patch.object(base, 'authenticated_common', return_value=self.common), \
             mock.patch.object(self.common, 'run_owned', side_effect=self.fake_worker):
            return base.collect_base(**args)

    def test_mock_control_complete_capture_then_publication(self):
        result = self.execute()
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['worker']['fixture_scope'], 'MOCK-CONTROL-NOT-NATIVE')
        self.assertEqual(result['snapshot_id'], 'SYNTHETIC-reviewed-inputs-not-native')
        self.assertEqual(result['hardware_validation'], 'NOT RUN')
        self.assertEqual(len(result['files']), 688)
        self.assertTrue((self.root / 'output/result.json').exists())

    def test_missing_id_name_or_cleanup_refused_before_publication(self):
        for field, value in (('container_id', None), ('name_absence_verified', False),
                             ('id_absence_verified', False), ('cleanup', 'FAIL')):
            with self.subTest(field=field):
                old = dict(self.cleanup)
                self.cleanup[field] = value
                with self.assertRaises(base.Refused):
                    self.execute()
                self.assertFalse((self.root / 'output').exists())
                self.cleanup = old

    def test_external_pin_and_bootstrap_binding_refused(self):
        for changes in ({'inputs_pin': '0' * 64}, {'packages_pin': '0' * 64}, {'bootstrap_pin': '0' * 64},
                        {'image_id': 'sha256:' + 'a' * 64}):
            with self.subTest(changes=changes):
                with self.assertRaises(base.Refused):
                    self.execute(**changes)
                self.assertFalse((self.root / 'output').exists())

    def test_source_authentication_refuses_drift_extra_and_bytecode_before_exec(self):
        for pins in ({**self.pins, 'evil.pyc': {'sha256': '0' * 64, 'mode': 0o644}},
                     {**self.pins, 'common.py': {'sha256': '0' * 64, 'mode': self.pins['common.py']['mode']}},
                     {**self.pins, 'common.py': {'sha256': self.pins['common.py']['sha256'], 'mode': 0o700}}):
            with self.subTest(pins=pins):
                with self.assertRaises(base.Refused):
                    base.authenticated_common(pins)

    def modeled_receivable(self):
        """Mock-control collector result using exact production receipt shape."""
        result = self.execute()
        result['worker'].pop('fixture_scope')
        raw = base.encoded(result)
        (self.root / 'output/result.json').write_bytes(raw)
        return result, raw

    def repin_modeled(self, result):
        raw = base.encoded(result)
        (self.root / 'output/result.json').write_bytes(raw)
        return raw

    def test_modeled_collector_receiver_positive_finite_admission(self):
        result, raw = self.modeled_receivable()
        accepted = base.receive_base(self.root / 'output', raw, base.digest(raw))
        self.assertEqual(accepted['status'], 'PASS')
        self.assertEqual(accepted['base']['package_count'], 341)
        self.assertEqual(accepted['base']['snapshot_id'], 'SYNTHETIC-reviewed-inputs-not-native')
        self.assertEqual(accepted['hardware_validation'], 'NOT RUN')
        self.assertEqual(len(accepted['approved_files']), 689)
        self.assertIn('observed/local/base-000-1-1/desc', accepted['approved_files'])

    def test_receiver_external_pin_actual_receipt_and_byte_drift(self):
        result, raw = self.modeled_receivable()
        with self.assertRaises(base.Refused):
            base.receive_base(self.root / 'output', raw, '0' * 64)
        (self.root / 'output/result.json').write_bytes(raw + b'\n')
        with self.assertRaises(base.Refused):
            base.receive_base(self.root / 'output', raw, base.digest(raw))
        (self.root / 'output/result.json').write_bytes(raw)
        (self.root / 'output/observed/local/base-000-1-1/desc').write_bytes(b'drift\n')
        with self.assertRaises(base.Refused):
            base.receive_base(self.root / 'output', raw, base.digest(raw))

    def test_receiver_coherent_metadata_and_query_forgery_refused(self):
        result, raw = self.modeled_receivable()
        path = self.root / 'output/observed/base.json'
        original = path.read_bytes()
        metadata = json.loads(original)
        metadata['packages'][0]['depend'] = ['fabricated-relation']
        poisoned = base.encoded(metadata)
        path.write_bytes(poisoned)
        result['base_sha256'] = base.digest(poisoned)
        result['files']['base.json'] = {'sha256': base.digest(poisoned), 'bytes': len(poisoned)}
        raw = self.repin_modeled(result)
        with self.assertRaises(base.Refused):
            base.receive_base(self.root / 'output', raw, base.digest(raw))
        path.write_bytes(original)
        result['base_sha256'] = base.digest(original)
        result['files']['base.json'] = {'sha256': base.digest(original), 'bytes': len(original)}
        path = self.root / 'output/observed/pacman-Ql.stdout'
        poisoned = path.read_bytes().replace(b'/usr/bin/base-000', b'/usr/bin/fabricated')
        path.write_bytes(poisoned)
        result['files']['pacman-Ql.stdout'] = {'sha256': base.digest(poisoned), 'bytes': len(poisoned)}
        raw = self.repin_modeled(result)
        with self.assertRaises(base.Refused):
            base.receive_base(self.root / 'output', raw, base.digest(raw))

    def test_receiver_coherent_bad_ownership_and_creation_policy_refused(self):
        original, raw = self.modeled_receivable()
        for mutate in (lambda r: r['worker'].update(container_id='bad-id'),
                       lambda r: r['worker'].update(container_id=True),
                       lambda r: r['worker'].update(container=17),
                       lambda r: r['worker'].update(ownership_verified=False),
                       lambda r: r['worker'].update(image_id='sha256:' + '9' * 64),
                       lambda r: r['worker'].update(id_absence_verified=False),
                       lambda r: r['worker']['commands'][2]['argv'].remove('--read-only'),
                       lambda r: r['worker']['commands'][7]['argv'].__setitem__(-1, '9' * 64),
                       lambda r: r['worker']['commands'][2]['argv'].__setitem__(31, '9' * 64),
                       lambda r: r['source_map']['base.py'].update(mode=True)):
            result = copy.deepcopy(original)
            mutate(result)
            raw = self.repin_modeled(result)
            with self.subTest(worker=result['worker']):
                with self.assertRaises(base.Refused):
                    base.receive_base(self.root / 'output', raw, base.digest(raw))

    def test_receiver_extra_file_directory_links_and_coherent_map_extras_refused(self):
        result, raw = self.modeled_receivable()
        output = self.root / 'output'
        extra = output / 'unapproved-private-data'
        extra.write_bytes(b'never read arbitrary extra contents')
        with self.assertRaises(base.Refused):
            base.receive_base(output, raw, base.digest(raw))
        extra.unlink()
        extra.mkdir()
        with self.assertRaises(base.Refused):
            base.receive_base(output, raw, base.digest(raw))
        extra.rmdir()
        extra = output / 'observed/secret.key'
        extra.write_bytes(b'not an approved metadata suffix')
        result['files']['secret.key'] = {'sha256': base.digest(extra.read_bytes()), 'bytes': extra.stat().st_size}
        raw = self.repin_modeled(result)
        with self.assertRaises(base.Refused):
            base.receive_base(output, raw, base.digest(raw))

    def test_receiver_expected_file_symlink_hardlink_and_parent_link_refused(self):
        result, raw = self.modeled_receivable()
        output = self.root / 'output'
        path = output / 'observed/local/base-000-1-1/desc'
        original = path.read_bytes()
        target = self.root / 'external-not-approved'
        target.write_bytes(original)
        path.unlink()
        path.symlink_to(target)
        with self.assertRaises((base.Refused, OSError)):
            base.receive_base(output, raw, base.digest(raw))
        path.unlink()
        os.link(target, path)
        with self.assertRaises(base.Refused):
            base.receive_base(output, raw, base.digest(raw))
        path.unlink()
        path.write_bytes(original)
        alias = self.root / 'root-alias'
        alias.symlink_to(output, target_is_directory=True)
        with self.assertRaises(OSError):
            base.receive_base(alias, raw, base.digest(raw))

    def test_real_term_before_and_after_result_write_invalidates_and_preserves_cleanup(self):
        for when in ('before', 'after'):
            with self.subTest(when=when):
                actual = self.common.write_new
                output = self.root / ('publication-' + when)
                fired = []
                def interrupted_write(path, raw, mode=0o600):
                    targeted = Path(path) == output / 'result.json'
                    if targeted and when == 'before':
                        fired.append(when)
                        os.kill(os.getpid(), signal.SIGTERM)
                    result = actual(path, raw, mode)
                    if targeted and when == 'after':
                        fired.append(when)
                        os.kill(os.getpid(), signal.SIGTERM)
                    return result
                with mock.patch.object(self.common, 'write_new', side_effect=interrupted_write):
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        self.execute(output=output)
                self.assertEqual(fired, [when])
                self.assertFalse((output / 'result.json').exists())
                receipt = caught.exception.receipt
                self.assertEqual((receipt['status'], receipt['cleanup']), ('FAIL', 'PASS'))
                self.assertEqual(receipt['worker']['fixture_scope'], 'MOCK-CONTROL-NOT-NATIVE')
                self.assertTrue(receipt['publication']['receipt_absence_verified'])

    def test_real_term_in_terminal_os_close_before_and_after(self):
        for when in ('before', 'after'):
            with self.subTest(when=when):
                output = self.root / ('close-' + when)
                target, fired = [], []
                original_create, actual_close = base.Publication.create, os.close
                def create(publication):
                    original_create(publication)
                    target.append(publication.fd)
                def close(descriptor):
                    hit = target and descriptor == target[0] and not fired and (output / 'result.json').exists()
                    if hit and when == 'before':
                        fired.append(when)
                        os.kill(os.getpid(), signal.SIGTERM)
                    result = actual_close(descriptor)
                    if hit and when == 'after':
                        fired.append(when)
                        os.kill(os.getpid(), signal.SIGTERM)
                    return result
                with mock.patch.object(base.Publication, 'create', new=create), mock.patch.object(base.os, 'close', new=close):
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        self.execute(output=output)
                self.assertEqual(fired, [when])
                self.assertFalse((output / 'result.json').exists())
                self.assertEqual(caught.exception.receipt['cleanup'], 'PASS')
                self.assertTrue(caught.exception.receipt['publication']['receipt_absence_verified'])
                with self.assertRaises(OSError):
                    os.fstat(target[0])

    def test_real_term_in_common_directory_close_reaps_all_descriptors(self):
        for when in ('before', 'after'):
            with self.subTest(when=when):
                output = self.root / ('directory-close-' + when)
                actual_close, fired = os.close, []
                before = set(os.listdir('/proc/' + str(os.getpid()) + '/fd'))
                def close(descriptor):
                    hit = False
                    if not fired and (output / 'result.json').exists():
                        info = os.fstat(descriptor)
                        root = output.stat()
                        hit = (info.st_dev, info.st_ino) == (root.st_dev, root.st_ino)
                    if hit and when == 'before':
                        fired.append(when)
                        os.kill(os.getpid(), signal.SIGTERM)
                    result = actual_close(descriptor)
                    if hit and when == 'after':
                        fired.append(when)
                        os.kill(os.getpid(), signal.SIGTERM)
                    return result
                with mock.patch.object(base.os, 'close', new=close):
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        self.execute(output=output)
                self.assertEqual(fired, [when])
                self.assertEqual(set(os.listdir('/proc/' + str(os.getpid()) + '/fd')), before)
                self.assertFalse((output / 'result.json').exists())
                self.assertEqual(caught.exception.receipt['cleanup'], 'PASS')
                self.assertTrue(caught.exception.receipt['publication']['receipt_absence_verified'])

    def test_replacement_output_preserved_and_original_inode_invalidated(self):
        for when in ('write', 'after-close'):
            with self.subTest(when=when):
                output, retired = self.root / ('replaced-' + when), self.root / ('original-' + when)
                foreign = b'{"status":"USER-OWNED-DO-NOT-DELETE"}\n'
                actual_write, actual_close = self.common.write_new, base.Publication.close
                fired = []
                def replace():
                    output.rename(retired)
                    output.mkdir()
                    (output / 'result.json').write_bytes(foreign)
                    fired.append(when)
                    os.kill(os.getpid(), signal.SIGTERM)
                def write(path, raw, mode=0o600):
                    result = actual_write(path, raw, mode)
                    if when == 'write' and Path(path) == output / 'result.json' and not fired:
                        replace()
                    return result
                def close(publication):
                    result = actual_close(publication)
                    if when == 'after-close' and not fired:
                        replace()
                    return result
                with mock.patch.object(self.common, 'write_new', side_effect=write), \
                     mock.patch.object(base.Publication, 'close', new=close):
                    with self.assertRaises((KeyboardInterrupt, base.Refused)) as caught:
                        self.execute(output=output)
                self.assertEqual(fired, [when])
                self.assertEqual((output / 'result.json').read_bytes(), foreign)
                self.assertFalse((retired / 'result.json').exists())
                self.assertEqual(caught.exception.receipt['cleanup'], 'PASS')
                self.assertTrue(caught.exception.receipt['publication']['receipt_absence_verified'])

    def test_real_term_private_teardown_completes_before_publication(self):
        actual_cleanup, temporary_paths, fired = tempfile.TemporaryDirectory.cleanup, [], []
        def cleanup(temporary):
            if Path(temporary.name).name.startswith('repository-client-native-base-') and not fired:
                temporary_paths.append(Path(temporary.name))
                fired.append(True)
                os.kill(os.getpid(), signal.SIGTERM)
            return actual_cleanup(temporary)
        with mock.patch.object(tempfile.TemporaryDirectory, 'cleanup', new=cleanup):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.execute()
        self.assertEqual(fired, [True])
        self.assertTrue(all(not path.exists() for path in temporary_paths))
        self.assertFalse((self.root / 'output').exists())
        self.assertEqual((caught.exception.receipt['status'], caught.exception.receipt['cleanup']), ('FAIL', 'PASS'))

    def test_inputs_snapshot_required_and_duplicate_json_refused(self):
        for raw in (b'{}\n', b'{"snapshot_id":"a","snapshot_id":"b"}\n',
                    b'{"snapshot_id":"../unsafe"}\n'):
            with self.assertRaises(base.Refused):
                base.bind_inputs({}, raw)


class RealBoundedCLITests(unittest.TestCase):
    def test_real_cli_dual_stream_observation(self):
        stdout, stderr = base.run_command([sys.executable, '-I', '-c', 'print("actual CLI output")'])
        self.assertEqual((stdout, stderr), (b'actual CLI output\n', b''))

    def test_real_cli_nonzero_stderr_and_output_limit_refused(self):
        for code, limit in (('raise SystemExit(7)', 1024), ('import sys;sys.stderr.write("error\\n")', 1024),
                            ('print("x"*8192)', 256)):
            with self.subTest(code=code):
                with self.assertRaises(base.Refused):
                    base.run_command([sys.executable, '-I', '-c', code], limit=limit)

    def test_real_signal_after_popen_before_assignment_reaps_child(self):
        actual = subprocess.Popen
        children = []
        def interrupted_spawn(*args, **kwargs):
            process = actual(*args, **kwargs)
            children.append(process)
            os.kill(os.getpid(), signal.SIGTERM)
            return process
        with mock.patch.object(base.subprocess, 'Popen', side_effect=interrupted_spawn):
            with self.assertRaises(KeyboardInterrupt):
                base.run_command([sys.executable, '-I', '-c', 'import time;time.sleep(60)'])
        self.assertEqual(len(children), 1)
        child = children[0]
        self.assertIsNotNone(child.returncode)
        self.assertTrue(child.stdout.closed and child.stderr.closed)
        with self.assertRaises(ProcessLookupError):
            os.kill(child.pid, 0)

    def test_real_cli_timeout_reaps_group(self):
        started = time.monotonic()
        with self.assertRaises(base.Refused):
            base.run_command([sys.executable, '-I', '-c', 'import time;time.sleep(60)'], timeout=0.15)
        self.assertLess(time.monotonic() - started, 3)

    def test_nofollow_read_real_file_symlink_parent_and_hardlink(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / 'record'
            path.write_bytes(b'actual bytes')
            self.assertEqual(base.nofollow_read(path), b'actual bytes')
            alias = root / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                base.nofollow_read(alias)
            parent = root / 'other'
            parent.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                base.nofollow_read(parent / 'record')
            os.link(path, root / 'hardlink')
            with self.assertRaises(base.Refused):
                base.nofollow_read(path)

    def test_real_worker_cli_refuses_host_and_does_not_publish(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'lock').write_bytes(fixture()[1])
            output = root / 'output'
            output.mkdir()
            result = subprocess.run([sys.executable, '-I', '-B', str(Path(base.__file__)), '--worker', '--lock', str(root / 'lock'),
                                     '--output', str(output), '--inputs', str(root / 'lock')], capture_output=True, timeout=10)
            # Test only local refusal. This host is not an isolated immutable native builder.
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(output.iterdir()), [])

    def test_real_signals_reap_spawned_child(self):
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                child_pid = root / 'child.pid'
                program = root / 'runner.py'
                code = 'import os,time;from pathlib import Path;Path(' + repr(str(child_pid)) + ').write_text(str(os.getpid()));time.sleep(60)'
                program.write_text('import importlib.util\n'
                    's=importlib.util.spec_from_file_location("b",' + repr(base.__file__) + ')\n'
                    'b=importlib.util.module_from_spec(s);s.loader.exec_module(b)\n'
                    'try: b.run_command(' + repr([sys.executable, '-I', '-c', code]) + ')\n'
                    'except KeyboardInterrupt: pass\n')
                runner = subprocess.Popen([sys.executable, '-I', '-B', str(program)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 5
                    while not child_pid.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(child_pid.exists())
                    pid = int(child_pid.read_text())
                    os.kill(runner.pid, signum)
                    runner.communicate(timeout=5)
                    self.assertEqual(runner.returncode, 0)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
                finally:
                    if runner.poll() is None:
                        runner.kill()
                        runner.communicate()


if __name__ == '__main__':
    unittest.main()
