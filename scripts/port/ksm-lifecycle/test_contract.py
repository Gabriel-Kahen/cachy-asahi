#!/usr/bin/env python3
"""Synthetic contract fixtures only: no native builds, Docker, GPG or installation."""
import copy
import gzip
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

import contract as c

RECIPE = Path(__file__).resolve().parents[3] / 'packages/tools/cachy-asahi-ksmctl'
ROOT = RECIPE.parents[2]
LOCK = ROOT / 'scripts/port/refreshed-desktop/proposed-builder-inventory.lock'
LOCK_SHA = '89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f'
EPOCH = 1791748800
IMAGE = 'sha256:' + 'a' * 64
FILENAME = f'{c.NAME}-{c.VERSION}-any.pkg.tar.xz'


def dump(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def make_members(approved, lock):
    result = []
    dirs = sorted({str(p) for name in c.PAYLOAD for p in PurePosixPath(name).parents if str(p) != '.'})
    payload = {name: (RECIPE / source).read_bytes() for name, (source, _) in c.PAYLOAD.items()}
    pkg = {'pkgname': [c.NAME], 'pkgbase': [c.NAME], 'xdata': ['pkgtype=pkg'], 'pkgver': [c.VERSION],
           'pkgdesc': ['Read-only KSM status and page-size-aware counter reporting'],
           'url': ['https://github.com/Gabriel-Kahen/cachy-asahi'], 'builddate': [str(EPOCH)],
           'packager': ['Synthetic fixture'], 'size': [str(sum(map(len, payload.values())))],
           'arch': ['any'], 'license': ['GPL-2.0-or-later'], 'depend': ['python>=3.11']}
    inputs = json.loads((ROOT / 'scripts/ci/inputs.lock.json').read_bytes())
    versions = dict(line.split(' ') for line in lock.decode().splitlines())
    architectures = {item['name'][0]: item['arch'][0] for item in inputs['rootfs_packages']
                     if versions.get(item['name'][0]) == item['version'][0]}
    architectures.update({item['name']: item['arch'] for item in inputs['packages']
                          if versions.get(item['name']) == item['version']})
    assert set(architectures) == set(versions)
    build = {'format': ['2'], 'pkgname': [c.NAME], 'pkgbase': [c.NAME], 'pkgver': [c.VERSION],
             'pkgarch': ['any'], 'pkgbuild_sha256sum': [approved['PKGBUILD']],
             'packager': ['Synthetic fixture'], 'builddate': [str(EPOCH)],
             'builddir': ['/tmp/work'], 'startdir': ['/tmp/work'],
             'buildtool': ['makepkg'], 'buildtoolver': ['7.1.0'],
             'buildenv': ['check', '!sign'], 'options': ['!debug'],
             'installed': [name + '-' + version + '-' + architectures[name] for name, version in versions.items()]}
    def encode(meta):
        return ''.join(f'{key} = {value}\n' for key, values in meta.items() for value in values).encode()
    files = {'.PKGINFO': encode(pkg), '.BUILDINFO': encode(build), **payload}
    for name in dirs + list(files):
        member = tarfile.TarInfo(name)
        member.uid = member.gid = 0
        member.mtime = EPOCH
        member.mode = 0o755 if name in dirs else c.PAYLOAD.get(name, ('', 0o644))[1]
        member.type = tarfile.DIRTYPE if name in dirs else tarfile.REGTYPE
        data = b'' if name in dirs else files[name]
        member.size = len(data)
        result.append((member, data))
    return result


def archive(members, kind='xz', bad_mtree=False, trailing=b''):
    mtree = ['#mtree', '/set type=file uid=0 gid=0 mode=644']
    for member, data in members:
        if member.isdir():
            mtree.append(f'./{member.name} type=dir mode={member.mode:o}')
        else:
            mtree.append(f'./{member.name} type=file mode={member.mode:o} size={len(data)} sha256digest={c.sha(data)}')
    if bad_mtree:
        mtree.append('./etc/shadow type=file size=0 sha256digest=' + 'a' * 64)
    m = tarfile.TarInfo('.MTREE')
    m.uid = m.gid = 0
    m.mode, m.mtime = 0o644, EPOCH
    blob = gzip.compress(('\n'.join(mtree) + '\n').encode(), mtime=0)
    m.size = len(blob)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for member, data in members + [(m, blob)]:
            member = copy.copy(member)
            if member.isfile():
                member.size = len(data)
            tar.addfile(member, io.BytesIO(data) if member.isfile() else None)
    raw = output.getvalue() + trailing
    return lzma.compress(raw) if kind == 'xz' else gzip.compress(raw, mtime=0)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ksm-contract-fixture-')
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.approved = {name: c.sha((RECIPE / name).read_bytes()) for name in sorted(c.INPUTS)}
        self.map = self.root / 'approved.json'
        self.map.write_bytes(dump(self.approved))
        self.assertEqual(c.sha(self.map.read_bytes()), c.APPROVED_MAP_SHA256)
        self.lock = LOCK.read_bytes()
        self.assertEqual(c.sha(self.lock), LOCK_SHA)
        self.assertEqual(dict(line.split(' ') for line in self.lock.decode().splitlines())['pacman'],
                         '7.1.0.r9.g54d9411-2')
        self.members = make_members(self.approved, self.lock)
        self.data = archive(self.members)
        self.roots = [self.root / 'build-one', self.root / 'build-two']
        for number, root in enumerate(self.roots):
            (root / 'artifacts').mkdir(parents=True)
            shutil.copytree(RECIPE, root / 'inputs', ignore=shutil.ignore_patterns('__pycache__'))
            (root / 'expected-packages.lock').write_bytes(self.lock)
            (root / 'build.log').write_bytes(b'Synthetic fixture, NOT RUN native\n')
            (root / 'validation.json').write_bytes(dump({'errors': [], 'artifacts': [{'errors': []}]}))
            files = {'packages.lock': self.lock, 'generated.SRCINFO': (RECIPE / '.SRCINFO').read_bytes(),
                     'environment.txt': b'Linux synthetic aarch64\n4096\n',
                     'makepkg.conf': b'SYNTHETIC=1\n', 'pacman.conf': b'SYNTHETIC=1\n',
                     'config.sha256': b'synthetic config fixture\n', FILENAME: self.data}
            for name, data in files.items():
                (root / 'artifacts' / name).write_bytes(data)
            command = ['docker', 'run', '--rm', '--name', 'cachy-asahi-' + f'{number:016x}', '--pull=never',
                       '--platform', 'linux/arm64', '--user', '1001:1001', '--cap-drop=ALL',
                       '--security-opt=no-new-privileges', '--read-only', '--pids-limit', '512',
                       '--memory', '4g', '--cpus', '4', '--network', 'none',
                       '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g',
                       '--env', 'CACHY_ASAHI_CONTAINER=1', '--env', f'SOURCE_DATE_EPOCH={EPOCH}',
                       '--mount', 'type=bind,src=/fixture/inputs,dst=/inputs,readonly',
                       '--mount', 'type=bind,src=/fixture/output,dst=/out',
                       '--mount', 'type=bind,src=/fixture/entry,dst=/builder-entry.sh,readonly',
                       '--mount', 'type=bind,src=/fixture/lock,dst=/expected-packages.lock,readonly',
                       '--entrypoint', '/bin/bash', IMAGE, '/builder-entry.sh']
            record = {'schema_version': 1, 'status': 'built-package-static-pass', 'hardware_status': 'NOT RUN',
                      'mode': 'native', 'network': 'none', 'image': IMAGE, 'image_id': IMAGE,
                      'builder_host_arch': 'aarch64', 'source_date_epoch': EPOCH, 'exit_code': 0,
                      'clean_environment_id': 'cachy-asahi-' + f'{number:016x}',
                      'entry_script_sha256': c.ENTRY_SHA256, 'expected_packages_sha256': c.sha(self.lock),
                      'recipe_inputs': self.approved,
                      'recipe_metadata': c.metadata((RECIPE / '.SRCINFO').read_bytes()), 'command': command}
            (root / 'provenance.json').write_bytes(dump(record))
            self.refresh(root)

    def record(self, root=None):
        return json.loads(((root or self.roots[0]) / 'provenance.json').read_bytes())

    def write_record(self, record, root=None):
        ((root or self.roots[0]) / 'provenance.json').write_bytes(dump(record))

    def refresh(self, root):
        record = self.record(root)
        names = c.REQUIRED | {'artifacts/' + p.name for p in (root / 'artifacts').iterdir()}
        record['files'] = {name: c.sha((root / name).read_bytes()) for name in names}
        record['artifacts'] = {FILENAME: c.sha((root / 'artifacts' / FILENAME).read_bytes())}
        self.write_record(record, root)

    def pair(self, **kw):
        return c.validate_build_pair(kw.get('first', self.roots[0]), kw.get('second', self.roots[1]),
                                     kw.get('approved', self.map), kw.get('image', IMAGE), kw.get('lock', self.lock))

    def repackage(self, change):
        members = copy.deepcopy(self.members)
        change(members)
        data = archive(members)
        for root in self.roots:
            (root / 'artifacts' / FILENAME).write_bytes(data)
            self.refresh(root)
        return data

    def test_pair_pass_is_curated_fixture_evidence(self):
        result, data = self.pair()
        self.assertEqual(data, self.data)
        self.assertEqual(result['hardware_status'], 'NOT RUN')
        self.assertEqual(result['native_execution'], 'controller-receipt-required')
        self.assertEqual(set(result['payload']), set(c.PAYLOAD))
        self.assertNotIn('command', result)
        self.assertNotIn('packager', json.dumps(result))
        self.assertEqual(result['provenance_sha256'], [c.sha((p / 'provenance.json').read_bytes()) for p in self.roots])
        self.assertEqual(len(set(result['clean_environment_ids'])), 2)

    def test_archive_revalidation_matches_pair(self):
        result, data = self.pair()
        checked = c.validate_archive(data, self.approved, self.lock, result['source_date_epoch'], result['filename'])
        for key in ('sha256', 'payload', 'pkginfo_sha256', 'buildinfo_sha256'):
            self.assertEqual(checked[key], result[key])

    def test_gzip_archive_supported(self):
        data = archive(self.members, kind='gz')
        result = c.validate_archive(data, self.approved, self.lock, EPOCH, FILENAME[:-2] + 'gz')
        self.assertEqual(result['sha256'], c.sha(data))

    def test_zstd_explicitly_refused(self):
        with self.assertRaisesRegex(c.Refused, 'compression'):
            c.validate_archive(self.data, self.approved, self.lock, EPOCH, FILENAME[:-2] + 'zst')

    def test_same_build_directory_refused(self):
        with self.assertRaisesRegex(c.Refused, 'distinct'):
            self.pair(second=self.roots[0])

    def test_same_clean_environment_refused(self):
        record = self.record(self.roots[1])
        record['clean_environment_id'] = self.record()['clean_environment_id']
        record['command'][record['command'].index('--name') + 1] = record['clean_environment_id']
        self.write_record(record, self.roots[1])
        with self.assertRaisesRegex(c.Refused, 'distinct'):
            self.pair()

    def test_bad_provenance_bindings(self):
        original = self.record()
        for key, value in {'mode': 'emulated', 'network': 'bridge', 'image_id': 'sha256:' + 'b' * 64,
                           'status': 'failed', 'builder_host_arch': 'x86_64', 'schema_version': True,
                           'exit_code': 1, 'entry_script_sha256': 'b' * 64,
                           'expected_packages_sha256': 'b' * 64, 'recipe_inputs': {}}.items():
            with self.subTest(key=key):
                record = copy.deepcopy(original)
                record[key] = value
                self.write_record(record)
                with self.assertRaises(c.Refused):
                    self.pair()
        self.write_record(original)

    def test_root_network_writable_and_cap_commands_refused(self):
        original = self.record()
        changes = [('--user', '0:0'), ('--network', 'bridge'), ('--memory', '0')]
        for flag, value in changes:
            with self.subTest(flag=flag):
                record = copy.deepcopy(original)
                record['command'][record['command'].index(flag) + 1] = value
                self.write_record(record)
                with self.assertRaises(c.Refused):
                    self.pair()
        for flag in ('--cap-drop=ALL', '--read-only'):
            record = copy.deepcopy(original)
            record['command'].remove(flag)
            self.write_record(record)
            with self.assertRaises(c.Refused):
                self.pair()

    def test_approved_map_tampering_refused(self):
        self.map.write_bytes(self.map.read_bytes() + b' ')
        with self.assertRaisesRegex(c.Refused, 'map hash'):
            self.pair()

    def test_archive_map_dictionary_tampering_refused(self):
        altered = self.approved | {'NOTICE': 'b' * 64}
        with self.assertRaisesRegex(c.Refused, 'map hash'):
            c.validate_archive(self.data, altered, self.lock, EPOCH, FILENAME)

    def test_lock_requires_full_sorted_unique_341(self):
        rows = self.lock.splitlines(keepends=True)
        for invalid in (b''.join(rows[:-1]), b''.join(reversed(rows)), b''.join([rows[0]] + rows[:-1])):
            with self.subTest(lock=c.sha(invalid)):
                with self.assertRaises(c.Refused):
                    self.pair(lock=invalid)

    def test_evidence_tampering_refused(self):
        (self.roots[0] / 'build.log').write_bytes(b'changed')
        with self.assertRaisesRegex(c.Refused, 'changed'):
            self.pair()

    def test_missing_required_pin_refused(self):
        record = self.record()
        del record['files']['artifacts/packages.lock']
        self.write_record(record)
        with self.assertRaises(c.Refused):
            self.pair()

    def test_extra_archive_refused_even_unrecorded(self):
        (self.roots[0] / 'artifacts/second.pkg.tar.xz').write_bytes(self.data)
        with self.assertRaisesRegex(c.Refused, 'unrecorded'):
            self.pair()

    def test_extra_snapshot_refused(self):
        (self.roots[0] / 'inputs/unapproved').write_bytes(b'x')
        with self.assertRaises(c.Refused):
            self.pair()

    def test_directory_scan_stops_at_first_excess_entry(self):
        class Entry:
            name = 'fixture'
            def is_file(self, *, follow_symlinks):
                self_test.assertFalse(follow_symlinks)
                return True
        class Scan:
            count = 0
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def __iter__(self):
                for _ in range(10000):
                    self.count += 1
                    if self.count > limit + 1:
                        raise AssertionError('scanner walked beyond limit + 1')
                    yield Entry()
        self_test = self
        for limit in (15, 32):
            scanner = Scan()
            with mock.patch.object(c.os, 'scandir', return_value=scanner):
                with self.assertRaisesRegex(c.Refused, 'entry bound'):
                    c._entries(self.roots[0], limit)
            self.assertEqual(scanner.count, limit + 1)

    def test_artifact_directory_entry_count_refused(self):
        for number in range(33):
            (self.roots[0] / 'artifacts' / f'extra-{number}').write_bytes(b'')
        with self.assertRaisesRegex(c.Refused, 'entry bound'):
            self.pair()

    def test_snapshot_changed_refused(self):
        (self.roots[0] / 'inputs/NOTICE').write_bytes(b'changed')
        with self.assertRaisesRegex(c.Refused, 'snapshot'):
            self.pair()

    def test_generated_metadata_changed_even_repinned(self):
        path = self.roots[0] / 'artifacts/generated.SRCINFO'
        path.write_bytes(path.read_bytes().replace(b'GPL-2.0-or-later', b'MIT'))
        self.refresh(self.roots[0])
        with self.assertRaisesRegex(c.Refused, 'recipe metadata'):
            self.pair()

    def test_copy_inventory_changed_even_repinned(self):
        (self.roots[0] / 'artifacts/packages.lock').write_bytes(self.lock.replace(b'3.14.8', b'3.14.9'))
        self.refresh(self.roots[0])
        with self.assertRaisesRegex(c.Refused, 'lock mismatch'):
            self.pair()

    def test_failed_static_validation_refused(self):
        for value in ({'errors': ['failure'], 'artifacts': [{'errors': []}]},
                      {'errors': [], 'artifacts': [False]}):
            (self.roots[0] / 'validation.json').write_bytes(dump(value))
            self.refresh(self.roots[0])
            with self.assertRaises(c.Refused):
                self.pair()

    def test_symlink_fifo_hardlink_evidence_refused(self):
        target = self.roots[0] / 'build.log'
        saved = target.read_bytes()
        external = self.root / 'external'
        external.write_bytes(saved)
        for kind in ('symlink', 'fifo', 'hardlink'):
            with self.subTest(kind=kind):
                target.unlink()
                if kind == 'symlink':
                    target.symlink_to(external)
                elif kind == 'fifo':
                    os.mkfifo(target)
                else:
                    os.link(external, target)
                with self.assertRaises(c.Refused):
                    self.pair()
                target.unlink()
                target.write_bytes(saved)

    def test_symlink_parent_refused(self):
        linked = self.root / 'linked'
        linked.symlink_to(self.roots[0], target_is_directory=True)
        with self.assertRaises(c.Refused):
            self.pair(first=linked)

    def test_duplicate_json_key_refused(self):
        path = self.roots[0] / 'provenance.json'
        path.write_bytes(path.read_bytes().replace(b'{', b'{"schema_version": 1,', 1))
        with self.assertRaisesRegex(c.Refused, 'duplicate'):
            self.pair()

    def test_payload_hash_change_refused_even_repinned(self):
        def change(members):
            for number, (member, data) in enumerate(members):
                if member.name == 'usr/bin/' + c.NAME:
                    members[number] = member, data + b'\n# changed\n'
        self.repackage(change)
        with self.assertRaisesRegex(c.Refused, 'payload'):
            self.pair()

    def test_wrong_modes_owners_types_refused(self):
        for attr, value in [('mode', 0o644), ('uid', 1001), ('gid', 1001),
                            ('type', tarfile.SYMTYPE), ('type', tarfile.CHRTYPE)]:
            with self.subTest(attr=attr, value=value):
                members = copy.deepcopy(self.members)
                member = next(m for m, _ in members if m.name == 'usr/bin/' + c.NAME)
                setattr(member, attr, value)
                with self.assertRaises(c.Refused):
                    c.validate_archive(archive(members), self.approved, self.lock, EPOCH, FILENAME)

    def test_extra_protected_or_hook_path_refused(self):
        for name in ('.INSTALL', 'usr/share/libalpm/hooks/test.hook', 'boot/kernel', 'etc/pacman.conf', '../escape'):
            with self.subTest(name=name):
                members = copy.deepcopy(self.members)
                member = tarfile.TarInfo(name)
                member.uid = member.gid = 0
                member.mode, member.mtime = 0o644, EPOCH
                members.append((member, b''))
                with self.assertRaises(c.Refused):
                    c.validate_archive(archive(members), self.approved, self.lock, EPOCH, FILENAME)

    def test_missing_and_duplicate_payload_refused(self):
        for members in (self.members[:-1], self.members + [self.members[-1]]):
            with self.assertRaises(c.Refused):
                c.validate_archive(archive(members), self.approved, self.lock, EPOCH, FILENAME)

    def test_pkginfo_identity_relations_and_dependency_refused(self):
        for old, new in [(b'license = GPL-2.0-or-later', b'license = MIT'),
                         (b'arch = any', b'arch = aarch64'),
                         (b'depend = python>=3.11', b'depend = python'),
                         (b'pkgver = 0.1.0-1', b'pkgver = 0.1.1-1'),
                         (b'xdata = pkgtype=pkg', b'provides = linux-asahi'),
                         (b'xdata = pkgtype=pkg', b'conflict = linux-asahi'),
                         (b'xdata = pkgtype=pkg', b'replaces = linux-asahi')]:
            with self.subTest(new=new):
                members = [(m, d.replace(old, new) if m.name == '.PKGINFO' else d) for m, d in self.members]
                with self.assertRaises(c.Refused):
                    c.validate_archive(archive(members), self.approved, self.lock, EPOCH, FILENAME)

    def test_buildinfo_input_inventory_and_architecture_refused(self):
        for old, new in [(self.approved['PKGBUILD'].encode(), b'b' * 64),
                         (b'abseil-cpp-20260817.0-2-aarch64', b'abseil-cpp-20260817.0-3-aarch64'),
                         (b'abseil-cpp-20260817.0-2-aarch64', b'abseil-cpp-20260817.0-2-x86_64'),
                         (b'buildtoolver = 7.1.0', b'buildtoolver = 7.0.0'),
                         (b'buildtoolver = 7.1.0', b'buildtoolver = 7.1.0.r9.g54d9411')]:
            with self.subTest(new=new):
                members = [(m, d.replace(old, new) if m.name == '.BUILDINFO' else d) for m, d in self.members]
                with self.assertRaises(c.Refused):
                    c.validate_archive(archive(members), self.approved, self.lock, EPOCH, FILENAME)

    def test_pinned_makepkg_version_differs_from_distribution_package(self):
        build = c.metadata(next(data for member, data in self.members if member.name == '.BUILDINFO'))
        self.assertEqual(build['buildtoolver'], ['7.1.0'])
        self.assertIn('pacman-7.1.0.r9.g54d9411-2-aarch64', build['installed'])
        self.assertEqual(len(build['installed']), 341)
        self.assertIn('pacman-mirrorlist-20260411-2-any', build['installed'])
        self.pair()

    def test_unreviewed_buildtool_package_lock_refused(self):
        changed = self.lock.replace(b'pacman 7.1.0.r9.g54d9411-2\n', b'pacman 7.1.0.r9.g54d9411-3\n')
        with self.assertRaisesRegex(c.Refused, 'buildtool package pin'):
            c.validate_archive(self.data, self.approved, changed, EPOCH, FILENAME)

    def test_mtree_unknown_path_refused(self):
        with self.assertRaisesRegex(c.Refused, 'mtree'):
            c.validate_archive(archive(self.members, bad_mtree=True), self.approved, self.lock, EPOCH, FILENAME)

    def test_nonzero_trailing_tar_refused(self):
        with self.assertRaisesRegex(c.Refused, 'trailing'):
            c.validate_archive(archive(self.members, trailing=b'BAD'), self.approved, self.lock, EPOCH, FILENAME)

    def test_decompression_bomb_refused(self):
        data = lzma.compress(b'\0' * (c.MAX_EXPANDED + 1))
        with self.assertRaisesRegex(c.Refused, 'bound'):
            c.validate_archive(data, self.approved, self.lock, EPOCH, FILENAME)

    def test_archive_byte_limit_and_bad_compression_refused(self):
        for data in (b'x' * (c.MAX_FILE + 1), b'not an archive'):
            with self.assertRaises(c.Refused):
                c.validate_archive(data, self.approved, self.lock, EPOCH, FILENAME)

    def test_xz_large_decoder_dictionary_refused(self):
        data = lzma.compress(b'bounded output', filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 128 * 1024 * 1024}])
        with self.assertRaisesRegex(c.Refused, 'compressed'):
            c.validate_archive(data, self.approved, self.lock, EPOCH, FILENAME)

    def test_command_additional_privilege_or_mount_refused(self):
        original = self.record()
        for addition in (['--privileged'], ['--cap-add=SYS_ADMIN'], ['--env', 'LD_PRELOAD=/injected'],
                         ['--mount', 'type=bind,src=/var/run/docker.sock,dst=/socket']):
            with self.subTest(addition=addition):
                record = copy.deepcopy(original)
                record['command'][-2:-2] = addition
                self.write_record(record)
                with self.assertRaises(c.Refused):
                    self.pair()

    def test_readwrite_source_mount_and_command_name_mismatch_refused(self):
        original = self.record()
        record = copy.deepcopy(original)
        record['command'] = [v.replace('dst=/inputs,readonly', 'dst=/inputs') for v in record['command']]
        self.write_record(record)
        with self.assertRaises(c.Refused):
            self.pair()
        record = copy.deepcopy(original)
        record['command'][record['command'].index('--name') + 1] = 'cachy-asahi-' + 'e' * 16
        self.write_record(record)
        with self.assertRaises(c.Refused):
            self.pair()

    def test_explicit_local_docker_endpoint_accepted(self):
        for root in self.roots:
            record = self.record(root)
            record['command'][1:1] = ['--host', 'unix:///run/docker.sock']
            self.write_record(record, root)
        self.pair()

    def test_tcp_docker_endpoint_refused(self):
        record = self.record()
        record['command'][1:1] = ['--host', 'tcp://host:2375']
        self.write_record(record)
        with self.assertRaises(c.Refused):
            self.pair()

    def test_pair_different_valid_metadata_refused(self):
        members = [(m, d.replace(b'Synthetic fixture', b'Other fixture') if m.name in {'.PKGINFO', '.BUILDINFO'} else d)
                   for m, d in self.members]
        (self.roots[1] / 'artifacts' / FILENAME).write_bytes(archive(members))
        self.refresh(self.roots[1])
        with self.assertRaisesRegex(c.Refused, 'pair'):
            self.pair()


if __name__ == '__main__':
    unittest.main()
