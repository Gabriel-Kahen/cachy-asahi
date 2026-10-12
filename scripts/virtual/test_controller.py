# SPDX-License-Identifier: MIT
"""Mocked host/controller checks. No Docker or ARM binaries are executed."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

import common
import controller as c


class GuardTests(unittest.TestCase):
    def setUp(self):
        c.CANCELLED = False
        c.OWNED_CONTAINERS.clear()

    def test_x86_or_root_refuses_before_docker(self):
        for arch, uid in [('x86_64', 1001), ('aarch64', 0)]:
            with self.subTest(arch=arch, uid=uid), patch('controller.platform.system', return_value='Linux'), \
                    patch('controller.platform.machine', return_value=arch), patch('controller.os.getuid', return_value=uid), \
                    patch('controller.command') as query, self.assertRaises(common.Refused):
                c.native_guard()
            query.assert_not_called()

    def test_native_host_still_refuses_remote_or_wrong_daemon(self):
        with patch('controller.platform.system', return_value='Linux'), patch('controller.platform.machine', return_value='aarch64'), \
                patch('controller.os.getuid', return_value=1001):
            with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://remote:2375'}), patch('controller.command') as query, self.assertRaises(common.Refused):
                c.native_guard()
            query.assert_not_called()
            with patch.dict(os.environ, {}, clear=True), patch('controller.command', side_effect=[
                    json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}]),
                    json.dumps({'Architecture': 'x86_64', 'OSType': 'linux'})]), self.assertRaises(common.Refused):
                c.native_guard()

    def test_container_specs_keep_install_prep_and_vm_boundaries_distinct(self):
        image = 'sha256:' + 'a' * 64
        with tempfile.TemporaryDirectory() as directory:
            roots = [Path(directory) / n for n in ('inputs', 'runner', 'out')]
            for p in roots:
                p.mkdir()
            install = c.container_args(image, 'cachy-virtual-install-a', *roots, root=True, writable=True, temporary=False)
            prep = c.container_args(image, 'cachy-virtual-prep-a', *roots, root=True)
            verify = c.container_args(image, 'cachy-virtual-verify-a', *roots, root=True, temporary=False)
            runtime = c.container_args(image, 'cachy-virtual-run-a', *roots)
            self.assertNotIn('--read-only', install)
            self.assertNotIn('--tmpfs', install)
            self.assertIn('--read-only', prep)
            self.assertEqual({x.split('=', 1)[1] for x in prep if x.startswith('--cap-add=')}, set(c.CAPS))
            self.assertEqual({x.split('=', 1)[1] for x in verify if x.startswith('--cap-add=')}, {'DAC_OVERRIDE'})
            self.assertFalse(any(x.startswith('--cap-add=') for x in runtime))
            for argv in (install, prep, verify, runtime):
                self.assertIn('--network=none', argv)
                self.assertIn('--pull=never', argv)
                self.assertIn('--memory=6g', argv)
                self.assertIn('--memory-swap=6g', argv)
                self.assertNotIn('--privileged', argv)
                self.assertFalse(any(x.startswith('--env') or x.startswith('--device') for x in argv))

    def test_actual_created_spec_rejects_devices_extra_caps_or_unbounded_resources(self):
        image = 'sha256:' + 'a' * 64
        actual = {'Image': image, 'Config': {'User': f'{os.getuid()}:{os.getgid()}'}, 'Mounts': [
            {'Type': 'bind', 'Destination': p, 'RW': rw} for p, rw in [('/inputs', False), ('/runner', False), ('/out', True)]],
            'HostConfig': {'NetworkMode': 'none', 'Privileged': False, 'CapDrop': ['ALL'], 'CapAdd': [], 'Devices': [],
                           'DeviceRequests': [], 'ReadonlyRootfs': True, 'Tmpfs': {'/tmp': 'rw'}, 'Memory': 6 * common.GIB,
                           'MemorySwap': 6 * common.GIB, 'NanoCpus': 4 * 10**9, 'PidsLimit': 256,
                           'SecurityOpt': ['no-new-privileges']}}
        c.validate_container(actual, image, False, False, True)
        for key, value in [('Privileged', True), ('Devices', ['gpu']), ('CapAdd', ['SYS_ADMIN']), ('MemorySwap', -1),
                           ('NetworkMode', 'host'), ('ReadonlyRootfs', False), ('SecurityOpt', ['no-new-privileges=false'])]:
            changed = copy.deepcopy(actual); changed['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(common.Refused):
                c.validate_container(changed, image, False, False, True)

    def test_commit_restores_config_and_has_only_owned_private_tag(self):
        base = {'User': 'alarm', 'WorkingDir': '/tmp', 'Entrypoint': [], 'Cmd': ['/bin/bash']}
        tag = 'cachy-virtual-private-' + 'a' * 32 + ':fixture'
        argv = c.commit_args('cachy-virtual-owned-a', base, tag)
        self.assertEqual(argv[-1], tag)
        self.assertIn('USER alarm', argv)
        self.assertIn('CMD ["/bin/bash"]', argv)
        self.assertIn('ENTRYPOINT [""]', argv)
        self.assertFalse(any(x.startswith('ENV ') for x in argv))
        with self.assertRaises(common.Refused):
            c.commit_args('cachy-virtual-owned-a', base, 'docker.io/stable:latest')
        self.assertEqual(c.config({'User': 'alarm'}), c.config({'User': 'alarm', 'Env': [], 'Cmd': [], 'WorkingDir': '/'}))

    def test_exact_sentinel_and_null_labels_acceptance_preserves_runtime_metadata(self):
        accepted = {'User': 'alarm', 'Env': ['PATH=/usr/bin', 'HOME=/home/alarm'],
                    'Entrypoint': [], 'Cmd': [], 'Labels': {}}
        self.assertEqual(c.config(accepted), c.config(accepted | {'Entrypoint': [''], 'Labels': None}))
        for changed in ({'Entrypoint': ['', '/bin/sh']}, {'Entrypoint': ['/usr/bin/env']},
                        {'Cmd': ['/usr/bin/python3', '/runner/controller.py']}, {'Env': accepted['Env'] + ['HOME=/tmp']},
                        {'Env': ['HOME=/home/alarm', 'PATH=/usr/bin']}, {'Labels': {'runtime': 'tooling'}}):
            with self.subTest(changed=changed):
                self.assertNotEqual(c.config(accepted), c.config(accepted | changed))
        command = accepted | {'Entrypoint': ['/bin/sh', '-c'], 'Cmd': ['printf test']}
        self.assertEqual(c.config(command)['Entrypoint'], command['Entrypoint'])
        self.assertEqual(c.config(command)['Cmd'], command['Cmd'])

    def test_actual_commit_changes_block_pinned_moby_empty_array_inheritance(self):
        # Transcribe only the pinned daemon/commit.go command merge branch;
        # exercise the actual CLI arguments rather than a fabricated payload.
        runtime = {'Entrypoint': ['/usr/bin/env'], 'Cmd': ['HOME=/tmp', '/usr/bin/python3', '/runner/controller.py']}
        for entry in (None, [], [''], ['/bin/sh', '-c']):
            for cmd in (None, [], ['printf test']):
                base = {'User': 'alarm', 'Env': ['PATH=/usr/bin'], 'Entrypoint': entry, 'Cmd': cmd}
                args = c.commit_args('cachy-virtual-tooling-' + 'a' * 32, base,
                                     'cachy-virtual-private-' + 'a' * 32 + ':fixture')
                changes = [args[n + 1] for n, value in enumerate(args) if value == '--change']
                payload = {key: json.loads(next(x.split(' ', 1)[1] for x in changes if x.startswith(key.upper() + ' ')))
                           for key in ('Entrypoint', 'Cmd')}
                if not payload['Entrypoint']:
                    if not payload['Cmd']:
                        payload['Cmd'] = runtime['Cmd']
                    if payload['Entrypoint'] is None:
                        payload['Entrypoint'] = runtime['Entrypoint']
                with self.subTest(entry=entry, cmd=cmd):
                    self.assertEqual(c.config(payload)['Entrypoint'], entry if entry not in (None, [], ['']) else [])
                    self.assertEqual(payload['Cmd'], cmd or [])
                    self.assertEqual(base['Env'], ['PATH=/usr/bin'])
                    self.assertFalse(any(x.startswith('ENV ') for x in changes))

    def test_cleanup_does_not_accept_merely_successful_remove(self):
        name = 'cachy-virtual-test-' + 'a' * 32
        c.OWNED_CONTAINERS.add(name)
        success = {'error': None, 'returncode': 0, 'stdout': '', 'stderr': ''}
        present = dict(success, stdout='container-id\n')
        with patch('controller.bounded', side_effect=[success, present]):
            result = c.remove_container(name)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn(name, c.OWNED_CONTAINERS)
        with patch('controller.bounded', side_effect=[dict(success, returncode=1), success]):
            result = c.remove_container(name)
        self.assertEqual(result['status'], 'PASS')
        self.assertNotIn(name, c.OWNED_CONTAINERS)
        with patch('controller.bounded') as query, self.assertRaises(common.Refused):
            c.remove_container('cachy-virtual-not-claimed')
        query.assert_not_called()

    def test_preexisting_container_name_is_never_claimed_or_removed(self):
        with patch('controller.command', return_value='preexisting'), patch('controller.remove_container') as remove, self.assertRaises(common.Refused):
            c.run_container(['docker', 'create', '--name', 'cachy-virtual-collision'], Path('/tmp/unopened.log'),
                            'sha256:' + 'a' * 64, False, False, True, 30, [])
        remove.assert_not_called()
        self.assertFalse(c.OWNED_CONTAINERS)

    def test_signal_during_cleanup_cannot_be_forgotten(self):
        with c.cleanup_signals():
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        self.assertTrue(c.CANCELLED)

    def test_final_receipt_cannot_forget_late_cancellation(self):
        for stage in ('projection', 'workspace_cleanup', 'final_save'):
            report = {'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW'}
            def write(path, value):
                common.save(path, value)
                if stage == 'final_save':
                    c.CANCELLED = True
            c.CANCELLED = stage != 'final_save'
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory, patch('controller.save', side_effect=write):
                path = Path(directory) / 'result.json'
                c.save_final_report(path, report)
                self.assertEqual(common.json_load(path)['status'], 'FAIL')
                self.assertEqual(report['status'], 'FAIL')
                self.assertTrue(c.CANCELLED)

    def test_actual_main_late_projection_cancellation_returns_failure(self):
        # Synthetic accepted-stage data only; every Docker/native action is mocked.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); inputs = root / 'accepted'; inputs.mkdir()
            cache = inputs / 'cache'; cache.mkdir()
            files, paths, rows = {}, {}, []
            for alias in ('base_lock', 'lifecycle_receipt', 'tooling_lock', 'tooling_audit'):
                path = inputs / (alias + '.json'); path.write_text('{}')
                paths[alias] = path; files[alias] = {'path': path.name, 'sha256': common.digest(path)}
            for name in sorted(common.OVERLAYS):
                path = inputs / 'baseline' / (name + '.pkg.tar.xz'); path.parent.mkdir(exist_ok=True)
                path.write_bytes(b'synthetic archive never executed')
                rows.append({'name': name, 'version': '1-1', 'archive': path.relative_to(inputs).as_posix(),
                             'sha256': common.digest(path), 'payload_sha256': {'usr/share/' + name: '0' * 64}})
            base, derived = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64
            cfg = c.config({'User': 'alarm'})
            contract = {'installed_image_id': base, 'source_commit': 'c' * 40,
                        'controller_sha256': common.digest(Path(c.__file__)), 'files': files, 'baseline': rows}
            path = inputs / 'contract.json'; common.save(path, contract); output = root / 'output'
            loaded = {'committed_config': {'committed_config': cfg}, 'tooling_lock': {'keyring_files': [], 'packages': []}}
            def command(argv, **_):
                if argv[1:3] == ['image', 'inspect']:
                    return json.dumps([{'Id': argv[-1], 'Architecture': 'arm64', 'Os': 'linux',
                                        'Config': cfg | {'Entrypoint': [''], 'Labels': None}, 'Size': 1}])
                if argv[1:3] == ['image', 'ls']:
                    return ''
                if argv[1] == 'commit':
                    return derived
                raise AssertionError(argv)
            def stage(argv, log, image, *args, **kwargs):
                mount = next(a for a in argv if a.startswith('type=bind,src=') and ',dst=/out' in a)
                target = Path(mount.split('src=', 1)[1].split(',dst=')[0])
                childpath = target.parent.parent / 'inputs/tooling-contract.json'
                child = common.json_load(childpath)
                if '--inside-tooling' in argv or '--inside-verify' in argv:
                    common.save(target / 'tooling.json', {'status': 'READY', 'package_count': 366,
                        'contract_sha256': common.digest(childpath), 'image_id': image, 'nonce': child['nonce'],
                        'packages': {'synthetic': '1-1'}, 'package_inventory_sha256': '0' * 64, 'private_cleanup': 'PASS'})
                elif any(a.endswith('/prepare.py') for a in argv):
                    (target / 'prepared').mkdir(); common.save(target / 'prepared/prepare.json', {'status': 'PREPARED'})
                else:
                    (target / 'proof').mkdir(); common.save(target / 'proof/result.json', {'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW'})
            def cancel(*_):
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            with patch('controller.native_guard', return_value={}), patch('controller.validate_input', return_value=(loaded, paths, cache)), \
                    patch('controller.command', side_effect=command), patch('controller.run_container', side_effect=stage), \
                    patch('controller.remove_container', return_value={'status': 'PASS'}), patch('controller.remove_private_tag', return_value={'status': 'PASS'}), \
                    patch('controller.free_bytes', return_value=100 * common.GIB), patch('controller.allocated', return_value=0), \
                    patch.object(c, 'CORE', {name: common.digest(Path(c.__file__).with_name(name)) for name in c.CORE}), \
                    patch.object(c, 'AUDITOR_PIN', common.digest(Path(c.__file__).with_name('audit_tooling.py'))), \
                    patch('controller.project', side_effect=cancel), patch.object(sys, 'argv', ['controller.py', '--contract', str(path),
                    '--contract-sha256', common.digest(path), '--output', str(output)]):
                self.assertFalse(c.main())
            self.assertTrue(c.CANCELLED)
            self.assertEqual(common.json_load(output / 'result.json')['status'], 'FAIL')
            self.assertFalse(any(root.glob('cachy-virtual-private-*')))

    def test_uncertain_commit_or_remaining_image_is_cleanup_failure(self):
        tag = 'cachy-virtual-private-' + 'a' * 32 + ':fixture'
        image = 'sha256:' + 'b' * 64
        ok = {'error': None, 'returncode': 0, 'stdout': '', 'stderr': ''}
        with patch('controller.bounded', side_effect=[ok, ok, dict(ok, stdout=image)]):
            self.assertEqual(c.remove_private_tag(tag, image)['status'], 'FAIL')
        with patch('controller.bounded', side_effect=[ok, ok]):
            self.assertEqual(c.remove_private_tag(tag, uncertain=True)['status'], 'FAIL')


class InputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        source = Path(__file__).parent
        native = common.json_load(source.parent / 'ci/inputs.lock.json')
        base = {r['name'][0]: r['version'][0] for r in native['rootfs_packages']}
        base.update({r['name']: r['version'] for r in native['packages']})
        rows = []
        (cls.root / 'baseline').mkdir()
        for name in sorted(common.OVERLAYS):
            p = cls.root / 'baseline' / (name + '.pkg.tar.xz')
            p.write_bytes(b'fake archive; data fixture only, never executed')
            rows.append({'name': name, 'version': '0.1.0-1', 'archive': p.relative_to(cls.root).as_posix(),
                         'sha256': common.digest(p), 'payload_sha256': {'usr/share/' + name + '/fixture': '0' * 64}})
        versions = {r['name']: r['version'] for r in rows}
        payload = {r['name']: r['payload_sha256'] for r in rows}
        def lock(name, data):
            p = cls.root / name; p.write_text(''.join(k + ' ' + v + '\n' for k, v in sorted(data.items()))); return p
        base_file = lock('base.lock', base)
        installed_file = lock('installed.lock', base | versions)
        base_image, installed_image = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64
        baseline_commit = '1' * 40
        cfg = c.config({'User': 'alarm'})
        checks = ['successful-lifecycle-handoff', 'lifecycle-receipt-binding', 'exact-base-plus-originals-inventory',
                  'complete-pacman-owned-payload', 'original-payload-hash', 'private-keyring-removed',
                  'only-empty-alarm-home', 'system-gnupg-state-removed']
        data = {
            'base_inputs_lock': native,
            'lifecycle_receipt': {'status': 'PASS', 'baseline_handoff_ready': True, 'source_commit': baseline_commit,
                                  'image_id': base_image, 'handoff_package_versions': versions, 'handoff_payload_sha256': payload},
            'commit_receipt': {'status': 'READY', 'purpose': 'sanitized-baseline-image-handoff', 'source_commit': baseline_commit,
                               'image_id': base_image, 'package_versions': versions, 'payload_sha256': payload, 'installed_package_count': 345,
                               'installed_packages_sha256': common.digest(installed_file), 'base_packages_sha256': common.digest(base_file),
                               'private_cleanup': 'PASS; no private contents or hashes recorded', 'checks': [{'check': x, 'status': 'PASS'} for x in checks]},
            'committed_config': {'status': 'PASS', 'image_id': installed_image, 'accepted_base_config': cfg,
                                 'committed_config': cfg, 'test_identity_in_image_env': False},
            'committed_verification': {'status': 'PASS', 'image_id': installed_image, 'source_commit': baseline_commit,
                                       'baseline': rows, 'installed_packages_sha256': common.digest(installed_file)}}
        files = {'base_lock': base_file, 'installed_lock': installed_file}
        for key, value in data.items():
            p = cls.root / (key + '.json'); common.save(p, value); files[key] = p
        # The base input JSON must retain its exact accepted original serialization.
        shutil.copyfile(source.parent / 'ci/inputs.lock.json', files['base_inputs_lock'])
        p = cls.root / 'installed-image.json'
        common.save(p, {'image_id': installed_image, 'base_image': base_image, 'source_commit': baseline_commit,
                        'lock_sha256': common.digest(installed_file), 'commit_receipt_sha256': common.digest(files['commit_receipt'])})
        files['installed_image_receipt'] = p
        for alias, name in [('tooling_lock', 'tooling.lock.json'), ('tooling_audit', 'tooling-audit.json')]:
            files[alias] = cls.root / name; shutil.copyfile(source / name, files[alias])
        cache = cls.root / 'tooling-cache'; cache.mkdir()
        tooling = common.json_load(source / 'tooling.lock.json')
        # Candidate closure is synthetic here; cryptographic data audit is separate.
        for name in ('qemu-hw-display-virtio-gpu', 'qemu-hw-display-virtio-gpu-pci'):
            if any(row['name'] == name for row in tooling['packages']):
                continue
            row = copy.deepcopy(next(r for r in tooling['packages'] if r['name'] == 'qemu-common'))
            row.update(name=name, filename=name + '-11.1.2-1-aarch64.pkg.tar.xz')
            tooling['packages'].append(row)
        tooling['packages'].sort(key=lambda row: row['name']); tooling['expected_package_count'] = 362
        common.save(files['tooling_lock'], tooling)
        audit = common.json_load(files['tooling_audit'])
        audit['tooling_lock_sha256'] = common.digest(files['tooling_lock'])
        for row in tooling['packages']:
            audit['packages'].setdefault(row['name'], {'archive_sha256': row['sha256'], 'hooks': {}})
        common.save(files['tooling_audit'], audit)
        cls.candidate_core = {name: common.digest(source / name) for name in c.CORE}
        cls.candidate_auditor = common.digest(source / 'audit_tooling.py')
        cls.candidate_lock = common.digest(files['tooling_lock'])
        cls.candidate_audit = common.digest(files['tooling_audit'])
        cls.cache_inputs = {r['filename']: r for r in tooling['keyring_files'] +
                            [i for row in tooling['packages'] for i in (row, c.audit_tooling.signature(row))]}
        cls.contract = {'schema_version': 1, 'execution': 'native-aarch64-controller-qemu-tcg-guest', 'source_commit': '2' * 40,
                        'baseline_source_commit': baseline_commit, 'installed_image_id': installed_image, 'baseline': rows,
                        'controller_sha256': common.digest(Path(c.__file__)), 'core_sha256': cls.candidate_core, 'audit_tooling_sha256': cls.candidate_auditor,
                        'cache_dir': 'tooling-cache', 'files': {key: {'path': p.relative_to(cls.root).as_posix(), 'sha256': common.digest(p)} for key, p in files.items()}}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def validate(self, contract):
        original_pinned = common.pinned
        seen = set()
        def inputs(root, name, sha):
            if Path(root).name == 'tooling-cache':
                self.assertIn(name, self.cache_inputs)
                row = self.cache_inputs[name]
                self.assertEqual(sha, row['sha256'])
                seen.add(name)
                value = Mock()
                value.stat.return_value.st_size = row['size']
                return value
            return original_pinned(root, name, sha)
        with patch('controller.pinned', side_effect=inputs), patch.object(c, 'CORE', self.candidate_core), \
                patch.object(c, 'AUDITOR_PIN', self.candidate_auditor), patch.object(c, 'LOCK_PIN', self.candidate_lock), \
                patch.object(c, 'AUDIT_PIN', self.candidate_audit):
            result = c.validate_input(contract, self.root)
        self.assertEqual(seen, set(self.cache_inputs))
        return result

    def test_full_distinct_source_and_baseline_commit_contract_is_accepted_as_data(self):
        loaded, _, _ = self.validate(self.contract)
        self.assertEqual(len(loaded['base_lock']), 341)
        self.assertEqual(len(loaded['installed_lock']), 345)
        self.assertNotEqual(self.contract['source_commit'], self.contract['baseline_source_commit'])

    def test_wrong_source_missing_original_or_missing_lock_is_rejected(self):
        for changes in [{'controller_sha256': '0' * 64}, {'baseline_source_commit': '3' * 40},
                        {'baseline': self.contract['baseline'][:-1]}, {'files': {}}]:
            changed = self.contract | changes
            with self.subTest(changes=changes), self.assertRaises(common.Refused):
                self.validate(changed)

    def test_tampered_original_or_escaping_cache_is_rejected_without_execution(self):
        path = self.root / self.contract['baseline'][0]['archive']
        original = path.read_bytes()
        try:
            path.write_bytes(original + b'tamper')
            with self.assertRaises(common.Refused):
                self.validate(self.contract)
        finally:
            path.write_bytes(original)
        changed = copy.deepcopy(self.contract)
        changed['cache_dir'] = '../outside'
        with self.assertRaises(common.Refused):
            self.validate(changed)


class ProjectionTests(unittest.TestCase):
    def test_capability_hash_binds_captured_canonical_list_not_raw_json_layout(self):
        import run
        with tempfile.TemporaryDirectory(prefix='virtual-capability-canonical-') as directory:
            root = Path(directory); raw = root / 'raw'; raw.mkdir(); out = root / 'out'; out.mkdir()
            row = {'check': 'version', 'status': 'STARTING', 'returncode': None, 'reason': None,
                   'stdout_sha256': None, 'stdout_bytes': None, 'stderr_sha256': None, 'stderr_bytes': None}
            rows = [row]; canonical = hashlib.sha256((json.dumps(rows, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
            capability = raw / 'capabilities.json'
            capability.write_text(json.dumps(rows, separators=(',', ':')) + '  \n')
            self.assertNotEqual(common.digest(capability), canonical)
            common.save(raw / 'result.json', {'capabilities': rows, 'events': []})
            with patch.object(c, 'CORE', c.CORE | {'run.py': common.digest(Path(run.__file__))}):
                report = {}; c.project(raw, out, report)
                self.assertEqual(report['qemu_capabilities_sha256'], canonical)
                self.assertEqual(report['qemu_capabilities'], rows)
                capability.write_text(json.dumps([dict(reversed(list(row.items())))], indent=1))
                other = {}; c.project(raw, out, other)
                self.assertEqual(other['qemu_capabilities_sha256'], canonical)
                common.save(raw / 'result.json', {'capabilities': [], 'events': []})
                with self.assertRaises(common.Refused): c.project(raw, out, {})

    def test_capability_failure_survives_projection_without_raw_outputs(self):
        import run
        with tempfile.TemporaryDirectory(prefix='virtual-capability-projection-') as directory:
            root = Path(directory); raw = root / 'raw'; raw.mkdir(); out = root / 'out'; out.mkdir()
            report = {}
            with patch('run.bounded', return_value={'returncode': 0, 'error': None,
                                                    'stdout': 'password=PRIVATE_HELP', 'stderr': ''}), \
                    self.assertRaises(common.Refused):
                run.check_capabilities(report, raw)
            common.save(raw / 'result.json', {'status': 'FAILED', 'events': [], 'frames': {}, **report})
            core = c.CORE | {'run.py': common.digest(Path(run.__file__))}
            with patch.object(c, 'CORE', core):
                public = {}; c.project(raw, out, public)
                self.assertEqual(public['qemu_capabilities'][0]['reason'], 'capability-missing')
                self.assertEqual(public['qemu_capabilities_sha256'], common.digest(raw / 'capabilities.json'))
                self.assertNotIn('PRIVATE_HELP', json.dumps(public))
                rows = common.json_load(raw / 'capabilities.json')
                for changed in [dict(rows[0], stdout='PRIVATE_HELP'), dict(rows[0], returncode=True),
                                dict(rows[0], check='PRIVATE_PATH'), dict(rows[0], reason='PRIVATE_PATH')]:
                    common.save(raw / 'capabilities.json', [changed])
                    with self.assertRaises(common.Refused): c.project(raw, out, {})
            common.save(raw / 'capabilities.json', rows)
            with patch.object(c, 'CORE', core | {'run.py': '0' * 64}), self.assertRaises(common.Refused):
                c.project(raw, out, {})

    def test_started_check_is_projected_when_final_guest_receipt_is_missing(self):
        import run
        with tempfile.TemporaryDirectory(prefix='virtual-capability-started-') as directory:
            root = Path(directory); raw = root / 'raw'; raw.mkdir(); out = root / 'out'; out.mkdir()
            row = {'check': 'version', 'status': 'STARTING', 'returncode': None, 'reason': None,
                   'stdout_sha256': None, 'stdout_bytes': None, 'stderr_sha256': None, 'stderr_bytes': None}
            common.save(raw / 'capabilities.json', [row])
            with patch.object(c, 'CORE', c.CORE | {'run.py': common.digest(Path(run.__file__))}):
                report = {}; c.project(raw, out, report)
                self.assertEqual(report['qemu_capabilities'], [row])
                common.save(raw / 'result.json', {'capabilities': []})
                with self.assertRaises(common.Refused): c.project(raw, out, {})

    def test_only_receipt_bound_frames_project_and_visual_acceptance_stays_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); raw = root / 'raw'; raw.mkdir(); out = root / 'out'; out.mkdir()
            frame = raw / 'minimal.ppm'; frame.write_bytes(b'P6\n1 1\n255\n\x00\x00\x00')
            common.save(raw / 'result.json', {'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW', 'frame_proof': 'REVIEW REQUIRED',
                                             'events': [{'event': 'phase_pass', 'stage': 'minimal'}],
                                             'frames': {'minimal': {'filename': frame.name, 'sha256': common.digest(frame), 'visual_review': 'NOT RUN'}}})
            (raw / 'private-keys-v1.d').mkdir(); (raw / 'guest.raw').write_bytes(b'private')
            report = {}; c.project(raw, out, report)
            self.assertEqual(report['guest']['frame_proof'], 'REVIEW REQUIRED')
            self.assertEqual(set(p.name for p in out.iterdir()), {'guest-events.json', 'minimal.ppm'})
            frame.write_bytes(b'tamper')
            with self.assertRaises(common.Refused):
                c.project(raw, out, {})


if __name__ == '__main__':
    unittest.main()
