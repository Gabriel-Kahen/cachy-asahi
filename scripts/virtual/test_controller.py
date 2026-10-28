# SPDX-License-Identifier: MIT
"""Mocked host/controller checks. No Docker or ARM binaries are executed."""
import base64
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


def decode_capture():
    """Finite report model; no decoder or guest actor."""
    import run
    from image_decode_report import ASSET_SHA256, CONTEXT_HASHES
    from test_image_decode_probe import fixture, encoded
    row = fixture(); row['asset']['sha256'] = ASSET_SHA256
    raw = encoded(row)
    nonce = 'd' * 32
    context = {key: 'a' * 64 for key in CONTEXT_HASHES}
    context.update(asset_sha256=ASSET_SHA256, run_id='123', run_attempt='1')
    event = {'event': 'image_decode_probe', 'nonce': nonce, 'stage': 'minimal',
             'elapsed_ms': 12, 'returncode': 0, 'error': None,
             'report_sha256': hashlib.sha256(raw).hexdigest(),
             'report_base64': base64.b64encode(raw).decode('ascii')}
    events = [{'event': 'gbm_pass', 'nonce': nonce},
              {'event': 'ipc_probe', 'stage': 'minimal', 'attempt': 1, 'elapsed_ms': 1,
               'returncode': 0, 'error': None, 'stdout': '[]', 'stderr': ''},
              {'event': 'command', 'argv': ['/usr/bin/hyprctl', '-j', 'configerrors'],
               'returncode': 0, 'error': None, 'stdout': '[]', 'stderr': ''},
              {'event': 'command', 'argv': ['/usr/bin/hyprctl', '-j', 'monitors'],
               'returncode': 0, 'error': None, 'stdout': '[{"width":1024,"height":768}]', 'stderr': ''}, event]
    return nonce, context, events, run.image_decode_observation(events, context, nonce)


def decode_core():
    return c.CORE | {name: common.digest(Path(c.__file__).with_name(name))
                     for name in ('run.py', 'image_decode_report.py')}


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
                        'run_id': '123', 'run_attempt': '1',
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
                    (target / 'prepared').mkdir(); common.save(target / 'prepared/prepare.json',
                        {'status': 'PREPARED', 'package_inventory': {'synthetic': '1-1'}})
                else:
                    (target / 'proof').mkdir(); common.save(target / 'proof/result.json', {'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW'})
            def cancel(*_, **__):
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            with patch('controller.native_guard', return_value={}), patch('controller.validate_input', return_value=(loaded, paths, cache)), \
                    patch('controller.command', side_effect=command), patch('controller.run_container', side_effect=stage), \
                    patch('controller.remove_container', return_value={'status': 'PASS'}), patch('controller.remove_private_tag', return_value={'status': 'PASS'}), \
                    patch('controller.free_bytes', return_value=100 * common.GIB), patch('controller.allocated', return_value=0), \
                    patch.object(c, 'CORE', {name: common.digest(Path(c.__file__).with_name(name)) for name in c.CORE}), \
                    patch.object(c, 'AUDITOR_PIN', common.digest(Path(c.__file__).with_name('audit_tooling.py'))), \
                    patch('controller.project', side_effect=cancel), patch.object(sys, 'argv', ['controller.py', '--contract', str(path),
                    '--contract-sha256', common.digest(path), '--output', str(output)]), \
                    patch('controller.prepared_decode_authority', return_value=({}, {})):
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
        cls.candidate_core = {name: common.digest(source / name) for name in
                              set(c.CORE) | {'image_decode_report.py', 'image_decode_probe.c'}}
        cls.candidate_auditor = common.digest(source / 'audit_tooling.py')
        cls.candidate_lock = common.digest(files['tooling_lock'])
        cls.candidate_audit = common.digest(files['tooling_audit'])
        cls.cache_inputs = {r['filename']: r for r in tooling['keyring_files'] +
                            [i for row in tooling['packages'] for i in (row, c.audit_tooling.signature(row))]}
        cls.contract = {'schema_version': 1, 'execution': 'native-aarch64-controller-qemu-tcg-guest', 'source_commit': '2' * 40,
                        'run_id': '123', 'run_attempt': '1',
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
    def test_ipc_retry_and_ready_diagnostics_and_compositor_logs_survive_projection(self):
        with tempfile.TemporaryDirectory(prefix='virtual-ipc-projection-') as directory:
            root = Path(directory); raw = root / 'raw'; raw.mkdir(); out = root / 'out'; out.mkdir()
            events = []
            for stage in ('minimal', 'overlay'):
                failed = {'event': 'ipc_probe', 'stage': stage, 'attempt': 1, 'elapsed_ms': 30000,
                          'returncode': 6, 'error': None,
                          'stdout': "Hyprland IPC didn't respond in time\n\nCouldn't read (6)\n", 'stderr': ''}
                ready = dict(failed, attempt=2, elapsed_ms=30500, returncode=0, stdout='[]')
                log = (stage + ' compositor event loop ready\n').encode()
                events += [failed, ready, {'event': 'session_log', 'stage': stage,
                           'filename': stage + '-compositor.log', 'sha256': hashlib.sha256(log).hexdigest(),
                           'base64': base64.b64encode(log).decode()}, {'event': 'phase_pass', 'stage': stage}]
            binding = {'contract_sha256': 'a' * 64, 'prepare_receipt_sha256': 'b' * 64,
                       'image_id': 'sha256:' + 'c' * 64, 'nonce': 'd' * 32}
            _, context, prefix, observation = decode_capture()
            events = prefix + events
            common.save(raw / 'result.json', {'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW', **binding,
                        'image_decode_observation': observation,
                        'events': [*events, {'event': 'unknown_private_event', 'stdout': 'PRIVATE KEY'}],
                        'private_path': '/private/keyring', 'frames': {}})
            with patch.object(c, 'CORE', decode_core()):
                report = {}; c.project(raw, out, report, image_decode_context=context)
            retained = common.json_load(out / 'guest-events.json')
            self.assertEqual(retained, events)
            self.assertEqual([e['returncode'] for e in retained[len(prefix):] if e['event'] == 'ipc_probe'], [6, 0, 6, 0])
            for event in retained:
                if event['event'] == 'session_log':
                    self.assertEqual(hashlib.sha256(base64.b64decode(event['base64'])).hexdigest(), event['sha256'])
            self.assertEqual({key: report['guest'][key] for key in binding}, binding)
            self.assertEqual(report['guest_events_sha256'], common.digest(out / 'guest-events.json'))
            self.assertEqual(set(p.name for p in out.iterdir()), {'guest-events.json'})
            self.assertNotIn('private_path', report['guest'])
            self.assertNotIn('PRIVATE KEY', (out / 'guest-events.json').read_text())

    def test_ipc_diagnostics_keep_existing_public_size_and_private_key_refusals(self):
        with tempfile.TemporaryDirectory(prefix='virtual-ipc-projection-bound-') as directory:
            root = Path(directory); raw = root / 'raw'; raw.mkdir(); out = root / 'out'; out.mkdir()
            event = {'event': 'ipc_probe', 'stage': 'minimal', 'attempt': 1, 'elapsed_ms': 1,
                     'returncode': 6, 'error': None, 'stdout': '', 'stderr': ''}
            for content in ('PRIVATE KEY', 'x' * (16 * 1024 ** 2)):
                with self.subTest(bytes=len(content)):
                    common.save(raw / 'result.json', {'events': [dict(event, stdout=content)]})
                    with self.assertRaisesRegex(common.Refused, 'guest public evidence rejected'):
                        c.project(raw, out, {})
                    self.assertFalse((out / 'guest-events.json').exists())

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
            nonce, context, events, observation = decode_capture()
            common.save(raw / 'result.json', {'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW', 'frame_proof': 'REVIEW REQUIRED',
                                             'nonce': nonce, 'image_decode_observation': observation,
                                             'events': [*events, {'event': 'phase_pass', 'stage': 'minimal'}],
                                             'frames': {'minimal': {'filename': frame.name, 'sha256': common.digest(frame), 'visual_review': 'NOT RUN'}}})
            (raw / 'private-keys-v1.d').mkdir(); (raw / 'guest.raw').write_bytes(b'private')
            with patch.object(c, 'CORE', decode_core()):
                report = {}; c.project(raw, out, report, image_decode_context=context)
            self.assertEqual(report['guest']['frame_proof'], 'REVIEW REQUIRED')
            self.assertEqual(set(p.name for p in out.iterdir()), {'guest-events.json', 'minimal.ppm'})
            frame.write_bytes(b'tamper')
            with patch.object(c, 'CORE', decode_core()), self.assertRaises(common.Refused):
                c.project(raw, out, {}, image_decode_context=context)


class ImageDecodeOuterTests(unittest.TestCase):
    def test_duplicate_uart_keys_refused_before_reserialization(self):
        import run
        self.assertEqual(run.parse_guest_event(b'{"event":"command","argv":[]}'), {'event': 'command', 'argv': []})
        for raw in (b'{"event":"image_decode_probe","event":"guest_pass"}',
                    b'{"event":"command","nested":{"nonce":"a","nonce":"b"}}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): run.parse_guest_event(raw)

    def test_expected_context_comes_from_selected_prepare_not_result(self):
        import run
        from test_image_decode_probe import build_fixture
        build, proof, packages = build_fixture()
        prepared = {'status': 'PREPARED', 'image_id': proof['image_id'], 'nonce': proof['nonce'],
                    'contract_sha256': 'e' * 64, 'package_inventory': packages,
                    'guest_image_sha256': 'f' * 64, 'image_decode_build': build}
        context = run.image_decode_context(proof, prepared, 'e' * 64)
        self.assertEqual(context['image_sha256'], 'f' * 64)
        self.assertEqual(context['helper_sha256'], build['helper']['sha256'])
        self.assertNotIn('image_sha256', build['guest_contract'])
        self.assertEqual(context['run_id'], proof['run_id'])
        mutations = [lambda p: p.update(status='FAILED'), lambda p: p.update(image_id='sha256:' + '0' * 64),
                     lambda p: p.update(nonce='0' * 32), lambda p: p.update(contract_sha256='0' * 64),
                     lambda p: p['package_inventory'].update(extra='1'),
                     lambda p: p['image_decode_build']['helper'].update(sha256='0' * 64),
                     lambda p: p['image_decode_build']['guest_contract'].update(source_sha256='0' * 64),
                     lambda p: p['image_decode_build'].update(run_attempt='99')]
        for change in mutations:
            changed = copy.deepcopy(prepared); change(changed)
            with self.subTest(change=change), self.assertRaises(ValueError):
                run.image_decode_context(proof, changed, 'e' * 64)

    def test_probe_requires_original_readiness_order_and_one_attempt(self):
        import run
        nonce, context, events, _ = decode_capture()
        cases = [[], events + [events[-1]], events[1:], events[:1] + events[2:],
                 events[:2] + [{'event': 'command', 'argv': ['wrong']}] + events[2:],
                 events[:-1] + [{'event': 'frame_ready', 'stage': 'minimal'}] + events[-1:],
                 events[:-1] + [{'event': 'command', 'argv': ['/usr/bin/hyprctl', '-j', 'clients']}] + events[-1:]]
        bad_monitor = copy.deepcopy(events); bad_monitor[-2]['stdout'] = '[{"width":0,"height":0}]'
        cases.append(bad_monitor)
        for changed in cases:
            with self.subTest(events=changed), self.assertRaises(ValueError):
                run.image_decode_observation(changed, context, nonce)

    def test_valid_decode_error_and_missing_cache_stay_observations(self):
        import run
        from test_image_decode_probe import fixture, encoded
        from image_decode_report import ASSET_SHA256
        nonce, context, events, _ = decode_capture()
        row = fixture(); row['asset']['sha256'] = ASSET_SHA256
        row['cache'].update(status='missing', size=None, sha256=None, errno=2)
        row['decode'].update(status='error', width=None, height=None, error_domain=1, error_code=2)
        raw = encoded(row); event = dict(events[-1], report_sha256=hashlib.sha256(raw).hexdigest(),
                                       report_base64=base64.b64encode(raw).decode('ascii'))
        observation = run.image_decode_observation(events[:-1] + [event], context, nonce)
        self.assertEqual(observation['observation']['decode']['status'], 'error')
        self.assertEqual(observation['observation']['cache']['status'], 'missing')
        self.assertEqual(set(observation), {'binding', 'observation'})

    def project_model(self, result, context):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); raw = root / 'raw'; out = root / 'out'; raw.mkdir(); out.mkdir()
            common.save(raw / 'result.json', result)
            with patch.object(c, 'CORE', decode_core()):
                report = {}; c.project(raw, out, report, image_decode_context=context)
            return report, common.json_load(out / 'guest-events.json')

    def test_later_failed_guest_preserves_bound_observation(self):
        nonce, context, events, observation = decode_capture()
        result = {'status': 'FAILED', 'nonce': nonce, 'events': events + [{'event': 'guest_failed', 'error': 'later failure'}],
                  'image_decode_observation': observation, 'frames': {}}
        report, retained = self.project_model(result, context)
        self.assertEqual(report['guest']['status'], 'FAILED')
        self.assertEqual(report['image_decode_observation'], observation)
        self.assertEqual(retained, result['events'])
        self.assertEqual(report['frames'], {})

    def test_result_self_binding_and_every_context_mutation_refused(self):
        nonce, context, events, observation = decode_capture()
        result = {'status': 'FAILED', 'nonce': nonce, 'events': events,
                  'image_decode_observation': observation, 'frames': {}}
        for key in context:
            changed = copy.deepcopy(result)
            changed['image_decode_observation']['binding']['context'][key] = '9' if key in ('run_id', 'run_attempt') else '0' * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.project_model(changed, context)
        with self.assertRaises(common.Refused): self.project_model(result, None)

    def test_closed_transport_failure_is_retained_but_cannot_capture(self):
        nonce, context, events, _ = decode_capture()
        failed = dict(events[-1], error='timeout', returncode=-9, elapsed_ms=None,
                      report_sha256=None, report_base64=None)
        result = {'status': 'FAILED', 'nonce': nonce, 'events': events[:-1] + [failed], 'frames': {}}
        report, retained = self.project_model(result, context)
        self.assertNotIn('image_decode_observation', report)
        self.assertEqual(retained[-1], failed)
        with self.assertRaises(ValueError): self.project_model(dict(result, status='CAPTURED_REQUIRES_VISUAL_REVIEW'), context)

    def test_capture_without_probe_and_duplicate_private_or_late_report_refused(self):
        nonce, context, events, observation = decode_capture()
        result = {'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW', 'nonce': nonce,
                  'events': events, 'image_decode_observation': observation, 'frames': {}}
        mutations = [lambda r: r.update(events=[]),
                     lambda r: r['events'].append(copy.deepcopy(r['events'][-1])),
                     lambda r: r['events'][-1].update(private_path='/private/key'),
                     lambda r: r['events'][-1].update(elapsed_ms=20001),
                     lambda r: r['events'][-1].update(report_sha256='0' * 64)]
        for change in mutations:
            changed = copy.deepcopy(result); change(changed)
            with self.subTest(change=change), self.assertRaises(ValueError): self.project_model(changed, context)

    def test_projector_sources_are_pinned_and_original_core_literals_await_root(self):
        core = decode_core()
        with patch.object(c, 'CORE', core): self.assertTrue(callable(c.reviewed_decode_run().image_decode_context))
        for key in ('run.py', 'image_decode_report.py'):
            with patch.object(c, 'CORE', core | {key: '0' * 64}), self.assertRaises(common.Refused): c.reviewed_decode_run()

    def test_guest_requires_observation_frames_and_original_gates(self):
        import run
        nonce, _, _, observation = decode_capture()
        report = {'frames': {'minimal': {}, 'overlay': {}}, 'image_decode_observation': observation}
        event = {'event': 'guest_pass', 'nonce': nonce}
        run.validate_guest_completion(event, nonce, True, {'minimal', 'overlay'}, report)
        cases = [(False, {'minimal', 'overlay'}, report, event),
                 (True, {'minimal'}, report, event),
                 (True, {'minimal', 'overlay'}, {'frames': report['frames']}, event),
                 (True, {'minimal', 'overlay'}, dict(report, frames={}), event),
                 (True, {'minimal', 'overlay'}, dict(report, frames={'minimal': {}}), event),
                 (True, {'minimal', 'overlay'}, report, dict(event, nonce='0' * 32))]
        for gbm, passed, changed, candidate in cases:
            with self.subTest(gbm=gbm, passed=passed, report=changed), self.assertRaises(common.Refused):
                run.validate_guest_completion(candidate, nonce, gbm, passed, changed)


if __name__ == '__main__':
    unittest.main()
