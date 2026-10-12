"""Virtual adapter tests use temporary fixtures and mocked fetch/owner commands."""
import copy
import base64
import hashlib
import json
import io
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent.resolve()
sys.path.insert(0, str(HERE))
import virtual_stage as v


def sha(data):
    return hashlib.sha256(data).hexdigest()


class VirtualStage(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root, self.native, self.work, self.cache = (self.base / n for n in ('root', 'native', 'work', 'cache'))
        for path in (self.root, self.native, self.work, self.cache):
            path.mkdir()
        self.output = self.base / 'stage'
        self.c = SimpleNamespace(native_out=self.native, work=self.work, image='sha256:' + 'a' * 64,
            installed='sha256:' + 'c' * 64, commit='b' * 40,
            report={'stages': {'lifecycle': {'status': 'PASS'}, 'desktop': {'status': 'FAIL'}, 'onboarding': {'status': 'FAIL'}}})
        self.base_map = {f'base-{n:03d}': '1-1' for n in range(341)}
        self.put(self.native / 'packages.lock', self.lock(self.base_map))
        self.put(self.native / 'image-id', self.c.image.encode())
        inputs = {'rootfs_packages': [], 'packages': [{'name': n, 'version': ver} for n, ver in self.base_map.items()]}
        self.put_json(self.native / 'inputs.lock.json', inputs)
        self.put_json(self.native / 'result.json', {'native_build': 'PASS', 'reviewed_inputs_sha256': v.digest(self.native / 'inputs.lock.json')})
        self.put_json(self.native / 'bootstrap.json', {'status': 'image-provisioned', 'image_id': self.c.image,
            'packages_lock_sha256': v.digest(self.native / 'packages.lock'), 'inputs_sha256': v.digest(self.native / 'inputs.lock.json')})
        self.rows = []
        for name in sorted(v.OVERLAYS):
            data = name.encode(); archive = 'baseline/' + name + '-1-1-any.pkg.tar.zst'
            self.rows.append({'name': name, 'version': '1-1', 'archive': archive, 'sha256': sha(data),
                              'payload_sha256': {'usr/share/' + name + '/setting': sha(data)}, 'original_extra': 'retained'})
            self.put(self.work / 'archive-inputs' / archive, data)
        self.put_json(self.work / 'fixtures-raw/archives.json', {'baseline': self.rows})
        self.versions = {r['name']: r['version'] for r in self.rows}
        self.payload = {r['name']: r['payload_sha256'] for r in self.rows}
        self.handoff = self.work / 'lifecycle-raw'
        self.put(self.handoff / 'installed-packages.lock', self.lock(self.base_map | self.versions))
        self.put_json(self.handoff / 'lifecycle/result.json', {'status': 'PASS', 'baseline_handoff_ready': True,
            'source_commit': self.c.commit, 'image_id': self.c.image, 'handoff_package_versions': self.versions,
            'handoff_payload_sha256': self.payload})
        self.put_json(self.handoff / 'commit-receipt.json', {'status': 'READY', 'purpose': 'sanitized-baseline-image-handoff',
            'source_commit': self.c.commit, 'image_id': self.c.image, 'package_versions': self.versions,
            'payload_sha256': self.payload, 'installed_package_count': 345,
            'installed_packages_sha256': v.digest(self.handoff / 'installed-packages.lock'),
            'base_packages_sha256': v.digest(self.native / 'packages.lock'),
            'private_cleanup': 'PASS; no private contents or hashes recorded',
            'checks': [{'check': n, 'status': 'PASS'} for n in sorted(v.GATES)]})
        self.put_json(self.handoff / 'installed-image.json', {'image_id': self.c.installed, 'source_commit': self.c.commit,
            'base_image': self.c.image, 'lock_sha256': v.digest(self.handoff / 'installed-packages.lock'),
            'commit_receipt_sha256': v.digest(self.handoff / 'commit-receipt.json')})
        self.put_json(self.handoff / 'committed-config.json', {'status': 'PASS', 'image_id': self.c.installed,
            'accepted_base_config': {'Entrypoint': [], 'Labels': {}}, 'committed_config': {'Entrypoint': [], 'Labels': {}},
            'test_identity_in_image_env': False})
        self.put_json(self.handoff / 'committed-image/result.json', {'status': 'PASS', 'image_id': self.c.installed,
            'source_commit': self.c.commit, 'baseline': self.rows,
            'installed_packages_sha256': v.digest(self.handoff / 'installed-packages.lock')})
        self.owner = self.root / 'scripts/virtual'; self.owner.mkdir(parents=True)
        self.blob_data = {}
        keys = []
        for name in ('archlinuxarm.gpg', 'archlinuxarm-trusted', 'archlinuxarm-revoked'):
            keys.append(self.blob(name))
        packages = []
        for n in range(19):
            row = self.blob(f'tooling-{n:02d}-1-1-aarch64.pkg.tar.xz')
            signature = self.blob(row['filename'] + '.sig')
            row.update(name=f'tooling-{n:02d}', version='1-1', signature_sha256=signature['sha256'], signature_size=signature['size'])
            packages.append(row)
        self.put_json(self.owner / 'tooling.lock.json', {'base_inputs_lock_sha256': v.digest(self.native / 'inputs.lock.json'),
            'base_package_count': 341, 'expected_package_count': 360, 'keyring_files': keys, 'packages': packages})
        self.put_json(self.owner / 'tooling-audit.json', {'status': 'PASS', 'tooling_lock_sha256': v.digest(self.owner / 'tooling.lock.json'),
                                                       'packages': {r['name']: {} for r in packages}})
        for name in ('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c', 'audit_tooling.py'):
            self.put(self.owner / name, (name + '\n').encode())
        self.rebind()
        exporter = self.root / 'scripts/ci/integration_export.py'; exporter.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(HERE.parent / 'integration_export.py', exporter)
        self.put(self.root / 'scripts/ci/native_arm.py', b'# fixture; never execute fetch\n')
        self.fetch = Mock(side_effect=self.mock_fetch)
        self.addCleanup(patch.stopall)
        patch.object(v, 'fetch_blob', self.fetch).start()
        self.command = patch.object(v, 'command', side_effect=self.mock_owner).start()

    def put(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)

    def put_json(self, path, value):
        self.put(path, (json.dumps(value, sort_keys=True) + '\n').encode())

    def lock(self, rows):
        return ''.join(f'{n} {ver}\n' for n, ver in sorted(rows.items())).encode()

    def mutate(self, path, action):
        value = v.read_json(path); action(value); self.put_json(path, value)

    def blob(self, name):
        data = ('blob-' + name).encode(); self.blob_data[name] = data
        return {'filename': name, 'url': 'https://example.invalid/' + name, 'size': len(data), 'sha256': sha(data)}

    def rebind(self):
        core = {n: v.digest(self.owner / n) for n in ('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c')}
        self.put(self.owner / 'controller.py', ('LOCK_PIN = ' + repr(v.digest(self.owner / 'tooling.lock.json')) + '\n' +
            'AUDIT_PIN = ' + repr(v.digest(self.owner / 'tooling-audit.json')) + '\n' +
            'AUDITOR_PIN = ' + repr(v.digest(self.owner / 'audit_tooling.py')) + '\nCORE = ' + repr(core) + '\nALIASES = ' + repr(v.ALIASES) + '\n').encode())
        self.c.virtual_packet_sha256 = {n: v.digest(self.owner / n) for n in v.PACKET_FILES}

    def mock_fetch(self, row, cache, deadline=None):
        path = cache / row['filename']; self.put(path, self.blob_data[row['filename']]); return path

    def mock_owner(self, argv, log, timeout):
        self.assertEqual(timeout, 3420)
        self.assertEqual(argv[1], '-B')
        contract_path = Path(argv[argv.index('--contract') + 1]); contract = v.read_json(contract_path)
        self.assertEqual(argv[argv.index('--contract-sha256') + 1], v.digest(contract_path))
        self.assertEqual(contract['baseline'], self.rows)
        self.assertEqual(set(contract['files']), v.ALIASES)
        self.assertEqual(len(list((contract_path.parent / 'tooling-cache').iterdir())), 41)
        out = Path(argv[argv.index('--output') + 1]); out.mkdir()
        events = [
            {'event': 'boot', 'nonce': 'e' * 32, 'arch': 'aarch64', 'page_size': 4096,
             'kernel': '7.2.10-1-aarch64-ARCH', 'execution': 'qemu-tcg-generic-aarch64', 'hardware_validation': 'NOT RUN'},
            {'event': 'gbm_pass', 'nonce': 'e' * 32, 'probe': {'schema': 1, 'status': 'PASS',
             'scope': 'guest_software_gbm_egl_only', 'renderer': 'llvmpipe', 'width': 64, 'height': 64,
             'verified_pixels': 4096, 'expected_rgba': [255, 0, 255, 255],
             'scanout': 'NOT_RUN', 'm2_hardware': 'NOT_RUN', 'performance': 'NOT_RUN'}}]
        for stage in ('minimal', 'overlay'):
            events.extend([{'event': 'frame_ready', 'stage': stage, 'monitors': [{'width': 8, 'height': 1}],
                            'clients': [{'pid': 100, 'mapped': True, 'size': [8, 1]}]},
                           {'event': 'phase_pass', 'stage': stage}])
        events.append({'event': 'guest_pass', 'nonce': 'e' * 32, 'software_session': 'PASS',
                       'hardware_validation': 'NOT RUN', 'graphics_acceleration': 'NOT RUN'})
        self.put_json(out / 'guest-events.json', events)
        frames = {}
        ppm = b'P6\n8 1\n255\n' + b''.join(bytes((n, n * 3, n * 5)) for n in range(8))
        for stage in ('minimal', 'overlay'):
            self.put(out / (stage + '.ppm'), ppm)
            frames[stage] = {'filename': stage + '.ppm', 'sha256': sha(ppm), 'width': 8, 'height': 1,
                             'distinct_rgb_values': 8, 'visual_review': 'NOT RUN'}
        receipt = {'schema_version': 1, 'purpose': 'bounded-generic-arm-software-proof',
            'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW', 'source_commit': contract['source_commit'],
            'baseline_image': contract['installed_image_id'], 'controller_contract_sha256': v.digest(contract_path),
            'source_sha256': contract['core_sha256'] | {'controller.py': contract['controller_sha256'],
                'audit_tooling.py': contract['audit_tooling_sha256']}, 'inputs': contract['files'],
            'cleanup': [{'container': 'cachy-virtual-' + stage + '-' + 'e' * 32,
                         'status': 'PASS', 'absence_verified': True} for stage in ('tooling', 'verify', 'prepare', 'run')] +
                       [{'private_tag': 'cachy-virtual-private-' + 'e' * 32 + ':fixture', 'image_id': 'sha256:' + 'd' * 64,
                         'status': 'PASS', 'absence_verified': True, 'commit_outcome_uncertain': False}],
            'private_workspace_cleanup': 'PASS', 'proof_contract_sha256': 'f' * 64, 'prepare_receipt_sha256': 'e' * 64,
            'guest': {'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW', 'execution': 'qemu-tcg-generic-aarch64',
                      'contract_sha256': 'f' * 64, 'prepare_receipt_sha256': 'e' * 64, 'image_id': 'sha256:' + 'd' * 64,
                      'nonce': 'e' * 32, 'software_session_ipc': 'PASS', 'software_compositor': 'REVIEW REQUIRED',
                      'frame_proof': 'REVIEW REQUIRED', 'hardware_validation': 'NOT RUN', 'graphics_acceleration': 'NOT RUN',
                      'm2_16k_pages': 'NOT RUN', 'performance': 'NOT RUN'},
            'frames': frames, 'guest_events_sha256': v.digest(out / 'guest-events.json'),
            'stages': {'tooling': {'status': 'READY', 'package_count': 364, 'image_id': 'sha256:' + 'd' * 64}, 'preparation': {'status': 'PREPARED'}}}
        self.put_json(out / 'result.json', receipt)
        self.put(out / 'qemu.log', b'QEMU diagnostic\n')
        for stage in ('tooling', 'verify', 'prepare', 'runtime'):
            self.put(out / (stage + '-container.log'), (stage + ' diagnostic\n').encode())
        self.put(out / 'unknown.txt', b'never export this\n')
        self.put(out / 'key-init.log', b'never export this either\n')
        self.put(log, b'controlled launcher output\n')
        return 0

    def run_adapter(self):
        return v.run_virtual(self.c, self.root, self.output, self.cache)

    def assert_prerequisite_refused(self):
        result = self.run_adapter(); self.assertEqual(result['status'], 'NOT RUN')
        self.fetch.assert_not_called(); self.command.assert_not_called()
        self.assertEqual(result['public'], [str(self.output / 'adapter-status')])
        return result

    def test_absent_accepted_packet_refuses_before_acquisition(self):
        del self.c.virtual_packet_sha256
        self.assertEqual(self.assert_prerequisite_refused()['error_code'], 'virtual-source-packet-not-accepted')

    def test_packet_drift_and_incomplete_map_refuse(self):
        self.c.virtual_packet_sha256['controller.py'] = '0' * 64
        self.assert_prerequisite_refused()

    def test_owner_constants_must_match_accepted_packet(self):
        with (self.owner / 'controller.py').open('ab') as stream:
            stream.write(b"LOCK_PIN = '" + b'0' * 64 + b"'\n")
        self.c.virtual_packet_sha256['controller.py'] = v.digest(self.owner / 'controller.py')
        self.assert_prerequisite_refused()

    def test_lifecycle_failure_refuses_without_fetch(self):
        self.c.report['stages']['lifecycle']['status'] = 'FAIL'; self.assert_prerequisite_refused()

    def test_wrong_installed_image_refuses(self):
        self.c.installed = 'sha256:' + 'd' * 64; self.assert_prerequisite_refused()

    def test_installed_inventory_extra_refuses(self):
        with (self.handoff / 'installed-packages.lock').open('ab') as stream:
            stream.write(b'extra 1-1\n')
        self.assert_prerequisite_refused()

    def test_lifecycle_full_payload_binding_required(self):
        self.mutate(self.handoff / 'lifecycle/result.json', lambda x: x['handoff_payload_sha256'].clear())
        self.assert_prerequisite_refused()

    def test_ready_receipt_and_all_cleanup_gates_required(self):
        self.mutate(self.handoff / 'commit-receipt.json', lambda x: x['checks'].pop())
        self.assert_prerequisite_refused()

    def test_original_archive_drift_refuses(self):
        self.put(self.work / 'archive-inputs' / self.rows[0]['archive'], b'wrong')
        self.assert_prerequisite_refused()

    def test_symlink_input_refuses_before_acquisition(self):
        path = self.handoff / 'installed-packages.lock'; target = self.base / 'actual-lock'
        path.rename(target); path.symlink_to(target)
        self.assert_prerequisite_refused()

    def test_duplicate_json_refuses(self):
        self.put(self.handoff / 'lifecycle/result.json', b'{"status":"PASS","status":"PASS"}')
        self.assert_prerequisite_refused()

    def test_reviewed_audit_cannot_be_fabricated_or_modified(self):
        self.mutate(self.owner / 'tooling-audit.json', lambda x: x.update(status='FAIL'))
        self.rebind(); self.assert_prerequisite_refused()

    def test_success_retains_only_explicit_public_capture_and_diagnostics(self):
        result = self.run_adapter()
        self.assertEqual(result['status'], 'PASS'); self.assertEqual(self.fetch.call_count, 41)
        self.assertEqual(result['owner_status'], 'CAPTURED_REQUIRES_VISUAL_REVIEW')
        self.assertEqual(result['visual_review'], 'REQUIRED'); self.assertEqual(result['hardware_validation'], 'NOT RUN')
        self.assertEqual({Path(p).name for p in result['public']}, {'adapter-status', *v.PUBLIC_DIRS})
        published = [p.name for directory in result['public'] for p in Path(directory).iterdir()]
        self.assertNotIn('unknown.txt', published); self.assertNotIn('key-init.log', published)
        acquisition = v.read_json(self.output / 'adapter-status/acquisition.json')
        self.assertEqual(len(acquisition['inputs']), 41); self.assertEqual(acquisition['status'], 'PIN_MATCH')

    def test_all_acquisition_results_collected_after_one_failure(self):
        def fetch(row, cache, deadline):
            if row['filename'] == 'archlinuxarm.gpg':
                raise ValueError('password=do-not-export')
            return self.mock_fetch(row, cache)
        self.fetch.side_effect = fetch
        result = self.run_adapter(); self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(self.fetch.call_count, 41); self.command.assert_not_called()
        receipt = v.read_json(self.output / 'adapter-status/acquisition.json')
        self.assertEqual(len(receipt['inputs']), 41); self.assertEqual(sum(r['status'] == 'FAIL' for r in receipt['inputs']), 1)
        self.assertNotIn('do-not-export', (self.output / 'adapter-status/result.json').read_text())

    def owner_mutation(self, action, code=0):
        def invoke(argv, log, timeout):
            self.mock_owner(argv, log, timeout)
            action(self.output / 'owner-public')
            return code
        self.command.side_effect = invoke

    def test_failed_owner_retains_failure_diagnostics_and_cleanup(self):
        self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda x: x.update(status='FAIL')), 1)
        result = self.run_adapter(); self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['owner_cleanup']['status'], 'PASS')
        self.assertTrue((self.output / 'virtual-public/qemu/qemu.log').is_file())

    def test_cleanup_uncertainty_refuses_pass(self):
        self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda x: x['cleanup'][0].update(status='FAIL', absence_verified=False)))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')

    def test_incomplete_owned_cleanup_refuses_pass(self):
        self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda x: x['cleanup'].pop()))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')

    def test_wrong_guest_proof_binding_refuses_pass(self):
        self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda x: x['guest'].update(contract_sha256='0' * 64)))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')

    def test_wrong_owner_contract_binding_refuses_pass_and_all_binary_publication(self):
        self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda x: x.update(controller_contract_sha256='0' * 64)))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
        self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())

    def test_wrong_guest_nonce_image_source_and_inputs_publish_no_frames(self):
        mutations = [lambda x: x['guest'].update(nonce='0' * 32),
                     lambda x: x['guest'].update(image_id='sha256:' + '0' * 64),
                     lambda x: x.update(source_commit='0' * 40),
                     lambda x: x['inputs'].pop('base_lock')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.owner_mutation(lambda out: self.mutate(out / 'result.json', mutation))
                self.assertEqual(self.run_adapter()['status'], 'FAIL')
                self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
                self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())
                shutil.rmtree(self.output)

    def test_cancel_during_frame_staging_never_selects_incomplete_binary(self):
        original_save = v.save
        def interrupted(path, value):
            if Path(path).name == 'receipt.json' and Path(path).parent.name == 'minimal-frame':
                raise KeyboardInterrupt()
            return original_save(path, value)
        with patch.object(v, 'save', side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.run_adapter()
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
        self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())
        self.assertEqual(v.read_json(self.output / 'adapter-status/result.json')['status'], 'FAIL')

    def test_missing_or_wrong_event_binding_refuses_pass(self):
        self.owner_mutation(lambda out: self.put(out / 'guest-events.json', b'[]'))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')

    def test_wrong_frame_hash_refuses_public_binary(self):
        self.owner_mutation(lambda out: self.put(out / 'minimal.ppm', b'wrong'))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())

    def test_private_log_content_rejected_without_copy(self):
        self.owner_mutation(lambda out: self.put(out / 'qemu.log', b'-----BEGIN PGP PRIVATE KEY BLOCK-----\n'))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        manifest = v.read_json(self.output / 'virtual-public/qemu/export-manifest.json')
        self.assertEqual(manifest['evidence_export'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/qemu/qemu.log').exists())

    def test_oversized_log_has_explicit_refusal_manifest(self):
        self.owner_mutation(lambda out: self.put(out / 'qemu.log', b'a' * (v.LIMIT + 1)))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertEqual(v.read_json(self.output / 'virtual-public/qemu/export-manifest.json')['evidence_export'], 'FAIL')

    def test_owner_public_symlink_refuses(self):
        def replace(out):
            (out / 'qemu.log').unlink(); (out / 'qemu.log').symlink_to(self.base / 'absent')
        self.owner_mutation(replace)
        self.assertEqual(self.run_adapter()['status'], 'FAIL')

    def test_timeout_retains_owner_failure_receipt(self):
        def timeout(argv, log, bound):
            self.mock_owner(argv, log, bound)
            self.mutate(self.output / 'owner-public/result.json', lambda x: x.update(status='FAIL'))
            raise ValueError('stage-deadline-exceeded')
        self.command.side_effect = timeout
        result = self.run_adapter(); self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['owner_cleanup']['status'], 'PASS')
        self.assertTrue((self.output / 'virtual-public/result/result.json').is_file())

    def test_cancel_propagates_after_fail_receipt_and_public_retention(self):
        def cancel(argv, log, bound):
            self.mock_owner(argv, log, bound)
            self.mutate(self.output / 'owner-public/result.json', lambda x: x.update(status='FAIL'))
            raise KeyboardInterrupt()
        self.command.side_effect = cancel
        with self.assertRaises(KeyboardInterrupt):
            self.run_adapter()
        receipt = v.read_json(self.output / 'adapter-status/result.json')
        self.assertEqual(receipt['status'], 'FAIL'); self.assertEqual(receipt['error_code'], 'cancelled')
        self.assertEqual(receipt['owner_cleanup']['status'], 'PASS')
        self.assertIn(str(self.output / 'virtual-public/qemu'), v.public_paths(self.output))

    def test_ordinary_exception_text_never_enters_adapter_receipt(self):
        self.command.side_effect = ValueError('Bearer sensitive-token')
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertNotIn('sensitive-token', (self.output / 'adapter-status/result.json').read_text())

    def test_cancel_during_acquisition_records_all_pending_inputs(self):
        count = 0
        def fetch(row, cache, deadline):
            nonlocal count
            count += 1
            if count == 3:
                raise KeyboardInterrupt()
            return self.mock_fetch(row, cache)
        self.fetch.side_effect = fetch
        with self.assertRaises(KeyboardInterrupt):
            self.run_adapter()
        receipt = v.read_json(self.output / 'adapter-status/acquisition.json')
        self.assertEqual(len(receipt['inputs']), 41)
        self.assertEqual(sum(r['status'] == 'PIN_MATCH' for r in receipt['inputs']), 2)
        self.assertTrue(all(r['error_code'] == 'tooling-acquisition-cancelled' for r in receipt['inputs'][2:]))
        self.command.assert_not_called()

    def test_global_deadline_stops_new_fetches_and_records_all_outcomes(self):
        clock = [0]
        def fetch(row, cache, deadline):
            clock[0] = 601
            raise v.AcquisitionDeadline('tooling-acquisition-deadline')
        self.fetch.side_effect = fetch
        with patch.object(v.time, 'monotonic', side_effect=lambda: clock[0]):
            result = self.run_adapter()
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(self.fetch.call_count, 1)
        receipt = v.read_json(self.output / 'adapter-status/acquisition.json')
        self.assertEqual(len(receipt['inputs']), 41)
        self.assertTrue(all(r['error_code'] == 'tooling-acquisition-deadline' for r in receipt['inputs']))
        self.command.assert_not_called()

    def altered_events(self, out, action):
        path = out / 'guest-events.json'
        events = json.loads(path.read_bytes())
        action(events); self.put_json(path, events)
        self.mutate(out / 'result.json', lambda x: x.update(guest_events_sha256=v.digest(path)))

    def test_rehashed_empty_incomplete_duplicate_or_reordered_events_publish_no_frames(self):
        mutations = [lambda events: events.clear(), lambda events: events.pop(3),
                     lambda events: events.insert(0, copy.deepcopy(events[0])),
                     lambda events: events.reverse()]
        for mutation in mutations:
            self.owner_mutation(lambda out: self.altered_events(out, mutation))
            self.assertEqual(self.run_adapter()['status'], 'FAIL')
            self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
            self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())
            shutil.rmtree(self.output)

    def test_nonce_boot_arch_page_and_software_probe_drift_publish_no_frames(self):
        mutations = [lambda events: events[0].update(nonce='0' * 32),
                     lambda events: events[1].update(nonce='0' * 32),
                     lambda events: events[-1].update(nonce='0' * 32),
                     lambda events: events[0].update(arch='x86_64'),
                     lambda events: events[0].update(page_size=16384),
                     lambda events: events[1]['probe'].update(renderer='host-GPU'),
                     lambda events: events[2]['clients'][0].update(mapped=False)]
        for mutation in mutations:
            self.owner_mutation(lambda out: self.altered_events(out, mutation))
            self.assertEqual(self.run_adapter()['status'], 'FAIL')
            self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
            self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())
            shutil.rmtree(self.output)

    def test_actual_interleaved_command_and_known_terminal_log_events_pass(self):
        data = b'\x1b[32mpublic compositor log\x1b[0m\n'
        def add(events):
            for command in ('/usr/bin/dmesg', '/usr/bin/pacman'):
                events.insert(1, {'event': 'command', 'argv': [command], 'returncode': 0, 'error': None,
                                  'stdout': 'public diagnostic', 'stderr': ''})
            events.insert(5, {'event': 'session_log', 'stage': 'minimal', 'filename': 'minimal-client.log',
                             'sha256': sha(data), 'base64': base64.b64encode(data).decode()})
        self.owner_mutation(lambda out: self.altered_events(out, add))
        self.assertEqual(self.run_adapter()['status'], 'PASS')

    def test_encoded_private_terminal_log_is_refused_before_event_copy(self):
        data = b'-----BEGIN PGP PRIVATE KEY BLOCK-----\n'
        def add(events):
            events.insert(3, {'event': 'session_log', 'stage': 'minimal', 'filename': 'minimal.log',
                              'sha256': sha(data), 'base64': base64.b64encode(data).decode()})
        self.owner_mutation(lambda out: self.altered_events(out, add))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/events').exists())
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())

    def test_unknown_event_fields_cannot_enter_public_projection(self):
        self.owner_mutation(lambda out: self.altered_events(out, lambda events: events[2].update(opaque='encoded-unknown-payload')))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/events').exists())
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())

    def test_duplicate_event_json_fields_refused_before_public_copy(self):
        def duplicate(out):
            path = out / 'guest-events.json'
            data = path.read_bytes().replace(b'"event": "boot"', b'"event": "boot", "event": "boot"', 1)
            self.put(path, data)
            self.mutate(out / 'result.json', lambda x: x.update(guest_events_sha256=sha(data)))
        self.owner_mutation(duplicate)
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/events').exists())
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())

    def test_unsafe_cache_ancestor_cannot_create_external_directory(self):
        external = self.base / 'external'; external.mkdir()
        link = self.base / 'linked-cache'; link.symlink_to(external, target_is_directory=True)
        result = v.run_virtual(self.c, self.root, self.output, link / 'new-cache')
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(list(external.iterdir()), [])
        self.fetch.assert_not_called(); self.command.assert_not_called()
        self.assertEqual(len(v.read_json(self.output / 'adapter-status/acquisition.json')['inputs']), 41)

    def test_repeated_late_cancel_is_deferred_then_fail_receipt_rewritten(self):
        original_save = v.save
        original_signal = v.signal.signal
        handlers = {}
        def track(sig, handler):
            handlers[sig] = handler
            return original_signal(sig, handler)
        fired = False
        def interrupted(path, value):
            nonlocal fired
            original_save(path, value)
            if Path(path) == self.output / 'adapter-status/result.json' and not fired:
                fired = True
                handlers[v.signal.SIGTERM](v.signal.SIGTERM, None)
                handlers[v.signal.SIGINT](v.signal.SIGINT, None)
        with patch.object(v.signal, 'signal', side_effect=track), patch.object(v, 'save', side_effect=interrupted), \
                self.assertRaises(KeyboardInterrupt):
            self.run_adapter()
        receipt = v.read_json(self.output / 'adapter-status/result.json')
        self.assertEqual(receipt['status'], 'FAIL'); self.assertEqual(receipt['error_code'], 'cancelled')
        self.assertEqual(len(v.read_json(self.output / 'adapter-status/acquisition.json')['inputs']), 41)
        self.assertTrue((self.output / 'virtual-public/result/result.json').is_file())

    def test_actual_source_literals_match_current_files_without_importing_owner(self):
        root = HERE.parents[2]
        accepted = {name: v.digest(root / 'scripts/virtual' / name) for name in v.PACKET_FILES}
        v.source_packet(SimpleNamespace(virtual_packet_sha256=accepted), root)


class BoundedTransport(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.cache = Path(temp.name)
        self.data = b'authenticated public package bytes'
        self.row = {'filename': 'fixture.pkg.tar.xz', 'url': 'https://example.invalid/fixture.pkg.tar.xz',
                    'sha256': sha(self.data), 'size': len(self.data)}

    def response(self, data=None, url=None):
        response = io.BytesIO(self.data if data is None else data)
        response.status = 200; response.headers = {'Content-Length': str(len(self.data))}
        response.geturl = lambda: url or self.row['url']
        return response

    def test_exact_input_download_and_cached_reuse(self):
        with patch.object(v, 'open_tooling', return_value=self.response()) as transport:
            path = v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600)
        transport.assert_called_once_with(self.row['url'], timeout=15)
        self.assertEqual(path.read_bytes(), self.data)
        with patch.object(v, 'open_tooling', side_effect=AssertionError('no cache fallback')):
            self.assertEqual(v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600), path)
        self.assertFalse(any(p.name.endswith('.partial') for p in self.cache.iterdir()))

    def test_oversize_hash_failure_and_insecure_final_response_remove_only_owned_partial(self):
        unrelated = self.cache / 'unrelated.partial'; unrelated.write_bytes(b'preserve')
        for response in (self.response(self.data + b'x'), self.response(b'x' * len(self.data)),
                         self.response(url='http://example.invalid/fixture.pkg.tar.xz')):
            with patch.object(v, 'open_tooling', return_value=response), self.assertRaises(ValueError):
                v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600)
            self.assertEqual(list(self.cache.iterdir()), [unrelated])

    def test_short_reads_are_checked_against_global_deadline(self):
        clock = [0]
        response = self.response()
        def trickle(size):
            clock[0] += 302
            return b'x'
        response.read1 = trickle
        with patch.object(v.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(v, 'open_tooling', return_value=response), self.assertRaises(v.AcquisitionDeadline):
            v.fetch_blob(self.row, self.cache, 600)
        self.assertEqual(clock[0], 604); self.assertEqual(list(self.cache.iterdir()), [])

    def test_cancelled_transport_closes_and_removes_owned_partial(self):
        response = self.response(); response.read1 = Mock(side_effect=KeyboardInterrupt())
        with patch.object(v, 'open_tooling', return_value=response), self.assertRaises(KeyboardInterrupt):
            v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600)
        self.assertTrue(response.closed); self.assertEqual(list(self.cache.iterdir()), [])

    def test_symlink_or_changed_cache_refused_without_network(self):
        path = self.cache / self.row['filename']; path.symlink_to('/absent')
        with patch.object(v, 'open_tooling') as transport, self.assertRaises(ValueError):
            v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600)
        transport.assert_not_called(); path.unlink(); path.write_bytes(b'wrong')
        with patch.object(v, 'open_tooling') as transport, self.assertRaises(ValueError):
            v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600)
        transport.assert_not_called()

    def test_redirect_rejects_insecure_hop_before_destination_request(self):
        with self.assertRaisesRegex(ValueError, 'insecure-redirect'):
            v.HTTPSRedirect().redirect_request(None, None, 302, '', {}, 'http://example.invalid/public')

    def test_phase_alarm_bounds_header_trickle_and_restores_outer_remaining_time(self):
        handlers, clock = [], [10]
        outer = Mock()
        with patch.object(v.signal, 'getsignal', return_value=outer), \
                patch.object(v.signal, 'getitimer', return_value=(1200, 0)), \
                patch.object(v.signal, 'signal', side_effect=lambda sig, handler: handlers.append(handler)), \
                patch.object(v.signal, 'setitimer') as timer, \
                patch.object(v.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(v.AcquisitionDeadline):
                with v.acquisition_clock() as deadline:
                    self.assertEqual(deadline, 610)
                    clock[0] = 610
                    with patch.object(v, 'open_tooling', side_effect=lambda *a, **k: handlers[0](v.signal.SIGALRM, None)):
                        v.fetch_blob(self.row, self.cache, deadline + 1)
            self.assertEqual(timer.call_args_list[0].args, (v.signal.ITIMER_REAL, 600))
            self.assertEqual(timer.call_args_list[-1].args, (v.signal.ITIMER_REAL, 600, 0))
            self.assertIs(handlers[-1], outer)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_earlier_enclosing_alarm_remains_authoritative(self):
        handlers = []
        outer = Mock(side_effect=KeyboardInterrupt())
        with patch.object(v.signal, 'getsignal', return_value=outer), \
                patch.object(v.signal, 'getitimer', return_value=(50, 0)), \
                patch.object(v.signal, 'signal', side_effect=lambda sig, handler: handlers.append(handler)), \
                patch.object(v.signal, 'setitimer') as timer:
            with self.assertRaises(KeyboardInterrupt):
                with v.acquisition_clock():
                    handlers[0](v.signal.SIGALRM, None)
            self.assertEqual(timer.call_args_list[0].args, (v.signal.ITIMER_REAL, 50))
            self.assertEqual(timer.call_args_list[-1].args, (v.signal.ITIMER_REAL, 0))
            outer.assert_called_once_with(v.signal.SIGALRM, None)
            self.assertIs(handlers[-1], outer)


if __name__ == '__main__':
    unittest.main()
