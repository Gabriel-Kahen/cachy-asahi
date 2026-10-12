# SPDX-License-Identifier: MIT
import copy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest

import broker as b
import capture as c
import producer


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.job = {'source_commit': 'a' * 40, 'recipe_source_commit': 'b' * 40, 'run_id': '7',
                    'run_attempt': '1', 'nonce': 'c' * 32, 'image_id': 'sha256:' + 'd' * 64}
        self.records = {'aggregate': {'schema_version': 1, 'purpose': 'frozen-development-only-native-integration',
            'status': 'PASS', 'source_commit': self.job['source_commit'], 'base_image': self.job['image_id'],
            'cancelled': False, 'development_only': True, 'selected_for_release': False,
            'hardware_validation': 'NOT RUN', 'production_trust': 'NOT RUN',
            'stages': {name: {'status': 'PASS'} for name in b.STAGES},
            'owned_image_cleanup': {'status': 'PASS', 'absence_verified': True, 'cleanup_uncertain': False}},
            'public_acceptance': {'purpose': 'accepted-repository-public-artifacts', 'status': 'PASS',
                                 **{key: self.job[key] for key in ('source_commit', 'run_id', 'nonce')}},
            'native_result': {'status': 'native-builds-and-virtual-integration-pass', 'mode': 'integration',
                              'native_build': 'PASS', 'virtual_integration': 'PASS'}}
        self.launched = {'status': 'PASS', 'cleanup': 'PASS', 'ownership_verified': True,
                         'container_id': 'e' * 64, 'container': 'cachy-asahi-repository-' + self.job['nonce'],
                         'nonce': self.job['nonce'], 'image_id': self.job['image_id'],
                         'absence_verified': True, 'name_absence_verified': True, 'id_absence_verified': True}
        self.checkpoints = [{'sequence': i, 'phase': c.PHASES[i - 1], 'durable_host_digest': True,
                            'sha256': str(i) * 64, 'payload_sha256': 'f' * 64} for i in (1, 2)]
        self.launched['checkpoints'] = [{'sequence': row['sequence'], 'phase': row['phase'],
                                       'frame_sha256': row['sha256'], 'payload_sha256': row['payload_sha256']}
                                      for row in self.checkpoints]
    def validate(self):
        return b.validate_terminal(self.records, self.job, self.launched, self.checkpoints, native_exit=0)
    def test_modeled_terminal_is_only_prerequisite(self):
        self.assertEqual(self.validate()['status'], 'PASS-terminal-prerequisites')
        self.assertEqual(self.validate()['native_admission'], 'NOT RUN')
    def test_every_initial_stage_and_derivative_cleanup_required(self):
        for name in b.STAGES:
            with self.subTest(stage=name):
                self.records['aggregate']['stages'][name]['status'] = 'FAIL'
                with self.assertRaises(c.Refused): self.validate()
                self.records['aggregate']['stages'][name]['status'] = 'PASS'
        self.records['aggregate']['owned_image_cleanup']['cleanup_uncertain'] = True
        with self.assertRaises(c.Refused): self.validate()
    def test_name_only_or_short_cid_cannot_backfill_old_run(self):
        for key, value in [('container_id', 'e' * 12), ('id_absence_verified', False),
                           ('ownership_verified', False), ('nonce', 'f' * 32)]:
            original = self.launched[key]; self.launched[key] = value
            with self.subTest(key=key), self.assertRaises(c.Refused): self.validate()
            self.launched[key] = original
    def test_boolean_or_unbound_checkpoint_rows_refuse(self):
        for key, value in [('sequence', True), ('sha256', 'short'), ('payload_sha256', '0' * 64)]:
            row = self.checkpoints[0]; old = row[key]; row[key] = value
            with self.subTest(key=key), self.assertRaises(c.Refused): self.validate()
            row[key] = old
    def test_missing_ack_native_exit_and_public_nonce_refuse(self):
        self.checkpoints.pop()
        with self.assertRaises(c.Refused): self.validate()
        self.checkpoints.append({'sequence': 2, 'phase': c.PHASES[1], 'durable_host_digest': True,
                                 'sha256': '2' * 64, 'payload_sha256': 'f' * 64})
        with self.assertRaises(c.Refused):
            b.validate_terminal(self.records, self.job, self.launched, self.checkpoints, native_exit=1)
        self.records['public_acceptance']['nonce'] = 'f' * 32
        with self.assertRaises(c.Refused): self.validate()
    def test_callback_cannot_manufacture_authority_and_binding_restores(self):
        class Pending:
            entered = False
            def interpose(self, *_):
                from contextlib import contextmanager
                @contextmanager
                def scope():
                    self.entered = True
                    try: yield
                    finally: self.entered = False
                return scope()
        pending = Pending()
        native = SimpleNamespace(main=lambda argv, integration_consumers: integration_consumers(object()) or 0)
        grant = c.encoded({'purpose': 'reviewed-same-job-handoff-execution', 'source_peer_preflight': 'PASS',
                           'development_only': True, 'added_seconds': 1200})
        with self.assertRaises(c.Refused):
            b.run_existing(native, object(), ['integration'], pending, object(), grant_raw=grant, grant_pin=c.digest(grant),
                           consumer=lambda *args, **kw: {'status': 'PASS'}, job_deadline=time.monotonic() + 30)
        self.assertFalse(pending.entered)
    def test_missing_external_grant_never_runs_initial_actor(self):
        calls = []
        grant = c.encoded({'purpose': 'reviewed-same-job-handoff-execution', 'source_peer_preflight': 'PENDING'})
        with self.assertRaises(c.Refused):
            b.run_existing(SimpleNamespace(main=lambda *args, **kw: calls.append(True)), object(), ['integration'],
                           object(), object(), grant_raw=grant, grant_pin=c.digest(grant), consumer=lambda *_: {},
                           job_deadline=time.monotonic() + 30)
        self.assertEqual(calls, [])
    def test_expired_or_cancelled_job_never_starts_actor(self):
        calls = []
        grant = c.encoded({'purpose': 'reviewed-same-job-handoff-execution', 'source_peer_preflight': 'PASS',
                           'development_only': True, 'added_seconds': 1200})
        for deadline, cancelled in [(-1, None), (time.monotonic() + 20, lambda: True)]:
            with self.subTest(deadline=deadline), self.assertRaises(c.Refused):
                b.run_existing(SimpleNamespace(main=lambda *args, **kw: calls.append(True)), object(), ['integration'],
                    object(), object(), grant_raw=grant, grant_pin=c.digest(grant), consumer=lambda *_: {},
                    job_deadline=deadline, cancelled=cancelled)
        self.assertEqual(calls, [])
    def test_updated_provenance_refuses_before_base_actor(self):
        request = c.encoded({'archive_role': 'updated', 'image_id': self.job['image_id'], 'source_commit': self.job['source_commit']})
        calls = []
        with self.assertRaises(c.Refused):
            b.collect_baseline({}, {}, SimpleNamespace(image=self.job['image_id'], commit=self.job['source_commit']),
                output=Path('/unused'), provenance_root=Path('/unused'), provenance_raw=request,
                provenance_pin=c.digest(request), deadline=time.monotonic() + 30,
                supervise=lambda *args, **kw: calls.append(True))
        self.assertEqual(calls, [])
    def test_unsigned_crypto_request_uses_actual_argv_and_logs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); files = {}; commands = []; evidence = {}; signers = {}
            def put(name, data):
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
                files[name] = {'sha256': c.digest(data), 'bytes': len(data)}
            for index, role in enumerate(('signer-A', 'signer-B', 'verifier'), 1):
                name = 'public/TEST-' + role + '-public.asc'; put(name, b'MODELED certificate ' + role.encode())
                signers[role] = {'fingerprint': str(index) * 40, 'public_sha256': files[name]['sha256']}
            put('public/TEST-signer-A-revoked-public.asc', b'MODELED revoked public')
            for label, role in (('baseline-A', 'signer-A'), ('updated-B', 'signer-B')):
                names = ['integration.db.tar.gz', 'integration.files.tar.gz', *('MODELED-' + str(i) + '.pkg.tar.xz' for i in range(5))]
                for name in names:
                    public = 'public/TEST-repositories/' + label + '/' + name
                    put(public, b'MODELED object'); put(public + '.sig', b'MODELED signature')
                    target = '/scratch/repos/' + label + '/' + name; home = '/test-home/' + role
                    argv = ['gpg', '--batch', '--no-options', '--homedir', home, '--no-default-keyring', '--keyring',
                            home + '/pubring.gpg', '--no-auto-key-retrieve', '--status-fd', '1', '--verify', target + '.sig', target]
                    label_name = 'verify-database-' + label if name.startswith('integration.') else 'verify-' + role
                    log = str(len(commands)) + '.txt'; put('raw/' + log, b'MODELED status')
                    evidence[log] = files['raw/' + log]['sha256']
                    commands.append({'label': label_name, 'argv': argv, 'log': log, 'exit_code': 0, 'sha256': evidence[log]})
            public = 'public/TEST-repository-aliases.json'; put(public, b'{}'); put(public + '.sig', b'MODELED signature')
            home = '/test-home/signer-B'; target = '/out/TEST-repository-aliases.json'
            log = 'alias.txt'; put('raw/' + log, b'MODELED alias status'); evidence[log] = files['raw/' + log]['sha256']
            commands.append({'label': 'verify-signer-B', 'argv': ['gpg', '--batch', '--no-options', '--homedir', home,
                '--no-default-keyring', '--keyring', home + '/pubring.gpg', '--no-auto-key-retrieve', '--status-fd', '1',
                '--verify', target + '.sig', target], 'log': log, 'exit_code': 0, 'sha256': evidence[log]})
            put('raw/revoked.txt', b'MODELED revoked'); evidence['revoked.txt'] = files['raw/revoked.txt']['sha256']
            commands.append({'label': 'gpg-revoked-A-status', 'log': 'revoked.txt', 'exit_code': 0, 'sha256': evidence['revoked.txt']})
            public_count = sum(name.startswith('public/') for name in files)
            for i in range(112 - public_count): put('public/TEST-MODELED-extra-' + str(i), b'fixture')
            repository = {'status': 'PASS', 'source_commit': self.job['source_commit'], 'commands': commands,
                          'public_TEST_identities': signers, 'evidence_sha256': evidence}
            put('raw/result.json', c.encoded(repository))
            result = b.crypto_request(root, files, 'raw/result.json', self.job, public_prefix='public', deadline=time.monotonic() + 20)
            self.assertEqual(len(result['native_verifications']), 15)
            self.assertNotIn('status', result)  # Request only; these modeled signatures are not accepted.
            commands[0].pop('argv'); put('raw/result.json', c.encoded(repository))
            with self.assertRaises(c.Refused):
                b.crypto_request(root, files, 'raw/result.json', self.job, public_prefix='public', deadline=time.monotonic() + 20)
    def test_capture_index_is_explicitly_mapped_for_exact_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'input').write_bytes(b'MODELED public fixture')
            receipt = c.capture_files({'public/file': root / 'input'}, root / 'captured', deadline=time.monotonic() + 20)
            mapped = b.capture_file_map(root / 'captured', receipt, deadline=time.monotonic() + 20)
            self.assertEqual(set(mapped), {'public/file', 'capture.json'})
            (root / 'captured/capture.json').write_bytes(c.encoded({'status': 'PENDING', 'files': {}}))
            with self.assertRaises(c.Refused):
                b.capture_file_map(root / 'captured', receipt, deadline=time.monotonic() + 20)
    def test_separate_exact_collector_tree_has_no_capture_index(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / 'source'; source.write_bytes(b'MODELED fixture')
            files = {'public/fixture': {'sha256': c.digest(source.read_bytes()), 'bytes': source.stat().st_size}}
            receipt = b.stage_exact({'public/fixture': source}, files, root / 'exact', deadline=time.monotonic() + 20)
            self.assertEqual(receipt['files'], files)
            self.assertFalse((root / 'exact/capture.json').exists())
            files['public/fixture']['sha256'] = '0' * 64
            with self.assertRaises(c.Refused):
                b.stage_exact({'public/fixture': source}, files, root / 'bad', deadline=time.monotonic() + 20)
    def test_crypto_supervision_receives_separate_exact128_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / 'source'; source.mkdir(); files = {}
            for index in range(128):
                name = f'MODELED-{index}.txt'; raw = str(index).encode(); (source / name).write_bytes(raw)
                files[name] = {'sha256': c.digest(raw), 'bytes': len(raw)}
            (source / 'extra-authority-file').write_bytes(b'MODELED additional authority ref')
            request = c.encoded({'schema_version': 2, 'purpose': 'repository-cryptographic-phases', 'files': files})
            seen = []
            def attest(staged, *_):
                seen.append({path.relative_to(staged).as_posix() for path in staged.rglob('*') if path.is_file()})
                return {'status': 'PASS', 'MODELED': True}
            result = b.attest_crypto({'crypto': SimpleNamespace(attest=attest)}, source, request, c.digest(request),
                root / 'unused-output', crypto_root=root / 'crypto-inputs', deadline=time.monotonic() + 20,
                supervise=lambda role, callback, **kw: callback())
            self.assertTrue(result['MODELED']); self.assertEqual(seen, [set(files)])
            self.assertTrue((source / 'extra-authority-file').exists())
    def test_baseline_request_uses_actual_snapshot_build_paths_and_pins(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); controller = SimpleNamespace(native_out=root / 'native', generated=root / 'fixtures',
                source=root / 'source', image=self.job['image_id'], commit=self.job['source_commit'], lock={'source_files': {}})
            def put(path, raw):
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            for name in ('scripts/build/container-entry.sh', 'scripts/integration/fixtures.py'):
                raw = b'# MODELED source ' + name.encode(); put(controller.source / name, raw)
                controller.lock['source_files'][name] = {'sha256': c.digest(raw), 'mode': 0o644}
            lock = b'MODELED package 1-1\n'; inputs = c.encoded({'snapshot_id': 'MODELED-actual-snapshot'})
            put(controller.native_out / 'packages.lock', lock); put(controller.native_out / 'inputs.lock.json', inputs)
            put(controller.native_out / 'bootstrap.json', c.encoded({'image_id': self.job['image_id'],
                'inputs_sha256': c.digest(inputs), 'packages_lock_sha256': c.digest(lock)}))
            fixture = {'source_commit': self.job['recipe_source_commit'], 'packages': {}}
            for name in sorted(b.ORIGINALS):
                archive = name + '-1-1-any.pkg.tar.xz'; payload = b'MODELED archive ' + name.encode()
                diff = b'MODELED diff ' + name.encode(); diff_name = 'actual-diffs/' + name + '.diff'
                fixture['packages'][name] = {'diff': diff_name, 'diff_sha256': c.digest(diff)}
                put(controller.generated / diff_name, diff)
                put(controller.native_out / (name + '-compare.json'), c.encoded({'MODELED': True}))
                for number in (1, 2):
                    source = controller.native_out / f'{name}-{number}'
                    declared = {'expected-packages.lock': lock, 'artifacts/' + archive: payload}
                    recipes = {'LICENSE': b'MODELED MIT license'}
                    for relative, raw in declared.items(): put(source / relative, raw)
                    for relative, raw in recipes.items(): put(source / 'inputs' / relative, raw)
                    put(source / 'provenance.json', c.encoded({'status': 'built-package-static-pass', 'mode': 'native',
                        'image_id': self.job['image_id'], 'files': {key: c.digest(raw) for key, raw in declared.items()},
                        'recipe_inputs': {key: c.digest(raw) for key, raw in recipes.items()}, 'artifacts': {archive: c.digest(payload)}}))
            put(controller.generated / 'fixture-manifest.json', c.encoded(fixture))
            def assemble():
                return b.baseline_provenance(controller, self.job, repository_url='https://github.com/MODELED/project',
                                             deadline=time.monotonic() + 20)
            result = assemble(); request = result['request']
            self.assertEqual(result['status'], 'PENDING'); self.assertEqual(request['snapshot_id'], 'MODELED-actual-snapshot')
            self.assertEqual(result['file_count'], len(result['selections']))
            self.assertIn(request['packages_lock'], request['files'])
            for row in request['packages']:
                self.assertTrue(row['archive'].startswith(row['first'] + '/artifacts/'))
                self.assertNotEqual(row['first'], row['second'])
            put(controller.native_out / 'inputs.lock.json', c.encoded({'snapshot_id': 'foreign-snapshot'}))
            with self.assertRaises(c.Refused): assemble()
    def test_create_approval_binds_only_exact_original_transformation(self):
        from test_launch import LaunchTests
        case = LaunchTests(); case.setUp()
        try:
            end = time.monotonic() + 20
            pending = b.Pending(case.private, b'# MODELED observer\n', c.digest(b'# MODELED observer\n'), job_deadline=end)
            bindings = []; pending.transport = SimpleNamespace(bind=lambda *args: bindings.append(args))
            pending.resolve(case.command)
            self.assertEqual(bindings, [('cachy-asahi-repository-' + case.contract['nonce'], case.contract['image_id'])])
            cid = case.private / ('launch-' + case.contract['nonce']) / 'cid'
            command = ['docker', 'create', '-i', '--cidfile', str(cid)] + case.command[2:]
            index = command.index('/runner/repository.py')
            command[index:index+1] = ['-I', '/runner/producer.py', '--handoff-deadline', repr(end)]
            self.assertEqual(pending.approve_create(command)['cidfile'], str(cid))
            for old, new in [('--network=none', '--network=host'), ('--memory=8g', '--memory=16g'),
                             (str(cid), str(cid.parent / 'foreign'))]:
                altered = list(command); altered[altered.index(old)] = new
                with self.subTest(old=old), self.assertRaises(c.Refused): pending.approve_create(altered)
            command[-1] = '--foreign'
            with self.assertRaises(c.Refused): pending.approve_create(command)
        finally:
            case.doCleanups()
    def test_schema2_complete_draft_retains_external_authority_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); files = {}
            def put(name, raw):
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
                files[name] = {'sha256': c.digest(raw), 'bytes': len(raw)}
            for name in ('native/bootstrap.json', 'native/packages.lock', 'native/inputs.lock.json', 'native/runner.json',
                         'source/fixture-manifest.json', 'source/integration.lock.json', 'source/recipes.lock.json',
                         'projected/result.json', 'projected/projection.json', 'public/manifest.json',
                         'raw/container-cleanup.json', 'raw/reset.json'):
                put(name, c.encoded({'MODELED': name}))
            self.records['native_result']['integration_sha256'] = files['source/integration.lock.json']['sha256']
            for role, name in [('aggregate', 'aggregate'), ('public_acceptance', 'public-acceptance'), ('native_result', 'native-result')]:
                put('terminal/' + name + '.json', c.encoded(self.records[role]))
            baseline = []
            for name in sorted(b.ORIGINALS):
                archive = name + '-1-1-any.pkg.tar.xz'; public = 'public/TEST-repositories/baseline-A/' + archive
                put(public, b'MODELED archive ' + name.encode())
                baseline.append({'name': name, 'archive': 'baseline/' + archive, 'version': '1-1', 'sha256': files[public]['sha256']})
            put('raw/contract.json', c.encoded({'baseline': baseline}))
            repository = {'status': 'PASS', 'source_commit': self.job['source_commit'],
                          'commands': [{'argv': ['MODELED']}], 'sync_cache_reset': {'receipt': 'reset.json'}}
            put('raw/result.json', c.encoded(repository))
            previous = '0' * 64
            for index, row in enumerate(self.checkpoints, 1):
                wire = producer.encode_frame({'MODELED': index}, self.job['nonce'], index, previous)
                frame = producer.parse_frame(wire, nonce=self.job['nonce'], sequence=index, previous_frame_sha256=previous)
                pin = frame['frame_sha256']
                row['sha256'], row['payload_sha256'] = pin, frame['frame']['payload_sha256']; previous = pin
                put(f'custody/checkpoint-{index}.json', wire[len(producer.FRAME_MARKER):])
            self.launched['checkpoints'] = [{'sequence': row['sequence'], 'phase': row['phase'],
                'frame_sha256': row['sha256'], 'payload_sha256': row['payload_sha256']} for row in self.checkpoints]
            put('custody/launch.json', c.encoded(self.launched))
            for role in ('request', 'receipt'):
                put('crypto/' + role + '.json', c.encoded({'schema_version': 2, 'purpose': 'repository-cryptographic-phases',
                    **{key: self.job[key] for key in ('source_commit', 'run_id', 'nonce', 'image_id')}, 'status': 'PASS'}))
            def assemble():
                return b.authority_candidate(root, files, self.job, records=self.records, launch_record=self.launched,
                    checkpoints=self.checkpoints, native_exit=0, crypto_request_ref='crypto/request.json',
                    crypto_receipt_ref='crypto/receipt.json', deadline=time.monotonic() + 20)
            result = assemble()
            self.assertEqual(result['status'], 'PENDING-external-authority')
            self.assertEqual(result['authority']['status'], result['authority']['crypto']['status'], 'PENDING')
            self.assertEqual(set(result['authority']['refs']), b.REFS)
            self.assertEqual(len(result['authority']['archives']), 4)
            self.assertEqual(result['file_count'], len(files))
            repository['commands'][0].pop('argv'); put('raw/result.json', c.encoded(repository))
            with self.assertRaises(c.Refused): assemble()
            repository['commands'][0]['argv'] = ['MODELED']; put('raw/result.json', c.encoded(repository))
            files.pop('terminal/native-result.json')
            with self.assertRaises(c.Refused): assemble()
    def test_authority_selection_retains_all_fifteen_alias_names_and_index(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); controller = SimpleNamespace(work=root / 'work', public=root / 'public',
                native_out=root / 'native', generated=root / 'fixtures', source=root / 'source', lock={'MODELED': True})
            def put(path, data):
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            raw = controller.work / 'repository-raw'; projected = controller.public / 'repository'
            commands, evidence, expected, operations = [], {}, set(), {}
            for number, (label, alias) in enumerate(b.LEGACY_LOGS.items()):
                name = f'{number:03d}-{label}.txt'; data = b'MODELED ' + label.encode()
                public_name = f'{number:03d}-{alias}.txt'
                commands.append({'label': label, 'log': name, 'argv': ['MODELED']})
                evidence[name] = c.digest(data); put(raw / name, data); put(projected / public_name, data)
                expected.add('projected/' + public_name)
            for number in range(9):
                name, alias = f'operation-{number}.txt', f'public-operation-{number}.txt'; data = name.encode()
                evidence[name] = c.digest(data); put(raw / name, data); put(projected / alias, data)
                operations[name] = {'public_path': alias, 'original_sha256': c.digest(data),
                                    'public_sha256': c.digest(data), 'bytes': len(data)}
                expected.add('projected/' + alias)
            put(raw / 'result.json', c.encoded({'status': 'PASS', 'test_private_state_removed': True,
                'commands': commands, 'cases': [{} for _ in range(11)], 'evidence_sha256': evidence}))
            put(projected / 'result.json', c.encoded({'evidence_sha256': evidence}))
            put(projected / 'repository-operation-aliases.json', c.encoded({'schema_version': 1,
                'purpose': 'validated-repository-operation-aliases', 'generic_content_guard': 'UNCHANGED',
                'original_bytes_preserved': True, 'files': operations}))
            manifest = controller.public / 'repository-public-artifacts/public-artifact-manifest.json'
            put(manifest, c.encoded({'files': {}}))
            lock = root / 'integration-lock.json'; put(lock, c.encoded(controller.lock))
            def select():
                return b.authority_selections(controller, integration_lock_path=lock,
                    integration_lock_pin=c.digest(lock.read_bytes()), deadline=time.monotonic() + 20)
            selections = select()
            self.assertTrue(expected <= set(selections))
            self.assertIn('projected/repository-operation-aliases.json', selections)
            (projected / 'public-operation-8.txt').unlink()
            with self.assertRaises(OSError): select()


if __name__ == '__main__': unittest.main()
