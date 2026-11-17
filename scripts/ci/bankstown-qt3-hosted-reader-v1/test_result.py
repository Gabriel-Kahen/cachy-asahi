# SPDX-License-Identifier: MIT
"""Internal MODEL composition controls; no dispatchable Source or native claim.

Real file/reference/image/receipt/inventory/admission/retirement predicates run.
The expected477 pin is explicitly modeled. Complete retained command/intent and
package replay are mocked boundaries in the broad composition model, and each
boundary separately runs unmocked on the existing synthetic builder fixture.
No fixture establishes a dispatchable Source78 or native identity/acceptance.
"""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock'):
        raise AssertionError('MODEL_RESULT_NO_ACTORS: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audio_result_controls', HERE / 'result.py')
Q = importlib.util.module_from_spec(spec); spec.loader.exec_module(Q)
H, B = Q.H, Q.B
T = Q.load('scripts/port/bankstown-qt3-native-v1/test_admission.py')


class Composition(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='audio-result-MODEL-'); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.source = self.root / 'source'; self.source.mkdir()
        self.materialized = self.root / 'image-root'; self.materialized.mkdir()
        self.now = 1000.0; self.pin = H.pin(b'MODEL_READER'); nonce = 'a' * 64
        binding = dict(source='b' * 40, ref='refs/heads/codex/MODEL', run='123', job='456', attempt=1, source_lock=H.pin(b'MODEL_SOURCE78_MAP'))
        context = dict(binding=binding, nonce=nonce, policy_pin=H.pin(b'MODEL_POLICY'), observed_epoch=110)
        descriptor = lambda body: dict(member='MODEL/' + body.decode(), **H.pin(body))
        delegation = dict(programs={k: descriptor(k.encode()) for k in ('owner', 'image_executor', 'owned_process')}, expires_epoch=200)
        request = dict(delegation_pin=H.pin(b'MODEL_DELEGATION'), staged_root=str(self.root / 'retired-input-mount'))
        self.state = dict(root=self.source, context=context, delegation=delegation, request=request,
                          inputs={'MODEL_ONLY': True}, policy={'MODEL_ONLY': True})
        protected = Q.I.inventory((Q.MAIN / 'scripts/ci/bankstown-qt3-native-profile-v1/expected349.lock').read_bytes(), 349)
        added = {f'model-added-{i:03}': '0.0-MODEL' for i in range(126)} | {'qt6-base': '6.12.0-3', 'rust': '1:1.99.0-1'}
        selected = dict(list(sorted(protected.items()))[:205], **added)
        catalog = H.encoded({'packages': {n: {'metadata': {'/.PKGINFO': {'pkgname': [n], 'pkgver': [v]}}} for n, v in selected.items()}})
        inventory = ''.join(n + ' ' + v + '\n' for n, v in sorted(dict(protected, **added).items())).encode()
        inventory_ref = self.ref('inventory.lock', inventory); catalog_ref = self.ref('catalog.json', catalog)
        self.state['inputs'] = dict(owner_inputs=dict(catalog=catalog_ref))
        self.state['policy'] = dict(image_endpoint_template='unix:///MODEL/{nonce}/docker.sock')
        for target in (Q.H, Q.R):
            p = patch.object(target, 'EXPECTED477', H.pin(inventory)); p.start(); self.addCleanup(p.stop)
        image = dict(schema=1, kind='BANKSTOWN_QT3_IMAGE_DATA_V1', status='PASS_PRIVATE_IMAGE_DATA_ONLY',
            source=dict(root=str(self.source), commit=binding['source'], ref=binding['ref']), binding=binding, nonce=nonce,
            delegation_pin=request['delegation_pin'], catalog=catalog_ref,
            image=dict(id='sha256:' + 'c' * 64, inventory=inventory_ref, protected349=H.PROTECTED349),
            filesystem=dict(root=str(self.materialized), image_id='sha256:' + 'c' * 64, archive=self.ref('image.tar', b'MODEL_NOT_AN_IMAGE')),
            executor=dict(code_pin=H.pin(b'image_executor'), engine_id='MODEL_ENGINE', docker_endpoint='unix:///MODEL/' + nonce + '/docker.sock', owner_pid=123, daemon_pid=456),
            lifetime=dict(observed_monotonic=self.now - 90, work_deadline_monotonic=self.now + 1000), legal='HELD', key_freshness='HELD', **H.FINAL)
        trial = T.model(); trial.update(source={k: image['source'][k] for k in ('commit', 'ref')},
            catalog=H.pin(catalog), image=dict(id=image['image']['id'], inventory=H.pin(inventory)),
            owned_executor={k: image['executor'][k] for k in ('code_pin', 'docker_endpoint', 'engine_id')})
        trial['materials']['model/catalog.json'] = H.pin(catalog); trial['materials']['model/inventory.lock'] = H.pin(inventory)
        raw_admission = H.encoded(trial)
        profile = dict(schema=1, purpose='bankstown-1.1.0-5-native-toolchain', compiler_version='1.99.0', target='aarch64-unknown-linux-gnu',
            tools=trial['tool_paths'], files=trial['selected_files'], admission_pin=H.pin(raw_admission), catalog_pin=trial['catalog'],
            image=trial['image'], legal='HELD', key_freshness='HELD', **B.FINAL)
        raw_profile = H.encoded(profile)
        joins = Q.I.check(inventory, (Q.MAIN / 'scripts/ci/bankstown-qt3-native-profile-v1/expected349.lock').read_bytes(), catalog)
        profile_receipt = dict(schema=1, kind='BANKSTOWN_QT3_PROFILE_DATA_V1', status='PASS_PASSIVE_PROFILE_DATA_ONLY',
            image_receipt=H.pin(H.encoded(image)), admission=H.pin(raw_admission),
            **{k: image[k] for k in ('source', 'binding', 'nonce', 'delegation_pin', 'image', 'catalog', 'filesystem', 'executor', 'lifetime')},
            inventory_joins=joins, frozen_consumers={n: dict(bytes=v[0], sha256=v[1]) for n, v in Q.P.PINS.items()},
            profile=dict(path=str(self.root / 'profile'), **H.pin(raw_profile)), legal='HELD', key_freshness='HELD', **H.FINAL)
        commands = [dict(step=step, argv=['/usr/bin/docker', '--host=' + image['executor']['docker_endpoint'], 'MODEL'], exit=0,
            supervision=dict(exit=0, reaped=True, ownership='REAPED', group_census='EMPTY_TWICE', output_complete=True,
                             timeout=False, signals=[], error=None)) for step in Q.STEPS]
        build = dict(schema=1, status='PASS_PRIVATE_TEST_BUILD_DATA_ONLY', admission_pin=H.pin(raw_admission), profile_pin=H.pin(raw_profile),
            source=trial['source'], image=trial['image'], commands=commands, artifact={'MODEL_ONLY': 'NO_PACKAGE_REPLAY'},
            owned_container_absence_verified=True, legal='HELD', key_freshness='HELD', hardware_status='NOT RUN', **B.FINAL)
        builder_raw = (Q.MAIN / Q.O.BUILDER_MEMBER).read_bytes()
        projection = dict(original=Q.O.BUILDER_PIN, projected=H.pin(builder_raw.replace(Q.O.DOCKER_BEFORE, Q.O.DOCKER_AFTER)),
                          seam='one Docker --host=<endpoint> argument; no receipt rewriting')
        pipeline = dict(schema=1, kind='BANKSTOWN_QT3_OWNED_PIPELINE_DATA_V1', completed=True, binding=binding, nonce=nonce,
            image_receipt=H.pin(H.encoded(image)), profile_receipt=H.pin(H.encoded(profile_receipt)), profile=profile_receipt['profile'],
            builder_projection=projection, private_build_status=build['status'], image_lifetime='EPHEMERAL_SAME_OWNED_DAEMON_UNTIL_CONTROLLER_RETIREMENT',
            legal='HELD', key_freshness='HELD', **H.FINAL)
        facts = dict(api='CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3', binding=binding, nonce=nonce, stage='qt3', native_architecture='aarch64',
            code_pin=image['executor']['code_pin'], engine_id=image['executor']['engine_id'], docker_endpoint=image['executor']['docker_endpoint'], uid=1000, gid=1000,
            owner_domain=dict(pid=123), daemon_domain=dict(pid=456), domain_policy_pin=context['policy_pin'],
            supervision_program_pin=H.pin(b'owned_process'), daemon_pidfd_held=True, whole_owner_deadline_enforced=True,
            daemon_deadline_enforced=True, exclusive_daemon=True, **H.FINAL)
        owner = dict(status='DELEGATED_OWNER_RETURNED_DATA_ONLY', binding=binding, result=pipeline, executor_facts=facts, **H.FINAL)
        executor = dict(status='DELEGATED_OWNED_STAGE_RETIRED_DATA_ONLY', binding=binding, owner=owner,
            delegation_pin=request['delegation_pin'], policy_pin=context['policy_pin'], cleanup=dict(errors=[], owned_storage_absent=True,
            services={role: dict(unit='cachy-current-' + nonce + '-' + role + '.service', empty_twice=True, pidfd_exited=True,
                natural=True, owner_residue_before_stop=False) for role in ('owner', 'daemon')}), **H.FINAL)
        launcher = dict(status='DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY', binding=binding, request_pin=H.pin(H.encoded(request)),
            cleanup=dict(owned_storage_absent=True, error_count=0), scope_absence=dict(scope='cachy-current-controller-' + nonce + '.scope', empty_twice=True),
            controller_retirement=dict(exit=0, group_census='EMPTY_TWICE', reaped=True, natural=True),
            retained_input_custody=dict(path=request['staged_root'], mount_id='123', retirement_owner='Root', retirement_observed_here=False, Root_acceptance=None), **H.FINAL)
        self.data = dict(image=image, profile=profile, profile_receipt=profile_receipt, admission=trial, build=build,
                         pipeline=pipeline, owner=owner, executor=executor, launcher=launcher)
        self.observation = dict(schema=1, kind='BANKSTOWN_QT3_RESULT_OBSERVATION_V1', binding=binding, nonce=nonce,
            request_pin=H.pin(H.encoded(request)), context_pin=H.pin(H.encoded(context)), source_lock=binding['source_lock'],
            reader_pin=self.pin, owner_pin=H.pin(b'owner'), record_pins={}, expected_image=trial['image'], expected_executor=image['executor'],
            launcher_window=dict(started_monotonic=self.now - 100, finished_monotonic=self.now - 10), image_observed_monotonic=self.now - 90,
            stage_window=dict(profile_verified_monotonic=self.now - 80, build_started_monotonic=self.now - 70,
                              build_finished_monotonic=self.now - 20, admission_observed_epoch=120), build_root=str(self.root / 'complete-build-MODEL'),
            retained_input_retirement=dict(path=request['staged_root'], mount_id='123', absent_twice=True, observed_monotonic=self.now - 5), **H.FINAL)

    def ref(self, name, raw):
        path = self.root / name; path.write_bytes(raw); return dict(path=str(path), **H.pin(raw))

    def records(self):
        records = {k: self.ref(k, H.encoded(v)) for k, v in self.data.items()}
        self.observation['record_pins'] = {k: Q.whole(v) for k, v in records.items()}
        records['observation'] = self.ref('observation', H.encoded(self.observation)); return records

    def check(self):
        with patch.object(time, 'monotonic', return_value=self.now), patch.object(Q, 'retained_commands') as commands, patch.object(Q, 'static_artifacts', return_value=self.data['build']['artifact']) as static:
            result = Q.qualify(self.state, self.records(), reader_pin=self.pin, now_monotonic=self.now)
            commands.assert_called_once(); static.assert_called_once(); return result

    def test_model_composition_keeps_all_holds_and_calls_static_boundary(self):
        # A fresh runner may have less than100 seconds of monotonic uptime.
        for host_uptime in (0.01, 50.0, 1e9):
            with self.subTest(host_uptime=host_uptime), patch.object(time, 'monotonic', return_value=host_uptime):
                result = self.check(); self.assertFalse(result['native_acceptance']); self.assertEqual(result['M2'], 'NOT_RUN')
                self.assertEqual(result['inventory_joins']['inventory_count'], 477); self.assertIsNone(result['Root_final_acceptance'])

    def test_actual_file_checks_are_mandatory(self):
        Path(self.data['image']['filesystem']['archive']['path']).unlink()
        with self.assertRaises(OSError): self.check()

    def test_selected_complete773_catalog_and_policy_endpoint_cannot_drift(self):
        self.state['inputs']['owner_inputs']['catalog'] = dict(self.data['image']['catalog'], sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'SELECTED_IMAGE_EXECUTOR'):
            self.check()
        self.state['inputs']['owner_inputs']['catalog'] = self.data['image']['catalog']
        self.state['policy']['image_endpoint_template'] = 'unix:///OTHER/{nonce}/docker.sock'
        with self.assertRaisesRegex(ValueError, 'SELECTED_IMAGE_EXECUTOR'):
            self.check()

    def test_selected_reader_image_executor_and_timing_refuse(self):
        original = copy.deepcopy(self.observation)
        for mutate in (lambda o: o.update(reader_pin=H.pin(b'other')), lambda o: o['expected_image'].update(id='sha256:' + 'd' * 64),
                       lambda o: o['expected_executor'].update(engine_id='STALE'), lambda o: o['launcher_window'].update(started_monotonic=self.now - 5000),
                       lambda o: o['stage_window'].update(build_finished_monotonic=self.now + 1), lambda o: o['retained_input_retirement'].update(absent_twice=False)):
            self.observation = copy.deepcopy(original); mutate(self.observation)
            with self.assertRaises(ValueError): self.check()

    def test_partial_build_controller_and_launcher_refuse(self):
        original = copy.deepcopy(self.data)
        for mutate in (lambda d: d['build']['commands'].pop(), lambda d: d['build'].update(owned_container_absence_verified=False),
                       lambda d: d['owner']['executor_facts'].update(exclusive_daemon=False), lambda d: d['executor']['cleanup']['services'].pop('daemon'),
                       lambda d: d['launcher']['controller_retirement'].update(natural=False), lambda d: d['pipeline'].update(hardware_acceptance=True),
                       lambda d: d['pipeline'].update(schema=True)):
            self.data = copy.deepcopy(original); mutate(self.data)
            with self.assertRaises(ValueError): self.check()

    def test_unmodified_command_natural_guard_refuses_timeout(self):
        self.data['build']['commands'][0]['supervision']['timeout'] = True
        with self.assertRaisesRegex(ValueError, 'NATURAL_COMMAND'): self.check()

    def test_missing_or_expired_image_originals_never_become_historical_pass(self):
        self.data['image']['lifetime']['work_deadline_monotonic'] = self.now - 1
        with self.assertRaises(ValueError): self.check()

    def test_actual_static_adapter_refuses_public_only_root(self):
        public = self.root / 'public-only'; public.mkdir()
        with self.assertRaisesRegex(ValueError, 'COMPLETE_RETAINED_BUILD'):
            Q.static_artifacts(public, self.source, self.data['admission'], H.pin(b'MODEL'), {}, [], self.now + 10)

    def test_actual_static_package_replay_on_complete_modeled_builder_bundle(self):
        # Existing fixture creates a synthetic ARM ELF/package with an inert
        # PKGBUILD, MODEL executor and modeled native identity. It runs no actor.
        F = Q.load('scripts/port/bankstown-qt3-native-v1/test_builder.py')
        base = self.root / 'static-MODEL'; base.mkdir(); f = F.Fixture(base)
        result = f.run(F.Executor(f))
        args = (f.output, f.source, f.d, H.pin(f.profile.read_bytes()), result['artifact'], result['commands'], time.monotonic() + 10)
        self.assertEqual(Q.static_artifacts(*args), result['artifact'])
        (f.output / 'artifacts/generated.SRCINFO').write_bytes(b'pkgname = stale\n')
        with self.assertRaises(ValueError): Q.static_artifacts(*args)

    def retained_fixture(self):
        F = Q.load('scripts/port/bankstown-qt3-native-v1/test_builder.py')
        base = self.root / 'commands-MODEL'; base.mkdir(); f = F.Fixture(base); e = F.Executor(f)
        result = Q.P.decoded(H.encoded(f.run(e)))
        # MODEL exactly the reviewed one-argument Docker endpoint projection.
        for row in result['commands']:
            argv = row['argv']; self.assertEqual(argv[1], '--host')
            row['argv'] = [argv[0], '--host=' + argv[2], *argv[3:]]
        def write():
            (f.output / 'result.json').write_bytes(H.encoded(result))
            (f.output / 'commands/commands.json').write_bytes(H.encoded(result['commands']))
        write(); return f, e, result, write

    def test_actual_retained_intent_command_and_inspect_composition(self):
        f, e, result, write = self.retained_fixture()
        Q.retained_commands(f.output, f.d, result, e.facts, H.pin(f.profile.read_bytes()))
        original = copy.deepcopy(result)
        for mutate in (lambda v: v['intent'].update(image='sha256:' + 'd' * 64), lambda v: v['intent'].update(cpus=99),
                       lambda v: v['intent']['mounts'][0].__setitem__(0, '/foreign'),
                       lambda v: v['commands'][3]['argv'].append('--privileged'),
                       lambda v: v['commands'][0].update(timeout_seconds=999),
                       lambda v: v['commands'][0].update(expected=True),
                       lambda v: v['commands'][9]['argv'].insert(3, '--force')):
            result.clear(); result.update(copy.deepcopy(original)); mutate(result); write()
            with self.assertRaises(ValueError): Q.retained_commands(f.output, f.d, result, e.facts, H.pin(f.profile.read_bytes()))

    def test_actual_retained_daemon_image_and_forced_retirement_refuse(self):
        f, e, result, write = self.retained_fixture()
        original = copy.deepcopy(result)
        for step, mutate in (('daemon', lambda v: v.update(ID='FOREIGN')),
                             ('image', lambda v: v[0].update(Id='sha256:' + 'd' * 64)),
                             ('inspect-terminal', lambda v: v[0]['State'].update(OOMKilled=True)),
                             ('retire-inspect', lambda v: v[0]['State'].update(Running=True))):
            result.clear(); result.update(copy.deepcopy(original))
            path = f.output / 'commands' / (step + '.stdout'); saved = path.read_bytes()
            data = Q.P.decoded(saved); mutate(data); raw = H.encoded(data); path.write_bytes(raw)
            next(row for row in result['commands'] if row['step'] == step)['output_pin'] = H.pin(raw); write()
            with self.assertRaises(ValueError): Q.retained_commands(f.output, f.d, result, e.facts, H.pin(f.profile.read_bytes()))
            path.write_bytes(saved)

    def test_whole_record_pin_and_alias_refuse(self):
        records = self.records(); Path(records['owner']['path']).write_bytes(b'{}')
        with self.assertRaises(ValueError): Q.qualify(self.state, records, reader_pin=self.pin, now_monotonic=self.now)
        records = self.records(); alias = self.root / 'alias'; alias.symlink_to(records['owner']['path'])
        records['owner']['path'] = str(alias)
        with self.assertRaises(ValueError): Q.qualify(self.state, records, reader_pin=self.pin, now_monotonic=self.now)


if __name__ == '__main__': unittest.main()
