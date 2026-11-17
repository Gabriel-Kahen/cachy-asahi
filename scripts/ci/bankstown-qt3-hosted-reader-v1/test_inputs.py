#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Real maintained metadata; explicit absent773 MODEL body boundary, no actors."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ATTEMPTS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {
            'os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock'}:
        ATTEMPTS.append(event)
        raise AssertionError('NO_OPERATIONAL_ROLE: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R = load('audio_reader_inputs', HERE / 'reader.py')
F = load('audio_reader_existing_input_models', ROOT / 'scripts/ci/bankstown-qt3-hosted-v1/test_inputs.py')


class Controls(unittest.TestCase):
    def setUp(self):
        self.model = F.InputControls('test_actual_plan_and_complete_unique_reference_selection')
        self.model.setUp()
        self.addCleanup(self.model.doCleanups)
        self.root = self.model.f.root
        self.r = dict(staged_inputs=self.put('wrapper.json', self.model.value), staged_root=str(self.root))
        self.provider = self.put('provider.json', self.model.provider())

    def put(self, name, value):
        path = self.model.path / name
        raw = R.encoded(value)
        path.write_bytes(raw)
        return dict(path=str(path), **R.pin(raw))

    def complete(self, **kw):
        args = dict(source_root=self.root, request=self.r, delegation=self.model.d, provider=self.provider)
        args.update(kw)
        # This seam alone omits the separately tested closed Source admission;
        # actual MODEL metadata/helpers/whole input-request pins remain real.
        with patch.object(R.C, 'source_rows', return_value=self.model.f.rows):
            return R.complete_inputs(**args)

    def test_missing_genuine773_refuses_before_any_intake_credit(self):
        with self.assertRaises(FileNotFoundError), patch.object(R.L.H, 'checked_inputs') as checked:
            self.complete()
        checked.assert_not_called()

    def test_model_composition_requires_true_archive_flag_and_all779_intake(self):
        flags = []
        original = R.I.plan_inputs

        def absent_body_boundary(**kw):
            flags.append(kw['verify_archives'])
            return original(**dict(kw, verify_archives=False))

        # Only absent archive bodies/intake are modeled. Provider selection,
        # complete plan, public trust identity and all779 references are real.
        with patch.object(R.I, 'plan_inputs', side_effect=absent_body_boundary), \
             patch.object(R.L.H, 'checked_inputs', return_value=(self.model.f.request, {'files': 779, 'bytes': 1})) as intake:
            envelope, result = self.complete()
        self.assertEqual(flags, [True])
        self.assertEqual(envelope, self.model.value)
        self.assertEqual(result['files'], 779)
        self.assertEqual(intake.call_args.args[:3], (self.r, self.model.d, self.root))
        self.assertIs(intake.call_args.args[3], R.C)

    def test_partial_provider_never_reaches_archive_or_intake_phase(self):
        provider = self.model.provider()
        provider['complete'] = False
        ref = self.put('partial-provider.json', provider)
        with patch.object(R.I, 'plan_inputs') as plan, self.assertRaises(ValueError):
            self.complete(provider=ref)
        plan.assert_not_called()

    def test_changed_provider_roles_refuse_even_with_whole_rehashed_json(self):
        provider = self.model.provider()
        provider['base_lock'] = dict(provider['base_lock'], sha256='0' * 64)
        ref = self.put('other-provider.json', provider)
        with self.assertRaisesRegex(ValueError, 'SAME_COMPLETE517_PROVIDER_FIELDS'):
            self.complete(provider=ref)

    def test_missing_duplicate_staged_refs_and_changed_candidate_whole_pin_refuse(self):
        for mutation in ('missing', 'duplicate', 'candidate'):
            value = copy.deepcopy(self.model.value)
            if mutation == 'missing':
                value['staged_refs'].pop()
            elif mutation == 'duplicate':
                value['staged_refs'].append(value['staged_refs'][0])
            else:
                next(iter(value['owner_inputs']['candidate_materials'].values()))['sha256'] = '0' * 64
            r = dict(self.r, staged_inputs=self.put(mutation + '.json', value))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.complete(request=r)

    def test_real_whole_selected_json_refuses_body_change_duplicate_and_noncanonical(self):
        path = Path(self.provider['path'])
        for raw in (b'changed', b'{"x":1,"x":2}', b'{"x":1}'):
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                R.selected(dict(path=str(path), **R.pin(raw)))

    def test_executing_reader_must_equal_external_whole_selection_before_result(self):
        with self.assertRaisesRegex(ValueError, 'EXTERNALLY_SELECTED_EXECUTING_READER'):
            R.qualify_result({}, {}, reader_pin=dict(bytes=1, sha256='0' * 64))

    def test_result_helper_is_whole_pinned_before_import(self):
        helper = self.model.path / 'result.py'
        helper.write_bytes(b'raise AssertionError("UNREVIEWED HELPER")\n')
        with patch.object(R, 'HERE', self.model.path), patch.object(R, 'load') as imported, \
             self.assertRaises(ValueError):
            R.qualify_result({}, {}, reader_pin=R.pin(Path(R.__file__).read_bytes()))
        imported.assert_not_called()

    def workflow(self):
        source = self.model.path / 'MODEL-dispatch-tree'
        path = source / R.WORKFLOW
        path.parent.mkdir(parents=True)
        path.write_bytes((ROOT / R.WORKFLOW).read_bytes())
        descriptor = dict(path=str(path), **R.pin(path.read_bytes()))
        branch = 'refs/heads/codex/MODEL-audio'
        registration = dict(id=123, ref='Gabriel-Kahen/cachy-asahi/' + R.WORKFLOW + '@' + branch, sha='b' * 40)
        delegation = dict(binding=dict(ref=branch), hosted=dict(repository='Gabriel-Kahen/cachy-asahi',
            job_key='audio', job_name='bankstown-qt3-hosted-v1', workflow_ref=registration['ref'], workflow_sha=registration['sha']))
        return source, descriptor, delegation, registration

    def test_model_workflow_join_and_missing_dispatch_leaf(self):
        source, ref, d, registration = self.workflow()
        R.workflow_binding(source, d, ref, registration)
        # The body/registration remain selected outside Source; they cannot
        # replace the missing leaf at the exact dispatch ref (fixed78's gap).
        external = self.model.path / 'selected-Main-workflow.yml'
        external.write_bytes(Path(ref['path']).read_bytes())
        Path(ref['path']).unlink()
        ref['path'] = str(external)
        with self.assertRaisesRegex(ValueError, 'OMITS_WORKFLOW_AT_DISPATCH_REF'):
            R.workflow_binding(source, d, ref, registration)

    def test_wrong_registration_workflow_token_policy_and_job_refuse(self):
        source, ref, d, registration = self.workflow()
        for key, value in (('id', True), ('ref', 'wrong'), ('sha', 'c' * 40)):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'REGISTRATION'):
                R.workflow_binding(source, d, ref, dict(registration, **{key: value}))
        changed = copy.deepcopy(d)
        changed['hosted']['job_name'] = 'other'
        with self.assertRaises(ValueError):
            R.workflow_binding(source, changed, ref, registration)
        path = Path(ref['path'])
        path.write_bytes(path.read_bytes().replace(b'actions: read', b'actions: write'))
        with self.assertRaisesRegex(ValueError, 'TOKEN_FREE_READ_ONLY_WORKFLOW'):
            R.workflow_binding(source, d, dict(ref, **R.pin(path.read_bytes())), registration)

    def test_no_actual_actor_attempt(self):
        self.assertEqual(ATTEMPTS, [])


if __name__ == '__main__':
    unittest.main()
