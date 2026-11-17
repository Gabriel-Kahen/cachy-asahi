#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fenced MODEL controls. Actual773 material bodies are intentionally absent."""
import copy
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {
            'os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock'}:
        raise AssertionError('MODEL forbids operational event: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


N = load('audio_hosted_inputs_model', HERE / 'inputs.py')
F = load('audio_actual_input_fixture', ROOT / 'scripts/ci/bankstown-qt3-native-source/test_inputs.py')


class InputControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='qt3-hosted-inputs-MODEL-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.f = F.Fixture(self.path)
        self.f.copy(N.MEMBER)
        fingerprint = json.loads((self.f.root / 'MODEL/base-lock.json').read_bytes())['signer_fingerprint']
        self.f.request['official_trust'] = dict(fingerprint=fingerprint,
            public_key=self.f.put('MODEL/public-certificate.DATA', b'MODEL PUBLIC DATA ONLY\n'),
            Root_admission=self.f.put('MODEL/Root-decision.DATA', b'MODEL UNISSUED DATA ONLY\n'))
        rows = {str(p.relative_to(self.f.root)): dict(N.pin(p.read_bytes()), mode=0o644)
                for p in self.f.root.rglob('*') if p.is_file()}
        mapping = N.encoded(dict(schema=1, kind='BANKSTOWN_QT3_CLOSED_NATIVE_SOURCE_V1',
            operation=N.OPERATION, files=rows, actual=dict(source=None, ref=None, run=None, job=None)))
        for name in ('source-map.json', 'source.lock.json'):
            (self.f.root / name).write_bytes(mapping)
        self.d = dict(schema=1, kind='ROOT_DELEGATED_BANKSTOWN_QT3_PRIVATE_TEST_V1', stage='qt3',
            capability=dict(operation=N.OPERATION), binding=dict(source_lock=N.pin(mapping)),
            inputs_pin=N.owner_inputs_pin(self.f.request))
        self.value = dict(schema=1, kind=N.KIND, owner_inputs=self.f.request,
                          staged_refs=N.references(self.f.request))

    def validate(self, value=None, delegation=None):
        return N.validate_hosted_inputs_v3(inputs=self.value if value is None else value,
            delegation=self.d if delegation is None else delegation, source_root=self.f.root)

    def provider(self):
        return dict(api='BASE349_CACHE_REFERENCES_V3', kind='VERIFIED_BASE349_CACHE_REFERENCES_DATA_V3',
            missing_materials={}, complete=True, verified_files=517, actual=dict(source=None, Root_trust=None),
            **{k: self.f.request[k] for k in ('base_lock', 'bootstrap_profile', 'base_materials',
                                            'supplemental_materials', 'keyring_materials')})

    def assemble(self, **extra):
        return N.assemble_inputs(complete_reference_result=self.provider(), source_root=self.f.root,
            delegation=self.d, **{k: self.f.request[k] for k in ('baseline_inventory', 'candidate_materials',
                                                             'catalog', 'official_trust')}, **extra)

    def test_actual_plan_and_complete_unique_reference_selection(self):
        result = self.validate()
        self.assertEqual(set(result), {'valid', 'required_refs'})
        self.assertIs(result['valid'], True)
        self.assertEqual(result['required_refs'], self.value['staged_refs'])
        self.assertEqual(len(result['required_refs']), 779)
        self.assertEqual([r['path'] for r in result['required_refs']], sorted({r['path'] for r in result['required_refs']}))
        selected = {k: len(self.f.request[k]) for k in ('base_materials', 'supplemental_materials',
                                                     'keyring_materials', 'candidate_materials')}
        self.assertEqual(selected, dict(base_materials=498, supplemental_materials=16,
                                       keyring_materials=3, candidate_materials=256))
        self.assertEqual(sum(r['bytes'] == 0 for r in result['required_refs']), 1)
        # Semantic validation deliberately did not invent or open absent archives.
        self.assertFalse(Path(next(iter(self.f.request['candidate_materials'].values()))['path']).exists())

    def test_old_schema_kind_nested_owner_and_extra_outer_refuse(self):
        for mutate in (lambda v: v.update(schema=3), lambda v: v.update(kind='ROOT_STAGED_CURRENT_INPUTS_V3'),
                       lambda v: v.update(owner_inputs={'image_inputs': {}, 'stage_inputs': {}}),
                       lambda v: v.update(Root_approved=True)):
            value = copy.deepcopy(self.value)
            mutate(value)
            with self.assertRaises(ValueError):
                self.validate(value)

    def test_root_owner_pin_missing_key_and_extra_key_refuse(self):
        changed = copy.deepcopy(self.d)
        changed['inputs_pin']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'ROOT_SELECTED_AUDIO_OWNER_INPUTS_PIN'):
            self.validate(delegation=changed)
        for mutate in (lambda v: v['owner_inputs'].pop('catalog'),
                       lambda v: v['owner_inputs'].update(image_inputs={})):
            value = copy.deepcopy(self.value)
            mutate(value)
            with self.assertRaisesRegex(ValueError, 'EXACT_NINE'):
                self.validate(value)

    def test_missing_extra_reordered_duplicate_or_changed_staged_ref_refuses(self):
        for change in ('missing', 'extra', 'order', 'duplicate', 'pin'):
            value = copy.deepcopy(self.value)
            refs = value['staged_refs']
            if change == 'missing':
                refs.pop()
            elif change == 'extra':
                refs.append(dict(path=str(self.path / 'extra.DATA'), bytes=1, sha256='0' * 64))
            elif change == 'order':
                refs.reverse()
            elif change == 'duplicate':
                refs.append(copy.deepcopy(refs[0]))
            else:
                refs[0]['sha256'] = '0' * 64
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'EXACT_ALL_SELECTED'):
                self.validate(value)

    def test_candidate_pin_mutation_refuses_real_plan_even_with_new_owner_pin(self):
        value = copy.deepcopy(self.value)
        next(iter(value['owner_inputs']['candidate_materials'].values()))['sha256'] = '0' * 64
        delegation = dict(self.d, inputs_pin=N.owner_inputs_pin(value['owner_inputs']))
        value['staged_refs'] = N.references(value['owner_inputs'])
        with self.assertRaisesRegex(ValueError, 'EXACT_CANDIDATE_WHOLE_PIN'):
            self.validate(value, delegation)

    def test_frozen_audio_code_or_source_map_tamper_refuses(self):
        (self.f.root / N.MEMBER).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'ORDINARY_AUDIO_INPUT_FILE|STABLE_WHOLE_AUDIO_INPUT'):
            self.validate()

    def test_map_alias_mode_and_nonnull_or_nondict_actual_refuse(self):
        alias = self.f.root / 'source.lock.json'
        alias.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'EXACT_SOURCE_MAP_ALIAS_MODE'):
            self.validate()
        alias.chmod(0o644)
        original = json.loads(alias.read_bytes())
        for actual in ([None], {'source': 'MODEL invented selection'}):
            mapping = dict(original, actual=actual)
            raw = N.encoded(mapping)
            for name in ('source-map.json', 'source.lock.json'):
                (self.f.root / name).write_bytes(raw)
            delegation = copy.deepcopy(self.d)
            delegation['binding']['source_lock'] = N.pin(raw)
            with self.subTest(actual=actual), self.assertRaisesRegex(ValueError, 'CLOSED_UNISSUED_AUDIO_SOURCE_MAP'):
                self.validate(delegation=delegation)

    def test_real_empty_metadata_file_is_valid_whole_data_not_omitted(self):
        path = self.path / 'MODEL-empty-revoked.DATA'
        path.write_bytes(b'')
        row = dict(path=str(path), **N.pin(b''))
        self.assertEqual(N.read_reference(row, 1024), b'')
        self.assertEqual(N.references({'keyring_materials': {'MODEL-empty': row}}), [row])

    def test_traversal_symlink_and_private_domains_refuse_before_plan(self):
        for path in (str(self.path / 'a/../b'), str(self.path / '.ssh/key'), str(self.path / '.gnupg/data')):
            value = copy.deepcopy(self.value)
            value['owner_inputs']['catalog']['path'] = path
            with self.assertRaises(ValueError):
                self.validate(value)
        alias = self.path / 'alias.DATA'
        alias.symlink_to(self.f.request['catalog']['path'])
        value = copy.deepcopy(self.value)
        value['owner_inputs']['catalog']['path'] = str(alias)
        with self.assertRaisesRegex(ValueError, 'UNALIASED_AUDIO'):
            self.validate(value)

    def test_conflicting_duplicate_ref_and_bool_size_refuse(self):
        for change in ('conflict', 'bool'):
            value = copy.deepcopy(self.value)
            trust = value['owner_inputs']['official_trust']
            if change == 'conflict':
                trust['public_key']['path'] = trust['Root_admission']['path']
            else:
                trust['public_key']['bytes'] = True
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'CONFLICTING_AUDIO_REFERENCE|WHOLE_AUDIO_FILE_REFERENCE'):
                self.validate(value)

    def test_actual_assembly_cannot_treat_absent773_as_verified(self):
        with self.assertRaises(FileNotFoundError):
            self.assemble()

    def test_real_provider_api_and_true_verification_dispatch_with_model_body_boundary(self):
        # Only delivered archive bodies are absent MODEL operands. The actual
        # provider selector and actual complete semantic plan still run.
        I, rows = N.source_inputs(self.f.root, self.d)
        original = I.plan_inputs
        flags, body_reads = [], []
        def model_plan(**kwargs):
            flags.append(kwargs['verify_archives'])
            return original(**dict(kwargs, verify_archives=False))
        output = self.path / 'wrapper.DATA.json'
        with patch.object(N, 'source_inputs', return_value=(I, rows)), \
             patch.object(I, 'plan_inputs', side_effect=model_plan), \
             patch.object(N, 'read_reference', side_effect=lambda row, cap, collect=True: body_reads.append((row, collect))):
            result = self.assemble(output=output)
        self.assertEqual(flags, [True])
        self.assertEqual(len(body_reads), 779)
        self.assertTrue(all(collect is False for _, collect in body_reads))
        self.assertEqual(json.loads(output.read_bytes()), result)
        self.assertEqual(set(result), {'schema', 'kind', 'owner_inputs', 'staged_refs'})
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(N.owner_inputs_pin(result['owner_inputs']), self.d['inputs_pin'])

    def test_incomplete_provider_result_never_promoted(self):
        result = self.provider()
        result['missing_materials'] = {'rootfs': 'MODEL missing'}
        with patch.object(N, 'source_inputs', return_value=N.source_inputs(self.f.root, self.d)):
            I, _ = N.source_inputs(self.f.root, self.d)
            with self.assertRaises(ValueError):
                I.provider_fields(result, source_root=self.f.root)


if __name__ == '__main__':
    unittest.main()
