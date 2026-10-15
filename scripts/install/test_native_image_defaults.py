"""Image handoff data controls only; no Docker, native actor or system mutation."""
import copy
import importlib.util
import itertools
import json
import os
from pathlib import Path
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

P = load('preflight_image_defaults', Path(os.environ.get('P0_IMAGE_TEST_PREFLIGHT', HERE / 'native_preflight.py')))
R = load('receiver_image_defaults', HERE / 'native_arm_trial.py')


class ImageDefaultsTests(unittest.TestCase):
    def setUp(self):
        self.controller = types.SimpleNamespace(image='sha256:' + 'a' * 64, commit='b' * 40)
        self.inputs, self.packages = b'inputs', b'packages'
        self.receiver = types.SimpleNamespace(input_selection=lambda selected: (P.sha(self.inputs), P.sha(self.packages)))
        self.image = dict(Id=self.controller.image, Architecture='arm64', Os='linux', Config=copy.deepcopy(P.CONFIG))

    def handoff(self, image=None):
        return P.image_handoff([self.image if image is None else image], self.controller,
            self.receiver, self.inputs, self.packages)

    def receiver_check(self, image, expected=None):
        class ReachedNativeGate(Exception): pass
        selection = dict(source_commit=self.controller.commit, image_id=self.controller.image,
            native_handoff_sha256=P.sha(P.encoded(image)), image_config_sha256=P.sha(P.encoded(image['Config'])))
        def require(value, code):
            if code == 'NATIVE_ORDINARY_PARENT': raise ReachedNativeGate()
            if not value: raise ValueError(code)
        with mock.patch.object(R, 'validate_selection'), mock.patch.object(R, 'input_selection', self.receiver.input_selection), \
             mock.patch.object(R, 'read', return_value=P.encoded(image)), mock.patch.object(R, 'require', side_effect=require):
            with self.assertRaisesRegex(ValueError, expected) if expected else self.assertRaises(ReachedNativeGate):
                R.verify_environment(selection, 0)

    def test_all_81_default_forms_bind_and_pass_unchanged_receiver_config_gate(self):
        fields = ('Cmd', 'Entrypoint', 'Shell', 'ArgsEscaped')
        for forms in itertools.product(('explicit', 'null', 'omitted'), repeat=4):
            image = copy.deepcopy(self.image)
            for key, form in zip(fields, forms):
                if form == 'null': image['Config'][key] = None
                if form == 'omitted': del image['Config'][key]
            before = copy.deepcopy(image)
            with self.subTest(forms=forms):
                handoff = self.handoff(image)
                self.assertEqual(handoff['Config'], P.CONFIG)
                self.assertEqual(image, before)
                self.assertEqual(handoff['image_id'], image['Id'])
                self.receiver_check(handoff)

    def test_nondefault_commands_shell_and_boolean_types_refuse(self):
        class EmptyList(list): pass
        cases = [(key, value) for key in ('Cmd', 'Entrypoint', 'Shell')
            for value in (['/bin/sh'], False, 0, '', {}, (), EmptyList())]
        cases += [('ArgsEscaped', value) for value in (True, 0, 0.0, '', [], {})]
        cases += [('Cmd', ['']), ('Shell', [''])]
        for key, value in cases:
            image = copy.deepcopy(self.image); image['Config'][key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, '^IMAGE_CONFIG '):
                self.handoff(image)

    def test_existing_empty_entrypoint_alias_and_label_policy_are_preserved(self):
        self.image['Config'].update(Entrypoint=[''], Labels=None)
        handoff = self.handoff()
        self.assertEqual(handoff['Config']['Entrypoint'], [''])
        self.assertIsNone(handoff['Config']['Labels'])
        self.receiver_check(handoff)

    def test_other_bindings_and_execution_policy_still_refuse(self):
        for key, value in [('User', '0'), ('WorkingDir', '/'), ('Env', P.CONFIG['Env'] + ['LD_PRELOAD=x']),
            ('Healthcheck', {'Test': ['CMD', 'true']}), ('Volumes', {'/etc': {}}), ('ExposedPorts', {'80/tcp': {}})]:
            image = copy.deepcopy(self.image); image['Config'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, '^IMAGE_CONFIG '): self.handoff(image)
        for key, value in [('Id', 'sha256:' + 'c' * 64), ('Architecture', 'amd64'), ('Os', 'windows')]:
            image = copy.deepcopy(self.image); image[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, '^IMAGE_BINDING$'): self.handoff(image)

    def test_handoff_schema_and_hash_authority_remain_exact(self):
        handoff = self.handoff()
        self.assertEqual(set(handoff['Config']), set(P.CONFIG))
        changed = copy.deepcopy(handoff); changed['Config']['Unexpected'] = None
        self.receiver_check(changed, '^IMAGE_CONFIG$')
        changed = copy.deepcopy(handoff); changed['Unexpected'] = None
        self.receiver_check(changed, '^IMAGE_HANDOFF_BINDING$')
        with mock.patch.object(R, 'validate_selection'), mock.patch.object(R, 'input_selection', self.receiver.input_selection), \
             mock.patch.object(R, 'read', return_value=P.encoded(handoff)):
            selection = dict(source_commit=self.controller.commit, image_id=self.controller.image,
                native_handoff_sha256='0' * 64, image_config_sha256=P.sha(P.encoded(handoff['Config'])))
            with self.assertRaisesRegex(ValueError, '^IMAGE_HANDOFF_HASH$'): R.verify_environment(selection, 0)


if __name__ == '__main__':
    unittest.main()
