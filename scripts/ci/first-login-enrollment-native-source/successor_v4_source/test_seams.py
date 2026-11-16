# SPDX-License-Identifier: MIT
"""Pure committed-module seam assertions; missing real inputs remain refusals.

Run against an ordinary checkout/public copied view. These checks intentionally
fail on incompatible committed modules, and never assert a completed pipeline.
"""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent/'payload/native'


def fence(event, args):
    if event.startswith(('socket.', 'subprocess.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock', 'resource.setrlimit'):
        raise AssertionError('PURE cross-contract DATA only: '+event)


sys.addaudithook(fence)


def encoded(value):return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class Controls(unittest.TestCase):
    def load(self, name):
        path = NATIVE/(name+'.py')
        self.assertTrue(path.is_file(), 'Missing committed module: '+str(path))
        spec = importlib.util.spec_from_file_location('PURE_SEAM_'+name, path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except (ValueError, ImportError) as error:
            self.fail('Committed module import refused '+name+' '+json.dumps(pin(path.read_bytes()))+': '+str(error))
        return module

    @staticmethod
    def owner():
        return dict(image_inputs={}, stage_inputs=dict(schema=3, kind='DELEGATED_CURRENT_PRIVATE_INPUTS_V3',
                    source_date_epoch=0, setup8={}, products={}))

    def test_actual_assembler_outer_parser_routes_to_distinct_inner_validator(self):
        A = self.load('inputs_current_v3')
        self.assertTrue(callable(getattr(A, 'validate_owner_inputs_v3', None)), 'Missing actual distinct inner validator API')
        inner = self.owner()
        outer = dict(schema=3, kind='ROOT_STAGED_CURRENT_INPUTS_V3', owner_inputs=inner, staged_refs=[])
        # Only dispatch is modeled. No Root/source/input semantics are approved.
        with patch.object(A, 'validate_owner_inputs_v3', return_value=dict(valid=True, required_refs=[])) as semantic:
            self.assertEqual(A.validate_hosted_inputs_v3(inputs=outer, delegation={}, source_root=NATIVE),
                             dict(valid=True, required_refs=[]))
            semantic.assert_called_once_with(inputs=inner, delegation={}, source_root=NATIVE)
        with self.assertRaises(ValueError):A.owner_shape(outer)
        # Genuine missing image material remains a refusal in the real inner parser.
        with self.assertRaises((ValueError, KeyError)):
            A.validate_owner_inputs_v3(inputs=inner, delegation={}, source_root=NATIVE)

    def test_actual_launcher_canonical_wrapper_reaches_missing_descriptor_refusal(self):
        L = self.load('hosted_current_v3')
        with tempfile.TemporaryDirectory(prefix='PURE-current-seam-') as temporary:
            root = Path(temporary); staged = root/'staged'; staged.mkdir(mode=0o700)
            outer = dict(schema=3, kind='ROOT_STAGED_CURRENT_INPUTS_V3', owner_inputs=self.owner(), staged_refs=[])
            body = encoded(outer); path = staged/'inputs.json'; path.write_bytes(body); path.chmod(0o600)
            request = dict(staged_root=str(staged), staged_inputs=dict(path=str(path), **pin(body)))
            self.assertEqual(L.decode(body), outer)
            # This absence is intentional; no fake descriptor/Root grant is issued.
            # A three-key wrapper gate fails this assertion before descriptor check.
            with self.assertRaisesRegex(ValueError, 'input assembler descriptor required'):
                L.checked_inputs(request, dict(programs={}), root, None, time.monotonic()+5)

    def test_actual_owner_inner_call_and_missing_authority_refusal(self):
        O = self.load('owner_delegated_v3')
        body = encoded(dict(schema=4, kind='PURE_MODEL_NO_ROOT_AUTHORITY', issuer=None, approved=False))
        with self.assertRaisesRegex(ValueError, 'delegation'):
            O.scope(body, pin(body)['sha256'])
        tree = ast.parse(Path(O.__file__).read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_owned_current_v3')
        calls = [n for n in ast.walk(function) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        inner = [n for n in calls if n.func.attr == 'validate_owner_inputs_v3']
        self.assertEqual(len(inner), 1, 'Owner must call the explicit inner API once')
        self.assertFalse(any(n.func.attr == 'validate_hosted_inputs_v3' for n in calls), 'Owner cannot reinterpret the outer envelope')
        keys = [n.slice.value for n in ast.walk(function) if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant)]
        self.assertIn('inputs_assembler', keys)
        self.assertNotIn('inputs_validator', keys)

    def test_actual_executor_context_identity_is_explicit_and_whole_pinned(self):
        E = self.load('owned_executor_current_v3')
        H = self.load('delegated_context_v4')
        self.assertTrue(callable(getattr(E, 'context_contract', None)), 'Executor still has the old V3-only context issuer gate')
        with self.assertRaisesRegex(ValueError, 'context descriptor'):
            E.context_contract(dict(programs={}))
        descriptor = dict(member='scripts/ci/first-login-enrollment-native-source/payload/native/delegated_context_v4.py',
                          **pin(Path(H.__file__).read_bytes()))
        # Identity tuple only, with no approval, binding, time or runtime authority.
        d = dict(schema=4, kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4', issuer='Root',
                 programs=dict(context=descriptor))
        context = dict(schema=4, kind=H.CONTEXT, issuer=H.ISSUER, operation=H.OPERATION,
                       program_pin={k: descriptor[k] for k in ('bytes', 'sha256')})
        try:
            selected = E.context_contract(d, context)
        except ValueError as error:
            self.fail('Actual selected context '+json.dumps(context['program_pin'])+' refused by executor pins '+
                      json.dumps(E.CONTEXT_PROGRAM_PINS, sort_keys=True)+': '+str(error))
        self.assertEqual(selected, 4, 'Actual context body must match the executor selected program pin')
        forged = copy.deepcopy(context); forged['issuer'] = 'DELEGATED_CONTEXT_PROGRAM_V3'
        with self.assertRaises(ValueError):E.context_contract(d, forged)

    def test_actual_reader_selects_current_retention_whole_body(self):
        R = self.load('reader_current_v3')
        actual = pin((NATIVE/'retention_delegated_v4.py').read_bytes())
        self.assertIn(actual, R.DELEGATED_RETENTION_VERSIONS,
                      'Current producer body must be explicitly supported by the independent Reader')

    def test_actual_reader_selects_current_constructor_whole_body(self):
        R = self.load('reader_current_v3')
        # Evaluate only the real Reader's single pure version-selection expression.
        # Several historical constructor pins coexist; membership alone would
        # hide selecting the wrong one for the current producer.
        tree = ast.parse(Path(R.__file__).read_bytes())
        expressions = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign) and
                       any(isinstance(target, ast.Name) and target.id == 'constructor_pin' for target in node.targets)]
        self.assertEqual(len(expressions), 1, 'One actual Reader constructor-version selector')
        expected = dict(source=dict(retention=pin((NATIVE/'retention_delegated_v4.py').read_bytes())))
        scope = dict(R.__dict__, expected=expected)
        selected = eval(compile(ast.Expression(expressions[0]), '<pure-Reader-constructor-selector>', 'eval'), scope)
        self.assertEqual(selected, pin((HERE/'prepare.py').read_bytes()),
                         'Current Source constructor must match the independent Reader selected version')

    def test_pure_fence_and_no_native_or_Root_acceptance_claim(self):
        for event in ('socket.connect', 'subprocess.Popen', 'os.system', 'os.fork', 'fcntl.flock'):
            with self.subTest(event=event), self.assertRaises(AssertionError):sys.audit(event)


if __name__ == '__main__':unittest.main()
