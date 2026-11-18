# SPDX-License-Identifier: MIT
"""Small inert MODEL proof controls. No compiler or native result is produced."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('family_proof_MODEL', HERE/'proof.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
sys.addaudithook(P.no_actors)


class Controls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='qt612-family-proof-MODEL-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.contract = dict(required_shared_modules=['Qml', 'Quick'],
            required_cmake_packages=['Qt6QmlPrivate'], required_cmake_helpers=['Qt6Qml/ModelHelper.cmake'])

    def fixture(self, component):
        build = self.root/component
        build.mkdir()
        for name in P.build_files(component, self.contract):
            path = build/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('MODEL inert '+name+'\n').encode())
            path.chmod(0o644)
        shader = None
        if component == 'shadertools':
            shader = self.root/'shader'
            shader.mkdir()
            for name in P.SHADER_FILES:
                (shader/name).write_bytes(('MODEL inert '+name+'\n').encode())
        return build, shader

    def capture(self, component='svg'):
        build, shader = self.fixture(component)
        return P.capture(component=component, build=build, contract=self.contract, shader_output=shader)

    def test_all_five_complete_byte_roundtrips(self):
        for component in sorted(P.COMPONENTS):
            with self.subTest(component=component):
                envelope = self.capture(component)
                self.assertEqual(set(envelope['files']), P.expected_files(component, self.contract))
                raw = P.encoded(envelope)
                output = P.unpack(P.decode(raw), component=component, contract=self.contract, output=self.root/('out-'+component))
                decoded = P.validate(envelope, component=component, contract=self.contract)
                self.assertEqual({p.relative_to(output).as_posix(): p.read_bytes() for p in output.rglob('*') if p.is_file()}, decoded)
                self.assertNotIn('native_acceptance', envelope)

    def test_exact_shader_thirteen_outputs_required(self):
        self.assertEqual(len(P.SHADER_FILES), 13)
        build, shader = self.fixture('shadertools')
        (shader/'extra').write_bytes(b'MODEL extra')
        with self.assertRaisesRegex(ValueError, 'EXACT_SHADER_OUTPUT_NAMESPACE'):
            P.capture(component='shadertools', build=build, contract={}, shader_output=shader)

    def test_missing_shader_and_missing_build_input_refuse(self):
        build, _ = self.fixture('svg')
        (build/'CMakeCache.txt').unlink()
        with self.assertRaises(OSError):
            P.capture(component='svg', build=build, contract={})
        shader_build, _ = self.fixture('shadertools')
        with self.assertRaisesRegex(ValueError, 'COMPLETE_SHADER_OUTPUT_REQUIRED'):
            P.capture(component='shadertools', build=shader_build, contract={})

    def test_unknown_component_and_cross_component_envelope_refuse(self):
        with self.assertRaisesRegex(ValueError, 'KNOWN_FAMILY_PROOF_COMPONENT'):
            P.build_files('foreign', {})
        envelope = self.capture()
        with self.assertRaisesRegex(ValueError, 'EXACT_BUILD_PROOF_ENVELOPE'):
            P.validate(envelope, component='gui_server', contract={})

    def test_omitted_or_extra_proof_member_refuses(self):
        envelope = self.capture()
        for remove in (True, False):
            bad = copy.deepcopy(envelope)
            if remove:
                bad['files'].clear()
            else:
                bad['files']['../escape'] = next(iter(bad['files'].values()))
            with self.assertRaisesRegex(ValueError, 'EXACT_REQUIRED_BUILD_PROOF_NAMESPACE'):
                P.validate(bad, component='svg', contract={})

    def test_changed_whole_pin_and_bad_base64_refuse(self):
        envelope = self.capture()
        for key, value in (('sha256', '0'*64), ('bytes', 1), ('base64', '!!!!')):
            bad = copy.deepcopy(envelope)
            bad['files']['build/CMakeCache.txt'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                P.validate(bad, component='svg', contract={})

    def test_noninteger_descriptor_and_duplicate_json_refuse(self):
        envelope = self.capture()
        envelope['files']['build/CMakeCache.txt']['bytes'] = True
        with self.assertRaisesRegex(ValueError, 'FINITE_WHOLE_PROOF_DESCRIPTOR'):
            P.validate(envelope, component='svg', contract={})
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_PROOF_JSON_KEY'):
            P.decode(b'{"schema":1,"schema":1}')
        with self.assertRaisesRegex(ValueError, 'NONFINITE_PROOF_JSON'):
            P.decode(b'{"x":NaN}')

    def test_finite_caps_refuse_complete_result(self):
        build, _ = self.fixture('svg')
        with patch.object(P, 'MAX_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'COMPLETE_PROOF_TOTAL_BYTE_CAP'):
                P.capture(component='svg', build=build, contract={})
        with patch.object(P, 'MAX_JSON', 1):
            with self.assertRaisesRegex(ValueError, 'COMPLETE_PROOF_JSON_CAP'):
                P.capture(component='svg', build=build, contract={})
        with patch.object(P, 'MAX_FILES', 1):
            with self.assertRaisesRegex(ValueError, 'FINITE_BUILD_PROOF_FILES'):
                P.build_files('gui_server', {})

    def test_symlink_hardlink_and_public_writable_capture_refuse(self):
        build, _ = self.fixture('svg')
        leaf = build/'CMakeCache.txt'
        raw = leaf.read_bytes()
        leaf.unlink()
        other = self.root/'other'
        other.write_bytes(raw)
        leaf.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'ORDINARY_PROOF_PATH'):
            P.capture(component='svg', build=build, contract={})
        leaf.unlink()
        os.link(other, leaf)
        with self.assertRaisesRegex(ValueError, 'BOUNDED_ORDINARY_PROOF_FILE'):
            P.capture(component='svg', build=build, contract={})
        leaf.unlink()
        leaf.write_bytes(raw)
        leaf.chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'BOUNDED_ORDINARY_PROOF_FILE'):
            P.capture(component='svg', build=build, contract={})

    def test_readback_fresh_root_required(self):
        envelope = self.capture()
        existing = self.root/'existing'
        existing.mkdir()
        with self.assertRaisesRegex(ValueError, 'FRESH_PROOF_READBACK_ROOT'):
            P.unpack(envelope, component='svg', contract={}, output=existing)
        alias = self.root/'alias'
        alias.symlink_to(existing, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'ORDINARY_PROOF_PATH'):
            P.unpack(envelope, component='svg', contract={}, output=alias)

    def test_contract_cannot_select_paths_outside_build(self):
        bad = dict(self.contract, required_cmake_helpers=['../../../outside'])
        with self.assertRaisesRegex(ValueError, 'CANONICAL_PROOF_MEMBER'):
            P.build_files('declarative', bad)

    def test_actor_fence_refuses(self):
        for event in ('subprocess.Popen', 'socket.__new__', 'ctypes.dlopen', 'os.system', 'os.exec', 'os.fork'):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, 'NO_ACTORS'):
                sys.audit(event)


if __name__ == '__main__':
    unittest.main()
