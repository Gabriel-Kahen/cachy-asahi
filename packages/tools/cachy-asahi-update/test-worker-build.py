#!/usr/bin/env python3
"""Synthetic Cargo output validation only; never execute Cargo or compiled code."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('worker_build', Path(__file__).with_name('worker-build.py'))
worker_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker_build)


def fixture():
    packages = [{'id': name, 'name': name, 'targets': [{'kind': ['bin'] if name == 'arch-update-tray' else ['custom-build']}]} for name in ('arch-update-tray', 'gettext-sys', 'system-deps')]
    metadata = {'packages': packages, 'resolve': {'nodes': [
        {'id': p['id'], 'features': ['gettext-system'] if p['name'] == 'gettext-sys' else ['default']} for p in packages]}}
    events = [{'reason': 'compiler-artifact', 'package_id': p['id'], 'features': list(node['features']),
               'target': p['targets'][0], 'executable': '/tmp/target/tray' if p['name'] == 'arch-update-tray' else None} for p, node in zip(packages, metadata['resolve']['nodes'])]
    events += [{'reason': 'build-script-executed', 'package_id': 'gettext-sys', 'cfgs': [], 'env': [], 'linked_libs': [], 'linked_paths': []}, {'reason': 'build-finished', 'success': True}]
    return metadata, events


def parse(metadata, events):
    return worker_build.unit_evidence(json.dumps(metadata).encode(),
                                      b'\n'.join(json.dumps(e).encode() for e in events), Path('/tmp/target/tray'))


class UnitTests(unittest.TestCase):
    def test_diagnostic_io_failure_preserves_unit_refusal_and_control_signals(self):
        for error in (OSError('synthetic diagnostic failure'), KeyboardInterrupt()):
            diagnostic = types.SimpleNamespace(fail=mock.Mock(side_effect=error))
            metadata, events = fixture(); events[0]['package_id'] = 'unreviewed'
            expected = ValueError if isinstance(error, Exception) else KeyboardInterrupt
            with self.subTest(error=type(error).__name__), self.assertRaises(expected):
                worker_build.unit_evidence(json.dumps(metadata).encode(),
                    b'\n'.join(json.dumps(event).encode() for event in events), Path('/tmp/target/tray'), diagnostic)
            self.assertEqual(diagnostic.fail.call_args.args[0], 'unit-source')

    def test_actual_records_remain_distinct_from_metadata_union(self):
        metadata, events = fixture()
        metadata['resolve']['nodes'][0]['features'].append('uncompiled-union-feature')
        result = parse(metadata, events)
        self.assertEqual(len(result['compiler_artifacts']), 3)
        self.assertNotIn('uncompiled-union-feature', result['compiler_artifacts'][0]['features'])

    def test_extra_source_or_actual_feature_refused(self):
        for key, value in [('package_id', 'unreviewed-source'), ('features', ['unreviewed-feature'])]:
            metadata, events = fixture();events[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): parse(metadata, events)

    def test_gettext_system_and_system_deps_binary_conditions_enforced(self):
        metadata, events = fixture();events[1]['features'] = []
        with self.assertRaisesRegex(ValueError, 'gettext'): parse(metadata, events)
        metadata, events = fixture();metadata['resolve']['nodes'][2]['features'].append('binary');events[2]['features'].append('binary')
        with self.assertRaisesRegex(ValueError, 'system-deps'): parse(metadata, events)

    def test_build_script_run_requires_compiled_script_feature_record(self):
        metadata, events = fixture();events.pop(1)
        with self.assertRaisesRegex(ValueError, 'retained compiled unit'): parse(metadata, events)

    def test_failed_incomplete_or_wrong_binary_cannot_pass(self):
        for failure in ('failed', 'missing-end', 'wrong-binary'):
            metadata, events = fixture()
            if failure == 'failed': events[-1]['success'] = False
            if failure == 'missing-end': events.pop()
            if failure == 'wrong-binary': events[0]['executable'] = '/tmp/another-tray'
            with self.subTest(failure=failure), self.assertRaises(ValueError): parse(metadata, events)


class DiagnosticBuildTests(unittest.TestCase):
    """Real Recorder/files, synthetic worker/ELF results; no native commands."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'out'; self.output.mkdir(mode=0o700)
        self.work = self.root / 'work'; self.work.mkdir()
        self.entry = self.root / 'entry.py'; self.entry.write_bytes(b'synthetic entry')
        self.helper = worker_build.module('test_compile_diagnostic', Path(__file__).with_name('worker-diagnostic.py'))
        self.recorder = None
        self.commands = []
        self.fault = None

    def setup_worker(self):
        def recorder(**kwargs):
            self.recorder = self.helper.Recorder(**kwargs)
            return self.recorder
        helper = types.SimpleNamespace(Recorder=recorder, binding_values=lambda: self.helper.binding_values(self.entry))
        def observe():
            if self.fault == 'pre-metadata': raise ValueError('synthetic observation refusal')
            return {}
        def metadata(*args):
            with self.recorder.step('metadata-source'):
                if self.fault == 'source':
                    error = ValueError('synthetic source mismatch')
                    self.recorder.fail('source-pins', error); raise error
                if self.fault == 'nested-unknown': raise RuntimeError('synthetic unknown metadata failure')
            args[4].mkdir(mode=0o700)
            data, _ = fixture()
            return json.dumps(data).encode(), {'image_id':'sha256:'+'2'*64,
                'observed_worker':{'nonce':'3'*32}, 'sha256':{key:'4'*64 for key in ('manifest','lock','audit','metadata','cfg')}}, {}, {}
        def run(argv, cwd, env, output, stem, timeout=None):
            self.commands.append((argv, stem, timeout))
            self.recorder.command_start(stem)
            if self.fault == 'cancel' and stem == 'cargo-build': raise KeyboardInterrupt()
            self.recorder.command_result(stem, True, True, 0)
            if stem == 'cargo-build':
                binary = self.work / 'target/aarch64-unknown-linux-gnu/release/arch-update-tray'
                binary.parent.mkdir(parents=True); binary.write_bytes(b'synthetic ELF fixture')
                data, events = fixture(); events[0]['executable'] = str(binary)
                if self.fault == 'unit-source': events[0]['package_id'] = 'unreviewed'
                if self.fault == 'incomplete': events[-1]['success'] = False
                (output / 'cargo-build.stdout').write_text('\n'.join(json.dumps(event) for event in events))
                (output / 'cargo-build.stderr').write_bytes(b'')
            if stem == 'elf-inspection': (output / 'elf-inspection.stdout').write_bytes(b'synthetic readelf fixture')
        def regular(path, limit):
            if self.fault == 'binary-drift' and len(self.commands) == 3: return b'changed fixture'
            return path.read_bytes()
        worker = types.SimpleNamespace(TARGET='aarch64-unknown-linux-gnu', set_diagnostic=lambda value: None,
            observe=observe, verify_controller=lambda *args:{'builder_inventory_sha256':'5'*64},
            metadata=metadata, run=run, regular=regular, digest=lambda data:hashlib.sha256(data).hexdigest())
        def elf(data):
            if self.fault == 'elf': raise ValueError('synthetic ELF refusal')
        gate = types.SimpleNamespace(elf=elf)
        def module(name, path):
            if path.name == 'worker-diagnostic.py': return helper
            if path.name == 'worker-metadata.py':
                if self.fault == 'import': raise ImportError('synthetic worker import refusal')
                return worker
            if path.name == 'build-gate.py': return gate
            raise AssertionError('unexpected module')
        def path(value):
            if str(value) == '/out': return self.output
            if str(value) == '/out/target-metadata': return self.output / 'target-metadata'
            return Path(value)
        args = types.SimpleNamespace(manifest=self.work / 'Cargo.toml', vendor=self.root / 'vendor', cargo_audit=self.root / 'audit.json')
        return args, module, path

    def execute(self, fault=None):
        self.fault = fault
        self.commands = []
        args, module, path = self.setup_worker()
        original_write = Path.write_text
        def write_text(target, *args, **kwargs):
            if target.name == 'compile-result.json':
                self.assertFalse(self.diagnostic()['compilation_accepted'])
            if fault == 'receipt-write' and target.name == 'compile-result.json': raise OSError('synthetic receipt write refusal')
            return original_write(target, *args, **kwargs)
        with mock.patch.object(worker_build, 'module', side_effect=module), \
             mock.patch.object(worker_build, 'Path', side_effect=path), \
             mock.patch.object(Path, 'write_text', write_text), \
             mock.patch.dict(worker_build.os.environ, {'CACHY_ASAHI_CONTROLLER_SHA256':'1'*64,'CACHY_ASAHI_IMAGE_ID':'sha256:'+'2'*64}):
            worker_build.build(args)

    def diagnostic(self):
        return json.loads((self.output / 'worker-diagnostic.json').read_bytes())

    def test_pre_metadata_failure_is_unknown_and_bound(self):
        with self.assertRaisesRegex(ValueError, 'observation'): self.execute('pre-metadata')
        value = self.diagnostic()
        self.assertEqual(value['first_failure']['operation'], 'compile-controller')
        self.assertEqual(value['first_failure']['predicate'], 'UNKNOWN')
        self.assertFalse(value['controller_validated'])
        self.assertFalse(value['compiler_launch_attempted'])

    def test_worker_import_failure_has_startup_record_before_metadata(self):
        with self.assertRaises(ImportError): self.execute('import')
        value = self.diagnostic()
        self.assertEqual(value['first_failure']['operation'], 'compile-worker-import')
        self.assertEqual(value['first_failure']['predicate'], 'UNKNOWN')
        self.assertFalse(value['controller_validated'])
        self.assertFalse(value['compiler_launch_attempted'])

    def test_elf_refusal_stays_unknown_and_blocks_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'ELF'): self.execute('elf')
        value = self.diagnostic()
        self.assertEqual(value['first_failure']['operation'], 'compile-elf')
        self.assertEqual(value['first_failure']['predicate'], 'UNKNOWN')
        self.assertFalse(value['compilation_accepted'])

    def test_nested_first_unknown_or_specific_refusal_survives_outer_step(self):
        for fault, predicate in [('nested-unknown','UNKNOWN'), ('source','source-pins')]:
            with self.subTest(fault=fault):
                with self.assertRaises((ValueError, RuntimeError)): self.execute(fault)
                value = self.diagnostic()
                self.assertEqual(value['first_failure']['operation'], 'metadata-source')
                self.assertEqual(value['first_failure']['predicate'], predicate)
                self.assertFalse(value['compilation_accepted'])
                (self.output / 'worker-diagnostic.json').unlink()

    def test_cancellation_is_not_compiler_acceptance(self):
        with self.assertRaises(KeyboardInterrupt): self.execute('cancel')
        value = self.diagnostic()
        self.assertTrue(value['cancelled'])
        self.assertEqual(value['first_failure']['error_kind'], 'Cancelled')
        self.assertTrue(value['compiler_launch_attempted'])
        self.assertFalse(value['compiler_return_observed'])
        self.assertFalse(value['compilation_accepted'])

    def test_original_unit_and_copy_gates_refuse_diagnostic_acceptance(self):
        for fault, predicate in [('unit-source','unit-source'), ('incomplete','unit-complete'), ('binary-drift','compile-binary-drift')]:
            with self.subTest(fault=fault):
                with self.assertRaises(ValueError): self.execute(fault)
                value = self.diagnostic()
                self.assertEqual(value['first_failure']['predicate'], predicate)
                self.assertFalse(value['compilation_accepted'])
                shutil.rmtree(self.work / 'target'); shutil.rmtree(self.output / 'target-metadata')
                (self.output / 'worker-diagnostic.json').unlink()

    def test_receipt_write_failure_cannot_set_compiler_accepted(self):
        with self.assertRaises(OSError): self.execute('receipt-write')
        value = self.diagnostic()
        self.assertEqual(value['first_failure']['operation'], 'compile-receipt')
        self.assertEqual(value['first_failure']['predicate'], 'UNKNOWN')
        self.assertFalse(value['compilation_accepted'])

    def test_positive_fixture_preserves_commands_gates_and_receipt_before_acceptance(self):
        self.execute()
        value = self.diagnostic()
        receipt = json.loads((self.output / 'target-metadata/compile-result.json').read_bytes())
        self.assertTrue(value['compilation_accepted'])
        self.assertIsNone(value['first_failure'])
        self.assertEqual(receipt['native_compilation'], 'PASS')
        self.assertEqual(receipt['elf_16k_segments'], 'PASS-static; loader NOT RUN')
        self.assertEqual([(row[1], row[2]) for row in self.commands], [('compile-gate',180),('cargo-build',1200),('elf-inspection',None)])
        self.assertEqual(self.commands[1][0], ['/usr/bin/cargo','build','--release','--frozen','--offline','--locked',
            '--target','aarch64-unknown-linux-gnu','--jobs','2','--message-format=json-render-diagnostics','-vv',
            '--manifest-path',str(self.work / 'Cargo.toml')])
        self.assertEqual(self.commands[2][0][:4], ['/usr/bin/readelf','-h','-l','-d'])


if __name__ == '__main__':
    unittest.main()
